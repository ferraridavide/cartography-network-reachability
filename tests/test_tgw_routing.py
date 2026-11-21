from __future__ import annotations

import ipaddress
import unittest

from cartography_reachability.models import (
    ExternalEndpoint,
    Route,
    TgwAttachment,
    TgwRoute,
    TgwTopology,
)
from cartography_reachability.tracer import RayTracer
from tests.test_elb_target_constraints import allow_all_egress, allow_ingress
from tests.test_overview_grouping import eni


def tgw_route(destination: str = "10.1.0.0/16") -> Route:
    return Route(
        id=f"rtb-src|{destination}",
        route_table_id="rtb-src",
        destination=ipaddress.ip_network(destination),
        gateway_id=None,
        target=None,
        peering_id=None,
        transit_gateway_id="tgw-1",
        state="active",
    )


def tracer(topology: TgwTopology) -> RayTracer:
    source = eni(
        "eni-src",
        "10.0.1.10",
        vpc_id="vpc-src",
        subnet_id="subnet-src",
        subnet_cidr="10.0.1.0/24",
        sg_ids=("sg-src",),
    )
    destination = eni(
        "eni-dst",
        "10.1.1.10",
        vpc_id="vpc-dst",
        subnet_id="subnet-dst",
        subnet_cidr="10.1.1.0/24",
        sg_ids=("sg-dst",),
    )
    return RayTracer(
        enis={source.id: source, destination.id: destination},
        egress_rules={"sg-src": [allow_all_egress("sg-src")]},
        ingress_rules={"sg-dst": [allow_ingress("sg-dst", 443)]},
        sg_allows=set(),
        subnet_route_table={"subnet-src": "rtb-src", "subnet-dst": "rtb-dst"},
        main_route_table={},
        routes_by_table={"rtb-src": [tgw_route()]},
        peering_vpcs={},
        tgw_topology=topology,
    )


def attached_topology(
    route_state: str | None = "active",
    route_type: str | None = "propagated",
    propagated: bool = True,
) -> TgwTopology:
    return TgwTopology(
        attachments=(
            TgwAttachment(
                id="tgw-attach-src",
                tgw_id="tgw-1",
                vpc_id="vpc-src",
                state="available",
                resource_type="vpc",
                route_table_ids=("tgw-rtb-src",),
            ),
            TgwAttachment(
                id="tgw-attach-dst",
                tgw_id="tgw-1",
                vpc_id="vpc-dst",
                state="available",
                resource_type="vpc",
                propagated_route_table_ids=("tgw-rtb-src",) if propagated else (),
            ),
        ),
        routes=(
            TgwRoute(
                id="tgw-rtb-src|10.1.0.0/16",
                route_table_id="tgw-rtb-src",
                destination=ipaddress.ip_network("10.1.0.0/16"),
                attachment_ids=("tgw-attach-dst",),
                state=route_state,
                route_type=route_type,
            ),
        ),
    )


class TgwRoutingTest(unittest.TestCase):
    def test_tgw_route_requires_attachment_and_records_hop(self) -> None:
        paths = tracer(attached_topology()).trace(
            source_filter=None,
            destination_filter=None,
            source_limit=0,
            pair_limit=0,
            path_limit=0,
        )

        self.assertEqual(len(paths), 1)
        self.assertIsNotNone(paths[0].tgw_hop)
        self.assertEqual(paths[0].tgw_hop.source_attachment_id, "tgw-attach-src")
        self.assertEqual(paths[0].tgw_hop.destination_attachment_id, "tgw-attach-dst")
        self.assertEqual(paths[0].as_dict()["tgw_hop"]["route_table_id"], "tgw-rtb-src")

    def test_tgw_route_without_source_attachment_is_blocked(self) -> None:
        topology = TgwTopology(
            attachments=(
                TgwAttachment(
                    id="tgw-attach-dst",
                    tgw_id="tgw-1",
                    vpc_id="vpc-dst",
                    state="available",
                    resource_type="vpc",
                    propagated_route_table_ids=("tgw-rtb-src",),
                ),
            ),
            routes=attached_topology().routes,
        )

        paths = tracer(topology).trace(None, None, 0, 0, 0)

        self.assertEqual(paths, [])

    def test_tgw_blackhole_route_blocks_reachability(self) -> None:
        paths = tracer(attached_topology(route_state="blackhole")).trace(
            None, None, 0, 0, 0
        )

        self.assertEqual(paths, [])

    def test_tgw_propagated_route_requires_propagation_to_source_table(self) -> None:
        paths = tracer(attached_topology(propagated=False)).trace(
            None, None, 0, 0, 0
        )

        self.assertEqual(paths, [])

    def test_tgw_route_to_external_attachment_is_terminal(self) -> None:
        source = eni(
            "eni-src",
            "10.0.1.10",
            vpc_id="vpc-src",
            subnet_id="subnet-src",
            subnet_cidr="10.0.1.0/24",
            sg_ids=("sg-src",),
        )
        topology = TgwTopology(
            attachments=(
                TgwAttachment(
                    id="tgw-attach-src",
                    tgw_id="tgw-1",
                    vpc_id="vpc-src",
                    state="available",
                    resource_type="vpc",
                    route_table_ids=("tgw-rtb-src",),
                ),
                TgwAttachment(
                    id="tgw-attach-vpn",
                    tgw_id="tgw-1",
                    vpc_id="vpn",
                    state="available",
                    resource_type="vpn",
                ),
            ),
            routes=(
                TgwRoute(
                    id="tgw-rtb-src|172.16.0.0/16",
                    route_table_id="tgw-rtb-src",
                    destination=ipaddress.ip_network("172.16.0.0/16"),
                    attachment_ids=("tgw-attach-vpn",),
                    state="active",
                    route_type="static",
                ),
            ),
        )
        terminal = ExternalEndpoint(
            id="external:tgw:tgw-1:tgw-attach-vpn:172.16.0.0/16",
            label="vpn tgw-attach-vpn",
            cidr=ipaddress.ip_network("172.16.0.0/16"),
            connection_kind="transit_gateway_vpn",
            connection_id="tgw-1",
            tgw_id="tgw-1",
            attachment_id="tgw-attach-vpn",
        )
        tracer = RayTracer(
            enis={source.id: source},
            egress_rules={"sg-src": [allow_all_egress("sg-src")]},
            ingress_rules={},
            sg_allows=set(),
            subnet_route_table={"subnet-src": "rtb-src"},
            main_route_table={},
            routes_by_table={"rtb-src": [tgw_route("172.16.0.0/16")]},
            peering_vpcs={},
            tgw_topology=topology,
            external_endpoints=[terminal],
        )

        paths = tracer.trace(None, None, 0, 0, 0)

        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0].dst.as_node()["terminal"])
        self.assertEqual(
            paths[0].dst.terminal_cidr, ipaddress.ip_network("172.16.0.0/16")
        )
        self.assertIsNotNone(paths[0].tgw_hop)


if __name__ == "__main__":
    unittest.main()
