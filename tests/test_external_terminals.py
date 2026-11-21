from __future__ import annotations

import ipaddress
import unittest

from cartography_reachability.models import ExternalEndpoint, Route, SecurityGroupRule
from cartography_reachability.tracer import RayTracer
from tests.test_elb_target_constraints import allow_all_egress
from tests.test_overview_grouping import eni


def peering_route(destination: str = "10.2.0.0/16") -> Route:
    return Route(
        id=f"rtb-src|{destination}|pcx-1",
        route_table_id="rtb-src",
        destination=ipaddress.ip_network(destination),
        gateway_id=None,
        target=None,
        peering_id="pcx-1",
        transit_gateway_id=None,
        state="active",
    )


def peering_terminal() -> ExternalEndpoint:
    return ExternalEndpoint(
        id="external:vpc-peering:pcx-1:vpc-foreign:10.2.0.0/16",
        label="foreign-vpc via pcx-1",
        cidr=ipaddress.ip_network("10.2.0.0/16"),
        connection_kind="vpc_peering",
        connection_id="pcx-1",
        vpc_id="vpc-foreign",
        account_id="999999999999",
    )


def allow_ingress_from(sg_id: str, port: int, cidr: str) -> SecurityGroupRule:
    return SecurityGroupRule(
        id=f"{sg_id}-ingress-{port}-{cidr}",
        sg_id=sg_id,
        direction="ingress",
        protocol="tcp",
        from_port=port,
        to_port=port,
        cidrs=(ipaddress.ip_network(cidr),),
        raw_cidrs=(cidr,),
    )


class ExternalTerminalsTest(unittest.TestCase):
    def test_peering_route_to_foreign_vpc_is_terminal_destination(self) -> None:
        source = eni(
            "eni-src",
            "10.0.1.10",
            vpc_id="vpc-local",
            subnet_id="subnet-src",
            sg_ids=("sg-src",),
        )
        tracer = RayTracer(
            enis={source.id: source},
            egress_rules={"sg-src": [allow_all_egress("sg-src")]},
            ingress_rules={},
            sg_allows=set(),
            subnet_route_table={"subnet-src": "rtb-src"},
            main_route_table={},
            routes_by_table={"rtb-src": [peering_route()]},
            peering_vpcs={"pcx-1": {"vpc-local", "vpc-foreign"}},
            external_endpoints=[peering_terminal()],
        )

        paths = tracer.trace(None, None, 0, 0, 0)

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].src.id, "eni-src")
        self.assertEqual(paths[0].dst.owner_type, "ExternalNetwork")
        self.assertEqual(paths[0].dst.terminal_connection_id, "pcx-1")
        self.assertEqual(str(paths[0].packet.dst), "10.2.0.0/16")

    def test_peering_terminal_source_uses_known_destination_ingress(self) -> None:
        destination = eni(
            "eni-dst",
            "10.0.1.20",
            vpc_id="vpc-local",
            subnet_id="subnet-dst",
            subnet_cidr="10.0.1.0/24",
            sg_ids=("sg-dst",),
        )
        tracer = RayTracer(
            enis={destination.id: destination},
            egress_rules={},
            ingress_rules={
                "sg-dst": [allow_ingress_from("sg-dst", 443, "10.2.0.0/16")]
            },
            sg_allows=set(),
            subnet_route_table={"subnet-dst": "rtb-dst"},
            main_route_table={},
            routes_by_table={},
            peering_vpcs={"pcx-1": {"vpc-local", "vpc-foreign"}},
            external_endpoints=[peering_terminal()],
        )

        paths = tracer.trace(None, None, 0, 0, 0)

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].src.owner_type, "ExternalNetwork")
        self.assertEqual(paths[0].dst.id, "eni-dst")
        self.assertEqual(paths[0].packet.protocol, "tcp")
        self.assertEqual(paths[0].packet.port_min, 443)


if __name__ == "__main__":
    unittest.main()
