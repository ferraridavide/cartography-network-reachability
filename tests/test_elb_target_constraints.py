from __future__ import annotations

import ipaddress
import unittest

from cartography_reachability.models import ElbTarget, Route, SecurityGroupRule
from cartography_reachability.tracer import RayTracer
from tests.test_overview_grouping import eni


def allow_all_egress(sg_id: str) -> SecurityGroupRule:
    return SecurityGroupRule(
        id=f"{sg_id}-egress-all",
        sg_id=sg_id,
        direction="egress",
        protocol="*",
        from_port=None,
        to_port=None,
        cidrs=(ipaddress.ip_network("0.0.0.0/0"),),
        raw_cidrs=("0.0.0.0/0",),
    )


def allow_ingress(sg_id: str, port: int) -> SecurityGroupRule:
    return SecurityGroupRule(
        id=f"{sg_id}-ingress-{port}",
        sg_id=sg_id,
        direction="ingress",
        protocol="tcp",
        from_port=port,
        to_port=port,
        cidrs=(ipaddress.ip_network("10.0.0.0/16"),),
        raw_cidrs=("10.0.0.0/16",),
    )


def local_route() -> Route:
    return Route(
        id="rtb-a|10.0.0.0/16",
        route_table_id="rtb-a",
        destination=ipaddress.ip_network("10.0.0.0/16"),
        gateway_id="local",
        target=None,
        peering_id=None,
        transit_gateway_id=None,
        state="active",
    )


class ElbTargetConstraintTest(unittest.TestCase):
    def tracer(self, elb_targets):
        lb_arn = (
            "arn:aws:elasticloadbalancing:eu-central-1:123:"
            "loadbalancer/app/app-lb/abc"
        )
        source = eni(
            "eni-lb",
            "10.0.1.10",
            owner_type="LoadBalancer",
            description="ELB app/app-lb/abc",
            elb_arn=lb_arn,
            sg_ids=("sg-lb",),
        )
        target = eni("eni-target", "10.0.2.10", sg_ids=("sg-target",))
        non_target = eni("eni-other", "10.0.2.11", sg_ids=("sg-target",))
        return RayTracer(
            enis={item.id: item for item in (source, target, non_target)},
            egress_rules={"sg-lb": [allow_all_egress("sg-lb")]},
            ingress_rules={"sg-target": [allow_ingress("sg-target", 8080)]},
            sg_allows=set(),
            subnet_route_table={"subnet-a": "rtb-a"},
            main_route_table={},
            routes_by_table={"rtb-a": [local_route()]},
            peering_vpcs={},
            elb_targets=elb_targets,
        )

    def test_elb_source_only_reaches_registered_target_on_target_group_port(self) -> None:
        lb_arn = (
            "arn:aws:elasticloadbalancing:eu-central-1:123:"
            "loadbalancer/app/app-lb/abc"
        )
        target = ElbTarget(
            load_balancer_arn=lb_arn,
            target_eni_id="eni-target",
            target_group_arn="arn:aws:elasticloadbalancing:eu-central-1:123:targetgroup/app/def",
            target_group_name="app",
            protocol="http",
            port=8080,
        )

        paths = self.tracer({lb_arn: {"eni-target": [target]}}).trace(
            source_filter=None,
            destination_filter=None,
            source_limit=10,
            pair_limit=100,
            path_limit=100,
        )

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].dst.id, "eni-target")
        self.assertEqual(paths[0].packet.protocol, "tcp")
        self.assertEqual(paths[0].packet.port_min, 8080)
        self.assertEqual(paths[0].packet.port_max, 8080)
        self.assertEqual(paths[0].elb_target, target)
        self.assertEqual(paths[0].elb_packet.as_dict()["ports"], "8080-8080")
        payload = paths[0].as_dict()
        self.assertEqual(
            list(payload["packet_space_by_stage"]),
            ["initial", "after_elb_target", "after_egress", "after_route", "after_ingress"],
        )
        self.assertLess(
            [step["type"] for step in payload["path"]].index("elb_target"),
            [step["type"] for step in payload["path"]].index("ingress_rule"),
        )

    def test_zero_limits_mean_unlimited(self) -> None:
        lb_arn = (
            "arn:aws:elasticloadbalancing:eu-central-1:123:"
            "loadbalancer/app/app-lb/abc"
        )
        target = ElbTarget(
            load_balancer_arn=lb_arn,
            target_eni_id="eni-target",
            target_group_arn="arn:aws:elasticloadbalancing:eu-central-1:123:targetgroup/app/def",
            target_group_name="app",
            protocol="http",
            port=8080,
        )

        paths = self.tracer({lb_arn: {"eni-target": [target]}}).trace(
            source_filter=None,
            destination_filter=None,
            source_limit=0,
            pair_limit=0,
            path_limit=0,
        )

        self.assertEqual(len(paths), 1)

    def test_elb_source_without_target_metadata_has_no_outgoing_paths(self) -> None:
        paths = self.tracer({}).trace(
            source_filter=None,
            destination_filter=None,
            source_limit=10,
            pair_limit=100,
            path_limit=100,
        )

        self.assertEqual(paths, [])


if __name__ == "__main__":
    unittest.main()
