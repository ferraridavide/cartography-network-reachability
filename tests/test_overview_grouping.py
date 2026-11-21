from __future__ import annotations

import ipaddress
import unittest

from cartography_reachability.metadata import (
    ecs_cluster_arn_from_task_arn,
    ecs_cluster_name_from_arn,
    ecs_service_arn_from_cluster_and_name,
    ecs_service_name_from_arn,
    ecs_service_name_from_task_group,
    elb_arn_from_eni_description,
)
from cartography_reachability.models import (
    Eni,
    PacketSpace,
    ReachabilityPath,
    Route,
    SecurityGroupRule,
)
from cartography_reachability.overview import build_overview_graph, workload_identity


def eni(
    eni_id: str,
    private_ip: str,
    owner_type: str = "EC2Instance",
    owner_id: str | None = None,
    **kwargs,
) -> Eni:
    return Eni(
        id=eni_id,
        private_ip=ipaddress.ip_address(private_ip),
        public_ip=None,
        private_dns_name=None,
        mac_address=None,
        description=kwargs.get("description"),
        interface_type="interface",
        requester_id=None,
        requester_managed=False,
        device_index=0,
        subnet_id=kwargs.get("subnet_id", "subnet-a"),
        subnet_cidr=ipaddress.ip_network(kwargs.get("subnet_cidr", "10.0.1.0/24")),
        vpc_id=kwargs.get("vpc_id", "vpc-a"),
        region="eu-central-1",
        account_id="123456789012",
        owner_id=owner_id or eni_id,
        owner_type=owner_type,
        owner_labels=(owner_type,),
        owner_name=kwargs.get("owner_name", owner_id or eni_id),
        owner_arn=kwargs.get("owner_arn"),
        elb_arn=kwargs.get("elb_arn"),
        auto_scaling_group_arn=kwargs.get("auto_scaling_group_arn"),
        auto_scaling_group_name=kwargs.get("auto_scaling_group_name"),
        instance_profile_arn=kwargs.get("instance_profile_arn"),
        instance_profile_name=kwargs.get("instance_profile_name"),
        ecs_service_arn=kwargs.get("ecs_service_arn"),
        ecs_service_name=kwargs.get("ecs_service_name"),
        ecs_cluster_arn=kwargs.get("ecs_cluster_arn"),
        ecs_cluster_name=kwargs.get("ecs_cluster_name"),
        sg_ids=kwargs.get("sg_ids", ("sg-a",)),
        subnet_availability_zone=kwargs.get("subnet_availability_zone"),
    )


def path(src: Eni, dst: Eni, route_id: str = "rtb-a|10.0.0.0/16") -> ReachabilityPath:
    packet = PacketSpace(ipaddress.ip_network("10.0.0.0/16"), "tcp", 443, 443)
    egress = SecurityGroupRule(
        "egress-1",
        "sg-src",
        "egress",
        "tcp",
        443,
        443,
        (ipaddress.ip_network("10.0.0.0/16"),),
        ("10.0.0.0/16",),
    )
    ingress = SecurityGroupRule(
        "ingress-1",
        "sg-dst",
        "ingress",
        "tcp",
        443,
        443,
        (ipaddress.ip_network("10.0.1.0/24"),),
        ("10.0.1.0/24",),
    )
    route = Route(
        route_id,
        "rtb-a",
        ipaddress.ip_network("10.0.0.0/16"),
        "local",
        None,
        None,
        None,
        "active",
    )
    return ReachabilityPath(src, dst, packet, packet, packet, egress, route, ingress)


class OverviewGroupingTest(unittest.TestCase):
    def test_elb_arn_extraction_from_eni_description(self) -> None:
        self.assertEqual(
            elb_arn_from_eni_description(
                "ELB app/acme-console-alb-or/3333cccc4444dddd",
                "eu-central-1",
                "123456789012",
            ),
            "arn:aws:elasticloadbalancing:eu-central-1:123456789012:"
            "loadbalancer/app/acme-console-alb-or/3333cccc4444dddd",
        )

    def test_ecs_names_are_extracted_from_arns_and_task_group(self) -> None:
        task_arn = (
            "arn:aws:ecs:eu-central-1:123456789012:"
            "task/acme-services-prod-storefront-services-cluster/"
            "0123456789abcdef0123456789abcdef"
        )
        cluster_arn = (
            "arn:aws:ecs:eu-central-1:123456789012:"
            "cluster/acme-services-prod-storefront-services-cluster"
        )

        self.assertEqual(
            ecs_cluster_name_from_arn(task_arn),
            "acme-services-prod-storefront-services-cluster",
        )
        self.assertEqual(ecs_cluster_arn_from_task_arn(task_arn), cluster_arn)
        self.assertEqual(
            ecs_service_name_from_arn(
                "arn:aws:ecs:eu-central-1:123456789012:"
                "service/acme-services-prod-storefront-services-cluster/api"
            ),
            "api",
        )
        self.assertEqual(ecs_service_name_from_task_group("service:api"), "api")
        self.assertEqual(
            ecs_service_arn_from_cluster_and_name(cluster_arn, "api"),
            "arn:aws:ecs:eu-central-1:123456789012:"
            "service/acme-services-prod-storefront-services-cluster/api",
        )

    def test_ec2_grouping_requires_same_asg_profile_and_evidence(self) -> None:
        src1 = eni(
            "eni-src-1",
            "10.0.1.10",
            owner_id="i-1",
            auto_scaling_group_arn="arn:aws:autoscaling:asg-a",
            auto_scaling_group_name="asg-a",
            instance_profile_arn="arn:aws:iam::123:instance-profile/app",
        )
        src2 = eni(
            "eni-src-2",
            "10.0.1.11",
            owner_id="i-2",
            auto_scaling_group_arn="arn:aws:autoscaling:asg-a",
            auto_scaling_group_name="asg-a",
            instance_profile_arn="arn:aws:iam::123:instance-profile/app",
        )
        dst = eni("eni-dst", "10.0.2.10", owner_type="RDSInstance")

        graph = build_overview_graph([path(src1, dst), path(src2, dst)])
        grouped_sources = [
            node for node in graph.nodes if node.properties["group_type"] == "ec2_asg_instance_profile"
        ]

        self.assertEqual(len(grouped_sources), 1)
        self.assertEqual(grouped_sources[0].properties["member_count"], 2)

    def test_ecs_grouping_prefers_service_and_falls_back_to_cluster(self) -> None:
        service_task = eni(
            "eni-task-service",
            "10.0.1.20",
            owner_type="ECSTask",
            ecs_service_arn="arn:aws:ecs:svc",
            ecs_service_name="svc",
            ecs_cluster_arn="arn:aws:ecs:cluster/base",
        )
        cluster_task = eni(
            "eni-task-cluster",
            "10.0.1.21",
            owner_type="ECSTask",
            ecs_cluster_arn="arn:aws:ecs:cluster/base",
            ecs_cluster_name="base",
        )

        self.assertEqual(workload_identity(service_task).kind, "ecs_service")
        self.assertEqual(workload_identity(cluster_task).kind, "ecs_cluster")

    def test_same_workload_different_route_evidence_does_not_group(self) -> None:
        src1 = eni(
            "eni-src-1",
            "10.0.1.10",
            owner_id="i-1",
            auto_scaling_group_arn="arn:aws:autoscaling:asg-a",
            instance_profile_arn="arn:aws:iam::123:instance-profile/app",
        )
        src2 = eni(
            "eni-src-2",
            "10.0.1.11",
            owner_id="i-2",
            auto_scaling_group_arn="arn:aws:autoscaling:asg-a",
            instance_profile_arn="arn:aws:iam::123:instance-profile/app",
        )
        dst = eni("eni-dst", "10.0.2.10", owner_type="RDSInstance")

        graph = build_overview_graph(
            [path(src1, dst, "rtb-a|10.0.0.0/16"), path(src2, dst, "rtb-b|10.0.0.0/16")]
        )

        self.assertIn("eni:eni-src-1", {node.id for node in graph.nodes})
        self.assertIn("eni:eni-src-2", {node.id for node in graph.nodes})

    def test_grouped_edge_preserves_path_count_and_member_metadata(self) -> None:
        src1 = eni(
            "eni-src-1",
            "10.0.1.10",
            description="first",
            auto_scaling_group_arn="arn:aws:autoscaling:asg-a",
            instance_profile_arn="arn:aws:iam::123:instance-profile/app",
        )
        src2 = eni(
            "eni-src-2",
            "10.0.1.11",
            description="second",
            auto_scaling_group_arn="arn:aws:autoscaling:asg-a",
            instance_profile_arn="arn:aws:iam::123:instance-profile/app",
        )
        dst = eni("eni-dst", "10.0.2.10", owner_type="RDSInstance")

        graph = build_overview_graph([path(src1, dst), path(src2, dst)])
        source_node = next(
            node for node in graph.nodes if node.properties["member_count"] == 2
        )
        source_edge = next(edge for edge in graph.edges if edge.source == source_node.id)

        self.assertEqual(len(source_edge.paths), 2)
        self.assertEqual(
            source_node.properties["member_eni_ids"], ["eni-src-1", "eni-src-2"]
        )
        self.assertEqual(
            source_node.properties["member_descriptions"], ["first", "second"]
        )


if __name__ == "__main__":
    unittest.main()
