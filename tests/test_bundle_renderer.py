from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cartography_reachability.renderers.bundle import (
    bundle_eni_label,
    render_bundle_json,
)
from tests.test_overview_grouping import eni, path


class BundleRendererTest(unittest.TestCase):
    def test_bundle_eni_label_uses_related_resource(self) -> None:
        ec2 = eni(
            "eni-ec2",
            "10.0.1.10",
            owner_id="i-0123456789abcdef0",
            owner_name="acme-prod-crm",
        )
        unnamed_ec2 = eni(
            "eni-unnamed-ec2",
            "10.0.1.18",
            owner_id="i-0123456789abcdef0",
            owner_name="i-0123456789abcdef0",
        )
        ecs = eni(
            "eni-ecs",
            "10.0.1.11",
            owner_type="ECSTask",
            owner_id="arn:aws:ecs:eu-central-1:123:task/cluster/task-abc",
            ecs_service_name="orders-service",
        )
        standalone_ecs = eni(
            "eni-ecs-standalone",
            "10.0.1.14",
            owner_type="ECSTask",
            owner_id="arn:aws:ecs:eu-central-1:123:task/batch-cluster/task-def",
            ecs_cluster_name="batch-cluster",
        )
        ecs_service_arn_only = eni(
            "eni-ecs-service-arn",
            "10.0.1.15",
            owner_type="ECSTask",
            owner_id="arn:aws:ecs:eu-central-1:123:task/app-cluster/task-ghi",
            ecs_service_arn="arn:aws:ecs:eu-central-1:123:service/app-cluster/api",
        )
        ecs_task_arn_only = eni(
            "eni-ecs-task-arn",
            "10.0.1.16",
            owner_type="ECSTask",
            owner_id="arn:aws:ecs:eu-central-1:123:task/app-cluster/task-jkl",
        )
        elb = eni(
            "eni-elb",
            "10.0.1.12",
            owner_type="LoadBalancer",
            description="ELB app/acme-online-status-alb/1111aaaa2222bbbb",
            elb_arn="arn:aws:elasticloadbalancing:eu-central-1:123:"
            "loadbalancer/app/acme-online-status-alb/1111aaaa2222bbbb",
            subnet_availability_zone="eu-central-1c",
        )
        other = eni(
            "eni-other",
            "10.0.1.13",
            owner_type="NetworkInterface",
            description="ElastiCache acme-services-prod-cache-rp-001",
        )
        lambda_eni = eni(
            "eni-lambda",
            "10.0.1.17",
            owner_type="NetworkInterface",
            description="AWS Lambda VPC ENI-test-mongo-connection-"
            "00000000-0000-4000-8000-abcdef012345",
        )

        self.assertEqual(bundle_eni_label(ec2), "acme-prod-crm")
        self.assertEqual(bundle_eni_label(unnamed_ec2), "i-0123456789abcdef0")
        self.assertEqual(bundle_eni_label(ecs), "orders-service")
        self.assertEqual(bundle_eni_label(standalone_ecs), "batch-cluster")
        self.assertEqual(bundle_eni_label(ecs_service_arn_only), "api")
        self.assertEqual(bundle_eni_label(ecs_task_arn_only), "app-cluster")
        self.assertEqual(bundle_eni_label(elb), "acme-online-status-alb (eu-central-1c)")
        self.assertEqual(
            bundle_eni_label(other),
            "ElastiCache acme-services-prod-cache-rp-001",
        )
        self.assertEqual(bundle_eni_label(lambda_eni), "test-mongo-connection")

    def test_bundle_eni_label_prefers_enriched_rds_name(self) -> None:
        rds = eni(
            "eni-rds",
            "10.0.1.18",
            owner_type="RDSInstance",
            description="RDSNetworkInterface",
            owner_name="orders-prod",
        )

        self.assertEqual(bundle_eni_label(rds), "orders-prod")

    def test_bundle_json_serializes_eni_hierarchy_and_edges(self) -> None:
        src = eni("eni-src", "10.0.1.10")
        dst = eni("eni-dst", "10.0.2.10", owner_type="RDSInstance")
        isolated = eni("eni-isolated", "10.0.3.10", owner_type="EC2Instance")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "packet_paths_bundle.json"
            render_bundle_json(
                [path(src, dst)],
                str(output_path),
                enis={item.id: item for item in (src, dst, isolated)},
            )
            data = json.loads(output_path.read_text())

        self.assertEqual(data["view"], "hierarchical-edge-bundling")
        self.assertEqual(data["node_count"], 3)
        self.assertEqual(data["edge_count"], 1)
        self.assertEqual(data["edges"][0]["source"], "eni:eni-src")
        self.assertEqual(data["edges"][0]["target"], "eni:eni-dst")
        self.assertEqual(
            next(node for node in data["nodes"] if node["eni_id"] == "eni-src")[
                "label"
            ],
            "eni-src",
        )
        self.assertIn("paths", data["edges"][0])
        self.assertIn("eni-isolated", {node["eni_id"] for node in data["nodes"]})

    def test_bundle_json_writes_frontend_data(self) -> None:
        src = eni("eni-src", "10.0.1.10")
        dst = eni("eni-dst", "10.0.2.10", owner_type="RDSInstance")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "packet_paths_bundle.json"
            render_bundle_json([path(src, dst)], str(output_path))
            data = json.loads(output_path.read_text())

        self.assertEqual(data["view"], "hierarchical-edge-bundling")
        self.assertEqual(data["node_count"], 2)
        self.assertEqual(data["edge_count"], 1)
        self.assertIn("nodes", data)
        self.assertIn("edges", data)


if __name__ == "__main__":
    unittest.main()
