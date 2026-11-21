from __future__ import annotations

import ipaddress
import unittest

from cartography_reachability.loader import CartographyLoader, RdsEndpointMatch
from tests.test_overview_grouping import eni


class RdsDnsEnrichmentTest(unittest.TestCase):
    def test_rds_endpoint_match_relabels_rds_network_interface(self) -> None:
        rds_eni = eni(
            "eni-rds",
            "10.0.2.15",
            owner_type="NetworkInterface",
            description="RDSNetworkInterface",
            owner_name="RDSNetworkInterface",
        )
        match = RdsEndpointMatch(
            db_instance_identifier="orders-prod",
            endpoint_address="orders-prod.abc.eu-central-1.rds.amazonaws.com",
            private_ips=(ipaddress.ip_address("10.0.2.15"),),
            owner_id="db-ABC123",
            owner_arn="arn:aws:rds:eu-central-1:123:db:orders-prod",
            account_id="123",
            region="eu-central-1",
        )

        enriched = CartographyLoader.enrich_rds_enis(
            {rds_eni.id: rds_eni}, [match]
        )[rds_eni.id]

        self.assertEqual(enriched.owner_type, "RDSInstance")
        self.assertEqual(enriched.owner_name, "orders-prod")
        self.assertEqual(enriched.owner_id, "db-ABC123")
        self.assertIn("RDSInstance", enriched.owner_labels)
        self.assertEqual(enriched.as_node()["name"], "orders-prod")

    def test_rds_endpoint_match_does_not_overwrite_non_rds_eni(self) -> None:
        ec2_eni = eni(
            "eni-ec2",
            "10.0.2.15",
            owner_type="EC2Instance",
            owner_name="app-server",
        )
        match = RdsEndpointMatch(
            db_instance_identifier="orders-prod",
            endpoint_address="orders-prod.abc.eu-central-1.rds.amazonaws.com",
            private_ips=(ipaddress.ip_address("10.0.2.15"),),
            owner_id="db-ABC123",
            owner_arn=None,
            account_id=None,
            region=None,
        )

        enriched = CartographyLoader.enrich_rds_enis(
            {ec2_eni.id: ec2_eni}, [match]
        )[ec2_eni.id]

        self.assertEqual(enriched.owner_type, "EC2Instance")
        self.assertEqual(enriched.owner_name, "app-server")

    def test_ambiguous_rds_endpoint_match_is_skipped(self) -> None:
        rds_eni = eni(
            "eni-rds",
            "10.0.2.15",
            owner_type="NetworkInterface",
            description="RDSNetworkInterface",
        )
        first = RdsEndpointMatch(
            db_instance_identifier="orders-prod-a",
            endpoint_address="orders-a.example.com",
            private_ips=(ipaddress.ip_address("10.0.2.15"),),
            owner_id="db-A",
            owner_arn=None,
            account_id=None,
            region=None,
        )
        second = RdsEndpointMatch(
            db_instance_identifier="orders-prod-b",
            endpoint_address="orders-b.example.com",
            private_ips=(ipaddress.ip_address("10.0.2.15"),),
            owner_id="db-B",
            owner_arn=None,
            account_id=None,
            region=None,
        )

        enriched = CartographyLoader.enrich_rds_enis(
            {rds_eni.id: rds_eni}, [first, second]
        )[rds_eni.id]

        self.assertEqual(enriched.owner_type, "NetworkInterface")
        self.assertNotEqual(enriched.owner_name, "orders-prod-a")


if __name__ == "__main__":
    unittest.main()
