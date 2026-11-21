from __future__ import annotations

import ipaddress
import unittest
from dataclasses import replace

from cartography_reachability.models import PacketSpace, ReachabilityPath, Route, SecurityGroupRule
from tests.test_overview_grouping import eni

from reachability_mcp import index as reachability_index
from reachability_mcp import server


def custom_path(
    src,
    dst,
    port: int = 5432,
    ingress_cidrs: tuple[str, ...] = ("0.0.0.0/0",),
    route_id: str = "rtb-a|10.0.0.0/16",
    route_kind: str = "local",
) -> ReachabilityPath:
    packet = PacketSpace(ipaddress.ip_network("10.0.0.0/16"), "tcp", port, port)
    egress = SecurityGroupRule(
        f"egress-{src.id}-{port}",
        "sg-src",
        "egress",
        "tcp",
        port,
        port,
        (ipaddress.ip_network("0.0.0.0/0"),),
        ("0.0.0.0/0",),
    )
    ingress_networks = tuple(ipaddress.ip_network(cidr) for cidr in ingress_cidrs)
    ingress = SecurityGroupRule(
        f"ingress-{dst.id}-{port}",
        "sg-dst",
        "ingress",
        "tcp",
        port,
        port,
        ingress_networks,
        ingress_cidrs,
    )
    route = Route(
        route_id,
        "rtb-a",
        ipaddress.ip_network("10.0.0.0/16"),
        "local" if route_kind == "local" else None,
        None,
        "pcx-123" if route_kind == "vpc_peering" else None,
        "tgw-123" if route_kind == "transit_gateway" else None,
        "active",
    )
    return ReachabilityPath(src, dst, packet, packet, packet, egress, route, ingress)


class ReachabilityMcpTest(unittest.TestCase):
    def setUp(self) -> None:
        src = replace(eni("eni-src", "10.0.1.10", owner_name="api"), account_name="prod")
        dst = replace(
            eni("eni-dst", "10.0.2.10", owner_type="RDSInstance", owner_name="orders-db"),
            account_name="prod",
        )
        internet = replace(
            eni(
                "eni-internet",
                "198.51.100.10",
                owner_type="ExternalNetwork",
                owner_name="internet",
                subnet_id="subnet-external",
                subnet_cidr="198.51.100.0/24",
                vpc_id="external",
                sg_ids=("sg-external",),
            ),
            account_name="external",
            terminal_kind="internet",
            terminal_cidr=ipaddress.ip_network("0.0.0.0/0"),
        )
        reachability_index._INDEX = reachability_index.build_reachability_index(
            [
                custom_path(src, dst, port=5432),
                custom_path(src, dst, port=3306),
                custom_path(src, dst, port=6379, route_id="rtb-peer|10.0.0.0/16", route_kind="vpc_peering"),
                custom_path(internet, dst, port=5432),
            ],
            {src.id: src, dst.id: dst, internet.id: internet},
        )

    def tearDown(self) -> None:
        reachability_index._INDEX = None

    def test_network_overview_includes_account_name_key(self) -> None:
        overview = server.network_overview()

        self.assertIn("account_name", overview["accounts"][0])

    def test_filter_entities_uses_skip_take_pagination(self) -> None:
        page = server.filter_entities(skip=0, take=1)

        self.assertEqual(page["returned"], 1)
        self.assertEqual(page["take"], 1)
        self.assertEqual(page["skip"], 0)
        self.assertEqual(page["next_skip"], 1)
        self.assertEqual(page["total"], 3)

    def test_edge_paths_uses_skip_take_pagination(self) -> None:
        source_id, destination_id = "eni:eni-src", "eni:eni-dst"

        page = server.edge_paths(source_id, destination_id, skip=0, take=1)

        self.assertEqual(page["returned"], 1)
        self.assertTrue(page["paths"][0]["path_id"].startswith("path-"))
        self.assertEqual(page["source_resource"]["resource_id"], source_id)
        self.assertEqual(page["destination_resource"]["resource_id"], destination_id)
        self.assertEqual(
            [step["type"] for step in page["paths"][0]["steps"]],
            [
                "source_resource",
                "source_attachment_eni",
                "egress_security_group_rule",
                "route",
                "ingress_security_group_rule",
                "destination_attachment_eni",
                "destination_resource",
            ],
        )
        self.assertEqual(page["paths"][0]["steps"][0]["resource"]["resource_id"], source_id)
        self.assertEqual(page["paths"][0]["steps"][1]["attachment"]["eni_id"], "eni-src")
        self.assertEqual(page["paths"][0]["steps"][2]["rule"]["security_group_id"], "sg-src")

    def test_rule_impact_ranking_includes_broad_sensitive_counts(self) -> None:
        result = server.top_security_group_rule_impacts(filters={"risk_flag": "broad_ingress"}, take=5)

        self.assertGreaterEqual(result["summary"]["rules_count"], 1)
        self.assertGreater(result["rules"][0]["broad_ingress_path_count"], 0)
        self.assertGreater(result["rules"][0]["sensitive_destination_count"], 0)

    def test_route_impact_ranking_classifies_external_boundary(self) -> None:
        result = server.top_route_impacts(filters={"external_kind": "vpc_peering"}, take=5)

        self.assertEqual(result["routes"][0]["target_kind"], "vpc_peering")
        self.assertGreater(result["routes"][0]["external_path_count"], 0)

    def test_internet_exposure_and_sensitive_summary(self) -> None:
        exposed = server.internet_exposed_resources(take=5)
        sensitive = server.sensitive_reachability_summary(kinds=["database"], take=5)

        self.assertTrue(any(row["label"].startswith("orders-db") for row in exposed["resources"]))
        self.assertEqual(sensitive["resources"][0]["service_kind"], "database")
        self.assertGreater(sensitive["resources"][0]["source_count"], 0)

    def test_filter_entities_supports_port_service_and_fields(self) -> None:
        result = server.filter_entities(
            service_kind="database",
            incoming_port=5432,
            fields=["resource_id", "service_kind"],
            take=10,
        )

        self.assertEqual(result["matches"], [{"resource_id": "eni:eni-dst", "service_kind": "database"}])

    def test_filter_entities_modes_control_inventory_detail(self) -> None:
        compact = server.filter_entities(query="orders-db", mode="compact", take=1)
        normal = server.filter_entities(query="orders-db", mode="normal", take=1)
        verbose = server.filter_entities(query="orders-db", mode="verbose", take=1)

        self.assertNotIn("member_enis", compact["matches"][0])
        self.assertIn("sample_private_ips", normal["matches"][0])
        self.assertIn("member_enis", verbose["matches"][0])

    def test_reachable_from_supports_port_protocol_and_grouping(self) -> None:
        result = server.reachable_from(
            "eni:eni-src",
            port=5432,
            protocol="tcp",
            group_by="service_kind",
            fields=["resource_id", "service_kind"],
            take=10,
        )

        self.assertEqual(result["destinations"], [{"resource_id": "eni:eni-dst", "service_kind": "database"}])
        self.assertEqual(result["grouped_counts"]["database"], 1)

    def test_edge_summary_includes_enriched_evidence(self) -> None:
        index = reachability_index.get_index()
        source_id = "eni:eni-src"
        destination_id = "eni:eni-dst"

        summary = server.edge_summary(source_id, destination_id)

        self.assertIn("source_resource", summary)
        self.assertIn("route_summaries", summary)
        self.assertIn("ingress_rule_summaries", summary)
        self.assertEqual(summary["destination_resource"]["service_kind"], "database")
        self.assertIn("representative_path_ids", summary)
        self.assertEqual(summary["edge_detail_call"]["arguments"]["edge_id"], summary["edge_id"])

    def test_edge_detail_supports_direct_edge_lookup(self) -> None:
        edge_id = reachability_index.get_index().edge_by_pair[("eni:eni-src", "eni:eni-dst")]

        detail = server.edge_detail(edge_id, take=2, include_path_explanations=True)

        self.assertEqual(detail["source_id"], "eni:eni-src")
        self.assertEqual(detail["destination_id"], "eni:eni-dst")
        self.assertEqual(detail["destination_resource"]["service_kind"], "database")
        self.assertEqual(detail["representative_paths"][0]["steps"][-2]["attachment"]["eni_id"], "eni-dst")
        self.assertEqual(detail["representative_paths"][0]["steps"][-1]["type"], "destination_resource")
        self.assertEqual(len(detail["representative_path_ids"]), 2)
        self.assertEqual(len(detail["path_explanations"]), 2)
        self.assertEqual(detail["validation_calls"][0]["tool"], "edge_summary")

    def test_path_explain_prefers_resource_context_with_attachment_evidence(self) -> None:
        index = reachability_index.get_index()
        edge_id = index.edge_by_pair[("eni:eni-src", "eni:eni-dst")]
        path_id = index.edges[edge_id]["path_ids"][0]

        text = server.path_explain(path_id, format="short")

        self.assertIn("orders-db", text)
        self.assertIn("service=database", text)
        self.assertIn("attachments eni-src -> eni-dst", text)

    def test_representative_paths_can_distinct_by_route(self) -> None:
        full = server.edge_paths("eni:eni-src", "eni:eni-dst", representative=False, take=10)
        representative = server.edge_paths(
            "eni:eni-src",
            "eni:eni-dst",
            representative=True,
            distinct_by=["route"],
            take=10,
        )

        self.assertEqual(full["returned"], 3)
        self.assertEqual(representative["returned"], 2)

    def test_external_boundary_summary_lists_cross_boundary_flows(self) -> None:
        result = server.external_boundary_summary(
            filters={"external_kind": "vpc_peering"},
            fields=["edge_id", "external_kinds"],
            take=5,
        )

        self.assertEqual(result["flows"][0]["external_kinds"], ["vpc_peering"])
        self.assertGreater(result["grouped_counts"]["external_kinds"]["vpc_peering"], 0)

    def test_impact_field_projection_preserves_summary(self) -> None:
        result = server.top_security_group_rule_impacts(fields=["rule_id"], take=1)

        self.assertEqual(list(result["rules"][0]), ["rule_id"])
        self.assertGreater(result["summary"]["affected_paths"], 0)

    def test_finding_candidates_returns_recommended_drilldowns(self) -> None:
        result = server.finding_candidates(take=5)

        self.assertGreaterEqual(result["summary"]["candidate_count"], 1)
        self.assertIn("representative_edges", result["candidates"][0])
        self.assertIn("suggested_exploration_branches", result["candidates"][0])
        self.assertIn("risk_reasons", result["candidates"][0])
        self.assertIn("impact_counts", result["candidates"][0])
        self.assertIn("rank_rationale", result["candidates"][0])
        self.assertNotIn("score", result["candidates"][0])
        self.assertNotIn("score_components", result["candidates"][0])

    def test_finding_candidates_can_include_scoring_debug(self) -> None:
        result = server.finding_candidates(take=5, include_scoring=True)

        self.assertIn("score", result["candidates"][0])
        self.assertIn("score_components", result["candidates"][0])

    def test_top_connectivity_hotspots_uses_clear_network_terms(self) -> None:
        result = server.top_connectivity_hotspots(take=1)

        self.assertEqual(result["summary"]["total_resources"], 3)
        self.assertIn("resources_with_outbound_reachability", result["summary"])
        self.assertIn("resources_with_inbound_reachability", result["summary"])
        self.assertNotIn("matching_resources", result["summary"])
        self.assertNotIn("terms", result)

    def test_investigate_candidate_expands_sg_rule_candidate(self) -> None:
        candidates = server.finding_candidates(take=20)["candidates"]
        candidate_id = next(candidate["candidate_id"] for candidate in candidates if candidate["candidate_id"].startswith("sg_rule:"))

        investigation = server.investigate_candidate(candidate_id, edge_take=1, path_explanation_take=1)

        self.assertEqual(investigation["candidate"]["candidate_id"], candidate_id)
        self.assertNotIn("score_components", investigation["candidate"])
        self.assertEqual(investigation["impact_detail"]["rule_id"], candidate_id.split(":", 1)[1])
        self.assertEqual(len(investigation["representative_edge_details"]), 1)
        self.assertEqual(len(investigation["path_explanations"]), 1)
        self.assertIn("remediation_hints", investigation)
        self.assertIn("suggested_exploration_branches", investigation)
        self.assertIn("resource_clusters", investigation["affected"])

    def test_investigate_candidate_expands_route_candidate(self) -> None:
        candidates = server.finding_candidates(take=20)["candidates"]
        candidate_id = next(candidate["candidate_id"] for candidate in candidates if candidate["candidate_id"].startswith("route:"))

        investigation = server.investigate_candidate(candidate_id, edge_take=1, path_explanation_take=0)

        self.assertEqual(investigation["impact_detail"]["route_id"], candidate_id.split(":", 1)[1])
        self.assertEqual(investigation["path_explanations"], [])

    def test_investigate_candidate_expands_internet_exposed_candidate(self) -> None:
        candidates = server.finding_candidates(take=20)["candidates"]
        candidate_id = next(candidate["candidate_id"] for candidate in candidates if candidate["candidate_id"].startswith("internet_exposed:"))

        investigation = server.investigate_candidate(candidate_id, edge_take=1, path_explanation_take=1)

        self.assertEqual(investigation["candidate"]["finding_type"], "internet_exposed_resource")
        self.assertIn("entity_detail", investigation["impact_detail"])
        self.assertIn("external_sources", investigation["impact_detail"])

    def test_investigate_candidate_rejects_unknown_candidate(self) -> None:
        with self.assertRaises(ValueError):
            server.investigate_candidate("sg_rule:does-not-exist")


if __name__ == "__main__":
    unittest.main()
