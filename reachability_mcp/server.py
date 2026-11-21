from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Annotated, Any

from pydantic import Field

try:
    from fastmcp import FastMCP
except ModuleNotFoundError:  # Compatibility with the older official MCP package.
    from mcp.server.fastmcp import FastMCP

try:
    from .index import entity_summary, get_index, packet_label, paginate, port_values, refresh_index
except ImportError:  # Support `python reachability_mcp/server.py` during inspector runs.
    from reachability_mcp.index import (
        entity_summary,
        get_index,
        packet_label,
        paginate,
        port_values,
        refresh_index,
    )

mcp = FastMCP("cartography-reachability")


def tool(func: Any) -> Any:
    return mcp.tool(func)


SENSITIVE_KINDS = {"database", "cache", "admin", "search", "messaging", "monitoring", "identity"}
SCORE_WEIGHTS = {
    "affected_paths": 1,
    "affected_source_count": 3,
    "affected_destination_count": 3,
    "external_path_count": 5,
    "wildcard_path_count": 4,
    "broad_ingress_path_count": 4,
    "sensitive_destination_count": 5,
}
ENTITY_COMPACT_FIELDS = [
    "resource_id",
    "label",
    "resource_type",
    "account_id",
    "account_name",
    "region",
    "vpc_id",
    "incoming_edges",
    "outgoing_edges",
    "path_count_in",
    "path_count_out",
    "risk_flags",
    "service_kind",
    "internet_exposed",
    "external_kinds",
    "grouping_status",
]
ENTITY_NORMAL_EXTRA_FIELDS = ["member_eni_count", "sample_private_ips", "eni_ids", "owner_hints"]


def normalize_mode(mode: str | None) -> str:
    return mode if mode in {"compact", "normal", "verbose"} else "compact"


def apply_fields(row: dict[str, Any], fields: list[str] | None) -> dict[str, Any]:
    if not fields:
        return row
    return {field: row.get(field) for field in fields}


def format_entity(
    entity: dict[str, Any],
    mode: str = "compact",
    fields: list[str] | None = None,
    include_member_enis: bool = False,
    sample_limit: int = 3,
) -> dict[str, Any]:
    mode = normalize_mode(mode)
    row = {field: entity.get(field) for field in ENTITY_COMPACT_FIELDS}
    row["member_eni_count"] = len(entity.get("member_enis", []))
    if mode in {"normal", "verbose"}:
        row.update({field: entity.get(field) for field in ENTITY_NORMAL_EXTRA_FIELDS})
        row["sample_private_ips"] = entity.get("private_ips", [])[:sample_limit]
        row["eni_ids"] = [eni["eni_id"] for eni in entity.get("member_enis", [])[:sample_limit]]
    if include_member_enis or mode == "verbose":
        row["member_enis"] = entity.get("member_enis", [])
        row["arn"] = entity.get("arn")
        row["subnet_ids"] = entity.get("subnet_ids", [])
        row["security_groups"] = entity.get("security_groups", [])
    return apply_fields(row, fields)


def format_entities(
    entities: list[dict[str, Any]],
    mode: str,
    fields: list[str] | None,
    include_member_enis: bool,
    sample_limit: int,
) -> list[dict[str, Any]]:
    return [
        format_entity(entity, mode, fields, include_member_enis, sample_limit)
        for entity in entities
    ]


def entity_ref(entity: dict[str, Any]) -> dict[str, Any]:
    row = {
        "resource_id": entity["resource_id"],
        "label": entity["label"],
        "resource_type": entity.get("resource_type"),
        "account_id": entity.get("account_id"),
        "account_name": entity.get("account_name"),
        "region": entity.get("region"),
        "vpc_id": entity.get("vpc_id"),
        "service_kind": entity.get("service_kind"),
    }
    if entity.get("grouping_status"):
        row["grouping_status"] = entity.get("grouping_status")
    member_count = len(entity.get("member_enis", []))
    if member_count:
        row["member_eni_count"] = member_count
    if entity.get("resource_type") == "NetworkInterface" and entity.get("owner_hints"):
        row["owner_hints"] = entity.get("owner_hints")
    return row


def attachment_ref(path: dict[str, Any], side: str) -> dict[str, Any]:
    return {
        "eni_id": path[f"{side}_eni"],
        "private_ip": path.get(f"{side}_private_ip"),
        "resource_id": path.get(f"{side}_id"),
        "resource_label": path.get(f"{side}_label"),
        "resource_type": path.get(f"{side}_resource_type"),
    }


def security_group_rule_ref(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": rule.get("id"),
        "security_group_id": rule.get("sg_id"),
        "direction": rule.get("direction"),
        "protocol": rule.get("protocol"),
        "from_port": rule.get("from_port"),
        "to_port": rule.get("to_port"),
        "cidrs": rule.get("cidrs", []),
    }


def route_ref(route: dict[str, Any]) -> dict[str, Any]:
    return {
        "route_id": route.get("id"),
        "route_table_id": route.get("route_table_id"),
        "destination": route.get("destination"),
        "target_kind": route.get("target_kind"),
        "target": route.get("target"),
    }


def path_steps(index: Any, path: dict[str, Any]) -> list[dict[str, Any]]:
    source = index.entities[path["source_id"]]
    destination = index.entities[path["destination_id"]]
    steps = [
        {"type": "source_resource", "resource": entity_ref(source)},
        {"type": "source_attachment_eni", "attachment": attachment_ref(path, "source")},
    ]
    if path.get("elb_target"):
        steps.append({"type": "load_balancer_forwarding", "target": path["elb_target"]})
    steps.extend(
        [
            {
                "type": "egress_security_group_rule",
                "rule": security_group_rule_ref(path["egress_rule"]),
                "packet": path["packet"],
            },
            {
                "type": "route",
                "route": route_ref(path["route"]),
                "packet": path["packet"],
            },
        ]
    )
    if path.get("tgw_hop"):
        steps.append({"type": "transit_gateway_hop", "hop": path["tgw_hop"]})
    steps.extend(
        [
            {
                "type": "ingress_security_group_rule",
                "rule": security_group_rule_ref(path["ingress_rule"]),
                "packet": path["packet"],
            },
            {"type": "destination_attachment_eni", "attachment": attachment_ref(path, "destination")},
            {"type": "destination_resource", "resource": entity_ref(destination)},
        ]
    )
    return steps


def entity_edge_ids(index: Any, entity_id: str, direction: str | None = None) -> list[str]:
    if direction == "incoming":
        return index.incoming.get(entity_id, [])
    if direction == "outgoing":
        return index.outgoing.get(entity_id, [])
    return index.incoming.get(entity_id, []) + index.outgoing.get(entity_id, [])


def port_range_contains(value: Any, wanted: int) -> bool:
    if value in (None, "", "*"):
        return True
    for part in str(value).split(","):
        part = part.strip()
        if not part or part == "*":
            return True
        if "-" in part:
            start, end = part.split("-", 1)
            if start.isdigit() and end.isdigit() and int(start) <= wanted <= int(end):
                return True
            continue
        if part.isdigit() and int(part) == wanted:
            return True
    return False


def edge_has_port(edge: dict[str, Any], port: int | str | None) -> bool:
    if port is None:
        return True
    wanted = int(port)
    return any(port_range_contains(value, wanted) for value in edge.get("ports", []))


def edge_has_protocol(edge: dict[str, Any], protocol: str | None) -> bool:
    return protocol is None or protocol in edge.get("protocols", [])


def entity_has_edge_match(
    index: Any,
    entity_id: str,
    direction: str | None = None,
    port: int | str | None = None,
    protocol: str | None = None,
    rule_id: str | None = None,
) -> bool:
    for edge_id in entity_edge_ids(index, entity_id, direction):
        edge = index.edges[edge_id]
        if not edge_has_port(edge, port) or not edge_has_protocol(edge, protocol):
            continue
        if rule_id and rule_id not in set(edge.get("egress_rules", []) + edge.get("ingress_rules", [])):
            continue
        return True
    return False


def sorted_impacts(
    impacts: dict[str, dict[str, Any]],
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    rows = []
    filters = filters or {}
    for impact in impacts.values():
        if filters.get("direction") and impact.get("direction") != filters["direction"]:
            continue
        if filters.get("risk_flag") and impact.get("grouped_counts", {}).get("risk_flags", {}).get(filters["risk_flag"], 0) == 0:
            continue
        if filters.get("external_kind") and impact.get("grouped_counts", {}).get("external_kinds", {}).get(filters["external_kind"], 0) == 0:
            continue
        if filters.get("target_kind") and impact.get("target_kind") != filters["target_kind"]:
            continue
        rows.append(impact)
    return sorted(rows, key=lambda row: (row.get("score", 0), row.get("affected_paths", 0)), reverse=True)


def pagination_meta(page: dict[str, Any]) -> dict[str, Any]:
    return {key: page[key] for key in ("skip", "take", "returned", "total", "next_skip")}


def entity_matches_filters(entity: dict[str, Any], filters: dict[str, Any] | None) -> bool:
    filters = filters or {}
    if filters.get("resource_type") and entity.get("resource_type") != filters["resource_type"]:
        return False
    if filters.get("account_id") and entity.get("account_id") != filters["account_id"]:
        return False
    if filters.get("region") and entity.get("region") != filters["region"]:
        return False
    if filters.get("vpc_id") and entity.get("vpc_id") != filters["vpc_id"]:
        return False
    if filters.get("service_kind") and entity.get("service_kind") != filters["service_kind"]:
        return False
    if filters.get("internet_exposed") is not None and entity.get("internet_exposed") != filters["internet_exposed"]:
        return False
    if filters.get("external_kind") and filters["external_kind"] not in entity.get("external_kinds", []):
        return False
    if filters.get("risk_flag") and filters["risk_flag"] not in entity.get("risk_flags", []):
        return False
    return True


def impact_path_ids(index: Any, impact: dict[str, Any]) -> list[str]:
    if impact.get("rule_id"):
        return index.rule_to_paths.get(impact["rule_id"], [])
    if impact.get("route_id"):
        return index.route_to_paths.get(impact["route_id"], [])
    return []


def impact_matches_filters(index: Any, impact: dict[str, Any], filters: dict[str, Any] | None) -> bool:
    filters = filters or {}
    if filters.get("direction") and impact.get("direction") != filters["direction"]:
        return False
    if filters.get("security_group_id") and impact.get("security_group_id") != filters["security_group_id"]:
        return False
    if filters.get("target_kind") and impact.get("target_kind") != filters["target_kind"]:
        return False
    if filters.get("risk_flag") and impact.get("grouped_counts", {}).get("risk_flags", {}).get(filters["risk_flag"], 0) == 0:
        return False
    if filters.get("external_kind") and impact.get("grouped_counts", {}).get("external_kinds", {}).get(filters["external_kind"], 0) == 0:
        return False
    if filters.get("protocol") and impact.get("grouped_counts", {}).get("protocols", {}).get(filters["protocol"], 0) == 0:
        return False
    if filters.get("port"):
        wanted = int(filters["port"])
        if not any(
            port_range_contains(value, wanted)
            for value in impact.get("grouped_counts", {}).get("ports", {})
        ):
            return False

    entity_filters = {
        key: filters.get(key)
        for key in ("resource_type", "account_id", "region", "vpc_id", "service_kind", "internet_exposed")
        if key in filters
    }
    if not entity_filters:
        return True
    for path_id in impact_path_ids(index, impact):
        path = index.paths[path_id]
        if entity_matches_filters(index.entities[path["source_id"]], entity_filters):
            return True
        if entity_matches_filters(index.entities[path["destination_id"]], entity_filters):
            return True
    return False


def path_edge_samples(index: Any, path_ids: list[str]) -> list[dict[str, Any]]:
    rows = []
    seen_edges = set()
    for path_id in path_ids:
        path = index.paths[path_id]
        edge_id = path["edge_id"]
        if edge_id in seen_edges:
            continue
        seen_edges.add(edge_id)
        edge = index.edges[edge_id]
        rows.append(
            {
                "edge_id": edge_id,
                "source_resource": entity_ref(index.entities[edge["source_id"]]),
                "destination_resource": entity_ref(index.entities[edge["destination_id"]]),
                "packets": edge.get("packet_labels", []),
                "risk_flags": edge.get("risk_flags", []),
                "external_kinds": edge.get("external_kinds", []),
            }
        )
    return rows


def edge_ref(index: Any, edge_id: str) -> dict[str, Any]:
    edge = index.edges[edge_id]
    source = index.entities[edge["source_id"]]
    destination = index.entities[edge["destination_id"]]
    return {
        "edge_id": edge_id,
        "source_id": edge["source_id"],
        "destination_id": edge["destination_id"],
        "source_resource": entity_ref(source),
        "destination_resource": entity_ref(destination),
        "path_count": edge.get("path_count", 0),
        "packet_labels": edge.get("packet_labels", []),
        "risk_flags": edge.get("risk_flags", []),
        "external_kinds": edge.get("external_kinds", []),
    }


def path_row(index: Any, path_id: str) -> dict[str, Any]:
    path = index.paths[path_id]
    return {
        "path_id": path_id,
        "edge_id": path["edge_id"],
        "steps": path_steps(index, path),
        "packet": path["packet"],
        "external_kind": path.get("external_kind"),
        "risk_flags": path.get("risk_flags", []),
    }


def representative_paths_for_edge(
    index: Any,
    edge_id: str,
    representative: bool = True,
    distinct_by: list[str] | None = None,
) -> list[dict[str, Any]]:
    edge = index.edges[edge_id]
    rows = [path_row(index, path_id) for path_id in edge.get("path_ids", [])]
    return representative_path_rows(rows, distinct_by) if representative else rows


def edge_detail_payload(
    index: Any,
    edge_id: str,
    representative: bool = True,
    distinct_by: list[str] | None = None,
    take: int = 3,
    include_path_explanations: bool = False,
) -> dict[str, Any]:
    edge = index.edges[edge_id]
    source = index.entities[edge["source_id"]]
    destination = index.entities[edge["destination_id"]]
    packet_spaces = []
    for value in edge.get("packet_spaces", []):
        try:
            packet_spaces.append(json.loads(value))
        except (TypeError, json.JSONDecodeError):
            packet_spaces.append(value)
    representative_rows = representative_paths_for_edge(index, edge_id, representative, distinct_by)
    representative_rows = representative_rows[: max(1, min(int(take), 500))]
    representative_path_ids = [row["path_id"] for row in representative_rows]
    payload = {
        "edge_id": edge_id,
        "source_id": edge["source_id"],
        "destination_id": edge["destination_id"],
        "source_resource": entity_ref(source),
        "destination_resource": entity_ref(destination),
        "path_count": edge["path_count"],
        "packet_labels": edge.get("packet_labels", []),
        "packet_spaces": packet_spaces,
        "routes": edge.get("routes", []),
        "route_summaries": edge.get("route_summaries", []),
        "egress_rules": edge.get("egress_rules", []),
        "egress_rule_summaries": edge.get("egress_rule_summaries", []),
        "ingress_rules": edge.get("ingress_rules", []),
        "ingress_rule_summaries": edge.get("ingress_rule_summaries", []),
        "tgw_hops": edge.get("tgw_hops", []),
        "elb_target_groups": edge.get("elb_target_groups", []),
        "load_balancer_forwarding": edge.get("load_balancer_forwarding", []),
        "route_targets": edge.get("route_targets", []),
        "external_kinds": edge.get("external_kinds", []),
        "risk_flags": edge.get("risk_flags", []),
        "representative": representative,
        "distinct_by": distinct_by
        or ["packet", "route", "ingress_rule", "egress_rule", "destination_attachment_eni", "load_balancer_forwarding"],
        "representative_path_ids": representative_path_ids,
        "representative_paths": representative_rows,
        "validation_calls": [
            {"tool": "edge_summary", "arguments": {"source_id": edge["source_id"], "destination_id": edge["destination_id"]}},
            {
                "tool": "edge_paths",
                "arguments": {
                    "source_id": edge["source_id"],
                    "destination_id": edge["destination_id"],
                    "representative": True,
                    "take": take,
                },
            },
        ],
    }
    if representative_path_ids:
        payload["validation_calls"].append(
            {"tool": "path_explain", "arguments": {"path_id": representative_path_ids[0], "format": "short"}}
        )
    if include_path_explanations:
        payload["path_explanations"] = [
            {"path_id": path_id, "text": path_explain_text(index, path_id, "short")}
            for path_id in representative_path_ids
        ]
    return payload


def compact_impact(row: dict[str, Any], sample_limit: int = 3) -> dict[str, Any]:
    compact = {
        key: row.get(key)
        for key in (
            "rule_id",
            "route_id",
            "security_group_id",
            "direction",
            "route_table_id",
            "destination",
            "target_kind",
            "target",
            "affected_paths",
            "affected_source_count",
            "affected_destination_count",
            "external_path_count",
            "wildcard_path_count",
            "broad_ingress_path_count",
            "sensitive_destination_count",
            "packets",
            "score",
        )
        if key in row
    }
    compact["grouped_counts"] = row.get("grouped_counts", {})
    compact["sample_edges"] = row.get("sample_edges", [])[:sample_limit]
    return compact


def grouped_entity_counts(entities: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "resource_types": dict(Counter(entity.get("resource_type") or "unknown" for entity in entities)),
        "accounts": dict(Counter(entity.get("account_id") or "unknown" for entity in entities)),
        "regions": dict(Counter(entity.get("region") or "unknown" for entity in entities)),
        "vpcs": dict(Counter(entity.get("vpc_id") or "unknown" for entity in entities)),
        "service_kinds": dict(Counter(entity.get("service_kind") or "unknown" for entity in entities)),
        "risk_flags": dict(Counter(flag for entity in entities for flag in entity.get("risk_flags", []))),
        "external_kinds": dict(Counter(kind for entity in entities for kind in entity.get("external_kinds", []))),
    }


def grouped_edge_counts(index: Any, edges: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_resource_types": dict(Counter(edge.get("source_resource_type") or "unknown" for edge in edges)),
        "destination_resource_types": dict(Counter(edge.get("destination_resource_type") or "unknown" for edge in edges)),
        "risk_flags": dict(Counter(flag for edge in edges for flag in edge.get("risk_flags", []))),
        "external_kinds": dict(Counter(kind for edge in edges for kind in edge.get("external_kinds", []))),
        "protocols": dict(Counter(protocol for edge in edges for protocol in edge.get("protocols", []))),
        "ports": dict(Counter(port for edge in edges for port in edge.get("ports", []))),
        "source_accounts": dict(
            Counter(index.entities[edge["source_id"]].get("account_id") or "unknown" for edge in edges)
        ),
        "destination_accounts": dict(
            Counter(index.entities[edge["destination_id"]].get("account_id") or "unknown" for edge in edges)
        ),
    }


@tool
def network_overview() -> dict[str, Any]:
    """Return a compact overview of the loaded network reachability graph."""
    index = get_index()
    resource_types = Counter(entity.get("resource_type") for entity in index.entities.values())
    accounts = defaultdict(lambda: {"account_name": None, "resources": 0, "paths": 0})
    regions = defaultdict(lambda: {"resources": 0, "paths": 0})
    for entity in index.entities.values():
        account = entity.get("account_id") or "unknown"
        region = entity.get("region") or "unknown"
        account_name = entity.get("account_name")
        if account_name and not accounts[account]["account_name"]:
            accounts[account]["account_name"] = account_name
        accounts[account]["resources"] += 1
        accounts[account]["paths"] += entity.get("path_count_out", 0)
        regions[region]["resources"] += 1
        regions[region]["paths"] += entity.get("path_count_out", 0)

    return {
        "resource_count": len(index.entities),
        "eni_count": len(index.eni_to_entity),
        "edge_count": len(index.edges),
        "path_count": len(index.paths),
        "resource_types": dict(sorted(resource_types.items())),
        "accounts": [dict(account_id=key, **value) for key, value in sorted(accounts.items())],
        "regions": [dict(region=key, **value) for key, value in sorted(regions.items())],
        "notable_flags": {
            f"{flag}_edges": len(set(edge_ids))
            for flag, edge_ids in sorted(index.risk_to_edges.items())
        },
    }


@tool
def filter_entities(
    query: Annotated[
        str | None,
        Field(description="Case-insensitive substring to match against labels, IDs, ARNs, accounts, IPs, ENIs, and security groups."),
    ] = None,
    resource_type: Annotated[
        str | None,
        Field(description="Exact resource type filter, such as ECSService, EC2Instance, LoadBalancer, RDSInstance, or ExternalNetwork."),
    ] = None,
    account_id: Annotated[str | None, Field(description="AWS account ID to match exactly.")] = None,
    region: Annotated[str | None, Field(description="AWS region to match exactly, for example eu-central-1.")] = None,
    vpc_id: Annotated[str | None, Field(description="VPC ID to match exactly.")] = None,
    subnet_id: Annotated[str | None, Field(description="Subnet ID that must contain at least one member ENI.")] = None,
    security_group_id: Annotated[str | None, Field(description="Security group ID attached to at least one member ENI.")] = None,
    private_ip: Annotated[str | None, Field(description="Private IPv4 address of a member ENI.")] = None,
    eni_id: Annotated[str | None, Field(description="Network interface ID contained by the entity.")] = None,
    has_public_ip: Annotated[bool | None, Field(description="When set, require entities to have or not have public IPs.")] = None,
    has_incoming: Annotated[bool | None, Field(description="When set, require entities to have or not have incoming reachability edges.")] = None,
    has_outgoing: Annotated[bool | None, Field(description="When set, require entities to have or not have outgoing reachability edges.")] = None,
    risk_flag: Annotated[
        str | None,
        Field(description="Assessment flag that must be present, such as broad_ingress, wildcard, external, transit_gateway, or load_balancer_forwarding."),
    ] = None,
    port: Annotated[int | None, Field(description="Require at least one incoming or outgoing edge with this TCP/UDP port.")] = None,
    protocol: Annotated[str | None, Field(description="Require at least one incoming or outgoing edge with this protocol.")] = None,
    incoming_port: Annotated[int | None, Field(description="Require at least one incoming edge with this TCP/UDP port.")] = None,
    outgoing_port: Annotated[int | None, Field(description="Require at least one outgoing edge with this TCP/UDP port.")] = None,
    external_kind: Annotated[
        str | None,
        Field(description="External boundary kind to match, such as internet, vpc_peering, transit_gateway, vpn, direct_connect, or unknown_external."),
    ] = None,
    internet_exposed: Annotated[bool | None, Field(description="When set, require resources classified as internet exposed or not internet exposed.")] = None,
    service_kind: Annotated[
        str | None,
        Field(description="Inferred service kind, such as database, cache, admin, load_balancer, messaging, search, monitoring, identity, or unknown."),
    ] = None,
    security_group_rule_id: Annotated[
        str | None,
        Field(description="Require at least one incoming or outgoing edge that depends on this security group rule ID."),
    ] = None,
    mode: Annotated[str, Field(description="Output detail mode: compact, normal, or verbose.")] = "compact",
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each matched resource row.")] = None,
    include_member_enis: Annotated[bool, Field(description="Include full member ENI arrays. Defaults to false for compact assessment output.")] = False,
    sample_limit: Annotated[int, Field(description="Number of private IP and ENI samples to include in non-compact rows.", ge=1)] = 3,
    skip: Annotated[int, Field(description="Number of matching entities to skip before returning results.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum number of matching entities to return, capped at 500.", ge=1)] = 50,
) -> dict[str, Any]:
    """Find resources/workloads using structured filters.

    Args:
        query: Case-insensitive text query over identifiers, labels, ARNs, account names, IPs, ENIs, and security groups.
        resource_type: Exact resource type to return.
        account_id: Exact AWS account ID to return.
        region: Exact AWS region to return.
        vpc_id: Exact VPC ID to return.
        subnet_id: Subnet ID that must contain a member ENI.
        security_group_id: Security group ID that must be attached to a member ENI.
        private_ip: Private IP that must belong to a member ENI.
        eni_id: ENI ID that must belong to the entity.
        has_public_ip: Filter by whether the entity has any public IP.
        has_incoming: Filter by whether the entity has incoming reachability.
        has_outgoing: Filter by whether the entity has outgoing reachability.
        risk_flag: Filter by a computed assessment risk flag.
        port: Filter by either incoming or outgoing packet port.
        protocol: Filter by either incoming or outgoing packet protocol.
        incoming_port: Filter by incoming packet port.
        outgoing_port: Filter by outgoing packet port.
        external_kind: Filter by classified external boundary kind.
        internet_exposed: Filter by internet exposure classification.
        service_kind: Filter by inferred service kind.
        security_group_rule_id: Filter by SG rule dependency.
        mode: Output detail mode.
        fields: Optional row field projection.
        include_member_enis: Include full member ENI details.
        sample_limit: Number of sample IPs/ENIs in normal rows.
        skip: Number of matches to skip.
        take: Number of matches to return.
    """
    index = get_index()
    query_lc = query.lower() if query else None

    def matches(entity: dict[str, Any]) -> bool:
        if resource_type and entity.get("resource_type") != resource_type:
            return False
        if account_id and entity.get("account_id") != account_id:
            return False
        if region and entity.get("region") != region:
            return False
        if vpc_id and entity.get("vpc_id") != vpc_id:
            return False
        if subnet_id and subnet_id not in entity.get("subnet_ids", []):
            return False
        if security_group_id and security_group_id not in entity.get("security_groups", []):
            return False
        if private_ip and private_ip not in entity.get("private_ips", []):
            return False
        if eni_id and eni_id not in [eni["eni_id"] for eni in entity.get("member_enis", [])]:
            return False
        if has_public_ip is not None and bool(entity.get("public_ips")) != has_public_ip:
            return False
        if has_incoming is not None and bool(entity.get("incoming_edges")) != has_incoming:
            return False
        if has_outgoing is not None and bool(entity.get("outgoing_edges")) != has_outgoing:
            return False
        if risk_flag and risk_flag not in entity.get("risk_flags", []):
            return False
        if internet_exposed is not None and bool(entity.get("internet_exposed")) != internet_exposed:
            return False
        if external_kind and external_kind not in entity.get("external_kinds", []):
            return False
        if service_kind and entity.get("service_kind") != service_kind:
            return False
        if port is not None and not entity_has_edge_match(index, entity["resource_id"], port=port, protocol=protocol):
            return False
        if protocol is not None and port is None and not entity_has_edge_match(index, entity["resource_id"], protocol=protocol):
            return False
        if incoming_port is not None and not entity_has_edge_match(
            index, entity["resource_id"], direction="incoming", port=incoming_port, protocol=protocol
        ):
            return False
        if outgoing_port is not None and not entity_has_edge_match(
            index, entity["resource_id"], direction="outgoing", port=outgoing_port, protocol=protocol
        ):
            return False
        if security_group_rule_id and not entity_has_edge_match(
            index, entity["resource_id"], rule_id=security_group_rule_id
        ):
            return False
        if query_lc:
            haystack = " ".join(
                str(value)
                for value in [
                    entity.get("resource_id"),
                    entity.get("label"),
                    entity.get("resource_type"),
                    entity.get("arn"),
                    entity.get("account_id"),
                    entity.get("account_name"),
                    entity.get("region"),
                    entity.get("vpc_id"),
                    entity.get("service_kind"),
                    entity.get("grouping_status"),
                    *entity.get("private_ips", []),
                    *entity.get("public_ips", []),
                    *entity.get("security_groups", []),
                    *[eni.get("eni_id") for eni in entity.get("member_enis", [])],
                ]
                if value
            ).lower()
            return query_lc in haystack
        return True

    matches_list = sorted(
        [entity for entity in index.entities.values() if matches(entity)],
        key=lambda item: (item["label"].lower(), item["resource_id"]),
    )
    page = paginate(matches_list, skip, take)
    rows = format_entities(page["items"], mode, fields, include_member_enis, sample_limit)
    return {
        "matches": rows,
        "summary": {"matching_resources": page["total"], "returned": page["returned"]},
        "grouped_counts": grouped_entity_counts(matches_list),
        **pagination_meta(page),
    }


@tool
def entity_detail(
    resource_id: Annotated[str, Field(description="Resource/workload ID returned by filter_entities, reachable_from, can_reach, or network edge tools.")],
    include_rule_summaries: Annotated[bool, Field(description="Include compact summaries of SG rules involved in this entity's incoming/outgoing edges.")] = False,
    include_route_summaries: Annotated[bool, Field(description="Include compact summaries of routes involved in this entity's incoming/outgoing edges.")] = False,
    include_member_enis: Annotated[bool, Field(description="Include full member ENI inventory for this entity.")] = True,
) -> dict[str, Any]:
    """Return identity, inventory, and reachability counts for one resource.

    Args:
        resource_id: Entity ID to inspect.
        include_rule_summaries: Include compact SG rule summaries.
        include_route_summaries: Include compact route summaries.
        include_member_enis: Include raw member ENI inventory.
    """
    index = get_index()
    entity = index.entities[resource_id]
    edge_ids = entity_edge_ids(index, resource_id)
    result = {
        "resource_id": entity["resource_id"],
        "label": entity["label"],
        "resource_type": entity["resource_type"],
        "arn": entity.get("arn"),
        "account_id": entity.get("account_id"),
        "account_name": entity.get("account_name"),
        "region": entity.get("region"),
        "vpc_id": entity.get("vpc_id"),
        "subnet_ids": entity.get("subnet_ids", []),
        "security_groups": entity.get("security_groups", []),
        "member_eni_count": len(entity.get("member_enis", [])),
        "incoming_edges": entity.get("incoming_edges", 0),
        "outgoing_edges": entity.get("outgoing_edges", 0),
        "path_count_in": entity.get("path_count_in", 0),
        "path_count_out": entity.get("path_count_out", 0),
        "risk_flags": entity.get("risk_flags", []),
        "service_kind": entity.get("service_kind"),
        "service_kind_inferred": entity.get("service_kind_inferred"),
        "internet_exposed": entity.get("internet_exposed"),
        "external_kinds": entity.get("external_kinds", []),
        "grouping_status": entity.get("grouping_status"),
        "owner_hints": entity.get("owner_hints", {}),
    }
    if include_member_enis:
        result["member_enis"] = entity.get("member_enis", [])
    if include_rule_summaries:
        rule_ids = sorted(
            {
                rule_id
                for edge_id in edge_ids
                for rule_id in index.edges[edge_id].get("egress_rules", []) + index.edges[edge_id].get("ingress_rules", [])
            }
        )
        result["rule_summaries"] = [index.rule_summaries[rule_id] for rule_id in rule_ids if rule_id in index.rule_summaries]
    if include_route_summaries:
        route_ids = sorted({route_id for edge_id in edge_ids for route_id in index.edges[edge_id].get("routes", [])})
        result["route_summaries"] = [index.route_summaries[route_id] for route_id in route_ids if route_id in index.route_summaries]
    return result


@tool
def top_connectivity_hotspots(
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional entity filters: resource_type, account_id, region, vpc_id, service_kind, internet_exposed, external_kind, and/or risk_flag."),
    ] = None,
    mode: Annotated[str, Field(description="Output detail mode for resource rows: compact, normal, or verbose.")] = "compact",
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each hotspot row.")] = None,
    include_member_enis: Annotated[bool, Field(description="Include full member ENI arrays in hotspot rows.")] = False,
    sample_limit: Annotated[int, Field(description="Number of IP/ENI samples in non-compact rows.", ge=1)] = 3,
    skip: Annotated[int, Field(description="Number of ranked source/destination rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum ranked source/destination rows to return per list, capped at 500.", ge=1)] = 10,
) -> dict[str, Any]:
    """Return high fan-out and high fan-in resources.

    Args:
        filters: Optional entity filters.
        mode: Output detail mode.
        fields: Optional hotspot field projection.
        include_member_enis: Include full member ENIs.
        sample_limit: Number of sample IPs/ENIs in normal rows.
        skip: Number of ranked rows to skip in both source and destination lists.
        take: Number of ranked rows to return in both source and destination lists.
    """
    index = get_index()
    entities = [entity for entity in index.entities.values() if entity_matches_filters(entity, filters)]
    source_rows = sorted(
        [entity for entity in entities if entity.get("outgoing_edges", 0) > 0],
        key=lambda item: (item.get("outgoing_edges", 0), item.get("path_count_out", 0)),
        reverse=True,
    )
    destination_rows = sorted(
        [entity for entity in entities if entity.get("incoming_edges", 0) > 0],
        key=lambda item: (item.get("incoming_edges", 0), item.get("path_count_in", 0)),
        reverse=True,
    )

    def hotspot(entity: dict[str, Any], direction: str) -> dict[str, Any]:
        row = format_entity(entity, mode, None, include_member_enis, sample_limit)
        row[f"{direction}_edges"] = entity.get(f"{direction}_edges", 0)
        row["path_count"] = entity.get("path_count_out" if direction == "outgoing" else "path_count_in", 0)
        return apply_fields(row, fields)

    source_page = paginate([hotspot(entity, "outgoing") for entity in source_rows], skip, take)
    destination_page = paginate([hotspot(entity, "incoming") for entity in destination_rows], skip, take)
    return {
        "summary": {
            "total_resources": len(entities),
            "resources_with_outbound_reachability": len(source_rows),
            "resources_with_inbound_reachability": len(destination_rows),
        },
        "grouped_counts": grouped_entity_counts(entities),
        "top_sources": source_page["items"],
        "top_destinations": destination_page["items"],
        "pagination": {
            "skip": skip,
            "take": take,
            "sources_returned": source_page["returned"],
            "sources_total": source_page["total"],
            "sources_next_skip": source_page["next_skip"],
            "destinations_returned": destination_page["returned"],
            "destinations_total": destination_page["total"],
            "destinations_next_skip": destination_page["next_skip"],
        },
    }


@tool
def reachable_from(
    resource_id: Annotated[str, Field(description="Source resource/workload ID to inspect.")],
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional edge filters: resource_type, protocol, port, risk_flag, external_kind, service_kind, and/or security_group_rule_id."),
    ] = None,
    port: Annotated[int | None, Field(description="Only return destinations reachable on this packet port.")] = None,
    protocol: Annotated[str | None, Field(description="Only return destinations reachable with this protocol.")] = None,
    external_only: Annotated[bool, Field(description="Only return edges with external boundary evidence.")] = False,
    sensitive_only: Annotated[bool, Field(description="Only return destinations classified as sensitive service kinds.")] = False,
    group_by: Annotated[str | None, Field(description="Optional grouping key for summary counts: resource_type, service_kind, risk_flag, port, protocol, external_kind, account_id, or vpc_id.")] = None,
    sort_by: Annotated[str, Field(description="Sort key: path_count, label, resource_type, service_kind, or risk_count.")] = "path_count",
    mode: Annotated[str, Field(description="Peer row detail mode: compact, normal, or verbose.")] = "compact",
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each destination row.")] = None,
    include_rule_summaries: Annotated[bool, Field(description="Include compact ingress/egress SG rule summaries for each edge row.")] = False,
    skip: Annotated[int, Field(description="Number of destination rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum destination rows to return, capped at 500.", ge=1)] = 50,
) -> dict[str, Any]:
    """Return resources reachable from a source resource.

    Args:
        resource_id: Source entity ID.
        filters: Optional destination edge filters.
        port: Port filter.
        protocol: Protocol filter.
        external_only: Restrict to external boundary evidence.
        sensitive_only: Restrict to sensitive destinations.
        group_by: Optional grouped summary dimension.
        sort_by: Result sort key.
        mode: Peer row detail mode.
        fields: Optional row field projection.
        include_rule_summaries: Include SG rule summaries.
        skip: Number of destinations to skip.
        take: Number of destinations to return.
    """
    index = get_index()
    source = index.entities[resource_id]
    rows = []
    for edge_id in index.outgoing.get(resource_id, []):
        edge = index.edges[edge_id]
        destination = index.entities[edge["destination_id"]]
        if not edge_matches_filters(edge, filters, destination, port, protocol, external_only, sensitive_only):
            continue
        rows.append(edge_peer_row(edge_id, edge, destination, mode, None, include_rule_summaries))
    rows = sort_peer_rows(rows, sort_by)
    projected_rows = [apply_fields(row, fields) for row in rows]
    page = paginate(projected_rows, skip, take)
    result = {
        "source": entity_ref(source),
        "summary": {"reachable_destination_count": len(rows), "returned": page["returned"]},
        "destinations": page["items"],
        **pagination_meta(page),
    }
    if group_by:
        result["grouped_counts"] = group_peer_rows(rows, group_by)
    return result


@tool
def can_reach(
    resource_id: Annotated[str, Field(description="Destination resource/workload ID to inspect.")],
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional edge filters: resource_type, protocol, port, risk_flag, external_kind, service_kind, and/or security_group_rule_id."),
    ] = None,
    port: Annotated[int | None, Field(description="Only return sources that can reach this destination on this packet port.")] = None,
    protocol: Annotated[str | None, Field(description="Only return sources that can reach this destination with this protocol.")] = None,
    external_only: Annotated[bool, Field(description="Only return edges with external boundary evidence.")] = False,
    sensitive_only: Annotated[bool, Field(description="Only return rows where this destination is classified as sensitive.")] = False,
    group_by: Annotated[str | None, Field(description="Optional grouping key for summary counts: resource_type, service_kind, risk_flag, port, protocol, external_kind, account_id, or vpc_id.")] = None,
    sort_by: Annotated[str, Field(description="Sort key: path_count, label, resource_type, service_kind, or risk_count.")] = "path_count",
    mode: Annotated[str, Field(description="Peer row detail mode: compact, normal, or verbose.")] = "compact",
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each source row.")] = None,
    include_rule_summaries: Annotated[bool, Field(description="Include compact ingress/egress SG rule summaries for each edge row.")] = False,
    skip: Annotated[int, Field(description="Number of source rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum source rows to return, capped at 500.", ge=1)] = 50,
) -> dict[str, Any]:
    """Return resources that can reach a destination resource.

    Args:
        resource_id: Destination entity ID.
        filters: Optional source edge filters.
        port: Port filter.
        protocol: Protocol filter.
        external_only: Restrict to external boundary evidence.
        sensitive_only: Restrict to sensitive destination rows.
        group_by: Optional grouped summary dimension.
        sort_by: Result sort key.
        mode: Peer row detail mode.
        fields: Optional row field projection.
        include_rule_summaries: Include SG rule summaries.
        skip: Number of sources to skip.
        take: Number of sources to return.
    """
    index = get_index()
    destination = index.entities[resource_id]
    rows = []
    for edge_id in index.incoming.get(resource_id, []):
        edge = index.edges[edge_id]
        source = index.entities[edge["source_id"]]
        if not edge_matches_filters(edge, filters, source, port, protocol, external_only, False):
            continue
        if sensitive_only and destination.get("service_kind") not in SENSITIVE_KINDS:
            continue
        rows.append(edge_peer_row(edge_id, edge, source, mode, None, include_rule_summaries))
    rows = sort_peer_rows(rows, sort_by)
    projected_rows = [apply_fields(row, fields) for row in rows]
    page = paginate(projected_rows, skip, take)
    result = {
        "destination": entity_ref(destination),
        "summary": {"reachable_source_count": len(rows), "returned": page["returned"]},
        "sources": page["items"],
        **pagination_meta(page),
    }
    if group_by:
        result["grouped_counts"] = group_peer_rows(rows, group_by)
    return result


@tool
def edge_summary(
    source_id: Annotated[str, Field(description="Source resource/workload ID for the edge.")],
    destination_id: Annotated[str, Field(description="Destination resource/workload ID for the edge.")],
) -> dict[str, Any]:
    """Summarize the reachability edge between two resources.

    Args:
        source_id: Source entity ID.
        destination_id: Destination entity ID.
    """
    index = get_index()
    edge_id = index.edge_by_pair[(source_id, destination_id)]
    result = edge_detail_payload(index, edge_id, representative=True, take=3)
    result.pop("representative_paths", None)
    result.pop("validation_calls", None)
    result["edge_detail_call"] = {"tool": "edge_detail", "arguments": {"edge_id": edge_id}}
    return result


@tool
def edge_detail(
    edge_id: Annotated[str, Field(description="Edge ID returned by finding_candidates, edge summaries, impact tools, or boundary summaries.")],
    representative: Annotated[
        bool,
        Field(description="When true, return representative paths covering distinct packet, route, rule, ENI, and load balancer combinations."),
    ] = True,
    distinct_by: Annotated[
        list[str] | None,
        Field(description="Representative key fields. Defaults to packet, route, ingress_rule, egress_rule, destination_attachment_eni, and load_balancer_forwarding."),
    ] = None,
    take: Annotated[int, Field(description="Maximum representative path rows to include, capped at 500.", ge=1)] = 3,
    include_path_explanations: Annotated[
        bool,
        Field(description="Include short path_explain text for returned representative paths."),
    ] = False,
) -> dict[str, Any]:
    """Return a direct edge lookup with source/destination IDs and representative path evidence.

    Args:
        edge_id: Edge ID to inspect.
        representative: Deduplicate paths by representative evidence dimensions.
        distinct_by: Representative distinctness fields.
        take: Number of representative paths to include.
        include_path_explanations: Include short explanation text for representative paths.
    """
    return edge_detail_payload(get_index(), edge_id, representative, distinct_by, take, include_path_explanations)


@tool
def edge_paths(
    source_id: Annotated[str, Field(description="Source resource/workload ID for the edge.")],
    destination_id: Annotated[str, Field(description="Destination resource/workload ID for the edge.")],
    representative: Annotated[
        bool,
        Field(description="When true, return representative paths covering distinct packet, route, rule, ENI, and load balancer combinations."),
    ] = True,
    distinct_by: Annotated[
        list[str] | None,
        Field(description="Representative key fields. Defaults to packet, route, ingress_rule, egress_rule, destination_attachment_eni, and load_balancer_forwarding."),
    ] = None,
    skip: Annotated[int, Field(description="Number of path/ray records to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum path/ray records to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Return individual rays/path evidence for a source-destination edge.

    Args:
        source_id: Source entity ID.
        destination_id: Destination entity ID.
        representative: Deduplicate paths by representative evidence dimensions.
        distinct_by: Representative distinctness fields.
        skip: Number of path records to skip.
        take: Number of path records to return.
    """
    index = get_index()
    edge_id = index.edge_by_pair[(source_id, destination_id)]
    rows = representative_paths_for_edge(index, edge_id, representative, distinct_by)
    page = paginate(rows, skip, take)
    edge = index.edges[edge_id]
    return {
        "edge_id": edge_id,
        "source_resource": entity_ref(index.entities[edge["source_id"]]),
        "destination_resource": entity_ref(index.entities[edge["destination_id"]]),
        "representative": representative,
        "distinct_by": distinct_by
        or ["packet", "route", "ingress_rule", "egress_rule", "destination_attachment_eni", "load_balancer_forwarding"],
        "paths": page["items"],
        **pagination_meta(page),
    }


def path_explain_text(index: Any, path_id: str, format: str = "normal") -> str:
    path = index.paths[path_id]
    packet = packet_label(path["packet"])
    egress = path["egress_rule"]
    ingress = path["ingress_rule"]
    route = path["route"]
    route_target = route.get("target") or route.get("target_kind")
    source = index.entities[path["source_id"]]
    destination = index.entities[path["destination_id"]]
    source_text = resource_phrase(source)
    destination_text = resource_phrase(destination)
    risk_summary = path_risk_summary(path, destination)
    if format == "short":
        return (
            f"{source_text} reaches {destination_text} over {packet} via {route.get('id')}; "
            f"attachments {path['source_eni']} -> {path['destination_eni']}; {risk_summary}"
        )
    lines = [
        risk_summary,
        f"{source_text}",
        f"  source attachment {path['source_eni']} ({path['source_private_ip']})",
        f"  egress {egress.get('sg_id')} {egress.get('id')} allows {packet} to {path['packet'].get('dst')}",
        f"  route {route.get('id')} selects {route.get('target_kind')} target {route_target} for {route.get('destination')}",
    ]
    if path.get("tgw_hop"):
        hop = path["tgw_hop"]
        lines.append(
            f"  transit gateway {hop.get('tgw_id')} uses table {hop.get('route_table_id')} "
            f"from {hop.get('source_attachment_id')} to {hop.get('destination_attachment_id')}"
        )
    if path.get("elb_target"):
        target = path["elb_target"]
        lines.append(
            "  load balancer target group "
            f"{target.get('target_group_name') or target.get('target_group_arn')} "
            f"forwards to {target.get('target_eni_id')}"
        )
    lines.extend(
        [
            f"  ingress {ingress.get('sg_id')} {ingress.get('id')} allows {packet} "
            f"from {', '.join(ingress.get('cidrs', [])) or 'referenced source security group'}",
            f"  reaches {destination_text}",
            f"  destination attachment {path['destination_eni']} ({path['destination_private_ip']})",
        ]
    )
    if format == "detailed":
        lines.append("  packet space by stage:")
        for stage, packet_space in path.get("packet_space_by_stage", {}).items():
            lines.append(f"    {stage}: {packet_label(packet_space)} to {packet_space.get('dst')}")
        if path.get("external_kind"):
            lines.append(f"  external boundary classification: {path['external_kind']}")
    return "\n".join(lines)


@tool
def path_explain(
    path_id: Annotated[str, Field(description="Path ID returned by edge_paths.")],
    format: Annotated[str, Field(description="Explanation format: short, normal, or detailed.")] = "normal",
) -> str:
    """Explain one path as a human-readable evidence chain.

    Args:
        path_id: Path/ray ID to explain.
        format: Explanation detail level.
    """
    return path_explain_text(get_index(), path_id, format)


@tool
def route_impact(
    route_id: Annotated[str, Field(description="Route ID returned by edge_summary, edge_paths, or route lists.")],
    include_full_lists: Annotated[bool, Field(description="Include full affected source and destination ID lists. Defaults to false for compact output.")] = False,
    skip: Annotated[int, Field(description="Number of sample edge rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum sample edge rows to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Return resources and paths that depend on a route.

    Args:
        route_id: Route ID to inspect.
        include_full_lists: Include full affected source/destination IDs.
        skip: Number of sample edges to skip.
        take: Number of sample edges to return.
    """
    index = get_index()
    path_ids = index.route_to_paths.get(route_id, [])
    impact = index.route_impacts.get(route_id, {})
    source_ids = {index.paths[path_id]["source_id"] for path_id in path_ids}
    destination_ids = {index.paths[path_id]["destination_id"] for path_id in path_ids}
    route_summary = index.route_summaries.get(route_id, {})
    edge_samples = path_edge_samples(index, path_ids)
    page = paginate(edge_samples, skip, take)
    result = {
        "route_id": route_id,
        "route_table_id": route_summary.get("route_table_id"),
        "destination": route_summary.get("destination"),
        "target_kind": route_summary.get("target_kind"),
        "target": route_summary.get("target"),
        "affected_paths": len(path_ids),
        "source_count": len(source_ids),
        "destination_count": len(destination_ids),
        "external_path_count": impact.get("external_path_count", 0),
        "wildcard_path_count": impact.get("wildcard_path_count", 0),
        "broad_ingress_path_count": impact.get("broad_ingress_path_count", 0),
        "sensitive_destination_count": impact.get("sensitive_destination_count", 0),
        "grouped_counts": impact.get("grouped_counts", {}),
        "sample_edges": page["items"],
        **pagination_meta(page),
    }
    if include_full_lists:
        result["source_ids"] = sorted(source_ids)
        result["destination_ids"] = sorted(destination_ids)
    return result


@tool
def security_group_rule_impact(
    rule_id: Annotated[str, Field(description="Security group rule ID returned by edge_summary or edge_paths.")],
    include_full_lists: Annotated[bool, Field(description="Include full affected source and destination label lists. Defaults to false for compact output.")] = False,
    skip: Annotated[int, Field(description="Number of sample edge rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum sample edge rows to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Return reachability evidence that depends on a security group rule.

    Args:
        rule_id: Security group rule ID to inspect.
        include_full_lists: Include full affected source/destination labels.
        skip: Number of sample edges to skip.
        take: Number of sample edges to return.
    """
    index = get_index()
    path_ids = index.rule_to_paths.get(rule_id, [])
    impact = index.rule_impacts.get(rule_id, {})
    sources = sorted({index.paths[path_id]["source_label"] for path_id in path_ids})
    destinations = sorted({index.paths[path_id]["destination_label"] for path_id in path_ids})
    packets = sorted({index.paths[path_id]["packet_label"] for path_id in path_ids})
    flags = sorted({flag for path_id in path_ids for flag in index.paths[path_id].get("risk_flags", [])})
    summary = index.rule_summaries.get(rule_id, {})
    sample_page = paginate(path_edge_samples(index, path_ids), skip, take)
    result = {
        "rule_id": rule_id,
        "direction": summary.get("direction"),
        "security_group_id": summary.get("security_group_id"),
        "protocol": summary.get("protocol"),
        "ports": summary.get("ports"),
        "cidrs": summary.get("cidrs", []),
        "affected_paths": len(path_ids),
        "source_count": len(sources),
        "destination_count": len(destinations),
        "packets": packets,
        "risk_flags": flags,
        "external_path_count": impact.get("external_path_count", 0),
        "wildcard_path_count": impact.get("wildcard_path_count", 0),
        "broad_ingress_path_count": impact.get("broad_ingress_path_count", 0),
        "sensitive_destination_count": impact.get("sensitive_destination_count", 0),
        "grouped_counts": impact.get("grouped_counts", {}),
        "sample_edges": sample_page["items"],
        **pagination_meta(sample_page),
    }
    if include_full_lists:
        result["sources"] = sources
        result["destinations"] = destinations
    return result


@tool
def top_security_group_rule_impacts(
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional filters: direction, security_group_id, risk_flag, external_kind, protocol, port, resource_type, account_id, region, vpc_id, service_kind, or internet_exposed."),
    ] = None,
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each ranked rule impact row.")] = None,
    sample_limit: Annotated[int, Field(description="Number of compact sample edges per rule row.", ge=1)] = 3,
    skip: Annotated[int, Field(description="Number of ranked rule rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum ranked rule rows to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Rank security group rules by assessment impact.

    Args:
        filters: Optional impact filters.
        fields: Optional row field projection.
        sample_limit: Number of sample edges per rule.
        skip: Number of rows to skip.
        take: Number of rows to return.
    """
    index = get_index()
    rows = [
        impact for impact in index.rule_impacts.values()
        if impact_matches_filters(index, impact, filters)
    ]
    rows.sort(key=lambda row: (row.get("score", 0), row.get("affected_paths", 0)), reverse=True)
    page = paginate(rows, skip, take)
    compact_rows = [apply_fields(compact_impact(row, sample_limit), fields) for row in page["items"]]
    return {
        "summary": impact_collection_summary(rows, "rules", page),
        "grouped_counts": impact_collection_grouped_counts(rows),
        "rules": compact_rows,
        "pagination": pagination_meta(page),
    }


@tool
def top_route_impacts(
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional filters: target_kind, risk_flag, external_kind, protocol, port, resource_type, account_id, region, vpc_id, service_kind, or internet_exposed."),
    ] = None,
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each ranked route impact row.")] = None,
    sample_limit: Annotated[int, Field(description="Number of compact sample edges per route row.", ge=1)] = 3,
    skip: Annotated[int, Field(description="Number of ranked route rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum ranked route rows to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Rank routes by assessment impact.

    Args:
        filters: Optional impact filters.
        fields: Optional row field projection.
        sample_limit: Number of sample edges per route.
        skip: Number of rows to skip.
        take: Number of rows to return.
    """
    index = get_index()
    rows = [
        impact for impact in index.route_impacts.values()
        if impact_matches_filters(index, impact, filters)
    ]
    rows.sort(key=lambda row: (row.get("score", 0), row.get("affected_paths", 0)), reverse=True)
    page = paginate(rows, skip, take)
    compact_rows = [apply_fields(compact_impact(row, sample_limit), fields) for row in page["items"]]
    return {
        "summary": impact_collection_summary(rows, "routes", page),
        "grouped_counts": impact_collection_grouped_counts(rows),
        "routes": compact_rows,
        "pagination": pagination_meta(page),
    }


@tool
def internet_exposed_resources(
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional entity filters: resource_type, account_id, region, vpc_id, service_kind, external_kind, and/or risk_flag."),
    ] = None,
    mode: Annotated[str, Field(description="Resource row detail mode: compact, normal, or verbose.")] = "compact",
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each resource row.")] = None,
    include_member_enis: Annotated[bool, Field(description="Include full member ENI arrays.")] = False,
    sample_limit: Annotated[int, Field(description="Number of IP/ENI samples in non-compact rows.", ge=1)] = 3,
    skip: Annotated[int, Field(description="Number of exposed resources to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum exposed resources to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """List resources with public IPs or internet-like ingress evidence.

    Args:
        filters: Optional entity filters.
        mode: Resource row detail mode.
        fields: Optional row field projection.
        include_member_enis: Include raw ENI inventory.
        sample_limit: Number of sample IPs/ENIs.
        skip: Number of rows to skip.
        take: Number of rows to return.
    """
    index = get_index()
    filter_values = dict(filters or {})
    filter_values.pop("internet_exposed", None)
    resources = [
        entity for entity in index.entities.values()
        if (entity.get("internet_exposed") or entity.get("public_ips"))
        and entity_matches_filters(entity, filter_values)
    ]
    resources.sort(
        key=lambda entity: (
            entity.get("internet_exposed", False),
            entity.get("incoming_edges", 0),
            entity.get("path_count_in", 0),
        ),
        reverse=True,
    )
    page = paginate(resources, skip, take)
    return {
        "summary": {
            "exposed_resource_count": len(resources),
            "with_public_ip": sum(1 for entity in resources if entity.get("public_ips")),
            "with_internet_ingress": sum(1 for entity in resources if entity.get("internet_exposed")),
            "returned": page["returned"],
        },
        "grouped_counts": grouped_entity_counts(resources),
        "resources": format_entities(page["items"], mode, fields, include_member_enis, sample_limit),
        "pagination": pagination_meta(page),
    }


@tool
def external_boundary_summary(
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional edge/entity filters: external_kind, resource_type, account_id, region, vpc_id, service_kind, risk_flag, protocol, or port."),
    ] = None,
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each flow row.")] = None,
    skip: Annotated[int, Field(description="Number of boundary flow rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum boundary flow rows to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Summarize flows crossing internet, peering, TGW, VPN, Direct Connect, or unknown external boundaries.

    Args:
        filters: Optional flow filters.
        fields: Optional row field projection.
        skip: Number of rows to skip.
        take: Number of rows to return.
    """
    index = get_index()
    rows = []
    matched_edges = []
    for edge_id, edge in index.edges.items():
        kinds = edge.get("external_kinds", [])
        if not kinds and "transit_gateway" in edge.get("risk_flags", []):
            kinds = ["transit_gateway"]
        if not kinds and "external" in edge.get("risk_flags", []):
            kinds = ["unknown_external"]
        source = index.entities[edge["source_id"]]
        destination = index.entities[edge["destination_id"]]
        if not kinds:
            continue
        edge_for_filter = {**edge, "external_kinds": kinds}
        if not edge_matches_filters(edge_for_filter, filters, destination, filters.get("port") if filters else None, filters.get("protocol") if filters else None, True, False):
            continue
        if filters and filters.get("account_id") and filters["account_id"] not in {source.get("account_id"), destination.get("account_id")}:
            continue
        if filters and filters.get("region") and filters["region"] not in {source.get("region"), destination.get("region")}:
            continue
        if filters and filters.get("vpc_id") and filters["vpc_id"] not in {source.get("vpc_id"), destination.get("vpc_id")}:
            continue
        row = {
            "edge_id": edge_id,
            "source": entity_ref(source),
            "destination": entity_ref(destination),
            "path_count": edge.get("path_count", 0),
            "external_kinds": kinds,
            "packet_labels": edge.get("packet_labels", []),
            "route_summaries": edge.get("route_summaries", []),
            "risk_flags": edge.get("risk_flags", []),
        }
        rows.append((row, edge))
        matched_edges.append(edge)
    rows.sort(key=lambda item: (item[0].get("path_count", 0), len(item[0].get("risk_flags", []))), reverse=True)
    projected_rows = [apply_fields(row, fields) for row, _edge in rows]
    page = paginate(projected_rows, skip, take)
    return {
        "summary": {"boundary_edge_count": len(projected_rows), "returned": page["returned"]},
        "grouped_counts": grouped_edge_counts(index, matched_edges),
        "flows": page["items"],
        "pagination": pagination_meta(page),
    }


@tool
def sensitive_reachability_summary(
    kinds: Annotated[
        list[str] | None,
        Field(description="Sensitive service kinds to include. Defaults to database, cache, admin, search, messaging, monitoring, and identity."),
    ] = None,
    risk_flags: Annotated[list[str] | None, Field(description="Optional list of risk flags that must appear on incoming edges.")] = None,
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each sensitive destination row.")] = None,
    skip: Annotated[int, Field(description="Number of sensitive destination rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum sensitive destination rows to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Identify sensitive destinations and summarize who can reach them.

    Args:
        kinds: Sensitive service kinds to include.
        risk_flags: Optional required incoming risk flags.
        fields: Optional row field projection.
        skip: Number of rows to skip.
        take: Number of rows to return.
    """
    index = get_index()
    wanted_kinds = set(kinds or sorted(SENSITIVE_KINDS))
    wanted_flags = set(risk_flags or [])
    rows = []
    for entity in index.entities.values():
        if entity.get("service_kind") not in wanted_kinds or entity.get("incoming_edges", 0) == 0:
            continue
        incoming_edges = [index.edges[edge_id] for edge_id in index.incoming.get(entity["resource_id"], [])]
        if wanted_flags and not any(wanted_flags & set(edge.get("risk_flags", [])) for edge in incoming_edges):
            continue
        source_ids = {edge["source_id"] for edge in incoming_edges}
        representative_edges = sorted(incoming_edges, key=lambda edge: edge.get("path_count", 0), reverse=True)[:3]
        row = {
            "resource_id": entity["resource_id"],
            "label": entity["label"],
            "resource_type": entity.get("resource_type"),
            "service_kind": entity.get("service_kind"),
            "service_kind_inferred": entity.get("service_kind_inferred"),
            "account_id": entity.get("account_id"),
            "account_name": entity.get("account_name"),
            "vpc_id": entity.get("vpc_id"),
            "incoming_edges": entity.get("incoming_edges", 0),
            "incoming_path_count": entity.get("path_count_in", 0),
            "source_count": len(source_ids),
            "risk_flags": sorted({flag for edge in incoming_edges for flag in edge.get("risk_flags", [])}),
            "external_kinds": sorted({kind for edge in incoming_edges for kind in edge.get("external_kinds", [])}),
            "top_sources": [
                {
                    "source_resource": entity_ref(index.entities[edge["source_id"]]),
                    "path_count": edge.get("path_count", 0),
                    "packet_labels": edge.get("packet_labels", []),
                    "risk_flags": edge.get("risk_flags", []),
                }
                for edge in representative_edges
            ],
            "representative_edge_ids": [edge["edge_id"] for edge in representative_edges],
        }
        rows.append(row)
    rows.sort(key=lambda row: (row.get("incoming_path_count", 0), row.get("source_count", 0)), reverse=True)
    projected_rows = [apply_fields(row, fields) for row in rows]
    page = paginate(projected_rows, skip, take)
    return {
        "summary": {"sensitive_destination_count": len(rows), "returned": page["returned"], "kinds": sorted(wanted_kinds)},
        "grouped_counts": {
            "service_kinds": dict(Counter(row.get("service_kind") or "unknown" for row in rows)),
            "resource_types": dict(Counter(row.get("resource_type") or "unknown" for row in rows)),
            "risk_flags": dict(Counter(flag for row in rows for flag in row.get("risk_flags", []))),
            "external_kinds": dict(Counter(kind for row in rows for kind in row.get("external_kinds", []))),
        },
        "resources": page["items"],
        "pagination": pagination_meta(page),
    }


def score_components_for_impact(impact: dict[str, Any]) -> dict[str, dict[str, int]]:
    return {
        key: {
            "count": int(impact.get(key, 0) or 0),
            "weight": weight,
            "contribution": int(impact.get(key, 0) or 0) * weight,
        }
        for key, weight in SCORE_WEIGHTS.items()
    }


def score_components_for_internet_entity(entity: dict[str, Any]) -> dict[str, dict[str, int]]:
    return {
        "incoming_edges": {
            "count": int(entity.get("incoming_edges", 0) or 0),
            "weight": 5,
            "contribution": int(entity.get("incoming_edges", 0) or 0) * 5,
        },
        "incoming_paths": {
            "count": int(entity.get("path_count_in", 0) or 0),
            "weight": 1,
            "contribution": int(entity.get("path_count_in", 0) or 0),
        },
        "sensitive_destination": {
            "count": 1 if entity.get("service_kind") in SENSITIVE_KINDS else 0,
            "weight": 10,
            "contribution": 10 if entity.get("service_kind") in SENSITIVE_KINDS else 0,
        },
    }


def score_component_total(components: dict[str, dict[str, int]]) -> int:
    return sum(component["contribution"] for component in components.values())


def impact_counts(impact: dict[str, Any]) -> dict[str, int]:
    return {
        "paths": int(impact.get("affected_paths", 0) or 0),
        "sources": int(impact.get("affected_source_count", 0) or 0),
        "destinations": int(impact.get("affected_destination_count", 0) or 0),
        "external_paths": int(impact.get("external_path_count", 0) or 0),
        "wildcard_paths": int(impact.get("wildcard_path_count", 0) or 0),
        "broad_ingress_paths": int(impact.get("broad_ingress_path_count", 0) or 0),
        "sensitive_destinations": int(impact.get("sensitive_destination_count", 0) or 0),
    }


def risk_reasons_for_impact(impact: dict[str, Any]) -> list[str]:
    reasons = []
    if impact.get("broad_ingress_path_count", 0):
        reasons.append("broad_ingress")
    if impact.get("wildcard_path_count", 0):
        reasons.append("wildcard_protocol_or_port")
    if impact.get("external_path_count", 0):
        reasons.append("external_boundary")
    if impact.get("sensitive_destination_count", 0):
        reasons.append("sensitive_destination")
    if not reasons:
        reasons.append("high_fanout_reachability")
    return reasons


def risk_reason_text(reasons: list[str]) -> str:
    labels = {
        "broad_ingress": "broad ingress",
        "wildcard_protocol_or_port": "wildcard protocol or ports",
        "external_boundary": "external boundary traversal",
        "sensitive_destination": "sensitive destinations",
        "high_fanout_reachability": "high fan-out reachability",
        "internet_exposure": "internet exposure evidence",
    }
    return ", ".join(labels.get(reason, reason.replace("_", " ")) for reason in reasons)


def rank_rationale(reasons: list[str], counts: dict[str, int]) -> str:
    signals = []
    if counts.get("paths"):
        signals.append(f"{counts['paths']} paths")
    if counts.get("sources") or counts.get("destinations"):
        signals.append(f"{counts.get('sources', 0)} sources to {counts.get('destinations', 0)} destinations")
    if counts.get("external_paths"):
        signals.append(f"{counts['external_paths']} external-boundary paths")
    if counts.get("sensitive_destinations"):
        signals.append(f"{counts['sensitive_destinations']} sensitive destinations")
    return f"{risk_reason_text(reasons)}; " + ", ".join(signals) if signals else risk_reason_text(reasons)


def internet_entity_impact_counts(entity: dict[str, Any]) -> dict[str, int]:
    return {
        "paths": int(entity.get("path_count_in", 0) or 0),
        "sources": int(entity.get("incoming_edges", 0) or 0),
        "destinations": 1,
        "external_paths": 0,
        "wildcard_paths": 0,
        "broad_ingress_paths": 0,
        "sensitive_destinations": 1 if entity.get("service_kind") in SENSITIVE_KINDS else 0,
    }


def suggested_exploration_branches(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    candidate_id = candidate["candidate_id"]
    kind, value = candidate_id.split(":", 1)
    branches = []
    if kind == "sg_rule":
        branches.extend(
            [
                {
                    "intent": "blast_radius",
                    "question": "Which sources and destinations depend on this security group rule?",
                    "calls": [{"tool": "security_group_rule_impact", "arguments": {"rule_id": value, "take": 10}}],
                },
                {
                    "intent": "sensitive_destinations",
                    "question": "Does this rule open paths into database, cache, admin, or other sensitive services?",
                    "calls": [{"tool": "finding_candidates", "arguments": {"filters": {"risk_flag": "broad_ingress", "service_kind": "database"}, "take": 5}}],
                },
            ]
        )
    elif kind == "route":
        branches.extend(
            [
                {
                    "intent": "boundary_validation",
                    "question": "Which network boundary or route-table association carries this reachability?",
                    "calls": [{"tool": "route_impact", "arguments": {"route_id": value, "take": 10}}],
                },
                {
                    "intent": "external_flows",
                    "question": "What other flows cross the same external boundary kind?",
                    "calls": [{"tool": "external_boundary_summary", "arguments": {"take": 10}}],
                },
            ]
        )
    elif kind == "internet_exposed":
        branches.extend(
            [
                {
                    "intent": "public_entrypoint_validation",
                    "question": "Which external or public-like sources can reach this resource?",
                    "calls": [{"tool": "can_reach", "arguments": {"resource_id": value, "external_only": True, "take": 10}}],
                },
                {
                    "intent": "inbound_controls",
                    "question": "Which ingress rules and routes make this public entrypoint reachable?",
                    "calls": [{"tool": "entity_detail", "arguments": {"resource_id": value, "include_rule_summaries": True, "include_route_summaries": True}}],
                },
            ]
        )

    first_edge = next(iter(candidate.get("representative_edges", [])), None)
    if first_edge:
        branches.append(
            {
                "intent": "packet_path_evidence",
                "question": "What is the representative packet path through SG rules, routes, and attachment ENIs?",
                "calls": [
                    {"tool": "edge_detail", "arguments": {"edge_id": first_edge["edge_id"]}},
                    {"tool": "edge_paths", "arguments": {"source_id": first_edge["source_id"], "destination_id": first_edge["destination_id"], "representative": True, "take": 3}},
                ],
            }
        )
    return branches


def candidate_output_row(candidate: dict[str, Any], include_scoring: bool) -> dict[str, Any]:
    row = dict(candidate)
    row.pop("recommended_next_calls", None)
    if not include_scoring:
        row.pop("score", None)
        row.pop("score_components", None)
    return row


def structured_next_calls_for_candidate(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    calls = []
    candidate_id = candidate["candidate_id"]
    kind, value = candidate_id.split(":", 1)
    if kind == "sg_rule":
        calls.append({"tool": "security_group_rule_impact", "arguments": {"rule_id": value, "take": 10}})
    elif kind == "route":
        calls.append({"tool": "route_impact", "arguments": {"route_id": value, "take": 10}})
    elif kind == "internet_exposed":
        calls.extend(
            [
                {"tool": "entity_detail", "arguments": {"resource_id": value, "include_member_enis": False}},
                {"tool": "can_reach", "arguments": {"resource_id": value, "external_only": True, "take": 10}},
            ]
        )
    for edge in candidate.get("representative_edges", [])[:2]:
        calls.append({"tool": "edge_detail", "arguments": {"edge_id": edge["edge_id"]}})
    first_edge = next(iter(candidate.get("representative_edges", [])), None)
    if first_edge:
        calls.append(
            {
                "tool": "edge_paths",
                "arguments": {
                    "source_id": first_edge["source_id"],
                    "destination_id": first_edge["destination_id"],
                    "representative": True,
                    "take": 3,
                },
            }
        )
    return calls


def affected_summary_for_paths(index: Any, path_ids: list[str], sample_limit: int = 10) -> dict[str, Any]:
    source_ids = sorted({index.paths[path_id]["source_id"] for path_id in path_ids})
    destination_ids = sorted({index.paths[path_id]["destination_id"] for path_id in path_ids})
    sources = [index.entities[resource_id] for resource_id in source_ids]
    destinations = [index.entities[resource_id] for resource_id in destination_ids]
    return {
        "source_count": len(sources),
        "destination_count": len(destinations),
        "source_samples": [entity_ref(entity) for entity in sources[:sample_limit]],
        "destination_samples": [entity_ref(entity) for entity in destinations[:sample_limit]],
        "grouped_counts": {
            "source_resource_types": dict(Counter(entity.get("resource_type") or "unknown" for entity in sources)),
            "destination_resource_types": dict(Counter(entity.get("resource_type") or "unknown" for entity in destinations)),
            "source_service_kinds": dict(Counter(entity.get("service_kind") or "unknown" for entity in sources)),
            "destination_service_kinds": dict(Counter(entity.get("service_kind") or "unknown" for entity in destinations)),
            "source_accounts": dict(Counter(entity.get("account_id") or "unknown" for entity in sources)),
            "destination_accounts": dict(Counter(entity.get("account_id") or "unknown" for entity in destinations)),
        },
        "resource_clusters": {
            "sources": resource_clusters(sources),
            "destinations": resource_clusters(destinations),
        },
    }


def resource_clusters(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    clusters: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for entity in entities:
        key = (
            entity.get("account_id"),
            entity.get("region"),
            entity.get("vpc_id"),
            entity.get("resource_type"),
            entity.get("service_kind"),
            tuple(entity.get("security_groups", [])),
            entity.get("grouping_status"),
        )
        clusters[key].append(entity)

    rows = []
    for (
        account_id,
        region,
        vpc_id,
        resource_type,
        service_kind,
        security_groups,
        grouping_status,
    ), members in clusters.items():
        rows.append(
            {
                "count": len(members),
                "account_id": account_id,
                "region": region,
                "vpc_id": vpc_id,
                "resource_type": resource_type,
                "service_kind": service_kind,
                "security_groups": list(security_groups),
                "grouping_status": grouping_status,
                "sample_resources": [entity_ref(entity) for entity in members[:3]],
            }
        )
    rows.sort(key=lambda row: (row["count"], row.get("resource_type") or "", row.get("service_kind") or ""), reverse=True)
    return rows


def build_candidate_rows(index: Any, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    candidates = []
    for impact in index.rule_impacts.values():
        if not impact_matches_filters(index, impact, filters) or not candidate_worthy_impact(impact):
            continue
        components = score_components_for_impact(impact)
        counts = impact_counts(impact)
        reasons = risk_reasons_for_impact(impact)
        representative_edges = [
            edge_ref(index, sample["edge_id"])
            for sample in impact.get("sample_edges", [])
            if sample.get("edge_id") in index.edges
        ]
        candidate = {
            "candidate_id": f"sg_rule:{impact['rule_id']}",
            "finding_type": "security_group_rule_impact",
            "severity_hint": severity_hint(impact),
            "score": impact.get("score", 0),
            "score_components": components,
            "title": f"Security group rule {impact['rule_id']} enables broad or sensitive reachability",
            "risk_reasons": reasons,
            "impact_counts": counts,
            "rank_rationale": rank_rationale(reasons, counts),
            "affected_paths": impact.get("affected_paths", 0),
            "affected_source_count": impact.get("affected_source_count", 0),
            "affected_destination_count": impact.get("affected_destination_count", 0),
            "representative_edge_ids": [edge["edge_id"] for edge in representative_edges],
            "representative_edges": representative_edges,
            "top_affected_resources": [
                edge["destination_resource"] for edge in representative_edges[:3]
            ],
            "supporting_rule_ids": [impact["rule_id"]],
            "supporting_route_ids": [],
        }
        candidate["recommended_next_calls"] = structured_next_calls_for_candidate(candidate)
        candidate["suggested_exploration_branches"] = suggested_exploration_branches(candidate)
        candidates.append(candidate)
    for impact in index.route_impacts.values():
        if not impact_matches_filters(index, impact, filters):
            continue
        if impact.get("external_path_count", 0) == 0 and impact.get("target_kind") in {None, "local"}:
            continue
        components = score_components_for_impact(impact)
        counts = impact_counts(impact)
        reasons = risk_reasons_for_impact(impact)
        representative_edges = [
            edge_ref(index, sample["edge_id"])
            for sample in impact.get("sample_edges", [])
            if sample.get("edge_id") in index.edges
        ]
        candidate = {
            "candidate_id": f"route:{impact['route_id']}",
            "finding_type": "route_boundary_impact",
            "severity_hint": severity_hint(impact),
            "score": impact.get("score", 0),
            "score_components": components,
            "title": f"Route {impact['route_id']} carries external or sensitive reachability",
            "risk_reasons": reasons,
            "impact_counts": counts,
            "rank_rationale": rank_rationale(reasons, counts),
            "affected_paths": impact.get("affected_paths", 0),
            "affected_source_count": impact.get("affected_source_count", 0),
            "affected_destination_count": impact.get("affected_destination_count", 0),
            "representative_edge_ids": [edge["edge_id"] for edge in representative_edges],
            "representative_edges": representative_edges,
            "top_affected_resources": [
                edge["destination_resource"] for edge in representative_edges[:3]
            ],
            "supporting_rule_ids": [],
            "supporting_route_ids": [impact["route_id"]],
        }
        candidate["recommended_next_calls"] = structured_next_calls_for_candidate(candidate)
        candidate["suggested_exploration_branches"] = suggested_exploration_branches(candidate)
        candidates.append(candidate)
    for entity in index.entities.values():
        if not entity.get("internet_exposed") or not entity_matches_filters(entity, filters):
            continue
        edge_ids = index.incoming.get(entity["resource_id"], [])[:3]
        representative_edges = [edge_ref(index, edge_id) for edge_id in edge_ids]
        components = score_components_for_internet_entity(entity)
        counts = internet_entity_impact_counts(entity)
        reasons = ["internet_exposure"]
        if entity.get("service_kind") in SENSITIVE_KINDS:
            reasons.append("sensitive_destination")
        candidate = {
            "candidate_id": f"internet_exposed:{entity['resource_id']}",
            "finding_type": "internet_exposed_resource",
            "severity_hint": "high" if entity.get("service_kind") in SENSITIVE_KINDS else "medium",
            "score": entity.get("path_count_in", 0) + entity.get("incoming_edges", 0) * 5,
            "score_components": components,
            "title": f"{entity['label']} is internet exposed",
            "risk_reasons": reasons,
            "impact_counts": counts,
            "rank_rationale": rank_rationale(reasons, counts),
            "affected_resources": [entity_ref(entity)],
            "representative_edge_ids": [edge["edge_id"] for edge in representative_edges],
            "representative_edges": representative_edges,
            "top_affected_resources": [entity_ref(entity)],
            "supporting_rule_ids": sorted(
                {
                    rule_id
                    for edge_id in index.incoming.get(entity["resource_id"], [])
                    for rule_id in index.edges[edge_id].get("ingress_rules", [])
                }
            )[:5],
            "supporting_route_ids": sorted(
                {
                    route_id
                    for edge_id in index.incoming.get(entity["resource_id"], [])
                    for route_id in index.edges[edge_id].get("routes", [])
                }
            )[:5],
        }
        candidate["score"] = score_component_total(components)
        candidate["recommended_next_calls"] = structured_next_calls_for_candidate(candidate)
        candidate["suggested_exploration_branches"] = suggested_exploration_branches(candidate)
        candidates.append(candidate)
    candidates.sort(key=lambda row: (severity_rank(row.get("severity_hint")), row.get("score", 0)), reverse=True)
    return candidates


@tool
def finding_candidates(
    filters: Annotated[
        dict[str, Any] | None,
        Field(description="Optional filters: risk_flag, external_kind, resource_type, account_id, region, vpc_id, service_kind, protocol, port, or internet_exposed."),
    ] = None,
    fields: Annotated[list[str] | None, Field(description="Optional field projection for each candidate row.")] = None,
    include_scoring: Annotated[
        bool,
        Field(description="Include internal ranking scores and score components. Defaults to false to keep candidate output evidence-focused."),
    ] = False,
    skip: Annotated[int, Field(description="Number of candidate finding rows to skip.", ge=0)] = 0,
    take: Annotated[int, Field(description="Maximum candidate finding rows to return, capped at 500.", ge=1)] = 20,
) -> dict[str, Any]:
    """Return ranked candidate findings with evidence IDs and recommended next tool calls.

    Args:
        filters: Optional candidate filters.
        fields: Optional candidate field projection.
        include_scoring: Include internal ranking debug fields.
        skip: Number of rows to skip.
        take: Number of rows to return.
    """
    candidates = build_candidate_rows(get_index(), filters)
    severity_counts = dict(Counter(row.get("severity_hint") for row in candidates))
    projected = [apply_fields(candidate_output_row(row, include_scoring), fields) for row in candidates]
    page = paginate(projected, skip, take)
    return {
        "summary": {
            "candidate_count": len(projected),
            "returned": page["returned"],
            "severity_hints": severity_counts,
            "ranking": "Candidates are sorted by severity and internal network-impact score. Set include_scoring=true to inspect ranking debug fields.",
        },
        "candidates": page["items"],
        "pagination": pagination_meta(page),
    }


@tool
def investigate_candidate(
    candidate_id: Annotated[str, Field(description="Candidate ID returned by finding_candidates, such as sg_rule:<rule_id>, route:<route_id>, or internet_exposed:<resource_id>.")],
    edge_take: Annotated[int, Field(description="Maximum representative edge details to include, capped at 500.", ge=1)] = 3,
    path_explanation_take: Annotated[int, Field(description="Maximum short path explanations to include across representative edges, capped at 50.", ge=0)] = 1,
    include_full_impacts: Annotated[
        bool,
        Field(description="Include fuller rule/route/resource impact lists. Defaults to false for compact assessment output."),
    ] = False,
    include_scoring: Annotated[
        bool,
        Field(description="Include internal candidate ranking scores and score components. Defaults to false."),
    ] = False,
) -> dict[str, Any]:
    """Expand one candidate finding into scoped evidence, representative paths, and validation calls.

    Args:
        candidate_id: Candidate ID returned by finding_candidates.
        edge_take: Number of representative edge details to include.
        path_explanation_take: Number of short path explanations to include.
        include_full_impacts: Include fuller impact lists when available.
        include_scoring: Include internal candidate ranking debug fields.
    """
    index = get_index()
    candidates = {candidate["candidate_id"]: candidate for candidate in build_candidate_rows(index)}
    if candidate_id not in candidates:
        raise ValueError(f"Unknown candidate_id {candidate_id!r}. Call finding_candidates() for valid candidate IDs.")
    candidate = candidates[candidate_id]
    kind, value = candidate_id.split(":", 1)
    edge_ids = candidate.get("representative_edge_ids", [])[: max(1, min(int(edge_take), 500))]
    edge_details = [
        edge_detail_payload(index, edge_id, representative=True, take=3, include_path_explanations=False)
        for edge_id in edge_ids
        if edge_id in index.edges
    ]

    explanation_budget = max(0, min(int(path_explanation_take), 50))
    path_explanations = []
    for detail in edge_details:
        for path_id in detail.get("representative_path_ids", []):
            if len(path_explanations) >= explanation_budget:
                break
            path_explanations.append(
                {"edge_id": detail["edge_id"], "path_id": path_id, "text": path_explain_text(index, path_id, "short")}
            )
        if len(path_explanations) >= explanation_budget:
            break

    result = {
        "candidate": candidate_output_row(candidate, include_scoring),
        "affected": {},
        "impact_detail": None,
        "representative_edge_details": edge_details,
        "path_explanations": path_explanations,
        "remediation_hints": remediation_hints_for_candidate(candidate),
        "validation_calls": candidate.get("recommended_next_calls", []),
        "suggested_exploration_branches": candidate.get("suggested_exploration_branches", []),
    }

    if kind == "sg_rule":
        path_ids = index.rule_to_paths.get(value, [])
        result["affected"] = affected_summary_for_paths(index, path_ids, 500 if include_full_impacts else 10)
        result["impact_detail"] = security_group_rule_impact(
            value,
            include_full_lists=include_full_impacts,
            take=500 if include_full_impacts else 10,
        )
    elif kind == "route":
        path_ids = index.route_to_paths.get(value, [])
        result["affected"] = affected_summary_for_paths(index, path_ids, 500 if include_full_impacts else 10)
        result["impact_detail"] = route_impact(
            value,
            include_full_lists=include_full_impacts,
            take=500 if include_full_impacts else 10,
        )
    elif kind == "internet_exposed":
        entity = index.entities[value]
        incoming_edge_ids = index.incoming.get(value, [])
        path_ids = [
            path_id
            for edge_id in incoming_edge_ids
            for path_id in index.edges[edge_id].get("path_ids", [])
        ]
        result["affected"] = affected_summary_for_paths(index, path_ids, 500 if include_full_impacts else 10)
        result["affected"]["resource"] = entity_ref(entity)
        result["impact_detail"] = {
            "entity_detail": entity_detail(
                value,
                include_rule_summaries=include_full_impacts,
                include_route_summaries=include_full_impacts,
                include_member_enis=include_full_impacts,
            ),
            "external_sources": can_reach(value, external_only=True, take=500 if include_full_impacts else 10),
        }
    return result


@tool
def refresh_reachability_index() -> dict[str, Any]:
    """Reload live Cartography data and rebuild the cached reachability index."""
    index = refresh_index()
    return {"resource_count": len(index.entities), "edge_count": len(index.edges), "path_count": len(index.paths)}


def edge_matches_filters(
    edge: dict[str, Any],
    filters: dict[str, Any] | None,
    peer: dict[str, Any] | None = None,
    port: int | str | None = None,
    protocol: str | None = None,
    external_only: bool = False,
    sensitive_only: bool = False,
) -> bool:
    filters = filters or {}
    port = port if port is not None else filters.get("port")
    protocol = protocol or filters.get("protocol")
    if filters.get("resource_type") and peer and peer.get("resource_type") != filters["resource_type"]:
        return False
    if filters.get("resource_type") and not peer and filters["resource_type"] not in {
        edge.get("source_resource_type"),
        edge.get("destination_resource_type"),
    }:
        return False
    if filters.get("service_kind") and peer and peer.get("service_kind") != filters["service_kind"]:
        return False
    if filters.get("internet_exposed") is not None and peer and peer.get("internet_exposed") != filters["internet_exposed"]:
        return False
    if filters.get("external_kind") and filters["external_kind"] not in edge.get("external_kinds", []):
        return False
    if external_only and not edge.get("external_kinds") and "external" not in edge.get("risk_flags", []) and "transit_gateway" not in edge.get("risk_flags", []):
        return False
    if sensitive_only and peer and peer.get("service_kind") not in SENSITIVE_KINDS:
        return False
    if not edge_has_protocol(edge, protocol):
        return False
    if not edge_has_port(edge, port):
        return False
    if filters.get("risk_flag") and filters["risk_flag"] not in edge.get("risk_flags", []):
        return False
    rule_id = filters.get("security_group_rule_id")
    if rule_id and rule_id not in set(edge.get("egress_rules", []) + edge.get("ingress_rules", [])):
        return False
    return True


def edge_peer_row(
    edge_id: str,
    edge: dict[str, Any],
    peer: dict[str, Any],
    mode: str = "compact",
    fields: list[str] | None = None,
    include_rule_summaries: bool = False,
) -> dict[str, Any]:
    row = {
        "edge_id": edge_id,
        "resource_id": peer["resource_id"],
        "label": peer["label"],
        "resource_type": peer["resource_type"],
        "account_id": peer.get("account_id"),
        "account_name": peer.get("account_name"),
        "vpc_id": peer.get("vpc_id"),
        "service_kind": peer.get("service_kind"),
        "internet_exposed": peer.get("internet_exposed"),
        "path_count": edge["path_count"],
        "protocols": edge.get("protocols", []),
        "ports": edge.get("ports", []),
        "route_targets": edge.get("route_targets", []),
        "external_kinds": edge.get("external_kinds", []),
        "risk_flags": edge.get("risk_flags", []),
    }
    if normalize_mode(mode) in {"normal", "verbose"}:
        row["member_eni_count"] = len(peer.get("member_enis", []))
        row["sample_private_ips"] = peer.get("private_ips", [])[:3]
        row["grouping_status"] = peer.get("grouping_status")
    if normalize_mode(mode) == "verbose":
        row["member_enis"] = peer.get("member_enis", [])
    if include_rule_summaries:
        row["egress_rule_summaries"] = edge.get("egress_rule_summaries", [])
        row["ingress_rule_summaries"] = edge.get("ingress_rule_summaries", [])
    return apply_fields(row, fields)


def sort_peer_rows(rows: list[dict[str, Any]], sort_by: str) -> list[dict[str, Any]]:
    if sort_by == "label":
        return sorted(rows, key=lambda row: row.get("label", "").lower())
    if sort_by == "resource_type":
        return sorted(rows, key=lambda row: (row.get("resource_type") or "", row.get("label", "").lower()))
    if sort_by == "service_kind":
        return sorted(rows, key=lambda row: (row.get("service_kind") or "", row.get("label", "").lower()))
    if sort_by == "risk_count":
        return sorted(rows, key=lambda row: (len(row.get("risk_flags", [])), row.get("path_count", 0)), reverse=True)
    return sorted(rows, key=lambda row: (-row.get("path_count", 0), row.get("label", "").lower()))


def group_peer_rows(rows: list[dict[str, Any]], group_by: str) -> dict[str, int]:
    values = []
    for row in rows:
        if group_by == "risk_flag":
            values.extend(row.get("risk_flags", []) or ["none"])
        elif group_by == "port":
            values.extend(row.get("ports", []) or ["unknown"])
        elif group_by == "protocol":
            values.extend(row.get("protocols", []) or ["unknown"])
        elif group_by == "external_kind":
            values.extend(row.get("external_kinds", []) or ["internal"])
        else:
            values.append(row.get(group_by) or "unknown")
    return dict(Counter(values))


def representative_path_rows(rows: list[dict[str, Any]], distinct_by: list[str] | None = None) -> list[dict[str, Any]]:
    keys = distinct_by or ["packet", "route", "ingress_rule", "egress_rule", "destination_attachment_eni", "load_balancer_forwarding"]
    result = []
    seen = set()
    for row in rows:
        marker = []
        for key in keys:
            value = representative_marker_value(row, key)
            if isinstance(value, dict):
                value = json.dumps(value, sort_keys=True)
            marker.append(value)
        marker_tuple = tuple(marker)
        if marker_tuple in seen:
            continue
        seen.add(marker_tuple)
        result.append(row)
    return result


def representative_marker_value(row: dict[str, Any], key: str) -> Any:
    if key == "packet":
        return row.get("packet")
    steps = row.get("steps", [])
    if key == "egress_rule":
        return step_value(steps, "egress_security_group_rule", "rule", "rule_id")
    if key == "ingress_rule":
        return step_value(steps, "ingress_security_group_rule", "rule", "rule_id")
    if key == "route":
        return step_value(steps, "route", "route", "route_id")
    if key in {"destination_attachment_eni", "destination_eni"}:
        return step_value(steps, "destination_attachment_eni", "attachment", "eni_id")
    if key in {"source_attachment_eni", "source_eni"}:
        return step_value(steps, "source_attachment_eni", "attachment", "eni_id")
    if key in {"load_balancer_forwarding", "elb_target"}:
        return step_value(steps, "load_balancer_forwarding", "target")
    if key == "tgw_hop":
        return step_value(steps, "transit_gateway_hop", "hop")
    return row.get(key)


def step_value(steps: list[dict[str, Any]], step_type: str, payload_key: str, nested_key: str | None = None) -> Any:
    for step in steps:
        if step.get("type") != step_type:
            continue
        value = step.get(payload_key)
        if nested_key and isinstance(value, dict):
            return value.get(nested_key)
        return value
    return None


def path_risk_summary(path: dict[str, Any], destination: dict[str, Any]) -> str:
    signals = list(path.get("risk_flags", []))
    if path.get("external_kind"):
        signals.append(f"external:{path['external_kind']}")
    if destination.get("service_kind") in SENSITIVE_KINDS:
        signals.append(f"sensitive_destination:{destination['service_kind']}")
    if not signals:
        signals.append("no special risk flags")
    return "risk: " + ", ".join(sorted(set(signals)))


def resource_phrase(entity: dict[str, Any]) -> str:
    parts = [entity.get("label") or entity.get("resource_id")]
    resource_type = entity.get("resource_type")
    service_kind = entity.get("service_kind")
    if resource_type or service_kind:
        parts.append(f"({resource_type or 'resource'}; service={service_kind or 'unknown'})")
    owner_hints = entity.get("owner_hints") or {}
    owner_name = owner_hints.get("owner_name") or owner_hints.get("owner_id")
    if entity.get("resource_type") == "NetworkInterface" and owner_name:
        parts.append(f"owner={owner_name}")
    return " ".join(part for part in parts if part)


def impact_collection_summary(rows: list[dict[str, Any]], item_name: str, page: dict[str, Any]) -> dict[str, Any]:
    return {
        f"{item_name}_count": len(rows),
        "returned": page["returned"],
        "affected_paths": sum(row.get("affected_paths", 0) for row in rows),
        "external_paths": sum(row.get("external_path_count", 0) for row in rows),
        "wildcard_paths": sum(row.get("wildcard_path_count", 0) for row in rows),
        "broad_ingress_paths": sum(row.get("broad_ingress_path_count", 0) for row in rows),
        "sensitive_destinations": sum(row.get("sensitive_destination_count", 0) for row in rows),
    }


def impact_collection_grouped_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "risk_flags": dict(Counter(flag for row in rows for flag, count in row.get("grouped_counts", {}).get("risk_flags", {}).items() for _ in range(count))),
        "external_kinds": dict(Counter(kind for row in rows for kind, count in row.get("grouped_counts", {}).get("external_kinds", {}).items() for _ in range(count))),
        "protocols": dict(Counter(protocol for row in rows for protocol, count in row.get("grouped_counts", {}).get("protocols", {}).items() for _ in range(count))),
        "ports": dict(Counter(port for row in rows for port, count in row.get("grouped_counts", {}).get("ports", {}).items() for _ in range(count))),
        "destination_service_kinds": dict(Counter(kind for row in rows for kind, count in row.get("grouped_counts", {}).get("destination_service_kinds", {}).items() for _ in range(count))),
    }


def candidate_worthy_impact(impact: dict[str, Any]) -> bool:
    return any(
        impact.get(key, 0) > 0
        for key in (
            "external_path_count",
            "wildcard_path_count",
            "broad_ingress_path_count",
            "sensitive_destination_count",
        )
    )


def severity_hint(impact: dict[str, Any]) -> str:
    if (
        impact.get("sensitive_destination_count", 0) > 0
        and (impact.get("broad_ingress_path_count", 0) > 0 or impact.get("external_path_count", 0) > 0)
    ):
        return "high"
    if impact.get("wildcard_path_count", 0) > 0 or impact.get("broad_ingress_path_count", 0) > 0:
        return "medium"
    if impact.get("external_path_count", 0) > 0:
        return "medium"
    return "low"


def severity_rank(value: str | None) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(value or "low", 0)


def remediation_hints_for_candidate(candidate: dict[str, Any]) -> list[str]:
    kind = candidate.get("finding_type")
    flags = set()
    for edge in candidate.get("representative_edges", []):
        flags.update(edge.get("risk_flags", []))
    hints = []
    if kind == "security_group_rule_impact":
        hints.append("Review the supporting security group rule and narrow it to the minimum required sources, destinations, protocols, and ports.")
        if "broad_ingress" in flags or "broad_ingress" in candidate.get("risk_reasons", []):
            hints.append("Replace broad ingress CIDRs with specific CIDRs or security group references for the intended callers.")
        if "wildcard" in flags or "wildcard_protocol_or_port" in candidate.get("risk_reasons", []):
            hints.append("Replace wildcard protocol or port access with explicit application ports.")
        hints.append("Split shared security groups if unrelated workloads depend on the same permissive rule.")
    elif kind == "route_boundary_impact":
        hints.append("Review the supporting route and confirm that each affected source and destination needs this boundary path.")
        hints.append("Prefer narrower peer CIDRs, route-table scoping, or subnet segmentation for sensitive destinations.")
        if candidate.get("supporting_route_ids"):
            hints.append("Validate route-table associations before removing or narrowing the route.")
    elif kind == "internet_exposed_resource":
        hints.append("Confirm whether the resource requires public or internet-like inbound reachability.")
        hints.append("Remove public IPs or internet-facing paths when they are not required.")
        hints.append("Restrict inbound rules to trusted sources and verify load balancer or gateway exposure separately.")
    else:
        hints.append("Validate the representative path evidence, then narrow the enabling rule or route to the intended business flow.")
    return hints


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
