from __future__ import annotations

import json
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from cartography_reachability.live import ReachabilityConfig, trace_live_reachability
from cartography_reachability.overview import build_overview_graph, path_edge_key
from cartography_reachability.renderers.common import (
    edge_packet_label,
    edge_summary as summarize_edge_paths,
    group_label,
)


@dataclass
class ReachabilityIndex:
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    eni_to_entity: dict[str, str] = field(default_factory=dict)
    edges: dict[str, dict[str, Any]] = field(default_factory=dict)
    edge_by_pair: dict[tuple[str, str], str] = field(default_factory=dict)
    paths: dict[str, dict[str, Any]] = field(default_factory=dict)
    rule_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    route_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    rule_impacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    route_impacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    outgoing: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    incoming: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    route_to_paths: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    rule_to_paths: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    risk_to_edges: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "entities": self.entities,
            "eni_to_entity": self.eni_to_entity,
            "edges": self.edges,
            "edge_by_pair": {
                f"{source}\u241f{target}": edge_id
                for (source, target), edge_id in self.edge_by_pair.items()
            },
            "paths": self.paths,
            "rule_summaries": self.rule_summaries,
            "route_summaries": self.route_summaries,
            "rule_impacts": self.rule_impacts,
            "route_impacts": self.route_impacts,
            "outgoing": dict(self.outgoing),
            "incoming": dict(self.incoming),
            "route_to_paths": dict(self.route_to_paths),
            "rule_to_paths": dict(self.rule_to_paths),
            "risk_to_edges": dict(self.risk_to_edges),
        }


_INDEX: ReachabilityIndex | None = None
_INDEX_LOCK = threading.Lock()


def get_index() -> ReachabilityIndex:
    global _INDEX
    if _INDEX is None:
        with _INDEX_LOCK:
            if _INDEX is None:
                _INDEX = load_live_reachability()
    return _INDEX


def refresh_index() -> ReachabilityIndex:
    global _INDEX
    with _INDEX_LOCK:
        _INDEX = load_live_reachability()
        return _INDEX


def load_live_reachability(config: ReachabilityConfig | None = None) -> ReachabilityIndex:
    paths, enis = trace_live_reachability(config)
    return build_reachability_index(paths, enis)


def entity_summary(entity: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_id": entity["resource_id"],
        "label": entity["label"],
        "resource_type": entity["resource_type"],
        "member_eni_count": len(entity.get("member_enis", [])),
        "sample_private_ips": entity.get("private_ips", [])[:5],
        "eni_ids": [eni["eni_id"] for eni in entity.get("member_enis", [])[:10]],
        "account_id": entity.get("account_id"),
        "account_name": entity.get("account_name"),
        "region": entity.get("region"),
        "vpc_id": entity.get("vpc_id"),
        "incoming_edges": entity.get("incoming_edges", 0),
        "outgoing_edges": entity.get("outgoing_edges", 0),
        "risk_flags": entity.get("risk_flags", []),
    }


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    return [value]


def unique_sorted(values: Any) -> list[str]:
    return sorted({str(value) for value in as_list(values) if value not in (None, "")})


def paginate(items: list[Any], skip: int = 0, take: int = 50) -> dict[str, Any]:
    skip = max(0, int(skip))
    take = max(1, min(int(take), 500))
    page = items[skip : skip + take]
    next_skip = skip + take if skip + take < len(items) else None
    return {
        "items": page,
        "skip": skip,
        "take": take,
        "returned": len(page),
        "total": len(items),
        "next_skip": next_skip,
    }


def packet_label(packet: dict[str, Any]) -> str:
    return f"{packet.get('protocol', '*')}/{packet.get('ports', '*')}"


def port_values(values: Any) -> set[int]:
    ports: set[int] = set()
    for value in as_list(values):
        if value in (None, "", "*"):
            continue
        text = str(value)
        for part in text.split(","):
            part = part.strip()
            if not part or part == "*":
                continue
            if "-" in part:
                start, end = part.split("-", 1)
                if start.isdigit():
                    ports.add(int(start))
                if end.isdigit():
                    ports.add(int(end))
                continue
            if part.isdigit():
                ports.add(int(part))
    return ports


def packet_ports(packet: dict[str, Any]) -> set[int]:
    return port_values(packet.get("ports"))


def rule_record(rule: Any) -> dict[str, Any]:
    return rule.as_dict() if hasattr(rule, "as_dict") else dict(rule)


def route_record(route: Any) -> dict[str, Any]:
    return route.as_dict() if hasattr(route, "as_dict") else dict(route)


def risk_flags_for_path(path: Any) -> list[str]:
    flags = []
    if "0.0.0.0/0" in getattr(path.ingress_rule, "raw_cidrs", ()):
        flags.append("broad_ingress")
    if path.packet.protocol in {"*", "any", "-1"} or path.packet.port_min is None:
        flags.append("wildcard")
    if path.src.owner_type == "ExternalNetwork" or path.dst.owner_type == "ExternalNetwork":
        flags.append("external")
    if path.tgw_hop is not None:
        flags.append("transit_gateway")
    if path.elb_target is not None:
        flags.append("load_balancer_forwarding")
    return sorted(set(flags))


def compact_rule_summary(rule: dict[str, Any], path_flags: list[str] | None = None) -> dict[str, Any]:
    ports = "*"
    if rule.get("from_port") is not None:
        ports = (
            str(rule.get("from_port"))
            if rule.get("from_port") == rule.get("to_port")
            else f"{rule.get('from_port')}-{rule.get('to_port')}"
        )
    sources_or_destinations = list(rule.get("cidrs") or [])
    flags = set(path_flags or [])
    if "0.0.0.0/0" in sources_or_destinations:
        flags.add("broad_ingress")
    protocol = rule.get("protocol")
    if protocol in {"*", "any", "-1"} or ports == "*":
        flags.add("wildcard")
    return {
        "rule_id": rule.get("id"),
        "security_group_id": rule.get("sg_id"),
        "direction": rule.get("direction"),
        "protocol": protocol,
        "ports": ports,
        "cidrs": sources_or_destinations,
        "risk_flags": sorted(flags),
    }


def compact_route_summary(route: dict[str, Any], path_flags: list[str] | None = None) -> dict[str, Any]:
    target_kind = route.get("target_kind")
    flags = set(path_flags or [])
    if target_kind == "vpc_peering":
        flags.add("external")
    if target_kind == "transit_gateway":
        flags.add("transit_gateway")
    return {
        "route_id": route.get("id"),
        "route_table_id": route.get("route_table_id"),
        "destination": route.get("destination"),
        "target_kind": target_kind,
        "target": route.get("target"),
        "risk_flags": sorted(flags),
    }


def external_kind_for_path(path: Any) -> str | None:
    terminal_kinds = {
        value
        for value in (path.src.terminal_kind, path.dst.terminal_kind)
        if value
    }
    route_kind = path.route.target_kind()
    if any("internet" in kind for kind in terminal_kinds):
        return "internet"
    if any("peering" in kind for kind in terminal_kinds) or route_kind == "vpc_peering":
        return "vpc_peering"
    if path.tgw_hop is not None or any("transit_gateway" in kind for kind in terminal_kinds):
        return "transit_gateway"
    if any("vpn" in kind for kind in terminal_kinds):
        return "vpn"
    if any("direct" in kind or "dx" in kind for kind in terminal_kinds):
        return "direct_connect"
    if path.src.owner_type == "ExternalNetwork" or path.dst.owner_type == "ExternalNetwork":
        return "unknown_external"
    return None


def service_kind_from_ports(ports: set[int]) -> str | None:
    if ports & {3306, 5432, 1433, 1521, 27017, 9042}:
        return "database"
    if ports & {6379, 11211}:
        return "cache"
    if ports & {22, 3389, 5985, 5986}:
        return "admin"
    if ports & {9200, 9300}:
        return "search"
    if ports & {5671, 5672, 9092, 9093}:
        return "messaging"
    if ports & {9090, 9100, 3000, 5601}:
        return "monitoring"
    if ports & {6443, 8443, 10250}:
        return "admin"
    return None


def classify_service_kind(entity: dict[str, Any], incoming_ports: set[int], outgoing_ports: set[int]) -> tuple[str, bool]:
    text = " ".join(
        str(value).lower()
        for value in [
            entity.get("label"),
            entity.get("resource_type"),
            entity.get("arn"),
            *entity.get("security_groups", []),
            *entity.get("subnet_ids", []),
        ]
        if value
    )
    resource_type = entity.get("resource_type")
    if resource_type in {"RDSInstance", "RDSCluster"}:
        return "database", False
    if resource_type in {"LoadBalancer", "AWSLoadBalancerV2"}:
        return "load_balancer", False
    if any(token in text for token in ("redis", "cache", "memcached", "elasticache")):
        return "cache", True
    if any(token in text for token in ("postgres", "mysql", "mariadb", "oracle", "mssql", "mongo", "db", "database")):
        return "database", True
    if any(token in text for token in ("opensearch", "elasticsearch", "search")):
        return "search", True
    if any(token in text for token in ("rabbit", "kafka", "queue", "mq")):
        return "messaging", True
    if any(token in text for token in ("admin", "bastion", "jump", "ssh", "rdp")):
        return "admin", True
    if any(token in text for token in ("monitor", "prometheus", "grafana", "metrics")):
        return "monitoring", True
    port_kind = service_kind_from_ports(incoming_ports or outgoing_ports)
    if port_kind:
        return port_kind, True
    return "unknown", False


def grouping_status(entity: dict[str, Any]) -> str:
    properties = entity.get("properties", {})
    if properties.get("grouped"):
        return "grouped"
    if entity.get("resource_type") != "NetworkInterface":
        return "standalone"
    interface_type = str(properties.get("interface_type") or "").lower()
    if properties.get("requester_managed") or any(
        token in interface_type
        for token in ("lambda", "nat_gateway", "vpc_endpoint", "network_load_balancer")
    ):
        return "aws_managed"
    return "unknown_owner"


def owner_hints(entity: dict[str, Any]) -> dict[str, Any]:
    properties = entity.get("properties", {})
    return {
        "owner_id": properties.get("owner_id"),
        "owner_name": properties.get("owner_name"),
        "interface_type": properties.get("interface_type"),
        "requester_id": properties.get("requester_id"),
        "requester_managed": properties.get("requester_managed"),
        "member_descriptions": properties.get("member_descriptions", [])[:5],
        "security_groups": entity.get("security_groups", [])[:5],
        "subnet_ids": entity.get("subnet_ids", [])[:5],
    }


def build_reachability_index(paths: list[Any], enis: dict[str, Any] | None = None) -> ReachabilityIndex:
    index = ReachabilityIndex()
    overview = build_overview_graph(paths, group_identical_rays=True, enis=enis or {})

    for node in overview.nodes:
        member_enis = []
        for eni in node.member_enis:
            member = {
                "eni_id": eni.id,
                "private_ip": str(eni.private_ip),
                "public_ip": eni.public_ip,
                "subnet_id": eni.subnet_id,
                "subnet_cidr": str(eni.subnet_cidr),
                "security_groups": list(eni.sg_ids),
                "owner_id": eni.owner_id,
                "owner_name": eni.owner_name,
                "resource_type": eni.owner_type,
            }
            member_enis.append(member)
            index.eni_to_entity[eni.id] = node.id

        properties = dict(node.properties)
        entity = {
            "resource_id": node.id,
            "label": group_label(node),
            "resource_type": node.resource_type,
            "arn": node.resource_arn,
            "account_id": properties.get("account_id"),
            "account_name": properties.get("account_name"),
            "region": properties.get("region"),
            "vpc_id": properties.get("vpc_id"),
            "subnet_ids": unique_sorted(properties.get("member_subnet_ids") or properties.get("subnet_id")),
            "security_groups": unique_sorted(
                properties.get("member_security_groups") or properties.get("security_groups")
            ),
            "private_ips": unique_sorted(properties.get("member_private_ips") or properties.get("private_ip")),
            "public_ips": unique_sorted(properties.get("member_public_ips") or properties.get("public_ip")),
            "member_enis": member_enis,
            "properties": properties,
            "incoming_edges": 0,
            "outgoing_edges": 0,
            "path_count_in": 0,
            "path_count_out": 0,
            "risk_flags": [],
            "service_kind": "unknown",
            "service_kind_inferred": False,
            "internet_exposed": False,
            "external_kinds": [],
            "grouping_status": None,
            "owner_hints": {},
        }
        index.entities[node.id] = entity

    sorted_edges = sorted(overview.edges, key=lambda edge: (edge.source, edge.target, edge.id))
    for edge_number, edge in enumerate(sorted_edges, start=1):
        edge_id = f"edge-{edge_number:04d}"
        edge_paths = sorted(edge.paths, key=path_edge_key)
        summary = summarize_edge_paths(edge_paths)
        flags = sorted({flag for path in edge_paths for flag in risk_flags_for_path(path)})
        edge_record = {
            "edge_id": edge_id,
            "source_id": edge.source,
            "destination_id": edge.target,
            "source": {"resource_id": edge.source, "label": index.entities[edge.source]["label"]},
            "destination": {"resource_id": edge.target, "label": index.entities[edge.target]["label"]},
            "source_resource_type": index.entities[edge.source]["resource_type"],
            "destination_resource_type": index.entities[edge.target]["resource_type"],
            "path_count": len(edge_paths),
            "packet_labels": sorted(summary["packet_labels"]),
            "routes": sorted(summary["route_ids"]),
            "route_targets": sorted(summary["route_targets"]),
            "egress_rules": sorted(summary["egress_ids"]),
            "ingress_rules": sorted(summary["ingress_ids"]),
            "tgw_hops": sorted(summary["tgw_hops"]),
            "elb_target_groups": sorted(summary["elb_target_groups"]),
            "protocols": sorted(summary["protocols"]),
            "ports": sorted(summary["ports"]),
            "risk_flags": flags,
            "path_ids": [],
        }
        index.edges[edge_id] = edge_record
        index.edge_by_pair[(edge.source, edge.target)] = edge_id
        index.outgoing[edge.source].append(edge_id)
        index.incoming[edge.target].append(edge_id)
        for flag in flags:
            index.risk_to_edges[flag].append(edge_id)

        for path in edge_paths:
            path_id = f"path-{len(index.paths) + 1:06d}"
            path_flags = risk_flags_for_path(path)
            external_kind = external_kind_for_path(path)
            egress_rule = rule_record(path.egress_rule)
            ingress_rule = rule_record(path.ingress_rule)
            route = route_record(path.route)
            path_record = {
                "path_id": path_id,
                "edge_id": edge_id,
                "source_id": edge.source,
                "destination_id": edge.target,
                "source_label": index.entities[edge.source]["label"],
                "destination_label": index.entities[edge.target]["label"],
                "source_eni": path.src.id,
                "destination_eni": path.dst.id,
                "source_private_ip": str(path.src.private_ip),
                "destination_private_ip": str(path.dst.private_ip),
                "packet": path.packet.as_dict(),
                "packet_label": edge_packet_label(path),
                "packet_space_by_stage": path.as_dict().get("packet_space_by_stage", {}),
                "egress_rule": egress_rule,
                "route": route,
                "ingress_rule": ingress_rule,
                "tgw_hop": path.tgw_hop.as_dict() if path.tgw_hop else None,
                "elb_target": path.elb_target.as_dict() if path.elb_target else None,
                "risk_flags": path_flags,
                "external_kind": external_kind,
                "source_resource_type": index.entities[edge.source]["resource_type"],
                "destination_resource_type": index.entities[edge.target]["resource_type"],
            }
            index.paths[path_id] = path_record
            edge_record["path_ids"].append(path_id)
            index.route_to_paths[path.route.id].append(path_id)
            index.rule_to_paths[path.egress_rule.id].append(path_id)
            index.rule_to_paths[path.ingress_rule.id].append(path_id)
            index.rule_summaries.setdefault(
                path.egress_rule.id,
                compact_rule_summary(egress_rule, path_flags),
            )
            index.rule_summaries.setdefault(
                path.ingress_rule.id,
                compact_rule_summary(ingress_rule, path_flags),
            )
            index.route_summaries.setdefault(
                path.route.id,
                compact_route_summary(route, path_flags),
            )

        edge_record["egress_rule_summaries"] = [
            index.rule_summaries[rule_id] for rule_id in edge_record["egress_rules"]
        ]
        edge_record["ingress_rule_summaries"] = [
            index.rule_summaries[rule_id] for rule_id in edge_record["ingress_rules"]
        ]
        edge_record["route_summaries"] = [
            index.route_summaries[route_id] for route_id in edge_record["routes"]
        ]
        edge_record["packet_spaces"] = sorted(
            {
                json.dumps(index.paths[path_id]["packet"], sort_keys=True)
                for path_id in edge_record["path_ids"]
            }
        )
        edge_record["external_kinds"] = sorted(
            {
                index.paths[path_id]["external_kind"]
                for path_id in edge_record["path_ids"]
                if index.paths[path_id]["external_kind"]
            }
        )
        edge_record["load_balancer_forwarding"] = [
            index.paths[path_id]["elb_target"]
            for path_id in edge_record["path_ids"]
            if index.paths[path_id].get("elb_target")
        ]

    for entity_id, entity in index.entities.items():
        out_edges = index.outgoing.get(entity_id, [])
        in_edges = index.incoming.get(entity_id, [])
        incoming_paths = [
            index.paths[path_id]
            for edge_id in in_edges
            for path_id in index.edges[edge_id]["path_ids"]
        ]
        outgoing_paths = [
            index.paths[path_id]
            for edge_id in out_edges
            for path_id in index.edges[edge_id]["path_ids"]
        ]
        incoming_ports = {
            port for path in incoming_paths for port in packet_ports(path.get("packet", {}))
        }
        outgoing_ports = {
            port for path in outgoing_paths for port in packet_ports(path.get("packet", {}))
        }
        service_kind, inferred = classify_service_kind(entity, incoming_ports, outgoing_ports)
        external_kinds = sorted(
            {
                path["external_kind"]
                for path in incoming_paths + outgoing_paths
                if path.get("external_kind")
            }
        )
        entity["outgoing_edges"] = len(out_edges)
        entity["incoming_edges"] = len(in_edges)
        entity["path_count_out"] = sum(index.edges[edge_id]["path_count"] for edge_id in out_edges)
        entity["path_count_in"] = sum(index.edges[edge_id]["path_count"] for edge_id in in_edges)
        entity["risk_flags"] = sorted(
            {flag for edge_id in out_edges + in_edges for flag in index.edges[edge_id]["risk_flags"]}
        )
        entity["service_kind"] = service_kind
        entity["service_kind_inferred"] = inferred
        entity["external_kinds"] = external_kinds
        entity["internet_exposed"] = bool(
            entity.get("public_ips")
            and (
                entity["incoming_edges"] > 0
                or "broad_ingress" in entity["risk_flags"]
                or "internet" in external_kinds
            )
        ) or any(path.get("external_kind") == "internet" for path in incoming_paths)
        entity["grouping_status"] = grouping_status(entity)
        entity["owner_hints"] = owner_hints(entity)

    index.rule_impacts = build_rule_impacts(index)
    index.route_impacts = build_route_impacts(index)
    return index


def counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def path_entities(index: ReachabilityIndex, path_ids: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sources = [index.entities[index.paths[path_id]["source_id"]] for path_id in path_ids]
    destinations = [index.entities[index.paths[path_id]["destination_id"]] for path_id in path_ids]
    return sources, destinations


def impact_samples(
    index: ReachabilityIndex,
    path_ids: list[str],
    sample_limit: int = 5,
) -> list[dict[str, Any]]:
    samples = []
    seen_edges = set()
    for path_id in path_ids:
        path = index.paths[path_id]
        edge_id = path["edge_id"]
        if edge_id in seen_edges:
            continue
        seen_edges.add(edge_id)
        edge = index.edges[edge_id]
        samples.append(
            {
                "edge_id": edge_id,
                "source": edge["source"],
                "destination": edge["destination"],
                "packets": edge.get("packet_labels", []),
                "risk_flags": edge.get("risk_flags", []),
            }
        )
        if len(samples) >= sample_limit:
            break
    return samples


def grouped_counts(index: ReachabilityIndex, path_ids: list[str]) -> dict[str, Any]:
    sources, destinations = path_entities(index, path_ids)
    paths = [index.paths[path_id] for path_id in path_ids]
    return {
        "source_resource_types": counter_dict([entity.get("resource_type") or "unknown" for entity in sources]),
        "destination_resource_types": counter_dict([entity.get("resource_type") or "unknown" for entity in destinations]),
        "source_accounts": counter_dict([entity.get("account_id") or "unknown" for entity in sources]),
        "destination_accounts": counter_dict([entity.get("account_id") or "unknown" for entity in destinations]),
        "source_vpcs": counter_dict([entity.get("vpc_id") or "unknown" for entity in sources]),
        "destination_vpcs": counter_dict([entity.get("vpc_id") or "unknown" for entity in destinations]),
        "destination_service_kinds": counter_dict([entity.get("service_kind") or "unknown" for entity in destinations]),
        "risk_flags": counter_dict([flag for path in paths for flag in path.get("risk_flags", [])]),
        "external_kinds": counter_dict([path.get("external_kind") or "internal" for path in paths]),
        "protocols": counter_dict([path.get("packet", {}).get("protocol") or "unknown" for path in paths]),
        "ports": counter_dict([path.get("packet", {}).get("ports") or "unknown" for path in paths]),
    }


def impact_score(impact: dict[str, Any]) -> int:
    return (
        impact.get("affected_paths", 0)
        + impact.get("affected_source_count", 0) * 3
        + impact.get("affected_destination_count", 0) * 3
        + impact.get("external_path_count", 0) * 5
        + impact.get("wildcard_path_count", 0) * 4
        + impact.get("broad_ingress_path_count", 0) * 4
        + impact.get("sensitive_destination_count", 0) * 5
    )


def build_rule_impacts(index: ReachabilityIndex) -> dict[str, dict[str, Any]]:
    impacts = {}
    for rule_id, path_ids in index.rule_to_paths.items():
        paths = [index.paths[path_id] for path_id in path_ids]
        sources, destinations = path_entities(index, path_ids)
        summary = index.rule_summaries.get(rule_id, {"rule_id": rule_id})
        sensitive_destination_ids = {
            entity["resource_id"]
            for entity in destinations
            if entity.get("service_kind") not in {None, "unknown", "load_balancer"}
        }
        impact = {
            **summary,
            "affected_paths": len(path_ids),
            "affected_source_count": len({path["source_id"] for path in paths}),
            "affected_destination_count": len({path["destination_id"] for path in paths}),
            "external_path_count": sum(1 for path in paths if path.get("external_kind")),
            "wildcard_path_count": sum(1 for path in paths if "wildcard" in path.get("risk_flags", [])),
            "broad_ingress_path_count": sum(1 for path in paths if "broad_ingress" in path.get("risk_flags", [])),
            "sensitive_destination_count": len(sensitive_destination_ids),
            "packets": sorted({path["packet_label"] for path in paths}),
            "grouped_counts": grouped_counts(index, path_ids),
            "sample_edges": impact_samples(index, path_ids),
        }
        impact["score"] = impact_score(impact)
        impacts[rule_id] = impact
    return impacts


def build_route_impacts(index: ReachabilityIndex) -> dict[str, dict[str, Any]]:
    impacts = {}
    for route_id, path_ids in index.route_to_paths.items():
        paths = [index.paths[path_id] for path_id in path_ids]
        destinations = [index.entities[path["destination_id"]] for path in paths]
        summary = index.route_summaries.get(route_id, {"route_id": route_id})
        sensitive_destination_ids = {
            entity["resource_id"]
            for entity in destinations
            if entity.get("service_kind") not in {None, "unknown", "load_balancer"}
        }
        impact = {
            **summary,
            "affected_paths": len(path_ids),
            "affected_source_count": len({path["source_id"] for path in paths}),
            "affected_destination_count": len({path["destination_id"] for path in paths}),
            "external_path_count": sum(1 for path in paths if path.get("external_kind")),
            "wildcard_path_count": sum(1 for path in paths if "wildcard" in path.get("risk_flags", [])),
            "broad_ingress_path_count": sum(1 for path in paths if "broad_ingress" in path.get("risk_flags", [])),
            "sensitive_destination_count": len(sensitive_destination_ids),
            "packets": sorted({path["packet_label"] for path in paths}),
            "grouped_counts": grouped_counts(index, path_ids),
            "sample_edges": impact_samples(index, path_ids),
        }
        impact["score"] = impact_score(impact)
        impacts[route_id] = impact
    return impacts


def save_index_json(path: str | Path) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(get_index().to_jsonable(), indent=2, sort_keys=True), encoding="utf-8")
    return output_path
