from __future__ import annotations

import json
from typing import Any

from cartography_reachability.constants import ANY_PROTOCOL
from cartography_reachability.models import Eni, PacketSpace, ReachabilityPath
from cartography_reachability.overview import OverviewNode, path_edge_key


def edge_packet_label(path: ReachabilityPath) -> str:
    data = path.packet.as_dict()
    return f"{data['protocol']}/{data['ports']}"


def summarize_ports(values: set[str], limit: int = 4) -> str:
    if not values:
        return "-"
    ordered = sorted(values)
    if len(ordered) <= limit:
        return ", ".join(ordered)
    return ", ".join(ordered[:limit]) + f" +{len(ordered) - limit}"


def eni_node_id(eni: Eni) -> str:
    return f"eni:{eni.id}"


def group_label(node: OverviewNode) -> str:
    descriptions = node.properties.get("member_descriptions") or []
    if node.properties.get("group_type") == "elb" and descriptions:
        return ", ".join(str(description) for description in descriptions)
    return node.label.replace("\n", " ")


def edge_summary(edge_paths: list[ReachabilityPath]) -> dict[str, Any]:
    packet_labels = {edge_packet_label(path) for path in edge_paths}
    packet_spaces = {
        json.dumps(path.packet.as_dict(), sort_keys=True) for path in edge_paths
    }
    dst_cidrs = {str(path.packet.dst) for path in edge_paths}
    protocols = {path.packet.protocol for path in edge_paths}
    ports = {path.packet.as_dict()["ports"] for path in edge_paths}
    broad_ingress = any(
        "0.0.0.0/0" in path.ingress_rule.raw_cidrs for path in edge_paths
    )
    wildcard = any(
        path.packet.protocol == ANY_PROTOCOL or path.packet.port_min is None
        for path in edge_paths
    )
    route_targets = {
        f"{path.route.target_kind()}:{path.route.as_dict()['target']}"
        for path in edge_paths
    }
    route_ids = {path.route.id for path in edge_paths}
    egress_ids = {path.egress_rule.id for path in edge_paths}
    ingress_ids = {path.ingress_rule.id for path in edge_paths}
    elb_target_groups = {
        value
        for value in (
            path.elb_target.target_group_arn or path.elb_target.target_group_name
            for path in edge_paths
            if path.elb_target is not None
        )
        if value
    }
    tgw_hops = {
        f"{path.tgw_hop.tgw_id}:{path.tgw_hop.route_table_id}:"
        f"{path.tgw_hop.destination_attachment_id}"
        for path in edge_paths
        if path.tgw_hop is not None
    }

    return {
        "packet_labels": packet_labels,
        "packet_spaces": packet_spaces,
        "dst_cidrs": dst_cidrs,
        "protocols": protocols,
        "ports": ports,
        "broad_ingress": broad_ingress,
        "wildcard": wildcard,
        "route_targets": route_targets,
        "route_ids": route_ids,
        "egress_ids": egress_ids,
        "ingress_ids": ingress_ids,
        "elb_target_groups": elb_target_groups,
        "tgw_hops": tgw_hops,
        "path_count": len(edge_paths),
    }


def path_payload(path: ReachabilityPath) -> dict[str, Any]:
    packet_space_by_stage = {
        "initial": PacketSpace().as_dict(),
        "after_egress": path.egress_packet.as_dict(),
        "after_route": path.routed_packet.as_dict(),
        "after_ingress": path.packet.as_dict(),
    }
    if path.elb_target:
        packet_space_by_stage = {
            "initial": PacketSpace().as_dict(),
            "after_elb_target": (path.elb_packet or PacketSpace()).as_dict(),
            "after_egress": path.egress_packet.as_dict(),
            "after_route": path.routed_packet.as_dict(),
            "after_ingress": path.packet.as_dict(),
        }

    return {
        "packet_space": path.packet.as_dict(),
        "packet_space_by_stage": packet_space_by_stage,
        "elb_target": path.elb_target.as_dict() if path.elb_target else None,
        "tgw_hop": path.tgw_hop.as_dict() if path.tgw_hop else None,
        "egress_rule": path.egress_rule.as_dict(),
        "route": path.route.as_dict(),
        "ingress_rule": path.ingress_rule.as_dict(),
    }


def edge_payload(
    edge_id: str, source: str, target: str, paths: list[ReachabilityPath]
) -> dict[str, Any]:
    summary = edge_summary(paths)
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "label": summarize_ports(summary["packet_labels"]),
        "path_count": summary["path_count"],
        "packet_spaces": sorted(summary["packet_spaces"]),
        "packet_labels": sorted(summary["packet_labels"]),
        "protocols": sorted(summary["protocols"]),
        "ports": sorted(summary["ports"]),
        "dst_cidrs": sorted(summary["dst_cidrs"]),
        "route_ids": sorted(summary["route_ids"]),
        "route_targets": sorted(summary["route_targets"]),
        "elb_target_groups": sorted(summary["elb_target_groups"]),
        "tgw_hops": sorted(summary["tgw_hops"]),
        "egress_rules": sorted(summary["egress_ids"]),
        "ingress_rules": sorted(summary["ingress_ids"]),
        "wildcard": summary["wildcard"],
        "broad_ingress": summary["broad_ingress"],
        "paths": [path_payload(path) for path in sorted(paths, key=path_edge_key)],
    }
