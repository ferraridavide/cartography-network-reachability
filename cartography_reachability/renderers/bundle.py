from __future__ import annotations

import json
from typing import Any

from cartography_reachability.metadata import (
    ecs_cluster_name_from_arn,
    ecs_service_name_from_arn,
    lambda_name_from_eni_description,
)
from cartography_reachability.models import Eni, ReachabilityPath
from cartography_reachability.overview import OverviewNode, build_overview_graph, path_edge_key

from .common import edge_payload, edge_summary, eni_node_id, group_label, summarize_ports


def elb_name_from_eni(eni: Eni) -> str | None:
    value = eni.description or eni.elb_arn or eni.owner_name
    if not value:
        return None
    if value.startswith("ELB "):
        value = value[4:]
    if "loadbalancer/" in value:
        value = value.split("loadbalancer/", 1)[1]
    parts = [part for part in value.split("/") if part]
    if len(parts) >= 3 and parts[0] in {"app", "net", "gwy"}:
        return parts[1]
    if parts:
        return parts[0]
    return value


def ecs_task_id(eni: Eni) -> str:
    return (eni.owner_id or eni.id).rstrip("/").rsplit("/", 1)[-1]


def bundle_eni_label(eni: Eni) -> str:
    if eni.owner_type == "EC2Instance":
        if eni.owner_name and eni.owner_name != eni.owner_id:
            return eni.owner_name
        return eni.owner_id or eni.id
    if eni.owner_type == "ECSTask":
        service_name = eni.ecs_service_name or ecs_service_name_from_arn(
            eni.ecs_service_arn
        )
        cluster_name = (
            eni.ecs_cluster_name
            or ecs_cluster_name_from_arn(eni.ecs_cluster_arn)
            or ecs_cluster_name_from_arn(eni.owner_id)
        )
        if service_name:
            return service_name
        if cluster_name:
            return cluster_name
        return ecs_task_id(eni)
    if eni.elb_arn or eni.owner_type in {"LoadBalancer", "AWSLoadBalancerV2"}:
        label = elb_name_from_eni(eni) or eni.description or eni.owner_name or eni.id
        if eni.subnet_availability_zone:
            return f"{label} ({eni.subnet_availability_zone})"
        return label
    if eni.owner_type in {"RDSInstance", "RDSCluster"} and eni.owner_name:
        return eni.owner_name
    lambda_name = lambda_name_from_eni_description(eni.description)
    if lambda_name:
        return lambda_name
    return eni.description or eni.owner_name or eni.owner_id or eni.id


def bundle_node_payload(eni: Eni, group: OverviewNode) -> dict[str, Any]:
    node = eni.as_node()
    label = bundle_eni_label(eni)
    return {
        "id": eni_node_id(eni),
        "eni_id": eni.id,
        "label": label,
        "eni_label": f"{eni.id} {eni.private_ip}",
        "private_ip": str(eni.private_ip),
        "group_id": group.id,
        "group_label": group_label(group),
        "resource_type": eni.owner_type,
        "resource_arn": eni.owner_arn,
        "account_id": eni.account_id,
        "account_name": eni.account_name,
        "vpc_id": eni.vpc_id,
        "subnet_id": eni.subnet_id,
        "subnet_availability_zone": eni.subnet_availability_zone,
        "security_groups": list(eni.sg_ids),
        "properties": node,
    }


def build_hierarchy(groups: list[OverviewNode]) -> dict[str, Any]:
    children = []
    for group in groups:
        leaves = []
        for eni in sorted(
            group.member_enis, key=lambda item: (str(item.private_ip), item.id)
        ):
            label = bundle_eni_label(eni)
            leaves.append(
                {
                    "name": label,
                    "node_id": eni_node_id(eni),
                    "label": label,
                    "eni_label": f"{eni.id} {eni.private_ip}",
                    "private_ip": str(eni.private_ip),
                    "resource_type": eni.owner_type,
                }
            )
        children.append(
            {
                "name": group_label(group),
                "group_id": group.id,
                "resource_type": group.resource_type,
                "children": leaves,
            }
        )
    return {"name": "aws", "children": children}


def build_bundle_payload(
    paths: list[ReachabilityPath],
    group_identical_rays: bool = True,
    enis: dict[str, Eni] | None = None,
) -> dict[str, Any]:
    overview = build_overview_graph(paths, group_identical_rays, enis)
    groups = sorted(
        overview.nodes, key=lambda node: (group_label(node).lower(), node.id)
    )
    axis: list[tuple[OverviewNode, Eni]] = []
    for group in groups:
        for eni in sorted(
            group.member_enis, key=lambda item: (str(item.private_ip), item.id)
        ):
            axis.append((group, eni))

    raw_edge_paths: dict[tuple[str, str], dict[tuple[Any, ...], ReachabilityPath]] = {}
    for path in paths:
        source = eni_node_id(path.src)
        target = eni_node_id(path.dst)
        raw_edge_paths.setdefault((source, target), {})[path_edge_key(path)] = path

    edges = []
    for index, ((source, target), deduped) in enumerate(sorted(raw_edge_paths.items())):
        edge_paths = list(deduped.values())
        payload = edge_payload(f"ray-{index}", source, target, edge_paths)
        summary = edge_summary(edge_paths)
        payload["width"] = max(1, min(8, 1 + summary["path_count"] // 3))
        payload["caption"] = summarize_ports(summary["packet_labels"])
        edges.append(payload)

    nodes = [bundle_node_payload(eni, group) for group, eni in axis]
    return {
        "generated_by": "cartography_reachability",
        "view": "hierarchical-edge-bundling",
        "group_identical_rays": group_identical_rays,
        "node_count": len(nodes),
        "group_count": len(groups),
        "edge_count": len(edges),
        "path_count": len(paths),
        "hierarchy": build_hierarchy(groups),
        "nodes": nodes,
        "edges": edges,
    }


def render_bundle_json(
    paths: list[ReachabilityPath],
    output_path: str,
    group_identical_rays: bool = True,
    enis: dict[str, Eni] | None = None,
) -> str:
    payload = build_bundle_payload(paths, group_identical_rays, enis)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return output_path
