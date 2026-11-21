from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .metadata import ecs_cluster_name_from_arn, ecs_service_name_from_arn
from .models import Eni, ReachabilityPath


@dataclass(frozen=True)
class WorkloadIdentity:
    kind: str
    key: str
    resource_type: str
    name: str | None
    arn: str | None
    groupable: bool


@dataclass(frozen=True)
class OverviewNode:
    id: str
    label: str
    resource_type: str
    resource_arn: str | None
    member_enis: tuple[Eni, ...]
    properties: dict[str, Any]


@dataclass(frozen=True)
class OverviewEdge:
    id: str
    source: str
    target: str
    paths: tuple[ReachabilityPath, ...]


@dataclass(frozen=True)
class OverviewGraph:
    nodes: tuple[OverviewNode, ...]
    edges: tuple[OverviewEdge, ...]
    path_count: int


def workload_identity(eni: Eni) -> WorkloadIdentity:
    if eni.elb_arn:
        return WorkloadIdentity(
            kind="elb",
            key=eni.elb_arn,
            resource_type="LoadBalancer",
            name=eni.owner_name,
            arn=eni.elb_arn,
            groupable=True,
        )

    if (
        eni.owner_type == "EC2Instance"
        and eni.auto_scaling_group_arn
        and eni.instance_profile_arn
    ):
        return WorkloadIdentity(
            kind="ec2_asg_instance_profile",
            key=f"{eni.auto_scaling_group_arn}|{eni.instance_profile_arn}",
            resource_type="AutoScalingGroup",
            name=eni.auto_scaling_group_name,
            arn=eni.auto_scaling_group_arn,
            groupable=True,
        )

    if eni.owner_type == "ECSTask" and eni.ecs_service_arn:
        return WorkloadIdentity(
            kind="ecs_service",
            key=eni.ecs_service_arn,
            resource_type="ECSService",
            name=eni.ecs_service_name or ecs_service_name_from_arn(eni.ecs_service_arn),
            arn=eni.ecs_service_arn,
            groupable=True,
        )

    if eni.owner_type == "ECSTask" and eni.ecs_cluster_arn:
        return WorkloadIdentity(
            kind="ecs_cluster",
            key=eni.ecs_cluster_arn,
            resource_type="ECSCluster",
            name=eni.ecs_cluster_name or ecs_cluster_name_from_arn(eni.ecs_cluster_arn),
            arn=eni.ecs_cluster_arn,
            groupable=True,
        )

    return WorkloadIdentity(
        kind="eni",
        key=eni.id,
        resource_type=eni.owner_type,
        name=eni.owner_name,
        arn=eni.owner_arn,
        groupable=False,
    )


def packet_signature(packet: Any) -> tuple[Any, ...]:
    return (
        str(packet.dst),
        packet.protocol,
        packet.port_min,
        packet.port_max,
    )


def rule_signature(rule: Any) -> tuple[Any, ...]:
    return (
        rule.id,
        rule.sg_id,
        rule.protocol,
        rule.from_port,
        rule.to_port,
        tuple(sorted(rule.raw_cidrs)),
    )


def route_signature(path: ReachabilityPath) -> tuple[Any, ...]:
    route_data = path.route.as_dict()
    return (
        path.route.id,
        path.route.route_table_id,
        str(path.route.destination),
        route_data["target_kind"],
        route_data["target"],
    )


def elb_target_signature(path: ReachabilityPath) -> tuple[Any, ...] | None:
    if path.elb_target is None:
        return None
    return (
        path.elb_target.load_balancer_arn,
        path.elb_target.target_eni_id,
        path.elb_target.target_group_arn,
        path.elb_target.protocol,
        path.elb_target.port,
    )


def tgw_hop_signature(path: ReachabilityPath) -> tuple[Any, ...] | None:
    if path.tgw_hop is None:
        return None
    return (
        path.tgw_hop.tgw_id,
        path.tgw_hop.source_attachment_id,
        path.tgw_hop.destination_attachment_id,
        path.tgw_hop.route_table_id,
        path.tgw_hop.route_id,
        str(path.tgw_hop.destination),
        path.tgw_hop.route_type,
        path.tgw_hop.state,
    )


def path_evidence_signature(
    path: ReachabilityPath, identities: dict[str, WorkloadIdentity]
) -> tuple[Any, ...]:
    destination_identity = identities[path.dst.id]
    return (
        destination_identity.kind,
        destination_identity.key,
        packet_signature(path.egress_packet),
        packet_signature(path.routed_packet),
        packet_signature(path.packet),
        elb_target_signature(path),
        tgw_hop_signature(path),
        route_signature(path),
        rule_signature(path.egress_rule),
        rule_signature(path.ingress_rule),
    )


def path_edge_key(path: ReachabilityPath) -> tuple[Any, ...]:
    return (
        path.src.id,
        path.dst.id,
        packet_signature(path.egress_packet),
        packet_signature(path.routed_packet),
        packet_signature(path.packet),
        elb_target_signature(path),
        tgw_hop_signature(path),
        route_signature(path),
        rule_signature(path.egress_rule),
        rule_signature(path.ingress_rule),
    )


def stable_group_id(identity: WorkloadIdentity, outgoing_signature: tuple[Any, ...]) -> str:
    payload = json.dumps(
        [identity.kind, identity.key, outgoing_signature], sort_keys=True, default=str
    )
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
    return f"group:{identity.kind}:{digest}"


def eni_node_id(eni: Eni) -> str:
    return f"eni:{eni.id}"


def eni_node_label(eni: Eni) -> str:
    return f"{eni.owner_name or eni.display_id()}\n{eni.owner_type} {eni.private_ip}"


def node_properties(
    identity: WorkloadIdentity, member_enis: tuple[Eni, ...], grouped: bool
) -> dict[str, Any]:
    first = member_enis[0]
    member_security_groups = sorted({sg for eni in member_enis for sg in eni.sg_ids})
    member_subnets = sorted({eni.subnet_id for eni in member_enis if eni.subnet_id})
    member_descriptions = sorted(
        {eni.description for eni in member_enis if eni.description}
    )

    return {
        "kind": "workload_group" if grouped else "resource_eni",
        "grouped": grouped,
        "group_type": identity.kind,
        "group_key": identity.key,
        "member_count": len(member_enis),
        "member_eni_ids": [eni.id for eni in member_enis],
        "member_private_ips": [str(eni.private_ip) for eni in member_enis],
        "member_public_ips": [eni.public_ip for eni in member_enis if eni.public_ip],
        "member_subnet_ids": member_subnets,
        "member_security_groups": member_security_groups,
        "member_descriptions": member_descriptions,
        "eni_id": first.id if not grouped else None,
        "resource_type": identity.resource_type,
        "resource_arn": identity.arn,
        "owner_id": first.owner_id,
        "owner_name": identity.name or first.owner_name,
        "owner_labels": sorted({label for eni in member_enis for label in eni.owner_labels}),
        "private_ip": str(first.private_ip) if not grouped else None,
        "public_ip": first.public_ip if not grouped else None,
        "private_dns_name": first.private_dns_name if not grouped else None,
        "mac_address": first.mac_address if not grouped else None,
        "description": first.description if not grouped else None,
        "interface_type": first.interface_type,
        "requester_id": first.requester_id,
        "requester_managed": first.requester_managed,
        "device_index": first.device_index if not grouped else None,
        "subnet_id": first.subnet_id if not grouped else None,
        "subnet_cidr": str(first.subnet_cidr) if not grouped else None,
        "vpc_id": first.vpc_id,
        "region": first.region,
        "account_id": first.account_id,
        "account_name": first.account_name,
        "security_groups": list(first.sg_ids) if not grouped else member_security_groups,
        "elb_arn": first.elb_arn,
        "auto_scaling_group_arn": first.auto_scaling_group_arn,
        "auto_scaling_group_name": first.auto_scaling_group_name,
        "instance_profile_arn": first.instance_profile_arn,
        "instance_profile_name": first.instance_profile_name,
        "ecs_service_arn": first.ecs_service_arn,
        "ecs_service_name": first.ecs_service_name,
        "ecs_cluster_arn": first.ecs_cluster_arn,
        "ecs_cluster_name": first.ecs_cluster_name,
    }


def build_overview_graph(
    paths: list[ReachabilityPath],
    group_identical_rays: bool = True,
    enis: dict[str, Eni] | None = None,
) -> OverviewGraph:
    eni_index: dict[str, Eni] = dict(enis or {})
    for path in paths:
        eni_index[path.src.id] = path.src
        eni_index[path.dst.id] = path.dst

    identities = {eni_id: workload_identity(eni) for eni_id, eni in eni_index.items()}
    outgoing: dict[str, list[tuple[Any, ...]]] = {eni_id: [] for eni_id in eni_index}
    for path in paths:
        outgoing[path.src.id].append(path_evidence_signature(path, identities))

    bucket_by_eni: dict[str, tuple[Any, ...]] = {}
    eni_ids_by_bucket: dict[tuple[Any, ...], list[str]] = {}
    for eni_id, identity in identities.items():
        outgoing_signature = tuple(sorted(outgoing[eni_id]))
        bucket = (
            identity.kind,
            identity.key,
            identity.resource_type,
            outgoing_signature,
        )
        bucket_by_eni[eni_id] = bucket
        eni_ids_by_bucket.setdefault(bucket, []).append(eni_id)

    node_id_by_eni: dict[str, str] = {}
    members_by_node: dict[str, list[Eni]] = {}
    identity_by_node: dict[str, WorkloadIdentity] = {}

    for eni_id, eni in eni_index.items():
        identity = identities[eni_id]
        bucket = bucket_by_eni[eni_id]
        should_group = (
            group_identical_rays
            and identity.groupable
            and len(eni_ids_by_bucket[bucket]) > 1
        )
        if should_group:
            node_id = stable_group_id(identity, bucket[-1])
        else:
            node_id = eni_node_id(eni)
        node_id_by_eni[eni_id] = node_id
        members_by_node.setdefault(node_id, []).append(eni)
        identity_by_node.setdefault(node_id, identity)

    nodes: list[OverviewNode] = []
    for node_id, members in sorted(members_by_node.items()):
        member_tuple = tuple(sorted(members, key=lambda eni: eni.id))
        identity = identity_by_node[node_id]
        grouped = len(member_tuple) > 1
        label = (
            f"{identity.name or identity.key}\n{identity.resource_type} ({len(member_tuple)} ENIs)"
            if grouped
            else eni_node_label(member_tuple[0])
        )
        nodes.append(
            OverviewNode(
                id=node_id,
                label=label,
                resource_type=identity.resource_type,
                resource_arn=identity.arn,
                member_enis=member_tuple,
                properties=node_properties(identity, member_tuple, grouped),
            )
        )

    edge_paths: dict[tuple[str, str], dict[tuple[Any, ...], ReachabilityPath]] = {}
    for path in paths:
        source_id = node_id_by_eni[path.src.id]
        target_id = node_id_by_eni[path.dst.id]
        edge_paths.setdefault((source_id, target_id), {})[path_edge_key(path)] = path

    edges: list[OverviewEdge] = []
    for index, ((source_id, target_id), deduped_paths) in enumerate(
        sorted(edge_paths.items())
    ):
        edges.append(
            OverviewEdge(
                id=f"can-reach-{index}",
                source=source_id,
                target=target_id,
                paths=tuple(deduped_paths.values()),
            )
        )

    return OverviewGraph(tuple(nodes), tuple(edges), len(paths))
