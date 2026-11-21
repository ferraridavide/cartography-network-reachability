from __future__ import annotations

import re
from typing import Any, Iterable

from .constants import ANY_PROTOCOL

def normalize_protocol(value: Any) -> str:
    if value is None or str(value) == "-1":
        return ANY_PROTOCOL
    return str(value).lower()


def infer_owner_type(labels: Iterable[str]) -> str:
    preferred = [
        "EC2Instance",
        "ECSTask",
        "RDSInstance",
        "RDSCluster",
        "LoadBalancer",
        "AWSLoadBalancerV2",
        "ElastiCacheCluster",
        "RedshiftCluster",
        "EFSFileSystem",
        "NetworkInterface",
    ]
    label_set = set(labels)
    for label in preferred:
        if label in label_set:
            return label
    ignored = {"Resource", "AWSResource", "ComputeInstance"}
    for label in sorted(label_set):
        if label not in ignored:
            return label
    return "NetworkInterface"


def pick_arn(properties: dict[str, Any] | None) -> str | None:
    if not properties:
        return None
    for key in ("arn", "resource_arn", "resourcearn", "dbi_resource_id"):
        value = properties.get(key)
        if value and str(value).startswith("arn:"):
            return str(value)
    for value in properties.values():
        if value and str(value).startswith("arn:"):
            return str(value)
    return None


def synthesize_resource_arn(
    owner_type: str, owner_id: str, region: str | None, account_id: str | None
) -> str | None:
    if not region or not account_id or not owner_id:
        return None
    if owner_id.startswith("arn:"):
        return owner_id
    if owner_type == "EC2Instance" and owner_id.startswith("i-"):
        return f"arn:aws:ec2:{region}:{account_id}:instance/{owner_id}"
    if owner_type == "NetworkInterface" and owner_id.startswith("eni-"):
        return f"arn:aws:ec2:{region}:{account_id}:network-interface/{owner_id}"
    return None


def elb_arn_from_eni_description(
    description: str | None, region: str | None, account_id: str | None
) -> str | None:
    if not description or not region or not account_id:
        return None
    match = re.fullmatch(r"ELB\s+(.+)", description.strip())
    if not match:
        return None
    return f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{match.group(1)}"


def lambda_name_from_eni_description(description: str | None) -> str | None:
    if not description:
        return None
    match = re.fullmatch(
        r"AWS Lambda VPC ENI-(.+)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        description.strip(),
    )
    if not match:
        return None
    return match.group(1)


def _arn_resource_after(value: str, marker: str) -> str | None:
    if marker in value:
        return value.split(marker, 1)[1]
    if value.startswith(marker.lstrip(":")):
        return value.split(marker.lstrip(":"), 1)[1]
    return None


def ecs_service_name_from_arn(value: str | None) -> str | None:
    if not value:
        return None
    resource = _arn_resource_after(value.strip(), ":service/")
    if resource is None:
        return None
    parts = [part for part in resource.split("/") if part]
    if not parts:
        return None
    return parts[-1]


def ecs_service_name_from_task_group(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if not value.startswith("service:"):
        return None
    name = value.split(":", 1)[1].strip()
    return name or None


def ecs_cluster_name_from_arn(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()

    cluster_resource = _arn_resource_after(value, ":cluster/")
    if cluster_resource is not None:
        parts = [part for part in cluster_resource.split("/") if part]
        return parts[-1] if parts else None

    task_resource = _arn_resource_after(value, ":task/")
    if task_resource is not None:
        parts = [part for part in task_resource.split("/") if part]
        if len(parts) >= 2:
            return parts[0]

    return None


def ecs_cluster_arn_from_task_arn(value: str | None) -> str | None:
    if not value or ":task/" not in value:
        return None
    prefix, resource = value.strip().split(":task/", 1)
    parts = [part for part in resource.split("/") if part]
    if len(parts) < 2:
        return None
    return f"{prefix}:cluster/{parts[0]}"


def ecs_service_arn_from_cluster_and_name(
    cluster_arn: str | None, service_name: str | None
) -> str | None:
    if not cluster_arn or not service_name or ":cluster/" not in cluster_arn:
        return None
    prefix = cluster_arn.strip().split(":cluster/", 1)[0]
    cluster_name = ecs_cluster_name_from_arn(cluster_arn)
    if not cluster_name:
        return None
    return f"{prefix}:service/{cluster_name}/{service_name}"
