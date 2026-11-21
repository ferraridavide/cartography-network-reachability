from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import Any

from .constants import ANY_CIDR, ANY_PROTOCOL
from .ip import network_intersection
from .metadata import normalize_protocol

@dataclass(frozen=True)
class PacketSpace:
    dst: ipaddress.IPv4Network = ANY_CIDR
    protocol: str = ANY_PROTOCOL
    port_min: int | None = None
    port_max: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "dst": str(self.dst),
            "protocol": self.protocol,
            "ports": "*"
            if self.port_min is None
            else f"{self.port_min}-{self.port_max}",
        }

    def intersect_cidr(self, cidr: ipaddress.IPv4Network) -> "PacketSpace | None":
        intersection = network_intersection(self.dst, cidr)
        if intersection is None:
            return None
        return replace(self, dst=intersection)

    def intersect_l4(
        self, protocol: str, from_port: int | None, to_port: int | None
    ) -> "PacketSpace | None":
        protocol = normalize_protocol(protocol)

        if self.protocol != ANY_PROTOCOL and protocol != ANY_PROTOCOL and self.protocol != protocol:
            return None

        new_protocol = self.protocol if protocol == ANY_PROTOCOL else protocol
        if self.protocol == ANY_PROTOCOL and protocol == ANY_PROTOCOL:
            new_protocol = ANY_PROTOCOL

        if protocol == ANY_PROTOCOL or protocol not in {"tcp", "udp"}:
            return replace(self, protocol=new_protocol)

        rule_min = 0 if from_port is None else int(from_port)
        rule_max = 65535 if to_port is None else int(to_port)
        ray_min = 0 if self.port_min is None else self.port_min
        ray_max = 65535 if self.port_max is None else self.port_max

        port_min = max(rule_min, ray_min)
        port_max = min(rule_max, ray_max)
        if port_min > port_max:
            return None
        return replace(self, protocol=new_protocol, port_min=port_min, port_max=port_max)


@dataclass(frozen=True)
class Eni:
    id: str
    private_ip: ipaddress.IPv4Address
    public_ip: str | None
    private_dns_name: str | None
    mac_address: str | None
    description: str | None
    interface_type: str | None
    requester_id: str | None
    requester_managed: bool | None
    device_index: int | None
    subnet_id: str
    subnet_cidr: ipaddress.IPv4Network
    vpc_id: str
    region: str | None
    account_id: str | None
    owner_id: str
    owner_type: str
    owner_labels: tuple[str, ...]
    owner_name: str | None
    owner_arn: str | None
    elb_arn: str | None
    auto_scaling_group_arn: str | None
    auto_scaling_group_name: str | None
    instance_profile_arn: str | None
    instance_profile_name: str | None
    ecs_service_arn: str | None
    ecs_service_name: str | None
    ecs_cluster_arn: str | None
    ecs_cluster_name: str | None
    sg_ids: tuple[str, ...]
    terminal_kind: str | None = None
    terminal_cidr: ipaddress.IPv4Network | None = None
    terminal_connection_id: str | None = None
    terminal_connection_name: str | None = None
    subnet_availability_zone: str | None = None
    account_name: str | None = None

    def display_id(self) -> str:
        return self.owner_id or self.id

    def as_node(self) -> dict[str, Any]:
        return {
            "id": self.display_id(),
            "eni_id": self.id,
            "resource_type": self.owner_type,
            "resource_arn": self.owner_arn,
            "elb_arn": self.elb_arn,
            "auto_scaling_group_arn": self.auto_scaling_group_arn,
            "auto_scaling_group_name": self.auto_scaling_group_name,
            "instance_profile_arn": self.instance_profile_arn,
            "instance_profile_name": self.instance_profile_name,
            "ecs_service_arn": self.ecs_service_arn,
            "ecs_service_name": self.ecs_service_name,
            "ecs_cluster_arn": self.ecs_cluster_arn,
            "ecs_cluster_name": self.ecs_cluster_name,
            "labels": list(self.owner_labels) if self.owner_labels else ["NetworkInterface"],
            "name": self.owner_name,
            "private_ip": str(self.private_ip),
            "public_ip": self.public_ip,
            "private_dns_name": self.private_dns_name,
            "mac_address": self.mac_address,
            "description": self.description,
            "interface_type": self.interface_type,
            "requester_id": self.requester_id,
            "requester_managed": self.requester_managed,
            "device_index": self.device_index,
            "subnet_id": self.subnet_id,
            "subnet_cidr": str(self.subnet_cidr),
            "subnet_availability_zone": self.subnet_availability_zone,
            "vpc_id": self.vpc_id,
            "region": self.region,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "security_groups": list(self.sg_ids),
            "terminal": self.terminal_kind is not None,
            "terminal_kind": self.terminal_kind,
            "terminal_cidr": str(self.terminal_cidr) if self.terminal_cidr else None,
            "terminal_connection_id": self.terminal_connection_id,
            "terminal_connection_name": self.terminal_connection_name,
        }


@dataclass(frozen=True)
class SecurityGroupRule:
    id: str
    sg_id: str
    direction: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidrs: tuple[ipaddress.IPv4Network, ...]
    raw_cidrs: tuple[str, ...]

    def l4_intersect(self, ray: PacketSpace) -> PacketSpace | None:
        return ray.intersect_l4(self.protocol, self.from_port, self.to_port)

    def egress_intersections(self, ray: PacketSpace) -> list[PacketSpace]:
        l4_ray = self.l4_intersect(ray)
        if l4_ray is None:
            return []
        cidrs = self.cidrs or (ANY_CIDR,)
        rays = []
        for cidr in cidrs:
            next_ray = l4_ray.intersect_cidr(cidr)
            if next_ray is not None:
                rays.append(next_ray)
        return rays

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sg_id": self.sg_id,
            "direction": self.direction,
            "protocol": self.protocol,
            "from_port": self.from_port,
            "to_port": self.to_port,
            "cidrs": list(self.raw_cidrs) if self.raw_cidrs else ["ANY"],
        }


@dataclass(frozen=True)
class Route:
    id: str
    route_table_id: str
    destination: ipaddress.IPv4Network
    gateway_id: str | None
    target: str | None
    peering_id: str | None
    transit_gateway_id: str | None
    state: str | None

    @property
    def prefixlen(self) -> int:
        return self.destination.prefixlen

    def target_kind(self) -> str:
        if self.gateway_id == "local":
            return "local"
        if self.peering_id:
            return "vpc_peering"
        if self.transit_gateway_id:
            return "transit_gateway"
        return self.gateway_id or self.target or "unknown"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "route_table_id": self.route_table_id,
            "destination": str(self.destination),
            "target_kind": self.target_kind(),
            "target": self.gateway_id or self.peering_id or self.transit_gateway_id or self.target,
        }


@dataclass(frozen=True)
class RoutedRay:
    packet: PacketSpace
    route_table_id: str
    route: Route


@dataclass(frozen=True)
class TgwAttachment:
    id: str
    tgw_id: str
    vpc_id: str
    state: str | None
    resource_type: str | None = None
    subnet_ids: tuple[str, ...] = ()
    route_table_ids: tuple[str, ...] = ()
    propagated_route_table_ids: tuple[str, ...] = ()
    account_id: str | None = None
    foreign: bool = False
    cidrs: tuple[ipaddress.IPv4Network, ...] = ()

    @property
    def available(self) -> bool:
        return self.state is None or self.state.lower() == "available"


@dataclass(frozen=True)
class TgwRoute:
    id: str
    route_table_id: str
    destination: ipaddress.IPv4Network
    attachment_ids: tuple[str, ...]
    state: str | None
    route_type: str | None

    @property
    def prefixlen(self) -> int:
        return self.destination.prefixlen

    @property
    def active(self) -> bool:
        route_type = self.route_type.lower() if self.route_type else None
        state = self.state.lower() if self.state else None
        return state in (None, "active") and route_type != "blackhole"

    @property
    def blackhole(self) -> bool:
        route_type = self.route_type.lower() if self.route_type else None
        state = self.state.lower() if self.state else None
        return state == "blackhole" or route_type == "blackhole"

    @property
    def propagated(self) -> bool:
        return self.route_type is not None and self.route_type.lower() == "propagated"


@dataclass(frozen=True)
class TgwHop:
    tgw_id: str
    source_attachment_id: str
    destination_attachment_id: str
    route_table_id: str
    route_id: str
    destination: ipaddress.IPv4Network
    route_type: str | None
    state: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tgw_id": self.tgw_id,
            "source_attachment_id": self.source_attachment_id,
            "destination_attachment_id": self.destination_attachment_id,
            "route_table_id": self.route_table_id,
            "route_id": self.route_id,
            "destination": str(self.destination),
            "route_type": self.route_type,
            "state": self.state,
        }


@dataclass(frozen=True)
class TgwTopology:
    attachments: tuple[TgwAttachment, ...] = ()
    routes: tuple[TgwRoute, ...] = ()

    @classmethod
    def empty(cls) -> "TgwTopology":
        return cls()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_attachments_by_tgw_vpc",
            self._build_attachments_by_tgw_vpc(),
        )
        object.__setattr__(self, "_routes_by_table", self._build_routes_by_table())

    def _build_attachments_by_tgw_vpc(
        self,
    ) -> dict[tuple[str, str], tuple[TgwAttachment, ...]]:
        grouped: dict[tuple[str, str], list[TgwAttachment]] = {}
        for attachment in self.attachments:
            grouped.setdefault((attachment.tgw_id, attachment.vpc_id), []).append(attachment)
        return {key: tuple(value) for key, value in grouped.items()}

    def _build_routes_by_table(self) -> dict[str, tuple[TgwRoute, ...]]:
        grouped: dict[str, list[TgwRoute]] = {}
        for route in self.routes:
            grouped.setdefault(route.route_table_id, []).append(route)
        return {
            key: tuple(sorted(value, key=lambda route: route.prefixlen, reverse=True))
            for key, value in grouped.items()
        }

    def available_attachments(self, tgw_id: str, vpc_id: str) -> tuple[TgwAttachment, ...]:
        return tuple(
            attachment
            for attachment in self._attachments_by_tgw_vpc.get((tgw_id, vpc_id), ())
            if attachment.available
            and (
                attachment.resource_type is None
                or attachment.resource_type.lower() == "vpc"
            )
        )

    def route_hop(self, tgw_id: str, src: Eni, dst: Eni) -> TgwHop | None:
        source_attachments = self.available_attachments(tgw_id, src.vpc_id)
        destination_attachments = self.available_attachments(tgw_id, dst.vpc_id)
        destination_attachment_ids = {
            attachment.id for attachment in destination_attachments
        }
        if not source_attachments or not destination_attachment_ids:
            return None

        for source_attachment in source_attachments:
            for route_table_id in source_attachment.route_table_ids:
                matching_routes = [
                    route
                    for route in self._routes_by_table.get(route_table_id, ())
                    if dst.private_ip in route.destination
                ]
                if not matching_routes:
                    continue

                # TGW route tables use longest-prefix match. A blackhole at the
                # best prefix blocks less-specific alternatives.
                best_prefix = matching_routes[0].prefixlen
                best_routes = [
                    route for route in matching_routes if route.prefixlen == best_prefix
                ]
                if any(route.blackhole for route in best_routes):
                    continue

                for route in best_routes:
                    matching_attachment_ids = [
                        attachment_id
                        for attachment_id in route.attachment_ids
                        if attachment_id in destination_attachment_ids
                    ]
                    if not route.active or not matching_attachment_ids:
                        continue
                    if (
                        route.propagated
                        and route_table_id
                        not in next(
                            attachment.propagated_route_table_ids
                            for attachment in destination_attachments
                            if attachment.id == matching_attachment_ids[0]
                        )
                    ):
                        continue
                    return TgwHop(
                        tgw_id=tgw_id,
                        source_attachment_id=source_attachment.id,
                        destination_attachment_id=matching_attachment_ids[0],
                        route_table_id=route_table_id,
                        route_id=route.id,
                        destination=route.destination,
                        route_type=route.route_type,
                        state=route.state,
                    )
        return None

    def terminal_hop(
        self, tgw_id: str, src_vpc_id: str, terminal: "ExternalEndpoint"
    ) -> TgwHop | None:
        if not terminal.attachment_id:
            return None
        source_attachments = self.available_attachments(tgw_id, src_vpc_id)
        if not source_attachments:
            return None

        for source_attachment in source_attachments:
            for route_table_id in source_attachment.route_table_ids:
                matching_routes = [
                    route
                    for route in self._routes_by_table.get(route_table_id, ())
                    if terminal.cidr.subnet_of(route.destination)
                    or route.destination.subnet_of(terminal.cidr)
                    or network_intersection(route.destination, terminal.cidr) is not None
                ]
                if not matching_routes:
                    continue
                best_prefix = matching_routes[0].prefixlen
                best_routes = [
                    route for route in matching_routes if route.prefixlen == best_prefix
                ]
                if any(route.blackhole for route in best_routes):
                    continue
                for route in best_routes:
                    if (
                        not route.active
                        or terminal.attachment_id not in route.attachment_ids
                    ):
                        continue
                    return TgwHop(
                        tgw_id=tgw_id,
                        source_attachment_id=source_attachment.id,
                        destination_attachment_id=terminal.attachment_id,
                        route_table_id=route_table_id,
                        route_id=route.id,
                        destination=route.destination,
                        route_type=route.route_type,
                        state=route.state,
                    )
        return None

    def terminal_source_hop(
        self, terminal: "ExternalEndpoint", dst_vpc_id: str, dst_ip: ipaddress.IPv4Address
    ) -> TgwHop | None:
        if not terminal.tgw_id or not terminal.attachment_id:
            return None
        source_attachments = tuple(
            attachment
            for attachment in self.attachments
            if attachment.id == terminal.attachment_id and attachment.available
        )
        destination_attachments = self.available_attachments(terminal.tgw_id, dst_vpc_id)
        destination_attachment_ids = {attachment.id for attachment in destination_attachments}
        if not source_attachments or not destination_attachment_ids:
            return None

        for source_attachment in source_attachments:
            for route_table_id in source_attachment.route_table_ids:
                matching_routes = [
                    route
                    for route in self._routes_by_table.get(route_table_id, ())
                    if dst_ip in route.destination
                ]
                if not matching_routes:
                    continue
                best_prefix = matching_routes[0].prefixlen
                best_routes = [
                    route for route in matching_routes if route.prefixlen == best_prefix
                ]
                if any(route.blackhole for route in best_routes):
                    continue
                for route in best_routes:
                    matching_attachment_ids = [
                        attachment_id
                        for attachment_id in route.attachment_ids
                        if attachment_id in destination_attachment_ids
                    ]
                    if not route.active or not matching_attachment_ids:
                        continue
                    return TgwHop(
                        tgw_id=terminal.tgw_id,
                        source_attachment_id=terminal.attachment_id,
                        destination_attachment_id=matching_attachment_ids[0],
                        route_table_id=route_table_id,
                        route_id=route.id,
                        destination=route.destination,
                        route_type=route.route_type,
                        state=route.state,
                    )
        return None


@dataclass(frozen=True)
class ExternalEndpoint:
    id: str
    label: str
    cidr: ipaddress.IPv4Network
    connection_kind: str
    connection_id: str
    vpc_id: str | None = None
    account_id: str | None = None
    region: str | None = None
    tgw_id: str | None = None
    attachment_id: str | None = None
    resource_type: str | None = None
    connection_name: str | None = None

    def as_eni(self) -> Eni:
        return Eni(
            id=self.id,
            private_ip=self.cidr.network_address,
            public_ip=None,
            private_dns_name=None,
            mac_address=None,
            description=self.label,
            interface_type="external-terminal",
            requester_id=None,
            requester_managed=None,
            device_index=None,
            subnet_id=f"external:{self.connection_id}",
            subnet_cidr=self.cidr,
            vpc_id=self.vpc_id or f"external:{self.connection_id}",
            region=self.region,
            account_id=self.account_id,
            owner_id=self.id,
            owner_type="ExternalNetwork",
            owner_labels=("ExternalNetwork",),
            owner_name=self.label,
            owner_arn=None,
            elb_arn=None,
            auto_scaling_group_arn=None,
            auto_scaling_group_name=None,
            instance_profile_arn=None,
            instance_profile_name=None,
            ecs_service_arn=None,
            ecs_service_name=None,
            ecs_cluster_arn=None,
            ecs_cluster_name=None,
            sg_ids=(),
            terminal_kind=self.connection_kind,
            terminal_cidr=self.cidr,
            terminal_connection_id=self.connection_id,
            terminal_connection_name=self.connection_name,
            subnet_availability_zone=None,
        )


@dataclass(frozen=True)
class ElbTarget:
    load_balancer_arn: str
    target_eni_id: str
    target_group_arn: str | None
    target_group_name: str | None
    protocol: str
    port: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "load_balancer_arn": self.load_balancer_arn,
            "target_eni_id": self.target_eni_id,
            "target_group_arn": self.target_group_arn,
            "target_group_name": self.target_group_name,
            "protocol": self.protocol,
            "port": self.port,
        }


@dataclass(frozen=True)
class ReachabilityPath:
    src: Eni
    dst: Eni
    egress_packet: PacketSpace
    routed_packet: PacketSpace
    packet: PacketSpace
    egress_rule: SecurityGroupRule
    route: Route
    ingress_rule: SecurityGroupRule
    elb_packet: PacketSpace | None = None
    elb_target: ElbTarget | None = None
    tgw_hop: TgwHop | None = None

    def key(self) -> tuple[Any, ...]:
        return (
            self.src.id,
            self.dst.id,
            str(self.packet.dst),
            self.packet.protocol,
            self.packet.port_min,
            self.packet.port_max,
            self.egress_rule.id,
            self.route.id,
            self.ingress_rule.id,
            None if self.elb_target is None else self.elb_target.target_group_arn,
            None if self.elb_target is None else self.elb_target.protocol,
            None if self.elb_target is None else self.elb_target.port,
            None if self.tgw_hop is None else self.tgw_hop.tgw_id,
            None if self.tgw_hop is None else self.tgw_hop.source_attachment_id,
            None if self.tgw_hop is None else self.tgw_hop.destination_attachment_id,
            None if self.tgw_hop is None else self.tgw_hop.route_table_id,
            None if self.tgw_hop is None else self.tgw_hop.route_id,
        )

    def as_dict(self) -> dict[str, Any]:
        packet_space_by_stage = {
            "initial": PacketSpace().as_dict(),
            "after_egress": self.egress_packet.as_dict(),
            "after_route": self.routed_packet.as_dict(),
            "after_ingress": self.packet.as_dict(),
        }
        if self.elb_target:
            packet_space_by_stage = {
                "initial": PacketSpace().as_dict(),
                "after_elb_target": (self.elb_packet or PacketSpace()).as_dict(),
                "after_egress": self.egress_packet.as_dict(),
                "after_route": self.routed_packet.as_dict(),
                "after_ingress": self.packet.as_dict(),
            }

        return {
            "packet_space": self.packet.as_dict(),
            "packet_space_by_stage": packet_space_by_stage,
            "elb_target": self.elb_target.as_dict() if self.elb_target else None,
            "tgw_hop": self.tgw_hop.as_dict() if self.tgw_hop else None,
            "source": self.src.as_node(),
            "destination": self.dst.as_node(),
            "path": [
                {"type": "source", "node": self.src.as_node()},
                *(
                    [{"type": "elb_target", "target": self.elb_target.as_dict()}]
                    if self.elb_target
                    else []
                ),
                {"type": "egress_rule", "rule": self.egress_rule.as_dict()},
                {"type": "route", "route": self.route.as_dict()},
                *(
                    [{"type": "tgw_hop", "hop": self.tgw_hop.as_dict()}]
                    if self.tgw_hop
                    else []
                ),
                {"type": "ingress_rule", "rule": self.ingress_rule.as_dict()},
                {"type": "destination", "node": self.dst.as_node()},
            ],
        }
