from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from .constants import ANY_PROTOCOL
from .models import (
    ElbTarget,
    Eni,
    ExternalEndpoint,
    PacketSpace,
    ReachabilityPath,
    Route,
    RoutedRay,
    SecurityGroupRule,
    TgwHop,
    TgwTopology,
)
from .ip import network_intersection, subtract_networks

class RayTracer:
    def __init__(
        self,
        enis: dict[str, Eni],
        egress_rules: dict[str, list[SecurityGroupRule]],
        ingress_rules: dict[str, list[SecurityGroupRule]],
        sg_allows: set[tuple[str, str]],
        subnet_route_table: dict[str, str],
        main_route_table: dict[str, str],
        routes_by_table: dict[str, list[Route]],
        peering_vpcs: dict[str, set[str]],
        tgw_topology: TgwTopology | None = None,
        external_endpoints: list[ExternalEndpoint] | None = None,
        elb_targets: dict[str, dict[str, list[ElbTarget]]] | None = None,
    ):
        self.enis = enis
        self.egress_rules = egress_rules
        self.ingress_rules = ingress_rules
        self.sg_allows = sg_allows
        self.subnet_route_table = subnet_route_table
        self.main_route_table = main_route_table
        self.routes_by_table = routes_by_table
        self.peering_vpcs = peering_vpcs
        self.tgw_topology = tgw_topology or TgwTopology.empty()
        self.external_endpoints = external_endpoints or []
        self.elb_targets = elb_targets or {}

    def route_table_for(self, eni: Eni) -> str | None:
        return self.subnet_route_table.get(eni.subnet_id) or self.main_route_table.get(
            eni.vpc_id
        )

    def trace_routes(self, ray: PacketSpace, route_table_id: str) -> list[RoutedRay]:
        remaining = [ray.dst]
        routed: list[RoutedRay] = []
        for route in self.routes_by_table.get(route_table_id, []):
            next_remaining = remaining
            for network in remaining:
                overlap = network_intersection(network, route.destination)
                if overlap is None:
                    continue
                routed.append(RoutedRay(replace(ray, dst=overlap), route_table_id, route))
                next_remaining = subtract_networks(next_remaining, overlap)
            remaining = next_remaining
            if not remaining:
                break
        return routed

    def route_hop(self, route: Route, src: Eni, dst: Eni) -> tuple[bool, TgwHop | None]:
        if route.gateway_id == "local":
            return src.vpc_id == dst.vpc_id, None
        if route.peering_id:
            vpcs = self.peering_vpcs.get(route.peering_id, set())
            return src.vpc_id in vpcs and dst.vpc_id in vpcs, None
        if route.transit_gateway_id:
            tgw_hop = self.tgw_topology.route_hop(route.transit_gateway_id, src, dst)
            return tgw_hop is not None, tgw_hop
        return False, None

    def ingress_intersections(
        self, ray: PacketSpace, src: Eni, dst_sg_id: str
    ) -> Iterable[tuple[PacketSpace, SecurityGroupRule]]:
        for rule in self.ingress_rules.get(dst_sg_id, []):
            l4_ray = rule.l4_intersect(ray)
            if l4_ray is None:
                continue

            sg_ref_allows = (
                False
                if src.terminal_cidr is not None
                else any(
                    (dst_sg_id, src_sg_id) in self.sg_allows
                    for src_sg_id in src.sg_ids
                )
            )
            if src.terminal_cidr is not None:
                cidr_allows = any(
                    network_intersection(src.terminal_cidr, cidr) is not None
                    for cidr in rule.cidrs
                )
            else:
                cidr_allows = any(src.private_ip in cidr for cidr in rule.cidrs)

            if sg_ref_allows or cidr_allows:
                yield l4_ray, rule

    @staticmethod
    def terminal_rule(
        terminal: ExternalEndpoint, direction: str = "terminal"
    ) -> SecurityGroupRule:
        return SecurityGroupRule(
            id=f"{terminal.id}/{direction}",
            sg_id=terminal.id,
            direction=direction,
            protocol=ANY_PROTOCOL,
            from_port=None,
            to_port=None,
            cidrs=(terminal.cidr,),
            raw_cidrs=(str(terminal.cidr),),
        )

    @staticmethod
    def terminal_route(terminal: ExternalEndpoint, destination: PacketSpace) -> Route:
        return Route(
            id=f"{terminal.id}|{destination.dst}",
            route_table_id=f"external:{terminal.connection_id}",
            destination=destination.dst,
            gateway_id=None,
            target=terminal.connection_id,
            peering_id=terminal.connection_id
            if terminal.connection_kind == "vpc_peering"
            else None,
            transit_gateway_id=terminal.tgw_id
            if terminal.connection_kind.startswith("transit_gateway")
            else None,
            state="active",
        )

    def terminal_route_hop(
        self, route: Route, src: Eni, terminal: ExternalEndpoint
    ) -> TgwHop | None:
        if route.transit_gateway_id and route.transit_gateway_id == terminal.tgw_id:
            return self.tgw_topology.terminal_hop(
                route.transit_gateway_id, src.vpc_id, terminal
            )
        return None

    def route_reaches_terminal(
        self, route: Route, src: Eni, terminal: ExternalEndpoint
    ) -> tuple[bool, TgwHop | None]:
        if network_intersection(route.destination, terminal.cidr) is None:
            return False, None
        if terminal.connection_kind == "vpc_peering":
            vpcs = self.peering_vpcs.get(terminal.connection_id, set())
            return (
                route.peering_id == terminal.connection_id
                and src.vpc_id in vpcs
                and terminal.vpc_id in vpcs,
                None,
            )
        if terminal.connection_kind.startswith("transit_gateway"):
            tgw_hop = self.terminal_route_hop(route, src, terminal)
            return tgw_hop is not None, tgw_hop
        return False, None

    def terminal_can_source_destination(
        self, terminal: ExternalEndpoint, dst: Eni
    ) -> tuple[bool, TgwHop | None]:
        if terminal.connection_kind == "vpc_peering":
            vpcs = self.peering_vpcs.get(terminal.connection_id, set())
            return terminal.vpc_id in vpcs and dst.vpc_id in vpcs, None
        if terminal.connection_kind.startswith("transit_gateway"):
            tgw_hop = self.tgw_topology.terminal_source_hop(
                terminal, dst.vpc_id, dst.private_ip
            )
            return tgw_hop is not None, tgw_hop
        return False, None

    @staticmethod
    def target_protocols(protocol: str) -> tuple[str, ...]:
        normalized = protocol.lower()
        if normalized in {"http", "https", "ssl", "tcp", "tls"}:
            return ("tcp",)
        if normalized == "udp":
            return ("udp",)
        if normalized in {"tcp_udp", "tcpudp"}:
            return ("tcp", "udp")
        return (ANY_PROTOCOL,)

    def elb_target_intersections(
        self, ray: PacketSpace, target: ElbTarget
    ) -> Iterable[PacketSpace]:
        port_min = target.port
        port_max = target.port
        protocols = self.target_protocols(target.protocol)
        if protocols == (ANY_PROTOCOL,) and target.port is not None:
            protocols = ("tcp", "udp")
        for protocol in protocols:
            next_ray = ray.intersect_l4(protocol, port_min, port_max)
            if next_ray is not None:
                yield next_ray

    def source_rays(
        self, src: Eni
    ) -> Iterable[tuple[str | None, PacketSpace, ElbTarget | None]]:
        initial_ray = PacketSpace()
        if not src.elb_arn:
            yield None, initial_ray, None
            return

        for target_eni_id, targets in self.elb_targets.get(src.elb_arn, {}).items():
            for target in targets:
                for ray in self.elb_target_intersections(initial_ray, target):
                    yield target_eni_id, ray, target

    def trace(
        self,
        source_filter: str | None,
        destination_filter: str | None,
        source_limit: int,
        pair_limit: int,
        path_limit: int,
    ) -> list[ReachabilityPath]:
        sources = [
            eni for eni in self.enis.values() if self.matches_filter(eni, source_filter)
        ]
        if source_limit > 0:
            sources = sources[:source_limit]

        paths: list[ReachabilityPath] = []
        seen: set[tuple[Any, ...]] = set()
        pair_count = 0

        for src in sources:
            route_table_id = self.route_table_for(src)
            if not route_table_id:
                continue

            source_egress_rules = [
                rule
                for sg_id in src.sg_ids
                for rule in self.egress_rules.get(sg_id, [])
            ]
            if not source_egress_rules:
                continue

            egress_rays: list[
                tuple[
                    str | None,
                    PacketSpace,
                    PacketSpace | None,
                    SecurityGroupRule,
                    ElbTarget | None,
                ]
            ] = []
            for target_eni_id, source_ray, elb_target in self.source_rays(src):
                for rule in source_egress_rules:
                    for ray in rule.egress_intersections(source_ray):
                        egress_rays.append((target_eni_id, ray, source_ray, rule, elb_target))

            for (
                target_eni_id,
                egress_ray,
                elb_packet,
                egress_rule,
                elb_target,
            ) in egress_rays:
                for routed_ray in self.trace_routes(egress_ray, route_table_id):
                    for terminal in self.external_endpoints:
                        terminal_reachable, tgw_hop = self.route_reaches_terminal(
                            routed_ray.route, src, terminal
                        )
                        if not terminal_reachable:
                            continue
                        terminal_packet = routed_ray.packet.intersect_cidr(terminal.cidr)
                        if terminal_packet is None:
                            continue
                        terminal_eni = terminal.as_eni()
                        if not self.matches_filter(terminal_eni, destination_filter):
                            continue
                        pair_count += 1
                        if pair_limit > 0 and pair_count > pair_limit:
                            return paths
                        terminal_rule = self.terminal_rule(terminal)
                        path = ReachabilityPath(
                            src=src,
                            dst=terminal_eni,
                            egress_packet=egress_ray,
                            routed_packet=terminal_packet,
                            packet=terminal_packet,
                            egress_rule=egress_rule,
                            route=routed_ray.route,
                            ingress_rule=terminal_rule,
                            elb_packet=elb_packet if elb_target else None,
                            elb_target=elb_target,
                            tgw_hop=tgw_hop,
                        )
                        key = path.key()
                        if key not in seen:
                            seen.add(key)
                            paths.append(path)
                            if path_limit > 0 and len(paths) >= path_limit:
                                return paths

                    for dst in self.enis.values():
                        if dst.id == src.id or not self.matches_filter(
                            dst, destination_filter
                        ):
                            continue
                        if target_eni_id is not None and dst.id != target_eni_id:
                            continue
                        if dst.private_ip not in routed_ray.packet.dst:
                            continue
                        route_reachable, tgw_hop = self.route_hop(
                            routed_ray.route, src, dst
                        )
                        if not route_reachable:
                            continue

                        pair_count += 1
                        if pair_limit > 0 and pair_count > pair_limit:
                            return paths

                        for dst_sg_id in dst.sg_ids:
                            for final_ray, ingress_rule in self.ingress_intersections(
                                routed_ray.packet, src, dst_sg_id
                            ):
                                path = ReachabilityPath(
                                    src=src,
                                    dst=dst,
                                    egress_packet=egress_ray,
                                    routed_packet=routed_ray.packet,
                                    packet=final_ray,
                                    egress_rule=egress_rule,
                                    route=routed_ray.route,
                                    ingress_rule=ingress_rule,
                                    elb_packet=elb_packet if elb_target else None,
                                    elb_target=elb_target,
                                    tgw_hop=tgw_hop,
                                )
                                key = path.key()
                                if key in seen:
                                    continue
                                seen.add(key)
                                paths.append(path)
                                if path_limit > 0 and len(paths) >= path_limit:
                                    return paths

        for terminal in self.external_endpoints:
            terminal_eni = terminal.as_eni()
            if not self.matches_filter(terminal_eni, source_filter):
                continue
            terminal_egress_rule = self.terminal_rule(terminal, "external_source")
            for dst in self.enis.values():
                if not self.matches_filter(dst, destination_filter):
                    continue
                terminal_reachable, tgw_hop = self.terminal_can_source_destination(
                    terminal, dst
                )
                if not terminal_reachable:
                    continue
                pair_count += 1
                if pair_limit > 0 and pair_count > pair_limit:
                    return paths
                routed_packet = PacketSpace(dst=dst.subnet_cidr)
                route = self.terminal_route(terminal, routed_packet)
                for dst_sg_id in dst.sg_ids:
                    for final_ray, ingress_rule in self.ingress_intersections(
                        routed_packet, terminal_eni, dst_sg_id
                    ):
                        path = ReachabilityPath(
                            src=terminal_eni,
                            dst=dst,
                            egress_packet=PacketSpace(dst=terminal.cidr),
                            routed_packet=routed_packet,
                            packet=final_ray,
                            egress_rule=terminal_egress_rule,
                            route=route,
                            ingress_rule=ingress_rule,
                            tgw_hop=tgw_hop,
                        )
                        key = path.key()
                        if key in seen:
                            continue
                        seen.add(key)
                        paths.append(path)
                        if path_limit > 0 and len(paths) >= path_limit:
                            return paths

        return paths

    @staticmethod
    def matches_filter(eni: Eni, value: str | None) -> bool:
        if value is None:
            return True
        return value in {
            eni.id,
            str(eni.private_ip),
            eni.public_ip or "",
            eni.owner_id,
            eni.owner_name or "",
            eni.owner_type,
            eni.owner_arn or "",
            eni.terminal_kind or "",
            str(eni.terminal_cidr or ""),
            eni.terminal_connection_id or "",
        }
