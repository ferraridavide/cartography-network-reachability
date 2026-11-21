from __future__ import annotations

import socket
from dataclasses import dataclass, replace
from ipaddress import IPv4Address
from typing import Any

from neo4j import GraphDatabase

from .ip import ipv4_address, ipv4_network
from .metadata import (
    ecs_cluster_arn_from_task_arn,
    ecs_cluster_name_from_arn,
    ecs_service_arn_from_cluster_and_name,
    ecs_service_name_from_arn,
    ecs_service_name_from_task_group,
    elb_arn_from_eni_description,
    infer_owner_type,
    normalize_protocol,
    pick_arn,
    synthesize_resource_arn,
)
from .models import (
    ElbTarget,
    Eni,
    ExternalEndpoint,
    Route,
    SecurityGroupRule,
    TgwAttachment,
    TgwRoute,
    TgwTopology,
)


@dataclass(frozen=True)
class RdsEndpointMatch:
    db_instance_identifier: str
    endpoint_address: str
    private_ips: tuple[IPv4Address, ...]
    owner_id: str
    owner_arn: str | None
    account_id: str | None
    region: str | None


def first_property(properties: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = properties.get(key)
        if value:
            return str(value)
    return None


def property_values(properties: dict[str, Any], *keys: str) -> tuple[str, ...]:
    values: list[str] = []
    for key in keys:
        value = properties.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            values.extend(str(item) for item in value if item)
            continue
        values.append(str(value))
    return tuple(dict.fromkeys(values))


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in {"true", "1", "yes"}


def tgw_route_attachment_ids(properties: dict[str, Any]) -> tuple[str, ...]:
    direct = property_values(
        properties,
        "transit_gateway_attachment_id",
        "transitgatewayattachmentid",
        "tgw_attachment_id",
        "attachment_id",
        "target_attachment_id",
    )
    if direct:
        return direct

    values: list[str] = []
    for value in properties.values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    attachment_id = first_property(
                        item,
                        "transit_gateway_attachment_id",
                        "transitgatewayattachmentid",
                        "id",
                    )
                    if attachment_id:
                        values.append(attachment_id)
                elif item and str(item).startswith("tgw-attach-"):
                    values.append(str(item))
        elif value and str(value).startswith("tgw-attach-"):
            values.append(str(value))
    return tuple(dict.fromkeys(values))


class CartographyLoader:
    def __init__(self, uri: str, user: str, password: str, database: str | None):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.database = database

    def close(self) -> None:
        self.driver.close()

    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        with self.driver.session(database=self.database) as session:
            return [dict(record) for record in session.run(query, **params)]

    @staticmethod
    def resolve_ipv4_addresses(hostname: str) -> tuple[IPv4Address, ...]:
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        except OSError:
            return ()

        addresses: list[IPv4Address] = []
        for result in results:
            raw_address = result[4][0]
            address = ipv4_address(raw_address)
            if address is not None:
                addresses.append(address)
        return tuple(dict.fromkeys(addresses))

    def load_rds_endpoint_matches(self) -> list[RdsEndpointMatch]:
        rows = self.run(
            """
            MATCH (rds:RDSInstance)
            WHERE rds.endpoint_address IS NOT NULL
            OPTIONAL MATCH (account:AWSAccount)-[:RESOURCE]-(rds)
            RETURN
              rds.id AS rds_id,
              rds.arn AS arn,
              rds.region AS region,
              rds.endpoint_address AS endpoint_address,
              rds.db_instance_identifier AS db_instance_identifier,
              account.id AS account_id
            """
        )

        matches: list[RdsEndpointMatch] = []
        for row in rows:
            endpoint_address = row.get("endpoint_address")
            db_instance_identifier = row.get("db_instance_identifier")
            if not endpoint_address or not db_instance_identifier:
                continue
            private_ips = self.resolve_ipv4_addresses(str(endpoint_address))
            if not private_ips:
                continue
            owner_id = (
                row.get("rds_id")
                or row.get("arn")
                or str(db_instance_identifier)
            )
            matches.append(
                RdsEndpointMatch(
                    db_instance_identifier=str(db_instance_identifier),
                    endpoint_address=str(endpoint_address),
                    private_ips=private_ips,
                    owner_id=str(owner_id),
                    owner_arn=row.get("arn"),
                    account_id=row.get("account_id"),
                    region=row.get("region"),
                )
            )
        return matches

    @staticmethod
    def eni_looks_like_rds_network_interface(eni: Eni) -> bool:
        if eni.owner_type == "RDSInstance":
            return True
        description = (eni.description or "").strip().lower()
        return eni.owner_type == "NetworkInterface" and (
            description == "rdsnetworkinterface"
            or description.startswith("rds")
        )

    @classmethod
    def enrich_rds_enis(
        cls, enis: dict[str, Eni], matches: list[RdsEndpointMatch]
    ) -> dict[str, Eni]:
        matches_by_ip: dict[IPv4Address, RdsEndpointMatch | None] = {}
        for match in matches:
            for private_ip in match.private_ips:
                if private_ip in matches_by_ip:
                    matches_by_ip[private_ip] = None
                else:
                    matches_by_ip[private_ip] = match

        enriched = dict(enis)
        for eni_id, eni in enis.items():
            match = matches_by_ip.get(eni.private_ip)
            if match is None or not cls.eni_looks_like_rds_network_interface(eni):
                continue
            owner_labels = tuple(
                dict.fromkeys(("RDSInstance", *eni.owner_labels))
            )
            enriched[eni_id] = replace(
                eni,
                owner_id=match.owner_id,
                owner_type="RDSInstance",
                owner_labels=owner_labels,
                owner_name=match.db_instance_identifier,
                owner_arn=match.owner_arn or eni.owner_arn,
                account_id=match.account_id or eni.account_id,
                region=match.region or eni.region,
            )
        return enriched

    def load_enis(self) -> dict[str, Eni]:
        rows = self.run(
            """
            MATCH (eni:NetworkInterface)-[:PART_OF_SUBNET]-(subnet:EC2Subnet)
            WHERE eni.private_ip_address IS NOT NULL
            OPTIONAL MATCH (owner)-[:NETWORK_INTERFACE]-(eni)
            OPTIONAL MATCH (owner_account:AWSAccount)-[:RESOURCE]-(owner)
            OPTIONAL MATCH (eni_account:AWSAccount)-[:RESOURCE]-(eni)
            OPTIONAL MATCH (owner)-[:MEMBER_AUTO_SCALE_GROUP]-(asg:AutoScalingGroup)
            OPTIONAL MATCH (owner)-[:INSTANCE_PROFILE]-(profile:AWSInstanceProfile)
            OPTIONAL MATCH (owner)-[:WORKLOAD_PARENT]-(ecs_parent)
            OPTIONAL MATCH (ecs_parent)-[:WORKLOAD_PARENT]-(ecs_grandparent:ECSCluster)
            OPTIONAL MATCH (owner)-[:TAGGED]->(owner_tag:AWSTag)
            OPTIONAL MATCH (eni)-[:MEMBER_OF_EC2_SECURITY_GROUP]-(sg:EC2SecurityGroup)
            WITH
              eni,
              subnet,
              owner,
              collect(DISTINCT sg.groupid) AS sg_ids,
              collect(DISTINCT coalesce(owner_account.id, eni_account.id)) AS account_ids,
              collect(DISTINCT coalesce(owner_account.name, owner_account._ont_name, eni_account.name, eni_account._ont_name)) AS account_names,
              collect(DISTINCT asg)[0] AS asg,
              collect(DISTINCT profile)[0] AS profile,
              collect(DISTINCT CASE WHEN ecs_parent IS NOT NULL AND "ECSService" IN labels(ecs_parent) THEN ecs_parent ELSE NULL END)[0] AS ecs_service,
              collect(DISTINCT CASE WHEN ecs_parent IS NOT NULL AND "ECSCluster" IN labels(ecs_parent) THEN ecs_parent ELSE ecs_grandparent END)[0] AS ecs_cluster,
              collect(DISTINCT CASE WHEN owner_tag.key = 'Name' THEN owner_tag.value ELSE NULL END) AS owner_name_tags
            RETURN
              eni.id AS eni_id,
              eni.private_ip_address AS private_ip,
              eni.public_ip AS public_ip,
              eni.private_dns_name AS private_dns_name,
              eni.mac_address AS mac_address,
              eni.description AS description,
              eni.interface_type AS interface_type,
              eni.requester_id AS requester_id,
              eni.requester_managed AS requester_managed,
              eni.device_index AS device_index,
              eni.region AS region,
              subnet.subnet_id AS subnet_id,
              subnet.cidr_block AS subnet_cidr,
              coalesce(subnet.availability_zone, subnet.availabilityzone) AS subnet_availability_zone,
              subnet.vpc_id AS vpc_id,
              account_ids AS account_ids,
              account_names AS account_names,
              coalesce(owner.id, eni.id) AS owner_id,
              CASE WHEN owner IS NULL THEN [] ELSE labels(owner) END AS owner_labels,
              head([tag_value IN owner_name_tags WHERE tag_value IS NOT NULL]) AS owner_name_tag,
              coalesce(owner.name, owner._ont_name, owner.id, eni.id) AS owner_name,
              CASE WHEN owner IS NULL THEN {} ELSE properties(owner) END AS owner_properties,
              CASE WHEN asg IS NULL THEN {} ELSE properties(asg) END AS asg_properties,
              CASE WHEN profile IS NULL THEN {} ELSE properties(profile) END AS profile_properties,
              CASE WHEN ecs_service IS NULL THEN {} ELSE properties(ecs_service) END AS ecs_service_properties,
              CASE WHEN ecs_cluster IS NULL THEN {} ELSE properties(ecs_cluster) END AS ecs_cluster_properties,
              sg_ids AS sg_ids
            """
        )
        enis: dict[str, Eni] = {}
        for row in rows:
            private_ip = ipv4_address(row["private_ip"])
            subnet_cidr = ipv4_network(row["subnet_cidr"])
            if private_ip is None or subnet_cidr is None or not row["vpc_id"]:
                continue
            account_id = next((value for value in row.get("account_ids", []) if value), None)
            account_name = next(
                (value for value in row.get("account_names", []) if value),
                None,
            )
            owner_labels = tuple(row.get("owner_labels") or ())
            owner_type = infer_owner_type(owner_labels)
            owner_id = row["owner_id"]
            owner_name = row.get("owner_name")
            if owner_type == "EC2Instance" and row.get("owner_name_tag"):
                owner_name = row.get("owner_name_tag")
            owner_arn = pick_arn(row.get("owner_properties")) or synthesize_resource_arn(
                owner_type, owner_id, row.get("region"), account_id
            )
            elb_arn = elb_arn_from_eni_description(
                row.get("description"), row.get("region"), account_id
            )
            asg_properties = row.get("asg_properties") or {}
            profile_properties = row.get("profile_properties") or {}
            ecs_service_properties = row.get("ecs_service_properties") or {}
            ecs_cluster_properties = row.get("ecs_cluster_properties") or {}
            owner_properties = row.get("owner_properties") or {}
            ecs_cluster_arn = first_property(
                ecs_cluster_properties, "arn", "cluster_arn", "clusterarn", "id"
            ) or first_property(
                owner_properties, "cluster_arn", "clusterarn"
            ) or ecs_cluster_arn_from_task_arn(owner_id)
            ecs_service_arn = first_property(
                ecs_service_properties, "arn", "service_arn", "servicearn", "id"
            )
            ecs_service_name = first_property(
                ecs_service_properties, "service_name", "servicename", "name", "_ont_name"
            ) or ecs_service_name_from_arn(
                ecs_service_arn
            ) or ecs_service_name_from_task_group(
                first_property(owner_properties, "group")
            )
            ecs_service_arn = ecs_service_arn or ecs_service_arn_from_cluster_and_name(
                ecs_cluster_arn, ecs_service_name
            )
            ecs_cluster_name = (
                first_property(
                    ecs_cluster_properties,
                    "cluster_name",
                    "clustername",
                    "name",
                    "_ont_name",
                )
                or ecs_cluster_name_from_arn(ecs_cluster_arn)
                or ecs_cluster_name_from_arn(owner_id)
            )
            enis[row["eni_id"]] = Eni(
                id=row["eni_id"],
                private_ip=private_ip,
                public_ip=row.get("public_ip"),
                private_dns_name=row.get("private_dns_name"),
                mac_address=row.get("mac_address"),
                description=row.get("description"),
                interface_type=row.get("interface_type"),
                requester_id=row.get("requester_id"),
                requester_managed=row.get("requester_managed"),
                device_index=row.get("device_index"),
                subnet_id=row["subnet_id"],
                subnet_cidr=subnet_cidr,
                subnet_availability_zone=row.get("subnet_availability_zone"),
                vpc_id=row["vpc_id"],
                region=row.get("region"),
                account_id=account_id,
                account_name=account_name,
                owner_id=owner_id,
                owner_type=owner_type,
                owner_labels=owner_labels,
                owner_name=owner_name,
                owner_arn=owner_arn,
                elb_arn=elb_arn,
                auto_scaling_group_arn=first_property(asg_properties, "arn", "id"),
                auto_scaling_group_name=first_property(asg_properties, "name"),
                instance_profile_arn=first_property(profile_properties, "arn", "id"),
                instance_profile_name=first_property(
                    profile_properties, "instance_profile_name", "name"
                ),
                ecs_service_arn=ecs_service_arn,
                ecs_service_name=ecs_service_name,
                ecs_cluster_arn=ecs_cluster_arn,
                ecs_cluster_name=ecs_cluster_name,
                sg_ids=tuple(sorted(s for s in row.get("sg_ids", []) if s)),
            )
        return self.enrich_rds_enis(enis, self.load_rds_endpoint_matches())

    def load_security_group_rules(self) -> tuple[
        dict[str, list[SecurityGroupRule]], dict[str, list[SecurityGroupRule]], set[tuple[str, str]]
    ]:
        rows = self.run(
            """
            MATCH (sg:EC2SecurityGroup)-[:MEMBER_OF_EC2_SECURITY_GROUP]-(rule:IpRule)
            OPTIONAL MATCH (range:AWSIpRange)-[:MEMBER_OF_IP_RULE]-(rule)
            RETURN
              sg.groupid AS sg_id,
              rule.id AS rule_id,
              labels(rule) AS labels,
              rule.protocol AS protocol,
              rule.fromport AS from_port,
              rule.toport AS to_port,
              collect(DISTINCT range.range) AS ranges
            """
        )
        egress: dict[str, list[SecurityGroupRule]] = {}
        ingress: dict[str, list[SecurityGroupRule]] = {}
        for row in rows:
            labels = set(row.get("labels") or ())
            direction = "ingress" if "IpPermissionInbound" in labels else "egress"
            raw_cidrs = tuple(sorted(r for r in row.get("ranges", []) if r and "." in r))
            cidrs = tuple(c for c in (ipv4_network(r) for r in raw_cidrs) if c is not None)
            rule = SecurityGroupRule(
                id=row["rule_id"],
                sg_id=row["sg_id"],
                direction=direction,
                protocol=normalize_protocol(row.get("protocol")),
                from_port=row.get("from_port"),
                to_port=row.get("to_port"),
                cidrs=cidrs,
                raw_cidrs=raw_cidrs,
            )
            target = ingress if direction == "ingress" else egress
            target.setdefault(rule.sg_id, []).append(rule)

        pairs = self.run(
            """
            MATCH (dst:EC2SecurityGroup)-[:ALLOWS_TRAFFIC_FROM]-(src:EC2SecurityGroup)
            RETURN DISTINCT dst.groupid AS dst_sg, src.groupid AS src_sg
            """
        )
        sg_allows = {(row["dst_sg"], row["src_sg"]) for row in pairs if row["dst_sg"] and row["src_sg"]}
        return egress, ingress, sg_allows

    def load_elb_targets(self) -> dict[str, dict[str, list[ElbTarget]]]:
        rows = self.run(
            """
            MATCH (lb:AWSLoadBalancerV2)-[expose:EXPOSE]->(target)
            OPTIONAL MATCH (target)-[:NETWORK_INTERFACE]-(direct_eni:NetworkInterface)
            OPTIONAL MATCH (target)<-[:PRIVATE_IP_ADDRESS]-(ip_eni:NetworkInterface)
            OPTIONAL MATCH (target)-[:WORKLOAD_PARENT*0..2]-(workload)-[:NETWORK_INTERFACE]-(workload_eni:NetworkInterface)
            WITH
              lb,
              properties(expose) AS expose_props,
              coalesce(
                properties(expose)["targetgrouparn"],
                properties(expose)["target_group_arn"],
                properties(expose)["TargetGroupArn"]
              ) AS target_group_arn,
              collect(DISTINCT direct_eni.id) +
                collect(DISTINCT ip_eni.id) +
                collect(DISTINCT workload_eni.id) AS target_eni_ids
            OPTIONAL MATCH (target_group:ELBV2TargetGroup)
            WHERE
              properties(target_group)["arn"] = target_group_arn OR
              properties(target_group)["targetgrouparn"] = target_group_arn OR
              properties(target_group)["id"] = target_group_arn
            UNWIND target_eni_ids AS target_eni_id
            WITH DISTINCT
              lb,
              expose_props,
              target_group,
              properties(target_group) AS target_group_props,
              target_group_arn,
              target_eni_id
            WHERE lb.arn IS NOT NULL AND target_eni_id IS NOT NULL
            RETURN
              lb.arn AS load_balancer_arn,
              target_eni_id AS target_eni_id,
              target_group_arn AS target_group_arn,
              coalesce(
                target_group_props["name"],
                target_group_props["id"],
                target_group_arn
              ) AS target_group_name,
              coalesce(expose_props["protocol"], target_group_props["protocol"]) AS protocol,
              coalesce(expose_props["port"], target_group_props["port"]) AS port
            """
        )
        targets: dict[str, dict[str, list[ElbTarget]]] = {}
        for row in rows:
            port = row.get("port")
            try:
                parsed_port = int(port) if port is not None else None
            except (TypeError, ValueError):
                parsed_port = None
            target = ElbTarget(
                load_balancer_arn=row["load_balancer_arn"],
                target_eni_id=row["target_eni_id"],
                target_group_arn=row.get("target_group_arn"),
                target_group_name=row.get("target_group_name"),
                protocol=normalize_protocol(row.get("protocol")),
                port=parsed_port,
            )
            targets.setdefault(target.load_balancer_arn, {}).setdefault(
                target.target_eni_id, []
            ).append(target)
        return targets

    def load_routes(self) -> tuple[
        dict[str, str],
        dict[str, str],
        dict[str, str],
        dict[str, list[Route]],
        dict[str, set[str]],
        TgwTopology,
        list[ExternalEndpoint],
    ]:
        rt_vpc_rows = self.run(
            """
            MATCH (vpc:AWSVpc)-[:MEMBER_OF_AWS_VPC]-(rt:EC2RouteTable)
            RETURN DISTINCT rt.route_table_id AS route_table_id, vpc.vpcid AS vpc_id
            """
        )
        route_table_vpc = {
            row["route_table_id"]: row["vpc_id"]
            for row in rt_vpc_rows
            if row["route_table_id"] and row["vpc_id"]
        }

        assoc_rows = self.run(
            """
            MATCH (rt:EC2RouteTable)-[:ASSOCIATION]-(assoc:EC2RouteTableAssociation)
            OPTIONAL MATCH (assoc)-[:ASSOCIATED_SUBNET]-(subnet:EC2Subnet)
            RETURN
              rt.route_table_id AS route_table_id,
              assoc.main AS main,
              subnet.subnet_id AS subnet_id
            """
        )
        subnet_route_table: dict[str, str] = {}
        main_route_table: dict[str, str] = {}
        for row in assoc_rows:
            route_table_id = row.get("route_table_id")
            if not route_table_id:
                continue
            subnet_id = row.get("subnet_id")
            if subnet_id:
                subnet_route_table[subnet_id] = route_table_id
            if row.get("main"):
                vpc_id = route_table_vpc.get(route_table_id)
                if vpc_id:
                    main_route_table[vpc_id] = route_table_id

        route_rows = self.run(
            """
            MATCH (route:EC2Route)-[:ROUTE]-(rt:EC2RouteTable)
            RETURN
              rt.route_table_id AS route_table_id,
              route.id AS route_id,
              route.destination_cidr_block AS destination_cidr_block,
              route.destination_ipv6_cidr_block AS destination_ipv6_cidr_block,
              route.destination_prefix_list_id AS destination_prefix_list_id,
              route.gateway_id AS gateway_id,
              route.target AS target,
              route.vpc_peering_connection_id AS peering_id,
              route.transit_gateway_id AS transit_gateway_id,
              route.state AS state
            """
        )
        routes_by_table: dict[str, list[Route]] = {}
        for row in route_rows:
            destination = ipv4_network(row.get("destination_cidr_block"))
            if destination is None:
                continue
            if row.get("state") not in (None, "active"):
                continue
            route = Route(
                id=row["route_id"],
                route_table_id=row["route_table_id"],
                destination=destination,
                gateway_id=row.get("gateway_id"),
                target=row.get("target"),
                peering_id=row.get("peering_id"),
                transit_gateway_id=row.get("transit_gateway_id"),
                state=row.get("state"),
            )
            routes_by_table.setdefault(route.route_table_id, []).append(route)
        for routes in routes_by_table.values():
            routes.sort(key=lambda route: route.prefixlen, reverse=True)

        peering_rows = self.run(
            """
            MATCH (pc:AWSPeeringConnection)-[:REQUESTER_VPC|ACCEPTER_VPC]-(vpc:AWSVpc)
            WHERE pc.status_code IS NULL OR pc.status_code = 'active'
            RETURN pc.id AS peering_id, collect(DISTINCT vpc.vpcid) AS vpc_ids
            """
        )
        peering_vpcs = {
            row["peering_id"]: set(row.get("vpc_ids") or ())
            for row in peering_rows
            if row["peering_id"]
        }

        tgw_topology = self.load_tgw_topology()
        external_endpoints = self.load_external_endpoints(tgw_topology)

        return (
            route_table_vpc,
            subnet_route_table,
            main_route_table,
            routes_by_table,
            peering_vpcs,
            tgw_topology,
            external_endpoints,
        )

    def load_tgw_topology(self) -> TgwTopology:
        attachment_rows = self.run(
            """
            MATCH (tgw:AWSTransitGateway)<-[:ATTACHED_TO]-(attachment:AWSTransitGatewayAttachment)
            OPTIONAL MATCH (vpc:AWSVpc)-[:RESOURCE]-(attachment)
            OPTIONAL MATCH (account:AWSAccount)-[:RESOURCE]-(attachment)
            OPTIONAL MATCH (vpc_account:AWSAccount)-[:RESOURCE]-(vpc)
            OPTIONAL MATCH (vpc)-[:BLOCK_ASSOCIATION]-(cidr:AWSCidrBlock)
            OPTIONAL MATCH (attachment)-[:PART_OF_SUBNET]-(subnet:EC2Subnet)
            RETURN
              coalesce(properties(tgw)["tgw_id"], properties(tgw)["id"]) AS tgw_id,
              properties(attachment) AS attachment_properties,
              coalesce(
                properties(attachment)["id"],
                properties(attachment)["transit_gateway_attachment_id"],
                properties(attachment)["transitgatewayattachmentid"]
              ) AS attachment_id,
              coalesce(
                properties(vpc)["vpcid"],
                properties(vpc)["id"],
                properties(subnet)["vpc_id"],
                properties(attachment)["resource_id"],
                properties(attachment)["resourceid"]
              ) AS vpc_id,
              coalesce(account.id, vpc_account.id) AS account_id,
              coalesce(account.foreign, vpc_account.foreign, false) AS foreign,
              coalesce(
                properties(vpc)["primary_cidr_block"],
                properties(vpc)["cidr_block"],
                properties(vpc)["cidrblock"]
              ) AS primary_cidr,
              collect(DISTINCT properties(cidr)["cidr_block"]) AS cidr_blocks,
              collect(DISTINCT properties(subnet)["subnet_id"]) AS subnet_ids
            """
        )

        route_table_rows = self.run(
            """
            MATCH (route_table)-[rel]-(attachment:AWSTransitGatewayAttachment)
            WHERE any(label IN labels(route_table)
              WHERE toLower(label) CONTAINS "transitgatewayroutetable")
            RETURN
              coalesce(
                properties(attachment)["id"],
                properties(attachment)["transit_gateway_attachment_id"],
                properties(attachment)["transitgatewayattachmentid"]
              ) AS attachment_id,
              coalesce(
                properties(route_table)["transit_gateway_route_table_id"],
                properties(route_table)["transitgatewayroutetableid"],
                properties(route_table)["route_table_id"],
                properties(route_table)["id"]
              ) AS route_table_id,
              type(rel) AS relationship_type
            """
        )
        associated_by_attachment: dict[str, set[str]] = {}
        propagated_by_attachment: dict[str, set[str]] = {}
        for row in route_table_rows:
            attachment_id = row.get("attachment_id")
            route_table_id = row.get("route_table_id")
            if not attachment_id or not route_table_id:
                continue
            relationship_type = str(row.get("relationship_type") or "").lower()
            if "propagat" in relationship_type:
                propagated_by_attachment.setdefault(attachment_id, set()).add(
                    route_table_id
                )
            if "associat" in relationship_type:
                associated_by_attachment.setdefault(attachment_id, set()).add(route_table_id)

        attachments: list[TgwAttachment] = []
        for row in attachment_rows:
            tgw_id = row.get("tgw_id")
            attachment_id = row.get("attachment_id")
            vpc_id = row.get("vpc_id")
            if not tgw_id or not attachment_id or not vpc_id:
                continue
            properties = row.get("attachment_properties") or {}
            cidrs = [
                cidr
                for cidr in (
                    ipv4_network(value)
                    for value in [
                        row.get("primary_cidr"),
                        *(row.get("cidr_blocks") or []),
                    ]
                )
                if cidr is not None
            ]
            attachments.append(
                TgwAttachment(
                    id=attachment_id,
                    tgw_id=tgw_id,
                    vpc_id=vpc_id,
                    state=first_property(properties, "state"),
                    resource_type=first_property(
                        properties, "resource_type", "resourcetype"
                    ),
                    account_id=row.get("account_id"),
                    foreign=truthy(row.get("foreign")),
                    cidrs=tuple(dict.fromkeys(cidrs)),
                    subnet_ids=tuple(
                        sorted(subnet for subnet in row.get("subnet_ids", []) if subnet)
                    ),
                    route_table_ids=tuple(
                        sorted(associated_by_attachment.get(attachment_id, set()))
                    ),
                    propagated_route_table_ids=tuple(
                        sorted(propagated_by_attachment.get(attachment_id, set()))
                    ),
                )
            )

        route_rows = self.run(
            """
            MATCH (route_table)-[rel]-(route)
            WHERE any(label IN labels(route_table)
              WHERE toLower(label) CONTAINS "transitgatewayroutetable")
              AND any(label IN labels(route)
                WHERE toLower(label) CONTAINS "transitgatewayroute")
            RETURN
              coalesce(
                properties(route_table)["transit_gateway_route_table_id"],
                properties(route_table)["transitgatewayroutetableid"],
                properties(route_table)["route_table_id"],
                properties(route_table)["id"]
              ) AS route_table_id,
              properties(route) AS route_properties,
              type(rel) AS relationship_type
            """
        )
        routes: list[TgwRoute] = []
        for row in route_rows:
            route_table_id = row.get("route_table_id")
            properties = row.get("route_properties") or {}
            destination = ipv4_network(
                first_property(
                    properties,
                    "destination_cidr_block",
                    "destinationcidrblock",
                    "cidr_block",
                    "cidr",
                )
            )
            attachment_ids = tgw_route_attachment_ids(properties)
            if route_table_id is None or destination is None:
                continue
            route_id = first_property(
                properties,
                "id",
                "route_id",
                "transit_gateway_route_id",
            ) or f"{route_table_id}|{destination}"
            routes.append(
                TgwRoute(
                    id=route_id,
                    route_table_id=route_table_id,
                    destination=destination,
                    attachment_ids=attachment_ids,
                    state=first_property(properties, "state"),
                    route_type=first_property(properties, "type", "route_type"),
                )
            )

        return TgwTopology(tuple(attachments), tuple(routes))

    def load_external_endpoints(
        self, tgw_topology: TgwTopology
    ) -> list[ExternalEndpoint]:
        peering_rows = self.run(
            """
            MATCH (account:AWSAccount)-[:RESOURCE]->(vpc:AWSVpc)<-[:REQUESTER_VPC|ACCEPTER_VPC]-(pc:AWSPeeringConnection)
            WHERE account.foreign = true
              AND (pc.status_code IS NULL OR pc.status_code = 'active')
            OPTIONAL MATCH (vpc)-[:BLOCK_ASSOCIATION]-(cidr:AWSCidrBlock)
            OPTIONAL MATCH (pc)-[:REQUESTER_CIDR|ACCEPTER_CIDR]->(pc_cidr:AWSCidrBlock)
            OPTIONAL MATCH (pc)-[:TAGGED]->(tag:AWSTag)
            WITH
              pc,
              vpc,
              account,
              collect(DISTINCT cidr.cidr_block) AS vpc_cidr_blocks,
              collect(DISTINCT CASE
                WHEN pc_cidr.vpcid = vpc.vpcid THEN pc_cidr.cidr_block
                ELSE NULL
              END) AS peering_cidr_blocks,
              collect(DISTINCT CASE
                WHEN tag.key = 'Name' THEN tag.value
                ELSE NULL
              END) AS name_tags
            RETURN
              pc.id AS peering_id,
              vpc.vpcid AS vpc_id,
              account.id AS account_id,
              coalesce(vpc.region, pc.requester_region, pc.accepter_region) AS region,
              coalesce(
                pc.name,
                pc._ont_name,
                head([tag_value IN name_tags WHERE tag_value IS NOT NULL])
              ) AS peering_name,
              coalesce(vpc.name, vpc._ont_name, vpc.vpcid) AS label,
              coalesce(vpc.primary_cidr_block, vpc.cidr_block, vpc.cidrblock) AS primary_cidr,
              vpc_cidr_blocks + peering_cidr_blocks AS cidr_blocks
            """
        )
        endpoints: dict[str, ExternalEndpoint] = {}
        for row in peering_rows:
            peering_id = row.get("peering_id")
            vpc_id = row.get("vpc_id")
            if not peering_id or not vpc_id:
                continue
            for cidr in [
                value
                for value in [
                    row.get("primary_cidr"),
                    *(row.get("cidr_blocks") or []),
                ]
                if value
            ]:
                network = ipv4_network(cidr)
                if network is None:
                    continue
                endpoint_id = f"external:vpc-peering:{peering_id}:{vpc_id}:{network}"
                peering_label = row.get("peering_name") or peering_id
                endpoints[endpoint_id] = ExternalEndpoint(
                    id=endpoint_id,
                    label=(
                        f"{peering_label} (pcx)"
                        if row.get("peering_name")
                        else peering_id
                    ),
                    cidr=network,
                    connection_kind="vpc_peering",
                    connection_id=peering_id,
                    vpc_id=vpc_id,
                    account_id=row.get("account_id"),
                    region=row.get("region"),
                    resource_type="vpc",
                    connection_name=row.get("peering_name"),
                )

        route_cidrs_by_attachment: dict[str, set[Any]] = {}
        for route in tgw_topology.routes:
            if not route.active:
                continue
            for attachment_id in route.attachment_ids:
                route_cidrs_by_attachment.setdefault(attachment_id, set()).add(
                    route.destination
                )

        for attachment in tgw_topology.attachments:
            resource_type = (attachment.resource_type or "").lower()
            external = attachment.foreign or resource_type not in {"", "vpc"}
            if not external:
                continue
            cidrs = set(attachment.cidrs) | route_cidrs_by_attachment.get(
                attachment.id, set()
            )
            for cidr in cidrs:
                endpoint_id = (
                    f"external:tgw:{attachment.tgw_id}:{attachment.id}:{cidr}"
                )
                endpoints[endpoint_id] = ExternalEndpoint(
                    id=endpoint_id,
                    label=(
                        f"{attachment.resource_type or 'external'} "
                        f"{attachment.id} via {attachment.tgw_id} ({cidr})"
                    ),
                    cidr=cidr,
                    connection_kind=f"transit_gateway_{resource_type or 'attachment'}",
                    connection_id=attachment.tgw_id,
                    vpc_id=attachment.vpc_id,
                    account_id=attachment.account_id,
                    tgw_id=attachment.tgw_id,
                    attachment_id=attachment.id,
                    resource_type=attachment.resource_type,
                )

        return sorted(endpoints.values(), key=lambda endpoint: endpoint.id)
