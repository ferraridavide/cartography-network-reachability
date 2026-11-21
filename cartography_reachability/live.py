from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .loader import CartographyLoader
from .models import Eni, ReachabilityPath
from .tracer import RayTracer


@dataclass(frozen=True)
class ReachabilityConfig:
    uri: str
    user: str
    password: str | None
    database: str | None
    source_filter: str | None = None
    destination_filter: str | None = None
    source_limit: int = 0
    pair_limit: int = 0
    path_limit: int = 0

    @classmethod
    def from_env(cls) -> "ReachabilityConfig":
        load_environment()
        return cls(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD"),
            database=os.getenv("NEO4J_DATABASE") or None,
            source_filter=os.getenv("REACHABILITY_SOURCE_FILTER"),
            destination_filter=os.getenv("REACHABILITY_DESTINATION_FILTER"),
            source_limit=int(os.getenv("REACHABILITY_SOURCE_LIMIT", "0")),
            pair_limit=int(os.getenv("REACHABILITY_PAIR_LIMIT", "0")),
            path_limit=int(os.getenv("REACHABILITY_PATH_LIMIT", "0")),
        )

    def connection_context(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "user": self.user,
            "database": self.database,
            "password_set": bool(self.password),
        }

    def trace_context(self) -> dict[str, Any]:
        return {
            "source_filter": self.source_filter,
            "destination_filter": self.destination_filter,
            "source_limit": self.source_limit,
            "pair_limit": self.pair_limit,
            "path_limit": self.path_limit,
        }


def load_environment() -> None:
    """Load `.env` from the current directory, then from the project root."""
    load_dotenv()
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def trace_live_reachability(
    config: ReachabilityConfig | None = None,
) -> tuple[list[ReachabilityPath], dict[str, Eni]]:
    config = config or ReachabilityConfig.from_env()
    if not config.password:
        raise RuntimeError(
            "NEO4J_PASSWORD is not set. Live reachability loading requires Neo4j "
            f"credentials. Connection context: {config.connection_context()}."
        )

    loader = CartographyLoader(config.uri, config.user, config.password, config.database)
    try:
        try:
            enis = loader.load_enis()
            egress_rules, ingress_rules, sg_allows = loader.load_security_group_rules()
            elb_targets = loader.load_elb_targets()
            (
                _route_table_vpc,
                subnet_route_table,
                main_route_table,
                routes_by_table,
                peering_vpcs,
                tgw_topology,
                external_endpoints,
            ) = loader.load_routes()
        except Exception as exc:
            raise RuntimeError(
                "Failed to load live Cartography data from Neo4j. "
                f"Connection context: {config.connection_context()}. "
                f"Original error: {type(exc).__name__}: {exc}"
            ) from exc
    finally:
        loader.close()

    tracer = RayTracer(
        enis=enis,
        egress_rules=egress_rules,
        ingress_rules=ingress_rules,
        sg_allows=sg_allows,
        subnet_route_table=subnet_route_table,
        main_route_table=main_route_table,
        routes_by_table=routes_by_table,
        peering_vpcs=peering_vpcs,
        tgw_topology=tgw_topology,
        external_endpoints=external_endpoints,
        elb_targets=elb_targets,
    )

    try:
        paths = tracer.trace(
            source_filter=config.source_filter,
            destination_filter=config.destination_filter,
            source_limit=config.source_limit,
            pair_limit=config.pair_limit,
            path_limit=config.path_limit,
        )
    except Exception as exc:
        raise RuntimeError(
            "Loaded Cartography data, but live reachability tracing failed. "
            f"Trace context: {config.trace_context()}. "
            f"Original error: {type(exc).__name__}: {exc}"
        ) from exc

    return paths, enis
