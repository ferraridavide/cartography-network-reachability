from __future__ import annotations

import argparse
import os
import sys

from .live import ReachabilityConfig, load_environment, trace_live_reachability
from .renderers import render_bundle_json


def parse_args() -> argparse.Namespace:
    load_environment()

    parser = argparse.ArgumentParser(
        description=(
            "Trace AWS ENI reachability from Cartography data and export the "
            "bundle JSON consumed by the frontend."
        )
    )
    parser.add_argument(
        "--uri",
        default=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        help="Neo4j Bolt URI (env: NEO4J_URI, default: bolt://localhost:7687).",
    )
    parser.add_argument(
        "--user",
        default=os.getenv("NEO4J_USER", "neo4j"),
        help="Neo4j user (env: NEO4J_USER, default: neo4j).",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("NEO4J_PASSWORD"),
        help="Neo4j password (env: NEO4J_PASSWORD).",
    )
    parser.add_argument(
        "--database",
        default=os.getenv("NEO4J_DATABASE") or None,
        help="Neo4j database name (env: NEO4J_DATABASE, default: server default).",
    )
    parser.add_argument(
        "--source",
        dest="source_filter",
        help="Source ENI id, owner id/name, private IP, or public IP.",
    )
    parser.add_argument(
        "--destination",
        dest="destination_filter",
        help="Destination ENI id, owner id/name, private IP, or public IP.",
    )
    parser.add_argument(
        "--source-limit",
        type=int,
        default=0,
        help="Maximum source ENIs to trace. Use 0 for no limit.",
    )
    parser.add_argument(
        "--pair-limit",
        type=int,
        default=0,
        help="Maximum source/destination candidate pairs to evaluate. Use 0 for no limit.",
    )
    parser.add_argument(
        "--path-limit",
        type=int,
        default=0,
        help="Maximum reachability paths to emit. Use 0 for no limit.",
    )
    parser.add_argument(
        "--format",
        choices=("bundle-json",),
        default="bundle-json",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--output",
        default="packet_paths_bundle.json",
        help="Output path for the frontend bundle JSON.",
    )
    parser.add_argument(
        "--group-identical-rays",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Group ENIs with the same workload identity and identical outgoing full-evidence rays.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.password:
        print("NEO4J_PASSWORD or --password is required.", file=sys.stderr)
        return 2

    paths, enis = trace_live_reachability(
        ReachabilityConfig(
            uri=args.uri,
            user=args.user,
            password=args.password,
            database=args.database,
            source_filter=args.source_filter,
            destination_filter=args.destination_filter,
            source_limit=args.source_limit,
            pair_limit=args.pair_limit,
            path_limit=args.path_limit,
        )
    )

    output_path = render_bundle_json(
        paths,
        args.output,
        args.group_identical_rays,
        enis,
    )
    print(f"Wrote hierarchical edge bundling JSON data to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
