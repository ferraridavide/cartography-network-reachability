from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser

from .live import ReachabilityConfig, load_environment, trace_live_reachability
from .renderers import render_bundle_json


def add_neo4j_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Neo4j connection")
    group.add_argument(
        "--uri",
        default=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        help="Neo4j Bolt URI (env: NEO4J_URI, default: bolt://localhost:7687).",
    )
    group.add_argument(
        "--user",
        default=os.getenv("NEO4J_USER", "neo4j"),
        help="Neo4j user (env: NEO4J_USER, default: neo4j).",
    )
    group.add_argument(
        "--password",
        default=os.getenv("NEO4J_PASSWORD"),
        help="Neo4j password (env: NEO4J_PASSWORD).",
    )
    group.add_argument(
        "--database",
        default=os.getenv("NEO4J_DATABASE") or None,
        help="Neo4j database name (env: NEO4J_DATABASE, default: server default).",
    )


def add_trace_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Tracing")
    group.add_argument(
        "--source",
        dest="source_filter",
        help="Source ENI id, owner id/name, private IP, or public IP.",
    )
    group.add_argument(
        "--destination",
        dest="destination_filter",
        help="Destination ENI id, owner id/name, private IP, or public IP.",
    )
    group.add_argument(
        "--source-limit",
        type=int,
        default=0,
        help="Maximum source ENIs to trace. Use 0 for no limit.",
    )
    group.add_argument(
        "--pair-limit",
        type=int,
        default=0,
        help="Maximum source/destination candidate pairs to evaluate. Use 0 for no limit.",
    )
    group.add_argument(
        "--path-limit",
        type=int,
        default=0,
        help="Maximum reachability paths to emit. Use 0 for no limit.",
    )
    group.add_argument(
        "--group-identical-rays",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Group ENIs with the same workload identity and identical outgoing full-evidence rays.",
    )


def add_export_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        default="packet_paths_bundle.json",
        help="Output path for the frontend bundle JSON.",
    )


def add_serve_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1", help="Address to bind (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000).")
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the UI in your default browser once the server starts.",
    )


def config_from_args(args: argparse.Namespace) -> ReachabilityConfig:
    return ReachabilityConfig(
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


def run_export(args: argparse.Namespace) -> int:
    paths, enis = trace_live_reachability(config_from_args(args))
    output_path = render_bundle_json(paths, args.output, args.group_identical_rays, enis)
    print(f"Wrote hierarchical edge bundling JSON data to {output_path}")
    return 0


def run_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .server import WEB_DIR, create_app, live_bundle_builder

    config = config_from_args(args)
    app = create_app(
        live_bundle_builder(config, args.group_identical_rays),
        connection=config.connection_context(),
    )
    url = f"http://{args.host}:{args.port}"
    if not (WEB_DIR / "index.html").is_file():
        print(
            "Warning: the frontend is not built, only the API is available. "
            "Run `npm install && npm run build` in bundle-frontend/.",
            file=sys.stderr,
        )
    print(f"Serving reachability UI on {url} (Neo4j: {config.uri})")
    print("The first page load traces reachability from Neo4j; use Re-trace in the UI to refresh.")
    if args.open:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def require_password(args: argparse.Namespace) -> bool:
    if args.password:
        return True
    print("NEO4J_PASSWORD or --password is required.", file=sys.stderr)
    return False


def main() -> int:
    """`cartography-reachability {serve,export}`."""
    load_environment()
    parser = argparse.ArgumentParser(
        prog="cartography-reachability",
        description="Trace AWS network reachability from Cartography data in Neo4j.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser(
        "serve",
        help="Start the web UI, tracing live from Neo4j.",
        description="Start the web UI. Reachability is traced from Neo4j on first load and on Re-trace.",
    )
    add_serve_args(serve)
    add_neo4j_args(serve)
    add_trace_args(serve)

    export = commands.add_parser(
        "export",
        help="Trace once and write the bundle JSON to a file.",
        description="Trace reachability once and write the bundle JSON consumed by the frontend.",
    )
    add_export_args(export)
    add_neo4j_args(export)
    add_trace_args(export)

    args = parser.parse_args()
    if not require_password(args):
        return 2
    return run_serve(args) if args.command == "serve" else run_export(args)


def export_main() -> int:
    """`raytrace-network-paths`: kept as a shortcut for `cartography-reachability export`."""
    load_environment()
    parser = argparse.ArgumentParser(
        prog="raytrace-network-paths",
        description=(
            "Trace AWS ENI reachability from Cartography data and export the "
            "bundle JSON consumed by the frontend."
        ),
    )
    add_export_args(parser)
    add_neo4j_args(parser)
    add_trace_args(parser)
    args = parser.parse_args()
    if not require_password(args):
        return 2
    return run_export(args)


if __name__ == "__main__":
    raise SystemExit(main())
