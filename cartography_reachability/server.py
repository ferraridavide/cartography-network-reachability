"""Web server: traces reachability from Neo4j on demand and serves the frontend."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from .live import ReachabilityConfig, trace_live_reachability
from .renderers import build_bundle_payload

WEB_DIR = Path(__file__).resolve().parent / "web"

BundleBuilder = Callable[[], dict[str, Any]]


@dataclass
class TraceState:
    payload: dict[str, Any] | None = None
    error: str | None = None
    running: bool = False
    generated_at: str | None = None
    duration_seconds: float | None = None


class BundleCache:
    """Builds the bundle once and reuses it until a refresh is requested.

    Requests that arrive while a trace is running wait for it and share its
    result instead of starting another trace.
    """

    def __init__(self, builder: BundleBuilder) -> None:
        self._builder = builder
        self._lock = threading.Lock()
        self._generation = 0
        self.state = TraceState()

    def get(self, refresh: bool = False) -> dict[str, Any]:
        seen_generation = self._generation
        with self._lock:
            traced_while_waiting = self._generation != seen_generation
            if self.state.payload is not None and (not refresh or traced_while_waiting):
                return self.state.payload

            self.state.running = True
            start = time.monotonic()
            try:
                payload = self._builder()
            except Exception as exc:
                self.state.error = str(exc)
                raise
            finally:
                self.state.running = False

            self.state.duration_seconds = round(time.monotonic() - start, 2)
            self.state.generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self.state.error = None
            payload["meta"] = {
                "source": "neo4j",
                "generated_at": self.state.generated_at,
                "duration_seconds": self.state.duration_seconds,
            }
            self.state.payload = payload
            self._generation += 1
            return payload


def live_bundle_builder(
    config: ReachabilityConfig, group_identical_rays: bool = True
) -> BundleBuilder:
    def build() -> dict[str, Any]:
        paths, enis = trace_live_reachability(config)
        return build_bundle_payload(paths, group_identical_rays, enis)

    return build


class SpaStaticFiles(StaticFiles):
    """Static files with a fallback to index.html for client-side routes."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            return await super().get_response("index.html", scope)
        if response.status_code == 404:
            return await super().get_response("index.html", scope)
        return response


def create_app(
    builder: BundleBuilder,
    web_dir: Path | None = WEB_DIR,
    connection: dict[str, Any] | None = None,
) -> Starlette:
    cache = BundleCache(builder)

    async def bundle(request: Request) -> Response:
        refresh = request.query_params.get("refresh") in {"1", "true", "yes"}
        try:
            payload = await run_in_threadpool(cache.get, refresh)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse(payload)

    async def status(request: Request) -> Response:
        state = cache.state
        return JSONResponse(
            {
                "connection": connection or {},
                "ready": state.payload is not None,
                "running": state.running,
                "error": state.error,
                "generated_at": state.generated_at,
                "duration_seconds": state.duration_seconds,
            }
        )

    routes: list[Route | Mount] = [
        Route("/api/bundle", bundle),
        Route("/api/status", status),
    ]
    if web_dir is not None and (web_dir / "index.html").is_file():
        routes.append(Mount("/", app=SpaStaticFiles(directory=web_dir, html=True)))
    else:

        async def missing_frontend(request: Request) -> Response:
            return PlainTextResponse(
                "The frontend is not built. Run `npm install && npm run build` in "
                "bundle-frontend/, or use `npm run dev` there for development.",
                status_code=503,
            )

        routes.append(Route("/{path:path}", missing_frontend))

    app = Starlette(routes=routes, middleware=[Middleware(GZipMiddleware, minimum_size=1024)])
    app.state.cache = cache
    return app
