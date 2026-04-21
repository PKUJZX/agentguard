"""FastAPI entrypoint for AgentGuard.

The app exposes two groups of routes:

* ``/agentguard/*`` — internal management endpoints (health, HITL approval).
* everything else — proxied to the upstream backend via the middleware chain.
"""

from __future__ import annotations

import contextlib
import logging

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .cel.engine import CELEngine
from .events import EventBus
from .events_api import build_events_router
from .hitl.approval_api import build_hitl_router
from .middleware.cel_policy import CELPolicyMiddleware
from .middleware.hitl import HITLMiddleware
from .middleware.idempotency import IdempotencyMiddleware
from .middleware.payload_sanitizer import PayloadSanitizer
from .proxy import Gateway
from .settings import Settings, get_settings
from .storage.hitl_registry import HITLRegistry
from .storage.redis_store import RedisStore

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI app with a lifespan that wires up all dependencies."""

    settings = settings or get_settings()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        logger.info("AgentGuard starting up. upstream=%s", settings.upstream_url)

        redis_store = RedisStore.from_url(settings.redis_url)
        cel_engine = CELEngine.from_file(settings.policies_path)
        hitl_registry = HITLRegistry.from_dsn(settings.postgres_dsn)
        await hitl_registry.initialize()

        http_client = httpx.AsyncClient()

        idempotency = IdempotencyMiddleware(
            store=redis_store,
            secret=settings.idempotency_secret,
            ttl_seconds=settings.idempotency_ttl,
        )
        cel_mw = CELPolicyMiddleware(engine=cel_engine)
        sanitizer = PayloadSanitizer.from_file(settings.dlp_rules_path)
        hitl_mw = HITLMiddleware(
            registry=hitl_registry,
            cel_engine=cel_engine,
            webhook_url=settings.hitl_webhook_url,
            http_client=http_client,
        )

        event_bus = EventBus()

        gateway = Gateway(
            settings=settings,
            idempotency=idempotency,
            cel=cel_mw,
            sanitizer=sanitizer,
            hitl=hitl_mw,
            http_client=http_client,
            event_bus=event_bus,
        )

        app.state.settings = settings
        app.state.gateway = gateway
        app.state.event_bus = event_bus
        app.state.redis_store = redis_store
        app.state.hitl_registry = hitl_registry
        app.state.http_client = http_client

        try:
            yield
        finally:
            logger.info("AgentGuard shutting down.")
            await http_client.aclose()
            await redis_store.close()
            await hitl_registry.close()

    app = FastAPI(
        title="AgentGuard",
        description="Zero-trust security gateway for autonomous AI agents.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(build_hitl_router(), prefix="/agentguard/hitl", tags=["hitl"])
    app.include_router(build_events_router(), prefix="/agentguard", tags=["events"])

    @app.get("/agentguard/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    async def proxy(path: str, request: Request) -> Response:
        # Reject any attempt to recursively call the gateway's own namespace.
        if path.startswith("agentguard/"):
            return JSONResponse(
                {"error": "reserved_namespace", "path": path}, status_code=404
            )
        gateway: Gateway = request.app.state.gateway
        return await gateway.handle(request)

    return app


app = create_app()


def run() -> None:
    """Console-script entry point (``agentguard`` command)."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "agentguard.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    run()
