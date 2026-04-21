"""HITL middleware — defense #3.

If the request targets a tool enumerated in ``policies.yaml:high_risk_tools``,
the middleware:

1. Persists the sanitized context to the registry.
2. Fires the webhook (best-effort).
3. Returns HTTP 202 with the ticket id, releasing the agent to sleep.

Approval and execution are driven out-of-band by the endpoints in
``hitl/approval_api.py``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from ..cel.engine import CELEngine
from ..hitl.webhook import post_webhook
from ..models import ProxyResponse, RequestContext
from ..storage.hitl_registry import HITLRegistry
from .payload_sanitizer import PayloadSanitizer  # noqa: F401 — for type docs only

logger = logging.getLogger(__name__)


class HITLMiddleware:
    def __init__(
        self,
        registry: HITLRegistry,
        cel_engine: CELEngine,
        webhook_url: str | None,
        http_client: httpx.AsyncClient,
    ) -> None:
        self.registry = registry
        self.cel_engine = cel_engine
        self.webhook_url = webhook_url
        self.http = http_client

    async def maybe_intercept(self, ctx: RequestContext) -> ProxyResponse | None:
        if not self.cel_engine.is_high_risk(ctx.tool_name):
            return None

        ticket_id = await self.registry.create(
            tool_name=ctx.tool_name,
            idempotency_key=ctx.idempotency_key,
            method=ctx.method,
            path=ctx.path,
            query=ctx.query_string,
            headers=ctx.headers,
            body_bytes=ctx.effective_body_bytes(),
            jwt_claims=ctx.jwt_claims,
            session=ctx.session,
            mcp=ctx.mcp,
            sanitized_findings=ctx.sanitized_findings,
        )

        await post_webhook(
            http_client=self.http,
            webhook_url=self.webhook_url,
            ticket_id=ticket_id,
            tool_name=ctx.tool_name,
            sanitized_findings=ctx.sanitized_findings,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        payload = {
            "status": "PENDING_APPROVAL",
            "ticket_id": ticket_id,
            "tool_name": ctx.tool_name,
            "poll_url": f"/agentguard/hitl/status/{ticket_id}",
            "message": (
                "This tool is configured as high-risk and requires "
                "out-of-band human approval. Poll the status URL until the "
                "ticket transitions to EXECUTED or REJECTED."
            ),
        }
        logger.info("hitl.issue_ticket ticket=%s tool=%s", ticket_id, ctx.tool_name)
        return ProxyResponse.json(status_code=202, payload=payload)
