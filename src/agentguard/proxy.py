"""Core reverse-proxy handler that composes the four middlewares.

The inbound request flows through:

    1. Idempotency  (Redis SETNX + response cache)
    2. CEL Policy   (allow/deny with JWT + session + mcp + request)
    3. Payload Sanitizer   (DLP regex masking)
    4. HITL Interceptor    (async approval for high-risk tools)

Any middleware may short-circuit the chain by returning a ``ProxyResponse``.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
from typing import Any

import httpx
from fastapi import Request
from fastapi.responses import Response

from .events import EventBus, Verdict, new_event
from .middleware.cel_policy import CELPolicyMiddleware
from .middleware.hitl import HITLMiddleware
from .middleware.idempotency import IdempotencyMiddleware
from .middleware.payload_sanitizer import PayloadSanitizer
from .models import ProxyResponse, RequestContext
from .settings import Settings

logger = logging.getLogger(__name__)


# Headers that must not be forwarded verbatim between client <-> upstream.
_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


class Gateway:
    """Glue object that owns middleware instances and the HTTP client."""

    def __init__(
        self,
        settings: Settings,
        idempotency: IdempotencyMiddleware,
        cel: CELPolicyMiddleware,
        sanitizer: PayloadSanitizer,
        hitl: HITLMiddleware,
        http_client: httpx.AsyncClient,
        event_bus: EventBus | None = None,
    ) -> None:
        self.settings = settings
        self.idempotency = idempotency
        self.cel = cel
        self.sanitizer = sanitizer
        self.hitl = hitl
        self.http = http_client
        self.event_bus = event_bus or EventBus()

    async def handle(self, request: Request) -> Response:
        t0 = time.monotonic()
        ctx = await self._build_context(request)
        session_id = ctx.session.get("session_id") if ctx.session else None

        # 1. Idempotency pre-check — if a cached response exists, replay it and
        # stop. This is what breaks the model's hallucinated retry loops.
        cached = await self.idempotency.lookup(ctx)
        if cached is not None:
            self.event_bus.publish(
                new_event(
                    verdict=Verdict.REPLAYED,
                    method=ctx.method,
                    path=ctx.path,
                    tool_name=ctx.tool_name,
                    session_id=session_id,
                    rule="idempotency",
                    reason="cached_response_replayed",
                    upstream_status=cached.status_code,
                    latency_ms=(time.monotonic() - t0) * 1000,
                    extra={"idempotency_key": ctx.idempotency_key},
                )
            )
            logger.info("idempotency.replay key=%s", ctx.idempotency_key)
            return _to_fastapi_response(cached)

        # 2. CEL policy evaluation.
        denial = await self.cel.evaluate(ctx)
        if denial is not None:
            import json

            try:
                deny_info = json.loads(denial.body)
            except Exception:  # noqa: BLE001
                deny_info = {}
            self.event_bus.publish(
                new_event(
                    verdict=Verdict.DENIED,
                    method=ctx.method,
                    path=ctx.path,
                    tool_name=ctx.tool_name,
                    session_id=session_id,
                    rule=deny_info.get("rule"),
                    reason=deny_info.get("reason"),
                    upstream_status=403,
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
            )
            logger.info("cel.deny tool=%s", ctx.tool_name)
            return _to_fastapi_response(denial)

        # 3. Payload sanitization (mutates ctx in place, may not short-circuit).
        await self.sanitizer.sanitize(ctx)
        if ctx.sanitized_findings:
            self.event_bus.publish(
                new_event(
                    verdict=Verdict.SANITIZED,
                    method=ctx.method,
                    path=ctx.path,
                    tool_name=ctx.tool_name,
                    session_id=session_id,
                    rule="dlp",
                    reason="payload_rewritten",
                    sanitized_findings=ctx.sanitized_findings,
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
            )

        # 4. HITL interception for high-risk tools.
        hitl_response = await self.hitl.maybe_intercept(ctx)
        if hitl_response is not None:
            import json

            try:
                info = json.loads(hitl_response.body)
            except Exception:  # noqa: BLE001
                info = {}
            self.event_bus.publish(
                new_event(
                    verdict=Verdict.SUSPENDED_HITL,
                    method=ctx.method,
                    path=ctx.path,
                    tool_name=ctx.tool_name,
                    session_id=session_id,
                    rule="high_risk_tool",
                    reason="awaiting_human_approval",
                    sanitized_findings=ctx.sanitized_findings,
                    ticket_id=info.get("ticket_id"),
                    upstream_status=202,
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
            )
            logger.info("hitl.suspended tool=%s", ctx.tool_name)
            return _to_fastapi_response(hitl_response)

        # 5. Forward upstream with the (possibly sanitized) payload.
        upstream = await self._forward(ctx)

        # 6. Store the response for future idempotent replays.
        await self.idempotency.store(ctx, upstream)

        self.event_bus.publish(
            new_event(
                verdict=(
                    Verdict.ALLOWED
                    if 200 <= upstream.status_code < 400
                    else Verdict.UPSTREAM_ERROR
                ),
                method=ctx.method,
                path=ctx.path,
                tool_name=ctx.tool_name,
                session_id=session_id,
                upstream_status=upstream.status_code,
                sanitized_findings=ctx.sanitized_findings,
                latency_ms=(time.monotonic() - t0) * 1000,
            )
        )
        return _to_fastapi_response(upstream)

    async def forward_after_approval(self, ctx: RequestContext) -> ProxyResponse:
        """Re-execute a previously-suspended request once HITL approval lands."""
        t0 = time.monotonic()
        upstream = await self._forward(ctx)
        await self.idempotency.store(ctx, upstream)
        session_id = ctx.session.get("session_id") if ctx.session else None
        self.event_bus.publish(
            new_event(
                verdict=Verdict.EXECUTED_HITL,
                method=ctx.method,
                path=ctx.path,
                tool_name=ctx.tool_name,
                session_id=session_id,
                rule="hitl.approve",
                reason="approved_and_executed",
                upstream_status=upstream.status_code,
                latency_ms=(time.monotonic() - t0) * 1000,
            )
        )
        return upstream

    async def _forward(self, ctx: RequestContext) -> ProxyResponse:
        url = self.settings.upstream_url.rstrip("/") + "/" + ctx.path.lstrip("/")
        if ctx.query_string:
            url = f"{url}?{ctx.query_string}"

        outbound_headers = {
            k: v for k, v in ctx.headers.items() if k.lower() not in _HOP_BY_HOP_HEADERS
        }
        try:
            upstream = await self.http.request(
                ctx.method,
                url,
                content=ctx.effective_body_bytes(),
                headers=outbound_headers,
                timeout=self.settings.request_timeout,
            )
        except httpx.HTTPError as exc:
            logger.warning("upstream.error url=%s error=%s", url, exc)
            return ProxyResponse.json(
                status_code=502,
                payload={"error": "upstream_unreachable", "detail": str(exc)},
            )

        response_headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in _HOP_BY_HOP_HEADERS
        }
        return ProxyResponse(
            status_code=upstream.status_code,
            body=upstream.content,
            headers=response_headers,
            media_type=upstream.headers.get("content-type", "application/octet-stream"),
        )

    # -------------------------- context construction --------------------------

    async def _build_context(self, request: Request) -> RequestContext:
        raw_body = await request.body()
        headers = {k.decode().lower(): v.decode() for k, v in request.headers.raw}
        body_json = _try_parse_json(raw_body, headers.get("content-type", ""))

        jwt_claims = _extract_jwt_claims(headers.get("authorization", ""))
        session = _extract_session(headers)
        tool_name = _extract_tool_name(request.url.path, body_json)
        mcp = {"tool": {"name": tool_name} if tool_name else {}}

        idem_key = headers.get("idempotency-key")

        return RequestContext(
            method=request.method,
            path=request.url.path,
            query_string=request.url.query or "",
            headers=headers,
            body_bytes=raw_body,
            body_json=body_json,
            jwt_claims=jwt_claims,
            session=session,
            mcp=mcp,
            idempotency_key=idem_key,
            tool_name=tool_name,
        )


# ------------------------------ helpers ------------------------------


def _to_fastapi_response(resp: ProxyResponse) -> Response:
    return Response(
        content=resp.body,
        status_code=resp.status_code,
        headers=resp.headers,
        media_type=resp.media_type,
    )


def _try_parse_json(body: bytes, content_type: str) -> Any | None:
    if not body:
        return None
    if "json" not in content_type.lower() and not body.lstrip().startswith((b"{", b"[")):
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _extract_jwt_claims(authorization: str) -> dict[str, Any]:
    """Decode a bearer JWT's claims segment WITHOUT verifying the signature.

    AgentGuard treats the JWT as a context hint only; signature verification is
    the responsibility of an upstream identity-aware proxy (OIDC sidecar etc.).
    In production, replace with a proper JOSE library call + issuer/audience
    checks.
    """

    if not authorization:
        return {}
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return {}
    token = parts[1]
    segments = token.split(".")
    if len(segments) < 2:
        return {}
    payload = segments[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded)
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return {}


def _extract_session(headers: dict[str, str]) -> dict[str, Any]:
    """Read session-pinning hints from headers.

    These headers are set by the Agent SDK when the session is initialized
    so the gateway can enforce "one session → one initial repository" locks.
    """

    session: dict[str, Any] = {}
    if sid := headers.get("x-session-id"):
        session["session_id"] = sid
    if initial_repo := headers.get("x-session-initial-repository"):
        session["initial_repository"] = initial_repo
    return session


def _extract_tool_name(path: str, body_json: Any | None) -> str | None:
    """Best-effort extraction of the MCP/tool name from the request."""

    if isinstance(body_json, dict):
        if isinstance(body_json.get("tool"), dict) and "name" in body_json["tool"]:
            return str(body_json["tool"]["name"])
        params = body_json.get("params")
        if isinstance(params, dict) and "name" in params:
            return str(params["name"])
        if "method" in body_json and isinstance(body_json["method"], str):
            return body_json["method"]
        if "tool_name" in body_json:
            return str(body_json["tool_name"])

    # Fallback: last path segment, e.g. POST /tools/execute_bank_transfer
    segments = [s for s in path.split("/") if s]
    if len(segments) >= 2 and segments[-2] in {"tools", "tool", "mcp"}:
        return segments[-1]
    return None
