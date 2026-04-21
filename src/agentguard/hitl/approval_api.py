"""FastAPI router for the HITL management plane.

Endpoints:

* ``GET  /agentguard/hitl/pending`` — list pending tickets (for operators).
* ``GET  /agentguard/hitl/status/{ticket_id}`` — poll endpoint for agents.
* ``POST /agentguard/hitl/approve`` — approver callback (HMAC-signed).
* ``POST /agentguard/hitl/reject``  — approver callback (HMAC-signed).

The HMAC signature models an OAuth 2.0 CIBA callback: approvers authenticate
out-of-band, and the identity provider sends back a signed assertion the
gateway can verify statelessly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..models import ProxyResponse, RequestContext, TicketStatus
from ..storage.hitl_registry import TicketView

logger = logging.getLogger(__name__)


class ApprovalRequest(BaseModel):
    ticket_id: str
    approver: str = Field(..., description="Identity of the approver (sub claim, email, etc.)")
    signature: str = Field(..., description="Hex HMAC-SHA256 over 'ticket_id|approver|action'.")


def _verify_signature(
    *, secret: str, ticket_id: str, approver: str, action: str, signature: str
) -> bool:
    message = f"{ticket_id}|{approver}|{action}".encode()
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _ticket_payload(view: TicketView) -> dict[str, Any]:
    body = None
    if view.response_body_b64:
        try:
            body = base64.b64decode(view.response_body_b64).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = view.response_body_b64
    return {
        "ticket_id": view.ticket_id,
        "status": view.status,
        "tool_name": view.tool_name,
        "approver": view.approver,
        "created_at": view.created_at.isoformat() if view.created_at else None,
        "updated_at": view.updated_at.isoformat() if view.updated_at else None,
        "sanitized_findings": view.sanitized_findings,
        "response": {
            "status_code": view.response_status,
            "body": body,
            "media_type": view.response_media_type,
        }
        if view.status == TicketStatus.EXECUTED.value
        else None,
    }


def build_hitl_router() -> APIRouter:
    router = APIRouter()

    @router.get("/pending")
    async def list_pending(request: Request) -> JSONResponse:
        registry = request.app.state.hitl_registry
        tickets = await registry.list_pending()
        return JSONResponse({"tickets": [_ticket_payload(t) for t in tickets]})

    @router.get("/status/{ticket_id}")
    async def get_status(ticket_id: str, request: Request) -> JSONResponse:
        registry = request.app.state.hitl_registry
        view = await registry.get(ticket_id)
        if view is None:
            raise HTTPException(status_code=404, detail="ticket_not_found")
        return JSONResponse(_ticket_payload(view))

    @router.post("/approve")
    async def approve(body: ApprovalRequest, request: Request) -> JSONResponse:
        return await _decide(
            action="approve",
            body=body,
            request=request,
        )

    @router.post("/reject")
    async def reject(body: ApprovalRequest, request: Request) -> JSONResponse:
        return await _decide(
            action="reject",
            body=body,
            request=request,
        )

    return router


async def _decide(*, action: str, body: ApprovalRequest, request: Request) -> JSONResponse:
    settings = request.app.state.settings
    registry = request.app.state.hitl_registry
    gateway = request.app.state.gateway

    if not _verify_signature(
        secret=settings.hitl_hmac_secret,
        ticket_id=body.ticket_id,
        approver=body.approver,
        action=action,
        signature=body.signature,
    ):
        raise HTTPException(status_code=401, detail="invalid_signature")

    current = await registry.get(body.ticket_id)
    if current is None:
        raise HTTPException(status_code=404, detail="ticket_not_found")
    if current.status != TicketStatus.PENDING.value:
        return JSONResponse(
            {"status": current.status, "detail": "ticket_already_resolved"},
            status_code=409,
        )

    if action == "reject":
        view = await registry.mark_rejected(body.ticket_id, body.approver)
        return JSONResponse(_ticket_payload(view))

    # Approve → replay the stored request to the upstream backend.
    view = await registry.mark_approved(body.ticket_id, body.approver)
    if view is None:
        raise HTTPException(status_code=404, detail="ticket_not_found")

    raw = await registry.get_raw_request(body.ticket_id)
    if raw is None:
        raise HTTPException(status_code=500, detail="ticket_body_missing")

    ctx = _ctx_from_raw(raw)
    response = await gateway.forward_after_approval(ctx)
    view = await registry.mark_executed(
        body.ticket_id,
        status_code=response.status_code,
        body=response.body,
        headers=response.headers,
        media_type=response.media_type,
    )
    return JSONResponse(_ticket_payload(view))


def _ctx_from_raw(raw: dict[str, Any]) -> RequestContext:
    body_bytes = base64.b64decode((raw.get("body_b64") or "").encode("ascii") or b"")
    body_json = None
    if body_bytes:
        import json

        try:
            body_json = json.loads(body_bytes)
        except json.JSONDecodeError:
            body_json = None

    return RequestContext(
        method=raw["method"],
        path=raw["path"],
        query_string=raw.get("query", ""),
        headers=dict(raw.get("headers", {})),
        body_bytes=body_bytes,
        body_json=body_json,
        jwt_claims=dict(raw.get("jwt_claims", {})),
        session=dict(raw.get("session", {})),
        mcp=dict(raw.get("mcp", {})),
        idempotency_key=raw.get("idempotency_key"),
        tool_name=raw.get("tool_name"),
    )


def sign_decision(secret: str, ticket_id: str, approver: str, action: str) -> str:
    """Helper used by the mock approval console / tests to mint a signature."""
    message = f"{ticket_id}|{approver}|{action}".encode()
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _dummy() -> ProxyResponse:  # pragma: no cover - keeps ProxyResponse imported
    return ProxyResponse.json(500, {})
