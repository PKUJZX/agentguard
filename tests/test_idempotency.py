"""Tests for the idempotency middleware."""

from __future__ import annotations

import json

import pytest

from agentguard.middleware.idempotency import IdempotencyMiddleware
from agentguard.models import ProxyResponse, RequestContext


def _make_ctx(
    *, idem_key: str | None = None, tool: str = "create_ticket", method: str = "POST"
) -> RequestContext:
    body = {"tool": {"name": tool}, "arguments": {"title": "demo"}}
    body_bytes = json.dumps(body).encode("utf-8")
    return RequestContext(
        method=method,
        path="/tools/" + tool,
        query_string="",
        headers={"content-type": "application/json"},
        body_bytes=body_bytes,
        body_json=body,
        jwt_claims={"sub": "ci-bot"},
        session={"session_id": "s-1"},
        mcp={"tool": {"name": tool}},
        idempotency_key=idem_key,
        tool_name=tool,
    )


@pytest.mark.asyncio
async def test_first_call_passes_and_subsequent_replay_cached(fake_redis_store):
    mw = IdempotencyMiddleware(store=fake_redis_store, secret="x", ttl_seconds=60)
    ctx1 = _make_ctx(idem_key="key-1")

    # First call — nothing cached, middleware reserves the key.
    assert await mw.lookup(ctx1) is None

    # Simulate upstream success and store the response.
    upstream = ProxyResponse.json(200, {"id": "ticket-123"})
    await mw.store(ctx1, upstream)

    # Second call with the same key — should return the cached replay.
    ctx2 = _make_ctx(idem_key="key-1")
    replay = await mw.lookup(ctx2)
    assert replay is not None
    assert replay.status_code == 200
    assert replay.headers.get("x-agentguard-replay") == "true"
    payload = json.loads(replay.body)
    assert payload["id"] == "ticket-123"


@pytest.mark.asyncio
async def test_derived_key_deduplicates_same_intent(fake_redis_store):
    mw = IdempotencyMiddleware(store=fake_redis_store, secret="x", ttl_seconds=60)
    # No explicit Idempotency-Key; middleware must derive the same key from
    # (session, tool, intent) across both requests.
    ctx1 = _make_ctx()
    ctx2 = _make_ctx()

    assert await mw.lookup(ctx1) is None
    await mw.store(ctx1, ProxyResponse.json(200, {"id": "ticket-derived"}))

    replay = await mw.lookup(ctx2)
    assert replay is not None
    assert json.loads(replay.body)["id"] == "ticket-derived"


@pytest.mark.asyncio
async def test_processing_state_returns_409(fake_redis_store):
    mw = IdempotencyMiddleware(store=fake_redis_store, secret="x", ttl_seconds=60)
    ctx1 = _make_ctx(idem_key="key-2")

    assert await mw.lookup(ctx1) is None  # reserves the key

    ctx2 = _make_ctx(idem_key="key-2")
    resp = await mw.lookup(ctx2)
    assert resp is not None
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_get_is_not_idempotency_protected(fake_redis_store):
    mw = IdempotencyMiddleware(store=fake_redis_store, secret="x", ttl_seconds=60)
    ctx = _make_ctx(method="GET")
    assert await mw.lookup(ctx) is None
    # No reservation should have been made; a second call also passes through.
    assert await mw.lookup(_make_ctx(method="GET")) is None


@pytest.mark.asyncio
async def test_upstream_failure_releases_reservation(fake_redis_store):
    mw = IdempotencyMiddleware(store=fake_redis_store, secret="x", ttl_seconds=60)
    ctx = _make_ctx(idem_key="key-3")

    assert await mw.lookup(ctx) is None
    # Upstream returned a 5xx — should release so a corrected retry can proceed.
    await mw.store(ctx, ProxyResponse.json(502, {"error": "bad gateway"}))

    ctx2 = _make_ctx(idem_key="key-3")
    assert await mw.lookup(ctx2) is None  # reservation is gone
