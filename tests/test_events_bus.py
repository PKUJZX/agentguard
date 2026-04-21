"""Tests for the gateway event bus and /agentguard/events* endpoints."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
async def app_and_client(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_UPSTREAM_URL", "http://upstream.local")
    monkeypatch.setenv("AGENTGUARD_REDIS_URL", "redis://unused/0")
    monkeypatch.setenv("AGENTGUARD_HITL_HMAC_SECRET", "secret")
    monkeypatch.setenv("AGENTGUARD_POLICIES_PATH", str(REPO_ROOT / "configs" / "policies.yaml"))
    monkeypatch.setenv("AGENTGUARD_DLP_RULES_PATH", str(REPO_ROOT / "configs" / "dlp_rules.yaml"))
    monkeypatch.setenv(
        "AGENTGUARD_POSTGRES_DSN", f"sqlite+aiosqlite:///{tmp_path / 'events.db'}"
    )
    from agentguard.settings import reset_settings_for_tests

    reset_settings_for_tests()

    from agentguard.main import create_app
    from agentguard.settings import get_settings

    settings = get_settings()
    app = create_app(settings)

    def _upstream_handler(request: httpx.Request) -> httpx.Response:
        body = request.content
        try:
            body_json = json.loads(body) if body else {}
        except json.JSONDecodeError:
            body_json = {}
        return httpx.Response(200, json={"ok": True, "received": body_json})

    upstream_transport = httpx.MockTransport(_upstream_handler)

    async with app.router.lifespan_context(app):
        import fakeredis.aioredis as _fakeredis

        app.state.redis_store._client = _fakeredis.FakeRedis(decode_responses=True)
        await app.state.http_client.aclose()
        app.state.http_client = httpx.AsyncClient(transport=upstream_transport)
        app.state.gateway.http = app.state.http_client
        app.state.gateway.hitl.http = app.state.http_client

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://gateway"
        ) as client:
            yield app, client


@pytest.mark.asyncio
async def test_event_bus_publishes_allowed_and_denied(app_and_client):
    app, client = app_and_client

    # ALLOWED — benign search_docs call.
    r = await client.post(
        "/tools/search_docs",
        json={"tool": {"name": "search_docs"}, "query": "what is oauth"},
        headers={
            "X-Session-Id": "events-sess-1",
            "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjaS1ib3QifQ.sig",
        },
    )
    assert r.status_code == 200

    # DENIED — DROP TABLE attempt.
    r2 = await client.post(
        "/tools/search_docs",
        json={"tool": {"name": "search_docs"}, "query": "weekly; DROP TABLE users;"},
        headers={
            "X-Session-Id": "events-sess-1",
            "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjaS1ib3QifQ.sig",
        },
    )
    assert r2.status_code == 403

    stats = (await client.get("/agentguard/stats")).json()
    assert stats["total"] >= 2
    assert stats["by_verdict"].get("ALLOWED", 0) >= 1
    assert stats["by_verdict"].get("DENIED", 0) >= 1

    recent = (await client.get("/agentguard/events/recent")).json()["events"]
    verdicts = [e["verdict"] for e in recent]
    assert "ALLOWED" in verdicts
    assert "DENIED" in verdicts
    denied = next(e for e in recent if e["verdict"] == "DENIED")
    assert denied["rule"] == "block-sql-drop"
    assert denied["tool_name"] == "search_docs"


@pytest.mark.asyncio
async def test_event_bus_reports_sanitized_findings(app_and_client):
    app, client = app_and_client

    r = await client.post(
        "/tools/send_message",
        json={
            "tool": {"name": "send_message"},
            "channel": "#leaks",
            "message": "AKIA0123456789ABCDEF and ghp_aaaaaaaaaaaaaaaaaaaaaa",
        },
        headers={
            "X-Session-Id": "events-sess-2",
            "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjaS1ib3QifQ.sig",
        },
    )
    assert r.status_code == 200

    recent = (await client.get("/agentguard/events/recent")).json()["events"]
    sanitized = [e for e in recent if e["verdict"] == "SANITIZED"]
    assert sanitized, "expected a SANITIZED event"
    rules_hit = {f["rule"] for ev in sanitized for f in ev["sanitized_findings"]}
    assert "aws-access-key" in rules_hit
    assert "github-pat" in rules_hit


@pytest.mark.asyncio
async def test_event_bus_reports_hitl_suspend(app_and_client):
    app, client = app_and_client

    r = await client.post(
        "/tools/execute_bank_transfer",
        json={"tool": {"name": "execute_bank_transfer"}, "arguments": {"amount": 1}},
        headers={"X-Session-Id": "events-sess-3", "Idempotency-Key": "ev-hitl-1"},
    )
    assert r.status_code == 202
    ticket_id = r.json()["ticket_id"]

    # Small async hop for any pending publishes.
    await asyncio.sleep(0)

    recent = (await client.get("/agentguard/events/recent")).json()["events"]
    suspended = [e for e in recent if e["verdict"] == "SUSPENDED_HITL"]
    assert suspended, "expected a SUSPENDED_HITL event"
    assert suspended[-1]["ticket_id"] == ticket_id
