"""End-to-end test for the HITL interception + approval flow.

Uses:
* FastAPI TestClient (actually ``httpx.AsyncClient`` + ``ASGITransport``).
* fakeredis for the idempotency store.
* aiosqlite for the HITL registry (same SQLAlchemy schema as production).
* A stub upstream transport that pretends to be the real MCP backend.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from agentguard.hitl.approval_api import sign_decision

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
async def app_and_client(monkeypatch, tmp_path):
    # Configure settings for this test run.
    monkeypatch.setenv("AGENTGUARD_UPSTREAM_URL", "http://upstream.local")
    monkeypatch.setenv("AGENTGUARD_REDIS_URL", "redis://unused/0")
    monkeypatch.setenv("AGENTGUARD_HITL_HMAC_SECRET", "secret")
    monkeypatch.setenv("AGENTGUARD_POLICIES_PATH", str(REPO_ROOT / "configs" / "policies.yaml"))
    monkeypatch.setenv("AGENTGUARD_DLP_RULES_PATH", str(REPO_ROOT / "configs" / "dlp_rules.yaml"))
    monkeypatch.setenv(
        "AGENTGUARD_POSTGRES_DSN", f"sqlite+aiosqlite:///{tmp_path / 'hitl.db'}"
    )
    from agentguard.settings import reset_settings_for_tests

    reset_settings_for_tests()

    # Build the app but replace Redis + the outbound HTTP client.
    from agentguard.main import create_app
    from agentguard.settings import get_settings

    settings = get_settings()



    app = create_app(settings)

    # Upstream stub — returns canned responses for known tools.
    def _upstream_handler(request: httpx.Request) -> httpx.Response:
        body = request.content
        try:
            body_json = json.loads(body) if body else {}
        except json.JSONDecodeError:
            body_json = {}
        return httpx.Response(
            200,
            json={
                "ok": True,
                "seen_tool": body_json.get("tool", {}).get("name"),
                "seen_body": body_json,
                "path": request.url.path,
            },
        )

    upstream_transport = httpx.MockTransport(_upstream_handler)

    # httpx's ASGITransport does not drive lifespan events. Run the lifespan
    # context manually so `app.state` is populated before the first request.
    async with app.router.lifespan_context(app):
        # Swap external connections with fakes before exercising the gateway.
        import fakeredis.aioredis as _fakeredis

        fake_client = _fakeredis.FakeRedis(decode_responses=True)
        app.state.redis_store._client = fake_client  # type: ignore[attr-defined]
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
async def test_hitl_full_flow(app_and_client):
    app, client = app_and_client

    # 1. Agent fires a high-risk tool call.
    resp = await client.post(
        "/tools/execute_bank_transfer",
        json={
            "tool": {"name": "execute_bank_transfer"},
            "arguments": {"amount": 10_000, "to": "acct-9"},
        },
        headers={"X-Session-Id": "sess-1", "Idempotency-Key": "idem-hitl-1"},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "PENDING_APPROVAL"
    ticket_id = data["ticket_id"]

    # 2. Operator queries the pending list.
    pending = await client.get("/agentguard/hitl/pending")
    assert pending.status_code == 200
    tickets = pending.json()["tickets"]
    assert any(t["ticket_id"] == ticket_id for t in tickets)

    # 3. Status poll before approval.
    status_resp = await client.get(f"/agentguard/hitl/status/{ticket_id}")
    assert status_resp.json()["status"] == "PENDING_APPROVAL"

    # 4. Approver signs and submits — gateway executes the request.
    signature = sign_decision("secret", ticket_id, "cfo@corp", "approve")
    approve = await client.post(
        "/agentguard/hitl/approve",
        json={"ticket_id": ticket_id, "approver": "cfo@corp", "signature": signature},
    )
    assert approve.status_code == 200
    approved = approve.json()
    assert approved["status"] == "EXECUTED"
    response_body = json.loads(approved["response"]["body"])
    assert response_body["ok"] is True
    assert response_body["seen_tool"] == "execute_bank_transfer"


@pytest.mark.asyncio
async def test_hitl_invalid_signature_is_rejected(app_and_client):
    app, client = app_and_client

    resp = await client.post(
        "/tools/execute_bank_transfer",
        json={"tool": {"name": "execute_bank_transfer"}, "arguments": {"amount": 1}},
        headers={"X-Session-Id": "sess-2", "Idempotency-Key": "idem-hitl-2"},
    )
    ticket_id = resp.json()["ticket_id"]

    bad = await client.post(
        "/agentguard/hitl/approve",
        json={
            "ticket_id": ticket_id,
            "approver": "evil@corp",
            "signature": "00" * 32,
        },
    )
    assert bad.status_code == 401


@pytest.mark.asyncio
async def test_reject_transitions_to_rejected(app_and_client):
    app, client = app_and_client

    resp = await client.post(
        "/tools/drop_database",
        json={"tool": {"name": "drop_database"}, "arguments": {"name": "prod"}},
        headers={"X-Session-Id": "sess-3", "Idempotency-Key": "idem-hitl-3"},
    )
    ticket_id = resp.json()["ticket_id"]

    sig = sign_decision("secret", ticket_id, "secops@corp", "reject")
    rej = await client.post(
        "/agentguard/hitl/reject",
        json={"ticket_id": ticket_id, "approver": "secops@corp", "signature": sig},
    )
    assert rej.status_code == 200
    assert rej.json()["status"] == "REJECTED"
