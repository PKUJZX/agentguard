"""Integration smoke-tests that mirror what the demo scripts exercise.

These tests instantiate the FastAPI app against a mock backend transport and
verify the three flagship defenses end-to-end:

* retry-storm: 5 identical POSTs produce 1 backend call + 4 replays
* injection : CEL repo-lock denies + DLP sanitizer rewrites the AWS key
* hitl      : execute_bank_transfer → 202 → HMAC-approved → EXECUTED
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import fakeredis.aioredis
import httpx
import pytest

from agentguard.hitl.approval_api import sign_decision

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
async def gateway_fixture(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_UPSTREAM_URL", "http://upstream.local")
    monkeypatch.setenv("AGENTGUARD_REDIS_URL", "redis://unused/0")
    monkeypatch.setenv("AGENTGUARD_HITL_HMAC_SECRET", "secret")
    monkeypatch.setenv("AGENTGUARD_POLICIES_PATH", str(REPO_ROOT / "configs" / "policies.yaml"))
    monkeypatch.setenv("AGENTGUARD_DLP_RULES_PATH", str(REPO_ROOT / "configs" / "dlp_rules.yaml"))
    monkeypatch.setenv("AGENTGUARD_POSTGRES_DSN", f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")

    from agentguard.main import create_app
    from agentguard.settings import get_settings, reset_settings_for_tests

    reset_settings_for_tests()
    settings = get_settings()
    app = create_app(settings)

    counter: Counter[str] = Counter()

    def _upstream(request: httpx.Request) -> httpx.Response:
        body_bytes = request.content
        try:
            body = json.loads(body_bytes) if body_bytes else {}
        except json.JSONDecodeError:
            body = {"raw": body_bytes.decode("utf-8", "replace")}
        tool = body.get("tool", {}).get("name") if isinstance(body, dict) else None
        counter[tool or request.url.path] += 1
        return httpx.Response(
            200,
            json={"ok": True, "tool": tool, "invocation_count": counter[tool or request.url.path], "received": body},
        )

    upstream_transport = httpx.MockTransport(_upstream)

    async with app.router.lifespan_context(app):
        fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
        app.state.redis_store._client = fake  # type: ignore[attr-defined]
        await app.state.http_client.aclose()
        app.state.http_client = httpx.AsyncClient(transport=upstream_transport)
        app.state.gateway.http = app.state.http_client
        app.state.gateway.hitl.http = app.state.http_client

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            yield app, client, counter


@pytest.mark.asyncio
async def test_demo_retry_storm_only_one_backend_call(gateway_fixture):
    _, client, counter = gateway_fixture

    headers = {
        "Idempotency-Key": "retry-demo-1",
        "X-Session-Id": "sess-retry",
        "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjaS1ib3QifQ.sig",
    }
    body = {"tool": {"name": "create_ticket"}, "arguments": {"title": "x"}}

    results = []
    for _ in range(5):
        r = await client.post("/tools/create_ticket", headers=headers, json=body)
        results.append(r)

    assert all(r.status_code == 200 for r in results)
    # First request reaches the backend; subsequent replays carry the header.
    replays = sum(1 for r in results if r.headers.get("x-agentguard-replay") == "true")
    assert replays == 4
    assert counter["create_ticket"] == 1


@pytest.mark.asyncio
async def test_demo_injection_repo_lock_and_dlp(gateway_fixture):
    _, client, _ = gateway_fixture

    base_headers = {
        "X-Session-Id": "sess-inject",
        "X-Session-Initial-Repository": "myorg/my-repo",
        "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjaS1ib3QifQ.sig",
    }

    legit = await client.post(
        "/tools/read_issue",
        headers=base_headers,
        json={"tool": {"name": "read_issue"}, "repository": "myorg/my-repo", "number": 1},
    )
    assert legit.status_code == 200

    hijacked = await client.post(
        "/tools/read_issue",
        headers=base_headers,
        json={"tool": {"name": "read_issue"}, "repository": "victim/private", "number": 1},
    )
    assert hijacked.status_code == 403
    assert hijacked.json()["rule"] == "repo-lock"

    dlp = await client.post(
        "/tools/send_message",
        headers=base_headers,
        json={
            "tool": {"name": "send_message"},
            "channel": "#exfil",
            "message": "AKIA0123456789ABCDEF",
        },
    )
    assert dlp.status_code == 200
    received = dlp.json()["received"]
    assert "AKIA0123456789ABCDEF" not in received["message"]
    assert "AKIA****REDACTED" in received["message"]


@pytest.mark.asyncio
async def test_demo_hitl_suspend_and_execute(gateway_fixture):
    _, client, counter = gateway_fixture

    headers = {
        "Idempotency-Key": "hitl-demo-1",
        "X-Session-Id": "sess-hitl",
    }
    body = {"tool": {"name": "execute_bank_transfer"}, "arguments": {"amount": 10}}
    r = await client.post("/tools/execute_bank_transfer", headers=headers, json=body)
    assert r.status_code == 202
    ticket_id = r.json()["ticket_id"]
    # Before approval the backend has NOT been called.
    assert counter["execute_bank_transfer"] == 0

    signature = sign_decision("secret", ticket_id, "cfo@corp", "approve")
    approve = await client.post(
        "/agentguard/hitl/approve",
        json={"ticket_id": ticket_id, "approver": "cfo@corp", "signature": signature},
    )
    assert approve.status_code == 200
    assert approve.json()["status"] == "EXECUTED"
    # After approval the backend has been called exactly once.
    assert counter["execute_bank_transfer"] == 1
