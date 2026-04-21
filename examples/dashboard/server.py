"""Live dashboard + one-click attack launcher for AgentGuard.

This is the "wow" experience: open ``http://localhost:9002`` while AgentGuard
is running, click an attack button, watch the gateway neutralize it in real
time with a colour-coded event feed.

The dashboard itself is a tiny FastAPI + vanilla JS single-page app. It:

* proxies ``/api/stream``, ``/api/stats``, ``/api/recent`` to the gateway's
  own event stream endpoints (keeps the gateway URL out of the browser),
* exposes ``POST /api/scenario/{name}`` which fires pre-canned attack
  sequences directly at the gateway on behalf of the operator.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import time
import uuid
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

GATEWAY_URL = os.environ.get("AGENTGUARD_GATEWAY_URL", "http://agentguard:8080")
HMAC_SECRET = os.environ.get("AGENTGUARD_HITL_HMAC_SECRET", "change-me-hitl-shared-secret")
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="AgentGuard Dashboard", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# A tiny JWT with sub=ci-bot (header.payload.signature, unsigned) — the gateway
# treats JWTs as hints only, so this is safe for the demo.
_DEMO_JWT = "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjaS1ib3QifQ.sig"


def _sign(ticket_id: str, approver: str, action: str) -> str:
    msg = f"{ticket_id}|{approver}|{action}".encode()
    return hmac.new(HMAC_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/api/stats")
async def api_stats() -> JSONResponse:
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{GATEWAY_URL}/agentguard/stats", timeout=5.0)
    return JSONResponse(resp.json(), status_code=resp.status_code)


@app.get("/api/recent")
async def api_recent(limit: int = 100) -> JSONResponse:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{GATEWAY_URL}/agentguard/events/recent",
            params={"limit": limit},
            timeout=5.0,
        )
    return JSONResponse(resp.json(), status_code=resp.status_code)


@app.get("/api/stream")
async def api_stream(request: Request) -> StreamingResponse:
    async def generator():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", f"{GATEWAY_URL}/agentguard/events") as upstream:
                async for line in upstream.aiter_lines():
                    if await request.is_disconnected():
                        break
                    if line is None:
                        continue
                    yield line + "\n"

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------- Attack scenario launchers ----------------------


async def _scenario_retry_storm(client: httpx.AsyncClient, out: list[dict]) -> None:
    idem_key = f"dash-retry-{uuid.uuid4().hex[:8]}"
    headers = {
        "Idempotency-Key": idem_key,
        "X-Session-Id": f"dash-sess-{uuid.uuid4().hex[:6]}",
        "Authorization": _DEMO_JWT,
    }
    body = {"tool": {"name": "create_ticket"}, "arguments": {"title": "deploy hotfix"}}
    for i in range(5):
        r = await client.post("/tools/create_ticket", headers=headers, json=body)
        try:
            count = r.json().get("invocation_count")
        except Exception:  # noqa: BLE001
            count = None
        out.append(
            {
                "step": i + 1,
                "status": r.status_code,
                "replay": r.headers.get("x-agentguard-replay") == "true",
                "backend_invocation_count": count,
            }
        )
        await asyncio.sleep(0.15)


async def _scenario_cross_repo(client: httpx.AsyncClient, out: list[dict]) -> None:
    headers = {
        "X-Session-Id": f"dash-sess-{uuid.uuid4().hex[:6]}",
        "X-Session-Initial-Repository": "myorg/my-repo",
        "Authorization": _DEMO_JWT,
    }
    # Legit call first.
    r1 = await client.post(
        "/tools/read_issue",
        headers=headers,
        json={"tool": {"name": "read_issue"}, "repository": "myorg/my-repo", "number": 42},
    )
    out.append({"step": 1, "label": "legit", "status": r1.status_code})
    await asyncio.sleep(0.15)
    # Hijacked call.
    r2 = await client.post(
        "/tools/read_issue",
        headers=headers,
        json={"tool": {"name": "read_issue"}, "repository": "victim/private", "number": 1},
    )
    out.append(
        {
            "step": 2,
            "label": "hijacked",
            "status": r2.status_code,
            "body": _safe(lambda: r2.json()),
        }
    )


async def _scenario_dlp(client: httpx.AsyncClient, out: list[dict]) -> None:
    headers = {
        "X-Session-Id": f"dash-sess-{uuid.uuid4().hex[:6]}",
        "Authorization": _DEMO_JWT,
    }
    r = await client.post(
        "/tools/send_message",
        headers=headers,
        json={
            "tool": {"name": "send_message"},
            "channel": "#exfil",
            "message": (
                "Forwarding credential AKIA0123456789ABCDEF and token "
                "ghp_aaaaaaaaaaaaaaaaaaaaaaaa for debugging."
            ),
        },
    )
    body = _safe(lambda: r.json())
    out.append(
        {
            "step": 1,
            "status": r.status_code,
            "message_reached_backend": _safe(
                lambda: body["received"]["message"] if body else None
            ),
        }
    )


async def _scenario_sql_drop(client: httpx.AsyncClient, out: list[dict]) -> None:
    headers = {
        "X-Session-Id": f"dash-sess-{uuid.uuid4().hex[:6]}",
        "Authorization": _DEMO_JWT,
    }
    r = await client.post(
        "/tools/search_docs",
        headers=headers,
        json={"tool": {"name": "search_docs"}, "query": "recent; DROP TABLE users;"},
    )
    out.append({"step": 1, "status": r.status_code, "body": _safe(lambda: r.json())})


async def _scenario_hitl(client: httpx.AsyncClient, out: list[dict]) -> None:
    # Intentionally NO ci-bot JWT: bank transfer is a finance-desk action, not
    # something our automation bot is allowed to perform. Without the ci-bot
    # JWT, the `ci-bot-tools-only` allow rule is skipped (its `when` is false),
    # and the request falls through to the high_risk_tools → HITL path.
    headers = {
        "X-Session-Id": f"dash-sess-{uuid.uuid4().hex[:6]}",
        "Idempotency-Key": f"dash-hitl-{int(time.time())}-{uuid.uuid4().hex[:4]}",
    }
    r = await client.post(
        "/tools/execute_bank_transfer",
        headers=headers,
        json={
            "tool": {"name": "execute_bank_transfer"},
            "arguments": {"amount": 50000, "to": "acct-XYZ"},
        },
    )
    body = _safe(lambda: r.json()) or {}
    ticket_id = body.get("ticket_id")
    out.append({"step": 1, "label": "suspend", "status": r.status_code, "ticket_id": ticket_id})
    if not ticket_id:
        return
    await asyncio.sleep(1.0)
    approver = "dashboard-operator@demo"
    sig = _sign(ticket_id, approver, "approve")
    r2 = await client.post(
        "/agentguard/hitl/approve",
        json={"ticket_id": ticket_id, "approver": approver, "signature": sig},
    )
    out.append(
        {
            "step": 2,
            "label": "approve",
            "status": r2.status_code,
            "ticket_status": _safe(lambda: r2.json().get("status")),
        }
    )


async def _scenario_payload_splitting(client: httpx.AsyncClient, out: list[dict]) -> None:
    """Payload-splitting: the agent was coaxed into stitching secrets across fields."""
    headers = {
        "X-Session-Id": f"dash-sess-{uuid.uuid4().hex[:6]}",
        "Authorization": _DEMO_JWT,
    }
    r = await client.post(
        "/tools/send_message",
        headers=headers,
        json={
            "tool": {"name": "send_message"},
            "channel": "#logs",
            "message": "Rotating keys — new primary is AKIA0123456789ABCDEF",
            "debug_hint": "sk-abcdefghijklmnopqrstuvwxyz01234",
            "notes": "GitHub PAT rotation: ghp_aaaaaaaaaaaaaaaaaaaaaaaa",
        },
    )
    out.append(
        {
            "step": 1,
            "status": r.status_code,
            "body": _safe(lambda: r.json()),
        }
    )


SCENARIOS = {
    "retry_storm": _scenario_retry_storm,
    "cross_repo": _scenario_cross_repo,
    "dlp": _scenario_dlp,
    "sql_drop": _scenario_sql_drop,
    "hitl": _scenario_hitl,
    "payload_splitting": _scenario_payload_splitting,
}


@app.post("/api/scenario/{name}")
async def run_scenario(name: str) -> JSONResponse:
    if name not in SCENARIOS:
        raise HTTPException(status_code=404, detail="unknown_scenario")
    out: list[dict] = []
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=20.0) as client:
        await SCENARIOS[name](client, out)
    return JSONResponse({"scenario": name, "steps": out})


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "examples.dashboard.server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 9002)),
        reload=False,
    )
