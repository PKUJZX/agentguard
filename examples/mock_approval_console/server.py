"""Mock HITL approval console.

A tiny web app that:
* receives webhook notifications from AgentGuard,
* lists pending tickets by calling the gateway's ``/agentguard/hitl/pending``
  endpoint,
* lets the approver click "Approve" or "Reject", which signs the decision with
  the shared HMAC secret and POSTs it back to AgentGuard.

This is NOT a production identity provider — it models the out-of-band OAuth
2.0 CIBA callback that production deployments should integrate against.
"""

from __future__ import annotations

import hashlib
import hmac
import os

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

GATEWAY_URL = os.environ.get("AGENTGUARD_GATEWAY_URL", "http://agentguard:8080")
HMAC_SECRET = os.environ.get("AGENTGUARD_HITL_HMAC_SECRET", "change-me-hitl-shared-secret")

app = FastAPI(title="AgentGuard Approval Console", version="0.1.0")
_recent_webhooks: list[dict] = []


def _sign(ticket_id: str, approver: str, action: str) -> str:
    message = f"{ticket_id}|{approver}|{action}".encode()
    return hmac.new(HMAC_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/inbox")
async def inbox(request: Request) -> JSONResponse:
    """Endpoint AgentGuard posts to when a ticket is created."""
    payload = await request.json()
    _recent_webhooks.insert(0, payload)
    del _recent_webhooks[50:]
    return JSONResponse({"received": True})


@app.get("/api/pending")
async def api_pending() -> JSONResponse:
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{GATEWAY_URL}/agentguard/hitl/pending", timeout=5.0)
    return JSONResponse(resp.json(), status_code=resp.status_code)


@app.post("/api/decide")
async def api_decide(request: Request) -> JSONResponse:
    payload = await request.json()
    action = payload.get("action")
    ticket_id = payload.get("ticket_id")
    approver = payload.get("approver") or "operator@example.com"
    if action not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="invalid_action")
    signature = _sign(ticket_id, approver, action)
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{GATEWAY_URL}/agentguard/hitl/{action}",
            json={"ticket_id": ticket_id, "approver": approver, "signature": signature},
            timeout=10.0,
        )
    return JSONResponse(resp.json(), status_code=resp.status_code)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(_INDEX_HTML)


_INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>AgentGuard Approval Console</title>
  <style>
    body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; color: #222; }
    h1 { font-size: 20px; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { padding: 8px; border: 1px solid #ddd; text-align: left; font-size: 13px; vertical-align: top; }
    th { background: #f6f6f6; }
    code { background: #f0f0f0; padding: 2px 4px; border-radius: 3px; }
    .findings { color: #a00; font-size: 12px; }
    button { padding: 4px 10px; margin-right: 4px; cursor: pointer; }
    .approve { background: #e8f5e9; }
    .reject  { background: #ffebee; }
    input { padding: 4px 8px; }
  </style>
</head>
<body>
  <h1>AgentGuard — Pending High-Risk Requests</h1>
  <p>Approver: <input id="approver" value="operator@example.com" size="30"/> <button onclick="refresh()">Refresh</button></p>
  <table>
    <thead>
      <tr><th>Ticket</th><th>Tool</th><th>Created</th><th>DLP Findings</th><th>Actions</th></tr>
    </thead>
    <tbody id="rows"><tr><td colspan="5">Loading...</td></tr></tbody>
  </table>
  <script>
    async function refresh() {
      const r = await fetch('/api/pending');
      const data = await r.json();
      const rows = document.getElementById('rows');
      if (!data.tickets || data.tickets.length === 0) {
        rows.innerHTML = '<tr><td colspan="5">No pending tickets.</td></tr>';
        return;
      }
      rows.innerHTML = data.tickets.map(t => `
        <tr>
          <td><code>${t.ticket_id}</code></td>
          <td>${t.tool_name || ''}</td>
          <td>${t.created_at || ''}</td>
          <td class="findings">${(t.sanitized_findings || []).map(f => f.rule + '×' + f.count).join(', ')}</td>
          <td>
            <button class="approve" onclick="decide('approve', '${t.ticket_id}')">Approve</button>
            <button class="reject"  onclick="decide('reject',  '${t.ticket_id}')">Reject</button>
          </td>
        </tr>`).join('');
    }
    async function decide(action, ticket_id) {
      const approver = document.getElementById('approver').value;
      const r = await fetch('/api/decide', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action, ticket_id, approver}),
      });
      const data = await r.json();
      alert(action + ': ' + JSON.stringify(data, null, 2));
      refresh();
    }
    refresh();
    setInterval(refresh, 5000);
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "examples.mock_approval_console.server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 9001)),
        reload=False,
    )
