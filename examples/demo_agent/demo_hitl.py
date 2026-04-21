"""Scenario: high-risk tool call is suspended until a human approves."""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _shared import (  # noqa: E402
    GATEWAY_URL,
    client,
    console,
    fail_panel,
    pass_panel,
    scenario_banner,
)

APPROVAL_CONSOLE_URL = os.environ.get("APPROVAL_CONSOLE_URL", "http://localhost:9001")
AUTO_APPROVE = os.environ.get("AUTO_APPROVE", "1") == "1"
HMAC_SECRET = os.environ.get("AGENTGUARD_HITL_HMAC_SECRET", "change-me-hitl-shared-secret")


def _sign(ticket_id: str, approver: str, action: str) -> str:
    msg = f"{ticket_id}|{approver}|{action}".encode()
    return hmac.new(HMAC_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def main() -> int:
    scenario_banner(
        4,
        "Async HITL intercepts a high-risk tool call",
        attack="Agent attempts `execute_bank_transfer` for $50,000.",
        defense="Gateway suspends with HTTP 202 + ticket; human must approve via HMAC-signed callback.",
    )

    # No ci-bot JWT here — bank transfer is a finance-desk request, so the
    # `ci-bot-tools-only` allow rule is intentionally skipped and the request
    # falls through to the high_risk_tools (HITL) path.
    headers = {
        "X-Session-Id": "demo-hitl-sess",
        "Idempotency-Key": f"demo-hitl-{int(time.time())}",
    }
    body = {
        "tool": {"name": "execute_bank_transfer"},
        "arguments": {"amount": 50_000, "to_account": "acct-XYZ"},
    }

    with client() as http:
        r = http.post("/tools/execute_bank_transfer", headers=headers, json=body)
    if r.status_code != 202:
        fail_panel(f"Expected 202 Accepted but got {r.status_code}.")
        return 1

    ticket = r.json()
    ticket_id = ticket["ticket_id"]
    console.print(f"[magenta]Gateway suspended[/] — ticket [bold]{ticket_id}[/]")
    console.print(f"Poll URL: {ticket['poll_url']}")
    console.print(f"Approval console: {APPROVAL_CONSOLE_URL}\n")

    if AUTO_APPROVE:
        console.print("[cyan]AUTO_APPROVE=1 — simulating approver signing off…[/]")
        approver = "ci-demo-approver@example.com"
        sig = _sign(ticket_id, approver, "approve")
        resp = httpx.post(
            f"{GATEWAY_URL}/agentguard/hitl/approve",
            json={"ticket_id": ticket_id, "approver": approver, "signature": sig},
            timeout=10.0,
        )
        final = resp.json()
        console.print(f"Final ticket status: [bold green]{final.get('status')}[/]")
        if final.get("status") == "EXECUTED":
            pass_panel("Bank transfer executed only after the human co-signed.")
            return 0
        fail_panel("Ticket did not reach EXECUTED state.")
        return 1

    console.print("[yellow]Open the approval console and click Approve.[/]")
    while True:
        resp = httpx.get(f"{GATEWAY_URL}/agentguard/hitl/status/{ticket_id}", timeout=5.0).json()
        console.print(f"  status={resp.get('status')}")
        if resp.get("status") in {"EXECUTED", "REJECTED", "FAILED"}:
            break
        time.sleep(3)
    if resp.get("status") == "EXECUTED":
        pass_panel("Human approved; gateway executed the transfer.")
        return 0
    fail_panel(f"Ticket resolved as {resp.get('status')}.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
