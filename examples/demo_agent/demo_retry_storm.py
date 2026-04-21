"""Scenario: hallucinated retry storm against a non-idempotent tool.

An LLM mis-interpreted a timed-out response and retried five times. Without
AgentGuard this would create five tickets; with the gateway only the first
request reaches the backend.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _shared import (  # noqa: E402
    DEMO_JWT,
    backend_stats,
    client,
    console,
    fail_panel,
    pass_panel,
    request_table,
    scenario_banner,
)


def main() -> int:
    scenario_banner(
        1,
        "Retry storm breaks on the idempotency lock",
        attack="Agent fires 5 identical `create_ticket` POSTs (simulated LLM retry loop).",
        defense="Redis SETNX holds the ticket; AgentGuard replays the cached response.",
    )
    idem_key = f"demo-retry-{uuid.uuid4().hex[:8]}"
    headers = {
        "Idempotency-Key": idem_key,
        "X-Session-Id": "demo-retry-sess",
        "Authorization": DEMO_JWT,
    }
    body = {
        "tool": {"name": "create_ticket"},
        "arguments": {"title": "deploy hotfix", "priority": "high"},
    }

    before = backend_stats()["invocations"].get("create_ticket", 0)
    rows: list[dict] = []
    with client() as http:
        for i in range(5):
            r = http.post("/tools/create_ticket", headers=headers, json=body)
            replay = r.headers.get("x-agentguard-replay") == "true"
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            rows.append(
                {
                    "Attempt": i + 1,
                    "Status": r.status_code,
                    "verdict": "REPLAYED" if replay else "ALLOWED",
                    "Backend counter": data.get("invocation_count", "—"),
                }
            )

    request_table(
        "5× create_ticket through AgentGuard",
        rows,
        ["Attempt", "Status", "verdict", "Backend counter"],
    )
    after = backend_stats()["invocations"].get("create_ticket", 0)
    delta = after - before
    console.print(f"Backend invocation counter: [bold]{before} → {after}[/] (delta [bold]{delta}[/])")

    if delta == 1:
        pass_panel("Only 1 of 5 identical retries actually hit the backend.")
        return 0
    fail_panel(f"Expected delta=1 but saw {delta}.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
