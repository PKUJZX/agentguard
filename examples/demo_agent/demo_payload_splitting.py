"""Scenario: payload-splitting exfiltration across multiple JSON fields.

A sophisticated prompt injection asks the agent to split a secret across
multiple fields (message / debug_hint / notes) in hopes of evading naïve
single-field DLP. AgentGuard's sanitizer walks every string in the request
body and applies regex masks uniformly.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _shared import (  # noqa: E402
    DEMO_JWT,
    client,
    fail_panel,
    pass_panel,
    request_table,
    scenario_banner,
)

SECRETS = [
    "AKIA0123456789ABCDEF",
    "ghp_aaaaaaaaaaaaaaaaaaaaaaaa",
    "sk-aaaaaaaaaaaaaaaaaaaaaaaa",
]


def main() -> int:
    scenario_banner(
        6,
        "DLP walks every field — payload splitting doesn't help",
        attack="Agent splits 3 secrets across 3 different JSON fields hoping to evade DLP.",
        defense="Sanitizer recursively rewrites every matched regex in the whole payload tree.",
    )

    headers = {"X-Session-Id": "demo-split-sess", "Authorization": DEMO_JWT}
    with client() as http:
        r = http.post(
            "/tools/send_message",
            headers=headers,
            json={
                "tool": {"name": "send_message"},
                "channel": "#logs",
                "message":     f"Rotation in progress — primary {SECRETS[0]}",
                "debug_hint":  f"fallback OAI key {SECRETS[2]}",
                "notes":       f"old GH PAT for rollback: {SECRETS[1]}",
            },
        )
    body = r.json()
    backend_received = body["received"]

    rows = []
    for field, val in backend_received.items():
        if field == "tool":
            continue
        leaked_secrets = [s for s in SECRETS if s in str(val)]
        rows.append(
            {
                "Field": field,
                "Backend value": (str(val)[:60] + "…") if len(str(val)) > 60 else str(val),
                "Leaked": ", ".join(leaked_secrets) or "—",
            }
        )

    request_table("Per-field outcome at the backend", rows, ["Field", "Backend value", "Leaked"])

    any_leak = any(row["Leaked"] != "—" for row in rows)
    if not any_leak:
        pass_panel("All 3 secrets masked across all 3 fields.")
        return 0
    fail_panel("A secret leaked through a field — tune DLP rules.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
