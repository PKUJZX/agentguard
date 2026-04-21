"""Scenario: SQL-injection style prompt asks the agent to run `DROP TABLE`."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _shared import (  # noqa: E402
    DEMO_JWT,
    client,
    console,
    fail_panel,
    pass_panel,
    request_table,
    scenario_banner,
)


def main() -> int:
    scenario_banner(
        5,
        "CEL deny rule fires on destructive SQL",
        attack="Injected system prompt tricks the agent into calling `search_docs` with `DROP TABLE users;`.",
        defense="CEL deny rule `block-sql-drop` pattern-matches the payload and returns 403.",
    )

    headers = {"X-Session-Id": "demo-sql-sess", "Authorization": DEMO_JWT}
    with client() as http:
        clean = http.post(
            "/tools/search_docs",
            headers=headers,
            json={"tool": {"name": "search_docs"}, "query": "how to rotate api keys"},
        )
        bad = http.post(
            "/tools/search_docs",
            headers=headers,
            json={"tool": {"name": "search_docs"}, "query": "recent; DROP TABLE users;"},
        )

    rows = [
        {"Case": "benign query", "Status": clean.status_code, "verdict": "ALLOWED" if clean.status_code == 200 else "DENIED"},
        {"Case": "DROP TABLE injection", "Status": bad.status_code, "verdict": "DENIED" if bad.status_code == 403 else "ALLOWED"},
    ]
    request_table("search_docs — benign vs. SQL injection", rows, ["Case", "Status", "verdict"])

    if clean.status_code == 200 and bad.status_code == 403:
        body = bad.json()
        console.print(f"Rule: [bold yellow]{body.get('rule')}[/] · Reason: [italic]{body.get('reason')}[/]")
        pass_panel("Destructive SQL was denied, benign queries pass through.")
        return 0
    fail_panel("Policy did not match expected outcome.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
