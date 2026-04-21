"""Scenario: prompt injection attempts to cross the repo-lock boundary."""

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
        2,
        "CEL repo-lock denies cross-repository access",
        attack="Prompt injection in an Issue comment asks the agent to read `victim/private`.",
        defense="CEL rule `repo-lock` enforces one-session→one-repo; the hijacked call is 403'd.",
    )

    headers = {
        "X-Session-Id": "demo-inject-sess",
        "X-Session-Initial-Repository": "myorg/my-repo",
        "Authorization": DEMO_JWT,
    }
    rows = []
    with client() as http:
        legit = http.post(
            "/tools/read_issue",
            headers=headers,
            json={"tool": {"name": "read_issue"}, "repository": "myorg/my-repo", "number": 42},
        )
        rows.append(
            {
                "Case": "legit (same repo)",
                "repository": "myorg/my-repo",
                "Status": legit.status_code,
                "verdict": "ALLOWED" if legit.status_code == 200 else "DENIED",
            }
        )
        hijacked = http.post(
            "/tools/read_issue",
            headers=headers,
            json={"tool": {"name": "read_issue"}, "repository": "victim/private", "number": 1},
        )
        rows.append(
            {
                "Case": "injection (cross repo)",
                "repository": "victim/private",
                "Status": hijacked.status_code,
                "verdict": "DENIED" if hijacked.status_code == 403 else "ALLOWED",
            }
        )

    request_table(
        "read_issue requests — legit vs. injected",
        rows,
        ["Case", "repository", "Status", "verdict"],
    )

    if legit.status_code == 200 and hijacked.status_code == 403:
        body = hijacked.json()
        console.print(
            f"Rule that fired: [bold yellow]{body.get('rule')}[/] — [italic]{body.get('reason')}[/]"
        )
        pass_panel("Session was pinned to the initial repo; cross-repo access blocked.")
        return 0

    fail_panel("Unexpected outcome.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
