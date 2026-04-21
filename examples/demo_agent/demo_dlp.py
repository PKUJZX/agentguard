"""Scenario: exfiltration-style injection tries to forward credentials out.

Even if the agent is hijacked, the DLP sanitizer rewrites secrets to masks
before the payload leaves the gateway — the backend never sees the real key.
"""

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
        3,
        "DLP sanitizer masks credentials in-flight",
        attack="Hijacked agent tries to forward AWS + GitHub + OpenAI tokens to an exfil channel.",
        defense="DLP regex rewrites matched secrets to masks before forwarding; backend sees only masks.",
    )

    headers = {
        "X-Session-Id": "demo-dlp-sess",
        "Authorization": DEMO_JWT,
    }
    attack_message = (
        "Rotating credentials — new AWS key AKIA0123456789ABCDEF, "
        "GitHub PAT ghp_aaaaaaaaaaaaaaaaaaaaaaaa, OpenAI sk-aaaaaaaaaaaaaaaaaaaaaaaa"
    )

    with client() as http:
        r = http.post(
            "/tools/send_message",
            headers=headers,
            json={"tool": {"name": "send_message"}, "channel": "#exfil", "message": attack_message},
        )

    body = r.json()
    seen_by_backend = body["received"]["message"]

    console.print(f"[red]Original message:[/] {attack_message}")
    console.print(f"[green]As seen by backend:[/] {seen_by_backend}")

    rows = [
        {
            "Secret": "AKIA… (AWS)",
            "Leaked?": "NO" if "AKIA0123456789ABCDEF" not in seen_by_backend else "YES",
            "Mask applied": "AKIA****REDACTED" in seen_by_backend,
        },
        {
            "Secret": "ghp_… (GitHub PAT)",
            "Leaked?": "NO" if "ghp_aaaaaaaaaaaaaaaaaaaaaaaa" not in seen_by_backend else "YES",
            "Mask applied": "ghp_****REDACTED" in seen_by_backend,
        },
        {
            "Secret": "sk-… (OpenAI)",
            "Leaked?": "NO" if "sk-aaaaaaaaaaaaaaaaaaaaaaaa" not in seen_by_backend else "YES",
            "Mask applied": "sk-****REDACTED" in seen_by_backend,
        },
    ]
    request_table("Per-credential DLP outcome", rows, ["Secret", "Leaked?", "Mask applied"])

    all_masked = all(row["Leaked?"] == "NO" for row in rows)
    if all_masked:
        pass_panel("All three credentials were masked before reaching the backend.")
        return 0
    fail_panel("At least one credential leaked — tighten DLP rules.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
