"""Shared helpers for the rich console demos."""

from __future__ import annotations

import os
from typing import Any

import httpx

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Install demo dependencies: pip install rich httpx"
    ) from exc


GATEWAY_URL = os.environ.get("AGENTGUARD_GATEWAY_URL", "http://localhost:8080")
BACKEND_STATS_URL = os.environ.get("MOCK_BACKEND_STATS_URL", "http://localhost:9000/stats")
DEMO_JWT = "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJjaS1ib3QifQ.sig"

console = Console()


def client() -> httpx.Client:
    return httpx.Client(base_url=GATEWAY_URL, timeout=10.0)


def backend_stats() -> dict:
    try:
        return httpx.get(BACKEND_STATS_URL, timeout=2.0).json()
    except httpx.HTTPError:
        return {"invocations": {}}


VERDICT_STYLE = {
    "ALLOWED":        ("✅ ALLOWED",        "bright_green"),
    "DENIED":         ("⛔ DENIED",         "bold red"),
    "REPLAYED":       ("🔁 REPLAYED",       "bright_blue"),
    "SANITIZED":      ("🩹 SANITIZED",      "yellow"),
    "SUSPENDED_HITL": ("⏸  PENDING HITL",   "magenta"),
    "EXECUTED_HITL":  ("✅ EXECUTED",       "bright_green"),
    "REJECTED_HITL":  ("🔴 REJECTED",       "bold red"),
}


def verdict_text(verdict: str) -> Text:
    label, style = VERDICT_STYLE.get(verdict, (verdict, "white"))
    return Text(label, style=style)


def scenario_banner(index: int, title: str, attack: str, defense: str) -> None:
    console.print()
    console.rule(f"[bold cyan]Scenario {index}: {title}[/bold cyan]", style="cyan")
    console.print(
        Panel.fit(
            Text.assemble(
                ("Attack  ", "bold red"), (attack, "white"),
                ("\nDefense ", "bold green"), (defense, "white"),
            ),
            border_style="cyan",
            padding=(0, 2),
        )
    )


def pass_panel(summary: str) -> None:
    console.print(
        Panel.fit(
            Text("✓ DEFENSE HELD — " + summary, style="bold green"),
            border_style="green",
            padding=(0, 2),
        )
    )


def fail_panel(summary: str) -> None:
    console.print(
        Panel.fit(
            Text("✗ UNEXPECTED — " + summary, style="bold red"),
            border_style="red",
            padding=(0, 2),
        )
    )


def request_table(
    title: str, rows: list[dict[str, Any]], headers: list[str]
) -> None:
    table = Table(title=title, title_style="bold cyan", show_lines=False)
    for h in headers:
        table.add_column(h)
    for row in rows:
        cells = []
        for h in headers:
            val = row.get(h, "")
            if h in {"verdict", "Verdict"}:
                cells.append(verdict_text(str(val)))
            else:
                cells.append(str(val))
        table.add_row(*cells)
    console.print(table)
