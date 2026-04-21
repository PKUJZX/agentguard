"""Outbound webhook posted when a HITL ticket is created.

The payload is intentionally minimal — it never contains the raw request body,
only the sanitized metadata. Full details are fetched from the registry via
the approval console's UI.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


async def post_webhook(
    http_client: httpx.AsyncClient,
    webhook_url: str | None,
    ticket_id: str,
    tool_name: str | None,
    sanitized_findings: list[dict[str, Any]],
    created_at: str,
) -> None:
    if not webhook_url:
        return
    payload = {
        "event": "hitl.ticket.created",
        "ticket_id": ticket_id,
        "tool_name": tool_name,
        "sanitized_findings": sanitized_findings,
        "created_at": created_at,
    }
    try:
        await http_client.post(webhook_url, json=payload, timeout=5.0)
    except httpx.HTTPError as exc:
        # Webhook delivery failures must not break the request path; a retry
        # worker (not implemented in MVP) would handle this in production.
        logger.warning("hitl.webhook_error url=%s error=%s", webhook_url, exc)
