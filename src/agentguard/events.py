"""In-process event bus used by the gateway to surface its decisions.

Every middleware that makes an interesting decision publishes a ``GatewayEvent``
to the bus. The bus keeps a rolling ring buffer for late subscribers (e.g. the
dashboard after a page refresh) and fans out new events to all live subscribers
over ``asyncio.Queue`` for real-time SSE streaming.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
import uuid
from collections import deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class Verdict(str, enum.Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    REPLAYED = "REPLAYED"
    SANITIZED = "SANITIZED"
    SUSPENDED_HITL = "SUSPENDED_HITL"
    APPROVED_HITL = "APPROVED_HITL"
    REJECTED_HITL = "REJECTED_HITL"
    EXECUTED_HITL = "EXECUTED_HITL"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"


@dataclass
class GatewayEvent:
    id: str
    ts: str
    verdict: str
    method: str
    path: str
    tool_name: str | None
    session_id: str | None
    rule: str | None = None
    reason: str | None = None
    sanitized_findings: list[dict[str, Any]] = field(default_factory=list)
    ticket_id: str | None = None
    upstream_status: int | None = None
    latency_ms: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def new_event(
    *,
    verdict: Verdict | str,
    method: str,
    path: str,
    tool_name: str | None,
    session_id: str | None,
    rule: str | None = None,
    reason: str | None = None,
    sanitized_findings: list[dict[str, Any]] | None = None,
    ticket_id: str | None = None,
    upstream_status: int | None = None,
    latency_ms: float | None = None,
    extra: dict[str, Any] | None = None,
) -> GatewayEvent:
    return GatewayEvent(
        id=uuid.uuid4().hex,
        ts=datetime.now(timezone.utc).isoformat(),
        verdict=verdict.value if isinstance(verdict, Verdict) else str(verdict),
        method=method,
        path=path,
        tool_name=tool_name,
        session_id=session_id,
        rule=rule,
        reason=reason,
        sanitized_findings=sanitized_findings or [],
        ticket_id=ticket_id,
        upstream_status=upstream_status,
        latency_ms=latency_ms,
        extra=extra or {},
    )


class EventBus:
    """Ring buffer + async subscriber fan-out."""

    def __init__(self, buffer_size: int = 500) -> None:
        self._buffer: deque[GatewayEvent] = deque(maxlen=buffer_size)
        self._subscribers: set[asyncio.Queue[GatewayEvent]] = set()
        self._lock = asyncio.Lock()
        self._stats: dict[str, int] = {}

    def publish(self, event: GatewayEvent) -> None:
        self._buffer.append(event)
        self._stats[event.verdict] = self._stats.get(event.verdict, 0) + 1
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Drop events for slow subscribers rather than block the hot path.
                logger.debug("event_bus.subscriber_full dropping event=%s", event.id)

    def recent(self, limit: int = 100) -> list[GatewayEvent]:
        events = list(self._buffer)
        return events[-limit:]

    def stats(self) -> dict[str, Any]:
        total = sum(self._stats.values())
        by_verdict = dict(self._stats)
        return {
            "total": total,
            "by_verdict": by_verdict,
            "buffered": len(self._buffer),
        }

    async def subscribe(self) -> asyncio.Queue[GatewayEvent]:
        q: asyncio.Queue[GatewayEvent] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[GatewayEvent]) -> None:
        async with self._lock:
            self._subscribers.discard(q)


def monotonic_ms() -> float:
    """Helper: elapsed ms from a reference start (caller subtracts manually)."""
    return time.monotonic() * 1000


# ------------------ iter helpers (used by /events SSE) ------------------


def format_sse(events: Iterable[GatewayEvent]) -> str:
    import json

    chunks = []
    for ev in events:
        chunks.append(f"data: {json.dumps(ev.to_dict())}\n\n")
    return "".join(chunks)
