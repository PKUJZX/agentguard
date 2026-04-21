"""HTTP endpoints that expose the gateway's event stream.

* ``GET /agentguard/events``         — Server-Sent Events stream (live).
* ``GET /agentguard/events/recent``  — JSON snapshot of the ring buffer (for
                                       dashboards that want to back-fill on load).
* ``GET /agentguard/stats``          — aggregate counters (for the stats bar).
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .events import EventBus

logger = logging.getLogger(__name__)


def build_events_router() -> APIRouter:
    router = APIRouter()

    @router.get("/stats")
    async def stats(request: Request) -> JSONResponse:
        bus: EventBus = request.app.state.event_bus
        return JSONResponse(bus.stats())

    @router.get("/events/recent")
    async def recent(request: Request, limit: int = 100) -> JSONResponse:
        bus: EventBus = request.app.state.event_bus
        events = [e.to_dict() for e in bus.recent(limit=limit)]
        return JSONResponse({"events": events})

    @router.get("/events")
    async def stream(request: Request) -> StreamingResponse:
        bus: EventBus = request.app.state.event_bus

        async def generator():
            queue = await bus.subscribe()
            try:
                # Replay the most recent 20 so the dashboard has immediate context.
                for ev in bus.recent(limit=20):
                    yield f"data: {json.dumps(ev.to_dict())}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        ev = await asyncio.wait_for(queue.get(), timeout=15.0)
                    except asyncio.TimeoutError:
                        # Heartbeat keeps the connection alive through proxies.
                        yield ": ping\n\n"
                        continue
                    yield f"data: {json.dumps(ev.to_dict())}\n\n"
            finally:
                await bus.unsubscribe(queue)

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    return router
