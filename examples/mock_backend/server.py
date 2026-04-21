"""Mock MCP-style backend used by the examples & docker-compose.

Simulates a handful of tool endpoints so that demo scripts can observe how
AgentGuard intercepts, sanitizes and replays requests. The backend keeps a
counter of how many times each tool was actually invoked — useful for
proving that idempotency replays never reach it.
"""

from __future__ import annotations

import os
from collections import Counter

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="AgentGuard Mock Backend", version="0.1.0")
invocation_counter: Counter[str] = Counter()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/stats")
async def stats() -> dict:
    return {"invocations": dict(invocation_counter)}


async def _handle_tool(request: Request, tool: str) -> JSONResponse:
    invocation_counter[tool] += 1
    body = await request.json() if await request.body() else {}
    return JSONResponse(
        {
            "ok": True,
            "tool": tool,
            "invocation_count": invocation_counter[tool],
            "received": body,
        }
    )


@app.post("/tools/create_ticket")
async def create_ticket(request: Request) -> JSONResponse:
    return await _handle_tool(request, "create_ticket")


@app.post("/tools/search_docs")
async def search_docs(request: Request) -> JSONResponse:
    return await _handle_tool(request, "search_docs")


@app.post("/tools/read_issue")
async def read_issue(request: Request) -> JSONResponse:
    return await _handle_tool(request, "read_issue")


@app.post("/tools/send_message")
async def send_message(request: Request) -> JSONResponse:
    return await _handle_tool(request, "send_message")


@app.post("/tools/execute_bank_transfer")
async def execute_bank_transfer(request: Request) -> JSONResponse:
    return await _handle_tool(request, "execute_bank_transfer")


@app.post("/tools/drop_database")
async def drop_database(request: Request) -> JSONResponse:
    return await _handle_tool(request, "drop_database")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "examples.mock_backend.server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 9000)),
        reload=False,
    )
