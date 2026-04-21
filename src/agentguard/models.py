"""Core data models shared across the gateway middleware chain."""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any


class TicketStatus(str, enum.Enum):
    """Lifecycle of a HITL-intercepted request."""

    PENDING = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


@dataclass
class ProxyResponse:
    """A response that any middleware may return to short-circuit the chain."""

    status_code: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    media_type: str = "application/json"

    @classmethod
    def json(cls, status_code: int, payload: dict[str, Any]) -> ProxyResponse:
        return cls(
            status_code=status_code,
            body=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
            media_type="application/json",
        )


@dataclass
class RequestContext:
    """Normalized view of an inbound request propagated through the chain."""

    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body_bytes: bytes
    body_json: Any | None

    jwt_claims: dict[str, Any]
    session: dict[str, Any]
    mcp: dict[str, Any]
    idempotency_key: str | None
    tool_name: str | None

    # Filled in after the sanitizer runs.
    sanitized_body_bytes: bytes | None = None
    sanitized_body_json: Any | None = None
    sanitized_findings: list[dict[str, Any]] = field(default_factory=list)

    def effective_body_bytes(self) -> bytes:
        """Return sanitized payload if present, otherwise the original."""
        return self.sanitized_body_bytes if self.sanitized_body_bytes is not None else self.body_bytes

    def effective_body_json(self) -> Any | None:
        if self.sanitized_body_json is not None:
            return self.sanitized_body_json
        return self.body_json

    def cel_activation(self) -> dict[str, Any]:
        """Build the variable bindings passed to the CEL evaluator."""
        return {
            "jwt": self.jwt_claims,
            "session": self.session,
            "mcp": self.mcp,
            "request": {
                "method": self.method,
                "path": self.path,
                "headers": self.headers,
                "body": self.effective_body_json() if self.effective_body_json() is not None else {},
            },
        }
