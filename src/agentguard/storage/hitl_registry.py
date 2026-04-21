"""Persistent registry of HITL-suspended requests.

Uses SQLAlchemy async with whatever backend the DSN points at:

* ``postgresql+asyncpg://...`` — production recommendation.
* ``sqlite+aiosqlite://...``    — unit tests / dev environments.

The plan specifies PostgreSQL; we abstract over SQLAlchemy so local tests do
not require a running Postgres server while the production deployment still
gets strong durability guarantees.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Column, DateTime, Integer, String, Text, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from ..models import TicketStatus

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class PendingRequest(Base):
    __tablename__ = "agentguard_pending_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ticket_id = Column(String(64), unique=True, nullable=False, index=True)
    status = Column(String(32), nullable=False)
    tool_name = Column(String(255), nullable=True)
    idempotency_key = Column(String(128), nullable=True)
    request_method = Column(String(16), nullable=False)
    request_path = Column(String(1024), nullable=False)
    request_query = Column(String(2048), nullable=False, default="")
    request_headers = Column(JSON, nullable=False, default=dict)
    request_body_b64 = Column(Text, nullable=False, default="")
    sanitized_findings = Column(JSON, nullable=False, default=list)
    jwt_claims = Column(JSON, nullable=False, default=dict)
    session = Column(JSON, nullable=False, default=dict)
    mcp = Column(JSON, nullable=False, default=dict)

    # Approval / execution state.
    approver = Column(String(255), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    response_status = Column(Integer, nullable=True)
    response_body_b64 = Column(Text, nullable=True)
    response_headers = Column(JSON, nullable=True)
    response_media_type = Column(String(255), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


@dataclass
class TicketView:
    """A DTO returned by read methods — avoids leaking ORM objects."""

    ticket_id: str
    status: str
    tool_name: str | None
    created_at: datetime
    updated_at: datetime
    approver: str | None
    response_status: int | None
    response_body_b64: str | None
    response_headers: dict | None
    response_media_type: str | None
    sanitized_findings: list
    idempotency_key: str | None


class HITLRegistry:
    def __init__(self, dsn: str) -> None:
        # Normalize common Postgres URL forms.
        if dsn.startswith("postgres://"):
            dsn = dsn.replace("postgres://", "postgresql+asyncpg://", 1)
        elif dsn.startswith("postgresql://"):
            dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
        self.dsn = dsn
        self._engine = create_async_engine(dsn, future=True)
        self._session = async_sessionmaker(self._engine, expire_on_commit=False)

    @classmethod
    def from_dsn(cls, dsn: str) -> HITLRegistry:
        return cls(dsn)

    async def initialize(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    async def create(
        self,
        *,
        tool_name: str | None,
        idempotency_key: str | None,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body_bytes: bytes,
        jwt_claims: dict[str, Any],
        session: dict[str, Any],
        mcp: dict[str, Any],
        sanitized_findings: list[dict[str, Any]],
    ) -> str:
        import base64

        ticket_id = secrets.token_urlsafe(16)
        async with self._session() as s:
            s.add(
                PendingRequest(
                    ticket_id=ticket_id,
                    status=TicketStatus.PENDING.value,
                    tool_name=tool_name,
                    idempotency_key=idempotency_key,
                    request_method=method,
                    request_path=path,
                    request_query=query or "",
                    request_headers=_sanitize_headers(headers),
                    request_body_b64=base64.b64encode(body_bytes).decode("ascii"),
                    sanitized_findings=sanitized_findings,
                    jwt_claims=jwt_claims,
                    session=session,
                    mcp=mcp,
                )
            )
            await s.commit()
        logger.info("hitl.create ticket=%s tool=%s", ticket_id, tool_name)
        return ticket_id

    async def get(self, ticket_id: str) -> TicketView | None:
        async with self._session() as s:
            row = await _fetch(s, ticket_id)
            if row is None:
                return None
            return _to_view(row)

    async def mark_approved(self, ticket_id: str, approver: str) -> TicketView | None:
        async with self._session() as s:
            row = await _fetch(s, ticket_id)
            if row is None:
                return None
            if row.status != TicketStatus.PENDING.value:
                return _to_view(row)
            row.status = TicketStatus.APPROVED.value
            row.approver = approver
            row.approved_at = datetime.now(timezone.utc)
            row.updated_at = datetime.now(timezone.utc)
            await s.commit()
            await s.refresh(row)
            return _to_view(row)

    async def mark_rejected(self, ticket_id: str, approver: str) -> TicketView | None:
        async with self._session() as s:
            row = await _fetch(s, ticket_id)
            if row is None:
                return None
            row.status = TicketStatus.REJECTED.value
            row.approver = approver
            row.approved_at = datetime.now(timezone.utc)
            row.updated_at = datetime.now(timezone.utc)
            await s.commit()
            await s.refresh(row)
            return _to_view(row)

    async def mark_executed(
        self,
        ticket_id: str,
        status_code: int,
        body: bytes,
        headers: dict[str, str],
        media_type: str,
    ) -> TicketView | None:
        import base64

        async with self._session() as s:
            row = await _fetch(s, ticket_id)
            if row is None:
                return None
            row.status = TicketStatus.EXECUTED.value
            row.response_status = status_code
            row.response_body_b64 = base64.b64encode(body).decode("ascii")
            row.response_headers = headers
            row.response_media_type = media_type
            row.updated_at = datetime.now(timezone.utc)
            await s.commit()
            await s.refresh(row)
            return _to_view(row)

    async def list_pending(self, limit: int = 50) -> list[TicketView]:
        async with self._session() as s:
            stmt = (
                select(PendingRequest)
                .where(PendingRequest.status == TicketStatus.PENDING.value)
                .order_by(PendingRequest.created_at.desc())
                .limit(limit)
            )
            rows = (await s.execute(stmt)).scalars().all()
            return [_to_view(r) for r in rows]

    async def get_raw_request(self, ticket_id: str) -> dict | None:
        """Read back the full original request so the proxy can replay it."""
        async with self._session() as s:
            row = await _fetch(s, ticket_id)
            if row is None:
                return None
            return {
                "method": row.request_method,
                "path": row.request_path,
                "query": row.request_query,
                "headers": dict(row.request_headers or {}),
                "body_b64": row.request_body_b64,
                "jwt_claims": dict(row.jwt_claims or {}),
                "session": dict(row.session or {}),
                "mcp": dict(row.mcp or {}),
                "tool_name": row.tool_name,
                "idempotency_key": row.idempotency_key,
            }


async def _fetch(session: AsyncSession, ticket_id: str) -> PendingRequest | None:
    stmt = select(PendingRequest).where(PendingRequest.ticket_id == ticket_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


def _to_view(row: PendingRequest) -> TicketView:
    return TicketView(
        ticket_id=row.ticket_id,
        status=row.status,
        tool_name=row.tool_name,
        created_at=row.created_at,
        updated_at=row.updated_at,
        approver=row.approver,
        response_status=row.response_status,
        response_body_b64=row.response_body_b64,
        response_headers=row.response_headers,
        response_media_type=row.response_media_type,
        sanitized_findings=list(row.sanitized_findings or []),
        idempotency_key=row.idempotency_key,
    )


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Strip Authorization / cookies from what we persist for audit."""
    redacted_keys = {"authorization", "cookie", "x-api-key"}
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in redacted_keys:
            out[k] = "***redacted***"
        else:
            out[k] = v
    return out


# Avoid unused-import warnings in static analyzers (update is imported for
# future use by callers that patch rows in bulk).
_ = update
_ = json
