"""Unit tests for CEL engine + policy middleware."""

from __future__ import annotations

import json
import textwrap

import pytest

from agentguard.cel.engine import CELEngine
from agentguard.middleware.cel_policy import CELPolicyMiddleware
from agentguard.models import RequestContext


@pytest.fixture
def engine(tmp_path):
    policy = textwrap.dedent(
        """
        allow_rules:
          - name: ci-bot-whitelist
            when: 'has(jwt.sub) && jwt.sub == "ci-bot"'
            allow: 'mcp.tool.name in ["create_ticket", "search_docs"]'
          - name: repo-lock
            when: 'has(session.initial_repository) && has(request.body.repository)'
            allow: 'request.body.repository == session.initial_repository'
        deny_rules:
          - name: block-sql-drop
            deny: 'string(request.body).matches("(?i)drop\\\\s+table")'
        high_risk_tools:
          - execute_bank_transfer
        """
    )
    path = tmp_path / "policies.yaml"
    path.write_text(policy, encoding="utf-8")
    return CELEngine.from_file(path)


def _ctx(
    *,
    tool: str,
    jwt: dict | None = None,
    session: dict | None = None,
    body: dict | None = None,
) -> RequestContext:
    body = body if body is not None else {"tool": {"name": tool}}
    body_bytes = json.dumps(body).encode("utf-8")
    return RequestContext(
        method="POST",
        path="/tools/" + tool,
        query_string="",
        headers={},
        body_bytes=body_bytes,
        body_json=body,
        jwt_claims=jwt or {},
        session=session or {},
        mcp={"tool": {"name": tool}},
        idempotency_key=None,
        tool_name=tool,
    )


@pytest.mark.asyncio
async def test_ci_bot_allowed_whitelisted_tool(engine):
    mw = CELPolicyMiddleware(engine)
    ctx = _ctx(tool="create_ticket", jwt={"sub": "ci-bot"})
    assert await mw.evaluate(ctx) is None


@pytest.mark.asyncio
async def test_ci_bot_denied_unknown_tool(engine):
    mw = CELPolicyMiddleware(engine)
    ctx = _ctx(tool="delete_production_table", jwt={"sub": "ci-bot"})
    resp = await mw.evaluate(ctx)
    assert resp is not None
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_repo_lock_rejects_cross_repo_access(engine):
    mw = CELPolicyMiddleware(engine)
    ctx = _ctx(
        tool="search_docs",
        jwt={"sub": "ci-bot"},
        session={"session_id": "s", "initial_repository": "myorg/good"},
        body={"tool": {"name": "search_docs"}, "repository": "victim/private"},
    )
    resp = await mw.evaluate(ctx)
    assert resp is not None
    assert resp.status_code == 403
    payload = json.loads(resp.body)
    assert payload["rule"] == "repo-lock"


@pytest.mark.asyncio
async def test_deny_rule_blocks_sql_drop(engine):
    mw = CELPolicyMiddleware(engine)
    ctx = _ctx(
        tool="search_docs",
        jwt={"sub": "ci-bot"},
        body={"tool": {"name": "search_docs"}, "query": "DROP TABLE users"},
    )
    resp = await mw.evaluate(ctx)
    assert resp is not None
    assert resp.status_code == 403
    assert json.loads(resp.body)["rule"] == "block-sql-drop"


def test_high_risk_tools_enumeration(engine):
    assert engine.is_high_risk("execute_bank_transfer") is True
    assert engine.is_high_risk("search_docs") is False
