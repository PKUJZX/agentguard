"""Tests for the DLP payload sanitizer."""

from __future__ import annotations

import json
import textwrap

import pytest

from agentguard.middleware.payload_sanitizer import PayloadSanitizer
from agentguard.models import RequestContext


@pytest.fixture
def sanitizer(tmp_path):
    rules_yaml = textwrap.dedent(
        """
        rules:
          - name: aws-access-key
            pattern: 'AKIA[0-9A-Z]{16}'
            mask: 'AKIA****REDACTED'
          - name: github-pat
            pattern: 'ghp_[A-Za-z0-9]{20,}'
            mask: 'ghp_****REDACTED'
          - name: openai-key
            pattern: 'sk-[A-Za-z0-9]{20,}'
            mask: 'sk-****REDACTED'
        """
    )
    path = tmp_path / "dlp.yaml"
    path.write_text(rules_yaml, encoding="utf-8")
    return PayloadSanitizer.from_file(path)


def _ctx_from_body(body: dict) -> RequestContext:
    b = json.dumps(body).encode("utf-8")
    return RequestContext(
        method="POST",
        path="/tools/send_message",
        query_string="",
        headers={"content-type": "application/json"},
        body_bytes=b,
        body_json=body,
        jwt_claims={},
        session={},
        mcp={"tool": {"name": "send_message"}},
        idempotency_key=None,
        tool_name="send_message",
    )


@pytest.mark.asyncio
async def test_aws_access_key_is_masked(sanitizer):
    ctx = _ctx_from_body({"secret": "AKIA0123456789ABCDEF", "normal": "value"})
    await sanitizer.sanitize(ctx)
    assert ctx.sanitized_body_bytes is not None
    sanitized = json.loads(ctx.sanitized_body_bytes)
    assert sanitized["secret"] == "AKIA****REDACTED"
    assert sanitized["normal"] == "value"
    assert ctx.sanitized_findings[0]["rule"] == "aws-access-key"


@pytest.mark.asyncio
async def test_multiple_rules_are_applied(sanitizer):
    ctx = _ctx_from_body(
        {
            "aws": "AKIAABCDEFGHIJKLMNOP",
            "gh": "ghp_abcdefghijklmnopqrst",
            "oai": "sk-abcdefghijklmnopqrst",
        }
    )
    await sanitizer.sanitize(ctx)
    sanitized = json.loads(ctx.sanitized_body_bytes)
    assert sanitized["aws"].startswith("AKIA****")
    assert sanitized["gh"].startswith("ghp_****")
    assert sanitized["oai"].startswith("sk-****")
    rule_names = {f["rule"] for f in ctx.sanitized_findings}
    assert rule_names == {"aws-access-key", "github-pat", "openai-key"}


@pytest.mark.asyncio
async def test_clean_payload_is_untouched(sanitizer):
    ctx = _ctx_from_body({"title": "hello", "priority": "low"})
    await sanitizer.sanitize(ctx)
    assert ctx.sanitized_body_bytes is None
    assert ctx.sanitized_findings == []


@pytest.mark.asyncio
async def test_effective_body_returns_sanitized(sanitizer):
    ctx = _ctx_from_body({"secret": "AKIA0123456789ABCDEF"})
    await sanitizer.sanitize(ctx)
    effective = ctx.effective_body_bytes()
    assert b"AKIA****REDACTED" in effective
    assert b"AKIA0123456789ABCDEF" not in effective
