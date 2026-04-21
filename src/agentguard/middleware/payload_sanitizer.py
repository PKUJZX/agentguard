"""Payload sanitizer — defense #2b (DLP regex rewrite).

The sanitizer implements the *programmatic payload rewrite* idea from the
research plan: instead of dropping the request, it replaces known secret
patterns with masks before the payload ever leaves the gateway. A concise
audit record of every rewrite is attached to ``ctx.sanitized_findings`` for
downstream structured logging / SIEM export.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..models import RequestContext

logger = logging.getLogger(__name__)


@dataclass
class DLPRule:
    name: str
    pattern: re.Pattern[str]
    mask: str


class PayloadSanitizer:
    def __init__(self, rules: list[DLPRule]) -> None:
        self.rules = rules

    @classmethod
    def from_file(cls, path: str | Path) -> PayloadSanitizer:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules: list[DLPRule] = []
        for entry in data.get("rules", []):
            rules.append(
                DLPRule(
                    name=entry["name"],
                    pattern=re.compile(entry["pattern"]),
                    mask=entry.get("mask", "****REDACTED****"),
                )
            )
        return cls(rules)

    async def sanitize(self, ctx: RequestContext) -> None:
        """Mutate ``ctx`` so downstream hops see the masked payload."""
        if not ctx.body_bytes:
            return

        try:
            text = ctx.body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Non-text body — leave untouched.
            return

        new_text, findings = self._apply_rules(text)

        if not findings:
            return

        ctx.sanitized_findings = findings
        ctx.sanitized_body_bytes = new_text.encode("utf-8")

        # Keep JSON view consistent so subsequent CEL evaluations / logging
        # see the masked values too.
        try:
            ctx.sanitized_body_json = json.loads(new_text)
        except json.JSONDecodeError:
            ctx.sanitized_body_json = None

        for f in findings:
            logger.info(
                "dlp.rewrite rule=%s count=%d tool=%s", f["rule"], f["count"], ctx.tool_name
            )

    def _apply_rules(self, text: str) -> tuple[str, list[dict]]:
        findings: list[dict] = []
        current = text
        for rule in self.rules:
            new_text, n = rule.pattern.subn(rule.mask, current)
            if n > 0:
                findings.append({"rule": rule.name, "count": n, "mask": rule.mask})
                current = new_text
        return current, findings
