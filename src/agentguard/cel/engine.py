"""CEL policy engine wrapping `cel-python` (celpy)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

try:
    import celpy
    from celpy import adapter
except ImportError as exc:  # pragma: no cover - fail fast at import time
    raise ImportError(
        "cel-python is required. Install with: pip install cel-python"
    ) from exc

logger = logging.getLogger(__name__)


@dataclass
class CELRule:
    name: str
    description: str
    when_expr: str | None
    expr: str
    kind: str  # "allow" or "deny"

    _when_program: Any = field(default=None, repr=False)
    _expr_program: Any = field(default=None, repr=False)


class PolicyDecision:
    """Outcome of evaluating the policy file against a request."""

    def __init__(
        self, allowed: bool, reason: str | None = None, rule: str | None = None
    ) -> None:
        self.allowed = allowed
        self.reason = reason
        self.rule = rule

    def __bool__(self) -> bool:
        return self.allowed


class CELEngine:
    """Load policy YAML, compile CEL expressions, evaluate per-request."""

    def __init__(
        self,
        allow_rules: list[CELRule],
        deny_rules: list[CELRule],
        high_risk_tools: set[str],
    ) -> None:
        self._env = celpy.Environment()
        self.allow_rules = [self._compile(r) for r in allow_rules]
        self.deny_rules = [self._compile(r) for r in deny_rules]
        self.high_risk_tools = set(high_risk_tools)

    @classmethod
    def from_file(cls, path: str | Path) -> CELEngine:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        allow = [
            CELRule(
                name=r.get("name", f"allow-{i}"),
                description=r.get("description", ""),
                when_expr=r.get("when"),
                expr=r["allow"],
                kind="allow",
            )
            for i, r in enumerate(data.get("allow_rules", []))
        ]
        deny = [
            CELRule(
                name=r.get("name", f"deny-{i}"),
                description=r.get("description", ""),
                when_expr=r.get("when"),
                expr=r["deny"],
                kind="deny",
            )
            for i, r in enumerate(data.get("deny_rules", []))
        ]
        high_risk = set(data.get("high_risk_tools", []) or [])
        return cls(allow_rules=allow, deny_rules=deny, high_risk_tools=high_risk)

    def evaluate(self, activation: dict[str, Any]) -> PolicyDecision:
        """Return a PolicyDecision for the request context.

        Evaluation order:
        1. ``deny_rules`` short-circuit — any matching ``deny`` => deny.
        2. ``allow_rules`` whose ``when`` evaluates true must all pass.
        """

        cel_ctx = self._activation_to_cel(activation)

        for rule in self.deny_rules:
            try:
                hit = self._run(rule._expr_program, cel_ctx)
            except Exception as exc:
                logger.warning(
                    "cel.rule_error rule=%s error=%s (failing closed)", rule.name, exc
                )
                return PolicyDecision(
                    False, reason=f"rule_error:{rule.name}", rule=rule.name
                )
            if hit:
                return PolicyDecision(
                    False, reason=f"deny_rule:{rule.name}", rule=rule.name
                )

        for rule in self.allow_rules:
            if rule._when_program is not None:
                try:
                    applies = self._run(rule._when_program, cel_ctx)
                except Exception as exc:
                    logger.warning(
                        "cel.when_error rule=%s error=%s (skipping rule)",
                        rule.name,
                        exc,
                    )
                    applies = False
                if not applies:
                    continue
            try:
                allowed = self._run(rule._expr_program, cel_ctx)
            except Exception as exc:
                logger.warning(
                    "cel.allow_error rule=%s error=%s (failing closed)",
                    rule.name,
                    exc,
                )
                return PolicyDecision(
                    False, reason=f"rule_error:{rule.name}", rule=rule.name
                )
            if not allowed:
                return PolicyDecision(
                    False,
                    reason=f"allow_rule_violated:{rule.name}",
                    rule=rule.name,
                )

        return PolicyDecision(True)

    def is_high_risk(self, tool_name: str | None) -> bool:
        return bool(tool_name) and tool_name in self.high_risk_tools

    # ---------------- internal ----------------

    def _compile(self, rule: CELRule) -> CELRule:
        rule._expr_program = self._compile_expr(rule.expr, rule.name)
        if rule.when_expr:
            rule._when_program = self._compile_expr(
                rule.when_expr, rule.name + ".when"
            )
        return rule

    def _compile_expr(self, expr: str, name: str):
        try:
            ast = self._env.compile(expr)
            return self._env.program(ast)
        except Exception as exc:
            raise ValueError(f"failed to compile CEL expression {name!r}: {exc}") from exc

    @staticmethod
    def _activation_to_cel(activation: dict[str, Any]):
        return adapter.json_to_cel(activation)

    @staticmethod
    def _run(program, cel_ctx) -> bool:
        result = program.evaluate(cel_ctx)
        if isinstance(result, Exception):  # pragma: no cover - celpy surfaces this
            raise result
        return bool(result)
