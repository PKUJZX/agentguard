"""CEL policy middleware — defense #2a (policy gate)."""

from __future__ import annotations

import logging

from ..cel.engine import CELEngine
from ..models import ProxyResponse, RequestContext

logger = logging.getLogger(__name__)


class CELPolicyMiddleware:
    def __init__(self, engine: CELEngine) -> None:
        self.engine = engine

    async def evaluate(self, ctx: RequestContext) -> ProxyResponse | None:
        decision = self.engine.evaluate(ctx.cel_activation())
        if decision.allowed:
            return None

        logger.info(
            "cel.deny rule=%s reason=%s tool=%s", decision.rule, decision.reason, ctx.tool_name
        )
        return ProxyResponse.json(
            status_code=403,
            payload={
                "error": "policy_denied",
                "rule": decision.rule,
                "reason": decision.reason,
            },
        )
