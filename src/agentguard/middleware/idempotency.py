"""Idempotency middleware implementing the plan's *defense #1*.

* Clients SHOULD pass ``Idempotency-Key``. If missing, the middleware derives a
  deterministic key from ``session_id + tool_name + intent_hash`` using HMAC so
  that the same intent repeated by a hallucinating model maps to the same key.
* Redis ``SETNX`` claims the key atomically. The winner runs the rest of the
  middleware chain; later requests are either served the cached response
  (``SUCCESS``) or informed that a concurrent attempt is in flight
  (``PROCESSING`` → HTTP 409).
* Once the upstream response is captured, it is persisted with a TTL that
  acts as the "intent expiry window" from the research plan, mitigating
  cross-time context drift.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

from ..models import ProxyResponse, RequestContext
from ..storage.redis_store import RedisStore, _b64_decode, _str_to_dict

logger = logging.getLogger(__name__)


class IdempotencyMiddleware:
    def __init__(self, store: RedisStore, secret: str, ttl_seconds: int) -> None:
        self._store = store
        self.secret = secret.encode("utf-8")
        self.ttl = ttl_seconds

    # ------------- public API -------------

    async def lookup(self, ctx: RequestContext) -> ProxyResponse | None:
        """Before the rest of the chain runs, check if this key was seen."""
        if not self._should_apply(ctx):
            return None

        key = ctx.idempotency_key or self._derive_key(ctx)
        ctx.idempotency_key = key

        state = await self._store.get_state(key)
        if state == "SUCCESS":
            cached = await self._store.get_cached_response(key)
            if cached:
                return _cached_to_response(cached)
        if state == "PROCESSING":
            return ProxyResponse.json(
                status_code=409,
                payload={
                    "error": "concurrent_request_in_flight",
                    "idempotency_key": key,
                },
            )

        reserved = await self._store.reserve(key, self.ttl)
        if not reserved:
            state = await self._store.get_state(key)
            if state == "SUCCESS":
                cached = await self._store.get_cached_response(key)
                if cached:
                    return _cached_to_response(cached)
            return ProxyResponse.json(
                status_code=409,
                payload={
                    "error": "concurrent_request_in_flight",
                    "idempotency_key": key,
                },
            )
        return None

    async def store(self, ctx: RequestContext, response: ProxyResponse) -> None:
        """Persist the upstream response so later retries replay it."""
        await self._store_response_for_key(ctx.idempotency_key, response)

    async def _store_response_for_key(
        self, key: str | None, response: ProxyResponse
    ) -> None:
        if not key:
            return
        if 200 <= response.status_code < 400:
            await self._store.mark_success(
                key,
                status_code=response.status_code,
                body=response.body,
                headers=response.headers,
                media_type=response.media_type,
                ttl_seconds=self.ttl,
            )
        else:
            # Release the reservation so a *corrected* retry can proceed.
            logger.info(
                "idempotency.release key=%s status=%s", key, response.status_code
            )
            await self._store.release(key)

    # ------------- helpers -------------

    def _should_apply(self, ctx: RequestContext) -> bool:
        # Only apply to methods with side effects.
        return ctx.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}

    def _derive_key(self, ctx: RequestContext) -> str:
        session_id = str(ctx.session.get("session_id") or "anon")
        tool_name = ctx.tool_name or ctx.path
        intent = _canonical_intent(ctx.body_json) if ctx.body_json is not None else ctx.body_bytes
        intent_hash = hashlib.sha256(
            intent if isinstance(intent, bytes) else intent.encode("utf-8")
        ).hexdigest()
        message = f"{session_id}|{tool_name}|{intent_hash}".encode()
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()


def _canonical_intent(payload: Any) -> str:
    """Produce a canonical string for hashing.

    Sorting keys ensures that a hallucinating model that reorders fields still
    maps to the same idempotency key. Non-essential free-text fields should be
    stripped here in production (the research plan warns that naive whole-body
    hashing is trivially bypassed).
    """
    try:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    except TypeError:
        return str(payload)


def _cached_to_response(cached: dict[str, str]) -> ProxyResponse:
    status_code = int(cached.get("status_code", "200"))
    body = _b64_decode(cached.get("body_b64", ""))
    headers = _str_to_dict(cached.get("headers", "{}"))
    headers.setdefault("x-agentguard-replay", "true")
    return ProxyResponse(
        status_code=status_code,
        body=body,
        headers=headers,
        media_type=cached.get("media_type", "application/octet-stream"),
    )
