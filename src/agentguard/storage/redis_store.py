"""Thin async wrapper around redis-py used by the idempotency middleware.

Isolating the Redis API behind this class lets tests swap in ``fakeredis``
without touching any middleware code.
"""

from __future__ import annotations

from typing import Protocol


class _AsyncRedisClient(Protocol):
    async def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None): ...
    async def get(self, key: str): ...
    async def hset(self, key: str, mapping: dict): ...
    async def hgetall(self, key: str): ...
    async def delete(self, *keys: str): ...
    async def expire(self, key: str, seconds: int): ...
    async def close(self): ...


class RedisStore:
    """State store for idempotency keys and cached responses.

    Two keys are used per idempotency token ``K``:

    * ``agentguard:idem:K`` — string, state machine (``PROCESSING`` | ``SUCCESS``).
    * ``agentguard:idem:K:response`` — hash, cached response fields.
    """

    def __init__(self, client: _AsyncRedisClient) -> None:
        self._client = client

    @classmethod
    def from_url(cls, url: str) -> RedisStore:
        import redis.asyncio as aioredis

        client = aioredis.from_url(url, decode_responses=True)
        return cls(client)

    @classmethod
    def from_client(cls, client: _AsyncRedisClient) -> RedisStore:
        return cls(client)

    # ---------------------- state transitions ----------------------

    async def reserve(self, key: str, ttl_seconds: int) -> bool:
        """Atomically reserve a key with state=PROCESSING.

        Returns True if this caller won the race (first request), False if a
        prior request has already reserved the same key.
        """
        full = self._state_key(key)
        result = await self._client.set(full, "PROCESSING", nx=True, ex=ttl_seconds)
        return bool(result)

    async def get_state(self, key: str) -> str | None:
        value = await self._client.get(self._state_key(key))
        return value

    async def mark_success(
        self,
        key: str,
        status_code: int,
        body: bytes,
        headers: dict[str, str],
        media_type: str,
        ttl_seconds: int,
    ) -> None:
        state_key = self._state_key(key)
        resp_key = self._response_key(key)

        await self._client.set(state_key, "SUCCESS", ex=ttl_seconds)

        mapping = {
            "status_code": str(status_code),
            "body_b64": _b64(body),
            "headers": _dict_to_str(headers),
            "media_type": media_type,
        }
        await self._client.hset(resp_key, mapping=mapping)
        await self._client.expire(resp_key, ttl_seconds)

    async def get_cached_response(self, key: str) -> dict[str, str] | None:
        data = await self._client.hgetall(self._response_key(key))
        if not data:
            return None
        return dict(data)

    async def release(self, key: str) -> None:
        """Remove state so a retry can proceed (used on upstream failure)."""
        await self._client.delete(self._state_key(key), self._response_key(key))

    async def close(self) -> None:
        close = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
        if close is None:
            return
        result = close()
        if hasattr(result, "__await__"):
            await result

    @staticmethod
    def _state_key(key: str) -> str:
        return f"agentguard:idem:{key}"

    @staticmethod
    def _response_key(key: str) -> str:
        return f"agentguard:idem:{key}:response"


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    import base64

    return base64.b64decode(data.encode("ascii"))


def _dict_to_str(data: dict[str, str]) -> str:
    import json

    return json.dumps(data)


def _str_to_dict(data: str) -> dict[str, str]:
    import json

    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return {}
