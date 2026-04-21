"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("AGENTGUARD_IDEMPOTENCY_SECRET", "test-secret")
os.environ.setdefault("AGENTGUARD_HITL_HMAC_SECRET", "test-hitl-secret")
os.environ.setdefault("AGENTGUARD_POLICIES_PATH", str(REPO_ROOT / "configs" / "policies.yaml"))
os.environ.setdefault("AGENTGUARD_DLP_RULES_PATH", str(REPO_ROOT / "configs" / "dlp_rules.yaml"))
os.environ.setdefault("AGENTGUARD_POSTGRES_DSN", "sqlite+aiosqlite:///:memory:")


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def fake_redis_store():
    """Return a RedisStore backed by fakeredis — no external service needed."""
    import fakeredis.aioredis

    from agentguard.storage.redis_store import RedisStore

    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return RedisStore.from_client(client)
