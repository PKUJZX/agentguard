# Quickstart

## 1. Docker Compose (recommended)

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs -f agentguard
```

Services started:

| Service            | Port | Purpose                                |
| ------------------ | ---- | -------------------------------------- |
| `agentguard`       | 8080 | The Sidecar gateway                    |
| `redis`            | 6379 | Idempotency state                      |
| `postgres`         | 5432 | HITL request registry                  |
| `mock-backend`     | 9000 | Fake MCP tool server                   |
| `approval-console` | 9001 | Web UI for HITL approvers              |

## 2. Run the three demos

```bash
docker compose exec agentguard python examples/demo_agent/demo_retry_storm.py
docker compose exec agentguard python examples/demo_agent/demo_injection.py
docker compose exec agentguard python examples/demo_agent/demo_hitl.py
```

### `demo_retry_storm.py`
Fires 5 identical `create_ticket` calls with the same `Idempotency-Key`. Only the first reaches `mock-backend` — the rest are served from the Redis cache, which the gateway logs as `idempotent replay`.

### `demo_injection.py`
Two sub-cases:
- A cross-repo attack tries to read `victim/private` after the session was locked to `my-org/my-repo`; the CEL rule `repo-lock` denies it with HTTP 403.
- A payload containing `AKIA0123456789ABCDEF` (an AWS Access Key) is automatically rewritten to `AKIA****REDACTED` before reaching the backend.

### `demo_hitl.py`
Calls the high-risk `execute_bank_transfer` tool:
1. Gateway returns `202 Accepted` with `ticket_id`.
2. Visit `http://localhost:9001` and approve the ticket.
3. The demo agent polls `/agentguard/hitl/status/<ticket_id>`, observes `APPROVED`, and then re-issues the request — the gateway forwards it and returns the real backend response.

## 3. Local development (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate
# cel-python >=0.5 pulls in google-re2 (C extension); pin 0.4.0 + pure-Python deps
pip install --no-deps cel-python==0.4.0 pendulum lark tomli jmespath python-dateutil
pip install -e ".[dev]"

# Run tests (20 tests, all pass)
pytest -q

# Run the gateway against a local mock backend (requires redis + postgres locally)
# or configure `AGENTGUARD_POSTGRES_DSN=sqlite+aiosqlite:///./ag.db` for quick try
uvicorn agentguard.main:app --host 0.0.0.0 --port 8080
```

## 4. Environment variables

All configuration is driven by environment variables prefixed `AGENTGUARD_`.
See `.env.example` in the repo root for the full list and defaults.
