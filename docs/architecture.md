# AgentGuard Architecture

AgentGuard is a **Sidecar-pattern** reverse proxy: the AI agent process is configured to talk to `http://localhost:8080` instead of directly to the real backend (via `iptables` redirect, proxy env vars, or explicit HTTP client base URL). Every request flows through four middlewares in order; any one of them can short-circuit the chain.

```
 ┌─────────────────────────── AgentGuard :8080 ───────────────────────────┐
 │                                                                        │
 │   [1] Idempotency  ──►  [2] CEL Policy  ──►  [3] Payload Sanitizer     │
 │          │                                            │                │
 │        Redis                                          │                │
 │                                                       ▼                │
 │                                             [4] HITL Interceptor  ──►  Backend
 │                                                       │                │
 │                                                  PostgreSQL            │
 └───────────────────────────────────────────────────────┼────────────────┘
                                                         │
                                                 Approval Console
                                                 (HMAC-signed callback)
```

## Middleware Chain

### 1. Idempotency (`middleware/idempotency.py`)

- Implements *"network-layer idempotency lock"* from the research plan.
- Client should supply `Idempotency-Key`; otherwise the gateway derives one as
  `HMAC_SHA256(secret, session_id || tool_name || intent_hash)`.
- Uses Redis `SET key value NX EX ttl` for atomic first-writer-wins.
- Stores the final response so **repeated retries by a hallucinating LLM replay the cached response** and cannot reach the real backend again.

### 2. CEL Policy (`middleware/cel_policy.py` + `cel/engine.py`)

- Loads `configs/policies.yaml`.
- For every request builds a CEL activation with `jwt`, `session`, `mcp`, `request` variables.
- Evaluates **allow_rules** (conjunctive when `when` matches) and **deny_rules** (disjunctive).
- Rejects with HTTP 403 at the network layer — prompt-injection-crafted tool calls cannot leave the proxy.

### 3. Payload Sanitizer (`middleware/payload_sanitizer.py`)

- Loads `configs/dlp_rules.yaml`.
- Rewrites (not blocks) matched secrets (`AKIA*`, `ghp_*`, `sk-*`, JWTs, PEM-encoded private keys, ...) with masks before forwarding.
- Emits a structured audit log of every rewrite.

### 4. HITL Interceptor (`middleware/hitl.py`)

- If `mcp.tool.name` is in `high_risk_tools`, the gateway:
  1. Persists the sanitized request context to PostgreSQL (`pending_requests`).
  2. Fires a webhook to the Approval Console.
  3. Returns `202 Accepted` with `{"status": "PENDING_APPROVAL", "ticket_id": ...}`.
- The agent is expected to poll `GET /agentguard/hitl/status/{ticket_id}`.
- An approver calls `POST /agentguard/hitl/approve` with an HMAC signature proving out-of-band authentication; the gateway then resumes and forwards the original request to the backend.

## Data Stores

| Store      | Role                                          | TTL / Retention         |
| ---------- | --------------------------------------------- | ----------------------- |
| Redis      | Idempotency state + response cache            | `AGENTGUARD_IDEMPOTENCY_TTL` seconds |
| PostgreSQL | HITL request registry, audit trail            | Indefinite (retained as audit-grade receipts) |

## Failure Modes

- Redis outage → gateway fails **closed**: idempotency middleware returns 503.
- PostgreSQL outage on high-risk request → gateway fails **closed**: HITL returns 503 (we must not forward a high-risk request without a durable audit record).
- CEL rule evaluation error → gateway fails **closed**: returns 500.
