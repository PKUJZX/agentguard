#!/usr/bin/env bash
# Lighter counterpart of demo.sh — assumes the stack is already up and just
# runs the six scripted scenarios one after another.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY=${PYTHON:-python3}
export AGENTGUARD_GATEWAY_URL="${AGENTGUARD_GATEWAY_URL:-http://localhost:8080}"
export MOCK_BACKEND_STATS_URL="${MOCK_BACKEND_STATS_URL:-http://localhost:9000/stats}"
export AUTO_APPROVE="${AUTO_APPROVE:-1}"

for demo in \
  demo_retry_storm.py \
  demo_injection.py \
  demo_sql_drop.py \
  demo_dlp.py \
  demo_payload_splitting.py \
  demo_hitl.py ; do
  "$PY" "examples/demo_agent/$demo" || true
  echo
done
