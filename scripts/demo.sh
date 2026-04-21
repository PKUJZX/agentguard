#!/usr/bin/env bash
# One-command AgentGuard live demo.
#
#   ./scripts/demo.sh
#
# Brings the full stack up with docker compose, waits for every component to
# become healthy, prints the dashboard URL, then runs the six scripted attack
# scenarios so you can watch them land on the live dashboard.
set -euo pipefail

BLUE='\033[1;34m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; DIM='\033[2m'; RESET='\033[0m'

say() { printf "${BLUE}==>${RESET} %s\n" "$*"; }
ok()  { printf "${GREEN}✓${RESET}  %s\n" "$*"; }
warn(){ printf "${YELLOW}!${RESET}  %s\n" "$*"; }
die() { printf "${RED}✗${RESET}  %s\n" "$*"; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v docker >/dev/null 2>&1 || die "docker is required"
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  die "docker compose (or docker-compose) is required"
fi

say "Starting docker compose stack (redis, postgres, mock-backend, agentguard, approval-console, dashboard)"
if ! "${DC[@]}" up -d --build; then
  cat <<'EOT'

  ✗ docker compose up 失败。如果你看到 "failed to resolve reference docker.io/library/...: i/o timeout"，
    这是国内直连 Docker Hub 超时导致的。解决办法：

      1) 给 Docker 配当前仍在运行的镜像源：
         详细步骤见  docs/docker-mirror.md

      2) 或者，预先用代理拉好基础镜像：
         docker pull redis:7-alpine
         docker pull postgres:16-alpine
         docker pull python:3.11-slim
         然后重跑 ./scripts/demo.sh

EOT
  die "docker compose up 失败"
fi

wait_for() {
  local name=$1 url=$2 tries=${3:-60}
  printf "   waiting for %-20s " "$name"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS -o /dev/null "$url"; then echo -e "${GREEN}ready${RESET}"; return 0; fi
    sleep 1
  done
  echo -e "${RED}timeout${RESET}"
  return 1
}

say "Waiting for services to become ready"
wait_for "agentguard gateway"   "http://localhost:8080/agentguard/health"     || die "gateway did not start"
wait_for "mock backend"         "http://localhost:9000/health"                || die "backend did not start"
wait_for "approval console"     "http://localhost:9001/"                      || warn "approval console slow"
wait_for "dashboard"            "http://localhost:9002/health"                || warn "dashboard slow"

cat <<EOF

${GREEN}Stack is ready.${RESET}

  ${DIM}Gateway${RESET}          http://localhost:8080/agentguard/health
  ${DIM}Mock backend${RESET}     http://localhost:9000/stats
  ${DIM}Approval console${RESET} http://localhost:9001/
  ${GREEN}>> Live dashboard${RESET} http://localhost:9002/

Open the live dashboard in your browser — the event feed will fill up as the
scenarios run below. You can also click the ${YELLOW}Attack Launcher${RESET} buttons yourself.

EOF

say "Running the 6 scripted attack scenarios against the gateway…"
PY=${PYTHON:-python3}
export AGENTGUARD_GATEWAY_URL="${AGENTGUARD_GATEWAY_URL:-http://localhost:8080}"
export MOCK_BACKEND_STATS_URL="${MOCK_BACKEND_STATS_URL:-http://localhost:9000/stats}"
export AUTO_APPROVE=1

for demo in \
  demo_retry_storm.py \
  demo_injection.py \
  demo_sql_drop.py \
  demo_dlp.py \
  demo_payload_splitting.py \
  demo_hitl.py ; do
  "$PY" "examples/demo_agent/$demo" || warn "scenario $demo reported failure"
  echo
done

cat <<EOF

${GREEN}All scenarios finished.${RESET}

Try it yourself:
  • Open ${GREEN}http://localhost:9002/${RESET} and click the buttons in ${YELLOW}Attack Launcher${RESET}.
  • Stop the stack with:  ${DIM}${DC[*]} down -v${RESET}

EOF
