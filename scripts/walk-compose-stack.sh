#!/usr/bin/env bash
# Walk the POST-DEPLOY CHECKLIST against the SHIPPED compose stack — the real
# Caddy image + real backend container (deploy/docker-compose.prod.yml), not
# the in-process stand-in of scripts/post_deploy_walk.py.
#
#   bash scripts/walk-compose-stack.sh   # requires docker
#
# Brings the production stack up exactly as deploy/README.md documents (env
# file, OUTPOST_HOST=localhost, fail-closed auth), then asserts the four
# checklist items against the LIVE stack over real TLS:
#
#   1. TLS    — https://localhost/api/health -> {"status":"ok"} through Caddy.
#               (OUTPOST_HOST=localhost makes Caddy's auto-HTTPS use its
#               internal CA — self-signed, so probes use curl -k.)
#   2. Auth   — /api/runs without a token -> 401; with an admin token -> 200.
#   3. Login  — POST /api/auth/login -> token; /api/auth/me -> enabled:true.
#   4. Agent  — heartbeat without credential -> 401; with OUTPOST_AGENT_TOKEN
#               -> 200 and the host appears online on /api/agents; the agent
#               credential is refused outside telemetry (/api/campaigns -> 403).
#
# The proxy path is /api/health, not /health: the Caddyfile proxies only
# /api/* (prefix-stripped) to the backend and serves everything else as the
# SPA fallback — so /health returns index.html, and the honest backend health
# JSON comes through /api/health. This is the real through-stack path a
# browser/user hits, and the checklist in deploy/README.md uses it.
#
# Exit 0 only when every assertion passes. Cleans up the stack and its
# outpost-data volume on the way out. Runs on CI in the Deploy job; this box
# has no docker, so the docker-less shape is already covered by the
# post-deploy walk verify.sh step.
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "  docker not found — the compose walk needs a docker host." >&2
  echo "  (Local coverage for the same checklist without docker: verify.sh's" >&2
  echo "   'Post-deploy walk' step, scripts/post_deploy_walk.py.)" >&2
  exit 3
fi

PROJ="outpost-compose-walk"
BASE="https://localhost"
ADMIN_PASSWORD="walk-compose-pass"
AGENT_TOKEN="walk-compose-tok"
COMPOSE_ARGS=(compose -p "$PROJ" -f deploy/docker-compose.prod.yml)

ENV_FILE="$(mktemp)"
cleanup() {
  docker "${COMPOSE_ARGS[@]}" --env-file "$ENV_FILE" down -v >/dev/null 2>&1 || true
  rm -f "$ENV_FILE"
}
trap cleanup EXIT

cat > "$ENV_FILE" <<EOF
OUTPOST_HOST=localhost
OUTPOST_ADMIN_PASSWORD=$ADMIN_PASSWORD
OUTPOST_AGENT_TOKEN=$AGENT_TOKEN
EOF

PASS=0
FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
bad() { echo "  [FAIL] $1${2:+ — $2}" >&2; FAIL=$((FAIL + 1)); }

code() { # code <url> [curl args...]
  local url=$1; shift
  curl -ks -o /dev/null -w '%{http_code}' "$url" "$@" 2>/dev/null || true
}

echo "== Bringing up the shipped compose stack (real Caddy + real backend) =="
docker "${COMPOSE_ARGS[@]}" --env-file "$ENV_FILE" up -d --build

# Wait for the stack to answer over TLS. Caddy generates its internal cert on
# first request; the backend boots its DB in the volume. Up to ~120s.
UP=""
LAST=""
for _ in $(seq 1 60); do
  LAST=$(code "$BASE/api/health")
  if [[ "$LAST" == "200" ]]; then UP=1; break; fi
  sleep 2
done
if [[ -z "$UP" ]]; then
  echo "  FAIL: stack never became healthy over TLS (last HTTP $LAST)" >&2
  docker "${COMPOSE_ARGS[@]}" --env-file "$ENV_FILE" ps >&2 || true
  exit 1
fi
ok "compose stack healthy over TLS — /api/health -> 200"

# 1. TLS — the health JSON through Caddy's TLS front + /api proxy.
BODY=$(curl -ks "$BASE/api/health" 2>/dev/null || true)
if echo "$BODY" | grep -q '"ok"'; then
  ok "1 · TLS /api/health -> {\"status\":\"ok\"} through the real Caddy front"
else
  bad "1 · TLS /api/health -> ok JSON" "body=${BODY:0:120}"
fi

# 2. Auth — 401 without a token, 200 with an admin token (fail-closed).
NO_TOKEN=$(code "$BASE/api/runs")
if [[ "$NO_TOKEN" == "401" ]]; then
  ok "2 · /api/runs no token -> 401 (fail-closed behind the proxy)"
else
  bad "2 · /api/runs no token -> 401" "HTTP $NO_TOKEN"
fi

LOGIN=$(curl -ks -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"$ADMIN_PASSWORD\"}" 2>/dev/null || true)
ADMIN_TOKEN=$(echo "$LOGIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null || true)
if [[ -z "$ADMIN_TOKEN" ]]; then
  bad "2 · admin login" "no token in: ${LOGIN:0:120}"
else
  WITH_TOKEN=$(code "$BASE/api/runs" -H "Authorization: Bearer $ADMIN_TOKEN")
  if [[ "$WITH_TOKEN" == "200" ]]; then
    ok "2 · /api/runs with admin token -> 200"
  else
    bad "2 · /api/runs with admin token -> 200" "HTTP $WITH_TOKEN"
  fi
fi

# 3. Login — /auth/me reports enabled with the admin role.
ME=$(curl -ks "$BASE/api/auth/me" -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null || true)
if echo "$ME" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("enabled") is True and d.get("role")=="admin" else 1)' 2>/dev/null; then
  ok "3 · login -> /auth/me enabled:true, role admin"
else
  bad "3 · login -> /auth/me enabled" "me=${ME:0:120}"
fi

# 4. Agent — the OUTPOST_AGENT_TOKEN flow against the fail-closed stack.
HB_BARE=$(code "$BASE/api/agents/walk-compose-host/heartbeat" \
  -X POST -H 'Content-Type: application/json' -d '{"platform":"linux"}')
if [[ "$HB_BARE" == "401" ]]; then
  ok "4 · heartbeat without credential -> 401"
else
  bad "4 · heartbeat without credential -> 401" "HTTP $HB_BARE"
fi

HB=$(code "$BASE/api/agents/walk-compose-host/heartbeat" \
  -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $AGENT_TOKEN" \
  -d '{"platform":"linux","version":"outpost-collector/1.0"}')
if [[ "$HB" == "200" ]]; then
  ok "4 · heartbeat with agent token -> 200"
else
  bad "4 · heartbeat with agent token -> 200" "HTTP $HB"
fi

AGENTS=$(curl -ks "$BASE/api/agents" -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null || true)
if echo "$AGENTS" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(a.get("host_id")=="walk-compose-host" and a.get("online") for a in d.get("agents", [])) else 1)' 2>/dev/null; then
  ok "4 · walk-compose-host online on /api/agents"
else
  bad "4 · walk-compose-host online on /api/agents" "agents=${AGENTS:0:160}"
fi

SCOPED=$(code "$BASE/api/campaigns" -H "Authorization: Bearer $AGENT_TOKEN")
if [[ "$SCOPED" == "403" ]]; then
  ok "4 · agent token refused outside telemetry -> 403"
else
  bad "4 · agent token refused outside telemetry -> 403" "HTTP $SCOPED"
fi

ADMIN_OK=$(code "$BASE/api/campaigns" -H "Authorization: Bearer $ADMIN_TOKEN")
if [[ "$ADMIN_OK" == "200" ]]; then
  ok "4 · admin unaffected -> 200"
else
  bad "4 · admin unaffected -> 200" "HTTP $ADMIN_OK"
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "✓ compose-stack post-deploy walk: $PASS passed, 0 failed"
  exit 0
fi
echo "✗ compose-stack post-deploy walk: $PASS passed, $FAIL failed" >&2
exit 1
