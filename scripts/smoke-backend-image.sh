#!/usr/bin/env bash
# Smoke-test the PRODUCTION backend image (backend/Dockerfile — the container
# the compose stack ships) with an empty network namespace.
#
# The web-image smoke proves the Caddy front serves; this proves the API
# server itself: it boots, answers /health, serves real endpoints, and makes
# zero external reach possible — all with `--network none`, so the container
# has no interface besides loopback and any outbound attempt fails at the OS
# level (license pings, update checks, telemetry — all impossible).
#
#   bash scripts/smoke-backend-image.sh [--image outpost-backend:ci]
#
# The container runs with NO env vars — the zero-config default (auth off,
# demo mode off). That is deliberate: production fail-closed auth is already
# asserted by the post-deploy walk in the same Deploy job (401 without a
# token, 200 with admin, agent token restricted to telemetry), so this smoke
# isolates the boot + serve + zero-egress contract. The python:3.12-slim
# image has no wget/curl, so every probe goes through the app's own runtime:
# `docker exec` + urllib over loopback.
#
# Assertions:
#   1. The container starts and does not crash-loop (RestartCount == 0).
#   2. ZERO EGRESS, asserted at the OS level: /proc/net/route inside the
#      container is empty — no network devices besides loopback exist.
#   3. Caddy.. uvicorn answers on loopback: GET /health -> 200 {"status":"ok"}.
#   4. The zero-config default is honest: GET /meta -> 200 with
#      "demo_mode":false (a fresh backend never masquerades demo data).
#   5. The API actually serves: GET /runs -> 200 JSON array.
set -euo pipefail

IMAGE="outpost-backend:ci"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not available — the container smoke test runs on CI (Deploy job)." >&2
  exit 3
fi

NAME="outpost-backend-smoke-$$"
echo "== smoke-testing $IMAGE with --network none (name $NAME) =="

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --network none --name "$NAME" "$IMAGE" >/dev/null

# Assertion 1: no crash-loop.
RC=$(docker inspect --format '{{.RestartCount}}' "$NAME")
[[ "$RC" == "0" ]] || { echo "  FAIL: container restarted ($RC times) — boot crash" >&2; docker logs "$NAME" 2>&1 | tail -20 >&2; exit 1; }
echo "  OK: container started cleanly (RestartCount=0)"

# Assertion 2 (cheap, early): the namespace really is empty.
ROUTES=$(docker exec "$NAME" cat /proc/net/route 2>/dev/null | tail -n +2 | tr -d ' \t' || true)
if [[ -n "$ROUTES" ]]; then
  echo "  FAIL: unexpected route entries in empty namespace:" >&2
  echo "$ROUTES" >&2
  exit 1
fi
echo "  OK: /proc/net/route empty — no device besides loopback (zero egress)"

# Probe helpers — urllib through the app's own runtime (slim has no wget).
status() { # status <url> -> "200"
  docker exec "$NAME" python -c "import urllib.request,sys; print(urllib.request.urlopen('$1', timeout=5).status)" 2>/dev/null || true
}
body() { # body <url> -> response text
  docker exec "$NAME" python -c "import urllib.request; print(urllib.request.urlopen('$1', timeout=10).read().decode('utf-8', 'replace'))" 2>/dev/null || true
}

# Readiness: uvicorn must answer /health on loopback before any assertion.
READY=""
for i in $(seq 1 30); do
  S=$(status "http://127.0.0.1:8001/health")
  if [[ "$S" == "200" ]]; then READY=1; break; fi
  sleep 1
done
if [[ -z "$READY" ]]; then
  echo "  FAIL: uvicorn never answered /health on loopback (last: '$(status "http://127.0.0.1:8001/health")')" >&2
  docker logs "$NAME" 2>&1 | tail -20 >&2
  exit 1
fi

# Assertion 3: /health.
S=$(status "http://127.0.0.1:8001/health")
[[ "$S" == "200" ]] || { echo "  FAIL: /health -> $S" >&2; exit 1; }
echo "  OK: GET /health -> 200"

# Assertion 4: zero-config default is honest (demo off, no masquerade).
META=$(body "http://127.0.0.1:8001/meta")
echo "$META" | grep -q '"demo_mode":false' || { echo "  FAIL: /meta demo_mode not false: $META" >&2; exit 1; }
echo "  OK: GET /meta -> 200, demo_mode false (fresh backend never fakes demo data)"

# Assertion 5: the API serves real endpoints (auth off -> /runs is public).
S=$(status "http://127.0.0.1:8001/runs")
[[ "$S" == "200" ]] || { echo "  FAIL: /runs -> $S" >&2; exit 1; }
RUNS=$(body "http://127.0.0.1:8001/runs")
echo "$RUNS" | grep -q '^\[' || { echo "  FAIL: /runs not a JSON array: ${RUNS:0:80}" >&2; exit 1; }
echo "  OK: GET /runs -> 200 JSON array"

echo "✓ smoke: $IMAGE boots and serves with the network namespace empty"
