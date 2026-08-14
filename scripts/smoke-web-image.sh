#!/usr/bin/env bash
# Smoke-test the PRODUCTION web image (deploy/Dockerfile.web) itself — the
# artifact that ships — with an empty network namespace.
#
# The air-gap CI job proves the full stack inside a test-harness image, but
# the harness image is NOT what users run. This proves the shipped Caddy
# image boots, serves the SPA + static bundle, and keeps the /api proxy live
# — all with `--network none`, so the container has no interface besides
# loopback and any external reach fails at the OS level.
#
#   bash scripts/smoke-web-image.sh [--image outpost-web:ci] [--host localhost]
#   bash scripts/smoke-web-image.sh --dist frontend/dist   # offline artifact check (no docker)
#
# Assertions:
#   1. The container starts and does not crash-loop (RestartCount == 0).
#   2. Caddy answers on loopback: GET / -> 200 with the SPA shell (id="root").
#   3. The built bundle serves: every /assets/* chunk referenced by
#      index.html returns 200 (proves the static artifact is intact).
#   4. The API proxy is live but the sibling backend is absent in isolation:
#      GET /api/health -> 502 (Caddy's reverse_proxy reached, backend
#      container not on this namespace — the honest isolated-state signal).
#   5. TLS serves on 443 via Caddy's internal CA for localhost (no ACME):
#      GET https://127.0.0.1/ -> 200 with --no-check-certificate.
#   6. ZERO EGRESS, asserted at the OS level: /proc/net/route inside the
#      container is empty — no network devices besides loopback exist.
#
# The image is built with VITE_API_URL=/api, so this runs the exact
# artifact the compose stack ships. Docker is required for the container
# mode (the repo's convention: the strongest gates run on CI where docker
# exists; this box runs the offline --dist mode).
set -euo pipefail

IMAGE="outpost-web:ci"
HOST="localhost"
DIST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --host)  HOST="$2"; shift 2 ;;
    --dist)  DIST="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -n "$DIST" ]]; then
  echo "== offline artifact check (--dist $DIST, no docker) =="
  IDX="$DIST/index.html"
  [[ -f "$IDX" ]] || { echo "  FAIL: $IDX missing" >&2; exit 1; }
  grep -q 'id="root"' "$IDX" || { echo "  FAIL: SPA shell marker (id=\"root\") not in index.html" >&2; exit 1; }
  echo "  OK: SPA shell marker present"
  ASSETS=$(grep -oE '/assets/[A-Za-z0-9._-]+\.(js|css)' "$IDX" | sort -u)
  [[ -n "$ASSETS" ]] || { echo "  FAIL: no /assets/* chunks referenced" >&2; exit 1; }
  MISSING=0
  while IFS= read -r a; do
    f="$DIST$a"
    if [[ ! -f "$f" ]]; then echo "  FAIL: referenced asset missing: $a" >&2; MISSING=1; fi
  done <<< "$ASSETS"
  if [[ $MISSING -eq 1 ]]; then exit 1; fi
  echo "  OK: all $(echo "$ASSETS" | wc -l | tr -d ' ') referenced chunks exist on disk"
  echo "offline artifact check passed"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not available — the container smoke test runs on CI (Deploy job)." >&2
  echo "Locally, use --dist <frontend/dist> for the offline artifact check." >&2
  exit 3
fi

NAME="outpost-web-smoke-$$"
echo "== smoke-testing $IMAGE with --network none (name $NAME) =="

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --network none --name "$NAME" \
  -e "OUTPOST_HOST=$HOST" \
  "$IMAGE" >/dev/null

# Assertion 1: no crash-loop.
RC=$(docker inspect --format '{{.RestartCount}}' "$NAME")
[[ "$RC" == "0" ]] || { echo "  FAIL: container restarted ($RC times) — boot crash" >&2; docker logs "$NAME" 2>&1 | tail -20 >&2; exit 1; }
echo "  OK: container started cleanly (RestartCount=0)"

# Assertion 6 (early, cheap): the namespace really is empty.
ROUTES=$(docker exec "$NAME" cat /proc/net/route 2>/dev/null | tail -n +2 | tr -d ' \t')
if [[ -n "$ROUTES" ]]; then
  echo "  FAIL: unexpected route entries in empty namespace:" >&2
  echo "$ROUTES" >&2
  exit 1
fi
echo "  OK: /proc/net/route empty — no device besides loopback (zero egress)"

# Helper: fetch a URL inside the container and print the HTTP status line.
status() { # status <url> -> HTTP/1.1 200 OK (busybox wget -S prints headers to stderr)
  docker exec "$NAME" wget -S -q -O /dev/null "$1" 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]+' | tail -1
}

# Readiness: Caddy must answer on loopback before any assertion.
for i in $(seq 1 30); do
  if [[ "$(status "http://127.0.0.1/")" == *" 200"* ]]; then break; fi
  sleep 1
done
S=$(status "http://127.0.0.1/")
[[ "$S" == *" 200"* ]] || { echo "  FAIL: Caddy never answered on loopback (got '$S')" >&2; docker logs "$NAME" 2>&1 | tail -20 >&2; exit 1; }

# Assertion 2: SPA shell.
HTML=$(docker exec "$NAME" wget -q -O - "http://127.0.0.1/")
echo "$HTML" | grep -q 'id="root"' || { echo "  FAIL: SPA shell marker missing from served index.html" >&2; exit 1; }
echo "  OK: GET / -> 200, SPA shell present"

# Assertion 3: every referenced chunk serves.
ASSETS=$(echo "$HTML" | grep -oE '/assets/[A-Za-z0-9._-]+\.(js|css)' | sort -u)
[[ -n "$ASSETS" ]] || { echo "  FAIL: no /assets/* chunks in served index.html" >&2; exit 1; }
BAD=0
while IFS= read -r a; do
  S=$(status "http://127.0.0.1$a")
  [[ "$S" == *" 200"* ]] || { echo "  FAIL: $a -> $S" >&2; BAD=1; }
done <<< "$ASSETS"
if [[ $BAD -eq 1 ]]; then exit 1; fi
echo "  OK: all $(echo "$ASSETS" | wc -l | tr -d ' ') referenced chunks serve 200"

# Assertion 4: the /api proxy is live; the sibling backend is absent here.
S=$(status "http://127.0.0.1/api/health")
[[ "$S" == *" 502"* ]] || { echo "  FAIL: expected 502 from /api (proxy live, backend absent) — got '$S'" >&2; exit 1; }
echo "  OK: /api/health -> 502 (proxy wired, backend container not in this namespace)"

# Assertion 5: TLS listener on 443 (internal CA for localhost, no ACME).
S=$(status "https://127.0.0.1/") || true
[[ "$S" == *" 200"* ]] || { echo "  FAIL: HTTPS did not serve 200 (got '$S')" >&2; exit 1; }
echo "  OK: https://127.0.0.1/ -> 200 (TLS up, internal CA, no ACME)"

echo "✓ smoke: $IMAGE boots and serves with the network namespace empty"
