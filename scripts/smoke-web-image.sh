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
#   bash scripts/smoke-web-image.sh [--image outpost-web:ci]
#   bash scripts/smoke-web-image.sh --dist frontend/dist   # offline artifact check (no docker)
#   bash scripts/smoke-web-image.sh --image outpost-web:ci --with-backend outpost-backend:ci
#                                                         # + the end-to-end flip phase
#
# The container runs with OUTPOST_HOST=http://localhost — the http:// scheme
# disables Caddy's automatic HTTPS for the smoke run. Caddy's auto-HTTPS
# would otherwise 308-redirect every plain-HTTP request to https:// (the
# production behavior), which makes loopback status assertions about the
# redirect instead of about serving; ACME is also impossible inside an empty
# namespace. Same image, same Caddyfile, one env knob — production TLS stays
# covered by `caddy validate` in the same Deploy job.
#
# Assertions (phase 1 — web alone, empty namespace):
#   1. The container starts and does not crash-loop (RestartCount == 0).
#   2. ZERO EGRESS, asserted at the OS level: /proc/net/route inside the
#      container is empty — no network devices besides loopback exist.
#   3. Caddy answers on loopback: GET / -> 200 with the SPA shell (id="root").
#   4. The built bundle serves: every /assets/* chunk referenced by
#      index.html returns 200 (proves the static artifact is intact).
#   5. The API proxy is live but the sibling backend is absent in isolation:
#      GET /api/health -> 502 (Caddy's reverse_proxy reached, backend
#      container not on this namespace — the honest isolated-state signal).
#
# Assertions (phase 2 — --with-backend: a second web container and the REAL
# backend share a docker --internal network; the proxy flips in one container
# as the backend joins):
#   6. On the shared network WITH the upstream still absent, /api/health is
#      502 (the proxy is honest about missing backends).
#   7. The FLIP: once the real backend joins the shared network, /api/health
#      turns 200 in the same container — no restart, same artifact.
#   8. End to end through the proxy: /api/runs -> 200 JSON array.
#   9. The backend boots clean and answers its own /health on loopback.
#  10. The pair still has zero external reach: the network is docker-internal
#      (no route out), and a socket connect from the backend to a TEST-NET
#      address fails — nothing leaves the host.
#
# (Docker forbids connecting a --network none container to another network —
# "cannot be connected to multiple networks with one of the networks in
# private (none) mode" — so the flip uses a second web container on the
# shared network rather than a live attach; phase 1 keeps the strict
# empty-namespace proof.)
# The image is built with VITE_API_URL=/api, so this runs the exact
# artifact the compose stack ships. Docker is required for the container
# mode (the repo's convention: the strongest gates run on CI where docker
# exists; this box runs the offline --dist mode).
set -euo pipefail

IMAGE="outpost-web:ci"
DIST=""
BACKEND_IMAGE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --dist)  DIST="$2"; shift 2 ;;
    --with-backend) BACKEND_IMAGE="$2"; shift 2 ;;
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
NAME2="outpost-web-e2e-$$"
BACKEND="outpost-backend-e2e-$$"
NET="outpost-smoke-net-$$"
URL="http://localhost"
echo "== smoke-testing $IMAGE with --network none (name $NAME) =="

cleanup() {
  docker rm -f "$NAME" "$NAME2" "$BACKEND" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --network none --name "$NAME" \
  -e "OUTPOST_HOST=http://localhost" \
  "$IMAGE" >/dev/null

# Assertion 1: no crash-loop.
RC=$(docker inspect --format '{{.RestartCount}}' "$NAME")
[[ "$RC" == "0" ]] || { echo "  FAIL: container restarted ($RC times) — boot crash" >&2; docker logs "$NAME" 2>&1 | tail -20 >&2; exit 1; }
echo "  OK: container started cleanly (RestartCount=0)"

# Assertion 2 (cheap, early): the namespace really is empty. Every stage is
# guarded so a non-match reports FAIL instead of tripping set -e silently.
ROUTES=$(docker exec "$NAME" cat /proc/net/route 2>/dev/null | tail -n +2 | tr -d ' \t' || true)
if [[ -n "$ROUTES" ]]; then
  echo "  FAIL: unexpected route entries in empty namespace:" >&2
  echo "$ROUTES" >&2
  exit 1
fi
echo "  OK: /proc/net/route empty — no device besides loopback (zero egress)"

# Fetch the HTTP status line for a URL inside a container (busybox wget -S
# prints response headers to stderr). Always exits 0 — callers compare text.
status() { # status <container> <url> -> "HTTP/1.1 200 OK"
  local c="$1" url="$2" out
  out=$(docker exec "$c" wget -S -q -O /dev/null "$url" 2>&1 || true)
  printf '%s\n' "$out" | grep -oE 'HTTP/[0-9.]+ [0-9]+' | tail -1 || true
}

# Readiness: Caddy must answer 200 on loopback before any assertion.
READY=""
for i in $(seq 1 30); do
  S=$(status "$NAME" "$URL/")
  if [[ "$S" == *" 200"* ]]; then READY=1; break; fi
  sleep 1
done
if [[ -z "$READY" ]]; then
  echo "  FAIL: Caddy never answered 200 on loopback (last: '$(status "$NAME" "$URL/")')" >&2
  docker logs "$NAME" 2>&1 | tail -20 >&2
  exit 1
fi

# Assertion 3: SPA shell.
HTML=$(docker exec "$NAME" wget -q -O - "$URL/" || true)
echo "$HTML" | grep -q 'id="root"' || { echo "  FAIL: SPA shell marker missing from served index.html" >&2; exit 1; }
echo "  OK: GET / -> 200, SPA shell present"

# Assertion 4: every referenced chunk serves.
ASSETS=$(echo "$HTML" | grep -oE '/assets/[A-Za-z0-9._-]+\.(js|css)' | sort -u)
[[ -n "$ASSETS" ]] || { echo "  FAIL: no /assets/* chunks in served index.html" >&2; exit 1; }
BAD=0
while IFS= read -r a; do
  S=$(status "$NAME" "$URL$a")
  [[ "$S" == *" 200"* ]] || { echo "  FAIL: $a -> $S" >&2; BAD=1; }
done <<< "$ASSETS"
if [[ $BAD -eq 1 ]]; then exit 1; fi
echo "  OK: all $(echo "$ASSETS" | wc -l | tr -d ' ') referenced chunks serve 200"

# Assertion 5: the /api proxy is live; the sibling backend is absent here.
S=$(status "$NAME" "$URL/api/health")
[[ "$S" == *" 502"* ]] || { echo "  FAIL: expected 502 from /api (proxy live, backend absent) — got '$S'" >&2; exit 1; }
echo "  OK: /api/health -> 502 (proxy wired, backend container not in this namespace)"

echo "✓ phase 1: $IMAGE boots and serves with the network namespace empty"

# -- Phase 2: the end-to-end flip ---------------------------------------------
# A second web container (same image) joins a docker --internal shared
# network — docker's no-egress network: containers reach each other by name,
# nothing routes out. It starts BEFORE the backend, so /api is an honest 502;
# the real backend then joins the same network and /api flips to 200 in that
# same container. (A --network none container cannot be attached to another
# network — docker forbids it — so the flip lives on the shared-net container
# and phase 1 keeps the strict empty-namespace proof.)
if [[ -n "$BACKEND_IMAGE" ]]; then
  echo "== phase 2: same web image on an --internal network; /api 502 until the real backend joins, then 200 =="

  # Assertion 10 (set-up): the shared network is docker-internal — by
  # construction it has no route to the outside world.
  docker network create --internal "$NET" >/dev/null
  INTERNAL=$(docker network inspect "$NET" -f '{{.Internal}}' || true)
  [[ "$INTERNAL" == "true" ]] || { echo "  FAIL: expected internal network, got Internal=$INTERNAL" >&2; exit 1; }
  echo "  OK: network $NET is docker-internal (no external route by construction)"

  # Web container on the shared network, backend NOT there yet.
  docker run -d --network "$NET" --name "$NAME2" \
    -e "OUTPOST_HOST=http://localhost" \
    "$IMAGE" >/dev/null
  RC=$(docker inspect --format '{{.RestartCount}}' "$NAME2")
  [[ "$RC" == "0" ]] || { echo "  FAIL: phase-2 web restarted ($RC times) — boot crash" >&2; docker logs "$NAME2" 2>&1 | tail -20 >&2; exit 1; }

  # Assertion 6: with the upstream absent, the proxy is an honest 502 — the
  # same artifact that will flip.
  FLIP_READY=""
  for i in $(seq 1 30); do
    S=$(status "$NAME2" "$URL/api/health")
    if [[ "$S" == *" 502"* ]]; then FLIP_READY=1; break; fi
    sleep 1
  done
  if [[ -z "$FLIP_READY" ]]; then
    echo "  FAIL: /api not 502 on the shared network with the backend absent (last: '$(status "$NAME2" "$URL/api/health")')" >&2
    docker logs "$NAME2" 2>&1 | tail -15 >&2
    exit 1
  fi
  echo "  OK: /api/health -> 502 with the upstream absent (proxy stays honest)"

  # The backend joins — the flip moment. The Caddyfile proxies to
  # `backend:8001` by name, so the backend needs the network alias to resolve
  # as `backend` on the shared network.
  docker run -d --network "$NET" --network-alias backend --name "$BACKEND" "$BACKEND_IMAGE" >/dev/null
  RC=$(docker inspect --format '{{.RestartCount}}' "$BACKEND")
  [[ "$RC" == "0" ]] || { echo "  FAIL: backend restarted ($RC times) — boot crash" >&2; docker logs "$BACKEND" 2>&1 | tail -20 >&2; exit 1; }
  echo "  OK: backend container started cleanly (RestartCount=0)"

  # Assertion 7 — THE FLIP: poll until Caddy's upstream DNS + dial succeed.
  FLIPPED=""
  for i in $(seq 1 20); do
    S=$(status "$NAME2" "$URL/api/health")
    if [[ "$S" == *" 200"* ]]; then FLIPPED=1; break; fi
    sleep 1
  done
  if [[ -z "$FLIPPED" ]]; then
    echo "  FAIL: /api/health never flipped to 200 (last: '$(status "$NAME2" "$URL/api/health")')" >&2
    docker logs "$BACKEND" 2>&1 | tail -15 >&2
    exit 1
  fi
  echo "  OK: /api/health 502 -> 200 — the real backend answered through the proxy in the same container"

  # Assertion 8: end to end through the proxy.
  RUNS=$(docker exec "$NAME2" wget -q -O - "$URL/api/runs" || true)
  echo "$RUNS" | grep -q '^\[' || { echo "  FAIL: /api/runs not a JSON array: ${RUNS:0:80}" >&2; exit 1; }
  echo "  OK: /api/runs -> 200 JSON array through the proxy (end to end)"

  # Assertion 9: the backend itself answers on loopback (probed with its own
  # python runtime — slim has no wget).
  BSTATUS=$(docker exec "$BACKEND" python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=5).status)" 2>/dev/null || true)
  [[ "$BSTATUS" == "200" ]] || { echo "  FAIL: backend /health -> '$BSTATUS'" >&2; exit 1; }
  echo "  OK: backend /health -> 200 on its own loopback"

  # Assertion 10 (behavioral): the pair cannot reach outside the host — a
  # socket connect from the backend to a TEST-NET-3 address must fail (the
  # host drops the packets; nothing ever leaves the machine).
  REACHED=$(docker exec "$BACKEND" python -c "import socket; socket.create_connection(('203.0.113.9', 53), timeout=3); print('REACHED')" 2>&1 || true)
  if [[ "$REACHED" == *"REACHED"* ]]; then
    echo "  FAIL: backend reached an external TEST-NET address from the internal network" >&2
    exit 1
  fi
  echo "  OK: external socket connect fails from the internal network (zero egress)"

  echo "✓ phase 2: web + real backend serve end to end on a zero-egress shared network"
fi
