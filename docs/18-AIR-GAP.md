# Air-Gap Guarantees

What OutPost promises when the network is blocked, which gate proves each
promise, and how to run every check standalone. The claim, stated plainly:

> **With no API keys and no operator action, the webapp, backend, and CLI
> make zero external HTTP requests. The frontend renders identically with
> the network fully blocked (~0.22 s median / ~0.32 s worst-case cold start
> on a small store, ~0.36 s worst case on the real 71-run soak store), and
> the only outbound calls the backend ever makes are opt-in: they fire only
> when an operator configures a key, a feed URL, or a webhook target.**

## The four gates + the measurement

| # | Gate | Proves | Command |
|---|---|---|---|
| 1 | `gate_airgap_artifacts.py` | The **shipped build** (dist/index.html + every JS/CSS chunk) contains no external dependency syntax — external origins in `src`/`href`/`url()`/`@import`, and `fetch`/`EventSource`/`WebSocket`/`xhr.open`/`import(` with an external literal. Covers every lazy-loaded chunk statically (the Playwright e2e gates only exercise two flows). Matches dependency syntax, so demo data / doc links / webhook examples can't false-positive. | `python scripts/gate_airgap_artifacts.py` |
| 2 | `gate_cli_network.py` | The **CLI** is loopback-only: a static AST scan (HTTP only via the `lib/api_client.py` seam, no raw sockets) plus a runtime 9-command matrix under a socket-blocking patch, with a negative control proving the patch bites. | `python scripts/gate_cli_network.py` |
| 3 | `gate_backend_egress.py` | The **backend/collectors egress contract**: `httpx` is the only permitted client, only in the 8 sanctioned (key/config-gated) modules; `requests`/`urllib`/`aiohttp`/raw sockets anywhere else fail; **no shell-out exfiltration** (`subprocess`/`os.system`/`os.popen`/`pty` are forbidden in the backend, and in collectors only `common/snapshot.py` may shell out — for local read-only commands like `tasklist`/`netstat`/`ps`, never a network-capable binary); collectors may use `requests` only in `common/shipper.py`. | `python scripts/gate_backend_egress.py` |
| 4 | `gate_backend_no_config_egress.py` | The runtime half, four phases: (a) with a fresh DB and env keys cleared, the routine **background flows** (run create → ingest → complete → detail → sample upload → sandbox demo detonation) make **zero httpx calls** — the httpx client itself is patched to record and block any non-loopback URL; (b) a negative control (dummy AbuseIPDB key + force-refresh) MUST make the probe observe `api.abuseipdb.com`; (c) **the enrichment cache keeps egress rare** — after that one refresh, repeated reads of the same run are silent (TTL cache hit); (d) **webhook delivery is target-limited** — a configured webhook + watchlist hit reach exactly the operator-configured URL and nothing else. | `python scripts/gate_backend_no_config_egress.py` |
| — | `demo/measure-airgap-load.mjs` | Measured cold start: production build, cache disabled, network modes baseline / airgap (external names fail fast) / black-hole (external hangs 25 s). Result: **~0.22 s median / ~0.32 s worst case** on the small store, **~0.36 s worst case on the real 71-run/560-alert soak store** — zero external attempts, zero hung requests, and the budget is now genuinely enforced (`--max-interactive <ms>`; `airgap-verify.sh` used to echo it without passing it). | `node demo/measure-airgap-load.mjs --web http://localhost:5174` |

## The runtime e2e gates

Both Playwright behavioral gates treat **any non-localhost HTTP request as a
console error and fail the sweep** — the same air-gap rule enforced in a real
browser against the live stack:

- `demo/e2e-alert-lifecycle.mjs` — Overview → run detail → triage round-trip.
- `demo/e2e-live-monitor.mjs` — auto-detect → live detonation → toasts.

## One-shot bundle

```bash
bash scripts/airgap-verify.sh --gates-only      # gates 1–4, no servers needed
bash scripts/airgap-verify.sh --web http://<host>:5174 --max 1000   # + latency budget
```

Runs gates 1–4 in sequence, then the cold-start harness against a live stack,
failing if the worst interactive render exceeds the budget (default 1000 ms).

The shipped-image smoke test runs standalone too:

```bash
bash scripts/smoke-web-image.sh --image outpost-web:ci   # container smoke (needs docker, CI-only)
bash scripts/smoke-web-image.sh --dist frontend/dist     # offline artifact check (no docker)
```

## Offline proof in CI (the strongest layer)

The `Air-gap` CI job builds `deploy/Dockerfile.airgap-ci` (full stack: backend
venv, frontend production build, Playwright+Chromium) and then runs
`scripts/airgap-offline.sh` inside a container launched with
**`docker run --network none`** — the network namespace is empty, so only
loopback exists and any attempt to reach an external host fails at the OS
level, regardless of library or technique. The script boots the backend
(with `CORS_ORIGINS` matching the frontend origin), seeds the campaign pair
plus a live-sourced run, boots the production preview, and runs the four-gate
bundle (with the latency budget) plus both Playwright e2e gates. This is the
runtime proof that the in-process probes simulate: the empty namespace makes
it real, on every push.

**The job runs at production volume.** `OUTPOST_OFFLINE_VOLUME=1` seeds a
deterministic ~11k-event store (`scripts/seed_volume.py`, schema created by
the app itself so it can never drift) and runs the whole bundle against it —
the guarantee is proven at production scale on every push, not just on a tiny
fixture. `OUTPOST_OFFLINE_DB=<path>` boots against a COPY of any given DB
(the original is never opened in place).

**The shipped production image gets its own empty-namespace smoke test.**
The air-gap job proves the full stack inside a *test-harness* image — but
the harness is not what users run. The `Deploy` job's smoke step
(`scripts/smoke-web-image.sh`) runs the **actual `deploy/Dockerfile.web`
artifact** under `docker run --network none` and asserts, from inside the
container via `docker exec` loopback (port publishing is impossible with an
empty namespace, so probing must be in-namespace): the container boots
without crash-looping, Caddy serves the SPA (`GET /` → 200 with the shell
marker), every `/assets/*` chunk referenced by the served `index.html`
returns 200, the `/api` proxy is live (502 — the sibling backend container
isn't on this namespace, which is the honest isolated-state signal), and
`/proc/net/route` inside the container is empty — the OS-level zero-egress
assertion. If the entrypoint ever tries to reach out at boot (license ping,
update check, ACME against a public CA), the empty namespace fails it
immediately.

The container runs with `OUTPOST_HOST=http://localhost` — the `http://`
scheme disables Caddy's automatic HTTPS for the smoke run. Caddy's
auto-HTTPS would otherwise 308-redirect every plain-HTTP request to
`https://` (the production behavior, which the first CI run of this step
proved live), turning loopback status assertions into assertions about the
redirect instead of about serving; ACME is also impossible inside an empty
namespace. Same image, same Caddyfile, one env knob — production TLS stays
covered by `caddy validate` in the same Deploy job.

**The backend container gets the same treatment.** `scripts/smoke-backend-image.sh`
runs the actual `backend/Dockerfile` API image under `docker run --network
none` with NO env vars — the zero-config default — and asserts, through the
app's own python runtime via `docker exec` loopback (slim has no wget):
the container boots without crash-looping, `/proc/net/route` is empty (the
OS-level zero-egress assertion, so a license ping or update check in the
entrypoint would fail immediately), `/health` returns 200, `/meta` reports
`demo_mode:false` (a fresh backend never masquerades demo data), and
`/runs` returns a 200 JSON array. Production fail-closed auth is asserted
separately by the post-deploy walk (401 without a token, 200 with admin,
agent token restricted to telemetry), so this smoke isolates the
boot + serve + zero-egress contract for the API side of the stack.

The volume run earned its keep immediately: the 11k/real-soak runs surfaced a
15 MB `/campaigns` response (~1.06 s — the timeline query shipped every
`raw_record` for all member runs) that the tiny-store runs never saw.
Fixed: the campaign timeline is now a projected column list capped at the 300
most recent rows with an honest `timeline_total`, cutting the endpoint to
~0.2 s / ~1.7 MB and the whole-page worst-case cold start from ~1.5 s to
~0.44 s on the real soak store. (The latency budget was also found decorative
— `airgap-verify.sh` echoed it but never passed it to the harness; it now
enforces it via `--max-interactive`, small-store runs on 1000 ms, volume runs
on the documented 1500 ms deployment budget.)

**The cold start was then profiled and cut further — the ~0.41 s honest
number was dominated by data-fetch contention, not rendering.** Five SSE
subscribers (three in the shell alone) each held a permanent connection on
the 6-slot HTTP/1.1 pool, so the Overview's session-count query queued behind
them (measured: `/runs` didn't leave the browser until 165–300 ms), and the
count then landed as a re-render that waited behind the whole Overview mount
(bimodal 320–540 ms). Fixes, all verified with a 12-sample cold-start
distribution on the real store: (1) a **shared stream hub** — one
`EventSource`, fanned out to every subscriber (`lib/streamHub.ts`), freeing
three pool slots; (2) **module-scope prefetch** of both session-count queries
so they grab the first pool batch (~66 ms); (3) **warm mount** — the shell
`await`s those prefetches (capped 200 ms) before rendering, so the status-bar
count is in the first commit instead of a queued re-render. Result: median
**228 ms**, p80 303 ms, worst 361 ms on the real store (was ~410 ms honest),
and the offline bundle's enforced worst case is now **~0.32 s** on the small
store.

## Self-hosted by design

- **Fonts** — IBM Plex Sans/Mono ship in the bundle (`frontend/public/fonts/`,
  local `@font-face`); no Google Fonts CDN. (A gstatic CDN 404 once failed CI —
  the fonts are self-hosted and the artifact gate would now catch the link
  class at build time.)
- **Storage** — SQLite locally; no telemetry, update check, or license ping.
- **No mobile layout** — desk tool, "best viewed 1024px+".

## The only egress, and when it fires

All outbound calls are backend-side, `httpx`, and gated:

| Call | Fires when | Gate |
|---|---|---|
| Threat-intel enrichment (AbuseIPDB / VirusTotal / abuse.ch) | an operator sets the API key | #3, #4 (cache keeps repeat lookups offline) |
| Sandbox detonation (Any.Run / Triage / Joe) | a provider key is set; else labeled local demo (no egress) | #3, #4 |
| Passive DNS / RDAP (crt.sh) | an operator runs a Footprint lookup | #3 |
| Webhook / email notifications | an operator configures a target | #3 |
| Agent shippers | stream to the org's own backend (`OUTPOST_API_URL`) | #3 |

## History

The gates were added in response to real CI flakes and audits, in order:
e2e gates treat non-localhost as errors (#20) → fonts self-hosted (#19) →
static artifact gate (#24) → CLI network gate (#22) → backend egress gate
(#25) → backend no-config runtime gate + cache phase (#26).
