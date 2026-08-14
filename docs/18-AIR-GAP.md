# Air-Gap Guarantees

What OutPost promises when the network is blocked, which gate proves each
promise, and how to run every check standalone. The claim, stated plainly:

> **With no API keys and no operator action, the webapp, backend, and CLI
> make zero external HTTP requests. The frontend renders identically with
> the network fully blocked (~0.3 s worst-case cold start), and the only
> outbound calls the backend ever makes are opt-in: they fire only when an
> operator configures a key, a feed URL, or a webhook target.**

## The four gates + the measurement

| # | Gate | Proves | Command |
|---|---|---|---|
| 1 | `gate_airgap_artifacts.py` | The **shipped build** (dist/index.html + every JS/CSS chunk) contains no external dependency syntax — external origins in `src`/`href`/`url()`/`@import`, and `fetch`/`EventSource`/`WebSocket`/`xhr.open`/`import(` with an external literal. Covers every lazy-loaded chunk statically (the Playwright e2e gates only exercise two flows). Matches dependency syntax, so demo data / doc links / webhook examples can't false-positive. | `python scripts/gate_airgap_artifacts.py` |
| 2 | `gate_cli_network.py` | The **CLI** is loopback-only: a static AST scan (HTTP only via the `lib/api_client.py` seam, no raw sockets) plus a runtime 9-command matrix under a socket-blocking patch, with a negative control proving the patch bites. | `python scripts/gate_cli_network.py` |
| 3 | `gate_backend_egress.py` | The **backend/collectors egress contract**: `httpx` is the only permitted client, only in the 8 sanctioned (key/config-gated) modules; `requests`/`urllib`/`aiohttp`/raw sockets anywhere else fail; **no shell-out exfiltration** (`subprocess`/`os.system`/`os.popen`/`pty` are forbidden in the backend, and in collectors only `common/snapshot.py` may shell out — for local read-only commands like `tasklist`/`netstat`/`ps`, never a network-capable binary); collectors may use `requests` only in `common/shipper.py`. | `python scripts/gate_backend_egress.py` |
| 4 | `gate_backend_no_config_egress.py` | The runtime half, four phases: (a) with a fresh DB and env keys cleared, the routine **background flows** (run create → ingest → complete → detail → sample upload → sandbox demo detonation) make **zero httpx calls** — the httpx client itself is patched to record and block any non-loopback URL; (b) a negative control (dummy AbuseIPDB key + force-refresh) MUST make the probe observe `api.abuseipdb.com`; (c) **the enrichment cache keeps egress rare** — after that one refresh, repeated reads of the same run are silent (TTL cache hit); (d) **webhook delivery is target-limited** — a configured webhook + watchlist hit reach exactly the operator-configured URL and nothing else. | `python scripts/gate_backend_no_config_egress.py` |
| — | `demo/measure-airgap-load.mjs` | Measured cold start: production build, cache disabled, network modes baseline / airgap (external names fail fast) / black-hole (external hangs 25 s). Result: **~0.3 s worst case**, zero external attempts, zero hung requests. `--max-interactive <ms>` turns it into a budget gate. | `node demo/measure-airgap-load.mjs --web http://localhost:5174` |

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
