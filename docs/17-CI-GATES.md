# CI Gates & Branch Protection

How `main` stays green and why a stale badge — or any red check — cannot merge.
See [18-AIR-GAP.md](18-AIR-GAP.md) for the consolidated air-gap guarantees
(the four gates + the measurement, and how to run each standalone).

## The gate stack (in order)

Every push to `main` and every pull request runs the `CI` workflow
(`.github/workflows/ci.yml`) with three parallel jobs:

| Job | What it runs | Fails on |
|---|---|---|
| `verify.sh — backend · collectors · CLI · frontend` | Fast-fail ladder, then the full sweep | stale badges/README claims, tsc errors, failing pytest/vitest, collector FP-baseline soaks, layout overflow, post-deploy walk |
| `Deploy — web image + Caddyfile + compose` | Production image build + **smoke-tests of the shipped images under `--network none`** — `scripts/smoke-web-image.sh` runs the actual `Dockerfile.web` artifact with an empty namespace (must boot, serve the SPA + every referenced chunk, keep the `/api` proxy live, and show an empty `/proc/net/route`), and `scripts/smoke-backend-image.sh` does the same for the `backend/Dockerfile` API container (must boot, serve `/health` + `/meta` with `demo_mode:false` + `/runs` over loopback via its own python runtime, empty `/proc/net/route`). The web smoke also has an **end-to-end phase** (`--with-backend`): a second web container (same image) joins a docker `--internal` shared network (no external route by construction; a `--network none` container cannot be attached to another network — docker forbids it — so the strict empty-namespace proof stays on its own container), starts with the backend absent so `/api/health` is an honest 502, then the real backend container joins the same network and `/api/health` **flips 502 → 200** in that same container, with `/api/runs` returning a 200 JSON array through the proxy — while a socket connect from the backend to a TEST-NET address still fails, proving the pair cannot reach outside the host. Then `scripts/walk-compose-stack.sh` brings up the **actual `deploy/docker-compose.prod.yml` stack** (real Caddy image + real backend container, `OUTPOST_HOST=localhost` so Caddy auto-HTTPS serves its internal CA) and walks the four post-deploy checklist items over real TLS — `/api/health` → ok through the proxy, `/api/runs` 401 without / 200 with an admin token, `/auth/login` + `/auth/me` enabled, and the agent-token flow (heartbeat 401 bare / 200 with the token + host online on `/api/agents`, token refused outside telemetry → 403). This is the leg that proves the compose file, its env interpolation, and the Caddy → backend wiring as the shipped containers — complementing the docker-less post-deploy walk in verify.sh. An **image-size gate** (`scripts/check-image-size.sh`) runs right after the web image build: the runtime image is multi-stage slim (caddy:2-alpine + dist only), so its size is a sharp bloat detector — growth past the 100 MB soft budget **warns** (printed + written to the run summary, exit 0) and past the 150 MB hard ceiling **fails** the job (a leaked build stage / node_modules dwarfs the base in one step; budgets tunable via `--budget-mb`/`--fail-mb`, measured size printed every run for calibration; when the hard ceiling trips, the script dumps the **top layers by size** (`docker history`) so the offending layer — a giant COPY, an npm/pip install, a leaked venv — is identifiable in the CI log instead of a bare number). The **backend image gets the same gate** (`outpost-backend:ci`, soft 300 MB / hard 400 MB — python:3.12-slim base + pip runtime deps + the app package only). Plus Caddyfile/compose config validation | Dockerfile/Caddyfile/compose drift; a shipped image that fails to boot or serves nothing; a proxy that can't reach the real backend; the compose stack failing to come up fail-closed |
| `Air-gap — full bundle in a --network none container` | Builds `deploy/Dockerfile.airgap-ci`, then `docker run --network none` runs `scripts/airgap-offline.sh` **at production volume** (`OUTPOST_OFFLINE_VOLUME=1` seeds a deterministic ~11k-event store): the four-gate bundle + cold-start budget + both e2es with the network namespace EMPTY, against production-scale data | any external host reachable by any library or technique (OS-level proof, not a simulation); a >1000 ms (1500 ms at volume) cold start |

Inside the verify job, three fast-fail tiers front-load the expensive checks
so the cheapest signal fails first. The sweep itself is 19 steps; beyond the
suites it includes the **identity gate** (`scripts/gate_proc_identity.py`) —
an AST scan of the detection/process-tree/baseline/CLI-rendering modules that
fails if any event-level `process_name` read lacks an `exe_path` resolution,
locking the process-identity fallback so a future rule can't silently regress
to name-only matching that skips nameless rows — and the **CLI network gate**
(`scripts/gate_cli_network.py`): a static AST scan proving HTTP only flows
through the env-configured api seam (`lib/api_client.py` + the two sanctioned
callers), plus a runtime proof that boots an isolated backend, seeds it, and
runs a 9-command CLI matrix under a loopback-only socket patch — any connect
outside loopback fails the sweep, and a negative control (an external-base
command that must be blocked) proves the patch can't go vacuously green —
and the **air-gap artifact gate** (`scripts/gate_airgap_artifacts.py`): a
static scan of the *shipped* build (`dist/index.html` + every asset chunk)
for external dependency syntax — external origins in `src`/`href`/`url()`/
`@import` (the class that once shipped `fonts.gstatic.com` links) and
`fetch`/`EventSource`/`WebSocket`/`xhr.open`/`import(` with an external
literal in any lazy-loaded chunk. It matches dependency syntax, not raw URL
strings, so demo data, doc links, and webhook examples can't false-positive;
this closes the gap where the Playwright e2e gates only exercise two flows
while the static scan covers every chunk in milliseconds — and the
**backend egress gate** (`scripts/gate_backend_egress.py`): an AST scan of
`backend/app` + `collectors` locking the server-side egress contract. The
backend *does* make outbound calls by design, but every one is opt-in — it
fires only when an operator configures a key (enrichment / sandbox / passive
DNS), a feed URL, or a webhook target. The gate asserts `httpx` is the only
permitted client and only inside the 8 sanctioned modules;`requests` / `urllib` / `aiohttp` / raw `socket.socket` anywhere else fail the
sweep, and in the collectors `requests` may appear only in `common/shipper.py`
(the seam targeting the env-configured `OUTPOST_API_URL`). The static gate
proves *where* httpx may live; the **backend no-config egress gate**
(`scripts/gate_backend_no_config_egress.py`) proves *when* it may fire: it
boots the app in-process with a fresh DB and the env keys cleared, patches the
httpx client itself to record and block any non-loopback URL, and drives the
routine background flows (run create → ingest → complete → detail → sample
upload → sandbox demo detonation) — zero config must mean zero httpx calls.
A negative control sets a dummy AbuseIPDB key and force-refreshes one IP:
the probe MUST observe the provider URL, proving the patch bites and keyed
paths really would egress — a third phase proves the **enrichment cache
keeps egress rare** (after that single refresh, repeated reads of the same
run are silent), and a fourth proves **webhook delivery is target-limited**
(a configured webhook + watchlist hit reach exactly the operator-configured
URL and nothing else). The static egress gate also forbids **shell-out
exfiltration**: `subprocess`/`os.system`/`os.popen`/`pty` are banned in the
backend, and in collectors only `common/snapshot.py` may shell out — for
local read-only commands (`tasklist`/`netstat`/`ps`), never a network-capable
binary. A one-shot bundle, `scripts/airgap-verify.sh`, runs all four gates
plus the cold-start latency harness against a live stack (failing if
interactive render exceeds a budget).

1. **`npx tsc --noEmit`** (~1 min in) — frontend type errors fail before the
   Playwright download.
2. **`bash scripts/refresh-badges.sh --check`** (~1.5 min in) — a stale badge
   or README count fails before the 3.5-min sweep. Collect-only
   (`pytest --collect-only` + `vitest list`), so it costs seconds.
3. **`bash verify.sh`** — the full sweep (tests, soaks, layout sweep,
   post-deploy walk, badge refresh gate).

A dedicated `Refresh dynamic badges` job runs on the **weekly schedule and
`workflow_dispatch` only** — it recomputes the four badge payloads from
`main` and commits any change, so badges self-heal without a code push.

### Image-size budgets — measured baselines

The size-gate budgets are grounded in real CI measurements, not guesses:

| Image | Measured (first run) | Soft budget (warn) | Hard ceiling (fail) |
|---|---|---|---|
| `outpost-web:ci` (caddy:2-alpine + dist only) | **60 MB** (63,742,559 B, commit `9e127aa`) | 100 MB | 150 MB |
| `outpost-backend:ci` (python:3.12-slim + pip deps + app) | **191 MB** (200,772,677 B, commit `326f97c`) | 300 MB | 400 MB |
| `outpost-airgap-ci` (test harness: node:22 + python3 + venv + frontend deps + Playwright/Chromium) | **1724 MB** (1,807,945,795 B, commit `f4f4ddf`) | 2048 MB | 2560 MB |

> **Last measured:** `outpost-web:ci` 60 MB — badge job @ `9e127aa` (2026-08-14).
> **Last measured:** `outpost-backend:ci` 191 MB — badge job @ `326f97c` (2026-08-14).
> **Last measured:** `outpost-airgap-ci` 1724 MB — badge job @ `f4f4ddf` (2026-08-14).

**Enforced statically:** verify.sh's `Image budgets` step runs
`scripts/gate_image_budget_docs.py` — every `check-image-size.sh`
invocation in `.github/workflows/ci.yml` (resolving the script's own
defaults when a step passes no flags) must match its row here, the
measured column must match `badges/image-sizes.json`, a row with no gate
step is drift too, and **every table row must carry its own `Last
measured` stamp line** — a fourth image can't be documented without its
trend data. Changing a budget in either file fails the sweep.

**Calibrate-on-first-run procedure:** every run prints the measured size, so
when a baseline legitimately shifts — a base-image major bump, a new runtime
dependency, a new image — take the freshly measured number, adjust
`--budget-mb`/`--fail-mb` in the Deploy/air-gap jobs (and this table), and
let the next run confirm. The headroom is deliberate: the shipped images sit
at ≈ 1.6–1.7× their baseline (absorbing legitimate growth while still
catching a layer-scale leak — node_modules / venv / test fixtures add
hundreds of MB in one step); the air-gap harness sits tighter at ≈ 1.19×
because its growth sources are lockfile-pinned, so a >300 MB jump means
something structural (a second Playwright browser, apt creep). A budget
should only be raised with a measurement in hand — never pre-emptively.

## Branch protection on `main`

`main` is protected with **required status checks**:

- **Required checks**: `verify.sh — backend · collectors · CLI · frontend`,
  `Deploy — web image + Caddyfile + compose`, and
  `Air-gap — full bundle in a --network none container` (a red offline
  air-gap run blocks merging, exactly like the verify sweep)
- **Strict mode**: on (branches must be up to date with `main` before merge)
- **Admins**: not enforced (admins can still merge in emergencies)

The badge gate is *enforceable* because the fast-fail runs inside the
required `verify.sh` check: a PR that carries a stale
`badges/tests.json` (or a README count that no longer matches reality) goes
red on that check, and branch protection refuses the merge. The same rule
blocks broken frontend builds, failing tests, and soak-FP regressions.

### The trap to avoid

Never add `Refresh dynamic badges` to the required checks. That job only
runs on `schedule`/`workflow_dispatch`, so it never appears on a PR — a
required check that never runs makes every PR permanently unmergeable.

## Auto-merge policy: green PRs merge themselves

The repo has `allow_auto_merge` enabled, so a PR merges **automatically the
instant the two required checks pass** — no human click needed. Combined
with strict mode, only fully-green, up-to-date PRs ever merge.

Per PR, the author opts in with one command:

```bash
gh pr merge <number> --auto --squash
```

(or the **Enable auto-merge** button in the PR sidebar). The PR then waits
for the required checks to pass and merges itself; the "Auto-merge will
merge this pull request when all required checks pass" state is visible on
the PR. No required reviews are configured, so green = merge.

Why auto-merge instead of a merge queue: GitHub's merge queue is not
exposable through the REST/GraphQL API (it is a UI-only branch setting), so
it cannot be applied as a repo policy from a script. Auto-merge achieves the
same outcome — "merge when green, without waiting" — and is the right scale
for a solo-maintainer repo. (If fleet-scale concurrent merging is ever
needed, enable the queue in the branch-protection UI and keep this policy.)

Notes:
- The badge-refresh bot lands **via a PR with auto-merge armed**, like every
  other change. A direct push would be rejected by the required checks
  (GH006 — the refresh job proved this the first time it tried after the
  rule was enforced): a locally-created bot commit never ran the checks, so
  the weekly job opens `chore/badges-*`, arms `--auto --squash`, and the
  gate merges it once verify + deploy + air-gap pass.
- **One-time repo setting required** for the bot to create its PR: GitHub
  disables Actions-created PRs by default. Enable *Settings → Actions →
  General → Workflow permissions → Allow GitHub Actions to create and
  approve pull requests* (UI-only; there is no REST API for it — the
  refresh job fails with a clear message until it's on). The job also needs
  `pull-requests: write` in its permissions block, which the workflow
  already declares.
- Admin bypass still applies: `enforce_admins` is false, so an admin can
  force-merge a red PR with `gh pr merge --admin` in an emergency.

To make this the default for every new PR, use the helper:

```bash
bash scripts/new-pr.sh "Title of the PR" "Optional body"
```

It pushes the current branch, opens the PR, and arms `--auto --squash` in
one step (refuses to run from a detached HEAD or `main`).

### If you ever need the merge queue (high-volume weeks)

GitHub's merge queue **cannot be enabled through the REST or GraphQL API**
— it is a UI-only branch setting (verified by schema introspection: the
protection-rule mutation exposes no queue field). If concurrent merges ever
need sequential re-testing against the latest `main`, enable it by hand
once:

1. Repo **Settings → Branches → edit** the `main` protection rule.
2. Tick **Require merge queue** (it becomes available once required status
   checks are set, as they are here).
3. The merge button becomes **Merge when ready** — PRs enter the queue,
   are re-tested against the latest `main`, and merge in order. Pair it
   with `gh pr merge --auto` so green PRs enter the queue without a click.

The queue adds serialization overhead (each PR is built/tested once more in
the queue), so for a solo maintainer, plain auto-merge remains the better
default — this is the policy to keep unless merge traffic grows.

## Inspecting / changing the rule

```bash
# Read the current protection rule
gh api repos/kripy17/OutPost/branches/main/protection

# Replace the required checks (verify + deploy, strict, admins not enforced)
gh api -X PUT repos/kripy17/OutPost/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "verify.sh — backend · collectors · CLI · frontend",
      "Deploy — web image + Caddyfile + compose"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": false
}
JSON
```

Check names must match GitHub's registered runs exactly (the em-dash and
`·` characters included). List them with:

```bash
gh api repos/kripy17/OutPost/commits/<sha>/check-runs -q '.check_runs[].name'
```
