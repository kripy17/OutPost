# OutPost — production deployment

Two supported paths. Both **require auth by default** (`OUTPOST_AUTH_REQUIRED=1`):
the backend fails closed and refuses to start until an admin credential is set,
so a production instance can never run open or with a forgeable token key.

---

## Path A · Docker (recommended)

One TLS-terminated stack: Caddy serves the webapp static bundle and proxies
`/api/*` to the backend (the bundle is built with `VITE_API_URL=/api`, so the
browser talks to a single origin).

```bash
cp deploy/.env.example .env.prod
$EDITOR .env.prod            # OUTPOST_HOST + OUTPOST_ADMIN_PASSWORD (required)
docker compose -f deploy/docker-compose.prod.yml --env-file .env.prod up --build -d
```

- **TLS**: public domain → Let's Encrypt automatic (port 80/443 open, domain
  resolves to this box). No domain → uncomment `tls internal` in
  `deploy/Caddyfile` (self-signed; visit with a one-time browser warning).
- **Data**: SQLite lives in the `outpost-data` volume; rebuilds and restarts
  keep every run/sample/setting.
- **Config**: every env knob is in `.env.prod` — admin/analyst passwords, the
  auth rate-limit knobs, and `OUTPOST_HOST` (also feeds CORS).
- **Rotating the admin password later**: either edit `.env.prod` and recreate
  the backend container, or use the webapp's Settings → Security (stores a
  salted PBKDF2 hash in the DB; survives without the env var).

## Path B · systemd (no Docker)

Run just the backend under systemd; serve the webapp build however you like
(Caddy/nginx static host, or `vite preview` on an internal box).

```bash
sudo cp deploy/outpost-backend.service /etc/systemd/system/
sudo mkdir -p /etc/outpost
sudo tee /etc/outpost/backend.env >/dev/null <<'EOF'
DATABASE_PATH=/opt/outpost/data/outpost.db
CORS_ORIGINS=["https://outpost.example.com"]
OUTPOST_AUTH_REQUIRED=1
OUTPOST_ADMIN_PASSWORD=CHANGE_ME
OUTPOST_AGENT_TOKEN=CHANGE_ME_TOO
EOF
sudo chmod 600 /etc/outpost/backend.env
sudo systemctl daemon-reload
sudo systemctl enable --now outpost-backend
```

Assumes the repo at `/opt/outpost` with its venv; the unit hardens the process
(`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`) and only allows writes under
`/opt/outpost/data`.

## Auth notes

- Zero-config default stays **open** for local runs (`OUTPOST_AUTH_REQUIRED`
  unset and no passwords configured) — the full test suite and `dev.sh` rely
  on this. Production sets the flag.
- Credentials are never compared as plaintext: the backend verifies against a
  salted PBKDF2-SHA256 hash. `OUTPOST_ADMIN_PASSWORD` is accepted for bootstrap
  convenience; for a secret-free env use `OUTPOST_ADMIN_PASSWORD_HASH` from
  `outpost auth hash` (see `backend/app/core/auth.py`).
- The read-only `analyst` role is optional; without it only admin logins exist.
- **Host agents**: set `OUTPOST_AGENT_TOKEN` (same value on the backend and
  every monitored host). Collectors authenticate as the `agent` role — scoped
  to telemetry only (ship events, heartbeat, claim/complete sessions, read
  run data). `outpost agent install --agent-token …` embeds it into the
  systemd unit / scheduled-task batch files. Without it, agents get 401s
  under fail-closed auth.

### Rotating the agent token

`outpost auth rotate-agent-token` rotates the credential end to end (admin
password required, prompted unless `OUTPOST_ADMIN_PASSWORD` is set):

```bash
outpost auth rotate-agent-token --backend-url https://<host>
# or with an explicit new value:  --token <new>
```

It generates (or accepts) a new token, stores it via `POST /auth/agent-token`
— the **DB-stored value immediately wins** over the env bootstrap token, so
old tokens stop working without a redeploy or restart — then re-embeds it
into this host's agent config (systemd unit / .bat files). Other monitored
hosts re-run `outpost agent install --agent-token <new>` with the printed
value. After a rotation the old `OUTPOST_AGENT_TOKEN` env is inert; remove it
on the next deploy.

## Post-deploy checklist

The first four items run automatically on every push as verify.sh's
`Post-deploy walk` step (`scripts/post_deploy_walk.py` — fail-closed backend
behind a self-signed TLS proxy, no Docker needed). On a live host, verify
manually:

1. `curl -k https://<host>/health` → `{"status":"ok"}` (TLS verified).
2. `curl -s https://<host>/api/runs` **without** a token → `401` (auth enforced).
3. Log in via the webapp (Settings → Security) with the admin password → the
   app loads real data and `/auth/me` reports `enabled: true`.
4. Deploy the agent on a monitored machine (`outpost agent install`) and watch
   it appear on the Agents page — for Windows hosts, run the
   [real-host validation checklist](../collectors/windows/README.md) first.

## Air-gapped deployment

The stack is fully self-contained at runtime — the webapp and backend make
**zero external HTTP requests** when enrichment is not configured:

- IBM Plex fonts ship in the bundle (`frontend/public/fonts/`, local
  `@font-face`) — no font CDN.
- SQLite persists locally; there is no telemetry, update check, or license
  ping to the outside world.
- This is **enforced in CI**: the Playwright e2e gates fail on any
  non-localhost request, and `scripts/gate_airgap_artifacts.py` statically
  scans the shipped build for external dependency syntax.

To deploy on a firewalled host (no outbound egress):

1. Build the images **on a connected machine** (`docker compose build`),
   then `docker save`/`docker load` them onto the host — the build needs the
   registry, the runtime does not.
2. Run the stack with no outbound routes. Only loopback is used: browser →
   Caddy (TLS) → backend → SQLite.
3. Optional egress (all config-gated — skip them and the stack runs in pure
   local mode):
   - Threat-intel enrichment (AbuseIPDB / VirusTotal / abuse.ch) and
     passive DNS (crt.sh / RDAP) — fire only when API keys are set in
     Settings, and cache results so repeated lookups stay offline.
   - Real sandbox detonation (Any.Run / Triage / Joe) — keyed providers
     only; without a key the panel falls back to the labeled local demo.
   - Webhook notifications — only to targets *you* configure.
4. Verify after boot with egress disabled:
   - the [post-deploy checklist](#post-deploy-checklist) items above, and
   - `bash scripts/airgap-verify.sh --web http://<host>:5174` — the one-shot
     bundle: all four gates (frontend artifacts, CLI network, backend
     egress, backend no-config runtime) plus the cold-start latency budget
     (≈ 0.3 s worst case on the production build; fails over 1 s). A clean
     run proves no external request is being attempted — see
     [`docs/18-AIR-GAP.md`](../docs/18-AIR-GAP.md) for the full guarantees.
