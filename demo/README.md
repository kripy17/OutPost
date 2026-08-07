# OutPost — automated webapp demos

Two Playwright demo scripts live here:

| Script | Flow | Output |
|---|---|---|
| [`shelf-stack-demo.mjs`](shelf-stack-demo.mjs) | Campaign arc: detonate → search → compare → watchlist → rules (see [`../13-CAMPAIGN-DEMO.md`](../13-CAMPAIGN-DEMO.md)) | screenshots per step |
| [`deck-demo.mjs`](deck-demo.mjs) | The redesigned SOC deck in 4 acts: Overview pan → Sample vault (library + detail) → Monitor detonation → run detail (risk gauge, kill chain, process-tree halos, timeline, analyst notes, detection rules) | **`deck-demo.webm`** video (cursor + subtitles) + 19 per-step screenshots |

## One-time setup

```bash
cd demo && npm i
```

Playwright's bundled Chromium can be installed with `npx playwright install
chromium`, or the script will use your system Google Chrome automatically.

## Prereqs per run

- Backend on **8001** and frontend on **5174** (see `../.freebuff/run.md`).
- The campaign pair seeded:

  ```bash
  cd backend && python -m app.seed_campaign
  ```

## Run

```bash
cd demo && node shelf-stack-demo.mjs          # visible browser (default)
HEADLESS=1 node shelf-stack-demo.mjs          # no visible browser (CI-friendly)
```

The detonation step streams a fresh sample through the Monitor page and waits
for it to complete (~25 s); the whole run takes ~1 minute. Screenshots land in
`demo/screenshots/`:

| File | Step |
|---|---|
| `01-detonate-live.png` | toast stream + live tree mid-detonation |
| `01-detonate-complete.png` | finished analysis |
| `02-search.png` | shared-C2 IOC search across the three samples |
| `03-compare.png` | variant A vs B diff (only-A / shared / only-B) |
| `04-watchlist.png` | C2 added to the personal watchlist |
| `05-c2-star.png` | ★ badge on the C2 in a run's network table |
| `05-rules-suricata.png` / `05-rules-sigma.png` | generated detection rules |

---

## Deck demo (redesign footage)

```bash
cd demo && node deck-demo.mjs            # record (headless, dark deck)
node deck-demo.mjs --rehearse            # verify selectors, no recording
```

Records **`demo/deck-demo.webm`** (~2 min, 1440×900) plus stills in
`demo/screenshots/deck/` — 01–06 Overview (stat strip, risk timeline,
detection volume, findings, quick actions), 07–08 Monitor detonation (live
toast stream → complete), 09–15 run detail (top, kill chain, process tree,
network, timeline, notes, rules). The dark command-deck theme is forced via
`colorScheme: dark` + a seeded `outpost-theme` localStorage so footage looks
identical regardless of OS preference. Detonation streams a fresh sample and
the run detail act follows *that* run, so every recording captures a live
analysis. No campaign seed needed.

## Options (env vars)

| Var | Default | Purpose |
|---|---|---|
| `WEBAPP_URL` | `http://localhost:5174` | frontend origin |
| `API_URL` | `http://localhost:8001` | backend origin |
| `C2_IP` | `203.0.113.88` | the campaign C2 to search / watchlist |
| `C2_LABEL` | `Shelf-Stack C2` | watchlist label |
| `HEADLESS` | off | `1` for headless (`deck-demo` records headless by default; `HEADLESS=0` for a visible browser) |

The script deletes any stale watchlist entry for `C2_IP` before step 4, so
re-runs are idempotent. `demo/screenshots/` is generated output — safe to
delete or gitignore.
