# OutPost — automated webapp demos

Two Playwright demo scripts live here:

| Script | Flow | Output |
|---|---|---|
| [`shelf-stack-demo.mjs`](shelf-stack-demo.mjs) | Campaign arc: detonate → search → compare → watchlist → rules (two samples sharing a C2 IP) | screenshots per step |
| [`deck-demo.mjs`](deck-demo.mjs) | The redesigned SOC deck in 8 acts: Overview pan → Sample vault (library + detail) → Monitor detonation → run detail (risk gauge, kill chain, process-tree halos, timeline, analyst notes, detection rules) → Findings triage queue (select → acknowledge → live badge counts → resolve, scoped to the fresh detonation) → Quality gates (History + run detail at the 1280px layout-sweep width) → the verify.sh gates run (3/3 green panel) → the air-gap story (the offline job's four gates + the measured cold-start harness, verdict panel) | **`deck-demo-trimmed.webm`** video (cursor + subtitles) + 30 per-step screenshots |

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
`demo/screenshots/` (generated per run — not checked in):

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

Records **`demo/deck-demo.webm`** (~4.5 min master, 1440×900) plus 30 stills in
`demo/screenshots/deck/` — 01–06 Overview (stat strip, risk timeline,
detection volume, findings, quick actions), 07–10 Sample vault (stats,
table, filter, detail), 11–12 Monitor detonation (live toast stream →
complete), 13–19 run detail (top, kill chain, process tree, network,
timeline, notes, rules), 20–26 Findings triage (open queue scoped to the
fresh detonation, select, acknowledge — with the live tab badges proving
queue counts stay live under the active filter — acknowledged tab, resolve,
resolved tab — the alert lifecycle), 27–28 Quality gates (the History charts
and a run detail at the 1280px layout-sweep width — the min-width bug class
the verify.sh Playwright gate catches, shown clean), 29 the verify.sh gates
run live (3/3 green panel), 30 the air-gap story (the offline job's four
gates — static artifact scan, CLI network matrix, backend egress contract,
no-config runtime egress — plus the measured cold-start harness, all run
against this very stack and rendered as a verdict panel). The dark command-deck
theme is forced via `colorScheme: dark` + a seeded `outpost-theme`
localStorage so footage looks identical regardless of OS preference.
Detonation streams a fresh sample and the run detail + findings acts follow
*that* run, so every recording captures a live analysis. No campaign seed
needed. The Monitor act needs no OS picker — the vision: the host OS is
auto-detected and the detonation targets it.

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

## Tightened cut (recommended for viewing/sharing)

```bash
.venv/bin/python demo/trim-demo.py          # -> demo/deck-demo-trimmed.webm (~150s)
.venv/bin/python demo/map-demo-pacing.py    # frame-diff pacing map (static runs + spikes)
.venv/bin/python demo/make-gif-preview.py   # -> demo/deck-demo-preview.gif (~36s loop)
.venv/bin/python demo/make-gif-preview.py --hero   # -> demo/deck-demo-hero.gif   (Overview, README)
.venv/bin/python demo/make-gif-preview.py --hero2  # -> demo/deck-demo-hero2.gif  (Monitor + run detail, README)
```

`--preset preview|hero|hero2` selects the reel; `--out` overrides the default.

`deck-demo-preview.gif` is a ~33s looping highlights reel (one window per
act — eight now, including the gates-run and air-gap acts — 480px wide /
10 fps, ffmpeg palette, ~2.3 MB) — previews the footage in any browser/git
host without a video player. Windows live in `make-gif-preview.py` (trimmed
timeline); re-run after any re-record.

`deck-demo-trimmed.webm` is the tightened edit: **269.4s → 150.3s**. The trim
cuts the ~25s detonation wait down to the live-analysis glimpse + completion,
cuts the static gate-execution blocks (the three e2e gates and the four
air-gap gates + cold-start harness run while the page holds still), trims
the hold pauses, and runs the cursor pans at 1.3–1.4× while every screenshot
hold stays ~2s at 1× (segment table lives in `trim-demo.py`, chosen against
the pacing map so no shot moment is lost — verified frame-by-frame for all
30 shots). `deck-demo.webm` is kept as the master footage; re-trim after any
re-record. Video-only (no audio), so cuts are silent-safe.
