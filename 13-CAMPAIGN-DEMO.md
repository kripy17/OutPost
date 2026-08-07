# OutPost — "Operation Shelf-Stack": three samples, one C2

A scripted webapp walkthrough for demos and portfolios. It exercises the full
dynamic-analysis workflow OutPost was built for — **detonate → search → compare
→ watchlist → rules** — all against one coherent story: two historical samples
and a live detonation that all beacon to the same C2 IP.

> **The dataset.** `backend/app/seed_campaign.py` seeds a campaign-style pair of
> completed runs that share C2 `203.0.113.88:4444` — the *same* infrastructure
> the webapp's synthetic detonation (`frontend/src/lib/synthetic.ts`) beacons
> to. So when you search that IP mid-demo, every sample in the story surfaces.

---

## The story

Last week an invoice-themed phish dropped two samples:

- **`ACME_invoice.docm`** (macro dropper) — Word launches `powershell.exe -enc`
  then `cmd.exe`, beacons to the campaign C2, drops a registry Run key, and
  also reaches a second C2 node (`185.220.101.34`) that external threat intel
  already flags as **malicious**.
- **`invoice_lure.lnk`** (LNK second-stage) — `wscript.exe` launches a hidden
  PowerShell, beacons to the *same* campaign C2, drops the same Run key, and
  finishes with a rapid file-rename burst (ransomware signature).

Today you detonate a third sample to find out if it's related.

---

## Before you start (reproducible)

1. Backend + frontend running (see `.freebuff/run.md`): API on `8001`, webapp on `5174`.
2. Seed the campaign pair — from `backend/`:

   ```bash
   python -m app.seed_campaign
   ```

   It prints the two variant run IDs and alert counts. (Already seeded? Look for
   `ACME_invoice.docm` and `invoice_lure.lnk` in the run history.)
3. Clear any stale watchlist entries for `203.0.113.88` (**Watchlist** page) so
   Step 4 starts clean.

> **Run IDs from this session** — Variant A `0302aa600d1d`, Variant B `e4f15e059839`.

---

## Automated run (Playwright)

Prefer watching it happen by hand? Skip to Step 1. Otherwise the whole
walkthrough can be driven and screenshotted automatically — great for demos,
portfolio footage, or CI:

```bash
cd demo && npm i          # once
cd backend && python -m app.seed_campaign   # ensure the pair is seeded
cd demo && node shelf-stack-demo.mjs       # or HEADLESS=1 node shelf-stack-demo.mjs
```

It runs all five steps below against the live webapp, waits for the
detonation to complete, and drops a screenshot per step into
`demo/screenshots/`. See `demo/README.md` for options (URLs, headless, C2).

---

## Step 1 — Detonate (Monitor page)

**Where:** `http://localhost:5174/monitor`

**Do:** click **▸ Detonate synthetic sample**, then watch. New alerts slide in as
toast cards (severity-colored, auto-dismissing); the process tree, network
table, and timeline update live. When the stream ends, press **Space** (or
click **End analysis**) and open **Full report →**.

**Expect:** a `detonate-demo.exe` run — `winword.exe → powershell.exe → cmd.exe`
tree; ~7 alerts across 6 rules including *"5 connections to 203.0.113.88 at
regular ~2s intervals (std-dev 0.0s)"*; the network table shows the C2 IP.

> The C2 reads `unknown` here — it has no external reputation yet and you
> haven't watchlisted it. That gap is exactly what Step 4 closes.

**Why it matters:** the webapp is a standalone dynamic-analysis workstation —
no collector, no VM: detonate a sample and watch every detection rule fire in
real time.

---

## Step 2 — IOC search: the shared C2

**Where:** `IOC Search` in the nav.

**Do:** type `203.0.113.88`, press **Search**.

**Expect:** matches from all three samples — your fresh detonation plus both
seeded variants (`ACME_invoice.docm`, `invoice_lure.lnk`) — each with its run
link. One IP, three samples.

**Why it matters:** cross-run IOC correlation ("have I seen this before?") is
what turns a single detonation into a campaign hypothesis. The demo shows it
answering a real question: *is today's sample related to last week's?*

---

## Step 3 — Compare

**Where:** `Compare` in the nav.

**Do:** pick **ACME_invoice.docm** and **invoice_lure.lnk** from the dropdowns.

**Expect:** the three-column diff —

| only A | shared | only B |
|---|---|---|
| `winword.exe`, `cmd.exe` | `powershell.exe` | `wscript.exe` |
| `1.1.1.1`, `185.220.101.34` | `203.0.113.88` | `8.8.8.8` |

**Why it matters:** same C2, same persistence key, same PowerShell stage —
*different droppers*. That's the signature of a coordinated campaign, and the
compare view makes the lineage visible at a glance.

---

## Step 4 — Watchlist

**Where:** `Watchlist` in the nav.

**Do:** add `203.0.113.88` with label **`Shelf-Stack C2`**. Then open any run's
detail — the detonation works nicely.

**Expect:** the C2 row in the network table now shows **★ suspicious** with your
label. Next to it on the variant A detail page, `185.220.101.34` shows
**malicious** from external intel (Abuse 92 / VT 18) — both threat-intel
sources side by side: your personal watchlist and third-party feeds.

**Why it matters:** the watchlist is personal, instant, and independent of
external APIs — you can flag an IOC the moment you *believe* it, before any
feed catches up.

---

## Step 5 — Detection rules

**Where:** the run detail page's **Detection Rules** panel (or `outpost rules`).

**Do:** on the fresh detonation, open the **Sigma** tab — one rule per alert
type observed (parent-child, LOLBin, beaconing, rename-burst, persistence).
Then open **ACME_invoice.docm** and check **Suricata**:

```text
alert tcp any any -> 185.220.101.34 4444 (msg:"OutPost: possible C2 traffic observed in run 0302aa600d1d to 185.220.101.34"; sid:161894; rev:1;)
```

**Expect:** a real Suricata rule generated from the intel-malicious connection,
plus Sigma YAML with deterministic IDs. Both tabs have copy buttons.

**Why it matters:** detonation → detection → *exportable detection logic*. The
rules come straight out of the analysis and are ready to paste into your own
SIEM/IDS — the demo closes the loop from sample to defense.

---

## Epilogue — what this demo proves

- **Standalone dynamic analysis** — detonate, watch, and investigate a sample
  entirely in the browser; no collector or VM required.
- **Live detection, explainably** — every alert states exactly what was observed
  ("5 connections at ~2s intervals"), and the toast stream keeps pace with the
  run.
- **Cross-run correlation** — IOC search ties today's detonation to historical
  runs; compare makes campaign lineage visible (same C2, different droppers).
- **Two-tier threat intel** — external feeds (malicious `185.220.101.34`) and
  your personal watchlist (★ `203.0.113.88`) work side by side.
- **Analysis → defense** — Suricata/Sigma rules generated from findings, ready
  to deploy.

---

## Appendix — seeded dataset

| Sample | Run ID | Vector | Events | Alerts |
|---|---|---|---|---|
| `ACME_invoice.docm` | `0302aa600d1d` | macro → PowerShell → cmd | 11 | 5 (2 parent-child, LOLBin, beacon, persistence) |
| `invoice_lure.lnk` | `e4f15e059839` | LNK → hidden PowerShell | 20 | 5 (first-seen, LOLBin, beacon, persistence, rename-burst) |

Alerts are produced by the live detection engine (`services/detection.py`,
rules 1–7), not pre-baked. On a completely empty DB, variant A also earns a
`first-seen-process` alert for `winword.exe` (6 total); on a DB where office
binaries are already established (as in the live demo), both variants settle at
5. Either way the pair reproduces the same campaign rule set, including
`first-seen-process` for the variant that introduces `wscript.exe`.

> **Note on reputations.** The seed script also fills the enrichment cache
> (C2 → malicious 87/64, `185.220.101.34` → malicious 92/18, DNS → clean), so
> a script-seeded replay shows intel verdicts offline. If you seeded via the
> API only (no cache entries, no API keys), the campaign C2 reads `unknown`
> until Step 4 — which is the point of the watchlist step.
