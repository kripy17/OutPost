#!/usr/bin/env python3
"""Benchmark the detection hot path — the fan-out recurrence scan and the
full evaluate_batch per-batch budget.

Measurements (median of N, rows fetched):
  1. Real DB: the heaviest run, old query (full history, index disabled via
     SQLite's NOT INDEXED — the pre-index engine) vs the new bounded query.
  2. Synthetic long-session case (clearly labeled): one run with 200k network
     events spanning 48h — full-history scan vs the 2h lookback, both with the
     index — showing why the lookback matters as sessions get long.
  3. End-to-end evaluate_batch on a COPY of the real DB (the live store is
     never mutated — evaluate_batch writes alerts): the heaviest run's newest
     100 events as one batch, timed cold (process map built from scratch) and
     warm (median of 5, incremental map), with the recurrence scan's share of
     the per-batch budget broken out.

Run:  .venv/bin/python scripts/bench_recurrence.py
"""

import datetime
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "backend" / "data" / "outpost.db"
LOOKBACK_SECONDS = 7200
ITERS = 7


def _conn(path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def scan(conn, run_id: str, cutoff_iso: str | None = None, use_index: bool = True) -> int:
    """Run the recurrence SELECT; returns rows fetched. `use_index=False`
    disables the composite index with SQLite's NOT INDEXED hint (the
    pre-index engine's table scan)."""
    hint = "" if use_index else " NOT INDEXED"
    if cutoff_iso is not None:
        rows = conn.execute(
            f"SELECT dest_ip, timestamp, pid FROM events{hint} "
            "WHERE run_id = ? AND event_type = 'network_connection' "
            "AND pid IS NOT NULL AND dest_ip IS NOT NULL AND timestamp >= ?",
            (run_id, cutoff_iso),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT dest_ip, timestamp, pid FROM events{hint} "
            "WHERE run_id = ? AND event_type = 'network_connection' "
            "AND pid IS NOT NULL AND dest_ip IS NOT NULL",
            (run_id,),
        ).fetchall()
    return len(rows)


def bench(fn, iters: int = ITERS) -> tuple[float, int]:
    times = []
    rows = 0
    for _ in range(iters):
        t0 = time.perf_counter()
        rows = fn()
        times.append(time.perf_counter() - t0)
    return statistics.median(times), rows


def plan(conn, run_id: str, cutoff_iso: str | None = None):
    base = (
        "EXPLAIN QUERY PLAN SELECT dest_ip, timestamp, pid FROM events "
        "WHERE run_id = ? AND event_type = 'network_connection' "
        "AND pid IS NOT NULL AND dest_ip IS NOT NULL"
    )
    if cutoff_iso is not None:
        return [tuple(r) for r in conn.execute(base + " AND timestamp >= ?", (run_id, cutoff_iso)).fetchall()]
    return [tuple(r) for r in conn.execute(base, (run_id,)).fetchall()]


def fmt(sec: float) -> str:
    return f"{sec * 1000:.2f} ms"


def main() -> int:
    print("== Fan-out recurrence scan — before vs after (index + lookback) ==\n")

    # ---- Real DB ----
    print(f"Real DB: {DB} ({DB.stat().st_size / 1024:.0f} KiB)")
    conn = _conn(DB)
    heaviest = conn.execute(
        "SELECT run_id, COUNT(*) AS n FROM events "
        "WHERE event_type = 'network_connection' AND pid IS NOT NULL AND dest_ip IS NOT NULL "
        "GROUP BY run_id ORDER BY n DESC LIMIT 1"
    ).fetchone()
    run_id = heaviest["run_id"]
    newest = conn.execute(
        "SELECT MAX(timestamp) AS t FROM events WHERE run_id = ?", (run_id,)
    ).fetchone()["t"]
    newest_dt = datetime.datetime.fromisoformat(newest.replace("Z", "+00:00"))
    cutoff = (newest_dt - datetime.timedelta(seconds=LOOKBACK_SECONDS)).isoformat()

    print(f"Heaviest run: {run_id} — {heaviest['n']} network events, newest {newest}\n")

    print("Query plans (the 'after' read is an index seek, not a table scan):")
    for label, kw in (("old (full history, no index)", dict(cutoff_iso=None, use_index=False)),
                      ("new (2h lookback + index)", dict(cutoff_iso=cutoff, use_index=True))):
        if kw["cutoff_iso"] is None:
            rows = conn.execute(
                "EXPLAIN QUERY PLAN SELECT dest_ip, timestamp, pid FROM events NOT INDEXED "
                "WHERE run_id = ? AND event_type = 'network_connection' "
                "AND pid IS NOT NULL AND dest_ip IS NOT NULL", (run_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "EXPLAIN QUERY PLAN SELECT dest_ip, timestamp, pid FROM events "
                "WHERE run_id = ? AND event_type = 'network_connection' "
                "AND pid IS NOT NULL AND dest_ip IS NOT NULL AND timestamp >= ?",
                (run_id, kw["cutoff_iso"]),
            ).fetchall()
        print(f"  {label}: {rows[0][3] if rows else '?'}")

    old_t, old_rows = bench(lambda: scan(conn, run_id, None, False))
    new_t, new_rows = bench(lambda: scan(conn, run_id, cutoff, True))
    print(f"\nReal heaviest run ({heaviest['n']} rows):")
    print(f"  old: {fmt(old_t)}  ({old_rows} rows fetched)")
    print(f"  new: {fmt(new_t)}  ({new_rows} rows fetched)")
    print(f"  speedup: {old_t / new_t:.1f}x")
    conn.close()

    # ---- Synthetic long session (labeled) ----
    print("\n-- Synthetic long-session case (NOT real telemetry) --")
    print("One run, 200k network events spanning 48h — isolates the lookback win.")
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp = tf.name
    tconn = _conn(tmp)
    tconn.execute("CREATE TABLE events (run_id TEXT, event_type TEXT, timestamp TEXT, pid INTEGER, dest_ip TEXT)")
    tconn.execute("CREATE INDEX idx_events_run_type ON events(run_id, event_type)")
    base = datetime.datetime(2026, 8, 1, tzinfo=datetime.timezone.utc)
    tconn.executemany(
        "INSERT INTO events VALUES (?, 'network_connection', ?, ?, ?)",
        [(run_id, (base + datetime.timedelta(seconds=(i * 86400) / 100_000 * 2)).isoformat(), 1000 + i % 50, f"10.0.0.{i % 255}") for i in range(200_000)],
    )
    tconn.commit()
    newest_syn = tconn.execute("SELECT MAX(timestamp) AS t FROM events").fetchone()["t"]
    cutoff_syn = (datetime.datetime.fromisoformat(newest_syn.replace("Z", "+00:00"))
                  - datetime.timedelta(seconds=LOOKBACK_SECONDS)).isoformat()
    full_t, full_rows = bench(lambda: scan(tconn, run_id, None, True))
    look_t, look_rows = bench(lambda: scan(tconn, run_id, cutoff_syn, True))
    print(f"  full-history: {fmt(full_t)}  ({full_rows:,} rows fetched)")
    print(f"  2h lookback:  {fmt(look_t)}  ({look_rows:,} rows fetched)")
    print(f"  speedup: {full_t / look_t:.1f}x  · rows: {full_rows:,} -> {look_rows:,} "
          f"({(1 - look_rows / full_rows) * 100:.0f}% fewer)")
    tconn.close()
    import os
    os.unlink(tmp)

    # ---- End-to-end evaluate_batch (real rules, real data, on a DB copy) ----
    print("\n-- End-to-end evaluate_batch (real rules, real data, on a DB copy) --")
    print("The live store is never touched: the DB is copied and every alert "
          "insert lands in the throwaway file.")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
    from app.services.detection import evaluate_batch  # noqa: E402

    # sqlite3.backup() is safe even if the live server is mid-write.
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_copy = tf.name
    try:
        src = sqlite3.connect(DB)
        dst = sqlite3.connect(tmp_copy)
        src.backup(dst)
        dst.commit()
        src.close()
        econn = _conn(tmp_copy)

        heaviest = econn.execute(
            "SELECT run_id, COUNT(*) AS n FROM events GROUP BY run_id "
            "ORDER BY n DESC LIMIT 1"
        ).fetchone()
        run_id = heaviest["run_id"]
        proc_n = econn.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'process_create'",
            (run_id,),
        ).fetchone()[0]
        restored = econn.execute(
            "SELECT 1 FROM run_process_maps WHERE run_id = ?", (run_id,)
        ).fetchone() is not None
        # Newest 100 events as one ingest batch, chronological.
        batch = [dict(r) for r in reversed(econn.execute(
            "SELECT * FROM events WHERE run_id = ? ORDER BY id DESC LIMIT 100", (run_id,)
        ).fetchall())]
        newest = batch[-1]["timestamp"]
        newest_dt = datetime.datetime.fromisoformat(newest.replace("Z", "+00:00"))
        cutoff = (newest_dt - datetime.timedelta(seconds=LOOKBACK_SECONDS)).isoformat()

        print(f"Heaviest run: {run_id} — {heaviest['n']:,} events "
              f"({proc_n:,} process_create; warm-restore row: {restored})")
        print(f"Batch: newest {len(batch)} events by id ({newest}) — a replay of "
              "already-ingested events, so `fire()` dedups and the numbers are "
              "the pure evaluation cost (rules, process map, windowed scans)\n")

        # Cold: cache is keyed by (db path, run) — the copy's path differs, so
        # this is a genuine restart-cold call. Warm: median of 5 steady-state
        # calls where the incremental map reads only the batch's own rows.
        t0 = time.perf_counter()
        alerts_cold = evaluate_batch(econn, run_id, batch)
        cold_t = time.perf_counter() - t0
        warm_times, alerts_warm = [], 0
        for _ in range(5):
            t0 = time.perf_counter()
            alerts_warm = evaluate_batch(econn, run_id, batch)
            warm_times.append(time.perf_counter() - t0)
        warm_t = statistics.median(warm_times)

        scan_t, scan_rows = bench(lambda: scan(econn, run_id, cutoff, True))
        print("Per-batch budget (full evaluate_batch — all ~30 rules/event, "
              "process map, windowed scans):")
        print(f"  cold: {fmt(cold_t)}  (map built "
              f"{'from persisted warm-restore' if restored else 'from scratch'})")
        print(f"  warm: {fmt(warm_t)}  (median of 5 — incremental map reads only "
              "the batch's rows)")
        print(f"  cold→warm delta: {fmt(cold_t - warm_t)} (map build of "
              f"{proc_n:,} process rows)")
        print(f"  of which the recurrence scan alone: {fmt(scan_t)} "
              f"({scan_rows:,} rows) — {scan_t / warm_t * 100:.1f}% of the "
              "warm budget (per-event rule evaluation dominates)")
        econn.close()
    finally:
        shutil.os.unlink(tmp_copy)
    return 0


if __name__ == "__main__":
    sys.exit(main())
