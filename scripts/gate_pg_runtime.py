#!/usr/bin/env python3
"""Live Postgres runtime smoke (Tier 4, docs/16).

Runs the real backend DB layer against a Postgres server and asserts the
sqlite3-compat shim (``core/db_pg``) holds for the app's actual query
shapes — the same ones the SQLite suite exercises:

  * schema init via the translated DDL (``core.db.init_db``, idempotent)
  * plain INSERT + ``lastrowid`` (the ``RETURNING id`` path)
  * ``ON CONFLICT ... DO UPDATE`` upserts (``excluded.*``)
  * ``INSERT OR IGNORE`` → ``ON CONFLICT DO NOTHING`` (rowcount 1 then 0 —
    the watchlist live-alerting contract)
  * ``GROUP_CONCAT`` → ``string_agg`` (the agents-page channels query,
    verbatim, including the nested-subquery variant)
  * ``ILIKE`` search (SQLite ``LIKE`` is case-insensitive — keep behavior)
  * ``LIMIT ? OFFSET ?`` pagination, ``executemany`` DELETE, FK enforcement

SKIPs cleanly (exit 0) when ``OUTPOST_DATABASE_URL`` is unset or psycopg is
missing, so verify.sh can include the gate everywhere; CI runs it for real
against a postgres service container (the ``pg-runtime`` job).
"""

import os
import sys

URL = os.getenv("OUTPOST_DATABASE_URL", "").strip()
if not URL:
    print("SKIP: OUTPOST_DATABASE_URL unset — Postgres runtime smoke not run")
    sys.exit(0)
try:
    import psycopg  # noqa: F401
except ImportError:
    print("SKIP: psycopg not installed — pip install 'psycopg[binary]' (backend[pg])")
    sys.exit(0)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

from app.core import config  # noqa: E402

config.DATABASE_URL = URL

from app.core.db import db_session, init_db  # noqa: E402

from datetime import datetime, timezone  # noqa: E402

NOW = datetime.now(timezone.utc).isoformat()

FAILURES: list[str] = []


def _check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}" + (f" — {detail}" if detail else ""))
        FAILURES.append(name)


def _event(run_id: str, pid: int, pname: str, host_id: str = "host-a") -> tuple:
    return (
        run_id, "linux", "process_create", NOW, pid, 1, pname, "/usr/bin/" + pname,
        "/usr/bin/" + pname, "10.0.0.5", 443, "tcp", None, None, host_id,
        '{"raw": true}', "auditd", None, "evil.example.com",
    )


def main() -> int:
    print(f"Postgres runtime smoke — {URL}")

    print("  schema init (idempotent ×2)")
    init_db()
    init_db()

    print("  run + event + lastrowid")
    run_id = "pg-smoke-run"
    with db_session() as conn:
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, source, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, "pg-smoke.bin", "linux", "live", "live", NOW),
        )
        cur = conn.execute(
            "INSERT INTO events (run_id, platform, event_type, timestamp, pid, ppid, "
            "process_name, command_line, exe_path, dest_ip, dest_port, protocol, "
            "file_path, registry_key, host_id, raw_record, log_source, query, tls_sni) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            _event(run_id, 100, "evil.sh"),
        )
        _check("event insert lastrowid (RETURNING id)", isinstance(cur.lastrowid, int) and cur.lastrowid > 0,
               f"got {cur.lastrowid!r}")
        event_id = cur.lastrowid
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        _check("row key access", row is not None and row["process_name"] == "evil.sh")
        _check("row index access", row is not None and row[0] == event_id)
        _check("dict(row) compat", row is not None and dict(row)["tls_sni"] == "evil.example.com")

    print("  upsert (ON CONFLICT DO UPDATE, excluded.*)")
    with db_session() as conn:
        for value in ("10.0.0.5", "10.0.0.6"):
            cur = conn.execute(
                "INSERT INTO enrichment_cache (ip, abuse_score, vt_malicious_count, reputation, checked_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET abuse_score = excluded.abuse_score, "
                "vt_malicious_count = excluded.vt_malicious_count, "
                "reputation = excluded.reputation, checked_at = excluded.checked_at",
                ("1.2.3.4", 42 if value == "10.0.0.5" else 99, 0, "malicious", NOW),
            )
            _check(f"upsert rowcount ({value})", cur.rowcount == 1, f"got {cur.rowcount}")
        row = conn.execute("SELECT * FROM enrichment_cache WHERE ip = ?", ("1.2.3.4",)).fetchone()
        _check("upsert applied latest value", row["abuse_score"] == 99, f"got {row['abuse_score']}")

    print("  INSERT OR IGNORE → rowcount 1 then 0 (watchlist contract)")
    with db_session() as conn:
        for expect in (1, 0):
            cur = conn.execute(
                "INSERT OR IGNORE INTO run_tuning_snapshot (run_id, params) VALUES (?, ?)",
                (run_id, '{"BEACON_WINDOW_MINUTES": 5}'),
            )
            _check(f"OR IGNORE rowcount == {expect}", cur.rowcount == expect, f"got {cur.rowcount}")
        for expect in (1, 0):
            cur = conn.execute(
                "INSERT OR IGNORE INTO watchlist_hits (run_id, ioc_type, ioc_value, first_seen) "
                "VALUES (?, ?, ?, ?)",
                (run_id, "ip", "1.2.3.4", NOW),
            )
            _check(f"watchlist_hits OR IGNORE rowcount == {expect}", cur.rowcount == expect, f"got {cur.rowcount}")

    print("  alert + triage UPDATE rowcount")
    with db_session() as conn:
        cur = conn.execute(
            "INSERT INTO alerts (run_id, rule_id, rule_name, severity, triggered_at, details, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'open')",
            (run_id, "test-rule", "Test Rule", "suspicious", NOW, "details"),
        )
        alert_id = cur.lastrowid
        _check("alert lastrowid", isinstance(alert_id, int) and alert_id > 0)
        cur = conn.execute(
            "UPDATE alerts SET status = 'acknowledged', status_comment = ?, status_at = ? WHERE id = ?",
            ("PG smoke", NOW, alert_id),
        )
        _check("UPDATE rowcount == 1", cur.rowcount == 1, f"got {cur.rowcount}")

    print("  GROUP_CONCAT → string_agg (agents-page channels query, verbatim)")
    with db_session() as conn:
        conn.execute(
            "INSERT INTO events (run_id, platform, event_type, timestamp, pid, ppid, process_name, "
            "command_line, exe_path, host_id, raw_record, log_source) "
            "VALUES (?, 'windows', 'process_create', ?, ?, 1, ?, ?, ?, 'host-b', ?, 'sysmon')",
            (run_id, NOW, 200, "b.exe", "b.exe", '{"raw": true}'),
        )
        rows = conn.execute(
            """
            SELECT e.host_id,
                   MAX(e.timestamp)                                  AS last_seen,
                   COUNT(*)                                          AS event_count,
                   COUNT(DISTINCT e.run_id)                          AS run_count,
                   GROUP_CONCAT(DISTINCT e.platform)                 AS platforms,
                   GROUP_CONCAT(DISTINCT COALESCE(e.log_source, 'webapp')) AS channels,
                   (SELECT GROUP_CONCAT(run_id) FROM
                      (SELECT DISTINCT run_id FROM events WHERE host_id = e.host_id
                       ORDER BY timestamp DESC LIMIT 5))             AS recent_run_ids
            FROM events e
            GROUP BY e.host_id
            ORDER BY last_seen DESC
            """
        ).fetchall()
        _check("agents query returns hosts", len(rows) == 2, f"got {len(rows)}")
        by_host = {r["host_id"]: r for r in rows}
        _check("channels string_agg (host-a=auditd)", by_host.get("host-a", {}).get("channels") == "auditd")
        _check("channels string_agg (host-b=sysmon)", by_host.get("host-b", {}).get("channels") == "sysmon")
        _check("recent_run_ids string_agg (nested subquery)",
               by_host.get("host-a", {}).get("recent_run_ids") == run_id)

    print("  ILIKE case-insensitive search (SQLite LIKE parity)")
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE process_name LIKE ? ESCAPE '\\' LIMIT ?",
            ("%POWERSHELL%", 10),
        ).fetchall()
        _check("lowercase pattern matches 'PowerShell.exe'", any(r["process_name"] == "evil.sh" for r in rows))

    print("  LIMIT/OFFSET pagination")
    with db_session() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id LIMIT ? OFFSET ?", (1, 1)).fetchall()
        _check("pagination returns exactly one row", len(rows) == 1, f"got {len(rows)}")

    print("  executemany DELETE")
    with db_session() as conn:
        conn.execute("INSERT INTO enrichment_cache (ip, checked_at) VALUES (?, ?)", ("9.9.9.9", NOW))
        conn.execute("INSERT INTO enrichment_cache (ip, checked_at) VALUES (?, ?)", ("8.8.8.8", NOW))
        cur = conn.executemany("DELETE FROM enrichment_cache WHERE ip = ?", [("9.9.9.9",), ("8.8.8.8",)])
        _check("executemany DELETE rowcount == 2", cur.rowcount == 2, f"got {cur.rowcount}")

    print("  run_notes + audit_log lastrowid")
    with db_session() as conn:
        cur = conn.execute(
            "INSERT INTO run_notes (run_id, note, created_at) VALUES (?, ?, ?)",
            (run_id, "PG smoke note", NOW),
        )
        _check("run_notes lastrowid", isinstance(cur.lastrowid, int) and cur.lastrowid > 0)
        cur = conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target_type, target_id, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (NOW, "local", "pg-smoke", "run", run_id, "smoke"),
        )
        _check("audit_log lastrowid", isinstance(cur.lastrowid, int) and cur.lastrowid > 0)

    print("  settings upsert (auth-style, excluded.value)")
    with db_session() as conn:
        cur = conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("pg.smoke", "first"),
        )
        _check("settings upsert rowcount", cur.rowcount == 1)
        cur = conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("pg.smoke", "second"),
        )
        _check("settings upsert rowcount (update)", cur.rowcount == 1)
        row = conn.execute("SELECT value FROM settings WHERE key = ?", ("pg.smoke",)).fetchone()
        _check("settings upsert applied update", row["value"] == "second")

    print("  FK enforcement (bogus run_id rejected)")
    try:
        with db_session() as conn:
            conn.execute(
                "INSERT INTO events (run_id, platform, event_type, timestamp) "
                "VALUES (?, 'linux', 'process_create', ?)",
                ("no-such-run", NOW),
            )
        _check("FK violation raised", False, "insert with bogus run_id did not raise")
    except Exception as exc:  # db_session rolls back and re-raises
        _check("FK violation raised", "foreign key" in str(exc).lower() or "constraint" in str(exc).lower(),
               f"got {type(exc).__name__}: {exc}")

    # cleanup so the smoke is re-runnable against the same server
    with db_session() as conn:
        conn.execute("DELETE FROM events WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM alerts WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM run_notes WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM enrichment_cache WHERE ip = '1.2.3.4'")
        conn.execute("DELETE FROM settings WHERE key = 'pg.smoke'")

    if FAILURES:
        print(f"\nPostgres runtime smoke: {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\nPostgres runtime smoke: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
