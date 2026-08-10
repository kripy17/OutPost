"""Data access for the `runs` table and run summary aggregation."""

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from ..core.schema import RunSummary
from ..services.risk import compute_risk_score


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_run(
    conn: sqlite3.Connection,
    run_id: str,
    sample_name: str,
    platform: str,
    session_type: str = "analysis",
    source: str = "monitor",
) -> None:
    """Create a run. `source` records where it came from (monitor detonation,
    live host collector, sandbox:<provider>, seed data, cli) so the webapp can
    badge provenance on every run card."""
    conn.execute(
        "INSERT INTO runs (run_id, sample_name, platform, session_type, source, started_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, sample_name, platform, session_type, source, utcnow()),
    )


def complete_run(conn: sqlite3.Connection, run_id: str) -> bool:
    cur = conn.execute(
        "UPDATE runs SET completed_at = ? WHERE run_id = ? AND completed_at IS NULL",
        (utcnow(), run_id),
    )
    return cur.rowcount > 0


def get_run(conn: sqlite3.Connection, run_id: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    return dict(row) if row else None


# Provenance markers that are demo/synthetic by construction — seeds, the
# webapp's generated detonations (current and legacy `monitor` label), and the
# keyless sandbox demo. Hidden from the archive by default so it reads as real
# telemetry first; `include_synthetic` reveals them. Real integrations
# (sandbox:anyrun/triage/joe), host collectors (`live`), and CLI analyses stay
# visible regardless.
SYNTHETIC_SOURCES = ("seed", "webapp-demo", "monitor", "sandbox:demo")


def _synthetic_clause(include_synthetic: bool) -> str:
    if include_synthetic:
        return ""
    marks = ",".join("?" for _ in SYNTHETIC_SOURCES)
    return f" AND r.source NOT IN ({marks})"


def list_runs(conn: sqlite3.Connection, q: str = "", host: str = "", include_synthetic: bool = False) -> list[dict]:
    """All runs newest-first; `q` filters by sample-name substring (the
    sample-vault's detonation history links here with ?q=<sample>) and `host`
    filters to runs whose events came from that host_id (the fleet links here
    with ?host=<host>). Synthetic provenance (seeds / webapp detonations / the
    keyless sandbox demo) is hidden unless `include_synthetic` is set — the
    archive reads as real telemetry first."""
    excl = _synthetic_clause(include_synthetic)
    args: tuple = SYNTHETIC_SOURCES if not include_synthetic else ()
    if q and host:
        rows = conn.execute(
            "SELECT DISTINCT r.* FROM runs r JOIN events e ON e.run_id = r.run_id "
            f"WHERE r.sample_name LIKE ? AND e.host_id = ?{excl} ORDER BY r.started_at DESC",
            (f"%{q}%", host, *args),
        ).fetchall()
    elif host:
        rows = conn.execute(
            "SELECT DISTINCT r.* FROM runs r JOIN events e ON e.run_id = r.run_id "
            f"WHERE e.host_id = ?{excl} ORDER BY r.started_at DESC",
            (host, *args),
        ).fetchall()
    elif q:
        rows = conn.execute(
            f"SELECT * FROM runs WHERE sample_name LIKE ?{excl.replace('r.source', 'source')} ORDER BY started_at DESC",
            (f"%{q}%", *args),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT * FROM runs WHERE 1=1{excl.replace('r.source', 'source')} ORDER BY started_at DESC",
            args,
        ).fetchall()
    return [dict(r) for r in rows]


def _count_processes(conn: sqlite3.Connection, run_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(DISTINCT pid) AS n FROM events WHERE run_id = ? AND event_type = 'process_create' AND pid IS NOT NULL",
        (run_id,),
    ).fetchone()
    return row["n"] if row else 0


def _count_unique_ips(conn: sqlite3.Connection, run_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(DISTINCT dest_ip) AS n FROM events WHERE run_id = ? AND event_type = 'network_connection' AND dest_ip IS NOT NULL",
        (run_id,),
    ).fetchone()
    return row["n"] if row else 0


def _alert_stats(conn: sqlite3.Connection, run_id: str) -> tuple[int, Optional[str]]:
    row = conn.execute(
        """
        SELECT COUNT(*) AS n,
               MAX(CASE severity WHEN 'malicious' THEN 2 WHEN 'suspicious' THEN 1 ELSE 0 END) AS sev
        FROM alerts WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if not row or not row["n"]:
        return 0, None
    sev = {2: "malicious", 1: "suspicious"}.get(row["sev"])
    return row["n"], sev


def _fired_rule_ids(conn: sqlite3.Connection, run_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT rule_id FROM alerts WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    return [r["rule_id"] for r in rows]


def _host_ids(conn: sqlite3.Connection, run_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT host_id FROM events WHERE run_id = ? AND host_id IS NOT NULL ORDER BY host_id",
        (run_id,),
    ).fetchall()
    return [r["host_id"] for r in rows]


def to_summary(conn: sqlite3.Connection, run: dict | sqlite3.Row) -> RunSummary:
    """Aggregate process/ip/alert stats into a RunSummary from a runs row."""
    alert_count, highest = _alert_stats(conn, run["run_id"])
    # Accept dicts and sqlite3.Row (the active-live route passes a raw Row).
    source = run["source"] if "source" in run.keys() else "monitor"
    return RunSummary(
        run_id=run["run_id"],
        sample_name=run["sample_name"],
        platform=run["platform"],
        session_type=run["session_type"],
        source=source,
        host_ids=_host_ids(conn, run["run_id"]),
        started_at=run["started_at"],
        completed_at=run["completed_at"],
        process_count=_count_processes(conn, run["run_id"]),
        unique_ips=_count_unique_ips(conn, run["run_id"]),
        alert_count=alert_count,
        highest_severity=highest,
        risk_score=compute_risk_score(_fired_rule_ids(conn, run["run_id"])),
    )
