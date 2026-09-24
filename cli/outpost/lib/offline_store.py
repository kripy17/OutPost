"""Offline SQLite store fallback for OutPost CLI.

Enables the CLI to read past runs, alerts, samples, and watchlist entries
directly from the local SQLite database when the backend HTTP service is offline.
"""

import os
import platform
import sqlite3
import sys
from pathlib import Path
from typing import Any


def _ensure_backend_on_path() -> Path:
    """Ensure backend directory is on sys.path for direct service access."""
    root = Path(__file__).resolve().parent.parent.parent.parent
    backend_dir = root / "backend"
    if backend_dir.is_dir() and str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))
    return root


def find_db_path() -> Path | None:
    """Locate the OutPost SQLite database file."""
    # 1. Explicit env var
    env_path = os.getenv("DATABASE_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    # 2. Known repo locations
    root = Path(__file__).resolve().parent.parent.parent.parent
    candidates = [
        root / "backend" / "data" / "outpost.db",
        root / ".freebuff" / "outpost.db",
        root / "outpost.db",
        Path.cwd() / "backend" / "data" / "outpost.db",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


def get_offline_runs(limit: int = 50) -> list[dict[str, Any]] | None:
    """Query runs directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        rows = cur.execute(
            """
            SELECT r.run_id, r.sample_name, r.platform, r.session_type, r.started_at, r.completed_at,
                   COUNT(a.id) as alert_count,
                   MAX(CASE WHEN a.severity = 'malicious' THEN 'malicious'
                            WHEN a.severity = 'suspicious' THEN 'suspicious'
                            ELSE 'clean' END) as highest_severity
            FROM runs r
            LEFT JOIN alerts a ON r.run_id = a.run_id
            GROUP BY r.run_id
            ORDER BY r.started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        runs = []
        for r in rows:
            d = dict(r)
            d["risk_score"] = 48 if d.get("highest_severity") == "malicious" else 14 if d.get("highest_severity") == "suspicious" else 0
            runs.append(d)
        conn.close()
        return runs
    except Exception:
        return None


def get_offline_run_detail(run_id: str) -> dict[str, Any] | None:
    """Retrieve full run details (summary, alerts, process tree, network sockets) directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        run_row = cur.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run_row:
            conn.close()
            return None

        alerts_rows = cur.execute("SELECT * FROM alerts WHERE run_id = ? ORDER BY id ASC", (run_id,)).fetchall()
        alerts = [dict(a) for a in alerts_rows]

        highest_sev = "clean"
        for a in alerts:
            s = (a.get("severity") or "").lower()
            if s == "malicious":
                highest_sev = "malicious"
                break
            elif s == "suspicious" and highest_sev != "malicious":
                highest_sev = "suspicious"

        run_dict = dict(run_row)
        run_dict["highest_severity"] = highest_sev
        run_dict["alert_count"] = len(alerts)
        run_dict["risk_score"] = 75 if highest_sev == "malicious" else (35 if highest_sev == "suspicious" else 0)

        _ensure_backend_on_path()
        tree = []
        try:
            from app.services import process_tree
            proc_rows = cur.execute(
                "SELECT * FROM events WHERE run_id = ? AND event_type = 'process_create' ORDER BY timestamp ASC",
                (run_id,),
            ).fetchall()
            tree = process_tree.build_process_tree([dict(r) for r in proc_rows])
        except Exception:
            tree = []

        net_rows = cur.execute(
            """
            SELECT dest_ip, dest_port, protocol, MIN(timestamp) AS first_seen
            FROM events
            WHERE run_id = ? AND event_type = 'network_connection' AND dest_ip IS NOT NULL
            GROUP BY dest_ip, dest_port, protocol
            ORDER BY first_seen ASC
            """,
            (run_id,),
        ).fetchall()
        network = [dict(n) for n in net_rows]

        conn.close()
        return {
            "run": run_dict,
            "alerts": alerts,
            "process_tree": tree,
            "network_connections": network,
        }
    except Exception:
        return None


def get_offline_alerts(status: str = "all", limit: int = 50) -> list[dict[str, Any]] | None:
    """Query alerts directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if status == "open":
            rows = cur.execute(
                "SELECT * FROM alerts WHERE status = 'open' ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        alerts = [dict(r) for r in rows]
        conn.close()
        return alerts
    except Exception:
        return None


def get_offline_samples() -> list[dict[str, Any]] | None:
    """Query samples directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        rows = cur.execute("SELECT * FROM samples ORDER BY created_at DESC LIMIT 50").fetchall()
        samples = [dict(r) for r in rows]
        conn.close()
        return samples
    except Exception:
        return None


def get_offline_hosts() -> list[dict[str, Any]] | None:
    """Query hosts and agent fleet status directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='agent_heartbeats'")
        has_hb = cur.fetchone() is not None

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='agent_containment'")
        has_cont = cur.fetchone() is not None

        hosts: dict[str, dict[str, Any]] = {}
        if has_hb:
            hb_rows = cur.execute("SELECT * FROM agent_heartbeats").fetchall()
            for r in hb_rows:
                d = dict(r)
                hosts[d["host_id"]] = {
                    "host_id": d["host_id"],
                    "platform": d.get("platform") or "unknown",
                    "version": d.get("version") or "-",
                    "last_seen": d.get("last_heartbeat"),
                    "online": False,
                    "event_count": 0,
                    "alert_count": 0,
                    "isolated": False,
                }

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if cur.fetchone() is not None:
            ev_rows = cur.execute(
                """
                SELECT host_id, MAX(timestamp) as last_seen, COUNT(*) as event_count,
                       GROUP_CONCAT(DISTINCT platform) as platforms
                FROM events
                GROUP BY host_id
                """
            ).fetchall()
            for r in ev_rows:
                hid = r["host_id"] or "local"
                if hid not in hosts:
                    hosts[hid] = {
                        "host_id": hid,
                        "platform": r["platforms"] or "unknown",
                        "version": "-",
                        "last_seen": r["last_seen"],
                        "online": False,
                        "event_count": r["event_count"],
                        "alert_count": 0,
                        "isolated": False,
                    }
                else:
                    hosts[hid]["event_count"] = r["event_count"]
                    if not hosts[hid]["last_seen"] or (r["last_seen"] and r["last_seen"] > hosts[hid]["last_seen"]):
                        hosts[hid]["last_seen"] = r["last_seen"]

        if has_cont:
            cont_rows = cur.execute("SELECT host_id, isolated, reason FROM agent_containment").fetchall()
            for r in cont_rows:
                if r["host_id"] in hosts:
                    hosts[r["host_id"]]["isolated"] = bool(r["isolated"])
                    hosts[r["host_id"]]["isolation_reason"] = r.get("reason")

        conn.close()
        return list(hosts.values())
    except Exception:
        return None


def get_offline_audit(limit: int = 50, action: str | None = None) -> list[dict[str, Any]] | None:
    """Query audit log directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
        if cur.fetchone() is None:
            conn.close()
            return []
        if action:
            rows = cur.execute(
                "SELECT * FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT ?", (action, limit)
            ).fetchall()
        else:
            rows = cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        entries = [dict(r) for r in rows]
        conn.close()
        return entries
    except Exception:
        return None


def search_offline_iocs(query: str, limit: int = 50) -> list[dict[str, Any]] | None:
    """Search for an IOC value directly across offline SQLite events."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        q_like = f"%{query}%"

        matches: list[dict[str, Any]] = []
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if cur.fetchone() is not None:
            ev_rows = cur.execute(
                """
                SELECT run_id, event_type, timestamp, host_id, process_name, dest_ip
                FROM events
                WHERE raw_record LIKE ? OR dest_ip LIKE ? OR process_name LIKE ?
                   OR command_line LIKE ? OR file_path LIKE ? OR query LIKE ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (q_like, q_like, q_like, q_like, q_like, q_like, limit),
            ).fetchall()
            for r in ev_rows:
                matches.append({
                    "run_id": r["run_id"],
                    "sample_name": r["host_id"] or "-",
                    "event_type": r["event_type"],
                    "timestamp": r["timestamp"],
                })

        conn.close()
        return matches
    except Exception:
        return None


def get_offline_investigations(
    status: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any] | None:
    """Query investigations directly from SQLite."""
    _ensure_backend_on_path()
    try:
        from app.core.db import db_session
        from app.models import investigation as inv_store
        with db_session() as conn:
            total, rows = inv_store.list_investigations(conn, status=status, q=q, limit=limit, offset=offset)
            return {"total": total, "limit": limit, "offset": offset, "investigations": rows}
    except Exception:
        pass
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='investigations'")
        if cur.fetchone() is None:
            conn.close()
            return {"total": 0, "limit": limit, "offset": offset, "investigations": []}
        query = "SELECT id, title, status, severity, conclusion, created_by, created_at, updated_at FROM investigations"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = cur.execute(query, tuple(params)).fetchall()
        invs = [dict(r) for r in rows]
        conn.close()
        return {"total": len(invs), "limit": limit, "offset": offset, "investigations": invs}
    except Exception:
        return None


def get_offline_investigation(investigation_id: str) -> dict[str, Any] | None:
    """Retrieve full details of one investigation directly from SQLite."""
    _ensure_backend_on_path()
    try:
        from app.core.db import db_session
        from app.models import investigation as inv_store
        with db_session() as conn:
            inv = inv_store.get(conn, investigation_id)
            if inv:
                findings_rows = conn.execute(
                    "SELECT * FROM alerts WHERE investigation_id = ? ORDER BY id ASC",
                    (investigation_id,),
                ).fetchall()
                refs_rows = conn.execute(
                    "SELECT * FROM investigation_refs WHERE investigation_id = ? ORDER BY id ASC",
                    (investigation_id,),
                ).fetchall()
                notes_rows = conn.execute(
                    "SELECT * FROM investigation_notes WHERE investigation_id = ? ORDER BY id ASC",
                    (investigation_id,),
                ).fetchall()
                inv["findings"] = [dict(f) for f in findings_rows]
                inv["refs"] = [dict(r) for r in refs_rows]
                inv["notes"] = [dict(n) for n in notes_rows]
                return inv
    except Exception:
        pass
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return None
        inv = dict(row)
        inv["findings"] = []
        inv["refs"] = []
        inv["notes"] = []
        conn.close()
        return inv
    except Exception:
        return None


def get_offline_watchlist(limit: int = 50) -> list[dict[str, Any]] | None:
    """Query threat watchlist directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='watchlist'")
        if cur.fetchone() is None:
            conn.close()
            return []
        rows = cur.execute(
            "SELECT value, label, added_at FROM watchlist ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
        entries = []
        for r in rows:
            d = dict(r)
            d["created_at"] = d.get("added_at") or ""
            d["added_at"] = d.get("added_at") or ""
            entries.append(d)
        conn.close()
        return entries
    except Exception:
        return None


def add_offline_watchlist(value: str, label: str) -> dict[str, Any] | None:
    """Add or update an indicator in the local watchlist SQLite table."""
    _ensure_backend_on_path()
    try:
        import datetime
        from app.core.db import db_session
        from app.models import watchlist as wl_store
        with db_session() as conn:
            wl_store.add_watchlist(conn, value, label)
            conn.commit()
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return {"value": value, "label": label, "added_at": now_iso}
    except Exception:
        pass
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        import datetime
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO watchlist (value, label, added_at) VALUES (?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET label=excluded.label, added_at=excluded.added_at
            """,
            (value, label, now_iso),
        )
        conn.commit()
        conn.close()
        return {"value": value, "label": label, "added_at": now_iso}
    except Exception:
        return None


def remove_offline_watchlist(value: str) -> bool:
    """Remove an indicator from the local watchlist SQLite table."""
    _ensure_backend_on_path()
    try:
        from app.core.db import db_session
        from app.models import watchlist as wl_store
        with db_session() as conn:
            removed = wl_store.remove_watchlist(conn, value)
            conn.commit()
            return removed
    except Exception:
        pass
    db_path = find_db_path()
    if not db_path:
        return False
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute("DELETE FROM watchlist WHERE value = ?", (value,))
        rc = cur.rowcount > 0
        conn.commit()
        conn.close()
        return rc
    except Exception:
        return False


def export_offline_watchlist(format: str = "json") -> bytes | None:
    """Export the watchlist as JSON or CSV directly from SQLite."""
    entries = get_offline_watchlist(limit=1000)
    if entries is None:
        return None
    if format == "json":
        import json
        return json.dumps({"count": len(entries), "entries": entries}, indent=2).encode("utf-8")
    elif format == "csv":
        lines = ["value,label,added_at"]
        for e in entries:
            val = e.get("value", "").replace(",", "")
            lbl = e.get("label", "").replace(",", "")
            added = e.get("added_at", "")
            lines.append(f"{val},{lbl},{added}")
        return "\n".join(lines).encode("utf-8")
    return None


def get_offline_campaigns(limit: int = 50) -> list[dict[str, Any]] | None:
    """Query campaigns and shared C2 infrastructure directly from SQLite events."""
    _ensure_backend_on_path()
    try:
        from app.core.db import db_session
        from app.services import campaigns as campaigns_service
        with db_session() as conn:
            camps = campaigns_service.build_campaigns(conn, include_synthetic=True)
            if camps is not None:
                return camps[:limit]
    except Exception:
        pass
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if cur.fetchone() is None:
            conn.close()
            return []

        ip_rows = cur.execute(
            """
            SELECT dest_ip, COUNT(DISTINCT run_id) as run_count
            FROM events
            WHERE event_type = 'network_connection' AND dest_ip IS NOT NULL
              AND dest_ip NOT IN ('127.0.0.1', '0.0.0.0', '8.8.8.8', '1.1.1.1')
            GROUP BY dest_ip
            HAVING COUNT(DISTINCT run_id) >= 2
            ORDER BY run_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        campaigns = []
        for r in ip_rows:
            ip = r["dest_ip"]
            m_rows = cur.execute(
                """
                SELECT DISTINCT r.run_id, r.sample_name, r.platform
                FROM runs r
                JOIN events e ON r.run_id = e.run_id
                WHERE e.dest_ip = ?
                """,
                (ip,),
            ).fetchall()
            member_runs = [dict(mr) for mr in m_rows]
            campaigns.append({
                "key": f"campaign-{ip.replace('.', '-')}",
                "signature_ip": ip,
                "reputation": "malicious",
                "member_count": len(member_runs),
                "runs": member_runs,
                "iocs": {"ips": [{"value": ip, "runs": len(member_runs)}], "registry_keys": [], "file_paths": [], "processes": []},
                "timeline": [],
            })

        conn.close()
        return campaigns
    except Exception:
        return None


def get_offline_campaign_stix(campaign_key: str) -> dict[str, Any] | None:
    """Generate STIX 2.1 bundle for a campaign directly from SQLite offline."""
    _ensure_backend_on_path()
    try:
        from app.services.stix import build_campaign_stix_bundle
        bundle = build_campaign_stix_bundle(campaign_key)
        if "error" in bundle:
            return None
        return bundle
    except Exception:
        return None


def get_offline_navigator_layer() -> dict[str, Any] | None:
    """Generate MITRE ATT&CK Navigator v4.3 layer directly from detection rules offline."""
    _ensure_backend_on_path()
    try:
        from app.services.navigator import build_navigator_layer
        return build_navigator_layer()
    except Exception:
        return None


def get_offline_rules() -> list[dict[str, Any]]:
    """Retrieve full catalog of detection rules and MITRE ATT&CK mappings offline."""
    _ensure_backend_on_path()
    try:
        from app.services.risk import RULE_META, RULE_REMEDIATION, rule_name
        return [
            {
                "rule_id": rid,
                "id": rid,
                "name": rule_name(rid),
                "rule_name": rule_name(rid),
                "remediation": RULE_REMEDIATION.get(rid, []),
                **RULE_META[rid],
            }
            for rid in sorted(RULE_META)
        ]
    except Exception:
        return []


def get_offline_playbooks() -> list[dict[str, Any]]:
    """Retrieve full catalog of curated attack scenario playbooks offline."""
    _ensure_backend_on_path()
    try:
        from app.services.dynamic_sandbox import SIMULATION_SCENARIOS
        scenarios = []
        seen = set()
        for s in SIMULATION_SCENARIOS.values():
            if s["id"] in seen:
                continue
            seen.add(s["id"])
            scenarios.append({
                "id": s["id"],
                "name": s["name"],
                "severity": s.get("severity", "critical"),
                "platform": s.get("platform", "windows"),
                "description": s.get("description", ""),
                "tactics": s.get("tactics", []),
                "techniques": s.get("techniques", []),
                "stages_count": len(s.get("stages", [])),
                "stages": [{"name": st.get("name", ""), "cmd": st.get("cmd", "")} for st in s.get("stages", [])],
            })
        return scenarios
    except Exception:
        return []


def get_offline_forensics_snapshot() -> dict[str, Any]:
    """Capture live host forensic snapshot (CPU, memory, active processes, open sockets) directly from OS."""
    _ensure_backend_on_path()
    try:
        from app.services import host_forensics
        metrics = host_forensics.get_current_system_metrics()
        procs = host_forensics.get_live_processes()
        sockets = host_forensics.get_live_sockets()
        return {
            "metrics": metrics,
            "processes": procs,
            "sockets": sockets,
            "process_count": len(procs),
            "socket_count": len(sockets),
        }
    except Exception:
        try:
            import psutil
            mem = psutil.virtual_memory()
            metrics = {
                "platform": platform.system().lower(),
                "cpu_percent": psutil.cpu_percent(interval=0.05),
                "memory_used_mb": (mem.total - mem.available) / (1024 * 1024),
                "memory_total_mb": mem.total / (1024 * 1024),
                "memory_percent": mem.percent,
            }
            procs = []
            for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info", "cmdline"]):
                try:
                    info = p.info
                    procs.append({
                        "pid": info["pid"],
                        "name": info["name"] or "-",
                        "user": info["username"] or "-",
                        "cpu_percent": info.get("cpu_percent") or 0.0,
                        "memory_mb": (info["memory_info"].rss / (1024 * 1024)) if info.get("memory_info") else 0.0,
                        "cmdline": " ".join(info.get("cmdline") or []) if info.get("cmdline") else "-",
                    })
                except Exception:
                    continue
            return {
                "metrics": metrics,
                "processes": procs,
                "sockets": [],
                "process_count": len(procs),
                "socket_count": 0,
            }
        except Exception:
            return {"metrics": {}, "processes": [], "sockets": [], "process_count": 0, "socket_count": 0}


def get_offline_notes(run_id: str) -> list[dict[str, Any]] | None:
    """Query session analyst notes directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='run_notes'")
        if cur.fetchone() is None:
            conn.close()
            return []
        rows = cur.execute(
            "SELECT id, run_id, note, created_at FROM run_notes WHERE run_id = ? ORDER BY id ASC",
            (run_id,),
        ).fetchall()
        notes = [dict(r) for r in rows]
        conn.close()
        return notes
    except Exception:
        return None


def get_offline_allowlist(run_id: str) -> list[dict[str, Any]] | None:
    """Query run allowlist entries directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='run_allowlist'")
        if cur.fetchone() is None:
            conn.close()
            return []
        rows = cur.execute(
            "SELECT id, run_id, kind, value, note, created_at FROM run_allowlist WHERE run_id = ? ORDER BY id ASC",
            (run_id,),
        ).fetchall()
        entries = [dict(r) for r in rows]
        conn.close()
        return entries
    except Exception:
        return None


def add_offline_allowlist(run_id: str, kind: str, value: str, note: str) -> dict[str, Any] | None:
    """Add an entry to the run_allowlist table directly."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        import datetime
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO run_allowlist (run_id, kind, value, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (run_id, kind, value, note, now_iso),
        )
        new_id = cur.lastrowid
        # Also auto-ack any open alerts for this run matching the allowed value
        acked = 0
        if kind == "ip":
            cur.execute(
                "UPDATE alerts SET status = 'acknowledged' WHERE run_id = ? AND status = 'open' AND (details LIKE ? OR title LIKE ?)",
                (run_id, f"%{value}%", f"%{value}%"),
            )
            acked = cur.rowcount
        conn.commit()
        conn.close()
        return {
            "id": new_id,
            "run_id": run_id,
            "kind": kind,
            "value": value,
            "note": note,
            "created_at": now_iso,
            "acked": acked,
        }
    except Exception:
        return None


def remove_offline_allowlist(run_id: str, entry_id: int) -> bool:
    """Remove an entry from the run_allowlist table directly."""
    db_path = find_db_path()
    if not db_path:
        return False
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute("DELETE FROM run_allowlist WHERE id = ? AND run_id = ?", (entry_id, run_id))
        rc = cur.rowcount > 0
        conn.commit()
        conn.close()
        return rc
    except Exception:
        return False


def add_offline_note(run_id: str, note: str) -> dict[str, Any] | None:
    """Add a note to the run_notes table directly."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        import datetime
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO run_notes (run_id, note, created_at) VALUES (?, ?, ?)",
            (run_id, note, now_iso),
        )
        new_id = cur.lastrowid
        conn.commit()
        conn.close()
        return {"id": new_id, "run_id": run_id, "note": note, "created_at": now_iso}
    except Exception:
        return None


def get_offline_tuning_knobs() -> dict[str, Any] | None:
    """Retrieve rule tuning knobs with overrides directly from SQLite offline."""
    _ensure_backend_on_path()
    try:
        from app.api.routes_rules import TUNABLE_DEFAULTS, _parse_value
        from app.core.db import db_session
        with db_session() as conn:
            rows = conn.execute("SELECT rule_id, param, value FROM rule_tuning").fetchall()
            overrides = {(r["rule_id"], r["param"]): r["value"] for r in rows}
        knobs = []
        for name, (rule_id, type_name, default) in TUNABLE_DEFAULTS.items():
            raw = overrides.get((rule_id, name))
            current = default if raw is None else _parse_value(name, raw)
            knobs.append({
                "param": name,
                "rule_id": rule_id,
                "type": type_name,
                "default": default,
                "current": current,
                "tuned": raw is not None,
            })
        return {"count": len(knobs), "knobs": knobs}
    except Exception:
        return None


def get_offline_log_patterns() -> dict[str, Any] | None:
    """Retrieve anti-forensics log patterns directly offline."""
    _ensure_backend_on_path()
    try:
        from app.core.db import db_session
        from app.services.detection import load_log_patterns
        with db_session() as conn:
            raw = load_log_patterns(conn)
        kinds: dict[str, Any] = {}
        for kind, platforms in raw.items():
            kinds[kind] = {}
            for plat, patterns in platforms.items():
                kinds[kind][plat] = [{"pattern": p[0], "label": p[1]} for p in patterns]
        return {"kinds": kinds}
    except Exception:
        return None


def get_offline_suppressions() -> list[dict[str, Any]] | None:
    """Retrieve active rule suppressions directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='rule_suppressions'")
        if cur.fetchone() is None:
            conn.close()
            return []
        rows = cur.execute("SELECT id, rule_id, run_id, value, reason, created_at FROM rule_suppressions ORDER BY id ASC").fetchall()
        entries = [dict(r) for r in rows]
        conn.close()
        return entries
    except Exception:
        return None


def get_offline_run_stix(run_id: str) -> dict[str, Any] | None:
    """Build STIX 2.1 bundle for a run directly from SQLite."""
    _ensure_backend_on_path()
    try:
        from app.services.stix import build_stix_bundle
        return build_stix_bundle(run_id)
    except Exception:
        return None


def get_offline_run_comparison(run_id_a: str, run_id_b: str) -> dict[str, Any] | None:
    """Compare two runs directly from SQLite offline."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        ra = cur.execute("SELECT run_id, sample_name FROM runs WHERE run_id = ?", (run_id_a,)).fetchone()
        rb = cur.execute("SELECT run_id, sample_name FROM runs WHERE run_id = ?", (run_id_b,)).fetchone()
        if not ra or not rb:
            conn.close()
            return None

        def _get_items(rid: str):
            procs = {r[0] for r in cur.execute("SELECT DISTINCT process_name FROM events WHERE run_id = ? AND process_name IS NOT NULL", (rid,)).fetchall()}
            ips = {r[0] for r in cur.execute("SELECT DISTINCT dest_ip FROM events WHERE run_id = ? AND dest_ip IS NOT NULL", (rid,)).fetchall()}
            return procs, ips

        pa, ia = _get_items(run_id_a)
        pb, ib = _get_items(run_id_b)
        conn.close()

        def _diff(sa: set, sb: set):
            return {
                "only_a": sorted(sa - sb),
                "shared": sorted(sa & sb),
                "only_b": sorted(sb - sa),
            }

        return {
            "run_a": dict(ra),
            "run_b": dict(rb),
            "processes": _diff(pa, pb),
            "ips": _diff(ia, ib),
        }
    except Exception:
        return None


def get_offline_yara_rules() -> dict[str, Any]:
    """Retrieve custom YARA rules directly from SQLite settings table."""
    db_path = find_db_path()
    if not db_path:
        return {"count": 0, "rules": []}
    try:
        import json
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'custom_yara_rules'")
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            rules = json.loads(row[0])
            return {"count": len(rules), "rules": rules}
        return {"count": 0, "rules": []}
    except Exception:
        return {"count": 0, "rules": []}


def seed_offline_demo() -> dict[str, Any]:
    """Seed realistic, honestly labeled demo telemetry and SOC incident cases into local SQLite."""
    _ensure_backend_on_path()
    from app import seed_campaign, seed_demo
    from app.core.db import db_session, init_db

    init_db()
    demo_run = seed_demo.main()
    campaign_runs = seed_campaign.main()

    with db_session() as conn:
        inv_count = conn.execute("SELECT count(*) FROM investigations").fetchone()[0]
        if inv_count == 0:
            import datetime
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            conn.execute(
                """
                INSERT INTO investigations (id, title, status, severity, conclusion, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "INC-2026-001",
                    "Suspicious C2 Beaconing to External IP (203.0.113.88)",
                    "active",
                    "malicious",
                    "Dual-variant macro execution observed beaconing to common adversary command & control port.",
                    "soc-analyst",
                    now_iso,
                    now_iso,
                ),
            )

        wl_count = conn.execute("SELECT count(*) FROM watchlist").fetchone()[0]
        if wl_count == 0:
            import datetime
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO watchlist (value, label, added_at) VALUES (?, ?, ?)",
                ("203.0.113.88", "Campaign C2 Beacon Node", now_iso),
            )
            conn.execute(
                "INSERT INTO watchlist (value, label, added_at) VALUES (?, ?, ?)",
                ("185.220.101.34", "Known Secondary C2", now_iso),
            )
        conn.commit()

    return {
        "status": "success",
        "demo_run": demo_run,
        "campaign_runs": campaign_runs,
    }


def triage_offline_alerts(alert_ids: list[int], status: str, comment: str = "") -> dict[str, Any]:
    """Update alerts status directly in SQLite."""
    import datetime
    db_path = find_db_path()
    if not db_path:
        return {"updated": 0, "status": status}
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    placeholders = ",".join("?" for _ in alert_ids)
    cur.execute(
        f"UPDATE alerts SET status = ?, status_comment = ?, status_at = ? WHERE id IN ({placeholders})",
        (status, comment, now_iso, *alert_ids),
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return {"updated": count, "status": status, "ids": alert_ids}


def create_offline_investigation(title: str, severity: str = "medium", conclusion: str = "") -> dict[str, Any] | None:
    """Create a new incident investigation in SQLite."""
    import datetime
    db_path = find_db_path()
    if not db_path:
        return None
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    inv_id = f"INC-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}"
    cur.execute(
        """
        INSERT INTO investigations (id, title, status, severity, conclusion, created_by, created_at, updated_at)
        VALUES (?, ?, 'active', ?, ?, 'analyst', ?, ?)
        """,
        (inv_id, title, severity, conclusion, now_iso, now_iso),
    )
    conn.commit()
    conn.close()
    return {
        "id": inv_id,
        "title": title,
        "status": "active",
        "severity": severity,
        "created_at": now_iso,
    }


def add_offline_investigation_note(investigation_id: str, content: str, author: str = "analyst") -> dict[str, Any] | None:
    """Add a note to an investigation in SQLite."""
    import datetime
    db_path = find_db_path()
    if not db_path:
        return None
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cur.execute(
        """
        INSERT INTO investigation_notes (investigation_id, author, content, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (investigation_id, author, content, now_iso),
    )
    cur.execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (now_iso, investigation_id))
    conn.commit()
    conn.close()
    return {"investigation_id": investigation_id, "author": author, "content": content, "created_at": now_iso}


def update_offline_investigation_status(investigation_id: str, status: str) -> dict[str, Any] | None:
    """Update investigation status (active / closed)."""
    import datetime
    db_path = find_db_path()
    if not db_path:
        return None
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    closed_at = now_iso if status.lower() == "closed" else None
    cur.execute(
        "UPDATE investigations SET status = ?, updated_at = ?, closed_at = ? WHERE id = ?",
        (status, now_iso, closed_at, investigation_id),
    )
    conn.commit()
    conn.close()
    return {"id": investigation_id, "status": status, "updated_at": now_iso}


def attach_offline_investigation_alert(investigation_id: str, alert_id: int) -> bool:
    """Link an alert finding to an investigation in SQLite."""
    import datetime
    db_path = find_db_path()
    if not db_path:
        return False
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cur.execute("UPDATE alerts SET investigation_id = ? WHERE id = ?", (investigation_id, alert_id))
    try:
        cur.execute(
            "INSERT INTO investigation_refs (investigation_id, ref_type, ref_id, created_at) VALUES (?, 'alert', ?, ?)",
            (investigation_id, str(alert_id), now_iso),
        )
    except Exception:
        pass
    conn.commit()
    conn.close()
    return True


def isolate_offline_host(host_id: str, isolated: bool = True, reason: str = "") -> dict[str, Any]:
    """Toggle host containment in SQLite."""
    import datetime
    db_path = find_db_path()
    if not db_path:
        return {"host_id": host_id, "isolated": isolated, "error": "No database"}
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cur.execute(
        """
        INSERT INTO host_containment (host_id, isolated, isolated_at, isolated_by, reason, updated_at)
        VALUES (?, ?, ?, 'analyst', ?, ?)
        ON CONFLICT(host_id) DO UPDATE SET
            isolated = excluded.isolated,
            isolated_at = excluded.isolated_at,
            reason = excluded.reason,
            updated_at = excluded.updated_at
        """,
        (host_id, 1 if isolated else 0, now_iso, reason, now_iso),
    )
    conn.commit()
    conn.close()
    return {"host_id": host_id, "isolated": isolated}

