"""IOC extraction & export (Phase 6 Task 23 — docs/10-STANDOUT-FEATURES.md #1).

Pure aggregation over the `events` table, deduplicated — no new analysis
logic. The resulting list is the reusable output of an analysis session:
paste it into tickets, notes, or other tools.
"""

import csv
import io


def _collect(conn, run_id: str, column: str, event_type: str, ioc_type: str) -> list[dict]:
    """Deduplicated IOC values of one kind, with their first-seen timestamp.

    `column`/`event_type` are hardcoded literals at call sites — never user
    input — so f-string SQL here is safe.
    """
    rows = conn.execute(
        f"""
        SELECT {column} AS value, MIN(timestamp) AS first_seen
        FROM events
        WHERE run_id = ? AND event_type = ? AND {column} IS NOT NULL AND {column} != ''
        GROUP BY {column}
        ORDER BY first_seen ASC
        """,
        (run_id, event_type),
    ).fetchall()
    return [
        {"type": ioc_type, "value": r["value"], "first_seen": r["first_seen"]}
        for r in rows
    ]


def extract_iocs(conn, run_id: str) -> dict:
    """Collect every IOC observed in a run, deduplicated, oldest first.

    IP-type IOCs carry `checked_at` from the enrichment cache (the age of the
    reputation verdict), so exports show the same staleness the UI does.
    """
    iocs: list[dict] = []
    iocs += _collect(conn, run_id, "dest_ip", "network_connection", "ip")
    iocs += _collect(conn, run_id, "file_path", "file_write", "file_path")
    iocs += _collect(conn, run_id, "registry_key", "registry_write", "registry_key")
    iocs += _collect(conn, run_id, "process_name", "process_create", "process")
    for ioc in iocs:
        if ioc["type"] == "ip":
            cached = conn.execute(
                "SELECT checked_at FROM enrichment_cache WHERE ip = ?",
                (ioc["value"],),
            ).fetchone()
            ioc["checked_at"] = cached["checked_at"] if cached else None
        else:
            ioc["checked_at"] = None
    return {"run_id": run_id, "count": len(iocs), "iocs": iocs}


def iocs_to_csv(data: dict) -> str:
    """Serialize extracted IOCs to CSV (type, value, first_seen, checked_at).

    `checked_at` carries the reputation cache age for IP IOCs (blank for
    other types / never-checked) — the export's staleness column.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "first_seen", "checked_at"])
    for ioc in data["iocs"]:
        writer.writerow([ioc["type"], ioc["value"], ioc["first_seen"], ioc.get("checked_at") or ""])
    return buf.getvalue()
