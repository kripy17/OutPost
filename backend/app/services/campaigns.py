"""Campaign clustering — runs that share infrastructure (webapp "Campaigns" view).

A campaign is the set of runs that share a single "signature" IOC. We anchor
on dest_ips shared by >= 2 runs — IP reuse is the strongest real-world signal
of shared infrastructure. Two guards keep the view honest:

- Known-clean IPs (enrichment-cache reputation == "clean") never anchor a
  campaign — a shared DNS resolver is not a campaign.
- IPs observed in only one run never anchor one.

Each campaign carries its member runs (RunSummary), the union of IOCs
observed across members (with per-value member counts), and a combined,
run-attributed timeline. Campaigns rank malicious/suspicious (or
watchlisted) infrastructure first, then by member count.
"""

from ..models import run as run_store
from ..models.event import get_cache
from ..models.run import SYNTHETIC_SOURCES
from ..models.watchlist import get_watchlist
from ..services import killchain

_SEVERITY_RANK = {"malicious": 0, "suspicious": 1, None: 2, "unknown": 3}


def _candidate_ips(conn) -> list[str]:
    """IPs connected to by two or more runs — possible campaign anchors."""
    rows = conn.execute(
        """
        SELECT dest_ip
        FROM events
        WHERE event_type = 'network_connection' AND dest_ip IS NOT NULL
        GROUP BY dest_ip
        HAVING COUNT(DISTINCT run_id) >= 2
        """
    ).fetchall()
    return [r["dest_ip"] for r in rows]


def _anchor(conn, ip: str) -> dict | None:
    """Display metadata for a candidate anchor IP, or None if it should not
    form a campaign (known-clean infrastructure)."""
    cached = get_cache(conn, ip)
    reputation = cached["reputation"] if cached else None
    if reputation == "clean":
        return None
    wl = get_watchlist(conn, ip)
    return {
        "reputation": reputation,
        "watchlist": bool(wl),
        "watchlist_label": wl["label"] if wl else None,
    }


def _evidence(conn, placeholders: str, run_ids: list[str], column: str) -> list[dict]:
    """Distinct values of a column across the member runs, with member counts.

    `column` is always a literal from the call sites below (never user input).
    """
    rows = conn.execute(
        f"""
        SELECT {column} AS value, COUNT(DISTINCT run_id) AS runs
        FROM events
        WHERE run_id IN ({placeholders}) AND {column} IS NOT NULL
        GROUP BY {column}
        ORDER BY runs DESC, value ASC
        """,
        run_ids,
    ).fetchall()
    return [{"value": r["value"], "runs": r["runs"]} for r in rows]


def campaigns_for_run(conn, run_id: str) -> list[dict]:
    """Compact references to the campaigns a run belongs to (for exports).

    Same clustering rules as build_campaigns, but returns only the signature
    IPs this run is part of — enough to link an exported report back to its
    campaign without computing the full clusters.
    """
    refs: list[dict] = []
    for ip in _candidate_ips(conn):
        anchor = _anchor(conn, ip)
        if anchor is None:
            continue
        row = conn.execute(
            """
            SELECT 1 FROM events
            WHERE run_id = ? AND event_type = 'network_connection' AND dest_ip = ?
            LIMIT 1
            """,
            (run_id, ip),
        ).fetchone()
        if row:
            refs.append({"key": ip, **anchor})
    refs.sort(key=lambda r: (_SEVERITY_RANK.get(r["reputation"], 2), r["key"]))
    return refs


def build_campaigns(conn, include_synthetic: bool = False) -> list[dict]:
    """Every campaign in run history, strongest first. Synthetic provenance
    (seeds / webapp detonations / the sandbox demo) is excluded by default,
    mirroring the runs archive and Event Log — campaigns read as real
    telemetry first. A campaign whose members fall below the two-run
    clustering invariant after the filter is dropped entirely.
    """
    campaigns: list[dict] = []
    for ip in _candidate_ips(conn):
        anchor = _anchor(conn, ip)
        if anchor is None:
            continue

        excl = "" if include_synthetic else " AND r.source NOT IN (?,?,?,?)"
        args: list = [] if include_synthetic else list(SYNTHETIC_SOURCES)
        run_rows = conn.execute(
            f"""
            SELECT DISTINCT r.*
            FROM runs r
            JOIN events e ON e.run_id = r.run_id
            WHERE e.dest_ip = ? AND e.event_type = 'network_connection'{excl}
            ORDER BY r.started_at DESC
            """,
            (ip, *args),
        ).fetchall()
        run_ids = [r["run_id"] for r in run_rows]
        # The clustering rule is two runs sharing the IP; a campaign reduced
        # below that by the synthetic filter is no longer a campaign.
        if len(run_ids) < 2:
            continue
        placeholders = ",".join("?" * len(run_ids))

        # Projected timeline: only the columns the UI renders (eventDetail),
        # capped at the 300 most recent rows. The full `e.*` here pulled every
        # raw_record across all member runs — on a soak-scale store that was
        # ~15MB of JSON per /campaigns call and >1s of serialization for a
        # timeline the UI truncates to 40 rows anyway. The honest total is
        # shipped separately as timeline_total for the "N events" label.
        timeline_rows = conn.execute(
            f"""
            SELECT e.id, e.timestamp, e.event_type, e.pid, e.ppid, e.process_name,
                   e.command_line, e.dest_ip, e.dest_port, e.protocol, e.file_path,
                   e.registry_key, e.run_id, r.sample_name
            FROM events e
            JOIN runs r ON r.run_id = e.run_id
            WHERE e.run_id IN ({placeholders})
            ORDER BY e.timestamp DESC, e.id DESC
            LIMIT 300
            """,
            run_ids,
        ).fetchall()
        timeline_rows.reverse()  # chronological again for display
        timeline = [dict(r) for r in timeline_rows]
        timeline_total = conn.execute(
            f"SELECT COUNT(*) AS n FROM events WHERE run_id IN ({placeholders})",
            run_ids,
        ).fetchone()["n"]

        # Roadmap 2.4 — correlated chain across the member runs: the union of
        # stage→stage links observed by any member, plus the most advanced
        # arc label. Campaigns with a fuller chain rank as higher-signal.
        member_alerts = conn.execute(
            f"""
            SELECT a.run_id, a.rule_id, a.triggered_at
            FROM alerts a
            WHERE a.run_id IN ({placeholders})
            ORDER BY a.triggered_at ASC
            """,
            run_ids,
        ).fetchall()
        chain_links = killchain.correlate_chain([dict(a) for a in member_alerts])

        campaigns.append(
            {
                "key": ip,
                **anchor,
                "runs": [run_store.to_summary(conn, dict(r)).model_dump(mode="json") for r in run_rows],
                "span_start": timeline[0]["timestamp"] if timeline else None,
                "span_end": timeline[-1]["timestamp"] if timeline else None,
                "iocs": {
                    "ips": _evidence(conn, placeholders, run_ids, "dest_ip"),
                    "registry_keys": _evidence(conn, placeholders, run_ids, "registry_key"),
                    "file_paths": _evidence(conn, placeholders, run_ids, "file_path"),
                    "processes": _evidence(conn, placeholders, run_ids, "process_name"),
                },
                "timeline": timeline,
                "timeline_total": timeline_total,
                "chain_links": chain_links,
                "chain_label": killchain.chain_label(chain_links),
            }
        )

    campaigns.sort(
        key=lambda c: (_SEVERITY_RANK.get(c["reputation"], 2), -len(c["runs"]), c["key"])
    )
    return campaigns
