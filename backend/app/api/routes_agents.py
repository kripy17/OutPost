"""Agent fleet status (audit gap #1) — which hosts are streaming telemetry.

GET /agents — one row per distinct `host_id` seen in the events table:
last heartbeat, event + alert counts, platform mix, and an online/offline
flag (online = event within the last 2 minutes). Events without an explicit
host (webapp detonations, sandbox runs) normalize to `host_id = 'local'`, so
the fleet always shows at least the machine running the backend.

The collectors stamp every shipped event with their host identity (see
collectors/common/shipper.py), which is what makes multi-host monitoring
possible: open the Live Monitor on any machine running `outpost agent run`
and its events land here attributed to that host.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from ..core.db import db_session

router = APIRouter(tags=["agents"])

# An agent is "online" when it shipped at least one event this recently.
ONLINE_WINDOW_SECONDS = 120


@router.get("/agents/{host_id}/snapshot", response_model=None)
def get_host_snapshot(host_id: str) -> dict:
    """The latest live system snapshot for a host (processes + listening
    ports), as shipped by its collector. 404 when the host never shipped one."""
    import json as _json

    with db_session() as conn:
        row = conn.execute(
            "SELECT payload, collected_at FROM host_snapshots WHERE host_id = ?",
            (host_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"No snapshot for host {host_id} — is its agent running?")
    payload = _json.loads(row["payload"])
    payload["stored_at"] = row["collected_at"]
    return payload


@router.get("/agents", response_model=None)
def list_agents(online_window: int = Query(ONLINE_WINDOW_SECONDS, ge=10, le=3600)) -> dict:
    """Fleet overview grouped by host_id."""
    now = datetime.now(timezone.utc)
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT e.host_id,
                   MAX(e.timestamp)                                  AS last_seen,
                   COUNT(*)                                          AS event_count,
                   COUNT(DISTINCT e.run_id)                          AS run_count,
                   GROUP_CONCAT(DISTINCT e.platform)                 AS platforms,
                   (SELECT COUNT(*) FROM alerts a
                    JOIN runs r ON r.run_id = a.run_id
                    WHERE r.run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = e.host_id))
                                                                    AS alert_count,
                   (SELECT GROUP_CONCAT(run_id) FROM
                      (SELECT DISTINCT run_id FROM events WHERE host_id = e.host_id
                       ORDER BY timestamp DESC LIMIT 5))             AS recent_run_ids
            FROM events e
            GROUP BY e.host_id
            ORDER BY last_seen DESC
            """
        ).fetchall()

    with db_session() as conn:
        snap_rows = {
            r["host_id"]: r["collected_at"]
            for r in conn.execute("SELECT host_id, collected_at FROM host_snapshots").fetchall()
        }

    agents = []
    for r in rows:
        last_seen = r["last_seen"]
        try:
            last_dt = datetime.fromisoformat(last_seen)
        except ValueError:
            last_dt = now
        online = (now - last_dt).total_seconds() <= online_window
        agents.append(
            {
                "host_id": r["host_id"],
                "last_seen": last_seen,
                "online": online,
                "event_count": r["event_count"],
                "run_count": r["run_count"],
                "alert_count": r["alert_count"],
                "platforms": sorted({p for p in (r["platforms"] or "").split(",") if p}),
                "recent_run_ids": [rid for rid in (r["recent_run_ids"] or "").split(",") if rid][:5],
                "last_snapshot_at": snap_rows.get(r["host_id"]),
            }
        )
    # Snapshot-only hosts (an agent that shipped a "running now" view but no
    # events yet) still belong in the fleet.
    known = {a["host_id"] for a in agents}
    for host_id, collected_at in snap_rows.items():
        if host_id in known:
            continue
        agents.append(
            {
                "host_id": host_id,
                "last_seen": collected_at,
                "online": False,
                "event_count": 0,
                "run_count": 0,
                "alert_count": 0,
                "platforms": [],
                "recent_run_ids": [],
                "last_snapshot_at": collected_at,
            }
        )

    return {
        "total": len(agents),
        "online": sum(1 for a in agents if a["online"]),
        "online_window_seconds": online_window,
        "agents": agents,
    }
