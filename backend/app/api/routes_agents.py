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

from fastapi import APIRouter, HTTPException, Query, Request

from ..core.db import db_session

router = APIRouter(tags=["agents"])

# An agent is "online" when it heartbeated (or shipped an event) this recently.
ONLINE_WINDOW_SECONDS = 120
# A host that heartbeated before but hasn't for this long is "silent" — the
# collector died, was uninstalled, or the network path broke.
SILENT_WINDOW_SECONDS = 600


@router.post("/agents/{host_id}/heartbeat", response_model=None)
def post_heartbeat(
    host_id: str,
    request: Request,
    payload: dict | None = None,
) -> dict:
    """Liveness ping from a running collector — upserted per host.

    The collector pings every ~60s regardless of event volume, so a quiet
    host (no events in the window) still reads as online, and a dead agent
    is flagged silent instead of blending in with hosts that never shipped
    anything.
    """
    import json as _json

    from ..core import auth as auth_service
    from ..services import fleet_health

    payload = payload or {}
    now = datetime.now(timezone.utc).isoformat()
    # Last-auth context: how THIS heartbeat authenticated — 'agent' (the
    # shared OUTPOST_AGENT_TOKEN), 'admin'/'analyst' (browser roles), or
    # 'local' (auth off / no credential). This is what lets the fleet view
    # tell collector-shipped hosts (authenticated as the agent) apart from
    # webapp-local traffic.
    auth_role = auth_service.role_from_request(request)
    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO agent_heartbeats (host_id, last_heartbeat, platform, version, last_auth_role, last_auth_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                last_heartbeat = excluded.last_heartbeat,
                platform = COALESCE(excluded.platform, agent_heartbeats.platform),
                version = COALESCE(excluded.version, agent_heartbeats.version),
                last_auth_role = excluded.last_auth_role,
                last_auth_at = excluded.last_auth_at
            """,
            (host_id, now, payload.get("platform"), payload.get("version"), auth_role, now),
        )
        # The host is alive again — a silent episode (if any) is over; the
        # next silence pages fresh.
        fleet_health.clear_notified(conn, host_id)

    # Live fleet push: the Agents page and Overview host panel flip this host
    # to online the moment the ping lands (polling stays as the fallback).
    from ..services import events_stream

    events_stream.publish_fleet_update(host_id, online=True, silent=False, last_heartbeat=now)
    return {"status": "ok", "host_id": host_id, "last_heartbeat": now}


@router.get("/hosts/{host_id}/watch", response_model=None)
def watch_host(host_id: str) -> dict:
    """The run to open when an operator says "watch this host" — its newest
    open live session if one is running, otherwise its most recent session.
    404 when the host has shipped no events yet. The Monitor page drives its
    host-watch mode off this."""
    from ..models import run as run_store

    with db_session() as conn:
        row = conn.execute(
            """
            SELECT r.* FROM runs r
            WHERE r.run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)
            ORDER BY (r.completed_at IS NULL) DESC, r.started_at DESC
            LIMIT 1
            """,
            (host_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"No sessions from host {host_id} yet")
        open_run = row["completed_at"] is None
        summary = run_store.to_summary(conn, row)
    return {"run_id": row["run_id"], "open": open_run, "run": summary.model_dump()}


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


@router.get("/baselines/{host_id}", response_model=None)
def get_host_baseline(host_id: str) -> dict:
    """The behavioral baseline learned for one host: what binaries it runs
    and which IPs it talks to, with observation counts. 404 when the host
    has shipped no events yet."""
    with db_session() as conn:
        rows = conn.execute(
            "SELECT kind, value, count, last_seen FROM host_baselines WHERE host_id = ? "
            "ORDER BY count DESC",
            (host_id,),
        ).fetchall()
        total_row = conn.execute(
            "SELECT COALESCE(SUM(count), 0) AS n, COUNT(*) AS distinct_obs "
            "FROM host_baselines WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        anomalies = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts a JOIN runs r ON r.run_id = a.run_id "
            "WHERE a.rule_id = 'baseline-anomaly' AND r.run_id IN "
            "(SELECT DISTINCT run_id FROM events WHERE host_id = ?)",
            (host_id,),
        ).fetchone()["n"]
    processes = [dict(x) for x in rows if x["kind"] == "process"]
    nets = [dict(x) for x in rows if x["kind"] == "net"]
    return {
        "host_id": host_id,
        "total_observations": total_row["n"],
        "distinct_observations": total_row["distinct_obs"],
        "processes": processes,
        "networks": nets,
        "anomaly_count": anomalies,
    }


@router.delete("/baselines/{host_id}", response_model=None)
def reset_host_baseline(host_id: str) -> dict:
    """Forget everything learned about a host — the baseline starts over from
    its next batch (useful after an operator deliberately changes what the
    host should do, e.g. a new toolchain install)."""
    with db_session() as conn:
        conn.execute("DELETE FROM host_baselines WHERE host_id = ?", (host_id,))
    return {"host_id": host_id, "reset": True}


@router.get("/agents", response_model=None)
def list_agents(
    online_window: int = Query(ONLINE_WINDOW_SECONDS, ge=10, le=3600),
    silent_window: int = Query(SILENT_WINDOW_SECONDS, ge=60, le=86400),
) -> dict:
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
                   GROUP_CONCAT(DISTINCT COALESCE(e.log_source, 'webapp')) AS channels,
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
        hb_rows = {
            r["host_id"]: r
            for r in conn.execute(
                "SELECT host_id, last_heartbeat, platform, version, last_auth_role, last_auth_at "
                "FROM agent_heartbeats"
            ).fetchall()
        }

    def _age_seconds(iso: str | None) -> int | None:
        if not iso:
            return None
        try:
            return max(0, int((now - datetime.fromisoformat(iso)).total_seconds()))
        except ValueError:
            return None

    agents = []
    for r in rows:
        last_seen = r["last_seen"]
        try:
            last_dt = datetime.fromisoformat(last_seen)
        except ValueError:
            last_dt = now
        hb = hb_rows.get(r["host_id"])
        hb_age = _age_seconds(hb["last_heartbeat"] if hb else None)
        online = (now - last_dt).total_seconds() <= online_window or (
            hb_age is not None and hb_age <= online_window
        )
        silent = hb is not None and (hb_age or 0) > silent_window
        agents.append(
            {
                "host_id": r["host_id"],
                "last_seen": last_seen,
                "online": online,
                "silent": silent,
                "last_heartbeat": hb["last_heartbeat"] if hb else None,
                "heartbeat_age_seconds": hb_age,
                "heartbeat_version": hb["version"] if hb else None,
                # Last-auth context + identity: only real collectors heartbeat
                # (with version=outpost-collector/1.0), so a heartbeat marks a
                # collector-shipped host; event-only hosts (webapp detonations,
                # sandbox runs) read as 'webapp'. Channels come from the events'
                # own log_source stamp (auditd / sysmon / webapp).
                "last_auth_role": hb["last_auth_role"] if hb else None,
                "last_auth_at": hb["last_auth_at"] if hb else None,
                "identity": "collector" if hb else "webapp",
                "channels": sorted({c for c in (r["channels"] or "").split(",") if c}),
                "event_count": r["event_count"],
                "run_count": r["run_count"],
                "alert_count": r["alert_count"],
                "platforms": sorted({p for p in (r["platforms"] or "").split(",") if p}),
                "recent_run_ids": [rid for rid in (r["recent_run_ids"] or "").split(",") if rid][:5],
                "last_snapshot_at": snap_rows.get(r["host_id"]),
            }
        )
    # Snapshot- or heartbeat-only hosts (an agent that shipped a "running now"
    # view or a liveness ping but no events yet) still belong in the fleet.
    known = {a["host_id"] for a in agents}
    extra_hosts = {**{h: None for h in snap_rows}, **{h: None for h in hb_rows}}
    for host_id in extra_hosts:
        if host_id in known:
            continue
        collected_at = snap_rows.get(host_id)
        hb = hb_rows.get(host_id)
        hb_age = _age_seconds(hb["last_heartbeat"] if hb else None)
        online = hb_age is not None and hb_age <= online_window or (
            collected_at is not None
            and (now - datetime.fromisoformat(collected_at)).total_seconds() <= online_window
        )
        agents.append(
            {
                "host_id": host_id,
                "last_seen": hb["last_heartbeat"] if hb else collected_at,
                "online": online,
                "silent": hb is not None and (hb_age or 0) > silent_window,
                "last_heartbeat": hb["last_heartbeat"] if hb else None,
                "heartbeat_age_seconds": hb_age,
                "heartbeat_version": hb["version"] if hb else None,
                "last_auth_role": hb["last_auth_role"] if hb else None,
                "last_auth_at": hb["last_auth_at"] if hb else None,
                "identity": "collector" if hb else "webapp",
                "channels": [],
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
        "silent": sum(1 for a in agents if a["silent"]),
        "online_window_seconds": online_window,
        "silent_window_seconds": silent_window,
        "agents": agents,
    }
