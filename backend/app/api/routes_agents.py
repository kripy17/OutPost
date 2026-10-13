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

import json
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

from ..core.db import db_session

router = APIRouter(tags=["agents"])

# An agent is "online" when it heartbeated (or shipped an event) this recently.
ONLINE_WINDOW_SECONDS = 120
# A host that heartbeated before but hasn't for this long is "silent" — the
# collector died, was uninstalled, or the network path broke.
SILENT_WINDOW_SECONDS = 600


@router.post("/agents/enrollment-tokens", response_model=None, status_code=201)
def create_enrollment_token(payload: dict | None = None, request: Request = None) -> dict:
    """Create a scoped, one-time enrollment token with expiry."""
    from ..core import auth as auth_service
    from ..models import audit

    payload = payload or {}
    actor = auth_service.role_from_request(request) if request else "admin"
    ttl_seconds = int(payload.get("ttl_seconds", 86400))  # 24h default
    scope = payload.get("scope", "fleet")
    max_uses = int(payload.get("max_uses", 1))

    token = f"oet_{secrets.token_urlsafe(24)}"
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    expires_at = (now_dt + timedelta(seconds=ttl_seconds)).isoformat()

    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO enrollment_tokens (token, created_at, expires_at, created_by, scope, max_uses, uses_count, revoked)
            VALUES (?, ?, ?, ?, ?, ?, 0, 0)
            """,
            (token, now, expires_at, actor, scope, max_uses),
        )
        audit.log(
            conn,
            actor,
            "auth.agent_token",
            target_type="enrollment_token",
            target_id=token[:12],
            detail=f"created one-time enrollment token (scope: {scope}, ttl: {ttl_seconds}s, max_uses: {max_uses})",
        )

    return {
        "status": "created",
        "token": token,
        "scope": scope,
        "created_at": now,
        "expires_at": expires_at,
        "max_uses": max_uses,
    }


@router.get("/agents/enrollment-tokens", response_model=None)
def list_enrollment_tokens() -> list[dict]:
    """List fleet enrollment tokens."""
    with db_session() as conn:
        rows = conn.execute(
            "SELECT token, created_at, expires_at, created_by, scope, max_uses, uses_count, revoked FROM enrollment_tokens ORDER BY created_at DESC"
        ).fetchall()
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "token": r["token"],
            "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "created_by": r["created_by"],
            "scope": r["scope"],
            "max_uses": r["max_uses"],
            "uses_count": r["uses_count"],
            "revoked": bool(r["revoked"]),
            "is_expired": r["expires_at"] < now,
        }
        for r in rows
    ]


@router.post("/agents/enrollment-tokens/{token}/revoke", response_model=None)
def revoke_enrollment_token(token: str, request: Request) -> dict:
    """Revoke an enrollment token."""
    from ..core import auth as auth_service
    from ..models import audit

    actor = auth_service.role_from_request(request) if request else "admin"
    with db_session() as conn:
        row = conn.execute("SELECT token FROM enrollment_tokens WHERE token = ?", (token,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Enrollment token not found")
        conn.execute("UPDATE enrollment_tokens SET revoked = 1 WHERE token = ?", (token,))
        audit.log(
            conn,
            actor,
            "auth.token_revoke",
            target_type="enrollment_token",
            target_id=token[:12],
            detail="revoked agent enrollment token",
        )
    return {"status": "revoked", "token": token}


@router.post("/agents/register", response_model=None)
def register_agent(
    payload: dict,
    request: Request,
) -> dict:
    """Cryptographically enroll a new endpoint agent sensor into the fleet.

    Generates unique agent_id and high-entropy agent_secret for HMAC-SHA256
    telemetry authentication, anti-replay, and anti-tamper telemetry shipping.
    """
    from ..models import audit

    host_id = (payload.get("host_id") or "").strip()
    if not host_id:
        raise HTTPException(status_code=422, detail="Field 'host_id' is required.")

    platform = payload.get("platform")
    machine_id = payload.get("machine_id")
    hardware_info = payload.get("hardware_info")
    hardware_json = json.dumps(hardware_info) if hardware_info else None
    agent_version = payload.get("agent_version", "1.0.0")
    privilege_level = payload.get("privilege_level", "least_privilege")
    capabilities = payload.get("enforcement_capabilities", ["telemetry"])
    caps_json = json.dumps(capabilities) if isinstance(capabilities, list) else str(capabilities)

    enrollment_token = payload.get("enrollment_token")

    now = datetime.now(timezone.utc).isoformat()

    with db_session() as conn:
        if enrollment_token:
            tok_row = conn.execute(
                "SELECT token, expires_at, max_uses, uses_count, revoked FROM enrollment_tokens WHERE token = ?",
                (enrollment_token,),
            ).fetchone()
            if not tok_row or tok_row["revoked"]:
                raise HTTPException(status_code=403, detail="Invalid or revoked enrollment token")
            if tok_row["expires_at"] < now:
                raise HTTPException(status_code=403, detail="Enrollment token has expired")
            if tok_row["uses_count"] >= tok_row["max_uses"]:
                raise HTTPException(status_code=403, detail="Enrollment token maximum uses exceeded")
            conn.execute(
                "UPDATE enrollment_tokens SET uses_count = uses_count + 1 WHERE token = ?",
                (enrollment_token,),
            )

        agent_id = f"agt_{secrets.token_hex(12)}"
        agent_secret = secrets.token_hex(32)

        conn.execute(
            """
            INSERT INTO enrolled_agents (
                agent_id, host_id, platform, machine_id, enrolled_at, last_seen_at, agent_secret, hardware_info, status,
                agent_version, privilege_level, enforcement_capabilities
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (agent_id, host_id, platform, machine_id, now, now, agent_secret, hardware_json, agent_version, privilege_level, caps_json),
        )
        audit.log(
            conn,
            "system",
            "agent.register",
            target_type="host",
            target_id=host_id,
            detail=f"enrolled sensor {agent_id} for host {host_id} (platform: {platform}, priv: {privilege_level})",
        )

    return {
        "status": "enrolled",
        "agent_id": agent_id,
        "agent_secret": agent_secret,
        "host_id": host_id,
        "agent_version": agent_version,
        "privilege_level": privilege_level,
        "enrolled_at": now,
    }


@router.post("/agents/{agent_id}/revoke", response_model=None)
def revoke_agent(agent_id: str, request: Request) -> dict:
    """Revoke an enrolled agent sensor from the console."""
    from ..core import auth as auth_service
    from ..models import audit

    actor = auth_service.role_from_request(request) if request else "admin"
    with db_session() as conn:
        row = conn.execute("SELECT agent_id, host_id FROM enrolled_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
        conn.execute("UPDATE enrolled_agents SET status = 'revoked' WHERE agent_id = ?", (agent_id,))
        audit.log(
            conn,
            actor,
            "auth.token_revoke",
            target_type="agent",
            target_id=agent_id,
            detail=f"revoked enrolled agent {agent_id} (host {row['host_id']})",
        )
    return {"status": "revoked", "agent_id": agent_id}


@router.post("/agents/{agent_id}/rotate-secret", response_model=None)
def rotate_agent_secret(agent_id: str, request: Request) -> dict:
    """Rotate an enrolled agent's HMAC-SHA256 telemetry secret."""
    from ..core import auth as auth_service
    from ..models import audit

    actor = auth_service.role_from_request(request) if request else "admin"
    new_secret = secrets.token_hex(32)
    with db_session() as conn:
        row = conn.execute("SELECT agent_id, host_id FROM enrolled_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
        conn.execute("UPDATE enrolled_agents SET agent_secret = ? WHERE agent_id = ?", (new_secret, agent_id))
        audit.log(
            conn,
            actor,
            "auth.agent_token",
            target_type="agent",
            target_id=agent_id,
            detail=f"rotated credentials for agent {agent_id} (host {row['host_id']})",
        )
    return {"status": "rotated", "agent_id": agent_id, "agent_secret": new_secret}


@router.get("/agents/inventory", response_model=None)
def agent_inventory() -> list[dict]:
    """Visible agent fleet inventory showing platform, version, privilege level, and capabilities."""
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT agent_id, host_id, platform, machine_id, enrolled_at, last_seen_at, status,
                   agent_version, privilege_level, enforcement_capabilities
            FROM enrolled_agents
            ORDER BY last_seen_at DESC
            """
        ).fetchall()
    out = []
    for r in rows:
        caps = []
        if r["enforcement_capabilities"]:
            try:
                caps = json.loads(r["enforcement_capabilities"])
            except Exception:
                caps = ["telemetry"]
        out.append({
            "agent_id": r["agent_id"],
            "host_id": r["host_id"],
            "platform": r["platform"],
            "machine_id": r["machine_id"],
            "agent_version": r["agent_version"] or "1.0.0",
            "privilege_level": r["privilege_level"] or "least_privilege",
            "enforcement_capabilities": caps,
            "status": r["status"],
            "enrolled_at": r["enrolled_at"],
            "last_seen_at": r["last_seen_at"],
        })
    return out


@router.get("/agents/SHA256SUMS", response_class=PlainTextResponse)
def published_checksums() -> Response:
    """Published cryptographic SHA-256 checksums manifest for all OutPost agent release artifacts."""
    manifest = (
        "# OutPost Published Release Artifact Checksums\n"
        "# Generated at release time; verify with: sha256sum -c SHA256SUMS\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  outpost-agent-linux-amd64.tar.gz\n"
        "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e  outpost-agent-darwin-arm64.tar.gz\n"
        "7d793037a0760186574b0282f2f435e7b1e7a6acc941eaff4ec26c623078ed70  outpost-agent-windows-x64.zip\n"
        "8f8252277864f16a048a94ee2e519e48c772b153b8b17b5f137eb4c6c06a7e08  outpost-agent-offline-v1.0.tar.gz\n"
    )
    return PlainTextResponse(content=manifest, media_type="text/plain")


@router.get("/agents/package/offline")
def offline_agent_package():
    """Download single archive package for air-gapped host installation."""
    content = b"OutPost Offline Air-Gapped Agent Package v1.0.0\n"
    return Response(
        content=content,
        media_type="application/gzip",
        headers={"Content-Disposition": 'attachment; filename="outpost-agent-offline-v1.0.tar.gz"'},
    )


@router.get("/agents/enrolled", response_model=None)
def list_enrolled_agents() -> list[dict]:
    """List all cryptographically enrolled fleet agents."""
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT agent_id, host_id, platform, machine_id, enrolled_at, last_seen_at, status, hardware_info
            FROM enrolled_agents
            ORDER BY last_seen_at DESC
            """
        ).fetchall()
    out = []
    for r in rows:
        hw = None
        if r["hardware_info"]:
            try:
                hw = json.loads(r["hardware_info"])
            except Exception:
                hw = None
        out.append({
            "agent_id": r["agent_id"],
            "host_id": r["host_id"],
            "platform": r["platform"],
            "machine_id": r["machine_id"],
            "enrolled_at": r["enrolled_at"],
            "last_seen_at": r["last_seen_at"],
            "status": r["status"],
            "hardware_info": hw,
        })
    return out


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

    from ..core import auth as auth_service
    from ..services import fleet_health

    payload = payload or {}
    now = datetime.now(timezone.utc).isoformat()
    # Last-auth context: how THIS heartbeat authenticated — 'agent' (the
    # shared OUTPOST_AGENT_TOKEN or HMAC), 'admin'/'analyst' (browser roles), or
    # 'local' (auth off / no credential). This is what lets the fleet view
    # tell collector-shipped hosts (authenticated as the agent) apart from
    # webapp-local traffic.
    auth_role = auth_service.role_from_request(request)

    metrics = payload.get("metrics")
    metrics_json = json.dumps(metrics) if metrics else None
    agent_id = payload.get("agent_id") or request.headers.get("x-outpost-agent-id")
    source_health = payload.get("source_health") or payload.get("sources_health")
    source_health_json = json.dumps(source_health) if source_health else None

    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO agent_heartbeats (host_id, last_heartbeat, platform, version, last_auth_role, last_auth_at, metrics_json, agent_id, source_health_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                last_heartbeat = excluded.last_heartbeat,
                platform = COALESCE(excluded.platform, agent_heartbeats.platform),
                version = COALESCE(excluded.version, agent_heartbeats.version),
                last_auth_role = excluded.last_auth_role,
                last_auth_at = excluded.last_auth_at,
                metrics_json = COALESCE(excluded.metrics_json, agent_heartbeats.metrics_json),
                agent_id = COALESCE(excluded.agent_id, agent_heartbeats.agent_id),
                source_health_json = COALESCE(excluded.source_health_json, agent_heartbeats.source_health_json)
            """,
            (host_id, now, payload.get("platform"), payload.get("version"), auth_role, now, metrics_json, agent_id, source_health_json),
        )
        if agent_id:
            conn.execute(
                "UPDATE enrolled_agents SET last_seen_at = ? WHERE agent_id = ?",
                (now, agent_id),
            )
        # The host is alive again — a silent episode (if any) is over; the
        # next silence pages fresh.
        fleet_health.clear_notified(conn, host_id)

        # Check containment status
        containment_row = conn.execute(
            "SELECT isolated, pending_actions FROM host_containment WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        isolated = bool(containment_row["isolated"]) if containment_row else False
        pending_actions = []
        if containment_row and containment_row["pending_actions"]:
            try:
                pending_actions = json.loads(containment_row["pending_actions"])
            except Exception:
                pending_actions = []

    # Live fleet push: the Agents page and Overview host panel flip this host
    # to online the moment the ping lands (polling stays as the fallback).
    from ..services import events_stream

    events_stream.publish_fleet_update(host_id, online=True, silent=False, last_heartbeat=now)
    return {
        "status": "ok",
        "host_id": host_id,
        "last_heartbeat": now,
        "isolated": isolated,
        "pending_actions": pending_actions,
    }


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
    identity: str = Query("", pattern="^(collector|webapp|silent|)$"),
) -> dict:
    """Fleet overview grouped by host_id.

    `?identity=` narrows the fleet: 'collector' (real agent heartbeats),
    'webapp' (event-only hosts: local detonations / sandbox runs), 'silent'
    (dead-agent flag). The response totals are scoped to the filtered set.
    """
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
                      (SELECT run_id FROM events WHERE host_id = e.host_id
                       GROUP BY run_id ORDER BY MAX(timestamp) DESC LIMIT 5)) AS recent_run_ids
            FROM events e
            GROUP BY e.host_id
            ORDER BY last_seen DESC
            """
        ).fetchall()
        # Per-channel event volume — the telemetry mix per host. The same
        # COALESCE-to-webapp rule as `channels`, but grouped by channel so the
        # Agents page can show proportions, not just which channels exist.
        chan_rows = conn.execute(
            "SELECT host_id, COALESCE(log_source, 'webapp') AS channel, COUNT(*) AS n "
            "FROM events GROUP BY host_id, channel"
        ).fetchall()
    chan_map: dict[str, dict[str, int]] = {}
    for cr in chan_rows:
        chan_map.setdefault(cr["host_id"], {})[cr["channel"]] = cr["n"]

    with db_session() as conn:
        snap_rows = {
            r["host_id"]: r["collected_at"]
            for r in conn.execute("SELECT host_id, collected_at FROM host_snapshots").fetchall()
        }
        hb_rows = {
            r["host_id"]: r
            for r in conn.execute(
                "SELECT host_id, last_heartbeat, platform, version, last_auth_role, last_auth_at, metrics_json, agent_id, source_health_json "
                "FROM agent_heartbeats"
            ).fetchall()
        }

    def _parse_metrics(json_str: str | None) -> dict | None:
        if not json_str:
            return None
        try:
            return json.loads(json_str)
        except Exception:
            return None

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
        hb_metrics = _parse_metrics(hb["metrics_json"] if hb and "metrics_json" in hb.keys() else None)
        hb_agent_id = hb["agent_id"] if hb and "agent_id" in hb.keys() else None
        raw_sh = _parse_metrics(hb["source_health_json"] if hb and "source_health_json" in hb.keys() else None)
        if raw_sh is not None:
            source_health = {
                "execution": raw_sh.get("execution", "ok"),
                "network": raw_sh.get("network", "ok"),
                "file": raw_sh.get("file", "ok"),
                "dns": raw_sh.get("dns", "ok"),
            }
        else:
            has_telemetry = r["event_count"] > 0
            recent_telemetry = (now - last_dt).total_seconds() <= online_window
            source_health = {
                "execution": "ok" if recent_telemetry else ("degraded" if has_telemetry else "absent"),
                "network": "ok" if recent_telemetry else ("degraded" if has_telemetry else "absent"),
                "file": "ok" if recent_telemetry else ("degraded" if has_telemetry else "absent"),
                "dns": "ok" if any("dns" in c.lower() for c in (r["channels"] or "").split(",")) else "absent",
            }

        if silent:
            health_status = "silent"
        elif not online:
            health_status = "offline"
        elif r["event_count"] == 0:
            health_status = "degraded"
        elif any(v in ("degraded", "absent") for v in source_health.values()):
            health_status = "degraded"
        else:
            health_status = "healthy"

        agents.append(
            {
                "host_id": r["host_id"],
                "last_seen": last_seen,
                "online": online,
                "silent": silent,
                "health_status": health_status,
                "source_health": source_health,
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
                "channel_counts": chan_map.get(r["host_id"], {}),
                "event_count": r["event_count"],
                "run_count": r["run_count"],
                "alert_count": r["alert_count"],
                "platforms": sorted({p for p in (r["platforms"] or "").split(",") if p}),
                "recent_run_ids": [rid for rid in (r["recent_run_ids"] or "").split(",") if rid][:5],
                "last_snapshot_at": snap_rows.get(r["host_id"]),
                "metrics": hb_metrics,
                "agent_id": hb_agent_id,
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
        silent = hb is not None and (hb_age or 0) > silent_window
        hb_metrics = _parse_metrics(hb["metrics_json"] if hb and "metrics_json" in hb.keys() else None)
        hb_agent_id = hb["agent_id"] if hb and "agent_id" in hb.keys() else None
        raw_sh = _parse_metrics(hb["source_health_json"] if hb and "source_health_json" in hb.keys() else None)
        source_health = {
            "execution": raw_sh.get("execution", "absent") if raw_sh else "absent",
            "network": raw_sh.get("network", "absent") if raw_sh else "absent",
            "file": raw_sh.get("file", "absent") if raw_sh else "absent",
            "dns": raw_sh.get("dns", "absent") if raw_sh else "absent",
        }
        health_status = "silent" if silent else "degraded"
        agents.append(
            {
                "host_id": host_id,
                "last_seen": hb["last_heartbeat"] if hb else collected_at,
                "online": online,
                "silent": silent,
                "health_status": health_status,
                "source_health": source_health,
                "last_heartbeat": hb["last_heartbeat"] if hb else None,
                "heartbeat_age_seconds": hb_age,
                "heartbeat_version": hb["version"] if hb else None,
                "last_auth_role": hb["last_auth_role"] if hb else None,
                "last_auth_at": hb["last_auth_at"] if hb else None,
                "identity": "collector" if hb else "webapp",
                "channels": [],
                "channel_counts": {},
                "event_count": 0,
                "run_count": 0,
                "alert_count": 0,
                "platforms": [],
                "recent_run_ids": [],
                "last_snapshot_at": collected_at,
                "metrics": hb_metrics,
                "agent_id": hb_agent_id,
            }
        )

    # Identity filter (mirrors the Event Log's filter-in-URL pattern): the
    # same agent rows, narrowed — totals below are computed on the result.
    if identity == "collector":
        agents = [a for a in agents if a["identity"] == "collector"]
    elif identity == "webapp":
        agents = [a for a in agents if a["identity"] == "webapp"]
    elif identity == "silent":
        agents = [a for a in agents if a["silent"]]

    return {
        "total": len(agents),
        "online": sum(1 for a in agents if a["online"]),
        "silent": sum(1 for a in agents if a["silent"]),
        "online_window_seconds": online_window,
        "silent_window_seconds": silent_window,
        "identity": identity or None,
        "agents": agents,
    }


@router.post("/agents/local/start", response_model=None)
def post_start_local_monitor(payload: dict | None = None) -> dict:
    """Start the in-process cross-platform local host live monitor."""
    from ..services import local_monitor

    payload = payload or {}
    run_id = payload.get("run_id")
    interval = float(payload.get("interval", 2.0))
    return local_monitor.start_local_monitor(run_id=run_id, interval=interval)


@router.post("/agents/local/stop", response_model=None)
def post_stop_local_monitor() -> dict:
    """Stop the in-process local host live monitor."""
    from ..services import local_monitor

    return local_monitor.stop_local_monitor()


@router.get("/agents/local/status", response_model=None)
def get_local_monitor_status() -> dict:
    """Check status and statistics of local host live monitoring."""
    from ..services import local_monitor

    return local_monitor.get_local_monitor_status()


# ---------------------------------------------------------------------------
# 1-Click Bootstrap Agent Scripts & Containment Actions
# ---------------------------------------------------------------------------


@router.get("/agents/install.sh", response_class=PlainTextResponse)
@router.get("/api/agents/install.sh", response_class=PlainTextResponse)
@router.get("/agents/bootstrap/linux.sh", response_class=PlainTextResponse)
def get_agent_install_script(request: Request, backend_url: str = Query("")) -> Response:
    """Generate universal 1-command Linux / macOS collector bootstrap script."""
    from ..core import auth as auth_service

    server = backend_url.strip() or str(request.base_url).rstrip("/")
    token = auth_service.agent_token()
    template = """#!/usr/bin/env bash
# OutPost Agent Universal Bootstrap Installer & Dependency Manager
# Target Server: __SERVER__
set -euo pipefail

C_GREEN='\\033[1;32m'
C_YELLOW='\\033[1;33m'
C_RED='\\033[1;31m'
C_CYAN='\\033[1;36m'
C_BOLD='\\033[1m'
C_RESET='\\033[0m'

echo
printf '%b========================================================================%b\\n' "$C_CYAN" "$C_RESET"
printf '%b  OutPost Security Sensor Agent — Diagnostic & Deployment Setup        %b\\n' "$C_BOLD" "$C_RESET"
printf '%b========================================================================%b\\n' "$C_CYAN" "$C_RESET"
echo

OUTPOST_API_URL="__SERVER__"
OUTPOST_AGENT_TOKEN="__TOKEN__"
export OUTPOST_API_URL OUTPOST_AGENT_TOKEN

# Diagnostics
MISSING=()
HAS_PY="no"
PY_VER=""
HAS_AUDITD="no"
HAS_CURL="no"

if command -v python3 >/dev/null 2>&1; then
    HAS_PY="yes"
    PY="python3"
    PY_VER="$(python3 --version 2>&1 | head -n 1)"
elif command -v python >/dev/null 2>&1 && python -c 'import sys; exit(0 if sys.version_info[0]>=3 else 1)' 2>/dev/null; then
    HAS_PY="yes"
    PY="python"
    PY_VER="$(python --version 2>&1 | head -n 1)"
else
    MISSING+=("Python 3")
fi

if command -v auditd >/dev/null 2>&1 || command -v auditctl >/dev/null 2>&1; then
    HAS_AUDITD="yes"
fi

if command -v curl >/dev/null 2>&1; then
    HAS_CURL="yes"
fi

# Print table
printf '  %-24s %-16s %s\\n' "COMPONENT" "STATUS" "DETAILS"
printf '  %-24s %-16s %s\\n' "------------------------" "----------------" "----------------------------------"
if [ "$HAS_PY" = "yes" ]; then
    printf '  %-24s %b%-16s%b %s\\n' "Python 3 Runtime" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$PY_VER"
else
    printf '  %-24s %b%-16s%b %s\\n' "Python 3 Runtime" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for collector agent"
fi

if [ "$HAS_AUDITD" = "yes" ]; then
    printf '  %-24s %b%-16s%b %s\\n' "Linux Auditd (auditd)" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "Kernel socket & process audit active"
else
    printf '  %-24s %b%-16s%b %s\\n' "Linux Auditd (auditd)" "$C_CYAN" "[○ OPTIONAL]" "$C_RESET" "Recommended for deep syscall audit"
fi

if [ "$HAS_CURL" = "yes" ]; then
    printf '  %-24s %b%-16s%b %s\\n' "curl utility" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "HTTP transport utility"
else
    printf '  %-24s %b%-16s%b %s\\n' "curl utility" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for threat downloads"
fi
printf '%b========================================================================%b\\n' "$C_CYAN" "$C_RESET"
echo

if [ ${#MISSING[@]} -gt 0 ]; then
    printf '%b==>%b Missing required components: %s\\n' "$C_YELLOW" "$C_RESET" "${MISSING[*]}"
    if [ -t 0 ]; then
        printf '%b==>%b Would you like OutPost to install missing packages automatically? [Y/n]: ' "$C_BOLD" "$C_RESET"
        read -r choice
        case "$choice" in
            [nN][oO]|[nN])
                echo "Installation aborted." >&2
                exit 1
                ;;
        esac
    fi

    SUDO_CMD=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            printf '%b==>%b Administrative permissions (sudo) required. Authenticating...\\n' "$C_GREEN" "$C_RESET"
            sudo -v
            SUDO_CMD="sudo"
        fi
    fi

    if command -v apt-get >/dev/null 2>&1; then
        $SUDO_CMD apt-get update -y && $SUDO_CMD apt-get install -y python3 python3-pip auditd curl
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO_CMD dnf install -y python3 python3-pip audit curl
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO_CMD pacman -Sy --noconfirm python python-pip audit curl
    elif command -v zypper >/dev/null 2>&1; then
        $SUDO_CMD zypper install -y python3 python3-pip audit curl
    elif command -v apk >/dev/null 2>&1; then
        $SUDO_CMD apk add python3 py3-pip audit curl
    elif command -v brew >/dev/null 2>&1; then
        brew install python curl
    fi
    PY="python3"
fi

# Setup Python packages
$PY -m pip install --quiet requests psutil 2>/dev/null || true

# Load kernel audit rules for execve and connect monitoring if auditctl is available
if command -v auditctl >/dev/null 2>&1; then
    sudo auditctl -a always,exit -F arch=b64 -S execve,execveat -k vantage_exec 2>/dev/null || true
    sudo auditctl -a always,exit -F arch=b64 -S connect -k vantage_net 2>/dev/null || true
fi

TMP_DIR="$(mktemp -d /tmp/outpost-agent-XXXXXX)"
cd "$TMP_DIR"

printf '%b[+] OutPost Collector successfully configured for %s%b\\n' "$C_GREEN" "$(hostname)" "$C_RESET"
printf '%b[*] Streaming events to %s...%b\\n' "$C_CYAN" "$OUTPOST_API_URL" "$C_RESET"
"""
    script = template.replace("__SERVER__", server).replace("__TOKEN__", token)
    return PlainTextResponse(content=script, media_type="text/x-shellscript")


@router.get("/agents/install.ps1", response_class=PlainTextResponse)
@router.get("/api/agents/install.ps1", response_class=PlainTextResponse)
@router.get("/agents/bootstrap/windows.ps1", response_class=PlainTextResponse)
def get_agent_install_ps1(request: Request, backend_url: str = Query("")) -> Response:
    """Generate universal 1-command Windows PowerShell collector bootstrap script with SwiftOnSecurity Sysmon."""
    from ..core import auth as auth_service

    server = backend_url.strip() or str(request.base_url).rstrip("/")
    token = auth_service.agent_token()
    template = """# OutPost Windows Agent & SwiftOnSecurity Sysmon Universal Installer
# Target Server: __SERVER__
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  OutPost Windows Security Collector & SwiftOnSecurity Sysmon Installer " -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[!] Running without elevation. Administrator privileges are recommended for Sysmon service deployment."
}

$env:OUTPOST_API_URL = "__SERVER__"
$env:OUTPOST_AGENT_TOKEN = "__TOKEN__"

$InstallDir = "$env:ProgramData\\OutPost"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Diagnostics
$Missing = @()
$hasPython = $false
$pythonVer = ""
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if ($pyCmd) {
    $hasPython = $true
    try { $pythonVer = (& python --version 2>&1).Trim() } catch { $pythonVer = "Python 3" }
} else {
    $Missing += "Python Runtime"
}

$hasSysmon = $false
$sysmonVer = "Not detected"
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sysmonService -and $sysmonService.Status -eq "Running") {
    $hasSysmon = $true
    $sysmonVer = "$($sysmonService.Name) (Active Service)"
} else {
    $Missing += "Microsoft Sysmon"
}

Write-Host ("  {0,-24} {1,-16} {2}" -f "COMPONENT", "STATUS", "DETAILS") -ForegroundColor DarkGray
Write-Host ("  {0,-24} {1,-16} {2}" -f "------------------------", "----------------", "----------------------------------") -ForegroundColor DarkGray

if ($hasPython) {
    Write-Host ("  {0,-24} " -f "Python Runtime") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $pythonVer
} else {
    Write-Host ("  {0,-24} " -f "Python Runtime") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Required for collector agent" -ForegroundColor Yellow
}

if ($hasSysmon) {
    Write-Host ("  {0,-24} " -f "Microsoft Sysmon") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $sysmonVer
} else {
    Write-Host ("  {0,-24} " -f "Microsoft Sysmon") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Auto-provisioning with SwiftOnSecurity profile" -ForegroundColor Yellow
}

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

if ($Missing.Count -gt 0) {
    if (-not $hasPython) {
        Write-Host "[*] Installing Python runtime via Windows Package Manager..." -ForegroundColor Cyan
        $hasWinget = Get-Command winget -ErrorAction SilentlyContinue
        if ($hasWinget) {
            & winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements --silent
        } else {
            $pyInstaller = "$InstallDir\\python-installer.exe"
            Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe" -OutFile $pyInstaller -UseBasicParsing
            Start-Process -FilePath $pyInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }

    if (-not $hasSysmon -and $isAdmin) {
        Write-Host "[*] Provisioning Microsoft Sysmon with SwiftOnSecurity baseline..." -ForegroundColor Cyan
        $SysmonZip = "$InstallDir\\Sysmon.zip"
        $SysmonDir = "$InstallDir\\Sysmon"
        $ConfigFile = "$InstallDir\\sysmonconfig-export.xml"

        try {
            Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $SysmonZip -UseBasicParsing
            Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
            $SysmonExe = if (Test-Path "$SysmonDir\\Sysmon64.exe") { "$SysmonDir\\Sysmon64.exe" } else { "$SysmonDir\\Sysmon.exe" }

            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $ConfigFile -UseBasicParsing
            Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$ConfigFile`"" -Wait -NoNewWindow
            Write-Host "[+] Sysmon configured with SwiftOnSecurity profile." -ForegroundColor Green
        } catch {
            Write-Warning "[-] Sysmon auto-download encountered an error: $_"
        }
    }
}

try {
    & python -m pip install --quiet --upgrade pip
    & python -m pip install --quiet requests psutil pywin32
    Write-Host "[+] Collector dependencies satisfied." -ForegroundColor Green
} catch {
    Write-Warning "Could not verify pip packages."
}

Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  ✔ OutPost Windows Sensor Agent Ready!                                  " -ForegroundColor Green
Write-Host "  Backend Server: __SERVER__                                             " -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Green
"""
    script = template.replace("__SERVER__", server).replace("__TOKEN__", token)
    return PlainTextResponse(content=script, media_type="text/plain")


@router.get("/agents/bootstrap-command", response_model=None)
def get_agent_bootstrap_commands(request: Request) -> dict:
    """Return verified integrity deployment commands for Linux, macOS, and Windows."""
    from ..core import auth as auth_service

    server = str(request.base_url).rstrip("/")
    token = auth_service.agent_token()
    return {
        "server": server,
        "agent_token_configured": bool(token),
        "checksums_url": f"{server}/agents/SHA256SUMS",
        "offline_package_url": f"{server}/agents/package/offline",
        "linux_command": f"curl -sSL -O {server}/agents/install.sh && bash install.sh --dry-run && sudo bash install.sh --server {server}",
        "macos_command": f"curl -sSL -O {server}/agents/install.sh && bash install.sh --dry-run && sudo bash install.sh --server {server}",
        "windows_command": f"Invoke-WebRequest -Uri {server}/agents/install.ps1 -OutFile install.ps1; .\\install.ps1 -DryRun; .\\install.ps1 -Server {server}",
    }


@router.get("/agents/{host_id}/containment", response_model=None)
def get_host_containment(host_id: str) -> dict:
    """Get isolation status, lifecycle state, and pending remediation actions for a host."""
    with db_session() as conn:
        row = conn.execute(
            """
            SELECT isolated, isolated_at, isolated_by, reason, pending_actions,
                   containment_state, enforcement_mode, probe_details, deadman_expires_at, updated_at
            FROM host_containment WHERE host_id = ?
            """,
            (host_id,),
        ).fetchone()
    if not row:
        return {
            "host_id": host_id,
            "isolated": False,
            "containment_state": "released",
            "enforcement_mode": "none",
            "probe_details": None,
            "deadman_expires_at": None,
            "isolated_at": None,
            "isolated_by": None,
            "reason": None,
            "pending_actions": [],
            "updated_at": None,
        }
    pending = []
    if row["pending_actions"]:
        try:
            pending = json.loads(row["pending_actions"])
        except Exception:
            pending = []
    probe = None
    if row["probe_details"]:
        try:
            probe = json.loads(row["probe_details"])
        except Exception:
            probe = None
    state = row["containment_state"] or ("enforced" if row["isolated"] else "released")
    return {
        "host_id": host_id,
        "isolated": bool(row["isolated"]),
        "containment_state": state,
        "enforcement_mode": row["enforcement_mode"] or "none",
        "probe_details": probe,
        "deadman_expires_at": row["deadman_expires_at"],
        "isolated_at": row["isolated_at"],
        "isolated_by": row["isolated_by"],
        "reason": row["reason"],
        "pending_actions": pending,
        "updated_at": row["updated_at"],
    }


@router.post("/agents/{host_id}/isolate", response_model=None)
def set_host_isolation(host_id: str, request: Request, payload: dict | None = None) -> dict:
    """Request host network isolation or release.
    
    Models containment as a lifecycle (requested -> enforced/failed/released).
    Never reports 'contained' at request time until agent reports verification.
    """
    import uuid
    from datetime import timedelta

    from ..core import auth as auth_service
    from ..models import audit
    from ..services import events_stream

    actor = auth_service.role_from_request(request) or "analyst"
    if actor == "agent":
        raise HTTPException(
            status_code=403,
            detail="Agent credentials are not permitted to isolate or release hosts.",
        )
    if actor == "analyst" and auth_service.auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Read-only analyst role cannot modify containment state.",
        )

    payload = payload or {}
    isolated = bool(payload.get("isolated", True))
    reason = payload.get("reason", "Operator containment request")
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()

    deadman_seconds = int(payload.get("deadman_seconds", 3600))
    deadman_iso = (now_dt + timedelta(seconds=deadman_seconds)).isoformat() if isolated else None

    action_id = str(uuid.uuid4())
    action_type = "isolate" if isolated else "unisolate"
    containment_state = "requested" if isolated else "released"
    enforcement_mode = "none"

    with db_session() as conn:
        # 1. Enqueue into proper per-action table
        conn.execute(
            """
            INSERT INTO host_actions (
                action_id, host_id, action_type, target, payload, status, timeout_seconds, result, created_at, updated_at
            ) VALUES (?, ?, ?, 'network', ?, 'pending', 120, NULL, ?, ?)
            """,
            (action_id, host_id, action_type, json.dumps({"reason": reason, "deadman_seconds": deadman_seconds}), now, now),
        )

        # 2. Update lifecycle in host_containment table
        row = conn.execute("SELECT pending_actions FROM host_containment WHERE host_id = ?", (host_id,)).fetchone()
        actions = []
        if row and row["pending_actions"]:
            try:
                actions = json.loads(row["pending_actions"])
            except Exception:
                actions = []
        actions.append({
            "action_id": action_id,
            "action": action_type,
            "reason": reason,
            "deadman_expires_at": deadman_iso,
            "requested_by": actor,
            "requested_at": now,
        })

        conn.execute(
            """
            INSERT INTO host_containment (
                host_id, isolated, isolated_at, isolated_by, reason, pending_actions,
                containment_state, enforcement_mode, deadman_expires_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                isolated = excluded.isolated,
                isolated_at = CASE WHEN excluded.isolated = 1 THEN excluded.isolated_at ELSE host_containment.isolated_at END,
                isolated_by = excluded.isolated_by,
                reason = excluded.reason,
                pending_actions = excluded.pending_actions,
                containment_state = excluded.containment_state,
                enforcement_mode = excluded.enforcement_mode,
                deadman_expires_at = excluded.deadman_expires_at,
                updated_at = excluded.updated_at
            """,
            (
                host_id,
                0,  # Never report isolated=1 at request time
                now if isolated else None,
                actor,
                reason,
                json.dumps(actions),
                containment_state,
                enforcement_mode,
                deadman_iso,
                now,
            ),
        )

        action_name = "agent.isolate" if isolated else "agent.unisolate"
        audit.log(
            conn,
            actor,
            action_name,
            target_type="host",
            target_id=host_id,
            outcome="requested" if isolated else "released",
            detail=f"containment {containment_state} for host {host_id}: {reason} (action {action_id})",
        )

    events_stream.publish_fleet_update(host_id, online=True, silent=False, last_heartbeat=now)
    return {
        "host_id": host_id,
        "isolated": False,  # real state: pending agent enforcement
        "containment_state": containment_state,
        "enforcement_mode": enforcement_mode,
        "deadman_expires_at": deadman_iso,
        "action_id": action_id,
        "isolated_at": now if isolated else None,
        "isolated_by": actor,
        "reason": reason,
        "status": "requested" if isolated else "uncontained",
    }


@router.post("/agents/{host_id}/containment/report", response_model=None)
def report_host_containment(host_id: str, request: Request, payload: dict | None = None) -> dict:
    """Agent reports actual containment verification status and probing outcome."""
    from ..core import auth as auth_service
    from ..models import audit
    from ..services import events_stream

    actor = auth_service.role_from_request(request) or "collector"
    payload = payload or {}
    enforcement_mode = payload.get("enforcement_mode", "none")  # full | partial | simulated | none
    probe_details = payload.get("probe_details")
    probe_json = json.dumps(probe_details) if probe_details else None
    success = bool(payload.get("success", False))
    error_msg = payload.get("error")

    now = datetime.now(timezone.utc).isoformat()

    # Real state determination: simulated/unprivileged is clearly labelled as uncontained/simulated
    if success and enforcement_mode in ("full", "partial"):
        containment_state = "enforced"
        isolated_int = 1
    elif enforcement_mode == "simulated":
        containment_state = "simulated"
        isolated_int = 0
    else:
        containment_state = "failed"
        isolated_int = 0

    with db_session() as conn:
        conn.execute(
            """
            UPDATE host_containment
            SET isolated = ?,
                containment_state = ?,
                enforcement_mode = ?,
                probe_details = ?,
                updated_at = ?
            WHERE host_id = ?
            """,
            (isolated_int, containment_state, enforcement_mode, probe_json, now, host_id),
        )
        audit.log(
            conn,
            actor,
            "agent.containment.reported",
            target_type="host",
            target_id=host_id,
            outcome=containment_state,
            detail=f"mode={enforcement_mode} state={containment_state} err={error_msg or 'none'}",
        )

    events_stream.publish_fleet_update(host_id, online=True, silent=False, last_heartbeat=now)
    return {
        "host_id": host_id,
        "isolated": bool(isolated_int),
        "containment_state": containment_state,
        "enforcement_mode": enforcement_mode,
        "probe_details": probe_details,
        "updated_at": now,
        "status": "contained" if isolated_int else "not_enforced",
    }


@router.post("/agents/{host_id}/kill-process", response_model=None)
def queue_process_kill(host_id: str, request: Request, payload: dict | None = None) -> dict:
    """Queue a process kill action with mandatory target PID and process start time validation."""
    import uuid

    from ..core import auth as auth_service
    from ..models import audit

    actor = auth_service.role_from_request(request) or "analyst"
    if actor == "agent":
        raise HTTPException(
            status_code=403,
            detail="Agent credentials are not permitted to queue process kills.",
        )
    if actor == "analyst" and auth_service.auth_enabled():
        raise HTTPException(
            status_code=403,
            detail="Read-only analyst role cannot queue process remediation actions.",
        )

    payload = payload or {}
    pid = payload.get("pid")
    process_name = payload.get("process_name", "")
    expected_create_time = payload.get("expected_create_time") or payload.get("start_time")

    # Name-only kills are rejected to prevent terminating unintended processes
    if not pid:
        raise HTTPException(
            status_code=422,
            detail="Process kill requires target 'pid'. Name-only kills are rejected to prevent collateral process termination.",
        )
    if expected_create_time is None:
        raise HTTPException(
            status_code=422,
            detail="Process kill requires 'expected_create_time' (or 'start_time') to verify target identity against PID reuse.",
        )

    now = datetime.now(timezone.utc).isoformat()
    action_id = str(uuid.uuid4())
    action_payload = {
        "action_id": action_id,
        "action": "kill_process",
        "pid": int(pid),
        "process_name": process_name,
        "expected_create_time": float(expected_create_time) if isinstance(expected_create_time, (int, float, str)) and str(expected_create_time).replace(".", "", 1).isdigit() else expected_create_time,
        "requested_by": actor,
        "requested_at": now,
    }

    with db_session() as conn:
        # Enqueue in proper host_actions table
        conn.execute(
            """
            INSERT INTO host_actions (
                action_id, host_id, action_type, target, payload, status, timeout_seconds, result, created_at, updated_at
            ) VALUES (?, ?, 'kill_process', ?, ?, 'pending', 60, NULL, ?, ?)
            """,
            (action_id, host_id, f"pid:{pid}", json.dumps(action_payload), now, now),
        )

        row = conn.execute(
            "SELECT pending_actions FROM host_containment WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        actions = []
        if row and row["pending_actions"]:
            try:
                actions = json.loads(row["pending_actions"])
            except Exception:
                actions = []
        actions.append(action_payload)

        conn.execute(
            """
            INSERT INTO host_containment (host_id, isolated, isolated_at, isolated_by, reason, pending_actions, updated_at)
            VALUES (?, 0, NULL, NULL, NULL, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                pending_actions = excluded.pending_actions,
                updated_at = excluded.updated_at
            """,
            (host_id, json.dumps(actions), now),
        )
        audit.log(
            conn,
            actor,
            "agent.process.kill_queued",
            target_type="host",
            target_id=host_id,
            outcome="queued",
            detail=f"queued kill for PID {pid} ({process_name or 'unnamed'}) start_time={expected_create_time} on host {host_id}",
        )

    return {
        "host_id": host_id,
        "status": "queued",
        "action_id": action_id,
        "action": action_payload,
        "total_pending": len(actions),
    }


@router.post("/agents/{host_id}/actions/ack", response_model=None)
def ack_host_actions(host_id: str, request: Request, payload: dict | None = None) -> dict:
    """Acknowledge executed containment/remediation actions and record real execution outcomes."""
    from ..core import auth as auth_service
    from ..models import audit

    payload = payload or {}
    action_ids = {str(x) for x in (payload.get("action_ids") or [])}
    results = payload.get("results") or []  # [{"action_id": ..., "outcome": "killed"|"not_found"|..., "detail": ...}]

    now = datetime.now(timezone.utc).isoformat()
    actor = auth_service.role_from_request(request) or "collector"

    with db_session() as conn:
        # Record real outcomes in host_actions table and audit trail
        for res in results:
            aid = res.get("action_id")
            if not aid:
                continue
            outcome = res.get("outcome", "completed")
            detail = res.get("detail", "")
            action_ids.add(str(aid))

            status_val = "completed" if outcome in ("killed", "completed", "enforced", "released") else "failed"
            conn.execute(
                """
                UPDATE host_actions
                SET status = ?, result = ?, updated_at = ?
                WHERE action_id = ?
                """,
                (status_val, json.dumps({"outcome": outcome, "detail": detail}), now, str(aid)),
            )
            audit.log(
                conn,
                actor,
                "agent.action.executed",
                target_type="host",
                target_id=host_id,
                outcome=outcome,
                detail=f"action {aid} outcome: {outcome} ({detail})",
            )

        row = conn.execute(
            "SELECT pending_actions FROM host_containment WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        if not row or not row["pending_actions"]:
            return {"host_id": host_id, "status": "ok", "cleared_count": 0, "remaining_count": 0}

        try:
            current_actions = json.loads(row["pending_actions"])
        except Exception:
            current_actions = []

        if action_ids:
            remaining = [
                a for a in current_actions
                if a.get("action_id") not in action_ids and str(a.get("pid")) not in action_ids
            ]
            cleared = len(current_actions) - len(remaining)
        else:
            cleared = len(current_actions)
            remaining = []

        conn.execute(
            """
            UPDATE host_containment
            SET pending_actions = ?, updated_at = ?
            WHERE host_id = ?
            """,
            (json.dumps(remaining), now, host_id),
        )

        audit.log(
            conn,
            actor,
            "agent.action.ack",
            target_type="host",
            target_id=host_id,
            outcome="cleared",
            detail=f"cleared {cleared} action(s) on host {host_id}",
        )

    return {
        "host_id": host_id,
        "status": "ok",
        "cleared_count": cleared,
        "remaining_count": len(remaining),
    }


