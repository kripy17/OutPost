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
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

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
                "channel_counts": chan_map.get(r["host_id"], {}),
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
                "channel_counts": {},
                "event_count": 0,
                "run_count": 0,
                "alert_count": 0,
                "platforms": [],
                "recent_run_ids": [],
                "last_snapshot_at": collected_at,
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
def get_agent_install_script(request: Request, backend_url: str = Query("")) -> Response:
    """Generate universal 1-command Linux / macOS collector bootstrap script."""
    from ..core import auth as auth_service

    server = backend_url.strip() or str(request.base_url).rstrip("/")
    token = auth_service.agent_token()
    script = f"""#!/usr/bin/env bash
# OutPost Agent Universal Bootstrap Installer
# Server: {server}
set -euo pipefail

echo "[*] Setting up OutPost Security Collector..."
OUTPOST_API_URL="{server}"
OUTPOST_AGENT_TOKEN="{token}"
export OUTPOST_API_URL OUTPOST_AGENT_TOKEN

TMP_DIR="$(mktemp -d /tmp/outpost-agent-XXXXXX)"
cd "$TMP_DIR"

if command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    echo "[-] Python 3 is required to run OutPost collector." >&2
    exit 1
fi

echo "[*] Launching OutPost Collector for $(hostname)..."
exec "$PY" -m collectors.common.collector_local --backend "$OUTPOST_API_URL"
"""
    return PlainTextResponse(content=script, media_type="text/x-shellscript")


@router.get("/agents/install.ps1", response_class=PlainTextResponse)
def get_agent_install_ps1(request: Request, backend_url: str = Query("")) -> Response:
    """Generate universal 1-command Windows PowerShell collector bootstrap script with SwiftOnSecurity Sysmon."""
    from ..core import auth as auth_service

    server = backend_url.strip() or str(request.base_url).rstrip("/")
    token = auth_service.agent_token()
    script = f"""# OutPost Windows Agent & SwiftOnSecurity Sysmon Universal Installer
# Target Server: {server}
$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  OutPost Windows Security Collector & SwiftOnSecurity Sysmon     " -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Warning "[!] Running without elevation. For complete kernel/Sysmon event visibility, run as Administrator."
}}

$env:OUTPOST_API_URL = "{server}"
$env:OUTPOST_AGENT_TOKEN = "{token}"

$InstallDir = "$env:ProgramData\\OutPost"
if (-not (Test-Path $InstallDir)) {{
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}}

# Check Sysmon installation
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sysmonService -and $sysmonService.Status -eq "Running") {{
    Write-Host "[+] Microsoft Sysmon service is active ($($sysmonService.Name))." -ForegroundColor Green
}} else {{
    if ($isAdmin) {{
        Write-Host "[*] Provisioning Microsoft Sysmon with SwiftOnSecurity baseline..." -ForegroundColor Yellow
        $SysmonZip = "$InstallDir\\Sysmon.zip"
        $SysmonDir = "$InstallDir\\Sysmon"
        $ConfigFile = "$InstallDir\\sysmonconfig-export.xml"

        try {{
            Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $SysmonZip -UseBasicParsing
            Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
            $SysmonExe = if (Test-Path "$SysmonDir\\Sysmon64.exe") {{ "$SysmonDir\\Sysmon64.exe" }} else {{ "$SysmonDir\\Sysmon.exe" }}

            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $ConfigFile -UseBasicParsing
            Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$ConfigFile`"" -Wait -NoNewWindow
            Write-Host "[+] Sysmon configured with SwiftOnSecurity profile." -ForegroundColor Green
        }} catch {{
            Write-Warning "[-] Sysmon auto-download encountered an error: $_"
        }}
    }} else {{
        Write-Warning "[!] Sysmon not installed. Run this installer as Administrator to auto-provision SwiftOnSecurity Sysmon."
    }}
}}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {{
    Write-Warning "[-] Python is required to run OutPost collector on Windows."
    exit 1
}}

Write-Host "[*] Installing collector Python dependencies (requests, psutil, pywin32)..." -ForegroundColor Cyan
try {{
    & python -m pip install --quiet requests psutil pywin32
}} catch {{}}

Write-Host "[*] Launching OutPost Windows Collector for $env:COMPUTERNAME..." -ForegroundColor Green
Write-Host "    Target Backend: $env:OUTPOST_API_URL" -ForegroundColor White
python -m collectors.windows.collector_win --backend-url "$env:OUTPOST_API_URL" --mode live
"""
    return PlainTextResponse(content=script, media_type="text/plain")



@router.get("/agents/bootstrap-command", response_model=None)
def get_agent_bootstrap_commands(request: Request) -> dict:
    """Return 1-click copy-paste deployment commands for Linux, macOS, and Windows."""
    from ..core import auth as auth_service

    server = str(request.base_url).rstrip("/")
    token = auth_service.agent_token()
    return {
        "server": server,
        "agent_token_configured": bool(token),
        "linux_command": f"curl -sSL {server}/api/agents/install.sh | sudo bash",
        "macos_command": f"curl -sSL {server}/api/agents/install.sh | sudo bash",
        "windows_command": f"irm {server}/api/agents/install.ps1 | iex",
    }


@router.get("/agents/{host_id}/containment", response_model=None)
def get_host_containment(host_id: str) -> dict:
    """Get isolation status and pending remediation actions for a host."""
    with db_session() as conn:
        row = conn.execute(
            "SELECT isolated, isolated_at, isolated_by, reason, pending_actions, updated_at "
            "FROM host_containment WHERE host_id = ?",
            (host_id,),
        ).fetchone()
    if not row:
        return {
            "host_id": host_id,
            "isolated": False,
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
    return {
        "host_id": host_id,
        "isolated": bool(row["isolated"]),
        "isolated_at": row["isolated_at"],
        "isolated_by": row["isolated_by"],
        "reason": row["reason"],
        "pending_actions": pending,
        "updated_at": row["updated_at"],
    }


@router.post("/agents/{host_id}/isolate", response_model=None)
def set_host_isolation(host_id: str, request: Request, payload: dict | None = None) -> dict:
    """Toggle host network isolation status (active containment)."""
    from ..core import auth as auth_service
    from ..services import events_stream

    payload = payload or {}
    isolated = bool(payload.get("isolated", True))
    reason = payload.get("reason", "Operator containment request")
    actor = auth_service.role_from_request(request) or "analyst"
    now = datetime.now(timezone.utc).isoformat()

    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO host_containment (host_id, isolated, isolated_at, isolated_by, reason, pending_actions, updated_at)
            VALUES (?, ?, ?, ?, ?, '[]', ?)
            ON CONFLICT(host_id) DO UPDATE SET
                isolated = excluded.isolated,
                isolated_at = CASE WHEN excluded.isolated = 1 THEN excluded.isolated_at ELSE host_containment.isolated_at END,
                isolated_by = excluded.isolated_by,
                reason = excluded.reason,
                updated_at = excluded.updated_at
            """,
            (host_id, 1 if isolated else 0, now, actor, reason, now),
        )

    events_stream.publish_fleet_update(host_id, online=True, silent=False, last_heartbeat=now)
    return {
        "host_id": host_id,
        "isolated": isolated,
        "isolated_at": now if isolated else None,
        "isolated_by": actor,
        "reason": reason,
        "status": "contained" if isolated else "uncontained",
    }


@router.post("/agents/{host_id}/kill-process", response_model=None)
def queue_process_kill(host_id: str, request: Request, payload: dict | None = None) -> dict:
    """Queue a process kill action to be executed by the target host collector."""
    from ..core import auth as auth_service

    payload = payload or {}
    pid = payload.get("pid")
    process_name = payload.get("process_name", "")
    if not pid and not process_name:
        raise HTTPException(status_code=422, detail="Either 'pid' or 'process_name' is required.")

    actor = auth_service.role_from_request(request) or "analyst"
    now = datetime.now(timezone.utc).isoformat()
    action = {
        "action": "kill_process",
        "pid": pid,
        "process_name": process_name,
        "requested_by": actor,
        "requested_at": now,
    }

    with db_session() as conn:
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
        actions.append(action)
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

    return {
        "host_id": host_id,
        "status": "queued",
        "action": action,
        "total_pending": len(actions),
    }

