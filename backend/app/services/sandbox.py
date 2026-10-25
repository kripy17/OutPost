"""Sandbox detonation adapter — push vault samples to a real sandbox.

Roadmap 3.3: samples stored in the vault can be submitted to an external
dynamic-analysis sandbox (Any.Run, Hatching Triage, or Joe Sandbox) and the
resulting report is normalized into the app's unified event schema and pushed
through the *same* detection pipeline as live ingestion — so a sandbox run
produces a normal run: process tree, network connections, alerts, risk score.

Configure `ANYRUN_API_KEY` / `TRIAGE_API_KEY` / `JOE_API_KEY` (+ optional
`SANDBOX_PROVIDER`) to enable external detonation. If no provider is configured,
the system rejects detonation requests with 422 Unprocessable Entity.

**Task lifecycle.** `POST /sandbox/detonate` creates a run + a task entry and
returns immediately (`submitted`). Configured live providers run in a background
asyncio task that polls the provider until the analysis finishes, fetches the
report, normalizes it, and ingests the events. `GET /sandbox/tasks/{id}` returns
live status + counts.

The live adapters are thin httpx wrappers over each provider's public REST
API (documented inline). They are best-effort by construction: any provider
failure lands in the task's `error` field instead of bubbling into the API.
The report *normalizers* are pure functions — unit-testable without network.
"""

import asyncio
import datetime
import uuid
from typing import Any

import httpx

from ..core import config
from ..core.db import db_session
from ..models import event as event_store
from ..models import run as run_store
from ..services import detection

# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

# (id, display name, env-key getter, live flag). `demo` is always available.
_PROVIDER_KEYS = ("anyrun", "triage", "joe")


def _key_for(provider: str) -> str:
    if provider == "anyrun":
        return config.ANYRUN_API_KEY
    if provider == "triage":
        return config.TRIAGE_API_KEY
    if provider == "joe":
        return config.JOE_API_KEY
    return ""


def is_configured(provider: str) -> bool:
    return provider in _PROVIDER_KEYS and bool(_key_for(provider))


def active_provider() -> str:
    """The provider to use for `auto`: SANDBOX_PROVIDER if set & configured,
    else the first configured one, else '' (no provider configured)."""
    if config.SANDBOX_PROVIDER in _PROVIDER_KEYS and is_configured(config.SANDBOX_PROVIDER):
        return config.SANDBOX_PROVIDER
    for p in _PROVIDER_KEYS:
        if is_configured(p):
            return p
    return ""


def resolve_provider(want: str) -> str:
    """Map a request's provider string to a concrete configured provider id."""
    want = (want or "auto").strip().lower()
    if want == "auto":
        active = active_provider()
        if not active:
            raise ValueError(
                "No sandbox provider is configured. "
                "Configure ANYRUN_API_KEY, TRIAGE_API_KEY, or JOE_API_KEY."
            )
        return active
    if want not in _PROVIDER_KEYS:
        raise ValueError(f"Unknown sandbox provider: {want} — expected auto, or one of {', '.join(_PROVIDER_KEYS)}")
    if not is_configured(want):
        raise ValueError(f"{want} is not configured — set the {want.upper()}_API_KEY env var")
    return want


def providers_status() -> list[dict]:
    """The provider list for GET /sandbox/providers."""
    out = []
    for pid, name in (("anyrun", "Any.Run"), ("triage", "Hatching Triage"), ("joe", "Joe Sandbox")):
        out.append({"id": pid, "name": name, "configured": is_configured(pid)})
    return out


# ---------------------------------------------------------------------------
# Event builders — the normalized event shape the rest of the pipeline expects
# ---------------------------------------------------------------------------

def _ev(run_id: str, platform: str, event_type: str, ts: str, **kw: Any) -> dict:
    ev = {
        "run_id": run_id,
        "platform": platform,
        "event_type": event_type,
        "timestamp": ts,
        "pid": None,
        "ppid": None,
        "process_name": None,
        "command_line": None,
        "dest_ip": None,
        "dest_port": None,
        "protocol": None,
        "file_path": None,
        "registry_key": None,
    }
    ev.update({k: v for k, v in kw.items() if v is not None})
    return ev


def _seq(base: datetime.datetime, index: int, step: int = 3) -> str:
    return (base + datetime.timedelta(seconds=index * step)).isoformat()


# ---------------------------------------------------------------------------
# Report normalizers — pure functions, unit-testable offline
# ---------------------------------------------------------------------------

def _process_rows(report: dict, key: str) -> list[dict]:
    """Tolerant extraction of the process list from any provider shape: a
    plain list, a dict keyed by pid (Triage), or nested under `process`."""
    raw = report.get(key)
    if isinstance(raw, dict) and isinstance(raw.get("process"), list):
        # Nested under `process` — check BEFORE the pid-keyed dict branch,
        # which would otherwise swallow this shape (returning [] from its
        # dict-values filter) and silently drop every process row.
        return [r for r in raw["process"] if isinstance(r, dict)]
    if isinstance(raw, dict):  # Triage: {"1234": {…}, …}
        return [v for v in raw.values() if isinstance(v, dict)]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    return []


def _network_rows(report: dict) -> list[dict]:
    """Tolerant extraction of connection rows from nested `network` shapes."""
    net = report.get("network")
    if isinstance(net, dict):
        rows = []
        for k in ("tcp", "udp", "connections"):
            v = net.get(k)
            if isinstance(v, list):
                rows += [r for r in v if isinstance(r, dict)]
        return rows
    if isinstance(net, list):
        return [r for r in net if isinstance(r, dict)]
    return []


def _value_rows(report: dict, key: str) -> list:
    """A provider's files/registry rows: a plain list of dicts or strings."""
    raw = report.get(key)
    return raw if isinstance(raw, list) else []


def _as_ts(value: Any) -> str | None:
    """A sandbox timestamp (ms epoch, ISO, or None) → ISO string, else None."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.datetime.fromtimestamp(value / 1000, tz=datetime.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        return value
    return None


def normalize_anyrun(report: dict, run_id: str, platform: str, base: datetime.datetime) -> list[dict]:
    """Any.Run `report/summary` + `report/network` → normalized events.

    Summary shape: `{"process": [{pid, ppid, processName, commandLine}],
    "files": [{path}], "registry": [{path}]}`; network rows are
    `{protocol, remoteHost, remotePort, processPid}`.
    """
    events: list[dict] = []
    i = 0
    for p in _process_rows(report, "process"):
        events.append(_ev(run_id, platform, "process_create", _seq(base, i),
                          pid=p.get("pid"), ppid=p.get("ppid"),
                          process_name=p.get("processName") or p.get("process_name"),
                          command_line=p.get("commandLine") or p.get("command_line")))
        i += 1
    for c in _network_rows(report):
        ts = _as_ts(c.get("timestamp")) or _seq(base, i)
        events.append(_ev(run_id, platform, "network_connection", ts,
                          pid=c.get("processPid") or c.get("pid"),
                          dest_ip=c.get("remoteHost") or c.get("dst_ip") or c.get("dest_ip"),
                          dest_port=c.get("remotePort") or c.get("dst_port") or c.get("dest_port"),
                          protocol=c.get("protocol") or "TCP"))
        i += 1
    for f in _value_rows(report, "files"):
        path = f.get("path") if isinstance(f, dict) else f
        events.append(_ev(run_id, platform, "file_write", _seq(base, i), pid=f.get("pid") if isinstance(f, dict) else None,
                          file_path=path, process_name=f.get("processName") if isinstance(f, dict) else None))
        i += 1
    for r in _value_rows(report, "registry"):
        key = r.get("path") if isinstance(r, dict) else r
        events.append(_ev(run_id, platform, "registry_write", _seq(base, i),
                          pid=r.get("pid") if isinstance(r, dict) else None,
                          registry_key=key, process_name=r.get("processName") if isinstance(r, dict) else None))
        i += 1
    return events


def normalize_triage(report: dict, run_id: str, platform: str, base: datetime.datetime) -> list[dict]:
    """Triage `reports/{task_id}` → normalized events.

    Shape: `{processes: {pid: {pid, ppid, process_name, command_line}},
    network: {tcp/udp: [{dst_ip, dst_port}]}, files: [{path}],
    registry: [{path}]}`.
    """
    events: list[dict] = []
    i = 0
    for p in _process_rows(report, "processes"):
        events.append(_ev(run_id, platform, "process_create", _seq(base, i),
                          pid=p.get("pid"), ppid=p.get("ppid"),
                          process_name=p.get("process_name") or p.get("processName"),
                          command_line=p.get("command_line") or p.get("commandLine")))
        i += 1
    for c in _network_rows(report):
        events.append(_ev(run_id, platform, "network_connection", _seq(base, i),
                          dest_ip=c.get("dst_ip") or c.get("dest_ip") or c.get("destination_ip"),
                          dest_port=c.get("dst_port") or c.get("dest_port") or c.get("destination_port"),
                          protocol=(c.get("protocol") or "TCP").upper()))
        i += 1
    for f in _value_rows(report, "files"):
        path = f.get("path") if isinstance(f, dict) else f
        events.append(_ev(run_id, platform, "file_write", _seq(base, i), file_path=path))
        i += 1
    for r in _value_rows(report, "registry"):
        key = r.get("path") if isinstance(r, dict) else r
        events.append(_ev(run_id, platform, "registry_write", _seq(base, i), registry_key=key))
        i += 1
    return events


def normalize_joe(report: dict, run_id: str, platform: str, base: datetime.datetime) -> list[dict]:
    """Joe Sandbox `analysis/{webid}/report` → normalized events.

    Shape (under `data`): `{processes: [{name, pid, parent_pid, command_line}],
    network: {tcp/udp: [{dst_ip, dst_port}]}, filesystem: [{path}],
    registry: [{path}]}`.
    """
    doc = report.get("data") if isinstance(report.get("data"), dict) else report
    events: list[dict] = []
    i = 0
    for p in _process_rows(doc, "processes"):
        events.append(_ev(run_id, platform, "process_create", _seq(base, i),
                          pid=p.get("pid"), ppid=p.get("parent_pid") or p.get("ppid"),
                          process_name=p.get("name") or p.get("process_name"),
                          command_line=p.get("command_line") or p.get("commandLine")))
        i += 1
    for c in _network_rows(doc):
        events.append(_ev(run_id, platform, "network_connection", _seq(base, i),
                          dest_ip=c.get("dst_ip") or c.get("dest_ip"),
                          dest_port=c.get("dst_port") or c.get("dest_port"),
                          protocol=(c.get("protocol") or "TCP").upper()))
        i += 1
    for f in _value_rows(doc, "filesystem"):
        path = f.get("path") if isinstance(f, dict) else f
        events.append(_ev(run_id, platform, "file_write", _seq(base, i), file_path=path))
        i += 1
    for r in _value_rows(doc, "registry"):
        key = r.get("path") if isinstance(r, dict) else r
        events.append(_ev(run_id, platform, "registry_write", _seq(base, i), registry_key=key))
        i += 1
    return events


def normalize_report(provider: str, report: dict, run_id: str, platform: str, base: datetime.datetime) -> list[dict]:
    """Dispatch to the provider's normalizer (raises on unknown provider)."""
    if provider == "anyrun":
        return normalize_anyrun(report, run_id, platform, base)
    if provider == "triage":
        return normalize_triage(report, run_id, platform, base)
    if provider == "joe":
        return normalize_joe(report, run_id, platform, base)
    raise ValueError(f"No report normalizer for provider: {provider}")


# ---------------------------------------------------------------------------
# Live adapters — thin httpx wrappers (documented API contracts)
# ---------------------------------------------------------------------------

async def _live_detonate(provider: str, task: dict, sample_bytes: bytes) -> dict:
    """Submit → poll → fetch report for a real provider. Returns the merged
    report dict ready for `normalize_report`. Raises on any failure — the
    task layer catches and records the error."""
    platform = task["platform"]
    key = _key_for(provider)
    if not key:
        raise RuntimeError(f"{provider} is not configured — set the {provider.upper()}_API_KEY env var")
    headers = {"User-Agent": "outpost-sandbox/1.0"}
    async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
        if provider == "anyrun":
            # POST /v1/analysis — multipart: file + env_os + env_type.
            # Response: {"data": {"id": "<analysis id>"}}.
            resp = await client.post(
                "https://api.any.run/v1/analysis",
                headers={"Authorization": f"Bearer {key}"},
                files={"file": (task["sample_name"], sample_bytes)},
                data={
                    "env_os": platform,
                    "env_type": "complete",
                    "opt_network_connect": "1",
                    "opt_privacy_type": "bylink",
                },
            )
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id")
            if not analysis_id:
                raise RuntimeError("Any.Run submit returned no analysis id")
            status_url = f"https://api.any.run/v1/analysis/{analysis_id}"
            report = {}
            for attempt in range(90):  # up to ~30 min
                st = (await client.get(status_url, headers={"Authorization": f"Bearer {key}"})).json()
                state = (st.get("data") or st).get("status", "").lower()
                if state in ("finished", "completed"):
                    break
                if state in ("failed", "error"):
                    raise RuntimeError(f"Any.Run analysis {analysis_id} failed")
                await asyncio.sleep(20)
            else:
                raise RuntimeError("Any.Run analysis timed out (30 min)")
            for part in ("summary", "network", "process", "files", "registry"):
                try:
                    r = await client.get(f"{status_url}/report/{part}", headers={"Authorization": f"Bearer {key}"})
                    r.raise_for_status()
                    data = r.json().get("data", r.json())
                    if isinstance(data, dict):
                        report.update(data)
                except Exception:
                    continue  # a missing report part must not fail the whole run
            return report

        if provider == "triage":
            # POST /v0/samples — multipart: file + _json config.
            # Response: {"id": "<sample id>"}; task id comes from GET /v0/samples/{id}.
            resp = await client.post(
                "https://api.tria.ge/v0/samples",
                headers={"Authorization": f"Bearer {key}"},
                files={"file": (task["sample_name"], sample_bytes)},
                data={"_json": '{"kind": "file", "interactive": false, "defaults": {"timeout": 120, "network": "internet"}}'},
            )
            resp.raise_for_status()
            sample_id = resp.json().get("id")
            if not sample_id:
                raise RuntimeError("Triage submit returned no sample id")
            for attempt in range(90):
                st = (await client.get(f"https://api.tria.ge/v0/samples/{sample_id}", headers={"Authorization": f"Bearer {key}"})).json()
                state = (st.get("status") or "").lower()
                if state in ("reported", "finished"):
                    break
                if state in ("failed", "error"):
                    raise RuntimeError(f"Triage analysis {sample_id} failed")
                await asyncio.sleep(20)
            else:
                raise RuntimeError("Triage analysis timed out (30 min)")
            tasks = (st.get("tasks") or {})
            task_id = next(iter(tasks), None)
            if not task_id:
                raise RuntimeError("Triage sample has no task id")
            r = await client.get(
                f"https://api.tria.ge/v0/samples/{sample_id}/reports/{task_id}",
                headers={"Authorization": f"Bearer {key}"},
            )
            r.raise_for_status()
            return r.json()

        if provider == "joe":
            # POST /v2/analysis/submit — form: apikey, sample, environment.
            # Response: {"data": {"webid": "..."}}.
            env = "linux_ubuntu_lts_x64" if platform == "linux" else "w10_x64"
            resp = await client.post(
                "https://jbxcloud.joesecurity.org/api/v2/analysis/submit",
                data={"apikey": key, "environment": env},
                files={"sample": (task["sample_name"], sample_bytes)},
            )
            resp.raise_for_status()
            webid = resp.json().get("data", {}).get("webid")
            if not webid:
                raise RuntimeError("Joe Sandbox submit returned no webid")
            for attempt in range(90):
                st = (await client.get(f"https://jbxcloud.joesecurity.org/api/v2/analysis/{webid}", params={"apikey": key})).json()
                state = ((st.get("data") or {}).get("status") or "").lower()
                if state in ("finished", "completed"):
                    break
                if state in ("failed", "error"):
                    raise RuntimeError(f"Joe Sandbox analysis {webid} failed")
                await asyncio.sleep(20)
            else:
                raise RuntimeError("Joe Sandbox analysis timed out (30 min)")
            r = await client.get(
                f"https://jbxcloud.joesecurity.org/api/v2/analysis/{webid}/report",
                params={"apikey": key},
            )
            r.raise_for_status()
            return r.json()

    raise RuntimeError(f"Unknown provider: {provider}")


# ---------------------------------------------------------------------------
# Task manager
# ---------------------------------------------------------------------------

_tasks: dict[str, dict] = {}


def create_run_id() -> str:
    """A run id in the same 12-hex shape as the ingest routes."""
    return uuid.uuid4().hex[:12]


def get_task(task_id: str) -> dict | None:
    return _tasks.get(task_id)


def create_task(run_id: str, sample_id: str, sample_name: str, provider: str, platform: str) -> dict:
    task_id = uuid.uuid4().hex[:12]
    task = {
        "task_id": task_id,
        "run_id": run_id,
        "sample_id": sample_id,
        "sample_name": sample_name,
        "provider": provider,
        "platform": platform,
        "status": "submitted",
        "events": 0,
        "alerts": 0,
        "risk_score": 0,
        "highest_severity": None,
        "error": None,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "finished_at": None,
    }
    _tasks[task_id] = task
    return task


async def run_task(task: dict, sample_bytes: bytes) -> None:
    """Execute one live external sandbox detonation: submit/poll/fetch,
    then ingest the normalized events through the real pipeline."""
    task["status"] = "running"
    base = datetime.datetime.now(datetime.timezone.utc)
    try:
        report = await _live_detonate(task["provider"], task, sample_bytes)
        events = normalize_report(task["provider"], report, task["run_id"], task["platform"], base)

        with db_session() as conn:
            row = run_store.get_run(conn, task["run_id"])
            if not row:
                raise RuntimeError(f"Run {task['run_id']} vanished during detonation")
            for ev in events:
                event_store.insert_event(conn, ev)
            new_alerts = detection.evaluate_batch(conn, task["run_id"], events)

            # Live watchlist alerting — watched IOCs in the sandbox report hit
            # the same channel as live ingestion.
            from ..models import watchlist as watchlist_store
            watchlist_matches = watchlist_store.record_hits(
                conn, task["run_id"], watchlist_store.match_events(conn, events)
            )

            run_store.complete_run(conn, task["run_id"])
            summary = run_store.to_summary(conn, run_store.get_run(conn, task["run_id"]))

        # SSE push so open Monitor connections see the sandbox alerts live.
        from ..services import events_stream
        events_stream.publish_alerts(new_alerts)
        if watchlist_matches:
            events_stream.publish_watchlist(
                task["run_id"], task["sample_name"], task["platform"], watchlist_matches
            )

        task.update(
            events=len(events),
            alerts=len(new_alerts),
            risk_score=summary.risk_score,
            highest_severity=summary.highest_severity,
            status="completed",
        )
    except Exception as exc:  # provider outage / bad report — surface, don't crash
        task["status"] = "error"
        task["error"] = str(exc)[:400]
    finally:
        task["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()


def task_out(task: dict) -> dict:
    """The API-facing shape (drops nothing — the task dict already matches)."""
    return dict(task)
