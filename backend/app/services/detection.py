"""Rule-based detection heuristics — the flagship feature.

Implements the rules from docs/11-DETECTION-LOGIC.md, extended by the
smarter-detection pass: per-OS tables (masquerading, parent-child, LOLBin,
persistence), the uncommon-port rule, and the composite attack-chain
correlation that fires when a single run touches 3+ kill-chain stages.

Every rule is explainable: `Alert.details` states exactly what was observed,
never a generic "suspicious activity detected". Runs on every ingested batch
so live monitoring is actually live.
"""

import re
import statistics
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..core.schema import Alert

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
# Per-OS legitimate system process → expected absolute path (roadmap 1.2).
# Rules pick the table by `event.platform`, defaulting to windows for legacy
# events that predate platform-aware ingestion.
LEGITIMATE_SYSTEM_PROCESSES = {
    "windows": {
        "svchost.exe": r"C:\Windows\System32\svchost.exe",
        "lsass.exe": r"C:\Windows\System32\lsass.exe",
        "explorer.exe": r"C:\Windows\explorer.exe",
        "rundll32.exe": r"C:\Windows\System32\rundll32.exe",
        "conhost.exe": r"C:\Windows\System32\conhost.exe",
        "csrss.exe": r"C:\Windows\System32\csrss.exe",
        "services.exe": r"C:\Windows\System32\services.exe",
        "winlogon.exe": r"C:\Windows\System32\winlogon.exe",
        "smss.exe": r"C:\Windows\System32\smss.exe",
        "spoolsv.exe": r"C:\Windows\System32\spoolsv.exe",
        "dwm.exe": r"C:\Windows\System32\dwm.exe",
    },
    "linux": {
        "bash": "/usr/bin/bash",
        "sh": "/usr/bin/sh",
        "systemd": "/usr/lib/systemd/systemd",
        "python3": "/usr/bin/python3",
        "ssh": "/usr/bin/ssh",
        "curl": "/usr/bin/curl",
        "wget": "/usr/bin/wget",
    },
    "macos": {
        "bash": "/bin/bash",
        "sh": "/bin/sh",
        "zsh": "/bin/zsh",
        "python3": "/usr/bin/python3",
        "osascript": "/usr/bin/osascript",
        "launchctl": "/bin/launchctl",
        "curl": "/usr/bin/curl",
    },
}

SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    # Office suites spawning script hosts / LOLBins directly (macro-style).
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("winword.exe", "regsvr32.exe"),
    ("excel.exe", "wscript.exe"),
    ("excel.exe", "mshta.exe"),
    ("powerpnt.exe", "cmd.exe"),
    ("powerpnt.exe", "powershell.exe"),
    ("outlook.exe", "wscript.exe"),
}

# LOLBin abuse patterns, per platform (roadmap 1.2). Windows keeps the classic
# macro/Office set; Linux adds the curl|sh download-and-exec family.
LOLBIN_SUSPICIOUS_PATTERNS = {
    "windows": [
        (r"powershell.*-enc(odedcommand)?\s", "base64-encoded PowerShell command"),
        (r"powershell.*-nop.*-w\s+hidden", "hidden-window PowerShell execution"),
        (r"powershell.*-ep\s+bypass", "PowerShell execution-policy bypass"),
        (r"powershell.*-windowstyle\s+hidden", "hidden-window PowerShell execution"),
        (r"(IEX\s*\()|(Invoke-Expression)", "PowerShell inline expression / download cradle"),
        (r"(New-Object).*(Net\.WebClient|Net\.HttpClient)", "PowerShell WebClient download cradle"),
        (r"Invoke-WebRequest", "PowerShell Invoke-WebRequest (download cradle)"),
        (r"certutil.*-urlcache|-decode", "certutil abused for download/decode (LOLBin)"),
        (r"bitsadmin\s+/transfer", "bitsadmin abused for download (LOLBin)"),
        (r"wmic\s+process\s+call\s+create", "wmic executing a remote process (LOLBin)"),
        (r"msiexec\s+/i\s+http", "msiexec installing a remote MSI (LOLBin)"),
        (r"regsvr32\s+/s\s+/u\s+/i:?http", "regsvr32 Squiblydoo (remote payload via COM)"),
        (r"mshta.*http", "mshta executing a remote HTA payload"),
        (r"rundll32.*javascript:", "rundll32 executing inline JavaScript"),
    ],
    "linux": [
        # /dev/tcp first: it is the strongest reverse-shell signal, and a
        # command like `bash -i >& /dev/tcp/…` matches both patterns — the
        # more specific detail should win.
        (r"/dev/tcp/", "bash /dev/tcp (reverse shell)"),
        (r"curl[^\n|]*\|\s*(ba)?sh", "curl piped to shell (download-and-exec)"),
        (r"wget[^\n|]*\|\s*(ba)?sh", "wget piped to shell (download-and-exec)"),
        (r"bash\s+-i", "interactive bash (reverse-shell smell)"),
        (r"(nc|ncat)\s+[^\n]*( -e | -c )", "netcat reverse/exec shell"),
        (r"socat\s+[^\n]*(exec|system):", "socat exec (reverse shell)"),
        (r"telnet\s+[^\n]+\s+\d+\s*[&|]", "telnet piped/backgrounded (reverse shell)"),
        (r"openssl\s+s_client\s+[^\n]*-quiet", "openssl s_client quiet (encrypted reverse shell)"),
        (r"base64\s+-d", "base64 decode (encoded payload)"),
        (r"python3?\s+-c", "inline python execution"),
        (r"perl\s+-e", "inline perl execution"),
        (r"chmod\s+\+x", "chmod +x (download-and-exec pattern)"),
    ],
    "macos": [
        # osascript is the macOS LOLBin: JXA/AppleScript download-and-exec.
        (r"osascript.*(do shell script|do shellscript)", "osascript executing a shell command (LOLBin)"),
        (r"osascript.*(JXA|OSAKit)", "osascript JXA script host"),
        (r"curl[^\n|]*\|\s*(ba)?sh", "curl piped to shell (download-and-exec)"),
        (r"bash\s+-i", "interactive bash (reverse-shell smell)"),
        (r"/dev/tcp/", "bash /dev/tcp (reverse shell)"),
        (r"python3?\s+-c", "inline python execution"),
        (r"base64\s+-d", "base64 decode (encoded payload)"),
        (r"chmod\s+\+x", "chmod +x (download-and-exec pattern)"),
    ],
}

# Ports commonly used by C2 frameworks / reverse shells (Metasploit 4444,
# IRC bots 6667, common bind shells 31337, etc.). Connections to these from
# a monitored host are a beacon/plant smell even before behavior confirms it.
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 9001, 9002, 50050}

# Persistence locations, per platform (roadmap 1.2). Windows persists via
# registry Run keys (registry_write events); Linux via shell/autostart files
# (file_write events). The same rule id family, different signal.
PERSISTENCE_PATHS = {
    "windows": {
        "registry": [
            r"\Software\Microsoft\Windows\CurrentVersion\Run",
            r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
    },
    "linux": {
        "files": [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            "/etc/cron",
            "/var/spool/cron",
            "/etc/crontab",
            "/etc/systemd/system",
            "/etc/rc.local",
            "/etc/init.d",
            ".config/autostart",
            "/etc/xdg/autostart",
        ]
    },
    "macos": {
        "files": [
            "LaunchAgents",
            "LaunchDaemons",
            ".zshrc",
            ".bash_profile",
            ".profile",
            "/etc/rc.local",
            "/etc/periodic",
        ]
    },
}

BEACON_WINDOW_MINUTES = 30
BEACON_MIN_CONNECTIONS = 5
BEACON_VARIANCE_THRESHOLD = 5.0  # seconds std-dev of intervals

RENAME_BURST_WINDOW_SECONDS = 10
RENAME_BURST_THRESHOLD = 10

# rule_id → kill-chain stage (for the composite attack-chain correlation).
_KILL_CHAIN_STAGE = {
    "masquerading": "Defense Evasion",
    "lolbin-abuse": "Execution",
    "suspicious-parent-child": "Execution",
    "first-seen-process": "Execution",
    "beaconing": "Command and Control",
    "unusual-port": "Command and Control",
    "registry-persistence": "Persistence",
    "autostart-persistence": "Persistence",
    "rename-burst": "Impact",
}


def _platform(event: dict) -> str:
    """Events may predate platform-aware ingestion — default to windows."""
    return (event.get("platform") or "windows").lower()


# ---------------------------------------------------------------------------
# Alert factory + dedup
# ---------------------------------------------------------------------------
def _make_alert(
    run_id: str,
    rule_id: str,
    rule_name: str,
    severity: str,
    event: dict,
    details: str,
) -> Alert:
    return Alert(
        run_id=run_id,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        triggered_at=datetime.now(timezone.utc),
        related_pid=event.get("pid") or event.get("ppid"),
        related_ip=event.get("dest_ip"),
        details=details,
    )


def _alert_exists(conn: sqlite3.Connection, run_id: str, rule_id: str, related: str | None) -> bool:
    """Dedupe: same rule + same related entity should only alert once per run.

    Prevents beaconing / rename-burst / event rules from spamming identical
    alerts on every polling batch.
    """
    if related is not None:
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE run_id = ? AND rule_id = ? AND (related_ip = ? OR related_pid = ?) LIMIT 1",
            (run_id, rule_id, related, related),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE run_id = ? AND rule_id = ? AND related_ip IS NULL AND related_pid IS NULL LIMIT 1",
            (run_id, rule_id),
        ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Rule 1 — Process Masquerading
# ---------------------------------------------------------------------------
def check_masquerading(event: dict) -> Optional[Alert]:
    r"""A known system binary running from an unexpected absolute path.

    Only absolute-path invocations are judged: a bare `bash -c …` command line
    tells us nothing about where the binary actually lives, so it never fires.
    Windows drive-letter paths (C:\…) and POSIX absolute paths (/usr/bin/…) both
    qualify.
    """
    platform = _platform(event)
    legit = LEGITIMATE_SYSTEM_PROCESSES.get(platform, {})
    name = (event.get("process_name") or "").lower()
    expected_path = legit.get(name)
    if not expected_path:
        return None
    cmdline = (event.get("command_line") or "").strip()
    if not cmdline:
        return None
    first_token = cmdline.split()[0].lower()
    is_abs = first_token.startswith("/") or (len(first_token) >= 3 and first_token[1] == ":")
    if not is_abs:
        return None
    if expected_path.lower() in cmdline.lower():
        return None
    return _make_alert(
        event["run_id"], "masquerading", "Process masquerading as system binary",
        "malicious", event,
        f"{name} running from an unexpected path — expected {expected_path}",
    )


# ---------------------------------------------------------------------------
# Rule 2 — Suspicious Parent-Child
# ---------------------------------------------------------------------------
def check_parent_child(event: dict, process_map: dict) -> Optional[Alert]:
    if event.get("event_type") != "process_create":
        return None
    parent = process_map.get(event.get("ppid"))
    if not parent:
        return None
    pair = (str(parent.get("process_name", "")).lower(), str(event.get("process_name", "")).lower())
    if pair in SUSPICIOUS_PARENT_CHILD:
        return _make_alert(
            event["run_id"], "suspicious-parent-child",
            "Suspicious parent-child process relationship",
            "malicious", event,
            f"{parent['process_name']} spawned {event['process_name']} — common macro-malware pattern",
        )
    return None


# ---------------------------------------------------------------------------
# Rule 3 — LOLBin Abuse
# ---------------------------------------------------------------------------
def check_lolbin_abuse(event: dict) -> Optional[Alert]:
    if event.get("event_type") != "process_create":
        return None
    platform = _platform(event)
    cmdline = event.get("command_line") or ""
    for pattern, description in LOLBIN_SUSPICIOUS_PATTERNS.get(platform, LOLBIN_SUSPICIOUS_PATTERNS["windows"]):
        if re.search(pattern, cmdline, re.IGNORECASE):
            return _make_alert(
                event["run_id"], "lolbin-abuse", "Living-off-the-land binary abuse",
                "malicious", event, description,
            )
    return None


# ---------------------------------------------------------------------------
# Rule 8 — Uncommon C2-style Port
# ---------------------------------------------------------------------------
def check_unusual_port(event: dict) -> Optional[Alert]:
    """Connection to a port commonly used by C2 frameworks / reverse shells.

    A plant that hasn't beaconed yet still shows up as a quiet connection to
    Metasploit's 4444, an IRC bot port, a bind-shell port, etc. — a cheap,
    low-FP early signal that complements beaconing.
    """
    if event.get("event_type") != "network_connection":
        return None
    port = event.get("dest_port")
    if port is None:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if port in SUSPICIOUS_PORTS:
        return _make_alert(
            event["run_id"], "unusual-port",
            "Connection to uncommon C2-style port",
            "suspicious", event,
            f"Connection to {event.get('dest_ip')}:{port} — port commonly used by C2 frameworks",
        )
    return None


# ---------------------------------------------------------------------------
# Rule 4 — C2-Style Beaconing
# ---------------------------------------------------------------------------
def _parse_ts(value) -> Optional[datetime]:
    """Accept ISO strings (with or without Z) or already-parsed datetimes."""
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _window_cutoff(events: list[dict], window_seconds: int) -> datetime:
    """Anchor the detection window to the newest event in the batch.

    Using `now` would break replay/import scenarios where ingested timestamps
    are in the past; anchoring to the data itself keeps the rules correct for
    both live streaming and batched synthetic events.
    """
    ref = None
    for ev in events:
        ts = _parse_ts(ev.get("timestamp", ""))
        if ts and (ref is None or ts > ref):
            ref = ts
    if ref is None:
        ref = datetime.now(timezone.utc)
    return ref - timedelta(seconds=window_seconds)


def _recent_connection_times(conn: sqlite3.Connection, run_id: str, dest_ip: str, cutoff: datetime) -> list[datetime]:
    rows = conn.execute(
        "SELECT timestamp FROM events WHERE run_id = ? AND dest_ip = ? AND timestamp >= ? ORDER BY timestamp ASC",
        (run_id, dest_ip, cutoff.isoformat()),
    ).fetchall()
    times = []
    for r in rows:
        ts = _parse_ts(r["timestamp"])
        if ts:
            times.append(ts)
    return times


def check_beaconing(
    conn: sqlite3.Connection,
    run_id: str,
    dest_ip: str,
    cutoff: datetime,
    min_conn: int = BEACON_MIN_CONNECTIONS,
    variance: float = BEACON_VARIANCE_THRESHOLD,
) -> Optional[Alert]:
    if not dest_ip:
        return None
    timestamps = _recent_connection_times(conn, run_id, dest_ip, cutoff)
    if len(timestamps) < min_conn:
        return None
    intervals = [(t2 - t1).total_seconds() for t1, t2 in zip(timestamps, timestamps[1:])]
    if len(intervals) < 2:
        return None
    if statistics.pstdev(intervals) >= variance:
        return None
    return Alert(
        run_id=run_id,
        rule_id="beaconing",
        rule_name="C2-style beaconing",
        severity="suspicious",
        triggered_at=datetime.now(timezone.utc),
        related_ip=dest_ip,
        details=(
            f"{len(timestamps)} connections to {dest_ip} at regular "
            f"~{int(statistics.mean(intervals))}s intervals (std-dev "
            f"{statistics.pstdev(intervals):.1f}s)"
        ),
    )


# ---------------------------------------------------------------------------
# Rule 5 — Persistence (registry Run keys on Windows, autostart files on
# Linux; roadmap 1.2)
# ---------------------------------------------------------------------------
def check_registry_persistence(event: dict) -> Optional[Alert]:
    """Windows: write to an autorun registry key."""
    if event.get("event_type") != "registry_write":
        return None
    key = event.get("registry_key") or ""
    for path in PERSISTENCE_PATHS.get("windows", {}).get("registry", []):
        if path.lower() in key.lower():
            return _make_alert(
                event["run_id"], "registry-persistence",
                "Persistence via registry Run key",
                "suspicious", event,
                f"Write to autorun key: {key}",
            )
    return None


def check_autostart_persistence(event: dict) -> Optional[Alert]:
    r"""Linux/macOS: write to a shell profile / cron / systemd / autostart path.

    Gated on the platform so a Windows event writing a path that merely
    *contains* a Linux autostart string (e.g. C:\Users\victim\.bashrc from
    WSL tampering) can't false-positive the Unix rule.
    """
    if event.get("event_type") != "file_write":
        return None
    platform = _platform(event)
    if platform not in ("linux", "macos"):
        return None
    path = (event.get("file_path") or "").lower()
    for candidate in PERSISTENCE_PATHS.get(platform, {}).get("files", []):
        if candidate.lower() in path:
            return _make_alert(
                event["run_id"], "autostart-persistence",
                "Persistence via shell/autostart file",
                "suspicious", event,
                f"Write to autostart path: {event.get('file_path')}",
            )
    return None


# ---------------------------------------------------------------------------
# Rule 7 — First-Seen Process (novelty detection, docs/11)
# ---------------------------------------------------------------------------
def check_first_seen(conn: sqlite3.Connection, run_id: str, event: dict, seen_names: set) -> Optional[Alert]:
    """A process name never observed in any *prior* run.

    Not inherently malicious, but worth a suspicious flag — especially in live
    monitoring, where "what's normal for this machine" builds up over time.
    `seen_names` dedupes within the current batch; the `_alert_exists` dedup
    in the orchestrator stops repeats across batches.
    """
    if event.get("event_type") != "process_create":
        return None
    name = event.get("process_name")
    if not name:
        return None
    if name in seen_names:
        return None
    seen_names.add(name)
    row = conn.execute(
        "SELECT 1 FROM events WHERE process_name = ? AND run_id != ? LIMIT 1",
        (name, run_id),
    ).fetchone()
    if row:
        return None
    return _make_alert(
        run_id, "first-seen-process", "First-seen process (novelty)",
        "suspicious", event,
        f"{name} has not been observed in any prior session",
    )


# ---------------------------------------------------------------------------
# Rule 6 — Rapid File Write Burst (ransomware indicator)
# ---------------------------------------------------------------------------
def _recent_file_writes(conn: sqlite3.Connection, run_id: str, pid: int, cutoff: datetime) -> list[str]:
    rows = conn.execute(
        "SELECT file_path FROM events WHERE run_id = ? AND pid = ? AND event_type = 'file_write' AND timestamp >= ?",
        (run_id, pid, cutoff.isoformat()),
    ).fetchall()
    return [r["file_path"] for r in rows]


def check_rename_burst(
    conn: sqlite3.Connection,
    run_id: str,
    event: dict,
    cutoff: datetime,
    threshold: int = RENAME_BURST_THRESHOLD,
) -> Optional[Alert]:
    pid = event.get("pid")
    if event.get("event_type") != "file_write" or pid is None:
        return None
    recent = _recent_file_writes(conn, run_id, pid, cutoff)
    if len(recent) > threshold:
        return _make_alert(
            run_id, "rename-burst", "Rapid file write burst (possible ransomware)",
            "malicious", event,
            f"{len(recent)} file writes from pid {pid} within {RENAME_BURST_WINDOW_SECONDS} seconds",
        )
    return None


# ---------------------------------------------------------------------------
# Rule tuning (roadmap 2.3) — DB overrides on top of the module defaults.
# ---------------------------------------------------------------------------
# Tunable knobs: param name → (rule_id, parse fn, default). The rule editor
# stores overrides in `rule_tuning`; absent rows mean "use the default", so an
# empty table is indistinguishable from the pre-editor behavior.
_DEFAULT_TUNABLES = {
    "BEACON_MIN_CONNECTIONS": ("beaconing", int, BEACON_MIN_CONNECTIONS),
    "BEACON_WINDOW_MINUTES": ("beaconing", int, BEACON_WINDOW_MINUTES),
    "BEACON_VARIANCE_THRESHOLD": ("beaconing", float, BEACON_VARIANCE_THRESHOLD),
    "RENAME_BURST_THRESHOLD": ("rename-burst", int, RENAME_BURST_THRESHOLD),
    "RENAME_BURST_WINDOW_SECONDS": ("rename-burst", int, RENAME_BURST_WINDOW_SECONDS),
}

# Defaults registry for the editor UI (kept separate from the lookup so the
# webapp can list every knob with its baseline even before any override).
TUNABLE_DEFAULTS: dict[str, tuple[str, str, object]] = {
    name: (rule_id, _type.__name__, default)
    for name, (rule_id, _type, default) in _DEFAULT_TUNABLES.items()
}


def _tunable(conn: sqlite3.Connection, name: str):
    """Resolve a tunable: DB override if present, else the module default."""
    rule_id, parse, default = _DEFAULT_TUNABLES[name]
    row = conn.execute(
        "SELECT value FROM rule_tuning WHERE rule_id = ? AND param = ?",
        (rule_id, name),
    ).fetchone()
    if not row:
        return default
    try:
        return parse(row["value"])
    except (TypeError, ValueError):
        return default


def _load_tunables(conn: sqlite3.Connection) -> dict[str, object]:
    """One query per batch — every knob at once, then read from the dict."""
    rows = conn.execute("SELECT rule_id, param, value FROM rule_tuning").fetchall()
    overrides: dict[tuple[str, str], str] = {(r["rule_id"], r["param"]): r["value"] for r in rows}
    loaded: dict[str, object] = {}
    for name, (rule_id, parse, default) in _DEFAULT_TUNABLES.items():
        raw = overrides.get((rule_id, name))
        if raw is None:
            loaded[name] = default
        else:
            try:
                loaded[name] = parse(raw)
            except (TypeError, ValueError):
                loaded[name] = default
    return loaded


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def evaluate_batch(conn: sqlite3.Connection, run_id: str, events: list[dict]) -> list[Alert]:
    """Run all rules against a batch of new events; persist and return alerts.

    Called from POST /ingest/batch. Keep it cheap — it runs on every event.
    """
    from ..models.event import insert_alert

    # Process map for parent-child rule: all process_create events in this run.
    process_rows = conn.execute(
        "SELECT pid, ppid, process_name FROM events WHERE run_id = ? AND event_type = 'process_create'",
        (run_id,),
    ).fetchall()
    process_map = {}
    for r in process_rows:
        pid = r["pid"]
        if pid is not None and pid not in process_map:
            process_map[pid] = {"pid": pid, "ppid": r["ppid"], "process_name": r["process_name"] or "unknown"}

    new_alerts: list[Alert] = []
    seen_related: set[tuple] = set()
    seen_names: set[str] = set()

    # Separate windows: beaconing looks back 30 min, rename-burst 10 s
    # (docs/11). Thresholds are tunable via the rule editor (roadmap 2.3).
    t = _load_tunables(conn)
    beacon_cutoff = _window_cutoff(events, int(t["BEACON_WINDOW_MINUTES"]) * 60)
    burst_cutoff = _window_cutoff(events, int(t["RENAME_BURST_WINDOW_SECONDS"]))

    for event in events:
        candidates: list[Optional[Alert]] = [
            check_masquerading(event),
            check_parent_child(event, process_map),
            check_lolbin_abuse(event),
            check_registry_persistence(event),
            check_autostart_persistence(event),
            check_unusual_port(event),
            check_first_seen(conn, run_id, event, seen_names),
        ]
        for alert in candidates:
            if alert is None:
                continue
            key = (alert.rule_id, alert.related_pid, alert.related_ip)
            if key in seen_related or _alert_exists(conn, run_id, alert.rule_id, alert.related_ip or (str(alert.related_pid) if alert.related_pid else None)):
                continue
            seen_related.add(key)
            insert_alert(conn, alert)
            new_alerts.append(alert)

    # Run-wide rules evaluated per unique IP / pid seen in this batch.
    for event in events:
        if event.get("event_type") == "network_connection" and event.get("dest_ip"):
            alert = check_beaconing(
                conn,
                run_id,
                event["dest_ip"],
                beacon_cutoff,
                min_conn=int(t["BEACON_MIN_CONNECTIONS"]),
                variance=int(t["BEACON_VARIANCE_THRESHOLD"] * 100) / 100.0,
            )
            if alert and not _alert_exists(conn, run_id, "beaconing", alert.related_ip):
                insert_alert(conn, alert)
                new_alerts.append(alert)
        if event.get("event_type") == "file_write" and event.get("pid"):
            alert = check_rename_burst(
                conn,
                run_id,
                event,
                burst_cutoff,
                threshold=int(t["RENAME_BURST_THRESHOLD"]),
            )
            if alert and not _alert_exists(conn, run_id, "rename-burst", str(alert.related_pid) if alert.related_pid else None):
                insert_alert(conn, alert)
                new_alerts.append(alert)

    # Composite rule (smartest single signal): if this run has now touched 3+
    # distinct kill-chain stages, one coordinated-attack-chain finding is
    # emitted. Deduped so it fires at most once per run — later batches can't
    # re-trigger it.
    fired = conn.execute(
        "SELECT DISTINCT rule_id FROM alerts WHERE run_id = ?", (run_id,)
    ).fetchall()
    stages = {_KILL_CHAIN_STAGE[r["rule_id"]] for r in fired if r["rule_id"] in _KILL_CHAIN_STAGE}
    if len(stages) >= 3 and not _alert_exists(conn, run_id, "attack-chain", None):
        chain_alert = Alert(
            run_id=run_id,
            rule_id="attack-chain",
            rule_name="Coordinated attack chain",
            severity="malicious",
            triggered_at=datetime.now(timezone.utc),
            related_ip=None,
            related_pid=None,
            details=(
                f"{len(stages)} distinct kill-chain stages observed — "
                f"{', '.join(sorted(stages))}"
            ),
        )
        insert_alert(conn, chain_alert)
        new_alerts.append(chain_alert)

    return new_alerts
