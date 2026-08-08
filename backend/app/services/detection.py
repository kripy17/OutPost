"""Rule-based detection heuristics — the flagship feature.

Implements the rules from docs/11-DETECTION-LOGIC.md, extended by the
smarter-detection pass: per-OS tables (masquerading, parent-child, LOLBin,
persistence), the uncommon-port rule, and the composite attack-chain
correlation that fires when a single run touches 3+ kill-chain stages.

Every rule is explainable: `Alert.details` states exactly what was observed,
never a generic "suspicious activity detected". Runs on every ingested batch
so live monitoring is actually live.
"""

import json
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

# Parents that make a first-seen process worth flagging: script hosts and
# LOLBins are how novel malware usually arrives on a host. A first-seen
# process spawned by a normal parent (explorer, a package manager, a UI
# updater) is mostly "user installed something" — high-FP noise on a live
# machine — so the novelty rule stays silent for those. This is the single
# biggest false-positive reducer for always-on live monitoring.
FIRST_SEEN_SCRIPT_HOSTS = {
    "powershell.exe", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "sh", "bash", "dash", "zsh",
    "python3", "python", "perl", "ruby", "node", "curl", "wget", "osascript",
}

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

# Discovery (rule 15) — how many distinct enumeration commands within the
# window make a run's recon worth flagging. One whoami is an admin; a spread
# of user/network/system queries inside two minutes is a recon sweep.
ENUM_WINDOW_SECONDS = 120
ENUM_BURST_THRESHOLD = 3

# Exfiltration (rule 16) — an archive created then an upload/connection to a
# non-private host inside the window is the classic data-staging arc.
STAGING_WINDOW_SECONDS = 180

# Rules 17–21 close the remaining ATT&CK tactics (14/14 coverage gate).

# Reconnaissance (T1595) — one process sweeping many distinct hosts on a single
# port inside the window is active scanning, not routine use.
SCAN_WINDOW_SECONDS = 60
SCAN_DISTINCT_TARGETS = 5

# Resource Development (T1587.001) — compiling a binary into an attacker-
# writable location (/tmp, /dev/shm, /var/tmp) rather than the normal install
# path. `gcc -o /usr/local/bin/x` is a system build; `gcc -o /tmp/x` is a
# capability being developed for later use.
_COMPILER_RE = re.compile(r"\b(gcc|g\+\+|cc|clang|clang\+\+|tcc)\b", re.IGNORECASE)
_TOOLCHAIN_OUT_RE = re.compile(r"\s-o\s+([^\s]+)")
_WRITABLE_COMPILE_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")

# Initial Access (T1566.002) — a document/viewer process spawning a script
# host or LOLBin: the macro→shell pivot that turns an attachment into code.
# Broader than SUSPICIOUS_PARENT_CHILD (which is Execution, T1204.002) — this
# keys on the *document* parent regardless of the exact child pair.
DOCUMENT_VIEWERS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "wps.exe",
    "soffice.bin", "soffice", "libreoffice", "acrobat.exe", "foxitreader.exe",
}
DROPPER_CHILDREN = {
    "powershell.exe", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "bash", "sh", "dash",
    "python", "python3", "perl", "wget", "curl", "zsh",
}

# Lateral Movement (T1021.001) — outbound RDP (3389) / SMB (445). RDP is the
# loudest manual-movement port; 445 is PsExec / remote-share territory.
LATERAL_PORTS = {3389, 445}

# rule_id → kill-chain stage (for the composite attack-chain correlation).
_KILL_CHAIN_STAGE = {
    "network-scan": "Reconnaissance",
    "toolchain-build": "Resource Development",
    "document-dropper": "Initial Access",
    "lateral-rdp-smb": "Lateral Movement",
    "screen-capture": "Collection",
    "masquerading": "Defense Evasion",
    "lolbin-abuse": "Execution",
    "suspicious-parent-child": "Execution",
    "first-seen-process": "Execution",
    "beaconing": "Command and Control",
    "unusual-port": "Command and Control",
    "registry-persistence": "Persistence",
    "autostart-persistence": "Persistence",
    "ssh-authorized-keys": "Persistence",
    "scheduled-task": "Persistence",
    "suid-set": "Privilege Escalation",
    "credential-dump": "Credential Access",
    "suspicious-extension": "Defense Evasion",
    "shell-history-wipe": "Defense Evasion",
    "enumeration-burst": "Discovery",
    "data-staging": "Exfiltration",
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
def check_first_seen(conn: sqlite3.Connection, run_id: str, event: dict, seen_names: set, process_map: dict) -> Optional[Alert]:
    """A process name never observed in any *prior* run — when the novelty is
    *meaningful*: it must be spawned by a script host / LOLBin parent
    (FIRST_SEEN_SCRIPT_HOSTS). A first-seen binary launched by a normal parent
    is indistinguishable from a user installing software, so it never fires —
    that keeps always-on live monitoring quiet on clean machines while still
    catching script-dropped payloads. `seen_names` dedupes within the current
    batch; `_alert_exists` stops repeats across batches.
    """
    if event.get("event_type") != "process_create":
        return None
    name = event.get("process_name")
    if not name:
        return None
    # Novelty alone is too noisy on a live host — require a script-host parent.
    parent = process_map.get(event.get("ppid"))
    if not parent or str(parent.get("process_name", "")).lower() not in FIRST_SEEN_SCRIPT_HOSTS:
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
        f"{name} has not been observed in any prior session (spawned by {parent['process_name']})",
    )


# ---------------------------------------------------------------------------
# Rule 9 — SSH authorized_keys tampering (persistent backdoor, T1098.004)
# ---------------------------------------------------------------------------
def check_ssh_authorized_keys(event: dict) -> Optional[Alert]:
    """A write to ~/.ssh/authorized_keys — an attacker dropping a public key
    for persistent passwordless login. Linux/macOS only."""
    if event.get("event_type") != "file_write":
        return None
    platform = _platform(event)
    if platform not in ("linux", "macos"):
        return None
    path = (event.get("file_path") or "").lower()
    if ".ssh" in path and "authorized_keys" in path:
        return _make_alert(
            event["run_id"], "ssh-authorized-keys",
            "SSH authorized_keys tampering",
            "suspicious", event,
            f"Write to SSH authorized_keys: {event.get('file_path')} — persistent backdoor login",
        )
    return None


# ---------------------------------------------------------------------------
# Rule 10 — SUID/SGID bit set (privilege escalation, T1548.001)
# ---------------------------------------------------------------------------
_SUID_RE = re.compile(
    r"chmod[^\n]*(\+[ug]?s\b|4\s?7\s?[0-7]\s?[0-7]\b|6\s?7\s?5\s?[0-7]\b|2\s?7\s?[0-7]\s?[0-7]\b)",
    re.IGNORECASE,
)


def check_suid_set(event: dict) -> Optional[Alert]:
    """chmod +s / 4755 / 6755 — making a binary run with elevated privileges.
    Classic linux/macOS privilege-escalation step. `chmod +x` never matches."""
    if event.get("event_type") != "process_create":
        return None
    platform = _platform(event)
    if platform not in ("linux", "macos"):
        return None
    cmdline = event.get("command_line") or ""
    if _SUID_RE.search(cmdline):
        return _make_alert(
            event["run_id"], "suid-set",
            "SUID/SGID bit set (privilege escalation)",
            "suspicious", event,
            f"chmod setting setuid/setgid: {cmdline.strip()[:120]}",
        )
    return None


# ---------------------------------------------------------------------------
# Rule 11 — Scheduled task created (Windows persistence, T1053.005)
# ---------------------------------------------------------------------------
_SCHTASKS_RE = re.compile(r"schtasks[^\n]*/\s?create", re.IGNORECASE)


def check_scheduled_task(event: dict) -> Optional[Alert]:
    """Windows: `schtasks /create` on the command line, or a registry write
    into the scheduled-task TaskCache — persistence that survives reboot."""
    if _platform(event) != "windows":
        return None
    if event.get("event_type") == "process_create":
        cmdline = event.get("command_line") or ""
        if _SCHTASKS_RE.search(cmdline):
            return _make_alert(
                event["run_id"], "scheduled-task",
                "Scheduled task created (persistence)",
                "suspicious", event,
                f"schtasks /create — persistent scheduled task: {cmdline.strip()[:120]}",
            )
    elif event.get("event_type") == "registry_write":
        key = (event.get("registry_key") or "").lower()
        if "schedule\\taskcache" in key:
            return _make_alert(
                event["run_id"], "scheduled-task",
                "Scheduled task created (persistence)",
                "suspicious", event,
                f"Write to scheduled-task registry: {event.get('registry_key')}",
            )
    return None


# ---------------------------------------------------------------------------
# Rule 12 — Credential Dumping (Windows, T1003.001)
# ---------------------------------------------------------------------------
# lsass.exe holds everyone's credentials in memory; dumping it (procdump -ma,
# comsvcs MiniDump, mimikatz, SAM/SYSTEM hive saves) is the loudest credential-
# theft signal on Windows. All patterns require the tool/flag explicitly — a
# plain `lsass.exe` mention in a doc or a normal system boot never matches.
CRED_DUMP_PATTERNS = [
    (r"mimikatz", "mimikatz credential-theft toolkit"),
    (r"sekurlsa", "sekurlsa credential extraction (mimikatz)"),
    (r"procdump[^\n]*lsass", "procdump dumping lsass.exe (credential theft)"),
    (r"comsvcs\.dll[^\n]*(MiniDump|#24)", "comsvcs.dll MiniDump of lsass (credential theft)"),
    (r"lsass\.exe\.dmp|\blsass\.dmp", "lsass memory dump file (credential theft)"),
    (r"reg\s+save[^\n]*(sam|system)", "registry hive dump of SAM/SYSTEM (credential theft)"),
    # Require an action verb before lsass/sam — `powershell Get-Process lsass`
    # is a routine diagnostic, so lsass alone never fires.
    (r"powershell[^\n]*(dump|dmp|save|Copy-Item|Add-Type|MiniDump|out-file)[^\n]*(lsass|sam\.hive)",
     "PowerShell dumping LSASS/SAM (credential theft)"),
]


def check_credential_dump(event: dict) -> Optional[Alert]:
    """Windows: a tool/flag combination that extracts credentials from lsass,
    the SAM hive, or the machine's password cache. Windows-only — the same
    command lines on Linux are either impossible (comsvcs) or a different
    trade (grep of the passwd file is normal, so it is not matched)."""
    if _platform(event) != "windows":
        return None
    if event.get("event_type") != "process_create":
        return None
    cmdline = event.get("command_line") or ""
    for pattern, description in CRED_DUMP_PATTERNS:
        if re.search(pattern, cmdline, re.IGNORECASE):
            return _make_alert(
                event["run_id"], "credential-dump",
                "Credential dumping",
                "malicious", event,
                description,
            )
    return None


# ---------------------------------------------------------------------------
# Rule 13 — Suspicious Double-Extension Executable (T1036.003)
# ---------------------------------------------------------------------------
# `invoice.pdf.exe` / `photo.jpg.scr` — a benign-looking extension followed by
# an executable one. Windows hides the real extension by default, which is
# exactly why attackers use this; on Linux it's a shipping-malware smell.
# No `js`/`vbs` in the tail: `pdf.js`, `zip.js`, `doc.js` are real, widely
# shipped libraries — npm installs and web-app writes would fire constantly
# on a live Linux box. Keep binary-Windows tails where a second extension is
# almost never legitimate.
_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|rtf|zip|7z|tar|lnk)"
    r"\.(exe|scr|bat|cmd|com|pif|ps1|msi)$",
    re.IGNORECASE,
)


def check_suspicious_extension(event: dict) -> Optional[Alert]:
    """A benign-looking extension *followed by* an executable one — the classic
    `invoice.pdf.exe` masquerade. Checks both process names and written file
    paths, cross-platform. The checked value is chosen by event type, NOT a
    `process_name or file_path` fallback: a real Sysmon file-write event
    carries the *writer's* process name (e.g. cmd.exe) alongside the written
    path, and taking process_name first would silently skip every file write."""
    if event.get("event_type") == "process_create":
        value = event.get("process_name") or ""
    elif event.get("event_type") == "file_write":
        value = event.get("file_path") or ""
    else:
        return None
    name = value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].strip()
    if not name or not _DOUBLE_EXT_RE.search(name):
        return None
    return _make_alert(
        event["run_id"], "suspicious-extension",
        "Suspicious double-extension executable",
        "malicious", event,
        f"File masquerading as a benign document with an executable tail: {value}",
    )


# ---------------------------------------------------------------------------
# Rule 14 — Shell History Wiped (linux/macOS, T1070.003)
# ---------------------------------------------------------------------------
# Clearing history erases the attacker's footprint — a classic anti-forensics
# step taken right after (or before) a payload runs.
_HISTORY_WIPE_PATTERNS = [
    (r"history\s+-c\b", "shell history cleared (history -c)"),
    (r"unset\s+HISTFILE", "HISTFILE unset — history collection disabled"),
    (r"(rm|unlink)[^\n]*(bash_history|zsh_history)", "shell history file deleted"),
    (r">\s*[^\n]*(bash_history|zsh_history)", "shell history file truncated"),
]


def check_shell_history_wipe(event: dict) -> Optional[Alert]:
    """linux/macOS: anti-forensics — history cleared, disabled, or deleted."""
    if event.get("event_type") != "process_create":
        return None
    platform = _platform(event)
    if platform not in ("linux", "macos"):
        return None
    cmdline = event.get("command_line") or ""
    for pattern, description in _HISTORY_WIPE_PATTERNS:
        if re.search(pattern, cmdline, re.IGNORECASE):
            return _make_alert(
                event["run_id"], "shell-history-wipe",
                "Shell history wiped (anti-forensics)",
                "suspicious", event,
                description,
            )
    return None


# ---------------------------------------------------------------------------
# Rule 15 — Discovery Enumeration Burst (T1082, composite)
# ---------------------------------------------------------------------------
# Per-platform enumeration command signatures, (regex, label). A run that
# sweeps several *distinct* kinds (user queries + network inventory + system
# info) inside the window is recon, not troubleshooting — one whoami alone
# never fires. Labels dedupe so repeating the same command doesn't count.
ENUM_PATTERNS = {
    "windows": [
        (r"\bwhoami\b", "whoami / current user"),
        (r"\bnet\s+user\b", "user enumeration (net user)"),
        (r"\bnet\s+(localgroup|group|share|view|session)\b", "network/group enumeration (net …)"),
        (r"\bsysteminfo\b", "system info (systeminfo)"),
        (r"\bipconfig\s+/all", "network config dump (ipconfig /all)"),
        (r"\b(arp\s+-a|netstat\s+-ano|netstat\s+-an\b)", "network inventory (arp/netstat)"),
        (r"\btasklist\s+/svc", "process/service inventory (tasklist /svc)"),
        (r"\b(query\s+user|quser)\b", "logged-on user query"),
        (r"\bwmic\s+useraccount\b", "account enumeration (wmic useraccount)"),
        (r"\bnltest\s+/dclist", "domain controller discovery (nltest /dclist)"),
    ],
    "linux": [
        (r"\bwhoami\b", "identity check (whoami)"),
        (r"\buname\s+-a", "system info (uname -a)"),
        (r"\b(getent\s+passwd|cat\s+/etc/passwd)", "account enumeration (/etc/passwd)"),
        (r"\b(ip\s+addr|ifconfig|ip\s+a\b)", "network config dump (ip addr)"),
        (r"\b(ss\s+-tulpn|ss\s+-tunlp|netstat\s+-tulpn)", "listening sockets (ss/netstat)"),
        (r"\b(arp\s+-a|ip\s+neigh)", "ARP/neighbor table"),
        (r"\b(ls\s+(-la\s+)?/home|ls\s+(-la\s+)?/root|find\s+/home\s+-maxdepth)", "user directory enumeration"),
        (r"\busers\b|\blast\b", "logged-on users (users/last)"),
        (r"\bcrontab\s+-l", "cron enumeration"),
    ],
    "macos": [
        (r"\bwhoami\b", "identity check (whoami)"),
        (r"\buname\s+-a", "system info (uname -a)"),
        (r"\b(dscl\s+\.\s+list|dscacheutil\s+-q\s+user)", "account enumeration (dscl/dscacheutil)"),
        (r"\b(system_profiler|sw_vers)", "system profiling"),
        (r"\b(ifconfig|ip\s+addr)", "network config dump"),
        (r"\b(arp\s+-a|netstat\s+-rn)", "network inventory"),
        (r"\bscutil\s+--dns", "DNS config dump"),
    ],
}


def load_enum_patterns(conn: sqlite3.Connection) -> dict[str, list[tuple[str, str]]]:
    """Effective ENUM_PATTERNS: DB override (settings key) or module defaults.

    The Rules page (GET/PUT /rules/enum-patterns) lets operators add or remove
    recon commands per platform without touching code; this is the single read
    path so the live engine always sees the latest edit. A missing or invalid
    stored value falls back to the module defaults — an empty table is
    indistinguishable from pre-editor behavior."""
    try:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = 'enum_patterns'"
        ).fetchone()
        if row is None:
            return ENUM_PATTERNS
        stored = json.loads(row["value"])
        if not isinstance(stored, dict):
            return ENUM_PATTERNS
        # Validate shape per platform; keep known platforms only, falling back
        # to defaults for anything malformed or missing.
        out = {}
        for platform, base in ENUM_PATTERNS.items():
            rows = stored.get(platform)
            if not isinstance(rows, list):
                out[platform] = base
                continue
            cleaned = []
            for item in rows:
                if not isinstance(item, dict):
                    continue
                pattern = (item.get("pattern") or "").strip()
                label = (item.get("label") or "").strip()
                # Whitespace-only rows are as useless as empty ones — a
                # hand-edited DB could hold either, and an empty regex would
                # silently match every command line.
                if pattern and label:
                    cleaned.append((pattern, label))
            out[platform] = cleaned if cleaned else base
        return out
    except (ValueError, TypeError):
        return ENUM_PATTERNS


def check_enumeration_burst(
    conn: sqlite3.Connection,
    run_id: str,
    cutoff: datetime,
    patterns: Optional[dict[str, list[tuple[str, str]]]] = None,
    min_distinct: int = ENUM_BURST_THRESHOLD,
) -> Optional[Alert]:
    """Discovery — a burst of *distinct* enumeration commands in the window.

    Queries process_create events (this batch is already persisted before
    evaluation) and counts distinct enumeration *kinds*, so five repeated
    whoami calls count once. Fires at least once per run (deduped by the
    run-wide section). `patterns` is the operator-editable table (see
    load_enum_patterns); defaults are used when omitted."""
    if patterns is None:
        patterns = ENUM_PATTERNS
    rows = conn.execute(
        "SELECT platform, pid, command_line FROM events "
        "WHERE run_id = ? AND event_type = 'process_create' AND timestamp >= ?",
        (run_id, cutoff.isoformat()),
    ).fetchall()
    seen: set[str] = set()
    actor_pids: set[int] = set()  # every process that performed an enum command
    for r in rows:
        platform = (r["platform"] or "windows").lower()
        table = patterns.get(platform, patterns["windows"])
        cmdline = r["command_line"] or ""
        for pattern, label in table:
            if re.search(pattern, cmdline, re.IGNORECASE):
                seen.add(label)
                if r["pid"] is not None:
                    actor_pids.add(r["pid"])
                break  # one label per command — repeats don't stack
    if len(seen) < min_distinct:
        return None
    return Alert(
        run_id=run_id,
        rule_id="enumeration-burst",
        rule_name="Discovery enumeration burst",
        severity="suspicious",
        triggered_at=datetime.now(timezone.utc),
        related_ip=None,
        related_pid=None,
        # The processes behind the sweep — the Monitor highlights exactly these
        # nodes in the live process tree.
        related_pids=sorted(actor_pids),
        details=(
            f"{len(seen)} distinct enumeration commands within "
            f"{ENUM_WINDOW_SECONDS}s: {', '.join(sorted(seen))}"
        ),
    )


# ---------------------------------------------------------------------------
# Rule 16 — Data Staging: Archive then Exfil (T1048, composite)
# ---------------------------------------------------------------------------
ARCHIVE_EXTENSIONS = (".zip", ".7z", ".rar", ".tar.gz", ".tgz", ".tar", ".tbz2", ".tar.bz2", ".txz", ".tar.xz")

# Archiver invocations that *create* an archive (not extract/list). Covers the
# flag-anywhere forms (`zip -qr`, `zip -r9`, `zip out.zip …` with no -r, `tar
# czvf`, `tar -zcf`, bzip2/xz variants) — real droppers rarely use the textbook
# minimal invocation.
_ARCHIVER_RE = re.compile(
    r"\b(7z|7za|7zr|rar|winrar)\s+a\b|"
    # tar: any create-form flags with `c` before `f` (`czf`, `czvf`, `zcvf`,
    # `cjf`) — `xf` (extract) / `tf` (list) have no c and never match.
    r"\bzip\s+-[a-z]*r\b|\bzip\s+[^\s|]+\.[zZ][iI][pP]\b|"
    r"\btar\s+-?[a-z]*c[a-z]*f[a-z]*\b|Compress-Archive",
    re.IGNORECASE,
)

# Upload / exfil command signatures (curl --upload-file / -T / -F / -Tfile
# no-space forms, scp/rsync to a remote, nc/ncat pushing data out — both the
# `< file` redirect and the classic `cat file | nc` pipe).
_UPLOAD_RE = re.compile(
    r"\bcurl\b[^\n]*(--upload-file|-T|-F|--data-binary)|"
    r"\bscp\b[^\n]+\b@\b|\bsftp\b|\brsync\b[^\n]+\b@\b|"
    r"\b(nc|ncat)\b[^\n]*<|\b(cat|dd)\s+[^\n]*\|\s*(nc|ncat)\b",
    re.IGNORECASE,
)


def _is_private(ip: str) -> bool:
    """RFC1918 + loopback + link-local — uploading to these isn't exfil."""
    if not ip or ip in ("127.0.0.1", "::1"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True  # hostnames / IPv6 treated as "not obviously private"
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    return False


def _archive_created_in_window(conn: sqlite3.Connection, run_id: str, cutoff: datetime) -> bool:
    """Any archive file written or archive-creating command run in the window."""
    writes = conn.execute(
        "SELECT file_path FROM events WHERE run_id = ? AND event_type = 'file_write' AND timestamp >= ?",
        (run_id, cutoff.isoformat()),
    ).fetchall()
    for r in writes:
        p = (r["file_path"] or "").lower()
        if p.endswith(ARCHIVE_EXTENSIONS):
            return True
    procs = conn.execute(
        "SELECT command_line FROM events WHERE run_id = ? AND event_type = 'process_create' AND timestamp >= ?",
        (run_id, cutoff.isoformat()),
    ).fetchall()
    for r in procs:
        if _ARCHIVER_RE.search(r["command_line"] or ""):
            return True
    return False


def _cmdline_has_private_ip(cmdline: str) -> bool:
    """Any RFC1918/loopback/link-local IP literal in a command line."""
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", cmdline):
        if _is_private(token):
            return True
    return False


def check_data_staging(conn: sqlite3.Connection, run_id: str, event: dict, cutoff: datetime) -> Optional[Alert]:
    """Exfiltration — an archive created in the window *plus* an upload signal.

    Fires on either the upload command (process_create) or a connection to a
    non-private host (network_connection) when an archive was created first.
    An archive alone, or an upload alone, never fires — the combination is the
    staging arc. Privacy is enforced on BOTH branches: an upload command that
    explicitly names a private IP (internal backup server) never fires, just
    like a connection to one."""
    if event.get("event_type") == "process_create":
        cmdline = event.get("command_line") or ""
        if not _UPLOAD_RE.search(cmdline):
            return None
        if _cmdline_has_private_ip(cmdline):
            return None
        signal = cmdline.strip()[:90]
    elif event.get("event_type") == "network_connection":
        if _is_private(event.get("dest_ip") or ""):
            return None
        signal = f"connection to {event.get('dest_ip')}:{event.get('dest_port') or '?'}"
    else:
        return None
    if not _archive_created_in_window(conn, run_id, cutoff):
        return None
    # related_ip is intentionally NOT set here: the same arc can surface as a
    # process_create (upload command) and a network_connection (the actual
    # push) — both share the pid, and the dedup key is (rule_id, pid, ip).
    # Dropping the ip makes both halves of one staging arc dedupe to a single
    # alert instead of double-firing.
    return Alert(
        run_id=run_id,
        rule_id="data-staging",
        rule_name="Data staging: archive then exfil",
        severity="malicious",
        triggered_at=datetime.now(timezone.utc),
        related_pid=event.get("pid"),
        related_ip=None,
        details=f"Archive created within {STAGING_WINDOW_SECONDS}s, then upload signal: {signal}",
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
# Rules 17–21 — the remaining ATT&CK tactics (14/14 coverage gate)
# ---------------------------------------------------------------------------


def check_network_scan(
    conn: sqlite3.Connection,
    run_id: str,
    event: dict,
    cutoff: datetime,
    min_targets: int = SCAN_DISTINCT_TARGETS,
) -> Optional[Alert]:
    """Reconnaissance (T1595) — a process sweeping many hosts on one port.

    One pid contacting >= `min_targets` distinct destinations on the same port
    inside the window is active scanning. Counting is per (pid, port) — a
    sweep across *multiple* ports stays under each port's threshold, a
    deliberate conservative FP gate (single-port sweeps are the loudest
    signal). related_ip/related_pid are left None so the whole sweep dedupes
    to a single alert per run (the details carry the pid + port)."""
    if event.get("event_type") != "network_connection":
        return None
    pid = event.get("pid")
    port = event.get("dest_port")
    if pid is None or port is None:
        return None
    rows = conn.execute(
        "SELECT DISTINCT dest_ip FROM events WHERE run_id = ? AND pid = ? AND dest_port = ? "
        "AND event_type = 'network_connection' AND dest_ip IS NOT NULL AND timestamp >= ?",
        (run_id, pid, port, cutoff.isoformat()),
    ).fetchall()
    targets = [r["dest_ip"] for r in rows]
    if len(targets) < min_targets:
        return None
    return Alert(
        run_id=run_id,
        rule_id="network-scan",
        rule_name="Active scanning (network reconnaissance)",
        severity="suspicious",
        triggered_at=datetime.now(timezone.utc),
        related_ip=None,
        related_pid=None,
        details=(
            f"{len(targets)} distinct hosts contacted on port {port} from pid {pid} "
            f"within {SCAN_WINDOW_SECONDS}s — active scanning"
        ),
    )


def check_toolchain_build(event: dict) -> Optional[Alert]:
    """Resource Development (T1587.001) — compiling into a writable location."""
    if event.get("event_type") != "process_create":
        return None
    platform = _platform(event)
    if platform not in ("linux", "macos"):
        return None
    cmdline = event.get("command_line") or ""
    if not _COMPILER_RE.search(cmdline):
        return None
    m = _TOOLCHAIN_OUT_RE.search(cmdline)
    if not m:
        return None
    out = m.group(1).strip("\"'")
    if not out.lower().startswith(_WRITABLE_COMPILE_DIRS):
        return None
    return _make_alert(
        event["run_id"], "toolchain-build",
        "Tool compiled from a writable location (capability development)",
        "suspicious", event,
        f"Compiler output to attacker-writable path: {out}",
    )


def check_document_dropper(event: dict, process_map: dict) -> Optional[Alert]:
    """Initial Access (T1566.002) — a document viewer spawned a script host.

    The attachment→code pivot: winword/soffice/outlook executing a shell or
    script interpreter. INTENTIONALLY independent of suspicious-parent-child
    (Execution, T1204.002): a macro attack fires both tactics, so the same
    pivot shows up as Initial Access + Execution (and the risk score sums both
    weights). Do not "fix" the overlap by suppressing one — each maps to a
    real stage of the intrusion."""
    if event.get("event_type") != "process_create":
        return None
    parent = process_map.get(event.get("ppid"))
    if not parent:
        return None
    parent_name = str(parent.get("process_name", "")).lower()
    child_name = str(event.get("process_name", "")).lower()
    if parent_name not in DOCUMENT_VIEWERS or child_name not in DROPPER_CHILDREN:
        return None
    return _make_alert(
        event["run_id"], "document-dropper",
        "Document viewer spawned a script interpreter (spearphishing)",
        "malicious", event,
        f"{parent['process_name']} spawned {event['process_name']} — macro/attachment drop pattern",
    )


def check_lateral_rdp_smb(event: dict) -> Optional[Alert]:
    """Lateral Movement (T1021.001) — outbound RDP (3389) / SMB (445).

    Highest-FP rule of the late tactics on a real host (corporate admins RDP
    to servers and SMB to file shares routinely). Low weight + the per-run
    IOC allowlist are the intended suppression path — allowlist a known file
    server and this goes quiet for that run."""
    if event.get("event_type") != "network_connection":
        return None
    port = event.get("dest_port")
    try:
        port = int(port) if port is not None else None
    except (TypeError, ValueError):
        return None
    if port not in LATERAL_PORTS:
        return None
    dest = event.get("dest_ip") or ""
    if dest in ("127.0.0.1", "::1"):
        return None  # local RDP/SMB (VM, file share) is not movement
    return _make_alert(
        event["run_id"], "lateral-rdp-smb",
        "Outbound RDP/SMB connection (lateral movement)",
        "suspicious", event,
        f"Outbound connection to {dest}:{port} — remote desktop / SMB (lateral movement)",
    )


# Collection (T1113) — screen-capture / clipboard-theft tool signatures. The
# Linux set keys on the process *name* (scrot/spectacle/maim/xwd) rather than
# the word "import" in a command line — `python3 -c "import os"` is normal and
# must never match.
CAPTURE_PATTERNS = {
    "windows": [
        (r"CopyFromScreen", "PowerShell screen capture (CopyFromScreen)"),
        (r"Get-Clipboard", "PowerShell clipboard read (Get-Clipboard)"),
        (r"nircmd[^\n]*screenshot", "nircmd screenshot capture"),
    ],
    "linux": [
        (r"ffmpeg[^\n]*x11grab", "ffmpeg X11 screen grab"),
        (r"\bxclip\s+-o\b|\bxsel\s+-b\b", "clipboard read (xclip/xsel)"),
    ],
    "macos": [
        (r"osascript[^\n]*clipboard", "osascript clipboard read"),
    ],
}
CAPTURE_PROCESS_NAMES = {
    "windows": {"snippingtool.exe"},
    "linux": {"scrot", "gnome-screenshot", "spectacle", "maim", "xwd"},
    "macos": {"screencapture"},
}


def check_screen_capture(event: dict) -> Optional[Alert]:
    """Collection (T1113) — screen-capture / clipboard-theft tools."""
    if event.get("event_type") != "process_create":
        return None
    platform = _platform(event)
    name = (event.get("process_name") or "").lower()
    if name in CAPTURE_PROCESS_NAMES.get(platform, set()):
        return _make_alert(
            event["run_id"], "screen-capture",
            "Screen capture / clipboard theft tool",
            "suspicious", event,
            f"Screen-capture tool invoked: {name}",
        )
    cmdline = event.get("command_line") or ""
    for pattern, description in CAPTURE_PATTERNS.get(platform, CAPTURE_PATTERNS["linux"]):
        if re.search(pattern, cmdline, re.IGNORECASE):
            return _make_alert(
                event["run_id"], "screen-capture",
                "Screen capture / clipboard theft tool",
                "suspicious", event,
                description,
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
    "ENUM_BURST_THRESHOLD": ("enumeration-burst", int, ENUM_BURST_THRESHOLD),
    "ENUM_WINDOW_SECONDS": ("enumeration-burst", int, ENUM_WINDOW_SECONDS),
    "STAGING_WINDOW_SECONDS": ("data-staging", int, STAGING_WINDOW_SECONDS),
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
# Analyst triage: rule suppressions + per-run IOC allowlists
# ---------------------------------------------------------------------------
# Suppression: rule_id + optional run_id (None = global). The run-detail page
# suppresses noisy rules for a single run; the Rules page can extend this to
# global scope. Loaded once per batch so edits apply to the next batch with no
# restart — same contract as rule tuning and enum patterns.
def load_suppressions(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT rule_id, run_id, reason FROM rule_suppressions").fetchall()
    return [dict(r) for r in rows]


def _rule_suppressed(suppressions: list[dict], rule_id: str, run_id: str) -> bool:
    for s in suppressions:
        if s["rule_id"] != rule_id:
            continue
        if s["run_id"] is None or s["run_id"] == run_id:
            return True
    return False


def load_run_allowlist(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT kind, value FROM run_allowlist WHERE run_id = ?", (run_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def allowlist_matches(kind: str, value: str, related_ip, details: str, sample_sha256: Optional[str] = None) -> bool:
    """Does one allowlist entry cover this alert?

    - `ip` matches the alert's related_ip exactly.
    - `file` / `registry` / `process` match a case-insensitive substring of
      the alert details, since that is where those alerts state exactly what
      was observed (e.g. "Write to autostart path: /home/u/.bashrc").
    - `hash` matches the run's uploaded-sample SHA-256 (alerts themselves
      never carry a hash, so the sample hash is the only hash in scope).
      Passed in from the run context; without it a hash entry never matches.
    """
    value = (value or "").strip()
    if not value:
        return False
    if kind == "ip":
        return bool(related_ip) and value.lower() == str(related_ip).lower()
    if kind == "hash":
        return bool(sample_sha256) and value.lower() == str(sample_sha256).lower()
    return value.lower() in (details or "").lower()


def load_run_sample_sha256(conn: sqlite3.Connection, run_id: str) -> Optional[str]:
    """The SHA-256 of the uploaded sample this run was detonated against, if
    any (runs link to samples by matching sample_name). Enables hash-kind
    allowlisting — a hash only has meaning in the sample-vault context."""
    row = conn.execute(
        "SELECT s.sha256 FROM samples s JOIN runs r ON r.sample_name = s.original_name "
        "WHERE r.run_id = ? ORDER BY s.created_at DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    return row["sha256"] if row else None


def _allowlist_blocks(allowlist: list[dict], alert: Alert, sample_sha256: Optional[str] = None) -> bool:
    for entry in allowlist:
        if allowlist_matches(entry["kind"], entry["value"], alert.related_ip, alert.details, sample_sha256):
            return True
    return False


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def evaluate_batch(conn: sqlite3.Connection, run_id: str, events: list[dict]) -> list[Alert]:
    """Run all rules against a batch of new events; persist and return alerts.

    Called from POST /ingest/batch. Keep it cheap — it runs on every event.
    Suppressions + allowlists are loaded once per batch, so an analyst's
    triage edit applies to the next ingested batch with no restart.
    """
    from ..models.event import insert_alert

    suppressions = load_suppressions(conn)
    allowlist = load_run_allowlist(conn, run_id)
    sample_sha256 = load_run_sample_sha256(conn, run_id)

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

    def fire(alert: Alert) -> bool:
        """Insert an alert unless suppressed, allowlisted, or already fired.

        Every insert in the engine flows through here, so analyst triage
        (rule suppression, IOC allowlist) gates every rule uniformly — new
        alerts, run-wide composites, everything.
        """
        if _rule_suppressed(suppressions, alert.rule_id, run_id):
            return False
        if _allowlist_blocks(allowlist, alert, sample_sha256):
            return False
        key = (alert.rule_id, alert.related_pid, alert.related_ip)
        related = alert.related_ip or (str(alert.related_pid) if alert.related_pid else None)
        if key in seen_related or _alert_exists(conn, run_id, alert.rule_id, related):
            return False
        seen_related.add(key)
        insert_alert(conn, alert)
        new_alerts.append(alert)
        return True

    # Separate windows: beaconing looks back 30 min, rename-burst 10 s
    # (docs/11). Thresholds are tunable via the rule editor (roadmap 2.3).
    t = _load_tunables(conn)
    beacon_cutoff = _window_cutoff(events, int(t["BEACON_WINDOW_MINUTES"]) * 60)
    burst_cutoff = _window_cutoff(events, int(t["RENAME_BURST_WINDOW_SECONDS"]))
    staging_cutoff = _window_cutoff(events, int(t["STAGING_WINDOW_SECONDS"]))
    scan_cutoff = _window_cutoff(events, SCAN_WINDOW_SECONDS)

    for event in events:
        candidates: list[Optional[Alert]] = [
            check_masquerading(event),
            check_parent_child(event, process_map),
            check_lolbin_abuse(event),
            check_registry_persistence(event),
            check_autostart_persistence(event),
            check_ssh_authorized_keys(event),
            check_suid_set(event),
            check_scheduled_task(event),
            check_credential_dump(event),
            check_suspicious_extension(event),
            check_shell_history_wipe(event),
            check_data_staging(conn, run_id, event, staging_cutoff),
            check_unusual_port(event),
            check_first_seen(conn, run_id, event, seen_names, process_map),
            check_toolchain_build(event),
            check_document_dropper(event, process_map),
            check_lateral_rdp_smb(event),
            check_screen_capture(event),
        ]
        for alert in candidates:
            if alert is not None:
                fire(alert)

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
            if alert:
                fire(alert)
        if event.get("event_type") == "file_write" and event.get("pid"):
            alert = check_rename_burst(
                conn,
                run_id,
                event,
                burst_cutoff,
                threshold=int(t["RENAME_BURST_THRESHOLD"]),
            )
            if alert:
                fire(alert)
        # Reconnaissance — active scanning over the whole window (once per run;
        # the run-wide section fires on the first qualifying network event).
        if event.get("event_type") == "network_connection":
            alert = check_network_scan(conn, run_id, event, scan_cutoff)
            if alert:
                fire(alert)

    # Discovery — enumeration burst over the whole window (once per batch;
    # deduped so it fires once per run). Patterns come from the operator-
    # editable per-platform table (load_enum_patterns) so Rules-page edits
    # apply live to the next batch.
    enum_cutoff = _window_cutoff(events, int(t["ENUM_WINDOW_SECONDS"]))
    enum_alert = check_enumeration_burst(
        conn, run_id, enum_cutoff,
        patterns=load_enum_patterns(conn),
        min_distinct=int(t["ENUM_BURST_THRESHOLD"]),
    )
    if enum_alert:
        fire(enum_alert)

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
        fire(chain_alert)

    return new_alerts
