"""Rule-based detection heuristics — the flagship feature.

Implements the rules from docs/11-DETECTION-LOGIC.md, extended by the
smarter-detection pass: per-OS tables (masquerading, parent-child, LOLBin,
persistence), the uncommon-port rule, and the composite attack-chain
correlation that fires when a single run touches 3+ kill-chain stages.

Every rule is explainable: `Alert.details` states exactly what was observed,
never a generic "suspicious activity detected". Runs on every ingested batch
so live monitoring is actually live.
"""

import ipaddress
import json
import os
import re
import sqlite3
import statistics

# ---------------------------------------------------------------------------
# Process-map cache (bounded per-batch reads on long sessions)
# ---------------------------------------------------------------------------
# The parent-child rule needs every process_create of a run, so the map is
# cached in memory per (db path, run) and extended incrementally per batch
# (only rows with id > last-seen are read). A lookback would break resolving
# an hours-old parent; incremental + LRU-capped keeps O(batch) per ingest
# with no semantic change. Evicted on run completion.
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from ..core.schema import Alert

_PROCESS_MAP_CACHE: OrderedDict[tuple[str, str], tuple[int, dict[int, dict]]] = OrderedDict()
_PROCESS_MAP_CACHE_MAX = 64


def _load_process_map(conn: sqlite3.Connection, run_id: str) -> tuple[dict[int, dict], int]:
    """The run's process map, incremental — returns (map, last_event_id)."""
    key = (_db_path(conn), run_id)
    cached = _PROCESS_MAP_CACHE.get(key)
    if cached is not None:
        _PROCESS_MAP_CACHE.move_to_end(key)
        last_id, process_map = cached
        new_rows = conn.execute(
            "SELECT id, pid, ppid, process_name, exe_path FROM events "
            "WHERE run_id = ? AND event_type = 'process_create' AND id > ?",
            (run_id, last_id),
        ).fetchall()
        max_id = last_id
        for r in new_rows:
            pid = r["pid"]
            if pid is not None and pid not in process_map:
                process_map[pid] = {"pid": pid, "ppid": r["ppid"], "process_name": _proc_name(dict(r)) or "unknown"}
            max_id = max(max_id, r["id"])
        _PROCESS_MAP_CACHE[key] = (max_id, process_map)
        return process_map, max_id

    # Warm start: a completed run's map was persisted (write-through at
    # completion) — restore it instead of re-scanning the whole run, then
    # catch up any rows added since (late collector batches).
    saved = conn.execute(
        "SELECT last_event_id, pids_json FROM run_process_maps WHERE run_id = ?", (run_id,)
    ).fetchone()
    if saved is not None:
        process_map: dict[int, dict] = {}
        max_id = 0
        try:
            saved_map = json.loads(saved["pids_json"])
            for pid_str, row in saved_map.items():
                process_map[int(pid_str)] = row
            max_id = int(saved["last_event_id"])
        except (ValueError, TypeError, KeyError):
            process_map = {}
            max_id = 0
        new_rows = conn.execute(
            "SELECT id, pid, ppid, process_name, exe_path FROM events "
            "WHERE run_id = ? AND event_type = 'process_create' AND id > ?",
            (run_id, max_id),
        ).fetchall()
        for r in new_rows:
            pid = r["pid"]
            if pid is not None and pid not in process_map:
                process_map[pid] = {"pid": pid, "ppid": r["ppid"], "process_name": _proc_name(dict(r)) or "unknown"}
            max_id = max(max_id, r["id"])
        _PROCESS_MAP_CACHE[key] = (max_id, process_map)
        return process_map, max_id

    process_rows = conn.execute(
        "SELECT id, pid, ppid, process_name, exe_path FROM events "
        "WHERE run_id = ? AND event_type = 'process_create'",
        (run_id,),
    ).fetchall()
    process_map: dict[int, dict] = {}
    max_id = 0
    for r in process_rows:
        pid = r["pid"]
        if pid is not None and pid not in process_map:
            process_map[pid] = {"pid": pid, "ppid": r["ppid"], "process_name": _proc_name(dict(r)) or "unknown"}
        max_id = max(max_id, r["id"])
    _PROCESS_MAP_CACHE[key] = (max_id, process_map)
    while len(_PROCESS_MAP_CACHE) > _PROCESS_MAP_CACHE_MAX:
        _PROCESS_MAP_CACHE.popitem(last=False)
    return process_map, max_id


def persist_run_process_map(conn: sqlite3.Connection, run_id: str) -> bool:
    """Write-through: persist the run's cached process map to the DB so a
    restarted backend restores it warm instead of re-scanning the whole run.
    Called on completion (before the in-memory eviction). Maps over a size
    cap are skipped — the full-scan fallback is still correct, just colder."""
    from datetime import datetime as _dt

    key = (_db_path(conn), run_id)
    cached = _PROCESS_MAP_CACHE.get(key)
    if cached is None or len(cached[1]) > 100_000:
        return False
    last_id, process_map = cached
    conn.execute(
        "INSERT INTO run_process_maps (run_id, last_event_id, pids_json, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(run_id) DO UPDATE SET last_event_id = excluded.last_event_id, "
        "pids_json = excluded.pids_json, updated_at = excluded.updated_at",
        (run_id, last_id, json.dumps({str(k): v for k, v in process_map.items()}),
         _dt.now(timezone.utc).isoformat()),
    )
    return True


def _db_path(conn: sqlite3.Connection) -> str:
    """The main database file path (cache key namespace per DB)."""
    row = conn.execute("PRAGMA database_list").fetchone()
    return row[2] if row else ""


def evict_run_process_map(run_id: str) -> None:
    """Drop a run's cached map — called on completion so finished sessions
    free their memory promptly (the LRU cap is the backstop)."""
    stale = [k for k in _PROCESS_MAP_CACHE if k[1] == run_id]
    for k in stale:
        del _PROCESS_MAP_CACHE[k]


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
# A mean interval BELOW this is a burst, not a beacon — parallel fetches /
# dev-stack polling land all connections within a fraction of a second and
# their ~0s intervals look perfectly "regular" to the variance gate (soak FP:
# 7 conns to one IP in 0.2s fired as beaconing). Real beacons are spaced.
BEACON_MIN_INTERVAL_SECONDS = 1.0

# Destinations that can never beacon: unspecified (0.0.0.0 — also the
# collector's IPv6-parse artifact), loopback, multicast, and link-local.
# Local dev traffic (frontend → backend on 127.0.0.1) is exactly the kind of
# regular-interval polling that false-positives the rule (soak FP: 5 conns to
# 127.0.0.1:8001 and 6 to 0.0.0.0:8001 fired).
_BEACON_EXCLUDED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),      # "this network" / parse artifact
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("::/128"),         # IPv6 unspecified
    ipaddress.ip_network("224.0.0.0/4"),    # multicast
    ipaddress.ip_network("169.254.0.0/16"), # link-local
]


def _is_routable_dest(ip: str) -> bool:
    """True for routable destinations only — excludes the non-routable / local
    ranges that fire the network rules on normal host traffic (soak-discovered:
    loopback dev-stack polling, 0.0.0.0 parse artifacts, etc.)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in _BEACON_EXCLUDED_NETS)

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

# Baseline anomalies (roadmap 4.x) — a host's own telemetry must reach this
# many learned observations before first-time processes/IPs start firing, so
# a brand-new host's initial traffic doesn't spam the triage queue.
BASELINE_MIN_EVENTS = 100

# Rules 17–21 close the remaining ATT&CK tactics (14/14 coverage gate).

# Reconnaissance (T1595) — one process sweeping many distinct hosts on a single
# port inside the window is active scanning, not routine use.
SCAN_WINDOW_SECONDS = 60
SCAN_DISTINCT_TARGETS = 5
# Fanning out across many distinct hosts on the WEB ports is browsing, not
# scanning — a page load hits a dozen CDN edges on 443 in seconds. The
# network-scan heuristic exempts them; the scan signal lives on non-web
# ports (22, 445, 3389, uncommon), where one pid hammering many hosts is
# unambiguous recon (Windows soak FP #1).
SCAN_EXEMPT_PORTS: tuple[int, ...] = (80, 443)

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
    "lateral-psexec-smb": "Lateral Movement",
    "lateral-winrm-wmi": "Lateral Movement",
    "lateral-smb-share": "Lateral Movement",
    "rdp-brute-force": "Lateral Movement",
    "log-service-stop": "Defense Evasion",
    "log-clearing": "Defense Evasion",
    "dns-tunneling": "Command and Control",
    "dns-long-label": "Command and Control",
    "dns-unusual-port": "Command and Control",
    "tls-sni-suspicious": "Command and Control",
    "doh-resolver-use": "Command and Control",
    "fanout-contact": "Command and Control",
    "fanout-recurring": "Command and Control",
}


def _platform(event: dict) -> str:
    """Events may predate platform-aware ingestion — default to windows."""
    return (event.get("platform") or "windows").lower()


def _proc_name(event: dict) -> str:
    """A process's identity, lowercased: `process_name` first, falling back to
    the basename of the resolved `exe_path` (auditd exe= / Sysmon Image).

    Both collectors now ship exe_path, and a bare basename is not a resolved
    path — but when process_name is MISSING (legacy rows, event types without
    Image), the exe_path basename is still a better identity than "unknown":
    it lets parent-child / dropper / first-seen matching resolve a parent
    that would otherwise silently never match."""
    name = event.get("process_name") or ""
    if not name:
        exe = (event.get("exe_path") or "").strip()
        name = os.path.basename(exe.replace("\\", "/")) if exe else ""
    return name.lower()


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
# On Arch/Ubuntu etc., /sbin/init (and /usr/sbin/init) are symlinks to
# systemd — pid 1's init execve is normal and must not trip the systemd path
# check (soak FP: "systemd running from an unexpected path — expected
# /usr/lib/systemd/systemd" fired on the real /sbin/init execve).
SYSTEMD_INIT_ALIASES = {"/sbin/init", "/usr/sbin/init"}


# Distros where /bin/sh → bash (Arch, etc.): the kernel comm is "bash" even
# though the argv[0] path is /usr/bin/sh. Without this, every benign `sh -c`
# wrapper (cron, systemd services, the package manager) reads as bash from an
# unexpected path (real-auditd soak FP: pid 89890's `/usr/bin/sh -c` fired).
_BASH_SH_ALIASES = {"/usr/bin/sh", "/bin/sh"}


def check_masquerading(event: dict) -> Alert | None:
    r"""A known system binary running from an unexpected absolute path.

    Only absolute-path invocations are judged: a bare `bash -c …` command line
    tells us nothing about where the binary actually lives, so it never fires.
    Windows drive-letter paths (C:\…) and POSIX absolute paths (/usr/bin/…) both
    qualify.

    When the event carries the kernel-resolved `exe_path` (auditd's `exe=`,
    stamped by the collector), that path is authoritative: symlinks are already
    followed, so `/usr/bin/sh -c …` on a sh→bash distro resolves to
    /usr/bin/bash and never fires, while a real masquerade (bash copied to
    /tmp/x) shows its true path and always does — argv[0] cannot spoof it.
    Events without `exe_path` fall back to the command line's first token.
    """
    platform = _platform(event)
    legit = LEGITIMATE_SYSTEM_PROCESSES.get(platform, {})
    name = _proc_name(event)
    expected_path = legit.get(name)
    if not expected_path:
        return None
    expected = expected_path.lower()

    exe_path = (event.get("exe_path") or "").strip()
    # exe_path is only authoritative when it is a RESOLVED path. A bare
    # basename ("explorer.exe") carries no path authority — Sysmon Image
    # can arrive basename-only (older configs, some providers), and treating
    # it as resolved would flag every system binary (Windows-soak FP:
    # "expected C:\Windows\explorer.exe, resolved explorer.exe").
    exe_is_abs = exe_path.startswith("/") or (
        len(exe_path) >= 3 and exe_path[1] == ":"
    )
    if exe_path and exe_is_abs:
        if expected in exe_path.lower():
            return None
        return _make_alert(
            event["run_id"], "masquerading", "Process masquerading as system binary",
            "malicious", event,
            f"{name} running from an unexpected path — expected {expected_path}, resolved {exe_path}",
        )

    cmdline = (event.get("command_line") or "").strip()
    if not cmdline:
        return None
    first_token = cmdline.split()[0].lower()
    is_abs = first_token.startswith("/") or (len(first_token) >= 3 and first_token[1] == ":")
    if not is_abs:
        return None
    if name == "systemd" and first_token in SYSTEMD_INIT_ALIASES:
        return None  # pid 1's init execve — systemd via the distro symlink
    if name == "bash" and first_token in _BASH_SH_ALIASES:
        return None  # sh→bash symlink distros (see _BASH_SH_ALIASES)
    if expected in cmdline.lower():
        return None
    return _make_alert(
        event["run_id"], "masquerading", "Process masquerading as system binary",
        "malicious", event,
        f"{name} running from an unexpected path — expected {expected_path}",
    )


# ---------------------------------------------------------------------------
# Rule 2 — Suspicious Parent-Child
# ---------------------------------------------------------------------------
def check_parent_child(event: dict, process_map: dict) -> Alert | None:
    if event.get("event_type") != "process_create":
        return None
    parent = process_map.get(event.get("ppid"))
    if not parent:
        return None
    pair = (_proc_name(parent), _proc_name(event))
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
def check_lolbin_abuse(event: dict) -> Alert | None:
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
def check_unusual_port(event: dict) -> Alert | None:
    """Connection to a port commonly used by C2 frameworks / reverse shells.

    A plant that hasn't beaconed yet still shows up as a quiet connection to
    Metasploit's 4444, an IRC bot port, a bind-shell port, etc. — a cheap,
    low-FP early signal that complements beaconing.
    """
    if event.get("event_type") != "network_connection":
        return None
    if not _is_routable_dest(event.get("dest_ip") or ""):
        # A local service on a C2-ish port (127.0.0.1:9001 dev listener) is
        # not a plant — soak-discovered FP. Only routable destinations count.
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
def _parse_ts(value) -> datetime | None:
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


def _recent_connection_times(
    conn: sqlite3.Connection,
    run_id: str,
    dest_ip: str,
    cutoff: datetime,
    dest_port: int | None = None,
) -> list[datetime]:
    """Connection timestamps to one destination CHANNEL (ip + port).

    Grouping by ip alone was a real-feed FP: a host's DNS-on-53 + DoH-on-443
    + one-off ports to the same resolver IP all aggregated into one "beacon".
    A C2 channel is one ip:port tuple — the port must participate.
    """
    if dest_port is None:
        rows = conn.execute(
            "SELECT timestamp FROM events WHERE run_id = ? AND dest_ip = ? AND timestamp >= ? ORDER BY timestamp ASC",
            (run_id, dest_ip, cutoff.isoformat()),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT timestamp FROM events WHERE run_id = ? AND dest_ip = ? AND dest_port = ? AND timestamp >= ? "
            "ORDER BY timestamp ASC",
            (run_id, dest_ip, dest_port, cutoff.isoformat()),
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
    min_interval: float = BEACON_MIN_INTERVAL_SECONDS,
    dest_port: int | None = None,
) -> Alert | None:
    """Regular low-variance connections to one destination CHANNEL.

    Two protocol-level exclusions keep real hosts quiet (both soak-discovered
    on the live auditd feed):
      * port 53 — DNS. Every machine queries its resolver at regular intervals;
        covert DNS channels are the DNS-tunnel rules' job, not beaconing's.
      * public DoH resolvers on 443 — dns.google / cloudflare-dns.com are
        background browser noise with exactly beacon-like cadence. A beacon to
        a resolver on a NON-DNS port (e.g. 1.1.1.1:4444) still fires.
    """
    if not _is_routable_dest(dest_ip):
        return None
    if dest_port == 53:
        return None  # DNS protocol — routine resolver cadence, covered by DNS-tunnel rules
    if dest_ip in DOH_RESOLVERS and dest_port == 443:
        return None  # public DoH resolver — legitimate background cadence (soak FP)
    timestamps = _recent_connection_times(conn, run_id, dest_ip, cutoff, dest_port)
    if len(timestamps) < min_conn:
        return None
    intervals = [(t2 - t1).total_seconds() for t1, t2 in zip(timestamps, timestamps[1:])]
    if len(intervals) < 2:
        return None
    if statistics.pstdev(intervals) >= variance:
        return None
    if statistics.mean(intervals) < min_interval:
        # A burst (all connections within a fraction of a second) reads as
        # perfectly regular to the variance gate — but it isn't a beacon.
        return None
    port_suffix = f":{dest_port}" if dest_port is not None else ""
    return Alert(
        run_id=run_id,
        rule_id="beaconing",
        rule_name="C2-style beaconing",
        severity="suspicious",
        triggered_at=datetime.now(timezone.utc),
        related_ip=dest_ip,
        details=(
            f"{len(timestamps)} connections to {dest_ip}{port_suffix} at regular "
            f"~{int(statistics.mean(intervals))}s intervals (std-dev "
            f"{statistics.pstdev(intervals):.1f}s)"
        ),
    )


# ---------------------------------------------------------------------------
# Rule 5 — Persistence (registry Run keys on Windows, autostart files on
# Linux; roadmap 1.2)
# ---------------------------------------------------------------------------
def check_registry_persistence(event: dict) -> Alert | None:
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


def check_autostart_persistence(event: dict) -> Alert | None:
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
def check_first_seen(conn: sqlite3.Connection, run_id: str, event: dict, seen_names: set, process_map: dict) -> Alert | None:
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
    name = _proc_name(event)
    if not name:
        return None
    # Novelty alone is too noisy on a live host — require a script-host parent.
    parent = process_map.get(event.get("ppid"))
    if not parent or _proc_name(parent) not in FIRST_SEEN_SCRIPT_HOSTS:
        return None
    if name in seen_names:
        return None
    seen_names.add(name)
    row = conn.execute(
        "SELECT 1 FROM events WHERE LOWER(process_name) = ? AND run_id != ? LIMIT 1",
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
def check_ssh_authorized_keys(event: dict) -> Alert | None:
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


def check_suid_set(event: dict) -> Alert | None:
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


def check_scheduled_task(event: dict) -> Alert | None:
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
            # Windows Task Scheduler (svchost.exe) maintains its own TaskCache
            # continuously — task state updates, trigger bookkeeping, tree
            # rebuilds — so its writes into that subtree are routine
            # maintenance, not persistence (Windows soak FP #2). Only a
            # NON-system process planting a task definition
            # (TaskCache\Tasks\{guid} / TaskCache\Tree\{name}) is the signal
            # worth surfacing; a bare root write defines no task.
            proc = _proc_name(event)
            if proc == "svchost.exe":
                return None
            if "\\tasks" in key or "\\tree" in key:
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


def check_credential_dump(event: dict) -> Alert | None:
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


def check_suspicious_extension(event: dict) -> Alert | None:
    """A benign-looking extension *followed by* an executable one — the classic
    `invoice.pdf.exe` masquerade. Checks both process names and written file
    paths, cross-platform. The checked value is chosen by event type, NOT a
    `process_name or file_path` fallback: a real Sysmon file-write event
    carries the *writer's* process name (e.g. cmd.exe) alongside the written
    path, and taking process_name first would silently skip every file write."""
    if event.get("event_type") == "process_create":
        # process_name, falling back to the resolved exe_path basename — a
        # double-extension masquerade on the Image itself (renamed binary)
        # is still a masquerade even when the row is nameless.
        value = event.get("process_name") or os.path.basename(
            (event.get("exe_path") or "").strip().replace("\\", "/")
        ) or ""
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


def check_shell_history_wipe(event: dict) -> Alert | None:
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
    patterns: dict[str, list[tuple[str, str]]] | None = None,
    min_distinct: int = ENUM_BURST_THRESHOLD,
) -> Alert | None:
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


def check_data_staging(conn: sqlite3.Connection, run_id: str, event: dict, cutoff: datetime) -> Alert | None:
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
) -> Alert | None:
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
) -> Alert | None:
    """Reconnaissance (T1595) — a process sweeping many hosts on one port.

    One pid contacting >= `min_targets` distinct destinations on the same port
    inside the window is active scanning. Counting is per (pid, port) — a
    sweep across *multiple* ports stays under each port's threshold, a
    deliberate conservative FP gate (single-port sweeps are the loudest
    signal). related_pid carries the scanning process so EACH distinct
    scanning (pid, port) surfaces its own alert (deduped per pid, storm-capped
    at NETWORK_SCAN_MAX_ALERTS per run) — two pids sweeping at once are both
    seen, not collapsed into the first."""
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
    # Web-browsing fan-out exemption (Windows soak FP #1): many distinct
    # hosts on the web ports (80/443) is normal traffic — a page load fans
    # out across CDNs — not a sweep. The scan signal lives on non-web ports.
    if port in SCAN_EXEMPT_PORTS:
        return None
    # Reputation-clean exemption: when every distinct target is cached with a
    # 'clean' reputation the pid reached known-good infrastructure (browsing /
    # a clean API fan-out), not swept unknown targets. Positive evidence only —
    # uncached/unknown targets still count toward the threshold, so a sweep of
    # unknown infra keeps firing.
    if all(_target_is_clean(conn, ip) for ip in targets):
        return None
    return Alert(
        run_id=run_id,
        rule_id="network-scan",
        rule_name="Active scanning (network reconnaissance)",
        severity="suspicious",
        triggered_at=datetime.now(timezone.utc),
        related_ip=None,
        related_pid=pid,
        details=(
            f"{len(targets)} distinct hosts contacted on port {port} from pid {pid} "
            f"within {SCAN_WINDOW_SECONDS}s — active scanning"
        ),
    )


def _target_is_clean(conn: sqlite3.Connection, ip: str) -> bool:
    """True only with positive evidence: the IP is cached with a 'clean'
    reputation. Uncached / unknown are NOT clean — a scan of unknown targets
    is still a scan, so the exemption never relies on absence of data."""
    row = conn.execute(
        "SELECT reputation FROM enrichment_cache WHERE ip = ?", (ip,)
    ).fetchone()
    return row is not None and row["reputation"] == "clean"


def check_toolchain_build(event: dict) -> Alert | None:
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


def check_document_dropper(event: dict, process_map: dict) -> Alert | None:
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
    parent_name = _proc_name(parent)
    child_name = _proc_name(event)
    if parent_name not in DOCUMENT_VIEWERS or child_name not in DROPPER_CHILDREN:
        return None
    return _make_alert(
        event["run_id"], "document-dropper",
        "Document viewer spawned a script interpreter (spearphishing)",
        "malicious", event,
        f"{parent['process_name']} spawned {event['process_name']} — macro/attachment drop pattern",
    )


def check_lateral_rdp_smb(event: dict) -> Alert | None:
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


def check_screen_capture(event: dict) -> Alert | None:
    """Collection (T1113) — screen-capture / clipboard-theft tools."""
    if event.get("event_type") != "process_create":
        return None
    platform = _platform(event)
    name = _proc_name(event)
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
# Lateral Movement depth (T1021) — remote-admin tooling and SMB share access,
# complementing the port-level lateral-rdp-smb rule. These key on the remote-
# admin *commands* (PsExec, WinRM/WMI, share enumeration) rather than the
# transport ports, so they fire even when traffic is localhost-proxied.
# ---------------------------------------------------------------------------
# PsExec / SMB-admin: mounting admin$ is the classic PsExec precondition;
# sc.exe / reg / wmic against a remote host are remote-admin in their own
# right (T1021.002).
PSEXEC_SMB_PATTERNS = {
    "windows": [
        (r"\bpsexec\b", "PsExec remote execution"),
        (r"net\s+use\b[^\n]*?\\[^\s]+?\\admin\$", "SMB admin$ share mounted (PsExec precondition)"),
        (r"sc\s+\\[^\s]+\s+create", "Remote service creation (sc \\\\host create)"),
        (r"reg\s+add\s+\\[^\s]+", "Remote registry write (reg add \\\\host)"),
    ],
    "linux": [],
    "macos": [],
}
# WinRM / WMI remote execution (T1021.006).
WINRM_WMI_PATTERNS = {
    "windows": [
        (r"\bwinrs\b", "WinRS remote shell"),
        (r"Invoke-Command\s+-ComputerName", "PowerShell remoting (Invoke-Command -ComputerName)"),
        (r"Enter-PSSession\b", "Interactive PowerShell remoting session"),
        (r"Invoke-WmiMethod\b|Invoke-CimMethod\b", "WMI/CIM remote method invocation"),
        (r"wmic\s+/node:", "WMI remote execution (wmic /node:)"),
    ],
    "linux": [],
    "macos": [],
}
# SMB share enumeration — scanning what a remote host exposes before mounting.
SMB_SHARE_PATTERNS = {
    "windows": [
        (r"net\s+view\b", "SMB share enumeration (net view)"),
        (r"dir\s+\\[^\s]+\\", "Directory listing of a remote SMB share"),
    ],
    "linux": [],
    "macos": [],
}
RDP_BRUTE_WINDOW_SECONDS = 60
RDP_BRUTE_MIN_CONNECTIONS = 4


def _command_match(patterns: dict[str, list[tuple[str, str]]], event: dict):
    """Return the first (rule_id, description) matching a command line."""
    if event.get("event_type") != "process_create":
        return None
    cmdline = event.get("command_line") or ""
    if not cmdline:
        return None
    for pattern, description in patterns.get(_platform(event), []):
        if re.search(pattern, cmdline, re.IGNORECASE):
            return description
    return None


def check_lateral_psexec_smb(event: dict) -> Alert | None:
    """Lateral Movement (T1021.002) — PsExec / SMB-admin remote tooling."""
    desc = _command_match(PSEXEC_SMB_PATTERNS, event)
    if desc is None:
        return None
    return _make_alert(
        event["run_id"], "lateral-psexec-smb",
        "PsExec / SMB-admin remote execution",
        "suspicious", event, desc,
    )


def check_lateral_winrm_wmi(event: dict) -> Alert | None:
    """Lateral Movement (T1021.006) — WinRM / WMI remote execution."""
    desc = _command_match(WINRM_WMI_PATTERNS, event)
    if desc is None:
        return None
    return _make_alert(
        event["run_id"], "lateral-winrm-wmi",
        "WinRM / WMI remote execution",
        "suspicious", event, desc,
    )


def check_lateral_smb_share(event: dict) -> Alert | None:
    """Lateral Movement (T1021.001) — remote SMB share enumeration."""
    desc = _command_match(SMB_SHARE_PATTERNS, event)
    if desc is None:
        return None
    return _make_alert(
        event["run_id"], "lateral-smb-share",
        "SMB share enumeration (lateral movement)",
        "suspicious", event, desc,
    )


def check_rdp_brute_force(
    conn: sqlite3.Connection,
    run_id: str,
    event: dict,
    cutoff: datetime,
    min_connections: int = RDP_BRUTE_MIN_CONNECTIONS,
) -> Alert | None:
    """Lateral Movement (T1021.001) — RDP connection burst (spray/brute).

    A single process slamming port 3389 repeatedly inside the window is the
    client-side signature of an RDP spray (credential brute-force or
    pass-the-hash against a fleet). Once per run via the related-ip dedup.
    The burst threshold is tunable from the Rules page.
    """
    if event.get("event_type") != "network_connection":
        return None
    try:
        port = int(event.get("dest_port") or 0)
    except (TypeError, ValueError):
        return None
    if port != 3389:
        return None
    pid = event.get("pid") or event.get("ppid")
    if pid is None:
        return None
    rows = conn.execute(
        "SELECT 1 FROM events WHERE run_id = ? AND event_type = 'network_connection' "
        "AND dest_port = 3389 AND pid = ? AND timestamp >= ?",
        (run_id, pid, cutoff.isoformat()),
    ).fetchall()
    if len(rows) >= min_connections:
        return _make_alert(
            run_id, "rdp-brute-force",
            "RDP connection burst (brute-force / spray)",
            "suspicious", event,
            f"Process {pid} made {len(rows)}+ RDP (3389) connections inside {RDP_BRUTE_WINDOW_SECONDS}s",
        )
    return None


# ---------------------------------------------------------------------------
# Defense Evasion depth (T1070) — anti-forensics beyond shell-history-wipe:
# the collector/logging service being stopped, or log stores being purged.
# A live monitor that gets silenced is the quietest attack of all.
# ---------------------------------------------------------------------------
LOG_SERVICE_STOP_PATTERNS = {
    "linux": [
        (r"systemctl\s+(stop|disable)\s+(auditd|rsyslog|syslog)", "auditd/rsyslog service stopped/disabled"),
        (r"auditctl\s+-e\s*0", "auditd disabled (auditctl -e 0)"),
        (r"service\s+(auditd|rsyslog)\s+stop", "auditd/rsyslog service stopped (sysvinit)"),
    ],
    "windows": [
        (r"sc\s+stop\s+(WinEventLog|EventLog)|sc\s+config\s+(WinEventLog|EventLog)\s+start=\s*disabled", "Windows Event Log service stopped/disabled"),
    ],
    "macos": [],
}
LOG_CLEAR_PATTERNS = {
    "windows": [
        (r"wevtutil\s+(cl|clear-log)\b", "Windows event log cleared (wevtutil)"),
        (r"Clear-EventLog\b|Remove-EventLog\b", "PowerShell event-log purge"),
    ],
    "linux": [
        (r"journalctl\s+--vacuum", "journal vacuumed (journalctl --vacuum)"),
        (r"rm\s+(-rf\s+)?/var/log/journal", "journal store deleted"),
        (r"find\s+/var/log\b[^\n]*-delete", "log files mass-deleted (find -delete)"),
    ],
    "macos": [],
}


def load_log_patterns(conn: sqlite3.Connection) -> dict[str, dict[str, list[tuple[str, str]]]]:
    """Effective log anti-forensics pattern tables (DB override or defaults).

    Mirrors load_enum_patterns: the Rules page (GET/PUT /rules/log-patterns)
    lets operators add or remove the per-platform signatures behind
    log-service-stop and log-clearing without touching code, and this is the
    single read path so the live engine always sees the latest edit. Returns
    {"service_stop": {platform: [(regex, label), …]}, "log_clear": {…}};
    a missing/invalid stored value falls back to the module defaults.
    """
    defaults = {"service_stop": LOG_SERVICE_STOP_PATTERNS, "log_clear": LOG_CLEAR_PATTERNS}
    try:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = 'log_patterns'"
        ).fetchone()
        if row is None:
            return defaults
        stored = json.loads(row["value"])
        if not isinstance(stored, dict):
            return defaults
        out: dict[str, dict[str, list[tuple[str, str]]]] = {}
        for kind, base in defaults.items():
            kind_rows = stored.get(kind)
            if not isinstance(kind_rows, dict):
                out[kind] = base
                continue
            per = {}
            for platform, plat_rows in base.items():
                rows = kind_rows.get(platform)
                if not isinstance(rows, list):
                    per[platform] = plat_rows
                    continue
                cleaned = []
                for item in rows:
                    if not isinstance(item, dict):
                        continue
                    pattern = (item.get("pattern") or "").strip()
                    label = (item.get("label") or "").strip()
                    if pattern and label:
                        cleaned.append((pattern, label))
                per[platform] = cleaned if cleaned else plat_rows
            out[kind] = per
        return out
    except (ValueError, TypeError):
        return defaults


def check_log_service_stop(
    event: dict, patterns: dict[str, list[tuple[str, str]]] | None = None
) -> Alert | None:
    """Defense Evasion (T1070.001) — the logging stack itself being silenced."""
    if patterns is None:
        patterns = LOG_SERVICE_STOP_PATTERNS
    desc = _command_match(patterns, event)
    if desc is None:
        return None
    return _make_alert(
        event["run_id"], "log-service-stop",
        "Logging service stopped/disabled (anti-forensics)",
        "malicious", event, desc,
    )


def check_log_clearing(
    event: dict, patterns: dict[str, list[tuple[str, str]]] | None = None
) -> Alert | None:
    """Defense Evasion (T1070.001) — log stores being purged."""
    if patterns is None:
        patterns = LOG_CLEAR_PATTERNS
    desc = _command_match(patterns, event)
    if desc is None:
        return None
    return _make_alert(
        event["run_id"], "log-clearing",
        "Event/journal logs purged (anti-forensics)",
        "malicious", event, desc,
    )


# ---------------------------------------------------------------------------
# Command and Control depth (T1071.004 / T1568) — DNS as a covert channel.
# Sysmon (Event ID 22) and DNS-aware collectors stamp the resolved `query` on
# network_connection events; these rules read that field. Tunneling uses a
# high-entropy/long-label *burst* under one base name; a single absurd label
# is the DGA/tunnel tell; a query to a non-53 port is a covert DNS channel.
# ---------------------------------------------------------------------------
DNS_PORT = 53
DNS_TUNNEL_WINDOW_SECONDS = 300
DNS_TUNNEL_MIN_DISTINCT = 6
DNS_LONG_LABEL_LEN = 24
DNS_LONG_LABEL_ENTROPY = 4.0
DNS_LABEL_ENTROPY = 3.0
DNS_LABEL_LEN = 16


def _label_entropy(label: str) -> float:
    """Shannon entropy per char of a DNS label (lowercase, alnum+hyphen)."""
    if not label:
        return 0.0
    counts: dict[str, int] = {}
    for ch in label.lower():
        counts[ch] = counts.get(ch, 0) + 1
    n = len(label)
    import math
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _dns_label_suspicious(label: str, entropy_min: float, length_min: int) -> bool:
    return len(label) >= length_min or _label_entropy(label) >= entropy_min


def check_dns_tunneling(
    conn: sqlite3.Connection,
    run_id: str,
    cutoff: datetime,
    min_distinct: int = DNS_TUNNEL_MIN_DISTINCT,
    label_entropy: float = DNS_LABEL_ENTROPY,
    label_len: int = DNS_LABEL_LEN,
) -> Alert | None:
    """C2 (T1071.004) — a burst of distinct suspicious DNS labels.

    Run-wide over the window: distinct query labels that are long or
    high-entropy (the classic `xxxxxxxx...base.example.com` tunnel shape).
    Fires once per run when the count clears the threshold. Thresholds come
    from the rule-tuning table (Rules page) — the defaults here are the
    stock values, so an unedited store behaves identically.
    """
    rows = conn.execute(
        "SELECT query FROM events WHERE run_id = ? AND event_type = 'network_connection' "
        "AND query IS NOT NULL AND query != '' AND timestamp >= ?",
        (run_id, cutoff.isoformat()),
    ).fetchall()
    labels: set[str] = set()
    for r in rows:
        q = (r["query"] or "").strip().lower().rstrip(".")
        if not q:
            continue
        parts = [p for p in q.split(".") if p]
        if len(parts) < 2:
            continue
        for label in parts[:-1]:  # skip the base domain label
            if _dns_label_suspicious(label, label_entropy, label_len):
                labels.add(label)
                break
    if len(labels) >= min_distinct:
        return Alert(
            run_id=run_id,
            rule_id="dns-tunneling",
            rule_name="DNS tunneling (suspicious label burst)",
            severity="suspicious",
            triggered_at=datetime.now(timezone.utc),
            related_ip=None,
            related_pid=None,
            details=(
                f"{len(labels)} distinct long/high-entropy DNS labels inside "
                f"{DNS_TUNNEL_WINDOW_SECONDS}s — classic DNS-tunnel shape"
            ),
        )
    return None


def check_dns_long_label(
    event: dict,
    long_len: int = DNS_LONG_LABEL_LEN,
    long_entropy: float = DNS_LONG_LABEL_ENTROPY,
) -> Alert | None:
    """C2 (T1568.002) — a single absurd DNS label (DGA / one-shot tunnel).

    Length/entropy thresholds are tunable from the Rules page; the defaults
    here are the stock values.
    """
    if event.get("event_type") != "network_connection":
        return None
    q = (event.get("query") or "").strip().lower().rstrip(".")
    if not q:
        return None
    parts = [p for p in q.split(".") if p]
    if len(parts) < 2:
        return None
    for label in parts[:-1]:
        if _dns_label_suspicious(label, long_entropy, long_len):
            return _make_alert(
                event["run_id"], "dns-long-label",
                "Long / high-entropy DNS query (DGA or tunneling)",
                "suspicious", event,
                f"DNS query with suspicious label: {q}",
            )
    return None


def check_dns_unusual_port(event: dict) -> Alert | None:
    """C2 (T1071.004) — DNS on a non-standard port (covert channel)."""
    if event.get("event_type") != "network_connection":
        return None
    q = event.get("query")
    if not q:
        return None
    try:
        port = int(event.get("dest_port") or 0)
    except (TypeError, ValueError):
        return None
    if port != DNS_PORT and _is_routable_dest(event.get("dest_ip") or ""):
        return _make_alert(
            event["run_id"], "dns-unusual-port",
            "DNS query on a non-standard port",
            "suspicious", event,
            f"DNS query {q} to {event.get('dest_ip')}:{port} — covert DNS channel",
        )
    return None


# ---------------------------------------------------------------------------
# Network behavior depth (T1071) — TLS-SNI tracking, DNS-over-HTTPS, and
# same-destination fan-out. These read the `tls_sni` field Sysmon stamps on
# Event ID 3 (DestinationHostname) plus the connection tuple itself.
# ---------------------------------------------------------------------------
# Known public DoH resolvers (IP → provider) — the doh-resolver-use gate.
# v6 keys are the COMPRESSED canonical form, matching what the collector
# stores (2001:4860:4860::8888 etc.) — the real-feed re-measurement showed
# the v6 Google resolver's regular 443 cadence firing beaconing because only
# the v4 forms were exempted.
DOH_RESOLVERS = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google",
    "8.8.4.4": "Google",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "76.76.2.2": "NextDNS",
    "76.76.10.2": "NextDNS",
    "2001:4860:4860::8888": "Google",
    "2001:4860:4860::8844": "Google",
    "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare",
    "2620:fe::fe": "Quad9",
    "2620:fe::9": "Quad9",
}
# Script hosts / LOLBins malware uses to exfil over HTTPS (and that a normal
# host rarely points at a DoH resolver) — the low-FP gate for doh-resolver-use.
DOH_SCRIPT_HOSTS = {
    "powershell.exe", "pwsh", "curl", "wget", "python", "python3", "perl",
    "ruby", "node", "certutil.exe", "mshta.exe", "bitsadmin.exe",
}
FANOUT_WINDOW_SECONDS = 300
FANOUT_MIN_PROCESSES = 5
# Recurring fan-out — the same destination crossing the fan-out threshold in
# >= this many distinct FANOUT_WINDOW_SECONDS buckets over the run's life is a
# long-running coordinated plant (it keeps re-fanning out as new processes
# spawn), not a one-off burst. Tunable from the Rules page.
FANOUT_RECUR_MIN_WINDOWS = 3
# The recurrence scan only looks back this far (2h by default) — bounded so a
# very long live session doesn't re-scan its whole event history on every
# ingest batch. 2h of 300s windows is 24 buckets; the 3-window threshold is
# comfortably inside it.
FANOUT_RECUR_LOOKBACK_SECONDS = 7200

# Storm guard — per-rule per-run alert caps. A long live session on a
# busy host legitimately produces a novel process per minute; without a
# cap, first-seen/enumeration/network-scan/beaconing/fan-out would bury
# the triage queue in near-duplicates. EVERY rule gets ALERT_CAP_DEFAULT;
# the burst-prone ones override it lower. The cap holds the most
# representative findings and records what was suppressed on the run
# (suppressed_alerts).
ALERT_CAP_DEFAULT = 25
FIRST_SEEN_MAX_ALERTS = 20
ENUM_BURST_MAX_ALERTS = 10
NETWORK_SCAN_MAX_ALERTS = 10
BEACONING_MAX_ALERTS = 15
FANOUT_MAX_ALERTS = 10
_IP_LITERAL_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def check_tls_sni_suspicious(event: dict) -> Alert | None:
    """C2 (T1071.001) — TLS SNI that no legitimate client sends.

    RFC 6066 forbids IP-literal SNIs, so an SNI that IS an IP is a covert
    channel / raw-tunnel tell; a long or high-entropy SNI label is the TLS
    cousin of the DNS DGA smell. Reads Sysmon's DestinationHostname.
    """
    if event.get("event_type") != "network_connection":
        return None
    sni = (event.get("tls_sni") or "").strip().lower()
    if not sni:
        return None
    if _IP_LITERAL_RE.fullmatch(sni):
        return _make_alert(
            event["run_id"], "tls-sni-suspicious",
            "TLS handshake with IP-literal SNI",
            "suspicious", event,
            f"TLS SNI is a raw IP ({sni}) — RFC 6066 forbids IP-literal SNIs (tunnel/C2 tell)",
        )
    parts = [p for p in sni.split(".") if p]
    for label in parts[:-1]:
        if _dns_label_suspicious(label, DNS_LONG_LABEL_ENTROPY, DNS_LONG_LABEL_LEN):
            return _make_alert(
                event["run_id"], "tls-sni-suspicious",
                "Long / high-entropy TLS SNI (DGA or tunneling)",
                "suspicious", event,
                f"TLS SNI with suspicious label: {sni}",
            )
    return None


def check_doh_resolver_use(event: dict) -> Alert | None:
    """C2 (T1071.004) — a script host / LOLBin talking to a known DoH resolver.

    DoH itself is normal (browsers use it); a *script host* pointed at a
    public DoH resolver is malware's way of dodging DNS inspection while
    exfiltrating or resolving C2. The script-host gate keeps it low-FP.
    """
    if event.get("event_type") != "network_connection":
        return None
    ip = event.get("dest_ip") or ""
    try:
        port = int(event.get("dest_port") or 0)
    except (TypeError, ValueError):
        return None
    if port != 443 or ip not in DOH_RESOLVERS:
        return None
    name = _proc_name(event)
    if name in DOH_SCRIPT_HOSTS:
        return _make_alert(
            event["run_id"], "doh-resolver-use",
            "DNS-over-HTTPS from a script host",
            "suspicious", event,
            f"{name} connected to {DOH_RESOLVERS[ip]} DoH resolver {ip}:443 — DoH used to dodge DNS inspection",
        )
    return None


def check_fanout_contact(
    conn: sqlite3.Connection,
    run_id: str,
    cutoff: datetime,
    min_processes: int = FANOUT_MIN_PROCESSES,
) -> list[Alert]:
    """C2 (T1071.001) — many distinct processes contacting ONE destination.

    A coordinated plant fans out: several independent processes all reaching
    the same routable IP inside the window. Returns an alert for EVERY
    qualifying destination IP in the batch (not just the first), so a
    multi-IP fan-out is fully surfaced; per-run dedup via related_ip + the
    storm cap keep a long session from flooding. Known DoH resolvers are
    excluded — they already have their own rule and legitimately see
    multi-process traffic. The fan-out threshold is tunable from the Rules
    page.
    """
    rows = conn.execute(
        "SELECT dest_ip, COUNT(DISTINCT pid) AS pids FROM events "
        "WHERE run_id = ? AND event_type = 'network_connection' "
        "AND pid IS NOT NULL AND dest_ip IS NOT NULL AND timestamp >= ? "
        "GROUP BY dest_ip HAVING pids >= ?",
        (run_id, cutoff.isoformat(), min_processes),
    ).fetchall()
    alerts: list[Alert] = []
    for row in rows:
        ip = row["dest_ip"]
        if not _is_routable_dest(ip) or ip in DOH_RESOLVERS:
            continue
        alerts.append(
            Alert(
                run_id=run_id,
                rule_id="fanout-contact",
                rule_name="Coordinated contact with one destination",
                severity="suspicious",
                triggered_at=datetime.now(timezone.utc),
                related_ip=ip,
                related_pid=None,
                details=(
                    f"{row['pids']} distinct processes contacted {ip} inside "
                    f"{FANOUT_WINDOW_SECONDS}s — coordinated fan-out to one destination"
                ),
            )
        )
    return alerts


def check_fanout_recurring(
    conn: sqlite3.Connection,
    run_id: str,
    min_processes: int = FANOUT_MIN_PROCESSES,
    min_windows: int = FANOUT_RECUR_MIN_WINDOWS,
    cutoff: datetime | None = None,
) -> list[Alert]:
    """C2 (T1071.001) — the SAME destination fanning out across MANY windows.

    fanout-contact flags a destination that crossed the threshold inside one
    FANOUT_WINDOW_SECONDS window — a one-off burst. A long-running coordinated
    plant keeps re-fanning out: as the session goes on, new processes keep
    contacting the same C2, so the destination crosses the fan-out threshold
    in multiple DISTINCT windows over the run's life. This returns an alert
    per destination that qualifies in >= `min_windows` separate windows (a
    persistence signal, not a burst). Deduped per IP per run; DoH resolvers
    excluded. The window size matches fanout-contact so the two read as one
    story: burst first, then "and it kept doing it".

    `cutoff` bounds the scan to recent windows (the caller anchors it to the
    batch's newest event minus FANOUT_RECUR_LOOKBACK_SECONDS) so a very long
    live session doesn't re-read its whole event history on every ingest
    batch — the (run_id, event_type) index narrows the read, the timestamp
    filter bounds it. None scans the full run.
    """
    if cutoff is None:
        rows = conn.execute(
            "SELECT dest_ip, timestamp, pid FROM events "
            "WHERE run_id = ? AND event_type = 'network_connection' "
            "AND pid IS NOT NULL AND dest_ip IS NOT NULL",
            (run_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT dest_ip, timestamp, pid FROM events "
            "WHERE run_id = ? AND event_type = 'network_connection' "
            "AND pid IS NOT NULL AND dest_ip IS NOT NULL AND timestamp >= ?",
            (run_id, cutoff.isoformat()),
        ).fetchall()
    # ip -> {window bucket -> set of distinct pids}
    per_ip: dict[str, dict[int, set[int]]] = {}
    for r in rows:
        ts = _parse_ts(r["timestamp"])
        if ts is None:
            continue
        bucket = int(ts.timestamp() // FANOUT_WINDOW_SECONDS)
        per_ip.setdefault(r["dest_ip"], {}).setdefault(bucket, set()).add(r["pid"])
    alerts: list[Alert] = []
    for ip, buckets in per_ip.items():
        if not _is_routable_dest(ip) or ip in DOH_RESOLVERS:
            continue
        qualifying = sum(1 for pids in buckets.values() if len(pids) >= min_processes)
        if qualifying < min_windows:
            continue
        alerts.append(
            Alert(
                run_id=run_id,
                rule_id="fanout-recurring",
                rule_name="Recurring coordinated fan-out",
                severity="suspicious",
                triggered_at=datetime.now(timezone.utc),
                related_ip=ip,
                related_pid=None,
                details=(
                    f"{ip} crossed the fan-out threshold in {qualifying} distinct "
                    f"{FANOUT_WINDOW_SECONDS}s windows — a long-running coordinated plant "
                    f"(>= {min_processes} processes per window, repeated)"
                ),
            )
        )
    return alerts


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
    "BEACON_MIN_INTERVAL_SECONDS": ("beaconing", float, BEACON_MIN_INTERVAL_SECONDS),
    "RENAME_BURST_THRESHOLD": ("rename-burst", int, RENAME_BURST_THRESHOLD),
    "RENAME_BURST_WINDOW_SECONDS": ("rename-burst", int, RENAME_BURST_WINDOW_SECONDS),
    "ENUM_BURST_THRESHOLD": ("enumeration-burst", int, ENUM_BURST_THRESHOLD),
    "ENUM_WINDOW_SECONDS": ("enumeration-burst", int, ENUM_WINDOW_SECONDS),
    "STAGING_WINDOW_SECONDS": ("data-staging", int, STAGING_WINDOW_SECONDS),
    "BASELINE_MIN_EVENTS": ("baseline-anomaly", int, BASELINE_MIN_EVENTS),
    "DNS_TUNNEL_WINDOW_SECONDS": ("dns-tunneling", int, DNS_TUNNEL_WINDOW_SECONDS),
    "DNS_TUNNEL_MIN_DISTINCT": ("dns-tunneling", int, DNS_TUNNEL_MIN_DISTINCT),
    "DNS_LABEL_LEN": ("dns-tunneling", int, DNS_LABEL_LEN),
    "DNS_LABEL_ENTROPY": ("dns-tunneling", float, DNS_LABEL_ENTROPY),
    "DNS_LONG_LABEL_LEN": ("dns-long-label", int, DNS_LONG_LABEL_LEN),
    "DNS_LONG_LABEL_ENTROPY": ("dns-long-label", float, DNS_LONG_LABEL_ENTROPY),
    "RDP_BRUTE_WINDOW_SECONDS": ("rdp-brute-force", int, RDP_BRUTE_WINDOW_SECONDS),
    "RDP_BRUTE_MIN_CONNECTIONS": ("rdp-brute-force", int, RDP_BRUTE_MIN_CONNECTIONS),
    "FANOUT_WINDOW_SECONDS": ("fanout-contact", int, FANOUT_WINDOW_SECONDS),
    "FANOUT_MIN_PROCESSES": ("fanout-contact", int, FANOUT_MIN_PROCESSES),
    "FANOUT_RECUR_MIN_WINDOWS": ("fanout-recurring", int, FANOUT_RECUR_MIN_WINDOWS),
    "FANOUT_RECUR_LOOKBACK_SECONDS": ("fanout-recurring", int, FANOUT_RECUR_LOOKBACK_SECONDS),
    # Storm guard: burst-prone rules cap their alerts per run so a long live
    # session stays readable (alert-fatigue management — a novel process per
    # minute on a busy host is real but shouldn't bury the queue). The
    # suppressed counts land on the run as `suppressed_alerts`.
    "FIRST_SEEN_MAX_ALERTS": ("first-seen-process", int, FIRST_SEEN_MAX_ALERTS),
    "ENUM_BURST_MAX_ALERTS": ("enumeration-burst", int, ENUM_BURST_MAX_ALERTS),
    "NETWORK_SCAN_MAX_ALERTS": ("network-scan", int, NETWORK_SCAN_MAX_ALERTS),
    "BEACONING_MAX_ALERTS": ("beaconing", int, BEACONING_MAX_ALERTS),
    "FANOUT_MAX_ALERTS": ("fanout-contact", int, FANOUT_MAX_ALERTS),
    # Every other rule defaults to this ceiling so nothing floods a long live
    # session; the named *_MAX_ALERTS knobs override it lower.
    "ALERT_CAP_DEFAULT": ("__default__", int, ALERT_CAP_DEFAULT),
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
# Suppression: rule_id + optional run_id (None = global) + optional value
# scope (a sample name, related IP, or detail substring — the queue sweep's
# one-click "suppress this rule for this sample/C2" action). The run-detail
# page suppresses noisy rules for a single run; the Rules page can extend
# this to global scope. Loaded once per batch so edits apply to the next
# batch with no restart — same contract as rule tuning and enum patterns.
def load_suppressions(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT rule_id, run_id, value, reason FROM rule_suppressions"
    ).fetchall()
    return [dict(r) for r in rows]


def _suppression_matches(s: dict, alert: Alert, run_sample_name: str | None) -> bool:
    """Does a suppression's value scope cover this alert?

    Deliberately loose so one entry covers the same surface an analyst sees
    in the queue sweep: matches the alert's related IP exactly, the run's
    sample name exactly (case-insensitive), or as a substring of the alert
    details (where file paths / registry keys / command fragments state
    exactly what was observed). No value = whole rule scope.
    """
    value = (s.get("value") or "").strip().lower()
    if not value:
        return True
    if alert.related_ip and value == str(alert.related_ip).lower():
        return True
    if run_sample_name and value == run_sample_name.lower():
        return True
    return value in (alert.details or "").lower()


def _rule_suppressed(
    suppressions: list[dict],
    rule_id: str,
    run_id: str,
    alert: Alert | None = None,
    run_sample_name: str | None = None,
) -> bool:
    for s in suppressions:
        if s["rule_id"] != rule_id:
            continue
        if s["run_id"] is not None and s["run_id"] != run_id:
            continue
        if alert is not None and not _suppression_matches(s, alert, run_sample_name):
            continue
        return True
    return False


def load_run_allowlist(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT kind, value FROM run_allowlist WHERE run_id = ?", (run_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def allowlist_matches(kind: str, value: str, related_ip, details: str, sample_sha256: str | None = None) -> bool:
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


def load_run_sample_sha256(conn: sqlite3.Connection, run_id: str) -> str | None:
    """The SHA-256 of the uploaded sample this run was detonated against, if
    any (runs link to samples by matching sample_name). Enables hash-kind
    allowlisting — a hash only has meaning in the sample-vault context."""
    row = conn.execute(
        "SELECT s.sha256 FROM samples s JOIN runs r ON r.sample_name = s.original_name "
        "WHERE r.run_id = ? ORDER BY s.created_at DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    return row["sha256"] if row else None


def _allowlist_blocks(allowlist: list[dict], alert: Alert, sample_sha256: str | None = None) -> bool:
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
    # The run's sample name — the value scope a queue-sweep suppression
    # matches against (suppress beaconing for "detonate-demo.sh" etc.).
    row = conn.execute(
        "SELECT sample_name FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    run_sample_name = row["sample_name"] if row else None
    # Anti-forensics pattern tables (operator-editable via /rules/log-patterns)
    # loaded once per batch so a Rules-page edit applies to the next ingest.
    log_patterns = load_log_patterns(conn)

    # Process map for parent-child rule: every process_create event in this
    # run. Incremental — the run's map is cached in memory keyed by (db, run)
    # and each batch adds only the NEW process rows (id > last seen), so a
    # very long live session costs O(batch) per ingest, not O(run). The full
    # map is kept (not time-bounded) because parent-child semantics need an
    # hours-old parent to still resolve — a lookback would miss that. Evicted
    # on run completion and LRU-capped, so memory stays bounded.
    process_map, last_proc_id = _load_process_map(conn, run_id)

    new_alerts: list[Alert] = []
    seen_related: set[tuple] = set()
    seen_names: set[str] = set()

    def fire(alert: Alert) -> bool:
        """Insert an alert unless suppressed, allowlisted, or already fired.

        Every insert in the engine flows through here, so analyst triage
        (rule suppression, IOC allowlist) gates every rule uniformly — new
        alerts, run-wide composites, everything. The per-rule storm cap is
        applied last, only to alerts that would otherwise be new, so capped
        runs keep their most representative findings and record what was
        held back.
        """
        if _rule_suppressed(suppressions, alert.rule_id, run_id, alert, run_sample_name):
            return False
        if _allowlist_blocks(allowlist, alert, sample_sha256):
            return False
        key = (alert.rule_id, alert.related_pid, alert.related_ip)
        related = alert.related_ip or (str(alert.related_pid) if alert.related_pid else None)
        if key in seen_related or _alert_exists(conn, run_id, alert.rule_id, related):
            return False
        cap = alert_caps.get(alert.rule_id)
        if cap is None and default_cap > 0:
            cap = default_cap
        if cap is not None:
            fired = fired_counts.get(alert.rule_id, 0)
            if fired >= cap:
                # Count the *distinct* alert once — remember it in the dedup
                # set so the next observation of the same (rule, pid, ip)
                # from this batch is a silent repeat, not another suppress.
                if key not in seen_related:
                    suppressed_counts[alert.rule_id] = suppressed_counts.get(alert.rule_id, 0) + 1
                    seen_related.add(key)
                return False
            fired_counts[alert.rule_id] = fired + 1
        seen_related.add(key)
        insert_alert(conn, alert)
        new_alerts.append(alert)
        return True

    # Separate windows: beaconing looks back 30 min, rename-burst 10 s
    # (docs/11). Thresholds are tunable via the rule editor (roadmap 2.3).
    t = _load_tunables(conn)

    # Storm guard caps: per-rule per-run alert ceilings (tunable via the
    # Rules page; defaults below). Every rule gets the DEFAULT cap so nothing
    # can flood a long live session; the burst-prone ones override it lower.
    default_cap = max(0, int(t.get("ALERT_CAP_DEFAULT", ALERT_CAP_DEFAULT)))
    alert_caps: dict[str, int] = {}
    for name, (rule_id, _parse, _default) in _DEFAULT_TUNABLES.items():
        if name.endswith("_MAX_ALERTS"):
            alert_caps[rule_id] = max(0, int(t.get(name, _default)))
    # Seeded from what's already persisted, so the cap holds *across* ingest
    # batches (a run's events usually arrive in several) — without this the
    # counter would reset every batch and the cap would never trip on a
    # long live session.
    fired_counts: dict[str, int] = {
        row["rule_id"]: row["n"]
        for row in conn.execute(
            "SELECT rule_id, COUNT(*) AS n FROM alerts WHERE run_id = ? GROUP BY rule_id",
            (run_id,),
        ).fetchall()
    }
    suppressed_counts: dict[str, int] = {}

    # Explainability: snapshot the *tuned* thresholds in effect for this run,
    # captured once (INSERT OR IGNORE) at first evaluation — the immutable
    # "scored under" context the run-detail page shows, so a tuned finding
    # explains itself (e.g. DNS_TUNNEL_MIN_DISTINCT=3 because the operator
    # tightened it). Stock runs store an empty object.
    tuned_params = {
        name: t[name]
        for name, (rule_id, _parse, default) in _DEFAULT_TUNABLES.items()
        if t[name] != default
    }
    conn.execute(
        "INSERT OR IGNORE INTO run_tuning_snapshot (run_id, params) VALUES (?, ?)",
        (run_id, json.dumps(tuned_params)),
    )
    beacon_cutoff = _window_cutoff(events, int(t["BEACON_WINDOW_MINUTES"]) * 60)
    burst_cutoff = _window_cutoff(events, int(t["RENAME_BURST_WINDOW_SECONDS"]))
    staging_cutoff = _window_cutoff(events, int(t["STAGING_WINDOW_SECONDS"]))
    scan_cutoff = _window_cutoff(events, SCAN_WINDOW_SECONDS)
    rdp_cutoff = _window_cutoff(events, int(t["RDP_BRUTE_WINDOW_SECONDS"]))
    dns_cutoff = _window_cutoff(events, int(t["DNS_TUNNEL_WINDOW_SECONDS"]))
    fanout_cutoff = _window_cutoff(events, int(t["FANOUT_WINDOW_SECONDS"]))

    for event in events:
        candidates: list[Alert | None] = [
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
            check_lateral_psexec_smb(event),
            check_lateral_winrm_wmi(event),
            check_lateral_smb_share(event),
            check_log_service_stop(event, log_patterns["service_stop"]),
            check_log_clearing(event, log_patterns["log_clear"]),
            check_dns_long_label(
                event,
                long_len=int(t["DNS_LONG_LABEL_LEN"]),
                long_entropy=float(t["DNS_LONG_LABEL_ENTROPY"]),
            ),
            check_dns_unusual_port(event),
            check_tls_sni_suspicious(event),
            check_doh_resolver_use(event),
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
                min_interval=float(t["BEACON_MIN_INTERVAL_SECONDS"]),
                dest_port=event.get("dest_port"),
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
        if event.get("event_type") == "network_connection":
            alert = check_rdp_brute_force(
                conn, run_id, event, rdp_cutoff,
                min_connections=int(t["RDP_BRUTE_MIN_CONNECTIONS"]),
            )
            if alert:
                fire(alert)

    # DNS channel — tunneling burst over the whole window (once per run;
    # deduped via _alert_exists). Reads the `query` field Sysmon/DNS-aware
    # collectors stamp on network_connection events.
    dns_alert = check_dns_tunneling(
        conn, run_id, dns_cutoff,
        min_distinct=int(t["DNS_TUNNEL_MIN_DISTINCT"]),
        label_entropy=float(t["DNS_LABEL_ENTROPY"]),
        label_len=int(t["DNS_LABEL_LEN"]),
    )
    if dns_alert:
        fire(dns_alert)

    # Network fan-out — many distinct processes contacting one destination
    # over the whole window (once per IP per run; deduped via related_ip).
    for fanout_alert in check_fanout_contact(
        conn, run_id, fanout_cutoff,
        min_processes=int(t["FANOUT_MIN_PROCESSES"]),
    ):
        fire(fanout_alert)
    # Recurring fan-out — the same destination crossing the threshold in
    # multiple distinct windows (a long-running plant, not a one-off burst).
    # Run-wide over the run's whole history; deduped per IP per run.
    # Lookback-bounded: anchored to the batch's newest event minus
    # FANOUT_RECUR_LOOKBACK_SECONDS, so a very long live session re-scans only
    # recent history per ingest instead of the whole run.
    recur_cutoff = _window_cutoff(events, int(t["FANOUT_RECUR_LOOKBACK_SECONDS"]))
    for recurring in check_fanout_recurring(
        conn, run_id,
        min_processes=int(t["FANOUT_MIN_PROCESSES"]),
        min_windows=int(t["FANOUT_RECUR_MIN_WINDOWS"]),
        cutoff=recur_cutoff,
    ):
        fire(recurring)

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
    # Storm guard: persist the suppressed counts (merged across batches) so
    # the cap is visible on the run — a capped finding explains itself.
    if suppressed_counts:
        import json as _json

        existing = conn.execute(
            "SELECT suppressed_alerts FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        merged: dict[str, int] = {}
        if existing and existing["suppressed_alerts"]:
            try:
                merged = _json.loads(existing["suppressed_alerts"])
            except (ValueError, TypeError):
                merged = {}
        for rule, count in suppressed_counts.items():
            merged[rule] = merged.get(rule, 0) + count
        conn.execute(
            "UPDATE runs SET suppressed_alerts = ? WHERE run_id = ?",
            (_json.dumps(merged), run_id),
        )

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

    # Baseline anomalies (roadmap 4.x) — the anomaly layer under the rule
    # engine: learn what this host normally executes/talks to from its own
    # telemetry, then flag first-time observations once the baseline is
    # established (BASELINE_MIN_EVENTS). Check-then-learn ordering means each
    # novel item fires exactly once — it's not in the baseline when the batch
    # arrives, we alert, we learn it, and the next batch sees it as known.
    from ..services import baseline as baseline_svc

    for host, kind, value, ev in baseline_svc.check_deviations(
        conn, events, min_events=int(t["BASELINE_MIN_EVENTS"])
    ):
        if not _alert_exists(conn, run_id, "baseline-anomaly", value):
            fire(baseline_svc.build_alert(run_id, host, kind, value, ev))
    baseline_svc.learn(conn, events)

    return new_alerts
