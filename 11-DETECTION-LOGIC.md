# Detection Logic — Anomaly & Malware Heuristics

This is the flagship feature of OutPost: turning raw process/network telemetry into actual flagged findings, not just a scrollable log. Every rule here is deliberately **rule-based, not ML** — this keeps detections explainable (you can point to exactly why something fired, which matters both for a viva and for real use), keeps the project within scope, and matches the project's explicit non-AI/ML direction.

Runs server-side in `app/services/detection.py`, evaluated against every batch of incoming events (see `docs/02-BACKEND-SPEC.md`). Each rule that fires creates an `Alert` record with a `rule_id`, `severity`, and a human-readable `details` string explaining the specific trigger.

## Design Principle: Explainable Over Clever

Every rule below should be describable in one sentence to someone with no security background, and every `Alert.details` string should say exactly what was observed, not just "suspicious activity detected." A vague alert is nearly useless to an analyst — "this fired, no idea why" defeats the entire point of building your own detection logic instead of using a black-box tool.

## Rule Set

### 1. Process Masquerading

**What it catches:** malware naming itself after a legitimate system process to blend in (e.g. `svchost.exe` running from somewhere other than `C:\Windows\System32\`).

```python
LEGITIMATE_SYSTEM_PROCESSES = {
    "svchost.exe": r"C:\Windows\System32\svchost.exe",
    "lsass.exe": r"C:\Windows\System32\lsass.exe",
    "explorer.exe": r"C:\Windows\explorer.exe",
}

def check_masquerading(event: dict) -> Alert | None:
    name = event.get("process_name", "").lower()
    expected_path = LEGITIMATE_SYSTEM_PROCESSES.get(name)
    if expected_path and expected_path.lower() not in event.get("command_line", "").lower():
        return make_alert(event, rule_id="masquerading", severity="malicious",
                           details=f"{name} running from an unexpected path — expected {expected_path}")
```

### 2. Suspicious Parent-Child Process Relationships

**What it catches:** the classic macro-malware pattern — an Office application spawning a shell or scripting engine.

```python
SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
}

def check_parent_child(event: dict, process_map: dict) -> Alert | None:
    parent = process_map.get(event.get("ppid"))
    if parent and (parent["process_name"].lower(), event["process_name"].lower()) in SUSPICIOUS_PARENT_CHILD:
        return make_alert(event, rule_id="suspicious-parent-child", severity="malicious",
                           details=f"{parent['process_name']} spawned {event['process_name']} — common macro-malware pattern")
```

### 3. Living-Off-the-Land Binary (LOLBin) Abuse

**What it catches:** legitimate OS tools (`powershell`, `certutil`, `mshta`, `rundll32`, `regsvr32`) invoked with flags/patterns commonly used to download or execute payloads while evading naive detection.

```python
LOLBIN_SUSPICIOUS_PATTERNS = [
    (r"powershell.*-enc(odedcommand)?\s", "base64-encoded PowerShell command"),
    (r"powershell.*-nop.*-w\s+hidden", "hidden-window PowerShell execution"),
    (r"certutil.*-urlcache|-decode", "certutil abused for download/decode (LOLBin)"),
    (r"mshta.*http", "mshta executing a remote HTA payload"),
    (r"rundll32.*javascript:", "rundll32 executing inline JavaScript"),
]

def check_lolbin_abuse(event: dict) -> Alert | None:
    cmdline = event.get("command_line", "")
    for pattern, description in LOLBIN_SUSPICIOUS_PATTERNS:
        if re.search(pattern, cmdline, re.IGNORECASE):
            return make_alert(event, rule_id="lolbin-abuse", severity="malicious", details=description)
```

### 4. C2-Style Beaconing Detection

**What it catches:** regular, low-variance connection intervals to the same destination — the hallmark of malware "checking in" with a command-and-control server, as opposed to normal human/application traffic which is bursty and irregular.

```python
def check_beaconing(run_id: str, dest_ip: str) -> Alert | None:
    timestamps = get_recent_connection_times(run_id, dest_ip, window_minutes=30)
    if len(timestamps) < 5:
        return None
    intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
    if statistics.pstdev(intervals) < BEACON_VARIANCE_THRESHOLD:
        return make_alert_for_ip(dest_ip, rule_id="beaconing", severity="suspicious",
                                  details=f"{len(timestamps)} connections to {dest_ip} at regular ~{int(statistics.mean(intervals))}s intervals")
```

### 5. Persistence via Registry Run Keys (Windows)

**What it catches:** writes to the standard autorun registry locations — one of the most common ways malware survives a reboot.

```python
PERSISTENCE_REGISTRY_PATHS = [
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

def check_registry_persistence(event: dict) -> Alert | None:
    key = event.get("registry_key", "")
    if event["event_type"] == "registry_write" and any(p.lower() in key.lower() for p in PERSISTENCE_REGISTRY_PATHS):
        return make_alert(event, rule_id="registry-persistence", severity="suspicious",
                           details=f"Write to autorun key: {key}")
```

### 6. Rapid File Rename/Write Burst (Ransomware Indicator)

**What it catches:** a high volume of file writes/renames in a short window from one process — the signature behavior of ransomware encrypting files.

```python
def check_rename_burst(run_id: str, pid: int) -> Alert | None:
    recent_writes = get_recent_file_writes(run_id, pid, window_seconds=10)
    if len(recent_writes) > RENAME_BURST_THRESHOLD:
        return make_alert_for_pid(pid, rule_id="rename-burst", severity="malicious",
                                   details=f"{len(recent_writes)} file writes from pid {pid} within 10 seconds")
```

### 7. First-Seen Process (Novelty Detection)

**What it catches:** a process name that has never appeared in any of your prior runs — not inherently malicious, but worth a lower-severity flag, especially useful in **live monitoring mode** where establishing "what's normal for this machine" over time has real value.

```python
def check_first_seen(event: dict) -> Alert | None:
    name = event.get("process_name")
    if event["event_type"] == "process_create" and not seen_before_in_history(name):
        return make_alert(event, rule_id="first-seen-process", severity="suspicious",
                           details=f"{name} has not been observed in any prior session")
```

This rule benefits directly from the cross-run IOC/process history described in `docs/10-STANDOUT-FEATURES.md` — implement that before this one, or it has nothing to compare against.

## Severity Guidance

- **`malicious`** — high-confidence indicators with very low false-positive rates in a monitoring context (masquerading, LOLBin abuse with encoded payloads, rename bursts)
- **`suspicious`** — real signal, but with a plausible benign explanation (a new process you genuinely just installed, a registry Run key from software you meant to install) — worth surfacing, not worth an "everything's on fire" reaction

`RunSummary.highest_severity` should reflect the highest severity among that run's alerts, and is what drives the ReputationBadge-style coloring on the run history page (`docs/07-UI-DESIGN-SYSTEM.md`).

## Testing Each Rule

Write one synthetic test script per rule that deliberately triggers it (e.g. a script that writes to a Run key, a script that spawns `cmd.exe` from a renamed `winword.exe`, a script that beacons on a fixed interval). This gives you a clean, repeatable demo where you can show each detection firing on command — genuinely stronger for a viva than hoping a real sample happens to trigger the interesting rules.

## Adding a New Rule

1. Write the check function in `app/services/detection.py`, following the pattern above
2. Give it a unique `rule_id` and a human-readable `rule_name`
3. Register it in the rule list that `POST /ingest/batch` runs against
4. Write a synthetic test script that triggers it, confirm the alert fires with the correct severity and a genuinely useful `details` string
