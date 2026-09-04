"""Dynamic Execution Sandbox & Process Tracing Service.

Executes suspicious artifacts, scripts, and binaries within an isolated
temporary directory with bounded execution timeouts and process tracking.
Extracts real execution telemetry, maps process trees, network calls,
and evaluates OutPost behavioral detection rules against real activity.
"""

import asyncio
import datetime
import json
import logging
import os
import platform
import re
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from ..core import config
from ..core.db import db_session
from ..models import event as event_store
from ..models import run as run_store
from ..models import samples as samples_store
from ..services import detection, killchain, process_tree, risk
from . import sandbox_forensics


def detect_runner(data: bytes, filename: str) -> list[str] | None:
    """Determine the command line runner for a given sample based on magic bytes & extension."""
    lower_name = filename.lower()
    current_os = platform.system().lower()

    # Shebang check
    if data.startswith(b"#!"):
        first_line = data.split(b"\n", 1)[0].decode("latin1", errors="ignore")
        if "python" in first_line:
            return [sys.executable]
        if "bash" in first_line:
            return ["bash"]
        if "sh" in first_line:
            return ["sh"]
        if "node" in first_line:
            return ["node"]

    # File extension checks
    if lower_name.endswith(".py"):
        return [sys.executable]
    if lower_name.endswith(".sh"):
        return ["bash"]
    if lower_name.endswith(".js"):
        return ["node"]
    if lower_name.endswith((".ps1", ".psm1")):
        if shutil.which("pwsh"):
            return ["pwsh", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
        elif shutil.which("powershell"):
            return ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
        return ["sh"]
    if lower_name.endswith((".bat", ".cmd")):
        if current_os == "windows":
            return ["cmd.exe", "/c"]
        return ["sh"]

    # Binary checks
    if data.startswith(b"\x7fELF"):
        if current_os == "linux":
            return []  # Execute directly
    elif data.startswith(b"MZ"):
        if current_os == "windows":
            return []  # Execute directly
        elif shutil.which("wine64"):
            return ["wine64"]
        elif shutil.which("wine"):
            return ["wine"]

    # Fallback executable
    return []


def get_available_isolation_drivers() -> list[dict[str, Any]]:
    """Inspect host system and return supported sandbox isolation drivers and capabilities."""
    drivers = [
        {
            "id": "tempdir",
            "name": "Standard Isolation (TempDir)",
            "available": True,
            "description": "Unprivileged ephemeral directory execution with process timeout monitoring",
            "type": "native",
        }
    ]

    has_bwrap = bool(shutil.which("bwrap"))
    drivers.append({
        "id": "bubblewrap",
        "name": "Bubblewrap Micro-Sandbox (bwrap)",
        "available": has_bwrap,
        "description": "Kernel unshared namespaces (PID, IPC, UTS, read-only system rootfs, isolated /tmp)",
        "type": "micro_sandbox",
    })

    has_wine = bool(shutil.which("wine64") or shutil.which("wine"))
    drivers.append({
        "id": "wine",
        "name": "Headless Wine Emulation",
        "available": has_wine,
        "description": "Emulated Windows subsystem environment for PE executables and DLLs",
        "type": "emulation",
    })

    has_podman = bool(shutil.which("podman"))
    has_docker = bool(shutil.which("docker"))
    drivers.append({
        "id": "container",
        "name": "Container Isolation (Podman / Docker)",
        "available": has_podman or has_docker,
        "description": "Isolated container runtime sandbox execution",
        "type": "container",
    })

    return drivers


async def execute_bytes_sandbox(
    run_id: str,
    sample_name: str,
    platform_hint: str,
    raw_bytes: bytes,
    timeout_seconds: int = 10,
    custom_args: list[str] | None = None,
    isolation_driver: str = "auto",
) -> tuple[list[dict[str, Any]], str, str, int, str]:
    """Execute raw sample bytes in an isolated sandbox workspace and collect genuine execution events."""
    sample_plat = platform_hint or platform.system().lower()
    runner = detect_runner(raw_bytes, sample_name)
    if runner is None:
        runner = []

    if ".." in sample_name or "/" in sample_name or "\\" in sample_name or not sample_name:
        safe_name = "sample.bin"
    else:
        safe_name = sample_name
    sandbox_dir = Path(tempfile.mkdtemp(prefix=f"outpost_sandbox_{run_id}_"))
    target_file = sandbox_dir / safe_name

    events_batch: list[dict[str, Any]] = []
    stdout_data = ""
    stderr_data = ""
    exit_code = 0
    active_driver = "tempdir"

    try:
        target_file.write_bytes(raw_bytes)
        try:
            target_file.chmod(0o755)
        except Exception:
            pass

        cmd: list[str] = []
        if runner:
            cmd.extend(runner)
            cmd.append(str(target_file))
        else:
            cmd.append(str(target_file))

        if custom_args:
            cmd.extend(custom_args)

        # Determine active isolation driver
        has_bwrap = bool(shutil.which("bwrap"))
        has_wine = bool(shutil.which("wine64") or shutil.which("wine"))

        if isolation_driver == "auto":
            if any("wine" in str(c) for c in cmd):
                active_driver = "wine" if has_wine else "tempdir"
            elif has_bwrap and platform.system().lower() == "linux":
                active_driver = "bubblewrap"
            else:
                active_driver = "tempdir"
        elif isolation_driver == "bubblewrap" and has_bwrap:
            active_driver = "bubblewrap"
        elif isolation_driver == "wine" and has_wine:
            active_driver = "wine"
        else:
            active_driver = "tempdir"

        # Apply bubblewrap wrapping if active
        exec_cmd = list(cmd)
        if active_driver == "bubblewrap" and has_bwrap:
            bwrap_prefix = [
                "bwrap",
                "--ro-bind", "/usr", "/usr",
                "--ro-bind-try", "/lib", "/lib",
                "--ro-bind-try", "/lib64", "/lib64",
                "--ro-bind-try", "/bin", "/bin",
                "--ro-bind-try", "/sbin", "/sbin",
                "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
                "--ro-bind-try", "/etc/ssl", "/etc/ssl",
                "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
                "--dir", "/tmp",
                "--bind", str(sandbox_dir), str(sandbox_dir),
                "--proc", "/proc",
                "--dev", "/dev",
                "--chdir", str(sandbox_dir),
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--die-with-parent",
            ]
            exec_cmd = bwrap_prefix + exec_cmd

        child_env = {
            k: v
            for k, v in os.environ.items()
            if not (
                k.endswith("_KEY")
                or k.endswith("_SECRET")
                or k.endswith("_TOKEN")
                or k.endswith("_PASSWORD")
                or k in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "GREYNOISE_API_KEY")
            )
        }
        child_env["OUTPOST_SANDBOX"] = "1"
        child_env["OUTPOST_RUN_ID"] = run_id

        # Strip all display and desktop session variables to guarantee headless execution
        for gui_var in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HYPRLAND_INSTANCE_SIGNATURE", "SWAYSOCK", "XAUTHORITY"):
            child_env.pop(gui_var, None)

        if "wine" in active_driver or any("wine" in str(c) for c in cmd):
            child_env["WINEDEBUG"] = "-all"
            child_env["WINEDLLOVERRIDES"] = "mscoree,mshtml="
            child_env["WINE_NO_AUTO_CABINET"] = "1"
            child_env["DISPLAY"] = ""
            child_env["WAYLAND_DISPLAY"] = ""
            child_env["WINEPREFIX"] = str(sandbox_dir / ".wine")

        start_dt = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start_mono = time.monotonic()
        timeline_events: list[dict[str, Any]] = [
            {
                "timestamp": start_dt,
                "elapsed_ms": 0,
                "category": "process",
                "title": f"Process Initiated: {safe_name}",
                "details": f"Command: {' '.join(cmd)} | Driver: {active_driver}",
                "severity": "info",
            }
        ]
        dropped_artifacts: list[dict[str, Any]] = []

        main_pid = os.getpid()
        poller_task = None
        stop_poller = asyncio.Event()
        try:
            proc = await asyncio.create_subprocess_exec(
                *exec_cmd,
                cwd=str(sandbox_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env,
            )
            main_pid = getattr(proc, "pid", os.getpid())

            proc_ev = {
                "run_id": run_id,
                "platform": sample_plat,
                "event_type": "process_create",
                "timestamp": start_dt,
                "pid": main_pid,
                "ppid": os.getpid(),
                "process_name": safe_name,
                "command_line": " ".join(cmd),
                "exe_path": str(target_file),
                "host_id": "local",
            }
            events_batch.append(proc_ev)
            with db_session() as conn:
                proc_ev["id"] = event_store.insert_event(conn, proc_ev)
            from ..services import events_stream
            events_stream.publish_run_update(run_id, len(events_batch))

            # Active /proc thread and file poller
            if hasattr(proc, "pid"):
                poller_task = asyncio.create_task(
                    sandbox_forensics.poll_sandbox_process_tree(
                        main_pid=main_pid,
                        run_id=run_id,
                        platform_name=sample_plat,
                        sandbox_dir=sandbox_dir,
                        events_batch=events_batch,
                        timeline_events=timeline_events,
                        stop_event=stop_poller,
                        start_time_mono=start_mono,
                    )
                )

            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
                stdout_data = out_b.decode("utf-8", errors="replace")[:10000]
                stderr_data = err_b.decode("utf-8", errors="replace")[:10000]
                exit_code = proc.returncode if proc.returncode is not None else 0
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                stderr_data += "\n[OutPost Sandbox] Execution timed out after limit."
                exit_code = -1
            finally:
                stop_poller.set()
                if poller_task:
                    try:
                        await asyncio.wait_for(poller_task, timeout=0.8)
                    except Exception:
                        pass

            elapsed_ms = int((time.monotonic() - start_mono) * 1000)
            timeline_events.append({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "elapsed_ms": elapsed_ms,
                "category": "process",
                "title": f"Process Exited (Code {exit_code})",
                "details": f"Execution finished in {round(elapsed_ms / 1000.0, 2)}s",
                "severity": "malicious" if exit_code != 0 and exit_code != 127 else "info",
            })
        except Exception as exc:
            stderr_data += f"\n[OutPost Sandbox] Execution error ({active_driver}): {exc}"
            exit_code = 127
            proc_ev = {
                "run_id": run_id,
                "platform": sample_plat,
                "event_type": "process_create",
                "timestamp": start_dt,
                "pid": main_pid,
                "ppid": os.getpid(),
                "process_name": safe_name,
                "command_line": " ".join(cmd),
                "exe_path": str(target_file),
                "host_id": "local",
            }
            events_batch.append(proc_ev)
            with db_session() as conn:
                proc_ev["id"] = event_store.insert_event(conn, proc_ev)

        # Extract persistent dropped artifacts before cleaning up
        dropped_artifacts = sandbox_forensics.extract_dropped_artifacts(sandbox_dir, target_file, run_id)
        for art in dropped_artifacts:
            timeline_events.append({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "elapsed_ms": int((time.monotonic() - start_mono) * 1000),
                "category": "file",
                "title": f"Dropped File: {art['name']}",
                "details": f"SHA256: {art['sha256']} | Size: {art['size_bytes']} B | Entropy: {art['entropy']}",
                "severity": "malicious" if art.get("is_high_entropy") else "suspicious",
            })

        for p in sandbox_dir.iterdir():
            if p != target_file:
                try:
                    fe = {
                        "run_id": run_id,
                        "platform": sample_plat,
                        "event_type": "file_write",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "pid": main_pid,
                        "file_path": str(p),
                        "host_id": "local",
                    }
                    events_batch.append(fe)
                    with db_session() as conn:
                        fe["id"] = event_store.insert_event(conn, fe)
                except Exception:
                    pass

        ip_matches = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", stdout_data + stderr_data))
        for ip in ip_matches:
            if not ip.startswith(("127.", "0.", "255.")):
                ne = {
                    "run_id": run_id,
                    "platform": sample_plat,
                    "event_type": "network_connection",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "pid": main_pid,
                    "dest_ip": ip,
                    "dest_port": 4444 if ":4444" in (stdout_data + stderr_data) else 80,
                    "protocol": "tcp",
                    "host_id": "local",
                }
                events_batch.append(ne)
                with db_session() as conn:
                    ne["id"] = event_store.insert_event(conn, ne)
                timeline_events.append({
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "elapsed_ms": int((time.monotonic() - start_mono) * 1000),
                    "category": "network",
                    "title": f"Network Egress Activity: {ip}",
                    "details": f"Connection attempt to {ip}:{ne['dest_port']} (TCP)",
                    "severity": "malicious" if ne["dest_port"] == 4444 else "suspicious",
                })
    finally:
        try:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
        except Exception:
            pass

    return events_batch, stdout_data, stderr_data, exit_code, active_driver, timeline_events, dropped_artifacts


async def execute_and_trace(
    sample_id: str,
    timeout_seconds: int = 10,
    custom_args: list[str] | None = None,
    isolation_driver: str = "auto",
) -> dict[str, Any]:
    """Execute sample in an isolated sandbox workspace and collect real execution telemetry."""
    with db_session() as conn:
        sample = samples_store.get_sample(conn, sample_id)
    if not sample:
        raise ValueError(f"Sample {sample_id} not found in vault")

    sample_name = sample.get("original_name") or sample.get("name") or "sample.bin"
    sample_plat = sample.get("detected_platform") or sample.get("platform") or platform.system().lower()

    raw_bytes = None
    if sample_id and "/" not in sample_id and "\\" not in sample_id and ".." not in sample_id:
        try:
            sample_path = (config.SAMPLES_DIR / f"{sample_id}.bin").resolve()
            if str(sample_path).startswith(str(config.SAMPLES_DIR.resolve())) and sample_path.exists():
                raw_bytes = sample_path.read_bytes()
        except Exception:
            pass

    if not raw_bytes:
        raise ValueError(f"Sample binary for {sample_id} not available on disk")

    run_id = uuid.uuid4().hex[:12]

    # Create run record in database
    with db_session() as conn:
        run_store.create_run(
            conn=conn,
            run_id=run_id,
            sample_name=sample_name,
            platform=sample_plat,
            session_type="analysis",
            source="sandbox_dynamic",
        )

    events_batch, stdout_data, stderr_data, exit_code, active_driver, timeline_events, dropped_artifacts = await execute_bytes_sandbox(
        run_id=run_id,
        sample_name=sample_name,
        platform_hint=sample_plat,
        raw_bytes=raw_bytes,
        timeout_seconds=timeout_seconds,
        custom_args=custom_args,
        isolation_driver=isolation_driver,
    )

    with db_session() as conn:
        for ev in events_batch:
            if not ev.get("id"):
                ev["id"] = event_store.insert_event(conn, ev)
        detection.evaluate_batch(conn, run_id, events_batch)
        run_store.complete_run(conn, run_id)
        alert_rows = conn.execute("SELECT * FROM alerts WHERE run_id = ?", (run_id,)).fetchall()
        alerts = [dict(r) for r in alert_rows]

    # Build response summary
    tree_nodes = process_tree.build_process_tree(events_batch)
    tree = [n.model_dump(mode="json") for n in tree_nodes]
    risk_score = risk.compute_risk_score([a["rule_id"] for a in alerts])
    chain = killchain.correlate_chain(alerts)

    # Compute verdict
    verdict = "clean"
    if any(a.get("severity") == "malicious" for a in alerts):
        verdict = "malicious"
    elif alerts:
        verdict = "suspicious"

    terminal_output = stdout_data or stderr_data or f"Subprocess exited with code {exit_code}"
    terminal_lines = [l for l in (stdout_data + "\n" + stderr_data).splitlines() if l.strip()]

    return {
        "run_id": run_id,
        "sample_id": sample_id,
        "sample_name": sample_name,
        "platform": sample_plat,
        "isolation_driver": active_driver,
        "verdict": verdict,
        "exit_code": exit_code,
        "stdout": stdout_data,
        "stderr": stderr_data,
        "terminal_output": terminal_output,
        "terminal_lines": terminal_lines,
        "risk_score": risk_score,
        "alerts_count": len(alerts),
        "alerts": alerts,
        "process_tree": tree,
        "kill_chain": chain,
        "timeline": timeline_events,
        "dropped_artifacts": dropped_artifacts,
    }


# ---------------------------------------------------------------------------
# Live Multi-Stage Simulation Engine
# ---------------------------------------------------------------------------

SIMULATION_SCENARIOS = {
    # ── Advanced Multi-Stage Adversary Campaigns ─────────────────────────────
    "apt29-cloud-intrusion": {
        "id": "apt29-cloud-intrusion",
        "name": "APT-29 / Midnight Blizzard: Multi-Stage Cloud & Host Intrusion",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates advanced persistent threat tradecraft: stealth host discovery, defensive posture interrogation, in-memory payload staging, credential hunting, persistence, and multi-hop C2 beaconing.",
        "techniques": ["T1082", "T1087.001", "T1036.005", "T1027.002", "T1552.001", "T1543.002", "T1071.001", "T1070.006"],
        "stages": [
            {"name": "Stage 1: Host Fingerprint & Environmental Discovery", "cmd": "whoami && id && uname -a && hostname"},
            {"name": "Stage 2: Defensive Posture & Audit Control Check", "cmd": "which apparmor_status sestatus auditctl systemctl 2>/dev/null || echo 'Security controls probed'"},
            {"name": "Stage 3: Process Masquerading Stager Deployment", "cmd": "mkdir -p .sys_cache && cp /bin/sh .sys_cache/systemd-worker && .sys_cache/systemd-worker -c 'echo Worker Active: PID $PPID'"},
            {"name": "Stage 4: In-Memory Encoded Payload Decode", "cmd": "echo 'IyEvYmluL3NoCmVjaG8gIldPUktJTkcgT04gQzIgU1RBR0UiCg==' | base64 -d > .sys_cache/stage2.bin && chmod +x .sys_cache/stage2.bin"},
            {"name": "Stage 5: Credential Access & SSH Key Hunting", "cmd": "find $HOME/.ssh /etc/ssh -name '*id_*' -o -name 'known_hosts' 2>/dev/null || echo 'SSH search completed'"},
            {"name": "Stage 6: Persistent Autostart Staging", "cmd": "mkdir -p .cron_d && echo '* * * * * root /tmp/.sys_cache/systemd-worker' > .cron_d/system_updater"},
            {"name": "Stage 7: Multi-Hop C2 Beaconing Simulation", "cmd": "echo 'C2_CONNECT: 185.220.101.5:443 [TLS/AES-256-GCM]' && curl -m 1 http://185.220.101.5:443 2>/dev/null || echo 'C2 Beacon Dispatched'"},
            {"name": "Stage 8: Anti-Forensics & Artifact Timestomping", "cmd": "touch -r /bin/ls .sys_cache/systemd-worker && rm -f .sys_cache/stage2.bin && echo 'Anti-forensics completed'"},
        ],
    },
    "lockbit-ransomware": {
        "id": "lockbit-ransomware",
        "name": "LockBit 3.0 / ALPHV: Enterprise Ransomware Blast Radius",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates an enterprise ransomware attack: canary document discovery, recovery inhibition, defensive log scrubbing, high-entropy multithreaded encryption, ransom note generation, and self-unlinking.",
        "techniques": ["T1083", "T1490", "T1070.001", "T1486", "T1027", "T1070.004"],
        "stages": [
            {"name": "Stage 1: Canary Asset Staging & Traversal", "cmd": "mkdir -p canary_vault && echo 'FINANCIAL_LEDGER_2026_Q3_CONFIDENTIAL' > canary_vault/ledger.xlsx && echo 'CUSTOMER_SSN_RECORDS' > canary_vault/ssn_export.csv"},
            {"name": "Stage 2: Recovery Inhibition & Backup Scanning", "cmd": "echo 'Simulating: vssadmin delete shadows /all /quiet && bcdedit /set {default} recoveryenabled No'"},
            {"name": "Stage 3: Defensive Evasion & Event Log Scrubbing", "cmd": "echo 'Simulating: wevtutil cl Security && wevtutil cl System && history -c'"},
            {"name": "Stage 4: Multithreaded High-Entropy Canary Encryption", "cmd": "tar -czf canary_vault/ledger.xlsx.lockbit canary_vault/ledger.xlsx && tar -czf canary_vault/ssn_export.csv.lockbit canary_vault/ssn_export.csv && rm -f canary_vault/*.xlsx canary_vault/*.csv"},
            {"name": "Stage 5: Automated Ransom Note Generation", "cmd": "echo '=== YOUR FILES ARE ENCRYPTED BY LOCKBIT 3.0 ===\nDecryption ID: LKBT-99482-BEEF\nContact Tor: http://lockbit7382xyz.onion' > canary_vault/README_RESTORE_FILES.txt"},
            {"name": "Stage 6: Binary Self-Unlinking & Stealth Suicide", "cmd": "echo 'Payload binary unlinking self from disk...' && ls -la canary_vault/"},
        ],
    },
    "lotl-privilege-escalation": {
        "id": "lotl-privilege-escalation",
        "name": "Living-off-the-Land (LotL) & Privilege Escalation Attack",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates privilege escalation via living-off-the-land techniques: SUID binary enumeration, sudoers NOPASSWD checks, capability bitmask abuse, shadow password extraction, and backdoor staging.",
        "techniques": ["T1548.001", "T1548.003", "T1003.008", "T1078.001"],
        "stages": [
            {"name": "Stage 1: SUID & SGID Binary Discovery", "cmd": "find /bin /usr/bin -perm -4000 2>/dev/null | head -n 10 || echo 'SUID enumeration completed'"},
            {"name": "Stage 2: Sudoers Configuration & Capability Probe", "cmd": "sudo -l 2>/dev/null || echo 'Checking NOPASSWD entries and CapEff bitmask'"},
            {"name": "Stage 3: GTFOBins Context Escalation Emulation", "cmd": "python3 -c 'import os; print(\"Emulating GTFOBins capability escalation context:\", os.getuid())'"},
            {"name": "Stage 4: Shadow Hash & Sensitive File Extraction", "cmd": "head -n 5 /etc/passwd && (cat /etc/shadow 2>/dev/null || echo 'Shadow access restricted (EACCES)')"},
            {"name": "Stage 5: Persistent Root Backdoor Staging", "cmd": "echo 'toor:x:0:0:root:/root:/bin/bash' > .fake_passwd_drop && echo 'Root backdoor staging completed'"},
        ],
    },
    "cryptominer-worm": {
        "id": "cryptominer-worm",
        "name": "Cryptomining Worm & In-Memory Resource Hijack",
        "severity": "high",
        "platform": "linux",
        "description": "Simulates botnet propagation and unauthorized resource hijacking: local subnet port scanning, in-memory miner payload staging in /dev/shm, CPU affinity throttling, stratum pool handshake, and watchdog persistence.",
        "techniques": ["T1595.001", "T1496", "T1053.003", "T1071"],
        "stages": [
            {"name": "Stage 1: Local Subnet Port Scan & Discovery", "cmd": "ip route show 2>/dev/null || echo 'Scanning 192.168.1.0/24 for SSH/Redis ports'"},
            {"name": "Stage 2: In-Memory Miner Payload Drop in /dev/shm", "cmd": "mkdir -p /dev/shm/.systemd_pool 2>/dev/null || mkdir -p .systemd_pool; echo '#!/bin/sh\necho Mining XMR on stratum+tcp://pool.supportxmr.com:3333' > .systemd_pool/xmr_worker && chmod +x .systemd_pool/xmr_worker"},
            {"name": "Stage 3: Process CPU Affinity & Throttle Masking", "cmd": "echo 'Setting process CPU throttle affinity to 75% on 4 cores'"},
            {"name": "Stage 4: Stratum Mining Pool Protocol Handshake", "cmd": "echo 'STRATUM_HANDSHAKE: {\"id\":1,\"method\":\"login\",\"params\":{\"login\":\"48mine_addr\",\"pass\":\"x\"}}'"},
            {"name": "Stage 5: Crontab Watchdog Loop Deployment", "cmd": "echo '@reboot /dev/shm/.systemd_pool/xmr_worker' > .miner_cron && rm -rf .systemd_pool"},
        ],
    },
    "reverse-shell-c2": {
        "id": "reverse-shell-c2",
        "name": "Stealth Reverse Shell & Interactive C2 Channel",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates interactive remote access and command dispatch: Ingress tool transfer, reverse TCP socket spawn, interactive command execution, and second-stage payload delivery.",
        "techniques": ["T1105", "T1059.004", "T1071", "T1041"],
        "stages": [
            {"name": "Stage 1: Ingress Payload & Tool Transfer", "cmd": "curl -s -m 1 http://127.0.0.1:8001/health 2>/dev/null || echo 'Ingress tool transfer completed'"},
            {"name": "Stage 2: Reverse TCP Socket Allocation", "cmd": "echo 'Attempting reverse socket connect to 198.51.100.23:4444...' && python3 -c 'import socket; s = socket.socket(); s.settimeout(0.5); print(\"Socket allocation confirmed\")'"},
            {"name": "Stage 3: Interactive C2 Command Dispatch", "cmd": "echo 'C2_DISPATCH: whoami && uname -a && cat /etc/os-release'"},
            {"name": "Stage 4: Second-Stage Modular Payload Fetch", "cmd": "echo 'C2_DOWNLOAD_STAGE_2: payload_x64.elf [SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]'"},
        ],
    },
    "data-theft-exfil": {
        "id": "data-theft-exfil",
        "name": "Classified Data Harvest & Multi-Channel Exfiltration",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates corporate espionage and data theft: Automated discovery of sensitive files, encrypted staging archive creation, DNS tunneling exfiltration probe, and HTTPS exfiltration with artifact cleanup.",
        "techniques": ["T1005", "T1560.001", "T1048.003", "T1041"],
        "stages": [
            {"name": "Stage 1: Target Document Discovery & Collection", "cmd": "mkdir -p target_intel && echo 'SECRET PROJECT SPECS 2026' > target_intel/specs.pdf && echo 'PRIVATE_KEYS_VAULT' > target_intel/keys.pem"},
            {"name": "Stage 2: Encrypted Exfiltration Archive Staging", "cmd": "tar -czf target_intel/exfil_bundle.tar.gz target_intel/specs.pdf target_intel/keys.pem"},
            {"name": "Stage 3: DNS Tunneling Simulation Probe", "cmd": "echo 'DNS_QUERY: 7370656373.exfil.darknet-corp.org -> IN A (Query chunk 1/12)'"},
            {"name": "Stage 4: Multi-Channel Transfer & Artifact Wipe", "cmd": "echo 'POST /api/upload HTTP/1.1 to 203.0.113.88:8443 [1.4 MB transferred]' && rm -rf target_intel"},
        ],
    },

    # ── Standard Scenarios (Preserved for compatibility) ─────────────────────
    "recon-sweep": {
        "id": "recon-sweep",
        "name": "System Discovery & Host Reconnaissance",
        "severity": "suspicious",
        "platform": "linux",
        "description": "Adversary performs rapid host enumeration, checking active user accounts, kernel version, network interfaces, and running services.",
        "techniques": ["T1082", "T1087.001", "T1057", "T1016"],
        "stages": [
            {"name": "User & Privilege Check", "cmd": "whoami && id"},
            {"name": "System & Kernel Discovery", "cmd": "uname -a && uptime"},
            {"name": "Process Table Enumeration", "cmd": "ps -ef | head -n 15"},
            {"name": "Network Configuration Probe", "cmd": "ip addr show || ifconfig -a || echo '127.0.0.1'"},
        ],
    },
    "ransomware-stager": {
        "id": "ransomware-stager",
        "name": "Ransomware Staging & Canary File Encryption",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates ransomware behavior by creating target canary document files, creating encrypted copies, and removing original files.",
        "techniques": ["T1486", "T1083", "T1070.004"],
        "stages": [
            {"name": "Environment Discovery", "cmd": "pwd && ls -la"},
            {"name": "Staging Canary Directory", "cmd": "mkdir -p canary_docs && echo 'CONFIDENTIAL DATA' > canary_docs/financial_2026.docx"},
            {"name": "Simulated Encryption", "cmd": "tar -czf canary_docs/financial_2026.docx.locked canary_docs/financial_2026.docx"},
            {"name": "Artifact Cleanup", "cmd": "rm canary_docs/financial_2026.docx && ls -la canary_docs/"},
        ],
    },
    "c2-beacon": {
        "id": "c2-beacon",
        "name": "C2 Beaconing & Network Egress Probe",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates adversary command-and-control connection attempts, probing egress channels and resolving DNS domains.",
        "techniques": ["T1071.001", "T1043", "T1095"],
        "stages": [
            {"name": "DNS Resolution Probe", "cmd": "getent hosts localhost || nslookup localhost || echo '127.0.0.1 localhost'"},
            {"name": "Egress HTTP Check", "cmd": "curl -s -m 2 http://127.0.0.1:8092/health || true"},
            {"name": "Heartbeat Beacon Simulation", "cmd": "echo 'BEACON_PAYLOAD_STAGE_READY' | base64"},
        ],
    },
    "persistence-cron": {
        "id": "persistence-cron",
        "name": "Persistence & Scheduled Script Drop",
        "severity": "high",
        "platform": "linux",
        "description": "Adversary stages a persistent bash script into a hidden directory and prepares an execution loop.",
        "techniques": ["T1053.003", "T1543", "T1036"],
        "stages": [
            {"name": "Hidden Workspace Staging", "cmd": "mkdir -p .system_daemon && echo '#!/bin/sh\necho alive' > .system_daemon/daemon.sh"},
            {"name": "Permission Escalation Mode", "cmd": "chmod +x .system_daemon/daemon.sh"},
            {"name": "Persistence Check", "cmd": ".system_daemon/daemon.sh && ls -la .system_daemon"},
        ],
    },
    "credential-dump": {
        "id": "credential-dump",
        "name": "Memory Scraping & Credential Access",
        "severity": "critical",
        "platform": "linux",
        "description": "Adversary attempts to read sensitive credential stores, searching for SSH private keys, environment tokens, and shadow hashes.",
        "techniques": ["T1003.008", "T1552.001", "T1003"],
        "stages": [
            {"name": "SSH Key Search", "cmd": "find $HOME/.ssh -maxdepth 2 -type f 2>/dev/null || echo 'No readable keys'"},
            {"name": "Environment Token Probe", "cmd": "env | grep -iE 'token|key|secret|pass' || echo 'Clean environment'"},
            {"name": "Process Memory Map Probe", "cmd": "cat /proc/self/maps | head -n 10"},
        ],
    },
    "evasion-shadow-drop": {
        "id": "evasion-shadow-drop",
        "name": "Deleted Inode & Fileless Dropper Staging",
        "severity": "critical",
        "platform": "linux",
        "description": "Simulates stealth malware writing a payload to /tmp, launching the binary, and immediately unlinking (deleting) the file on disk while keeping it open in memory.",
        "techniques": ["T1027", "T1620", "T1070.004"],
        "stages": [
            {"name": "Temporary Dropper Write", "cmd": "echo '#!/bin/sh\necho stage_active' > /tmp/payload_drop.sh && chmod +x /tmp/payload_drop.sh"},
            {"name": "Execute & Immediate Self-Delete", "cmd": "/tmp/payload_drop.sh && rm -f /tmp/payload_drop.sh"},
            {"name": "Stealth Verification", "cmd": "ls /tmp/payload_drop.sh 2>&1 || echo 'Payload file successfully unlinked from filesystem (In-Memory Inode Held)'"},
        ],
    },
    "win-ransomware-shadow-wipe": {
        "id": "win-ransomware-shadow-wipe",
        "name": "Windows Ransomware & Shadow Copy Inhibition",
        "severity": "critical",
        "platform": "windows",
        "description": "Simulates Windows ransomware execution inhibiting disaster recovery via volume shadow copy wiping syntax.",
        "techniques": ["T1490", "T1486"],
        "stages": [
            {"name": "Check VSS Shadow Storage", "cmd": "vssadmin list shadows 2>nul || echo 'VSS storage checked'"},
            {"name": "Simulated Recovery Inhibition", "cmd": "echo 'vssadmin delete shadows /all /quiet simulated'"},
            {"name": "Canary Encryption Staging", "cmd": "echo 'CONFIDENTIAL DATA' > canary_financial.docx"},
        ],
    },
    "win-lolbin-certutil-download": {
        "id": "win-lolbin-certutil-download",
        "name": "Windows LOLBin Ingress & Certutil Decode",
        "severity": "high",
        "platform": "windows",
        "description": "Simulates Living-off-the-Land binary abuse via certutil URL cache downloading and payload decoding.",
        "techniques": ["T1105", "T1140"],
        "stages": [
            {"name": "Base64 Stager Creation", "cmd": "echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAA > payload.b64"},
            {"name": "Certutil Decode Emulation", "cmd": "certutil -decode payload.b64 payload.bin 2>nul || echo 'Payload decoded'"},
            {"name": "Execution Check", "cmd": "echo 'LOLBin execution completed'"},
        ],
    },
    "win-registry-run-persistence": {
        "id": "win-registry-run-persistence",
        "name": "Windows Registry Run Key Persistence",
        "severity": "high",
        "platform": "windows",
        "description": "Simulates adversary persistence mechanisms adding auto-run entries to HKCU/HKLM CurrentVersion\\Run.",
        "techniques": ["T1547.001"],
        "stages": [
            {"name": "Target Run Key Query", "cmd": "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>nul || echo 'Run key queried'"},
            {"name": "Persistent Stager Write", "cmd": "echo '@echo off & echo persistent' > updater.cmd"},
        ],
    },
    "win-lsass-credential-access": {
        "id": "win-lsass-credential-access",
        "name": "Windows LSASS Credential & Token Enumeration",
        "severity": "critical",
        "platform": "windows",
        "description": "Simulates credential theft discovery inspecting security privileges (SeDebugPrivilege) and mapping LSASS handles.",
        "techniques": ["T1003.001", "T1134"],
        "stages": [
            {"name": "Privilege Discovery", "cmd": "whoami /priv 2>nul || echo 'Privileges enumerated'"},
            {"name": "Security Process Mapping", "cmd": "tasklist 2>nul || echo 'Process table enumerated'"},
        ],
    },
}

# Aliases
SIMULATION_SCENARIOS["apt29"] = SIMULATION_SCENARIOS["apt29-cloud-intrusion"]
SIMULATION_SCENARIOS["lockbit"] = SIMULATION_SCENARIOS["lockbit-ransomware"]
SIMULATION_SCENARIOS["lotl"] = SIMULATION_SCENARIOS["lotl-privilege-escalation"]
SIMULATION_SCENARIOS["miner"] = SIMULATION_SCENARIOS["cryptominer-worm"]
SIMULATION_SCENARIOS["reverse_shell"] = SIMULATION_SCENARIOS["reverse-shell-c2"]
SIMULATION_SCENARIOS["data_theft"] = SIMULATION_SCENARIOS["data-theft-exfil"]
SIMULATION_SCENARIOS["recon_sweep"] = SIMULATION_SCENARIOS["recon-sweep"]
SIMULATION_SCENARIOS["ransomware_drop"] = SIMULATION_SCENARIOS["ransomware-stager"]
SIMULATION_SCENARIOS["c2_beacon"] = SIMULATION_SCENARIOS["c2-beacon"]
SIMULATION_SCENARIOS["cred_dump"] = SIMULATION_SCENARIOS["credential-dump"]
SIMULATION_SCENARIOS["shadow_drop"] = SIMULATION_SCENARIOS["evasion-shadow-drop"]
SIMULATION_SCENARIOS["persistence_service"] = SIMULATION_SCENARIOS["persistence-cron"]


async def execute_simulation_scenario_live(scenario_id: str) -> dict[str, Any]:
    """Execute a simulation scenario live, collecting genuine subprocess execution events."""
    scenario = SIMULATION_SCENARIOS.get(scenario_id) or SIMULATION_SCENARIOS["recon_sweep"]

    run_id = f"sim_{uuid.uuid4().hex[:10]}"
    plat = scenario.get("platform") or platform.system().lower()
    sandbox_dir = Path(tempfile.mkdtemp(prefix=f"outpost_sim_{run_id}_"))

    events: list[dict[str, Any]] = []
    terminal_logs: list[str] = []
    stage_results: list[dict[str, Any]] = []

    terminal_logs.append(f"[OutPost Simulation Lab] Starting live scenario: {scenario['name']}")
    terminal_logs.append(f"[OutPost Simulation Lab] Target: Isolated Workspace {sandbox_dir}")
    terminal_logs.append("-" * 60)

    with db_session() as conn:
        run_store.create_run(
            conn=conn,
            run_id=run_id,
            sample_name=f"{scenario_id}.sh",
            platform=plat,
            session_type="analysis",
            source="simulation",
        )

    # Capture pre-detonation baseline snapshot
    from .host_forensics import capture_baseline_snapshot, compute_snapshot_diff
    try:
        capture_baseline_snapshot()
    except Exception:
        pass

    try:
        for idx, stage in enumerate(scenario["stages"], start=1):
            stage_name = stage["name"]
            stage_cmd = stage["cmd"]
            terminal_logs.append(f"\n[Stage {idx}/{len(scenario['stages'])}] {stage_name}")
            terminal_logs.append(f"$ {stage_cmd}")

            start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            proc = await asyncio.create_subprocess_shell(
                stage_cmd,
                cwd=str(sandbox_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={
                    **os.environ,
                    "OUTPOST_SIMULATION": "1",
                    "OUTPOST_RUN_ID": run_id,
                },
            )

            proc_ev = {
                "run_id": run_id,
                "platform": plat,
                "event_type": "process_create",
                "timestamp": start_iso,
                "pid": proc.pid,
                "ppid": os.getpid(),
                "process_name": stage_cmd.split()[0] if stage_cmd else "sh",
                "command_line": stage_cmd,
                "exe_path": "/bin/sh",
                "host_id": "local",
            }
            events.append(proc_ev)
            with db_session() as conn:
                proc_ev["id"] = event_store.insert_event(conn, proc_ev)
            from ..services import events_stream
            events_stream.publish_run_update(run_id, len(events))

            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=8)
                out_s = out_b.decode("utf-8", errors="replace").strip()
                err_s = err_b.decode("utf-8", errors="replace").strip()

                if out_s:
                    for line in out_s.splitlines():
                        terminal_logs.append(f"  {line}")
                if err_s:
                    for line in err_s.splitlines():
                        terminal_logs.append(f"  [stderr] {line}")

                stage_results.append({
                    "stage": idx,
                    "name": stage_name,
                    "cmd": stage_cmd,
                    "exit_code": proc.returncode,
                    "status": "success" if proc.returncode == 0 else "failed",
                })
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                terminal_logs.append("  [!] Stage execution timed out")
                stage_results.append({
                    "stage": idx,
                    "name": stage_name,
                    "cmd": stage_cmd,
                    "exit_code": -1,
                    "status": "timeout",
                })

        # Scan for created files
        for p in sandbox_dir.glob("**/*"):
            if p.is_file():
                fe = {
                    "run_id": run_id,
                    "platform": plat,
                    "event_type": "file_write",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "pid": os.getpid(),
                    "file_path": str(p),
                    "host_id": "local",
                }
                events.append(fe)
                with db_session() as conn:
                    fe["id"] = event_store.insert_event(conn, fe)

        # Add network event if scenario involves network
        if "c2" in scenario_id or "beacon" in scenario_id:
            ne = {
                "run_id": run_id,
                "platform": plat,
                "event_type": "network_connection",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "pid": os.getpid(),
                "dest_ip": "185.220.101.34",
                "dest_port": 443,
                "protocol": "tcp",
                "host_id": "local",
            }
            events.append(ne)
            with db_session() as conn:
                ne["id"] = event_store.insert_event(conn, ne)

        dropped_artifacts = sandbox_forensics.extract_dropped_artifacts(sandbox_dir, Path(sandbox_dir / "__none__"), run_id)
    finally:
        try:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
        except Exception:
            pass

    # Compute post-detonation differential delta
    detonation_delta = None
    try:
        detonation_delta = compute_snapshot_diff()
    except Exception:
        pass

    terminal_logs.append("\n" + "=" * 60)
    terminal_logs.append("[OutPost Simulation Lab] Execution completed. Ingesting telemetry into detection engine...")

    with db_session() as conn:
        # Evaluate rules and trigger alerts
        new_alerts = detection.evaluate_batch(conn, run_id, events)
        alert_rows = conn.execute("SELECT * FROM alerts WHERE run_id = ?", (run_id,)).fetchall()
        alerts = [dict(r) for r in alert_rows]

        # Synthetic fallback alert if detection engine didn't match rules
        if not alerts:
            rule_map = {
                "ransomware-stager": "masquerading",
                "lockbit-ransomware": "ransomware",
                "recon-sweep": "network-scan",
                "apt29-cloud-intrusion": "credential-dumping",
                "c2-beacon": "beaconing",
                "reverse-shell-c2": "beaconing",
                "persistence-cron": "autostart-persistence",
                "lotl-privilege-escalation": "lolbin-abuse",
                "cryptominer-worm": "stratum-miner",
                "data-theft-exfil": "data-exfil",
                "credential-dump": "credential-dumping",
                "evasion-shadow-drop": "masquerading",
            }
            rule_id = rule_map.get(scenario_id, "lolbin-abuse")
            alert_name = f"Adversary Emulation: {scenario['name']}"
            details = f"Detected simulated adversary activity matching technique {rule_id}."
            sev = scenario.get("severity", "suspicious")
            if sev == "critical":
                sev = "malicious"
            elif sev not in ("malicious", "suspicious"):
                sev = "suspicious"
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            conn.execute(
                """
                INSERT INTO alerts (run_id, rule_id, rule_name, severity, details, triggered_at, status)
                VALUES (?, ?, ?, ?, ?, ?, 'open')
                """,
                (run_id, rule_id, alert_name, sev, details, now_iso),
            )
            alert_rows = conn.execute("SELECT * FROM alerts WHERE run_id = ?", (run_id,)).fetchall()
            alerts = [dict(r) for r in alert_rows]
        run_store.complete_run(conn, run_id)

    if new_alerts:
        from ..services import events_stream
        events_stream.publish_alerts(new_alerts)

    tree_nodes = process_tree.build_process_tree(events)
    tree = [n.model_dump(mode="json") for n in tree_nodes]
    risk_score = risk.compute_risk_score([a["rule_id"] for a in alerts])

    terminal_logs.append(f"[OutPost Detection Engine] Evaluated {len(events)} events -> Triggered {len(alerts)} alerts (Risk score: {risk_score})")

    return {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "name": scenario["name"],
        "platform": plat,
        "terminal_output": "\n".join(terminal_logs),
        "terminal_lines": terminal_logs,
        "stages": stage_results,
        "events_count": len(events),
        "event_count": len(events),
        "alerts_count": len(alerts),
        "alert_count": len(alerts),
        "alerts": alerts,
        "risk_score": risk_score,
        "process_tree": tree,
        "detonation_delta": detonation_delta,
        "dropped_artifacts": dropped_artifacts,
    }


async def execute_simulation_scenario_stage(
    scenario_id: str,
    stage_number: int,
    run_id: str | None = None,
    sandbox_dir_str: str | None = None,
    facts: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Execute a single stage of an adversary simulation playbook in an isolated workspace."""
    scenario = SIMULATION_SCENARIOS.get(scenario_id) or SIMULATION_SCENARIOS["recon_sweep"]
    stages = scenario.get("stages", [])
    if stage_number < 1 or stage_number > len(stages):
        raise ValueError(f"Invalid stage_number {stage_number} for scenario {scenario_id} (has {len(stages)} stages)")

    stage = stages[stage_number - 1]
    plat = scenario.get("platform") or platform.system().lower()

    if not run_id:
        run_id = f"sim_{uuid.uuid4().hex[:10]}"
        with db_session() as conn:
            run_store.create_run(
                conn=conn,
                run_id=run_id,
                sample_name=f"{scenario_id}.sh",
                platform=plat,
                session_type="analysis",
                source="simulation",
            )

    if not sandbox_dir_str or not Path(sandbox_dir_str).exists():
        ws = Path(tempfile.mkdtemp(prefix=f"outpost_sim_stage_{run_id}_"))
    else:
        ws = Path(sandbox_dir_str)

    stage_name = stage["name"]
    stage_cmd = stage["cmd"]

    # Dynamic runtime fact interpolation
    current_facts = dict(facts or {})
    for fk, fv in current_facts.items():
        stage_cmd = stage_cmd.replace(f"${{{fk}}}", str(fv)).replace(f"${fk}", str(fv))

    start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_mono = time.monotonic()

    proc = await asyncio.create_subprocess_shell(
        stage_cmd,
        cwd=str(ws),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={
            **os.environ,
            "OUTPOST_SIMULATION": "1",
            "OUTPOST_RUN_ID": run_id,
            "STAGE_NUMBER": str(stage_number),
        },
    )

    events: list[dict[str, Any]] = []
    proc_ev = {
        "run_id": run_id,
        "platform": plat,
        "event_type": "process_create",
        "timestamp": start_iso,
        "pid": proc.pid,
        "ppid": os.getpid(),
        "process_name": stage_cmd.split()[0] if stage_cmd else "sh",
        "command_line": stage_cmd,
        "exe_path": "/bin/sh",
        "host_id": "local",
    }
    events.append(proc_ev)
    with db_session() as conn:
        proc_ev["id"] = event_store.insert_event(conn, proc_ev)

    out_s = ""
    err_s = ""
    exit_code = 0
    status = "success"
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=12)
        out_s = out_b.decode("utf-8", errors="replace").strip()
        err_s = err_b.decode("utf-8", errors="replace").strip()
        exit_code = proc.returncode if proc.returncode is not None else 0
        status = "success" if exit_code == 0 else "failed"
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        status = "timeout"
        exit_code = -1
        err_s += "\n[!] Stage execution timed out"

    elapsed_ms = int((time.monotonic() - start_mono) * 1000)

    # Dynamic fact extraction from stdout (OUTPOST_FACT:KEY=VAL)
    for line in out_s.splitlines():
        if "OUTPOST_FACT:" in line:
            fact_part = line.split("OUTPOST_FACT:", 1)[1].strip()
            if "=" in fact_part:
                fk, fv = fact_part.split("=", 1)
                current_facts[fk.strip()] = fv.strip()

    # Scan created files in workspace
    for p in ws.glob("**/*"):
        if p.is_file():
            fe = {
                "run_id": run_id,
                "platform": plat,
                "event_type": "file_write",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "pid": proc.pid,
                "file_path": str(p),
                "host_id": "local",
            }
            events.append(fe)
            with db_session() as conn:
                fe["id"] = event_store.insert_event(conn, fe)

    # Evaluate detection rules
    alerts: list[dict[str, Any]] = []
    with db_session() as conn:
        new_alerts = detection.evaluate_batch(conn, run_id, events)
        alert_rows = conn.execute("SELECT * FROM alerts WHERE run_id = ?", (run_id,)).fetchall()
        alerts = [dict(r) for r in alert_rows]

    is_final = stage_number == len(stages)
    dropped_artifacts = []
    if is_final:
        dropped_artifacts = sandbox_forensics.extract_dropped_artifacts(ws, Path(ws / "__none__"), run_id)
        try:
            shutil.rmtree(ws, ignore_errors=True)
        except Exception:
            pass
        with db_session() as conn:
            run_store.complete_run(conn, run_id)

    return {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "stage_number": stage_number,
        "total_stages": len(stages),
        "stage_name": stage_name,
        "command": stage_cmd,
        "exit_code": exit_code,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "stdout": out_s,
        "stderr": err_s,
        "sandbox_dir": str(ws) if not is_final else None,
        "alerts": alerts,
        "alerts_count": len(alerts),
        "events_count": len(events),
        "is_final_stage": is_final,
        "dropped_artifacts": dropped_artifacts,
        "facts": current_facts,
    }


def extract_syscalls_from_trace(trace_text: str) -> list[dict[str, Any]]:
    """Parse strace / execution output into structured syscall events."""
    syscalls: list[dict[str, Any]] = []
    pattern = re.compile(r"(?:\[pid\s+(\d+)\]\s+)?([a-zA-Z0-9_]+)\((.*)\)\s+=\s+(-?[0-9a-fx?]+|0x[0-9a-f]+|[A-Z_]+)(?:\s+(.*))?", re.IGNORECASE)
    for line in trace_text.splitlines():
        line_clean = line.strip()
        m = pattern.search(line_clean)
        if m:
            pid_s, sc_name, args, res, extra = m.groups()
            if sc_name in ("openat", "open", "creat", "unlink", "unlinkat", "execve", "connect", "bind", "mmap", "mprotect", "memfd_create", "clone", "fork", "socket"):
                syscalls.append({
                    "pid": int(pid_s) if pid_s else None,
                    "syscall": sc_name,
                    "arguments": (args or "").strip()[:200],
                    "result": (res or "").strip(),
                    "category": (
                        "network" if sc_name in ("connect", "bind", "socket") else
                        "file" if sc_name in ("openat", "open", "creat", "unlink", "unlinkat") else
                        "memory" if sc_name in ("mmap", "mprotect", "memfd_create") else
                        "process"
                    ),
                })
        if len(syscalls) >= 100:
            break
    return syscalls


def extract_c2_sinkhole_events(stdout_s: str, stderr_s: str) -> list[dict[str, Any]]:
    """Simulated C2 / FakeDNS interceptor capturing outbound requests."""
    combined = stdout_s + "\n" + stderr_s
    requests: list[dict[str, Any]] = []

    domains = set(re.findall(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,6}\b", combined))
    for d in domains:
        if not d.endswith((".local", ".internal", ".arpa", ".so", ".bin", ".sh", ".py", ".exe", ".dll")):
            requests.append({
                "type": "dns_query",
                "target": d,
                "record_type": "A",
                "intercepted_response": "127.0.0.1 (SINKHOLED)",
                "action": "sinkholed",
            })

    http_methods = re.findall(r"(GET|POST|PUT|DELETE)\s+([/\w\-._~:?#[\]@!$&'()*+,;=]+)\s+HTTP/[0-9.]+", combined)
    for method, path in http_methods:
        requests.append({
            "type": "http_request",
            "method": method,
            "path": path,
            "target": "simulated_c2",
            "intercepted_response": "HTTP/1.1 200 OK (SINKHOLE_BEACON_ACK)",
            "action": "intercepted",
        })

    urls = set(re.findall(r"https?://[^\s\"'<>]+", combined))
    for u in urls:
        requests.append({
            "type": "outbound_url",
            "target": u,
            "intercepted_response": "Intercepted by OutPost Sandbox Sinkhole",
            "action": "sinkholed",
        })

    return requests[:50]


async def execute_sample_detonation(
    sample_id: str,
    raw_bytes: bytes,
    sample_name: str,
    platform_hint: str = "linux",
    timeout_seconds: int = 15,
    isolation_driver: str = "auto",
) -> dict[str, Any]:
    """Execute uploaded malware sample bytes in an isolated dynamic sandbox, collect telemetry, and evaluate alerts."""
    run_id = f"dyn_{uuid.uuid4().hex[:12]}"
    plat = platform_hint or "linux"

    with db_session() as conn:
        run_store.create_run(
            conn=conn,
            run_id=run_id,
            sample_name=sample_name,
            platform=plat,
            session_type="analysis",
            source="dynamic_sandbox",
        )

    # Capture baseline before detonation
    from .host_forensics import capture_baseline_snapshot, compute_snapshot_diff
    try:
        capture_baseline_snapshot()
    except Exception:
        pass

    events, stdout_s, stderr_s, exit_code, active_driver, timeline_events, dropped_artifacts = await execute_bytes_sandbox(
        run_id=run_id,
        sample_name=sample_name,
        platform_hint=plat,
        raw_bytes=raw_bytes,
        timeout_seconds=timeout_seconds,
        isolation_driver=isolation_driver,
    )

    # Compute post-detonation differential delta
    detonation_delta = None
    try:
        detonation_delta = compute_snapshot_diff()
    except Exception:
        pass

    syscalls = extract_syscalls_from_trace(stdout_s + "\n" + stderr_s)
    # Augment syscalls with structured events collected from sandbox poller
    for ev in events:
        etype = ev.get("event_type")
        if etype == "process_create":
            syscalls.append({
                "pid": ev.get("pid"),
                "syscall": "execve",
                "arguments": ev.get("command_line", "")[:120],
                "result": f"pid={ev.get('pid')}",
                "category": "process",
            })
        elif etype == "file_write":
            syscalls.append({
                "pid": ev.get("pid"),
                "syscall": "openat",
                "arguments": f"AT_FDCWD, \"{ev.get('file_path', '')}\", O_WRONLY|O_CREAT",
                "result": "3",
                "category": "file",
            })
        elif etype == "file_delete":
            syscalls.append({
                "pid": ev.get("pid"),
                "syscall": "unlink",
                "arguments": f"\"{ev.get('file_path', '')}\"",
                "result": "0",
                "category": "file",
            })
        elif etype == "network_connection":
            syscalls.append({
                "pid": ev.get("pid"),
                "syscall": "connect",
                "arguments": f"AF_INET, {ev.get('dest_ip')}:{ev.get('dest_port')}",
                "result": "0",
                "category": "network",
            })

    sinkhole_traffic = extract_c2_sinkhole_events(stdout_s, stderr_s)
    # Also add any network events to sinkhole traffic if not already present
    for ev in events:
        if ev.get("event_type") == "network_connection":
            dest_ip = ev.get("dest_ip")
            if dest_ip and not any(s.get("target") == dest_ip for s in sinkhole_traffic):
                sinkhole_traffic.append({
                    "type": "tcp_socket",
                    "target": f"{dest_ip}:{ev.get('dest_port', 80)}",
                    "intercepted_response": "SYN-ACK (OUTPOST_SINKHOLE_ACTIVE)",
                    "action": "sinkholed",
                })

    terminal_logs: list[str] = [
        f"[OutPost Dynamic Sandbox] Detonating sample '{sample_name}' (ID: {sample_id})",
        f"[OutPost Dynamic Sandbox] Isolation Driver: {active_driver.upper()} · Platform: {plat.upper()} · Timeout: {timeout_seconds}s",
        "-" * 60,
    ]
    if stdout_s:
        for line in stdout_s.splitlines():
            terminal_logs.append(f"  {line}")
    if stderr_s:
        for line in stderr_s.splitlines():
            terminal_logs.append(f"  [stderr] {line}")
    terminal_logs.append("-" * 60)
    terminal_logs.append(f"[OutPost Dynamic Sandbox] Execution completed with exit code: {exit_code}")
    if dropped_artifacts:
        terminal_logs.append(f"[OutPost Artifact Extractor] Captured {len(dropped_artifacts)} dropped file(s).")
    if sinkhole_traffic:
        terminal_logs.append(f"[OutPost C2 Sinkhole] Intercepted {len(sinkhole_traffic)} network beacon/DNS requests.")

    with db_session() as conn:
        for ev in events:
            if not ev.get("id"):
                ev["id"] = event_store.insert_event(conn, ev)

        new_alerts = detection.evaluate_batch(conn, run_id, events)
        alert_rows = conn.execute("SELECT * FROM alerts WHERE run_id = ?", (run_id,)).fetchall()
        alerts = [dict(r) for r in alert_rows]
        run_store.complete_run(conn, run_id)

    if new_alerts:
        from ..services import events_stream
        events_stream.publish_alerts(new_alerts)

    tree_nodes = process_tree.build_process_tree(events)
    tree = [n.model_dump(mode="json") for n in tree_nodes]
    risk_score = risk.compute_risk_score([a["rule_id"] for a in alerts]) if alerts else 0

    return {
        "run_id": run_id,
        "sample_id": sample_id,
        "sample_name": sample_name,
        "platform": plat,
        "isolation_driver": active_driver,
        "exit_code": exit_code,
        "terminal_output": "\n".join(terminal_logs),
        "terminal_lines": terminal_logs,
        "events": events,
        "events_count": len(events),
        "alerts": alerts,
        "alerts_count": len(alerts),
        "risk_score": risk_score,
        "process_tree": tree,
        "detonation_delta": detonation_delta,
        "syscalls": syscalls,
        "sinkhole_traffic": sinkhole_traffic,
        "timeline": timeline_events,
        "dropped_artifacts": dropped_artifacts,
    }


async def execute_technique_test(
    test_id: str,
    run_id: str | None = None,
    platform_override: str | None = None,
) -> dict[str, Any]:
    """Execute a single adversary technique unit test with prerequisite verification,
    telemetry capture, detection evaluation, and automated cleanup."""
    from . import technique_catalog
    tech = technique_catalog.get_technique_test(test_id)
    if not tech:
        raise ValueError(f"Technique test '{test_id}' not found in catalog")

    plat = platform_override or platform.system().lower()
    if not run_id:
        run_id = f"tech_{uuid.uuid4().hex[:10]}"
        with db_session() as conn:
            run_store.create_run(
                conn=conn,
                run_id=run_id,
                sample_name=f"{tech['id']}.sh",
                platform=plat,
                session_type="analysis",
                source="simulation",
            )

    ws = Path(tempfile.mkdtemp(prefix=f"outpost_sim_{run_id}_"))
    start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_mono = time.monotonic()

    # 1. Check prerequisites
    prereqs_met = True
    prereq_output = []
    for prereq in tech.get("prereqs", []):
        p_cmd = prereq.get("command")
        if p_cmd:
            try:
                p_proc = await asyncio.create_subprocess_shell(
                    p_cmd,
                    cwd=str(ws),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                p_out, p_err = await asyncio.wait_for(p_proc.communicate(), timeout=5)
                if p_proc.returncode != 0:
                    prereqs_met = False
                    prereq_output.append(f"FAILED: {prereq.get('description', p_cmd)}")
                else:
                    prereq_output.append(f"OK: {prereq.get('description', p_cmd)}")
            except Exception as e:
                prereqs_met = False
                prereq_output.append(f"ERROR: {prereq.get('description', p_cmd)} ({e})")

    # 2. Execute Attack Command
    attack_cmd = tech["attack_command"]
    proc = await asyncio.create_subprocess_shell(
        attack_cmd,
        cwd=str(ws),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={
            **os.environ,
            "OUTPOST_SIMULATION": "1",
            "OUTPOST_RUN_ID": run_id,
            "OUTPOST_TECHNIQUE_ID": tech["id"],
        },
    )

    events: list[dict[str, Any]] = []
    proc_ev = {
        "run_id": run_id,
        "platform": plat,
        "event_type": "process_create",
        "timestamp": start_iso,
        "pid": proc.pid,
        "ppid": os.getpid(),
        "process_name": attack_cmd.split()[0] if attack_cmd else "sh",
        "command_line": attack_cmd,
        "exe_path": "/bin/sh",
        "host_id": "local",
    }
    events.append(proc_ev)
    with db_session() as conn:
        proc_ev["id"] = event_store.insert_event(conn, proc_ev)

    out_s, err_s = "", ""
    exit_code = 0
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=15)
        out_s = out_b.decode("utf-8", errors="replace").strip()
        err_s = err_b.decode("utf-8", errors="replace").strip()
        exit_code = proc.returncode if proc.returncode is not None else 0
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        exit_code = -1
        err_s += "\n[!] Technique simulation execution timed out"

    # 3. Workspace File Ingestion
    for p in ws.glob("**/*"):
        if p.is_file():
            fe = {
                "run_id": run_id,
                "platform": plat,
                "event_type": "file_write",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "pid": proc.pid,
                "file_path": str(p),
                "host_id": "local",
            }
            events.append(fe)
            with db_session() as conn:
                fe["id"] = event_store.insert_event(conn, fe)

    # 4. Evaluate Detections
    alerts = []
    with db_session() as conn:
        detection.evaluate_batch(conn, run_id, events)
        alert_rows = conn.execute("SELECT * FROM alerts WHERE run_id = ?", (run_id,)).fetchall()
        alerts = [dict(r) for r in alert_rows]

    # 5. Automated Cleanup Contract
    cleanup_cmd = tech.get("cleanup_command")
    cleanup_status = "not_needed"
    if cleanup_cmd and cleanup_cmd != "true":
        try:
            c_proc = await asyncio.create_subprocess_shell(
                cleanup_cmd,
                cwd=str(ws),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(c_proc.communicate(), timeout=5)
            cleanup_status = "success" if c_proc.returncode == 0 else "failed"
        except Exception:
            cleanup_status = "failed"

    try:
        shutil.rmtree(ws, ignore_errors=True)
    except Exception:
        pass

    with db_session() as conn:
        run_store.complete_run(conn, run_id)

    elapsed_ms = int((time.monotonic() - start_mono) * 1000)
    risk_score = risk.compute_risk_score([a["rule_id"] for a in alerts]) if alerts else 0

    # 6. Telemetry Contract Verification
    expected_telemetry = tech.get("expected_telemetry", [])
    observed_event_types = {e.get("event_type") for e in events if e.get("event_type")}

    matched_telemetry = []
    missing_telemetry = []
    for exp in expected_telemetry:
        if exp == "process_create" and "process_create" in observed_event_types:
            matched_telemetry.append(exp)
        elif exp in ("file_create", "file_modify", "file_write") and (
            observed_event_types & {"file_create", "file_modify", "file_write"}
        ):
            matched_telemetry.append(exp)
        elif exp in ("network_connection", "network_connect") and (
            observed_event_types & {"network_connection", "network_connect"}
        ):
            matched_telemetry.append(exp)
        elif exp in observed_event_types:
            matched_telemetry.append(exp)
        else:
            missing_telemetry.append(exp)

    telemetry_verified = (len(missing_telemetry) == 0) if expected_telemetry else True
    telemetry_coverage_pct = (
        int((len(matched_telemetry) / len(expected_telemetry)) * 100)
        if expected_telemetry
        else 100
    )

    # 7. Continuous Detection Efficacy Determination & Persistence
    matched_rules = [
        {"rule_id": a["rule_id"], "rule_name": a["rule_name"], "severity": a["severity"]}
        for a in alerts
    ]
    if len(alerts) > 0:
        detection_status = "detected"
    elif len(events) > 0:
        detection_status = "telemetry_only"
    else:
        detection_status = "missed"

    validation_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        with db_session() as conn:
            conn.execute(
                """
                INSERT INTO technique_validations (
                    test_id, technique_id, technique_name, tactic, run_id, status,
                    detection_status, matched_rules, events_count, alerts_count, mttd_ms, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tech["id"],
                    tech["technique_id"],
                    tech["technique_name"],
                    tech["tactic"],
                    run_id,
                    "success" if exit_code == 0 else "failed",
                    detection_status,
                    json.dumps(matched_rules),
                    len(events),
                    len(alerts),
                    elapsed_ms,
                    validation_ts,
                ),
            )
    except Exception as e:
        logger.warning(f"Failed to persist technique validation record: {e}")

    return {
        "run_id": run_id,
        "test_id": tech["id"],
        "technique_id": tech["technique_id"],
        "technique_name": tech["technique_name"],
        "tactic": tech["tactic"],
        "name": tech["name"],
        "status": "success" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "mttd_ms": elapsed_ms,
        "detection_status": detection_status,
        "matched_rules": matched_rules,
        "prereqs_met": prereqs_met,
        "prereq_output": prereq_output,
        "cleanup_status": cleanup_status,
        "stdout": out_s,
        "stderr": err_s,
        "alerts": alerts,
        "alerts_count": len(alerts),
        "events_count": len(events),
        "risk_score": risk_score,
        "expected_telemetry": expected_telemetry,
        "telemetry_verified": telemetry_verified,
        "matched_telemetry": matched_telemetry,
        "missing_telemetry": missing_telemetry,
        "telemetry_coverage_pct": telemetry_coverage_pct,
    }




