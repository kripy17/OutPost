"""Dynamic Execution Sandbox & Process Tracing Service.

Executes suspicious artifacts, scripts, and binaries inside a throwaway
temporary directory with a bounded execution timeout, a sanitized payload
filename (traversal-proof), and a minimal child environment (no operator
secrets leak to the sample). This is containment hygiene, NOT strong
isolation: for real isolation run OutPost inside a container/VM or dispatch
to an external provider. Extracts execution telemetry, maps process trees,
network calls, and evaluates OutPost behavioral detection rules against
real activity.
"""

import asyncio
import datetime
import os
import platform
import re
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from ..core import config
from ..core.db import db_session
from ..models import event as event_store
from ..models import run as run_store
from ..models import samples as samples_store
from ..services import detection, killchain, process_tree, risk, screenshots


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
        elif shutil.which("wine"):
            return ["wine"]

    # Fallback executable
    return []


async def execute_and_trace(
    sample_id: str,
    timeout_seconds: int = 10,
    custom_args: list[str] | None = None,
) -> dict[str, Any]:
    """Execute sample in an isolated sandbox workspace and collect real execution telemetry."""
    with db_session() as conn:
        sample = samples_store.get_sample(conn, sample_id)
    if not sample:
        raise ValueError(f"Sample {sample_id} not found in vault")

    sample_name = sample.get("original_name") or sample.get("name") or "sample.bin"
    # Defense-in-depth: never trust an operator-supplied filename for path
    # joins. Strip to the bare basename and reject traversal-shaped names so
    # the payload can only ever land inside the mkdtemp cage below.
    payload_name = Path(sample_name).name
    if not payload_name or payload_name in {".", ".."} or "/" in sample_name or "\\" in sample_name:
        payload_name = "sample.bin"
    sample_plat = sample.get("detected_platform") or sample.get("platform") or platform.system().lower()

    raw_bytes = None
    try:
        sample_path = config.SAMPLES_DIR / f"{sample_id}.bin"
        if sample_path.exists():
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

    runner = detect_runner(raw_bytes, payload_name)
    if runner is None:
        runner = []

    sandbox_dir = Path(tempfile.mkdtemp(prefix=f"outpost_sandbox_{run_id}_"))
    target_file = sandbox_dir / payload_name

    # Periodic screen capture while the detonation runs (docs/10 #4). A no-op
    # unless OUTPOST_SCREENSHOT_CMD is configured — reported honestly either way.
    shot_session = screenshots.ScreenshotSession(run_id)
    shot_session.start()

    events_batch: list[dict[str, Any]] = []
    stdout_data = ""
    stderr_data = ""
    exit_code = 0

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

        start_dt = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Emit initial process create event
        main_pid = os.getpid() + 1000 + (hash(run_id) % 5000)
        events_batch.append({
            "run_id": run_id,
            "platform": sample_plat,
            "event_type": "process_create",
            "timestamp": start_dt,
            "pid": main_pid,
            "ppid": os.getpid(),
            "process_name": sample_name,
            "command_line": " ".join(cmd),
            "exe_path": str(target_file),
            "host_id": "local",
        })

        try:
            # Minimal environment: the detonated sample is untrusted code, so
            # it must never inherit operator secrets (intel API keys, sandbox
            # provider credentials, notification webhooks).
            child_env: dict[str, str] = {
                key: os.environ[key]
                for key in ("PATH", "LANG", "LC_ALL", "TMPDIR", "HOME", "SYSTEMROOT", "COMSPEC", "WINDIR")
                if key in os.environ
            }
            child_env["OUTPOST_SANDBOX"] = "1"
            child_env["OUTPOST_RUN_ID"] = run_id
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(sandbox_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env,
            )
            main_pid = proc.pid

            # ── Real-time /proc telemetry ──────────────────────────────────
            # Poll /proc for child processes and network connections while
            # the sample runs — captures what a parent process can't see.
            stop_monitoring = asyncio.Event()

            # Snapshot the system's pre-existing TCP connections BEFORE the
            # sample starts so only NEW connections are reported (otherwise
            # the monitor floods with unrelated browser/system traffic).
            _pre_existing_conns: set[str] = set()
            try:
                with open("/proc/net/tcp") as _fh:  # noqa: ASYNC230
                    for _line in _fh.readlines()[1:]:
                        _parts = _line.split()
                        if len(_parts) >= 4:
                            _pre_existing_conns.add(_parts[2])
            except OSError:
                pass

            async def _monitor() -> None:
                """Sample /proc for child processes + new TCP connections."""
                seen_pids: set[int] = {main_pid}
                seen_conns: set[str] = set(_pre_existing_conns)
                while not stop_monitoring.is_set():
                    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    # ── Child processes via /proc/<pid>/task/<pid>/children ──
                    # This kernel-provided file lists direct children — much
                    # faster than scanning all of /proc.
                    try:
                        children_path = f"/proc/{main_pid}/task/{main_pid}/children"
                        with open(children_path) as fh:  # noqa: ASYNC230
                            child_pids = [int(x) for x in fh.read().split()]
                    except (OSError, ValueError):
                        child_pids = []
                    for proc_pid in child_pids:
                        if proc_pid in seen_pids:
                            continue
                        seen_pids.add(proc_pid)
                        # Read identity immediately — short-lived processes
                        # vanish between the children listing and the read.
                        cmdline, exe, comm = "", "", ""
                        try:
                            with open(f"/proc/{proc_pid}/cmdline", "rb") as fh:  # noqa: ASYNC230
                                cmdline = fh.read().replace(b"\x00", b" ").decode(errors="replace").strip()
                        except OSError:
                            pass
                        try:
                            with open(f"/proc/{proc_pid}/comm") as fh:  # noqa: ASYNC230
                                comm = fh.read().strip()
                        except OSError:
                            pass
                        try:
                            exe = os.readlink(f"/proc/{proc_pid}/exe")
                        except OSError:
                            pass
                        name = (
                            os.path.basename(exe)
                            or (cmdline.split()[0].rsplit("/", 1)[-1] if cmdline else "")
                            or comm
                            or f"pid_{proc_pid}"
                        )
                        events_batch.append({
                            "run_id": run_id, "platform": sample_plat,
                            "event_type": "process_create", "timestamp": now,
                            "pid": proc_pid, "ppid": main_pid,
                            "process_name": name, "command_line": cmdline[:2000],
                            "exe_path": exe, "host_id": "local",
                        })
                    # ── New TCP connections (delta from pre-snapshot) ──
                    try:
                        with open("/proc/net/tcp") as fh:  # noqa: ASYNC230
                            for line in fh.readlines()[1:]:
                                parts = line.split()
                                if len(parts) < 4:
                                    continue
                                state = parts[3]
                                # 01=ESTABLISHED 02=SYN_SENT 03=SYN_RECV — capture
                                # attempts too, not just completed connections.
                                if state not in ("01", "02", "03"):
                                    continue
                                remote_hex = parts[2]
                                conn_key = f"{remote_hex}:{state}"
                                if conn_key in seen_conns:
                                    continue
                                seen_conns.add(conn_key)
                                try:
                                    ip_hex, port_hex = remote_hex.split(":")
                                    ip = ".".join(str(int(ip_hex[i:i + 2], 16)) for i in range(6, -1, -2))
                                    port = int(port_hex, 16)
                                except (ValueError, IndexError):
                                    continue
                                if ip.startswith(("127.", "0.", "255.")):
                                    continue
                                events_batch.append({
                                    "run_id": run_id, "platform": sample_plat,
                                    "event_type": "network_connection", "timestamp": now,
                                    "dest_ip": ip, "dest_port": port,
                                    "protocol": "tcp", "host_id": "local",
                                })
                    except OSError:
                        pass
                    try:
                        await asyncio.wait_for(stop_monitoring.wait(), timeout=0.3)
                    except asyncio.TimeoutError:
                        pass  # normal poll tick

            monitor_task = asyncio.create_task(_monitor())

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
                stop_monitoring.set()
                monitor_task.cancel()
        except Exception as exc:
            stderr_data += f"\n[OutPost Sandbox] Execution error: {exc}"
            exit_code = 127

        # Scan for dropped files in sandbox_dir
        for p in sandbox_dir.iterdir():
            if p != target_file:
                try:
                    events_batch.append({
                        "run_id": run_id,
                        "platform": sample_plat,
                        "event_type": "file_write",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "pid": main_pid,
                        "file_path": str(p),
                        "host_id": "local",
                    })
                except Exception:
                    pass

        # Inspect stdout/stderr for extracted IPs and network indicators
        ip_matches = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", stdout_data + stderr_data))
        for ip in ip_matches:
            if not ip.startswith(("127.", "0.", "255.")):
                events_batch.append({
                    "run_id": run_id,
                    "platform": sample_plat,
                    "event_type": "network_connection",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "pid": main_pid,
                    "dest_ip": ip,
                    "dest_port": 4444 if ":4444" in (stdout_data + stderr_data) else 80,
                    "protocol": "tcp",
                    "host_id": "local",
                })

        # Store events and evaluate behavioral detection rules
        with db_session() as conn:
            for ev in events_batch:
                event_store.insert_event(conn, ev)
            detection.evaluate_batch(conn, run_id, events_batch)
            run_store.complete_run(conn, run_id)
            alert_rows = conn.execute("SELECT * FROM alerts WHERE run_id = ?", (run_id,)).fetchall()
            alerts = [dict(r) for r in alert_rows]

    finally:
        shot_session.stop()
        try:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
        except Exception:
            pass

    # Build response summary
    tree_nodes = process_tree.build_process_tree(events_batch)
    tree = [n.model_dump(mode="json") for n in tree_nodes]
    risk_score = risk.compute_risk_score([a["rule_id"] for a in alerts])
    chain = killchain.correlate_chain(alerts)

    # Compute verdict — derived from detection severities only. A nonzero exit
    # code alone is not evidence of malice (benign tools crash too); it stays
    # visible via `exit_code` and stderr in the payload.
    verdict = "clean"
    if any(a.get("severity") == "malicious" for a in alerts):
        verdict = "malicious"
    elif any(a.get("severity") in ("suspicious", "elevated") for a in alerts):
        verdict = "suspicious"

    shots = shot_session.shots

    return {
        "run_id": run_id,
        "sample_id": sample_id,
        "sample_name": sample_name,
        "platform": sample_plat,
        "verdict": verdict,
        "exit_code": exit_code,
        "stdout": stdout_data,
        "stderr": stderr_data,
        "risk_score": risk_score,
        "alerts_count": len(alerts),
        "alerts": alerts,
        "process_tree": tree,
        "kill_chain": chain,
        "events_count": len(events_batch),
        "screenshots": {
            "available": bool(shots),
            "capture_status": screenshots.status(),
            "count": len(shots),
            "shots": shots,
        },
    }
