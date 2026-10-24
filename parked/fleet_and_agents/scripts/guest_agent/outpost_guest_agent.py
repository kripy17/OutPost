#!/usr/bin/env python3
"""OutPost Guest VM Detonation Agent (outpost-guest-agent).

Lightweight, zero-dependency HTTP agent designed to run inside isolated
Windows or Linux guest Virtual Machines (QEMU / KVM / Proxmox / VirtualBox).

Listens on guest port 8009. Provides:
- Health and environment checks (GET /health)
- Native sample dropping and execution (POST /detonate)
- Windows Sysmon / Event Log (EVTX) telemetry extraction
- In-guest network socket and dropped file harvesting
- Snapshot-safe ephemeral execution

Contract:
- Port: 8009
- Authentication: Optional Bearer token via OUTPOST_GUEST_TOKEN
"""

import base64
import datetime
import hashlib
import http.server
import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("outpost-guest-agent")

PORT = int(os.environ.get("OUTPOST_GUEST_PORT", "8009"))
AUTH_TOKEN = os.environ.get("OUTPOST_GUEST_TOKEN", "").strip()


def calculate_entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    occ = [0] * 256
    for b in data:
        occ[b] += 1
    ent = 0.0
    total = len(data)
    for count in occ:
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def get_guest_system_info() -> dict[str, Any]:
    return {
        "agent": "outpost-guest-agent",
        "version": "1.0.0",
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "python": sys.version.split()[0],
    }


def query_windows_sysmon_events(since_time_iso: str | None = None) -> list[dict[str, Any]]:
    """Query Sysmon operational channel for events created during the detonation."""
    if platform.system().lower() != "windows":
        return []

    events = []
    try:
        # Query via PowerShell Get-WinEvent for portable zero-dependency execution
        ps_script = """
        $channel = 'Microsoft-Windows-Sysmon/Operational'
        if (-not (Get-WinEvent -ListProvider *sysmon* -ErrorAction SilentlyContinue)) {
            Write-Output '[]'
            exit
        }
        $events = Get-WinEvent -LogName $channel -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                Id = $_.Id
                TimeCreated = $_.TimeCreated.ToString('o')
                Message = $_.Message
            }
        }
        $events | ConvertTo-Json -Compress
        """
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw = json.loads(proc.stdout.strip())
            if isinstance(raw, dict):
                events.append(raw)
            elif isinstance(raw, list):
                events.extend(raw)
    except Exception as exc:
        log.warning("Sysmon query failed: %s", exc)

    return events


def query_guest_network_sockets() -> list[dict[str, Any]]:
    """Capture active listening and established connections from netstat."""
    sockets = []
    try:
        proc = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP"):
                proto = parts[0].lower()
                local = parts[1]
                remote = parts[2] if len(parts) >= 3 else "*:*"
                state = parts[3] if len(parts) >= 4 and proto == "tcp" else "LISTENING"
                pid = parts[-1] if parts[-1].isdigit() else "0"
                sockets.append({
                    "protocol": proto,
                    "local": local,
                    "remote": remote,
                    "state": state,
                    "pid": int(pid),
                })
    except Exception as exc:
        log.warning("Socket capture failed: %s", exc)
    return sockets


def execute_sample_payload(
    sample_bytes: bytes,
    filename: str,
    timeout_seconds: int = 15,
    custom_args: list[str] | None = None,
) -> dict[str, Any]:
    """Drop and execute payload inside guest environment, monitoring artifacts and telemetry."""
    temp_dir = Path(tempfile.mkdtemp(prefix="outpost_guest_detonation_"))
    target_path = temp_dir / (filename or "sample.exe")
    target_path.write_bytes(sample_bytes)

    if platform.system().lower() != "windows":
        try:
            target_path.chmod(0o755)
        except Exception:
            pass

    cmd = [str(target_path)]
    if custom_args:
        cmd.extend(custom_args)

    start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_mono = time.monotonic()
    stdout_text = ""
    stderr_text = ""
    exit_code = 0

    log.info("Executing sample: %s with timeout %ds", target_path, timeout_seconds)
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(temp_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            out, err = proc.communicate(timeout=timeout_seconds)
            stdout_text = out or ""
            stderr_text = err or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_text, stderr_text = proc.communicate()
            exit_code = -1
            stderr_text += "\n[Guest Agent] Detonation reached execution timeout limit."
    except Exception as exc:
        exit_code = 127
        stderr_text += f"\n[Guest Agent] Execution launch error: {exc}"

    elapsed_ms = int((time.monotonic() - start_mono) * 1000)

    # Collect dropped artifacts from execution directory
    dropped_artifacts = []
    try:
        for f in temp_dir.rglob("*"):
            if f.is_file() and f != target_path:
                try:
                    b = f.read_bytes()
                    h256 = hashlib.sha256(b).hexdigest()
                    ent = calculate_entropy(b)
                    dropped_artifacts.append({
                        "name": f.name,
                        "rel_path": str(f.relative_to(temp_dir)),
                        "size_bytes": len(b),
                        "sha256": h256,
                        "entropy": ent,
                        "is_high_entropy": ent > 7.0,
                    })
                except Exception:
                    pass
    except Exception:
        pass

    sysmon_events = query_windows_sysmon_events(start_iso)
    active_sockets = query_guest_network_sockets()

    return {
        "status": "completed",
        "guest_info": get_guest_system_info(),
        "filename": filename,
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "stdout": stdout_text[:8000],
        "stderr": stderr_text[:8000],
        "sysmon_events": sysmon_events,
        "active_sockets": active_sockets,
        "dropped_artifacts": dropped_artifacts,
    }


class GuestAgentRequestHandler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: dict[str, Any]):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        if not AUTH_TOKEN:
            return True
        auth_header = self.headers.get("Authorization", "")
        if auth_header == f"Bearer {AUTH_TOKEN}":
            return True
        self._send_json(401, {"error": "Unauthorized: invalid guest agent token"})
        return False

    def do_GET(self):
        if not self._check_auth():
            return
        if self.path == "/health":
            self._send_json(200, {
                "status": "ready",
                "system": get_guest_system_info(),
            })
        elif self.path == "/sockets":
            self._send_json(200, {
                "sockets": query_guest_network_sockets(),
            })
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        if not self._check_auth():
            return
        if self.path == "/detonate":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_len)
                req_data = json.loads(raw_body.decode("utf-8"))

                sample_b64 = req_data.get("sample_base64", "")
                sample_bytes = base64.b64decode(sample_b64)
                filename = req_data.get("filename", "sample.exe")
                timeout = int(req_data.get("timeout", 15))
                args = req_data.get("args", [])

                result = execute_sample_payload(
                    sample_bytes=sample_bytes,
                    filename=filename,
                    timeout_seconds=timeout,
                    custom_args=args,
                )
                self._send_json(200, result)
            except Exception as exc:
                log.exception("Detonation failure")
                self._send_json(500, {"error": f"Guest detonation error: {exc}"})
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def log_message(self, format, *args):
        log.info("%s - %s", self.address_string(), format % args)


def main():
    server = http.server.HTTPServer(("0.0.0.0", PORT), GuestAgentRequestHandler)
    log.info("OutPost Guest Agent active on port %d (%s %s)", PORT, platform.system(), platform.release())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down guest agent...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
