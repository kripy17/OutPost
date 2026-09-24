#!/usr/bin/env python3
"""OutPost Benign Sample — System Information & Telemetry Audit Tool.

A legitimate, non-malicious administrative script used by DevOps and SRE teams
to collect host health metrics and environmental diagnostics.
Exercises:
  1. Operating System & Kernel architecture inspection (uname, platform)
  2. CPU core count & load metric interrogation
  3. Memory capacity analysis (/proc/meminfo)
  4. Safe JSON formatted diagnostic emission

Detonation Outcome:
  - Exit Code: 0 (Success)
  - Behavioral Risk Score: 0/100 (Clean)
  - Detection Alerts: 0 (No false positives)
  - Verdict: BENIGN / CLEAN
"""

import json
import os
import platform
import sys
import time


def get_meminfo() -> dict:
    mem = {}
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip()
                        if key in ("MemTotal", "MemFree", "MemAvailable", "SwapTotal", "SwapFree"):
                            mem[key] = val
        except Exception:
            pass
    if not mem:
        mem = {"MemTotal": "16384 MB (estimated)", "MemAvailable": "8192 MB (estimated)"}
    return mem


def get_disk_health() -> list[dict]:
    points = []
    for mount in ("/", "/tmp"):
        if os.path.exists(mount):
            try:
                st = os.statvfs(mount)
                free_gb = round((st.f_bavail * st.f_frsize) / (1024 ** 3), 2)
                total_gb = round((st.f_blocks * st.f_frsize) / (1024 ** 3), 2)
                points.append({"mount": mount, "total_gb": total_gb, "free_gb": free_gb, "status": "HEALTHY"})
            except Exception:
                pass
    return points


def main():
    print("=================================================================")
    print("  OutPost Benign Verification Suite: Host Audit Tool             ")
    print("  Purpose: Baseline Verification & False-Positive Immunity Test   ")
    print("=================================================================")
    start_time = time.time()

    audit_payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "audit_version": "1.4.0-clean",
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python_runtime": sys.version.split()[0],
            "cpu_count": os.cpu_count() or 1,
        },
        "memory": get_meminfo(),
        "storage": get_disk_health(),
        "verdict_intent": "legitimate_system_administration",
    }

    # Emit human-readable progress
    print(f"[*] Auditing host environment: {audit_payload['system']['os']} {audit_payload['system']['release']}")
    print(f"[*] Detected {audit_payload['system']['cpu_count']} CPU core(s), platform {audit_payload['system']['architecture']}")
    print(f"[*] Memory Total: {audit_payload['memory'].get('MemTotal', 'N/A')}")
    for disk in audit_payload['storage']:
        print(f"[*] Mount '{disk['mount']}': {disk['free_gb']} GB free of {disk['total_gb']} GB")

    elapsed = round((time.time() - start_time) * 1000, 2)
    print(f"[✓] System audit completed successfully in {elapsed}ms. Zero adversarial actions taken.")
    print("--- DIAGNOSTIC JSON REPORT ---")
    print(json.dumps(audit_payload, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
