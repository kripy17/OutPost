#!/usr/bin/env python3
"""OutPost Benign Sample — Microservice Health & Liveness Probe.

A legitimate, non-malicious client script used in Kubernetes / cloud environments
to ping local service endpoints, measure latency, and verify operational readiness.
Exercises:
  1. Safe local network socket connectivity check (127.0.0.1)
  2. Latency measurement
  3. Structured JSON status reporting

Detonation Outcome:
  - Exit Code: 0 (Success)
  - Behavioral Risk Score: 0/100 (Clean)
  - Detection Alerts: 0 (No false positives)
  - Verdict: BENIGN / CLEAN
"""

import json
import socket
import sys
import time


def check_port(host: str, port: int, timeout: float = 0.5) -> dict:
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((host, port))
        latency_ms = round((time.time() - start) * 1000, 2)
        s.close()
        is_open = (res == 0)
        return {"host": host, "port": port, "open": is_open, "latency_ms": latency_ms}
    except Exception as e:
        return {"host": host, "port": port, "open": False, "error": str(e)}


def main():
    print("=================================================================")
    print("  OutPost Benign Verification Suite: Service Health Probe        ")
    print("  Purpose: Benign Local Socket Healthcheck (Zero Beaconing)      ")
    print("=================================================================")

    target_ports = [8001, 5174, 80, 443]
    results = []

    for port in target_ports:
        status = check_port("127.0.0.1", port)
        results.append(status)
        state_str = "OPEN / LISTENING" if status.get("open") else "CLOSED / UNREACHABLE"
        print(f"[*] Probed localhost:{port} -> {state_str} ({status.get('latency_ms', 0)} ms)")

    summary = {
        "probe_type": "liveness_healthcheck",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": "benign_diagnostics",
        "endpoints_checked": len(results),
        "results": results,
    }

    print("[✓] Healthcheck probe complete. All communication strictly confined to loopback interface.")
    print("--- HEALTH PROBE JSON ---")
    print(json.dumps(summary, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
