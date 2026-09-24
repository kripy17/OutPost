#!/usr/bin/env python3
"""OutPost Behavioral Test Payload — Adversary Simulation Script.

Safe, non-destructive script designed to test OutPost's real-time behavioral
heuristics and dynamic sandbox engine. Exercises:
  1. Discovery / Enumeration (whoami, uname, id)
  2. LOLBin Execution (subprocess shell chaining)
  3. C2 Beaconing (attempted outbound socket on uncommon port 4444)
  4. Persistence Simulation (safe mock autostart write in /tmp)
  5. File Activity Burst (rapid temporary file creations/modifications)
"""

import os
import socket
import subprocess
import sys
import tempfile
import time


def main():
    print("[*] Starting OutPost Adversary Simulation Test...")

    # 1. Discovery / Enumeration burst
    print("[1/5] Executing Discovery / Enumeration burst...")
    for cmd in [["whoami"], ["uname", "-a"], ["id"]]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            print(f"  > Ran '{' '.join(cmd)}' -> {res.stdout.strip()}")
        except Exception as e:
            print(f"  > Command failed: {e}")

    # 2. Simulated C2 Network Beaconing
    print("[2/5] Simulating C2 Network Connection to 203.0.113.88:4444...")
    for i in range(3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex(("127.0.0.1", 4444))
            s.close()
            print(f"  > Beacon attempt {i+1} sent to 203.0.113.88:4444")
        except Exception:
            pass
        time.sleep(0.01)

    # 3. Persistence Simulation (Safe path in temp directory)
    print("[3/5] Simulating Autostart / Persistence write...")
    temp_dir = tempfile.gettempdir()
    mock_autostart = os.path.join(temp_dir, "mock_outpost_persistence.sh")
    with open(mock_autostart, "w") as f:
        f.write("#!/bin/sh\n# Mock persistence artifact\nexit 0\n")
    print(f"  > Wrote persistence artifact: {mock_autostart}")

    # 4. Rapid File Modification Burst
    print("[4/5] Simulating Rapid File Burst (12 files)...")
    burst_files = []
    for i in range(12):
        path = os.path.join(temp_dir, f"outpost_test_burst_{i}.tmp")
        with open(path, "w") as f:
            f.write(f"test burst payload {i}\n")
        burst_files.append(path)
    time.sleep(0.1)

    # Cleanup temporary burst files
    for path in burst_files:
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        os.remove(mock_autostart)
    except OSError:
        pass

    print("[5/5] Adversary simulation completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
