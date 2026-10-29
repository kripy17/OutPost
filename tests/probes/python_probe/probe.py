#!/usr/bin/env python3
"""OutPost Behavioral Probe - Python Script Ground Truth Sample

Designed exclusively for isolated sandbox baseline tracing and parser validation.
Performs deterministic, harmless actions:
  1. Writes to file "probe_py.tmp"
  2. Chmods "probe_py.tmp" to 0600
  3. Renames "probe_py.tmp" -> "probe_py_renamed.tmp"
  4. Deletes "probe_py_renamed.tmp"
  5. Spawns child process via subprocess.run
  6. Attempts DNS lookup for non-existent domain "probe-py.test.invalid"
  7. Attempts TCP connection to TEST-NET-1 IP 192.0.2.1:80 (RFC 5737)
  8. Exits cleanly with status 0
"""

import os
import socket
import subprocess
import sys


def main() -> int:
    print("=== OutPost Python Probe Starting ===")
    sys.stdout.flush()

    # 1. File write
    target_file = "probe_py.tmp"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write("OutPost python probe payload data\n")

    # 2. File chmod to 0600
    os.chmod(target_file, 0o600)

    # 3. File rename
    renamed_file = "probe_py_renamed.tmp"
    os.rename(target_file, renamed_file)

    # 4. File delete
    os.unlink(renamed_file)

    # 5. Process spawn via subprocess
    cmd = [sys.executable, "-c", "import sys; print('--- Python Probe Child Process Executing ---'); sys.exit(0)"]
    subprocess.run(cmd, check=False)

    # 6. DNS lookup attempt (expected to fail in airgap/isolated sandbox)
    try:
        socket.gethostbyname("probe-py.test.invalid")
    except Exception:
        pass

    # 7. TCP socket connect attempt (TEST-NET-1, RFC 5737)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(0.1)
        sock.connect(("192.0.2.1", 80))
    except Exception:
        pass
    finally:
        sock.close()

    print("=== OutPost Python Probe Exiting ===")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
