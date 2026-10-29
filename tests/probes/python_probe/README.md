# OutPost Ground-Truth Behavioral Probe: Python Script

## 1. Provenance & Execution Specifications
- **Source File:** `probe.py`
- **Interpreter:** `python3` (CPython >= 3.10)
- **Fixed SHA-256 Digest:**
  `3d3b947196339910dc004bab2ef6a6cdb74eb3fda4d6ed3d9bdd0d2c266223ff`

---

## 2. Expected Action Specification (Derived from Source)
Derived directly from `probe.py` source statements:

| Action Index | Category | Operation | Target / Arguments | Expected Return / Status |
| :--- | :--- | :--- | :--- | :--- |
| **P1** | `process` | Script Launch | `execve("python3", ["python3", ".../probe.py"], ...)` | Starts main Python interpreter |
| **P2** | `file` | File Write | `open("probe_py.tmp", "w")` -> `write("OutPost python probe payload data\n")` | File created and written: exactly 34 bytes (`len("OutPost python probe payload data\n") == 34`). Explicit Python `open()` allocates descriptor `fd 10` (contrasting with shell stdout redirection which writes on `fd 1`). |
| **P3** | `file` | Permission Change | `os.chmod("probe_py.tmp", 0o600)` | Mode updated to `0600` |
| **P4** | `file` | File Rename | `os.rename("probe_py.tmp", "probe_py_renamed.tmp")` | Returns `None` |
| **P5** | `file` | File Deletion | `os.unlink("probe_py_renamed.tmp")` | Returns `None` |
| **P6** | `process` | Subprocess Spawn | `subprocess.run([sys.executable, "-c", "import sys; print('--- Python Probe Child Process Executing ---'); sys.exit(0)"])` | `clone`/`fork`, child prints banner and exits 0 |
| **P7** | `dns` | DNS Query Attempt | `socket.gethostbyname("probe-py.test.invalid")` | Resolver issues IPv4 query (`AF_INET`). Kernel reports `POLLERR` on isolated airgap interface. Per glibc default (`attempts: 2`), 2 query attempts occur before raising `socket.gaierror`. |
| **P8** | `network` | TCP Socket Connect | `socket.socket(...)` -> `connect(("192.0.2.1", 80))` | Connection fails (`ENETUNREACH` in isolated namespace; caught), socket closed |
| **P9** | `process` | Script Exit | `sys.exit(0)` | Exit code `0` |

---

## 3. Telemetry Expectations & Noise Suppression
- **Process Count:** 2 processes (parent python interpreter and child python `-c` worker process).
- **File Mutations:** Exactly 5 file mutation events (`probe_py.tmp` create, write 34 bytes, chmod 0600, rename `probe_py_renamed.tmp`, unlink).
- **Suppressed System Reads:** 191 reads suppressed under Python runtime noise policy (CPython startup, `.venv/`, `site-packages`, `pyvenv.cfg`, `.pth`, bytecode `.pyc`, `/proc/sys/vm`, `/proc/self/maps`, entrypoint script open).
- **DNS Events:** 4 events (2 UDP sendto query attempts to `127.0.0.1:53` + 2 poll failure events under `AF_INET`).
- **Network Connects:** 1 failed TCP connect attempt to `192.0.2.1:80` (`ENETUNREACH`).
