# OutPost Known Defects & Tracking Register

This document records confirmed architectural defects, platform-specific limitations, and isolation edge cases tracked across development stages.

---

## Defect Register

### OUTPOST-DYNAMIC-01: Bubblewrap Isolation Driver Hides User-Space Virtual Environments under `/home`

- **Component**: Dynamic Execution Engine (`backend/app/services/dynamic_sandbox.py`)
- **Severity**: Medium (Development / Test Environment Only; Production Containers Unaffected)
- **Status**: Queued for Stage 3 (Dynamic Sandbox Elevation)
- **Affected Tests**:
  - `backend/app/tests/test_dynamic_sandbox_real.py::test_real_file_dropper_carving_and_entropy`
  - `backend/app/tests/test_dynamic_sandbox_real.py::test_real_network_beacon_and_pcap_capture`
- **Symptom**:
  When running pytest via a Python 3.12 virtual environment located in the user's home directory (e.g. `/home/kripy/.venv_py312/` using uv Python at `/home/kripy/.local/share/uv/python/cpython-3.12.16-linux-x86_64-gnu/`), dynamic execution inside `bubblewrap` fails with:
  ```
  WARNING outpost.sandbox:dynamic_sandbox.py:847 Failed to parse strace log for run dyn_xxx:
  Sample start seam not found in trace for run 'dyn_xxx': execution never reached target sample
  ```
- **Root Cause**:
  The Linux `bwrap` security sandbox constructs a tight, hermetic jail by mounting an empty temporary filesystem over `/home` (`--tmpfs /home`) and unsharing user namespaces to prevent sandbox breakout or tampering with the host user's files and credentials.
  When the active Python interpreter or virtualenv resides under `/home`, child processes launched inside the sandbox (`/usr/bin/env python3` or dynamic script wrappers) cannot access the virtualenv runtime libraries in `/home/kripy/`. On Python 3.14 (system Python installed in `/usr/bin/python3`), the test suite passes 100% (672/672) because `/usr` is mounted read-only (`--ro-bind /usr /usr`).
- **Resolution Plan for Stage 3**:
  1. Detect when the sandbox execution runner is invoked from an out-of-system virtualenv path.
  2. Bind-mount the interpreter prefix read-only at a neutral sandbox location (e.g. `/opt/runtime/python3`) or use an isolated guest rootfs / VM disk image during dynamic detonation.
  3. Ensure CI pipeline runs dynamic tests under both system-level Python installations and containerized environments.
