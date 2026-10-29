# OutPost Automation & CI Validation Scripts

This directory contains automated utility scripts, continuous integration (CI) quality gates, forensic screenshot tools, and verification harnesses for the OutPost platform.

---

## Key Scripts

### Screenshot & Documentation Automation
- `capture_screenshots.py` — Automated script that seeds demo threat telemetry, spins up backend and frontend instances, and uses headless Chromium to capture high-resolution screenshots for documentation.

### Quality Gates & Air-Gap Verification
- `gate_backend_egress.py` — Enforces zero network egress across backend modules to verify air-gap isolation.
- `gate_cli_network.py` — Validates that the OutPost CLI never performs unsolicited network calls.
- `gate_proc_identity.py` — Verifies process identity and compound PID handling.
- `airgap-verify.sh` — Offline test suite verifying that no cloud dependencies or telemetry are contacted at runtime.

### Setup & Local Development
- `dev.sh` / `dev.ps1` — Quick developer launcher for local live-reload servers.
- `install.sh` / `install.ps1` — Local environment installer.
- `setup_qemu_sandbox.sh` — Helper script to configure an optional QEMU/KVM virtualized sandbox.
