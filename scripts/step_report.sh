#!/usr/bin/env bash
# scripts/step_report.sh — Automated, non-interactive verification reporter
# Writes raw command outputs to reports/step-${STEP}.txt
set -euo pipefail

STEP="${1:-1}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REPORTS_DIR="$ROOT_DIR/reports"
mkdir -p "$REPORTS_DIR"
REPORT_FILE="$REPORTS_DIR/step-${STEP}.txt"

FAILED_COMMANDS=()

virt_out=""
virt_rc=0
if virt_out=$(systemd-detect-virt 2>&1); then
  virt_rc=0
else
  virt_rc=$?
fi

echo "=== OutPost Step ${STEP} Automated Verification Report ===" > "$REPORT_FILE"
echo "Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$REPORT_FILE"
echo "Root directory: $ROOT_DIR" >> "$REPORT_FILE"
echo "Git branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')" >> "$REPORT_FILE"
echo "Git commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')" >> "$REPORT_FILE"
echo "Host kernel: $(uname -a)" >> "$REPORT_FILE"
echo "Host virtualization: ${virt_out} (exit code: ${virt_rc})" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

if [ "$STEP" = "1" ]; then
  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 1: Git Tracked Services Inventory" >> "$REPORT_FILE"
  echo "Command: git ls-files backend/app/services | wc -l" >> "$REPORT_FILE"
  git ls-files backend/app/services | wc -l >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "Command: git ls-files backend/app/services" >> "$REPORT_FILE"
  git ls-files backend/app/services >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 2: Backend Data Directory Tracking" >> "$REPORT_FILE"
  echo "Command: git ls-files backend/data" >> "$REPORT_FILE"
  git ls-files backend/data >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 3: Database Reality (backend/data/outpost.db)" >> "$REPORT_FILE"
  echo "Command: sqlite3 backend/data/outpost.db 'SELECT count(*) FROM events;'" >> "$REPORT_FILE"
  sqlite3 backend/data/outpost.db "SELECT count(*) FROM events;" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "Command: sqlite3 backend/data/outpost.db 'SELECT run_id, sample_name, platform, source, origin FROM runs;'" >> "$REPORT_FILE"
  sqlite3 backend/data/outpost.db "SELECT run_id, sample_name, platform, source, origin FROM runs;" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "Command: sqlite3 backend/data/outpost.db 'SELECT sample_id, original_name, sha256, origin FROM samples;'" >> "$REPORT_FILE"
  sqlite3 backend/data/outpost.db "SELECT sample_id, original_name, sha256, origin FROM samples;" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 4: Sandbox Hardening & Capability Guarantees" >> "$REPORT_FILE"
  echo "Command: grep -n \"cap-drop\|clearenv\|unshare\" backend/app/services/dynamic_sandbox.py" >> "$REPORT_FILE"
  grep -n "cap-drop\|clearenv\|unshare" backend/app/services/dynamic_sandbox.py >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "Command: .venv/bin/python scripts/gate_backend_egress.py" >> "$REPORT_FILE"
  if ! .venv/bin/python scripts/gate_backend_egress.py >> "$REPORT_FILE" 2>&1; then
    FAILED_COMMANDS+=("scripts/gate_backend_egress.py")
  fi
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 5: Validation Corpus Metrics" >> "$REPORT_FILE"
  echo "Command: .venv/bin/pytest backend/app/tests/test_validation_corpus_gate.py -v" >> "$REPORT_FILE"
  if ! .venv/bin/pytest backend/app/tests/test_validation_corpus_gate.py -v >> "$REPORT_FILE" 2>&1; then
    FAILED_COMMANDS+=("backend/app/tests/test_validation_corpus_gate.py")
  fi
  echo "" >> "$REPORT_FILE"

elif [ "$STEP" = "2" ]; then
  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 1: Host Prerequisites & Tooling Verification" >> "$REPORT_FILE"
  echo "Command: uname -a" >> "$REPORT_FILE"
  uname -a >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "Command: bwrap --version" >> "$REPORT_FILE"
  bwrap --version >> "$REPORT_FILE" 2>&1 || true
  echo "" >> "$REPORT_FILE"
  echo "Command: gcc --version | head -n 1" >> "$REPORT_FILE"
  gcc --version 2>&1 | head -n 1 >> "$REPORT_FILE" || true
  echo "" >> "$REPORT_FILE"
  echo "Command: strace --version | head -n 2" >> "$REPORT_FILE"
  if command -v strace >/dev/null 2>&1; then
    strace --version | head -n 2 >> "$REPORT_FILE"
  else
    echo "strace: NOT INSTALLED on host (Prerequisite pending: sudo pacman -S strace)" >> "$REPORT_FILE"
  fi
  echo "" >> "$REPORT_FILE"
  echo "Command: tcpdump --version | head -n 2" >> "$REPORT_FILE"
  if command -v tcpdump >/dev/null 2>&1; then
    tcpdump --version 2>&1 | head -n 2 >> "$REPORT_FILE"
  else
    echo "tcpdump: NOT INSTALLED on host (Prerequisite pending: sudo pacman -S tcpdump)" >> "$REPORT_FILE"
  fi
  echo "" >> "$REPORT_FILE"
  echo "Command: sysctl kernel.yama.ptrace_scope" >> "$REPORT_FILE"
  sysctl kernel.yama.ptrace_scope >> "$REPORT_FILE" 2>&1 || cat /proc/sys/kernel/yama/ptrace_scope >> "$REPORT_FILE" 2>&1 || echo "not set" >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 2: Dev-Probe Guard Implementation & Fixed Code Hashes" >> "$REPORT_FILE"
  echo "Command: grep -A 10 \"DEV_PROBE_ALLOWED_HASHES\" backend/app/services/dynamic_sandbox.py" >> "$REPORT_FILE"
  grep -A 10 "DEV_PROBE_ALLOWED_HASHES" backend/app/services/dynamic_sandbox.py >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"
  echo "Command: grep -A 15 \"payload_sha256 = hashlib\" backend/app/services/dynamic_sandbox.py" >> "$REPORT_FILE"
  grep -A 15 "payload_sha256 = hashlib" backend/app/services/dynamic_sandbox.py >> "$REPORT_FILE"
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 3: Ground-Truth Probes Inventory & Exact SHA-256 Sums" >> "$REPORT_FILE"
  echo "Command: sha256sum tests/probes/*/*" >> "$REPORT_FILE"
  sha256sum tests/probes/*/* >> "$REPORT_FILE" 2>&1 || true
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 4: Dev-Probe Guard Parametric Tests (Refusals, Tampering & Execution)" >> "$REPORT_FILE"
  echo "Command: .venv/bin/pytest backend/app/tests/test_sandbox_security.py -k \"dev_probe or environment\" -v" >> "$REPORT_FILE"
  if ! .venv/bin/pytest backend/app/tests/test_sandbox_security.py -k "dev_probe or environment" -v >> "$REPORT_FILE" 2>&1; then
    FAILED_COMMANDS+=("backend/app/tests/test_sandbox_security.py (dev_probe suite)")
  fi
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 5: Strace Parser & Ground-Truth Test Suite (test_strace_parser.py)" >> "$REPORT_FILE"
  echo "Command: .venv/bin/pytest backend/app/tests/test_strace_parser.py -v" >> "$REPORT_FILE"
  if ! .venv/bin/pytest backend/app/tests/test_strace_parser.py -v >> "$REPORT_FILE" 2>&1; then
    FAILED_COMMANDS+=("backend/app/tests/test_strace_parser.py")
  fi
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 6: C Probe Ground-Truth Action vs. Stored Analysis Events Table" >> "$REPORT_FILE"
  echo "Command: Python comparison table against tests/probes/c_probe/README.md" >> "$REPORT_FILE"
  if ! .venv/bin/python -c '
import sqlite3
from app.services.strace_parser import parse_and_persist_strace_log
from app.core.db import SCHEMA

conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row
conn.executescript(SCHEMA)
conn.execute("INSERT INTO runs (run_id, sample_name, platform, started_at) VALUES (\"run_rep\", \"probe_elf\", \"linux\", \"2026-10-27T00:00:00Z\")")
stats = parse_and_persist_strace_log("run_rep", "tests/fixtures/c_probe_strace.log", conn)

te = stats["total_events"]
pc = stats["process_count"]
fe = stats["file_events"]
ne = stats["network_events"]
de = stats["dns_events"]
print(f"Extraction Summary: total_events={te}, processes={pc}, file_events={fe}, network={ne}, dns={de}")
print("\n[Recorded Processes]")
for p in conn.execute("SELECT host_pid, ns_pid, process_name, status, exit_code FROM analysis_processes").fetchall():
    h_pid = p["host_pid"]
    n_pid = p["ns_pid"]
    p_name = p["process_name"]
    p_stat = p["status"]
    p_exit = p["exit_code"]
    print(f"  PID host={h_pid} ns={n_pid} name={p_name} status={p_stat} exit_code={p_exit}")

print("\n[Recorded Event Timeline (Contiguous seq)]")
print("  Seq | Category | Event Type       | Action   | Target Path / Destination")
print("  ----+----------+------------------+----------+----------------------------------------------")
for e in conn.execute("SELECT seq, category, event_type, action, target_path FROM analysis_events ORDER BY seq ASC").fetchall():
    s_idx = e["seq"]
    c_name = e["category"]
    e_type = e["event_type"]
    a_name = e["action"]
    t_path = e["target_path"]
    print(f"  {s_idx:03d} | {c_name:8s} | {e_type:16s} | {a_name:8s} | {t_path}")
' >> "$REPORT_FILE" 2>&1; then
    FAILED_COMMANDS+=("Section 6 C Probe Ground Truth check")
  fi
  echo "" >> "$REPORT_FILE"

  echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
  echo "SECTION 7: Sandbox Environment API & UI State" >> "$REPORT_FILE"
  echo "Command: grep -n \"dev_probe_only\" frontend/src/routes/analysis.tsx frontend/src/components/dynamicAnalysis/LaunchRunDrawer.tsx" >> "$REPORT_FILE"
  grep -n "dev_probe_only\|devProbeOnly" frontend/src/routes/analysis.tsx frontend/src/components/dynamicAnalysis/LaunchRunDrawer.tsx >> "$REPORT_FILE" || true
  echo "" >> "$REPORT_FILE"
fi

echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
echo "SECTION 8: Full Verification Sweep (verify.sh — all 24 gates)" >> "$REPORT_FILE"
if ! ./verify.sh >> "$REPORT_FILE" 2>&1; then
  FAILED_COMMANDS+=("verify.sh (one or more gates failed)")
fi
echo "" >> "$REPORT_FILE"

echo "--------------------------------------------------------------------------------" >> "$REPORT_FILE"
echo "SECTION 9: Verification Failure Summary" >> "$REPORT_FILE"
if [ ${#FAILED_COMMANDS[@]} -eq 0 ]; then
  echo "All verification sections passed (0 failures detected)." >> "$REPORT_FILE"
else
  echo "VERIFICATION FAILURES DETECTED (${#FAILED_COMMANDS[@]} failed):" >> "$REPORT_FILE"
  for cmd in "${FAILED_COMMANDS[@]}"; do
    echo "  - $cmd" >> "$REPORT_FILE"
  done
fi
echo "" >> "$REPORT_FILE"

echo "Report successfully generated at: $REPORT_FILE"
