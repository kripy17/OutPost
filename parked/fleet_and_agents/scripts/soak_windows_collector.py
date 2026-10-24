#!/usr/bin/env python3
"""Simulated Windows (Sysmon) collector soak against the live backend.

The REAL collector code path is exercised: `parse_sysmon_event` (the actual
normalization) plus the real `Shipper` (buffering, host_id + log_source
stamping, batch POST). Only the win32evtlog channel tailing is simulated —
this script feeds realistic Sysmon EventData payloads into the parser instead
of reading the Windows Event Log (this host is Linux; that one OS call can't
run here). Everything after the parser is the production pipeline.

Two phases, both into one live source=live session:
  A. benign baseline — ~45 normal Windows events (browsing, notepad, DNS,
     temp-file writes, non-persistence registry). Alerts here = false-positive
     candidates on the modeled baseline.
  B. known-malicious macro-dropper story — winword -> powershell -enc ->
     whoami/net enumeration -> C2 (185.220.101.34) -> Run\\Updater persistence
     -> .enc file burst. Alerts here = the detection sanity check.

Run:  .venv/bin/python scripts/soak_windows_collector.py
"""

import argparse
import datetime
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collectors" / "windows"))
sys.path.insert(0, str(ROOT / "collectors" / "common"))

from collector_win import parse_sysmon_event  # noqa: E402
from shipper import Shipper  # noqa: E402


class _StubTime:
    def __init__(self, ts: float):
        self._ts = ts

    def timestamp(self) -> float:
        return self._ts


class _StubRecord:
    """Minimal stand-in for a win32evtlog record (mirrors the collector tests)."""

    def __init__(self, event_id: int, data: list, ts: float):
        self.EventID = event_id
        self.Data = data
        self.TimeGenerated = _StubTime(ts)


def _post(path: str, body) -> dict:
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=__import__("json").dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return __import__("json").loads(resp.read())


def _get(path: str) -> dict:
    with urllib.request.urlopen(f"{BASE}{path}") as resp:
        return __import__("json").loads(resp.read())


def _record(event_id: int, data: list, ts_epoch: float) -> dict:
    """One Sysmon record -> normalized unified-schema event (real parser)."""
    ev = parse_sysmon_event(_StubRecord(event_id, data, ts_epoch))
    assert ev is not None, f"parser dropped EventID {event_id}"
    return ev


def _ticker(start: float, step: float):
    """A tiny monotonic timestamp source — distinct timestamps keep the
    backend's natural-key dedup from collapsing the events."""
    t = [start]
    def tick() -> float:
        t[0] += step
        return t[0]
    return tick


def _benign_baseline(now: float) -> list[dict]:
    """~45 normal Windows events — the modeled FP baseline."""
    evs: list[dict] = []
    tick = _ticker(now - 180, 3)

    # Process creates — legit system + user software.
    proc = [
        ("explorer.exe", r"C:\Windows\explorer.exe", "explorer.exe", 780, 600),
        ("svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs", 600, 4),
        ("dwm.exe", r"C:\Windows\System32\dwm.exe", "dwm.exe", 600, 4),
        ("notepad.exe", r"C:\Windows\System32\notepad.exe", 'notepad.exe "C:\\Users\\alice\\Desktop\\notes.txt"', 4000, 780),
        ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", 'chrome.exe --type=renderer', 4000, 780),
        ("msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "msedge.exe --type=gpu-process", 4000, 780),
        ("SearchIndexer.exe", r"C:\Windows\System32\SearchIndexer.exe", "SearchIndexer.exe /Embedding", 600, 4),
        ("conhost.exe", r"C:\Windows\System32\conhost.exe", "conhost.exe 0xffffffff -ForceV1", 4000, 780),
        ("svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k LocalServiceNetworkRestricted", 600, 4),
        ("ONENOTE.EXE", r"C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE", "ONENOTE.EXE", 4000, 780),
    ]
    for name, image, cmd, pid, ppid in proc:
        evs.append(_record(1, ["Image", image, "CommandLine", cmd, "ProcessId", str(pid),
                               "ParentProcessId", str(ppid)], tick()))

    # Network — clean public resolvers/CDNs + local DNS.
    net = [
        (4000, "1.1.1.1", 443, "TCP"),
        (4000, "8.8.8.8", 53, "UDP"),
        (4000, "172.217.14.110", 443, "TCP"),
        (4000, "13.107.42.12", 443, "TCP"),
        (4000, "20.190.160.15", 443, "TCP"),
        (4000, "151.101.2.132", 443, "TCP"),
        (600, "192.168.1.1", 53, "UDP"),
        (4000, "104.18.24.7", 443, "TCP"),
    ]
    for pid, ip, port, proto in net:
        evs.append(_record(3, ["Image", "chrome.exe", "ProcessId", str(pid),
                               "DestinationIp", ip, "DestinationPort", str(port),
                               "Protocol", proto, "DestinationHostname", ""], tick()))

    # File writes — temp/cache/downloads.
    files = [
        r"C:\Users\alice\AppData\Local\Temp\chrome_installer.log",
        r"C:\Users\alice\Downloads\report.pdf",
        r"C:\Users\alice\Documents\notes.docx",
        r"C:\Windows\Temp\msedge_update.log",
        r"C:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\IE\cache1.dat",
    ]
    for f in files:
        evs.append(_record(11, ["Image", "chrome.exe", "ProcessId", "4000",
                                "TargetFilename", f], tick()))

    # Registry — non-persistence keys (Explorer state, task cache, cloud store).
    reg = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore",
    ]
    for k in reg:
        evs.append(_record(13, ["Image", "explorer.exe", "ProcessId", "4000",
                                "TargetObject", k, "Details", "Binary"], tick()))
    return evs


def _malicious_story(now: float) -> list[dict]:
    """The macro-dropper kill chain — the detection sanity check."""
    evs: list[dict] = []
    tick = _ticker(now - 60, 4)

    # 1. winword opens the lure (legit parent: explorer).
    evs.append(_record(1, ["Image", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                           "CommandLine", r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /q /n',
                           "ProcessId", "5000", "ParentProcessId", "4000"], tick()))
    # 2. macro -> powershell -enc (the LOLBin tell).
    evs.append(_record(1, ["Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                           "CommandLine", "powershell.exe -enc SQBFAFgAAGgBdAA=",
                           "ProcessId", "5001", "ParentProcessId", "5000"], tick()))
    # 3. recon: whoami + net enumeration.
    evs.append(_record(1, ["Image", r"C:\Windows\System32\cmd.exe",
                           "CommandLine", "cmd.exe /c whoami", "ProcessId", "5002",
                           "ParentProcessId", "5001"], tick()))
    evs.append(_record(1, ["Image", r"C:\Windows\System32\cmd.exe",
                           "CommandLine", "cmd.exe /c net view", "ProcessId", "5002",
                           "ParentProcessId", "5001"], tick()))
    evs.append(_record(1, ["Image", r"C:\Windows\System32\cmd.exe",
                           "CommandLine", "cmd.exe /c net localgroup administrators",
                           "ProcessId", "5002", "ParentProcessId", "5001"], tick()))
    # 4. C2 beacon to a known-bad Tor exit IP + a routable reserved C2.
    evs.append(_record(3, ["Image", "powershell.exe", "ProcessId", "5001",
                           "DestinationIp", "185.220.101.34", "DestinationPort", "4444",
                           "Protocol", "TCP", "DestinationHostname", "tor-exit-34.for-privacy.net"], tick()))
    evs.append(_record(3, ["Image", "powershell.exe", "ProcessId", "5001",
                           "DestinationIp", "203.0.113.88", "DestinationPort", "4444",
                           "Protocol", "TCP", "DestinationHostname", ""], tick()))
    # 5. persistence: Run\Updater.
    evs.append(_record(13, ["Image", "powershell.exe", "ProcessId", "5001",
                            "TargetObject", r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                            "Details", r"powershell.exe -enc SQBFAFgAAGgBdAA="], tick()))
    # 6. data-staging burst: .enc files.
    for i in range(6):
        evs.append(_record(11, ["Image", "powershell.exe", "ProcessId", "5001",
                                "TargetFilename", rf"C:\Users\victim\Documents\invoice_00{i}.enc"], tick()))
    return evs


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
                         "detections. verify.sh step 8 runs this mode.")
    args = ap.parse_args()
    BASE = args.backend.rstrip("/")

    # Live session, exactly how a real Windows collector run is labeled:
    # session_type=live is forced to source="live" server-side (host telemetry).
    now = time.time()
    # Distinct soak- name so the archive can tell a modeled baseline from a
    # REAL agent session (agent-<host>-<date>) — soak runs masquerading as
    # agent sessions used to pollute History and the daily summary.
    soak_name = f"soak-windows-{args.host}-{time.strftime('%Y-%m-%d', time.gmtime())}"
    run = _post("/runs", {"sample_name": soak_name,
                          "platform": "windows", "session_type": "live"})
    run_id = run["run_id"]
    print(f"Windows collector soak → live session {run_id} (host {args.host}, "
          f"source=live, platform=windows)\n")

    shipper = Shipper(BASE, run_id, host_id=args.host)

    # Phase A — benign baseline (FP measurement).
    benign = _benign_baseline(now)
    for ev in benign:
        shipper.add(ev)
    shipper.flush()
    time.sleep(0.3)
    alerts_a = _get(f"/runs/{run_id}/alerts")
    print(f"Phase A — benign baseline ({len(benign)} events):")
    _report("FP?", alerts_a)

    # Phase B — malicious kill chain (detection sanity check).
    evil = _malicious_story(now)
    for ev in evil:
        shipper.add(ev)
    shipper.flush()
    time.sleep(0.3)
    alerts_b = _get(f"/runs/{run_id}/alerts")
    print(f"\nPhase B — known-malicious macro-dropper ({len(evil)} events):")
    _report("DET", alerts_b)

    # Verdict.
    fp_rules = {a["rule_id"] for a in alerts_a}
    det_rules = {a["rule_id"] for a in alerts_b if a["rule_id"] not in fp_rules}
    print("\n══════════════════════════════════════════════════════")
    print("Honest framing: only the win32evtlog tail is simulated; the parser,")
    print("shipper, backend ingest, and every detection rule are the production path.")
    print(f"  FP candidates (fired on the modeled benign baseline): "
          f"{sorted(fp_rules) or 'none'}")
    print(f"  Detection-only rules (malicious story): {sorted(det_rules) or 'none'}")
    print(f"  Shared (expected noise: first-seen on novel processes): "
          f"{sorted(fp_rules & {a['rule_id'] for a in alerts_b})}")
    print(f"  Run: {run_id} — open in the webapp at /runs/{run_id}")

    if args.gate:
        # The gate: FP budget is ZERO on the modeled benign baseline, and the
        # malicious story must still land its core detections (guards against
        # over-exemption — a fix that silences benign AND evil alike fails).
        core = {"suspicious-parent-child", "lolbin-abuse",
                "registry-persistence", "unusual-port"}
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
