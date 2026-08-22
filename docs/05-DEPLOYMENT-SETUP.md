# Deployment & Safety Notes

OutPost's collector runs on whatever machine you point it at — that's a deliberate architectural choice, not an oversight. There's no hypervisor dependency baked into the core system.

## Deployment Options

**Your own machine, for live monitoring:** install the collector directly and run it continuously — this is the "always-on" use case, watching your real system's process/network activity and flagging anomalies as they happen.

**A dedicated lab/test machine, physical or virtual:** if you want a stable, resettable environment for repeated testing, any machine works — a spare laptop, a lab PC, or a VM if that's what you have available. The collector doesn't care which.

**An isolated VM, specifically when analyzing something you don't trust:** if you're deliberately running a suspicious file to observe its behavior, use an isolated environment for that one task. This is a sensible precaution, not a required part of the architecture — see the safety note below.

## Installing the Collector

**Windows:**
1. Install **Sysmon** (Microsoft Sysinternals) with a tuned config — the SwiftOnSecurity config is a solid community starting point — enabling at minimum Event ID 1 (process create), 3 (network connection), 11 (file create), 12/13/14 (registry)
2. Install Python + `pywin32` + `requests`
3. Run `collectors/windows/collector_win.py` pointed at your backend URL

**Linux:**
1. Install `auditd`, load the rules in `collectors/linux/audit.rules` (watches `execve`/`connect` syscalls)
2. Install Python + `requests`
3. Run `collectors/linux/collector_linux.py` pointed at your backend URL

Both are detailed in `docs/03-COLLECTOR-SPEC.md`.

## Safety Note (read before analyzing an untrusted sample)

OutPost is built to be safe for everyday live monitoring on a real machine — that's the common case. The one situation that needs extra care is deliberately running a file you don't trust:

- If you're not confident a file is safe, run it in an isolated environment (a VM with no bridged network, or any machine you're fine resetting) rather than on your daily-driver system
- Keep an easy way to reset that environment (a VM snapshot, or a reimageable test machine) if you're doing this repeatedly
- Never test on a machine with data or access you're not prepared to lose

This is standard precaution, not a mandatory multi-step protocol — use your judgment on how much isolation a given file actually warrants.

## Sample Handling

If your coursework involves real malware samples specifically (rather than synthetic test scripts that just mimic suspicious behavior), check your department's policy first. Real samples, if approved, should come from established researcher-facing sources (e.g. MalwareBazaar) — never random forum links. Synthetic test scripts (spawn a few child processes, connect to a test IP/port you control) are the safer default for development and demos, and are enough to prove every detection heuristic actually fires correctly.
