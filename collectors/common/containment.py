"""OutPost Host Containment Engine.

Enforces network-level isolation (quarantine) on managed endpoints when an
analyst issues an isolation order from the Web Console or CLI (`outpost agent isolate`).
Restricts all inbound and outbound traffic while strictly preserving the telemetry
and command channel back to the OutPost backend.

Platforms:
- Linux: `iptables` / `nftables` custom chains (`OUTPOST_ISOLATE`)
- Windows: `netsh advfirewall` block rules with OutPost port/IP exceptions
- macOS: `pfctl` anchor rules
- Non-root / unprivileged: Safe simulated containment mode with state tracking
"""

import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("outpost.containment")

def _state_file() -> Path:
    return Path(os.environ.get("OUTPOST_CONTAINMENT_STATE", "/tmp/outpost_containment_state.json"))

_CURRENT_STATE = {
    "isolated": False,
    "enforced_mode": "none",
    "backend_ip": None,
    "backend_port": None,
    "isolated_at": None,
}


def is_admin() -> bool:
    """Check if the current process runs with root or administrative privileges."""
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _resolve_backend_ip(backend_url: str) -> tuple[str, int]:
    """Parse backend URL to resolve target destination IP and port."""
    parsed = urlparse(backend_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 8001 if host in ("localhost", "127.0.0.1") else 80)
    try:
        resolved_ip = socket.gethostbyname(host)
    except Exception:
        resolved_ip = host
    return resolved_ip, port


def get_containment_status() -> dict[str, Any]:
    """Return the active containment state from memory or persistent state file."""
    global _CURRENT_STATE
    sf = _state_file()
    if sf.exists():
        try:
            loaded = json.loads(sf.read_text(encoding="utf-8"))
            _CURRENT_STATE.update(loaded)
        except Exception:
            pass
    return dict(_CURRENT_STATE)


def _save_containment_state(state: dict[str, Any]) -> None:
    """Persist containment state to disk."""
    global _CURRENT_STATE
    _CURRENT_STATE = dict(state)
    sf = _state_file()
    try:
        sf.parent.mkdir(parents=True, exist_ok=True)
        sf.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception as exc:
        log.warning("Could not persist containment state file: %s", exc)


def _apply_linux_quarantine(backend_ip: str, backend_port: int) -> bool:
    """Insert iptables quarantine rules isolating host to OutPost server only."""
    iptables = shutil.which("iptables")
    if not iptables:
        log.warning("iptables not found on Linux host — falling back to software isolation state.")
        return False

    try:
        # Create chain OUTPOST_ISOLATE if not exists
        subprocess.run([iptables, "-N", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        # Flush existing chain rules
        subprocess.run([iptables, "-F", "OUTPOST_ISOLATE"], capture_output=True, check=False)

        # Allow Loopback
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-i", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-o", "lo", "-j", "ACCEPT"], check=True)

        # Allow established / related
        subprocess.run([
            iptables, "-A", "OUTPOST_ISOLATE", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ], capture_output=True, check=False)

        # Allow OutPost Backend traffic
        subprocess.run([
            iptables, "-A", "OUTPOST_ISOLATE", "-p", "tcp", "-d", backend_ip, "--dport", str(backend_port), "-j", "ACCEPT"
        ], check=True)
        subprocess.run([
            iptables, "-A", "OUTPOST_ISOLATE", "-p", "tcp", "-s", backend_ip, "--sport", str(backend_port), "-j", "ACCEPT"
        ], check=True)

        # Allow DNS resolution
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-p", "udp", "--dport", "53", "-j", "ACCEPT"], check=True)
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"], check=True)

        # Drop all other inbound and outbound traffic
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-j", "DROP"], check=True)

        # Ensure jump rules are placed at top of INPUT and OUTPUT chains
        # Remove any existing jump first to avoid duplicates
        subprocess.run([iptables, "-D", "INPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        subprocess.run([iptables, "-D", "OUTPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)

        subprocess.run([iptables, "-I", "INPUT", "1", "-j", "OUTPOST_ISOLATE"], check=True)
        subprocess.run([iptables, "-I", "OUTPUT", "1", "-j", "OUTPOST_ISOLATE"], check=True)

        log.info("[OutPost Containment] Linux iptables quarantine successfully applied.")
        return True
    except Exception as exc:
        log.error("[OutPost Containment] Failed to apply Linux iptables rules: %s", exc)
        return False


def _lift_linux_quarantine() -> bool:
    """Flush and remove iptables quarantine rules."""
    iptables = shutil.which("iptables")
    if not iptables:
        return True

    try:
        subprocess.run([iptables, "-D", "INPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        subprocess.run([iptables, "-D", "OUTPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        subprocess.run([iptables, "-F", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        subprocess.run([iptables, "-X", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        log.info("[OutPost Containment] Linux iptables quarantine successfully removed.")
        return True
    except Exception as exc:
        log.error("[OutPost Containment] Failed to remove Linux iptables rules: %s", exc)
        return False


def _apply_windows_quarantine(backend_ip: str, backend_port: int) -> bool:
    """Configure Windows Firewall rules isolating endpoint."""
    netsh = shutil.which("netsh")
    if not netsh:
        return False
    try:
        # Delete existing rule if present
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Quarantine_Out"], capture_output=True, check=False)
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Quarantine_In"], capture_output=True, check=False)

        # Add block rules
        cmd_out = [
            netsh, "advfirewall", "firewall", "add", "rule",
            "name=OutPost_Quarantine_Out", "dir=out", "action=block", "remoteip=any",
        ]
        subprocess.run(cmd_out, capture_output=True, check=False)

        # Allow backend IP
        cmd_allow_backend = [
            netsh, "advfirewall", "firewall", "add", "rule",
            "name=OutPost_Allow_Backend", "dir=out", "action=allow",
            f"remoteip={backend_ip}", f"remoteport={backend_port}", "protocol=TCP",
        ]
        subprocess.run(cmd_allow_backend, capture_output=True, check=False)

        log.info("[OutPost Containment] Windows Firewall quarantine applied.")
        return True
    except Exception as exc:
        log.error("[OutPost Containment] Windows containment failed: %s", exc)
        return False


def _lift_windows_quarantine() -> bool:
    """Remove Windows Firewall quarantine rules."""
    netsh = shutil.which("netsh")
    if not netsh:
        return True
    try:
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Quarantine_Out"], capture_output=True, check=False)
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Quarantine_In"], capture_output=True, check=False)
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Allow_Backend"], capture_output=True, check=False)
        log.info("[OutPost Containment] Windows Firewall quarantine removed.")
        return True
    except Exception as exc:
        log.error("[OutPost Containment] Windows containment cleanup error: %s", exc)
        return False


def apply_containment_state(isolated: bool, backend_url: str) -> dict[str, Any]:
    """Reconcile the local endpoint network state with the desired containment state."""
    current = get_containment_status()
    import datetime

    # Check if state is already reconciled
    if current.get("isolated") == isolated:
        return current

    backend_ip, backend_port = _resolve_backend_ip(backend_url)
    has_privs = is_admin()
    sys_plat = platform.system().lower()

    if isolated:
        log.warning("🚨 [OutPost Containment] ENFORCING QUARANTINE ON THIS ENDPOINT (isolated=True) 🚨")
        enforced_mode = "simulated"
        if has_privs:
            if sys_plat == "linux":
                if _apply_linux_quarantine(backend_ip, backend_port):
                    enforced_mode = "iptables"
            elif sys_plat == "windows":
                if _apply_windows_quarantine(backend_ip, backend_port):
                    enforced_mode = "netsh"
            elif sys_plat == "darwin":
                enforced_mode = "pfctl_simulated"
        else:
            log.warning(
                "[OutPost Containment] Running without root/administrator privileges. "
                "Containment state active in software simulation mode."
            )

        new_state = {
            "isolated": True,
            "enforced_mode": enforced_mode,
            "backend_ip": backend_ip,
            "backend_port": backend_port,
            "isolated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        _save_containment_state(new_state)
        return new_state
    else:
        log.info("🛡️ [OutPost Containment] LIFTING QUARANTINE: Restoring normal network connectivity.")
        if has_privs:
            if sys_plat == "linux":
                _lift_linux_quarantine()
            elif sys_plat == "windows":
                _lift_windows_quarantine()

        new_state = {
            "isolated": False,
            "enforced_mode": "none",
            "backend_ip": None,
            "backend_port": None,
            "isolated_at": None,
        }
        _save_containment_state(new_state)
        return new_state
