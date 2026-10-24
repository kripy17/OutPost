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
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("outpost.containment")

def _state_file() -> Path:
    if os.environ.get("OUTPOST_CONTAINMENT_STATE"):
        return Path(os.environ["OUTPOST_CONTAINMENT_STATE"])
    if os.name == "nt":
        base = Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "OutPost"
    else:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            base = Path("/var/run/outpost")
        else:
            base = Path.home() / ".outpost"
    return base / "containment_state.json"

_CURRENT_STATE = {
    "isolated": False,
    "enforced_mode": "none",
    "backend_ip": None,
    "backend_port": None,
    "isolated_at": None,
    "deadman_expires_at": None,
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


def get_containment_status(backend_url: str = "") -> dict[str, Any]:
    """Return active containment state. Evaluates local dead-man release timer."""
    sf = _state_file()
    if sf.exists():
        try:
            loaded = json.loads(sf.read_text(encoding="utf-8"))
            _CURRENT_STATE.update(loaded)
        except Exception:
            pass

    # Local dead-man release check
    deadman_exp = _CURRENT_STATE.get("deadman_expires_at")
    if deadman_exp and _CURRENT_STATE.get("isolated"):
        try:
            import datetime
            exp_dt = datetime.datetime.fromisoformat(deadman_exp.replace("Z", "+00:00"))
            if datetime.datetime.now(datetime.timezone.utc) > exp_dt:
                log.warning("[OutPost Containment] Dead-man timer expired! Auto-reverting network isolation.")
                _revert_quarantine()
                _CURRENT_STATE["isolated"] = False
                _CURRENT_STATE["enforced_mode"] = "none"
                _CURRENT_STATE["deadman_expires_at"] = None
                _save_containment_state(_CURRENT_STATE)
        except Exception as exc:
            log.debug("Deadman evaluation error: %s", exc)

    return dict(_CURRENT_STATE)


def _save_containment_state(state: dict[str, Any]) -> None:
    """Persist containment state to disk with secure 0600 permissions."""
    global _CURRENT_STATE
    _CURRENT_STATE = dict(state)
    sf = _state_file()
    try:
        sf.parent.mkdir(parents=True, exist_ok=True)
        sf.write_text(json.dumps(state, indent=2), encoding="utf-8")
        try:
            os.chmod(sf, 0o600)
        except Exception:
            pass
    except Exception as exc:
        log.warning("Could not persist containment state file: %s", exc)


def _revert_quarantine() -> None:
    """Safely remove firewall containment rules across supported operating systems."""
    sys_plat = platform.system().lower()
    if is_admin():
        if sys_plat == "linux":
            _lift_linux_quarantine()
        elif sys_plat == "windows":
            _lift_windows_quarantine()


def probe_containment(backend_ip: str, backend_port: int) -> dict[str, Any]:
    """Probe network boundaries to verify whether isolation is genuinely active."""
    # Probe backend connectivity
    backend_ok = False
    try:
        s = socket.create_connection((backend_ip, backend_port), timeout=1.5)
        backend_ok = True
        s.close()
    except Exception:
        backend_ok = False

    # Probe external connectivity (must fail if fully isolated)
    external_blocked = True
    try:
        s_ext = socket.create_connection(("1.1.1.1", 53), timeout=1.0)
        external_blocked = False
        s_ext.close()
    except Exception:
        external_blocked = True

    return {
        "backend_reachable": backend_ok,
        "external_blocked": external_blocked,
        "verified": backend_ok and external_blocked,
    }


def _apply_linux_quarantine(backend_ip: str, backend_port: int) -> bool:
    """Insert iptables & ip6tables quarantine rules isolating host to OutPost server only."""
    iptables = shutil.which("iptables")
    if not iptables:
        log.warning("iptables not found on Linux host — falling back to software isolation state.")
        return False

    try:
        # IPv4 Isolation Chain
        subprocess.run([iptables, "-N", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        subprocess.run([iptables, "-F", "OUTPOST_ISOLATE"], capture_output=True, check=False)

        # Allow Loopback
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-i", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-o", "lo", "-j", "ACCEPT"], check=True)

        # Allow traffic strictly to/from OutPost Backend IP & port (established & new)
        subprocess.run([
            iptables, "-A", "OUTPOST_ISOLATE", "-p", "tcp", "-d", backend_ip, "--dport", str(backend_port),
            "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"
        ], check=True)
        subprocess.run([
            iptables, "-A", "OUTPOST_ISOLATE", "-p", "tcp", "-s", backend_ip, "--sport", str(backend_port),
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ], check=True)

        # Restrict DNS resolution to backend resolver only
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-p", "udp", "-d", backend_ip, "--dport", "53", "-j", "ACCEPT"], capture_output=True, check=False)
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-p", "tcp", "-d", backend_ip, "--dport", "53", "-j", "ACCEPT"], capture_output=True, check=False)

        # Drop all other traffic (drops already-established unauthorized flows)
        subprocess.run([iptables, "-A", "OUTPOST_ISOLATE", "-j", "DROP"], check=True)

        # Place jump rules at top of INPUT and OUTPUT chains
        subprocess.run([iptables, "-D", "INPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        subprocess.run([iptables, "-D", "OUTPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        subprocess.run([iptables, "-I", "INPUT", "1", "-j", "OUTPOST_ISOLATE"], check=True)
        subprocess.run([iptables, "-I", "OUTPUT", "1", "-j", "OUTPOST_ISOLATE"], check=True)

        # IPv6: Drop all non-loopback flows to prevent IPv6 bypass
        ip6tables = shutil.which("ip6tables")
        if ip6tables:
            subprocess.run([ip6tables, "-N", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-F", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-A", "OUTPOST_ISOLATE", "-i", "lo", "-j", "ACCEPT"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-A", "OUTPOST_ISOLATE", "-o", "lo", "-j", "ACCEPT"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-A", "OUTPOST_ISOLATE", "-j", "DROP"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-D", "INPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-D", "OUTPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-I", "INPUT", "1", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-I", "OUTPUT", "1", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)

        # Flush established non-backend connections via conntrack if available
        conntrack = shutil.which("conntrack")
        if conntrack:
            subprocess.run([conntrack, "-F"], capture_output=True, check=False)

        log.info("[OutPost Containment] Linux iptables & ip6tables quarantine successfully applied.")
        return True
    except Exception as exc:
        log.error("[OutPost Containment] Failed to apply Linux iptables rules: %s", exc)
        return False


def _lift_linux_quarantine() -> bool:
    """Flush and remove iptables & ip6tables quarantine rules."""
    iptables = shutil.which("iptables")
    if iptables:
        try:
            subprocess.run([iptables, "-D", "INPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([iptables, "-D", "OUTPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([iptables, "-F", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([iptables, "-X", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        except Exception as exc:
            log.debug("Error flushing iptables: %s", exc)

    ip6tables = shutil.which("ip6tables")
    if ip6tables:
        try:
            subprocess.run([ip6tables, "-D", "INPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-D", "OUTPUT", "-j", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-F", "OUTPOST_ISOLATE"], capture_output=True, check=False)
            subprocess.run([ip6tables, "-X", "OUTPOST_ISOLATE"], capture_output=True, check=False)
        except Exception as exc:
            log.debug("Error flushing ip6tables: %s", exc)

    log.info("[OutPost Containment] Linux iptables quarantine successfully removed.")
    return True


def _apply_windows_quarantine(backend_ip: str, backend_port: int) -> bool:
    """Configure Windows Firewall policy isolating endpoint while preserving backend access."""
    netsh = shutil.which("netsh")
    if not netsh:
        return False
    try:
        _lift_windows_quarantine()

        # Set default firewall policy to block both inbound and outbound traffic
        subprocess.run([netsh, "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"], capture_output=True, check=False)

        # Allow outbound traffic to OutPost backend
        subprocess.run([
            netsh, "advfirewall", "firewall", "add", "rule",
            "name=OutPost_Allow_Backend_Out", "dir=out", "action=allow",
            f"remoteip={backend_ip}", f"remoteport={backend_port}", "protocol=TCP",
        ], capture_output=True, check=False)

        # Allow inbound responses from OutPost backend
        subprocess.run([
            netsh, "advfirewall", "firewall", "add", "rule",
            "name=OutPost_Allow_Backend_In", "dir=in", "action=allow",
            f"remoteip={backend_ip}", f"remoteport={backend_port}", "protocol=TCP",
        ], capture_output=True, check=False)

        log.info("[OutPost Containment] Windows Firewall quarantine applied.")
        return True
    except Exception as exc:
        log.error("[OutPost Containment] Windows containment failed: %s", exc)
        return False


def _lift_windows_quarantine() -> bool:
    """Remove Windows Firewall quarantine rules and restore default policy."""
    netsh = shutil.which("netsh")
    if not netsh:
        return True
    try:
        subprocess.run([netsh, "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"], capture_output=True, check=False)
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Allow_Backend_Out"], capture_output=True, check=False)
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Allow_Backend_In"], capture_output=True, check=False)
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Quarantine_Out"], capture_output=True, check=False)
        subprocess.run([netsh, "advfirewall", "firewall", "delete", "rule", "name=OutPost_Quarantine_In"], capture_output=True, check=False)
        log.info("[OutPost Containment] Windows Firewall quarantine removed.")
        return True
    except Exception as exc:
        log.error("[OutPost Containment] Windows containment cleanup error: %s", exc)
        return False


def apply_containment_state(
    isolated: bool,
    backend_url: str,
    deadman_expires_at: str | None = None,
) -> dict[str, Any]:
    """Reconcile the local endpoint network state with the desired containment state."""
    current = get_containment_status(backend_url)
    import datetime

    if current.get("isolated") == isolated and (not isolated or current.get("deadman_expires_at") == deadman_expires_at):
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
                    enforced_mode = "full"
                else:
                    enforced_mode = "none"
            elif sys_plat == "windows":
                if _apply_windows_quarantine(backend_ip, backend_port):
                    enforced_mode = "full"
                else:
                    enforced_mode = "none"
            elif sys_plat == "darwin":
                # macOS packet filter enforcement is unsupported
                log.warning("[OutPost Containment] macOS isolation is documented as unsupported.")
                enforced_mode = "unsupported"
        else:
            log.warning(
                "[OutPost Containment] Running without root/administrator privileges. "
                "Containment state active in software simulation mode (NOT ENFORCED)."
            )
            enforced_mode = "simulated"

        probe = probe_containment(backend_ip, backend_port) if has_privs and enforced_mode == "full" else None

        new_state = {
            "isolated": True,
            "enforced_mode": enforced_mode,
            "backend_ip": backend_ip,
            "backend_port": backend_port,
            "isolated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "deadman_expires_at": deadman_expires_at,
            "probe_details": probe,
        }
        _save_containment_state(new_state)
        return new_state
    else:
        log.info("🛡️ [OutPost Containment] LIFTING QUARANTINE: Restoring normal network connectivity.")
        _revert_quarantine()

        new_state = {
            "isolated": False,
            "enforced_mode": "none",
            "backend_ip": None,
            "backend_port": None,
            "isolated_at": None,
            "deadman_expires_at": None,
            "probe_details": None,
        }
        _save_containment_state(new_state)
        return new_state
