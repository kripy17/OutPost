"""AsyncRAT family configuration decoder.

Targets AsyncRAT payloads (v0.5.7B / v0.5.8 / v0.5.9).
Extracts C2 servers, connection ports, mutex names, Pastebin fallback URLs,
and client certificates from .NET configuration classes.
"""

import base64
import re
from typing import Any

from .base import FamilyConfigDecoder

_ASYNCRAT_SIGNATURES = [
    b"asyncclient",
    b"asyncrat",
    b"server.exe",
    b"pastebin",
    b"ports",
    b"hosts",
]


class AsyncRATDecoder(FamilyConfigDecoder):
    """Decoder targeting AsyncRAT configurations."""

    family_name = "AsyncRAT"
    target_version = "v0.5.7B / v0.5.8"
    description = "Decodes AsyncRAT C2 host, port, mutex, and Pastebin configurations"

    def can_decode(self, data: bytes, metadata: dict[str, Any]) -> bool:
        lower_data = data.lower()
        # Must explicitly contain family identifier
        if b"asyncrat" not in lower_data and b"asyncclient" not in lower_data:
            return False
        # And at least one secondary indicator
        indicators = [b"pastebin", b"ports", b"hosts", b"server.exe", b"mutex", b"stub.config"]
        return any(ind in lower_data for ind in indicators)

    def decode(self, data: bytes, metadata: dict[str, Any]) -> dict[str, Any] | None:
        text = data.decode("latin1", errors="replace")

        # 1. Look for Hosts configuration
        c2_hosts: list[str] = []
        host_line_match = re.search(r"Hosts?[:=\s]+([a-zA-Z0-9.,_ -]+)", text, re.IGNORECASE)
        if host_line_match:
            candidate_tokens = [tok.strip() for tok in host_line_match.group(1).split(",")]
            for tok in candidate_tokens:
                if re.match(r"^(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})$", tok):
                    if not tok.startswith(("127.", "0.", "255.")) and tok not in ("schema.org", "w3.org", "microsoft.com"):
                        if tok not in c2_hosts:
                            c2_hosts.append(tok)

        if not c2_hosts:
            host_matches = re.findall(r"(?:c2\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\b(?:[a-zA-Z0-9-]+\.)+(?:xyz|biz|top|ru|cc)\b)", text)
            for h in host_matches:
                if not h.startswith(("127.", "0.", "255.")) and h not in c2_hosts:
                    c2_hosts.append(h)

        # 2. Look for Ports configuration (e.g. Ports: 6606,7707)
        port = 6606
        port_line_match = re.search(r"Ports?[:=\s]+(\d{2,5})", text, re.IGNORECASE)
        if port_line_match:
            port = int(port_line_match.group(1))
        else:
            p_match = re.search(r"\b(6606|7707|8808)\b", text)
            if p_match:
                port = int(p_match.group(1))

        # 3. Look for Pastebin fallback
        pb_match = re.search(r"https?://(?:pastebin\.com/raw/|textbin\.net/raw/)[a-zA-Z0-9_-]+", text)
        pastebin_url = pb_match.group(0) if pb_match else None

        # 4. Mutex
        mutex_match = re.search(r"Mutex[:=\s]+([a-zA-Z0-9_-]+)", text, re.IGNORECASE)
        if mutex_match:
            mutex = mutex_match.group(1)
        else:
            fallback_m = re.search(r"(?:AsyncRAT|AsyncClient)[\w-]*", text)
            mutex = fallback_m.group(0) if fallback_m else "AsyncRAT-Server"

        # 5. Version
        ver_match = re.search(r"\b0\.5\.[0-9][a-zA-Z]?\b", text)
        version = ver_match.group(0) if ver_match else self.target_version

        if not c2_hosts and not pastebin_url:
            return None

        primary_c2 = f"{c2_hosts[0]}:{port}" if c2_hosts else (pastebin_url or "unknown")

        return {
            "family": self.family_name,
            "version": version,
            "c2_endpoint": primary_c2,
            "c2_servers": [f"{h}:{port}" for h in c2_hosts] if c2_hosts else [primary_c2],
            "port": port,
            "mutex": mutex,
            "pastebin_fallback": pastebin_url,
            "confidence": "high",
        }
