"""RedLine Stealer configuration decoder.

Targets RedLine infostealer samples (v1/v2).
Extracts C2 IP/port endpoints (Net.Tcp / HTTP), Campaign IDs, and XOR/encryption keys
from .NET string dictionaries and configuration structures.
"""

import re
from typing import Any

from .base import FamilyConfigDecoder

_REDLINE_SIGNATURES = [
    b"redline",
    b"iremoteendpoint",
    b"downloadandexecute",
    b"net.tcp://",
    b"authorizationid",
    b"useragent",
]


class RedLineDecoder(FamilyConfigDecoder):
    """Decoder targeting RedLine infostealer configurations."""

    family_name = "RedLine"
    target_version = "v1/v2"
    description = "Decodes RedLine Stealer Net.Tcp C2 endpoints and campaign keys"

    def can_decode(self, data: bytes, metadata: dict[str, Any]) -> bool:
        lower_data = data.lower()
        if b"redline" in lower_data:
            return True
        # Cluster of distinct RedLine stealer endpoint / token identifiers
        redline_tokens = [b"iremoteendpoint", b"downloadandexecute", b"authorizationid"]
        return sum(1 for tok in redline_tokens if tok in lower_data) >= 2

    def decode(self, data: bytes, metadata: dict[str, Any]) -> dict[str, Any] | None:
        text = data.decode("latin1", errors="replace")

        # 1. Search for Net.Tcp endpoint or IP:Port
        c2_endpoint = None
        net_tcp_match = re.search(r"net\.tcp://([a-zA-Z0-9.-]+:\d{2,5}(?:/[a-zA-Z0-9_.-]+)?)", text)
        if net_tcp_match:
            c2_endpoint = net_tcp_match.group(0)
        else:
            # Fallback to standard IP:Port endpoint
            ip_port_match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b", text)
            if ip_port_match:
                c2_endpoint = f"{ip_port_match.group(1)}:{ip_port_match.group(2)}"

        if not c2_endpoint:
            # Search for domain:port
            dom_match = re.search(r"\b([a-zA-Z0-9.-]+\.(?:com|org|net|xyz|ru|to|top)):(\d{2,5})\b", text)
            if dom_match:
                c2_endpoint = f"{dom_match.group(1)}:{dom_match.group(2)}"

        if not c2_endpoint:
            return None

        # 2. Extract Campaign ID / Build
        campaign_match = re.search(r"(?:Build|ID|Campaign)[:=\s]+([a-zA-Z0-9_-]{3,24})", text, re.IGNORECASE)
        campaign_id = campaign_match.group(1) if campaign_match else "Default"

        # 3. Extract Message / Key
        key_match = re.search(r"(?:Key|Message)[:=\s]+([a-zA-Z0-9@#$%^&*-]{4,32})", text, re.IGNORECASE)
        key = key_match.group(1) if key_match else None

        return {
            "family": self.family_name,
            "version": self.target_version,
            "c2_endpoint": c2_endpoint,
            "campaign_id": campaign_id,
            "encryption_key": key,
            "protocol": "net.tcp" if "net.tcp" in c2_endpoint else "tcp",
            "confidence": "high",
        }
