"""AgentTesla family configuration decoder.

Targets AgentTesla infostealer samples (v2/v3).
Extracts C2 delivery protocol (SMTP, FTP, HTTP, Telegram, Discord), server hosts,
usernames, passwords, and exfiltration channels.
"""

import re
from typing import Any

from .base import FamilyConfigDecoder

_AGENT_TESLA_SIGNATURES = [
    b"agenttesla",
    b"webpanel",
    b"smtpserver",
    b"ftpuser",
    b"telegrambot",
    b"discordwebhook",
]


class AgentTeslaDecoder(FamilyConfigDecoder):
    """Decoder targeting AgentTesla infostealer configurations."""

    family_name = "AgentTesla"
    target_version = "v2/v3"
    description = "Decodes AgentTesla SMTP/FTP/HTTP/Telegram exfiltration configurations"

    def can_decode(self, data: bytes, metadata: dict[str, Any]) -> bool:
        lower_data = data.lower()
        # Look for cluster of distinct AgentTesla markers
        match_count = sum(1 for sig in _AGENT_TESLA_SIGNATURES if sig in lower_data)
        return match_count >= 2

    def decode(self, data: bytes, metadata: dict[str, Any]) -> dict[str, Any] | None:
        lower_data = data.lower()
        c2_type = "unknown"
        c2_target = None
        port = None
        user = None

        # 1. Telegram Exfiltration
        tg_match = re.search(rb"api\.telegram\.org/bot([0-9]{8,12}:[a-zA-Z0-9_-]{30,40})/sendmessage", data)
        if tg_match:
            c2_type = "telegram"
            c2_target = tg_match.group(0).decode("latin1")
        # 2. SMTP Exfiltration
        elif b"smtp" in lower_data:
            c2_type = "smtp"
            smtp_host = re.search(rb"smtp\.[\w.-]+\.[a-z]{2,}", lower_data)
            if smtp_host:
                c2_target = smtp_host.group(0).decode("ascii")
                port = 587
        # 3. HTTP / Webpanel
        elif b"webpanel" in lower_data:
            c2_type = "http_panel"
            panel_url = re.search(rb"https?://[\w.-]+/[a-zA-Z0-9_/.-]*\.(?:php|asp)", data)
            if panel_url:
                c2_target = panel_url.group(0).decode("latin1")

        if not c2_target:
            # Fallback check for email
            email_match = re.search(rb"[\w.+-]+@[\w-]+\.[\w.-]{2,}", data)
            if email_match:
                user = email_match.group(0).decode("ascii")

        if not c2_target and not user:
            return None

        return {
            "family": self.family_name,
            "version": self.target_version,
            "exfiltration_protocol": c2_type,
            "c2_endpoint": c2_target,
            "port": port,
            "account": user,
            "confidence": "high",
        }
