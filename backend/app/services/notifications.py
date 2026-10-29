"""Alert notifications — settings and channel management for OutPost.

Settings live in the `settings` table (key/value); a channel is enabled when
its keys are present and non-empty.
"""

from typing import Any

WEBHOOK_KEY = "NOTIFY_WEBHOOK_URL"
SLACK_KEY = "NOTIFY_SLACK_WEBHOOK_URL"
DISCORD_KEY = "NOTIFY_DISCORD_WEBHOOK_URL"
TG_TOKEN_KEY = "NOTIFY_TELEGRAM_BOT_TOKEN"
TG_CHAT_KEY = "NOTIFY_TELEGRAM_CHAT_ID"
SMTP_HOST_KEY = "NOTIFY_SMTP_HOST"
SMTP_PORT_KEY = "NOTIFY_SMTP_PORT"
SMTP_USER_KEY = "NOTIFY_SMTP_USER"
SMTP_PASS_KEY = "NOTIFY_SMTP_PASS"
SMTP_FROM_KEY = "NOTIFY_SMTP_FROM"
SMTP_TO_KEY = "NOTIFY_SMTP_TO"

_SETTING_KEYS = (
    WEBHOOK_KEY, SLACK_KEY, DISCORD_KEY, TG_TOKEN_KEY, TG_CHAT_KEY,
    SMTP_HOST_KEY, SMTP_PORT_KEY, SMTP_USER_KEY, SMTP_PASS_KEY,
    SMTP_FROM_KEY, SMTP_TO_KEY,
)


def _get_all(conn) -> dict[str, str]:
    rows = conn.execute(
        f"SELECT key, value FROM settings WHERE key IN ({','.join('?' * len(_SETTING_KEYS))})",
        _SETTING_KEYS,
    ).fetchall()
    return {r["key"]: (r["value"] or "").strip() for r in rows}


def get_settings(conn) -> dict[str, Any]:
    """All channel config, as a flat dict (webhook_url aliased for back-compat)."""
    s = _get_all(conn)
    s.setdefault(SMTP_PORT_KEY, "587")
    return {
        "webhook_url": s.get(WEBHOOK_KEY, ""),
        "slack_webhook": s.get(SLACK_KEY, ""),
        "discord_webhook": s.get(DISCORD_KEY, ""),
        "telegram_bot_token": s.get(TG_TOKEN_KEY, ""),
        "telegram_chat_id": s.get(TG_CHAT_KEY, ""),
        "smtp_host": s.get(SMTP_HOST_KEY, ""),
        "smtp_port": s.get(SMTP_PORT_KEY, "587"),
        "smtp_user": s.get(SMTP_USER_KEY, ""),
        "smtp_pass": s.get(SMTP_PASS_KEY, ""),
        "smtp_from": s.get(SMTP_FROM_KEY, ""),
        "smtp_to": s.get(SMTP_TO_KEY, ""),
    }


def set_settings(conn, body: dict[str, Any]) -> None:
    """Persist channel config. Only known keys are written; empty clears."""
    mapping = {
        WEBHOOK_KEY: body.get("webhook_url", ""),
        SLACK_KEY: body.get("slack_webhook", ""),
        DISCORD_KEY: body.get("discord_webhook", ""),
        TG_TOKEN_KEY: body.get("telegram_bot_token", ""),
        TG_CHAT_KEY: body.get("telegram_chat_id", ""),
        SMTP_HOST_KEY: body.get("smtp_host", ""),
        SMTP_PORT_KEY: str(body.get("smtp_port", 587)),
        SMTP_USER_KEY: body.get("smtp_user", ""),
        SMTP_PASS_KEY: body.get("smtp_pass", ""),
        SMTP_FROM_KEY: body.get("smtp_from", ""),
        SMTP_TO_KEY: body.get("smtp_to", ""),
    }
    for key, value in mapping.items():
        conn.execute(
            """
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, (value or "").strip()),
        )
