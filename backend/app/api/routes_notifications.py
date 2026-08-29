"""Notification settings — view/configure all alert channels.

- GET  /notifications/settings — every channel's current config (webhook,
                                 Slack, Discord, Telegram, SMTP)
- PUT  /notifications/settings — update any subset of channels ("" clears)

Delivery happens inside the ingestion path via services/notifications;
`enabled` is true when at least one channel is configured.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from ..core.db import db_session
from ..services import notifications as notify

router = APIRouter(tags=["notifications"])


class NotifySettingsIn(BaseModel):
    """Secret fields are `str | None`: None/absent = keep stored value,
    "" = explicitly clear. Non-secret plain strings default to overwrite."""

    webhook_url: str | None = None
    slack_webhook: str | None = None
    discord_webhook: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int | str = 587
    smtp_user: str = ""
    smtp_pass: str | None = None
    smtp_from: str = ""
    smtp_to: str = ""


def _response(settings: dict) -> dict:
    enabled = bool(
        settings["webhook_url"] or settings["slack_webhook"] or settings["discord_webhook"]
        or settings["telegram_bot_token"] or settings["smtp_host"]
    )
    # Never echo credentials back to the browser; a set value is signalled by
    # `<field>_set` so the UI can say "keep existing". Covers the SMTP
    # password, the Telegram bot token, and every webhook URL.
    secret_fields = ("smtp_pass", "telegram_bot_token", "webhook_url", "slack_webhook", "discord_webhook")
    out = {**settings, "enabled": enabled}
    for field in secret_fields:
        out[f"{field}_set"] = bool(out.get(field))
        out[field] = ""
    return out


@router.get("/notifications/settings", response_model=None)
def get_settings() -> dict:
    with db_session() as conn:
        settings = notify.get_settings(conn)
    return _response(settings)


@router.put("/notifications/settings", response_model=None)
def set_settings(body: NotifySettingsIn) -> dict:
    with db_session() as conn:
        # Secret fields: None (absent) + a previously stored one → keep the
        # old value (the GET response never returns credentials, so a UI
        # round-trip can't clobber them). An explicit "" clears the secret.
        existing = notify.get_settings(conn)
        payload = body.model_dump()
        for field in ("smtp_pass", "telegram_bot_token", "webhook_url", "slack_webhook", "discord_webhook"):
            if payload.get(field) is None and existing.get(field):
                payload[field] = existing[field]
        notify.set_settings(conn, payload)
        settings = notify.get_settings(conn)
    return _response(settings)
