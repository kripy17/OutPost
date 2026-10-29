"""Notification settings — view/configure all alert channels.

- GET  /notifications/settings — every channel's current config (webhook,
                                 Slack, Discord, Telegram, SMTP)
- PUT  /notifications/settings — update any subset of channels ("" clears)
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..core.db import db_session
from ..core.ssrf import validate_outbound_url
from ..models import audit
from ..services import notifications as notify

router = APIRouter(tags=["notifications"])


class NotifySettingsIn(BaseModel):
    webhook_url: str = ""
    slack_webhook: str = ""
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int | str = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""
    smtp_to: str = ""


def _response(settings: dict) -> dict:
    enabled = bool(
        settings["webhook_url"]
        or settings["slack_webhook"]
        or settings["discord_webhook"]
        or settings["telegram_bot_token"]
        or settings["smtp_host"]
    )
    # Never echo the SMTP password back to the browser; a set password is
    # signalled by `smtp_pass_set` so the UI can say "keep existing".
    smtp_pass_set = bool(settings["smtp_pass"])
    return {**settings, "enabled": enabled, "smtp_pass": "", "smtp_pass_set": smtp_pass_set}


@router.get("/notifications/settings", response_model=None)
def get_settings() -> dict:
    with db_session() as conn:
        settings = notify.get_settings(conn)
    return _response(settings)


@router.put("/notifications/settings", response_model=None)
def set_settings(body: NotifySettingsIn) -> dict:
    # SSRF guard on outbound webhooks
    for field_name, url_val in [
        ("webhook_url", body.webhook_url),
        ("slack_webhook", body.slack_webhook),
        ("discord_webhook", body.discord_webhook),
    ]:
        if url_val and url_val.strip():
            is_valid, reason, _ = validate_outbound_url(url_val.strip())
            if not is_valid:
                raise HTTPException(status_code=400, detail=f"SSRF violation in {field_name}: {reason}")

    with db_session() as conn:
        # Blank SMTP password + a previously stored one -> keep the old value
        # (the GET response never returns it, so the UI can't clobber it).
        existing = notify.get_settings(conn)
        payload = body.model_dump()
        if not payload.get("smtp_pass") and existing.get("smtp_pass"):
            payload["smtp_pass"] = existing["smtp_pass"]
        notify.set_settings(conn, payload)
        settings = notify.get_settings(conn)
        audit.log(
            conn,
            actor="analyst",
            action="settings.webhook_update",
            target_type="notifications",
            target_id="settings",
            detail="updated notification integration channels",
            before_state=_response(existing),
            after_state=_response(settings),
        )
    return _response(settings)
