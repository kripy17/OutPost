"""Notification settings (roadmap 3.1) — view/configure the alert webhook.

- GET  /notifications/settings — current webhook URL (masked? no — it's the
                                 analyst's own endpoint, shown plainly)
- PUT  /notifications/settings — set the webhook URL ("" disables)

Webhook delivery itself happens inside the ingestion path via
services/notifications.notify_new_alerts.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from ..core.db import db_session
from ..services import notifications as notify

router = APIRouter(tags=["notifications"])


class NotifySettingsIn(BaseModel):
    webhook_url: str = ""


@router.get("/notifications/settings", response_model=None)
def get_settings() -> dict:
    with db_session() as conn:
        url = notify.get_webhook_url(conn)
    return {"enabled": bool(url), "webhook_url": url}


@router.put("/notifications/settings", response_model=None)
def set_settings(body: NotifySettingsIn) -> dict:
    with db_session() as conn:
        notify.set_webhook_url(conn, body.webhook_url)
        url = notify.get_webhook_url(conn)
    return {"enabled": bool(url), "webhook_url": url}
