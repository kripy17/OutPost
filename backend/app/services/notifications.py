"""Alert notifications (roadmap 3.1) — webhook on new malicious alerts.

Settings live in the `settings` table (key/value) with a `NOTIFY_WEBHOOK_URL`
row; absent or empty means notifications are off. When a malicious alert is
raised, `notify_new_alerts` POSTs a compact JSON payload to the webhook —
fire-and-forget (the ingestion path must not block on a slow/unreachable
endpoint), with a short timeout and a quiet failure.

The CLI already ships `plyer`; a desktop-notification path could reuse it,
but the webhook is the portable, zero-dependency channel first.
"""

import httpx

from ..core.schema import Alert

WEBHOOK_KEY = "NOTIFY_WEBHOOK_URL"
_TIMEOUT = 5.0


def get_webhook_url(conn) -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (WEBHOOK_KEY,)).fetchone()
    return (row["value"] if row else "").strip()


def set_webhook_url(conn, url: str) -> None:
    conn.execute(
        """
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (WEBHOOK_KEY, url.strip()),
    )


def _payload(alert: Alert) -> dict:
    return {
        "event": "outpost.alert",
        "severity": alert.severity,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "run_id": alert.run_id,
        "details": alert.details,
        "triggered_at": alert.triggered_at.isoformat(),
    }


async def notify_new_alerts(alerts: list[Alert]) -> list[str]:
    """POST each *malicious* alert to the configured webhook.

    Reads the webhook URL from its own DB session (safe to call after the
    ingestion transaction commits). Returns the webhook URLs actually
    attempted (for tests/logging). Quiet on failure — ingestion must never
    break because a webhook is down.
    """
    from ..core.db import db_session

    with db_session() as conn:
        webhook = get_webhook_url(conn)
    if not webhook:
        return []

    targets = [a for a in alerts if a.severity == "malicious"]
    if not targets:
        return []

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for alert in targets:
            try:
                await client.post(webhook, json=_payload(alert))
            except httpx.HTTPError:
                pass
    return [webhook]
