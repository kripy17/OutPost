"""Alert notifications — fan-out across webhook / Slack / Discord / Telegram / SMTP.

Settings live in the `settings` table (key/value); a channel is enabled when
its keys are present and non-empty. When a malicious alert is raised (or a
watched IOC appears in a new batch), `notify_new_alerts` / `notify_watchlist_hits`
deliver to **every** configured channel — fire-and-forget (the ingestion path
must not block on a slow/unreachable endpoint), with a short timeout and a
quiet failure.

Channels
--------
- `NOTIFY_WEBHOOK_URL`      generic JSON webhook (existing contract, unchanged)
- `NOTIFY_SLACK_WEBHOOK_URL`   Slack incoming-webhook (text payload)
- `NOTIFY_DISCORD_WEBHOOK_URL` Discord webhook (content payload)
- `NOTIFY_TELEGRAM_BOT_TOKEN` + `NOTIFY_TELEGRAM_CHAT_ID`  bot sendMessage
- `NOTIFY_SMTP_HOST/PORT/USER/PASS/FROM/TO`                plain-text email

All HTTP delivery uses httpx (async); SMTP uses stdlib smtplib via a thread so
it never blocks the event loop. Everything is deliberately dependency-light.
"""

import asyncio
import html
import smtplib
import ssl
from email.message import EmailMessage

import httpx

from ..core.schema import Alert

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

_TIMEOUT = 5.0

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


def get_settings(conn) -> dict:
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


def set_settings(conn, body: dict) -> None:
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


# -- Payload shaping ------------------------------------------------------------


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


def _watchlist_payload(
    run_id: str, sample_name: str, platform: str, matches: list[dict], sent_at: str
) -> dict:
    return {
        "event": "outpost.watchlist",
        "run_id": run_id,
        "sample_name": sample_name,
        "platform": platform,
        "matches": matches,
        "sent_at": sent_at,
    }


def _human_line(payload: dict) -> str:
    """One-line rendering used by Slack/Discord/Telegram/email bodies."""
    if payload.get("event") == "outpost.watchlist":
        vals = ", ".join(
            f"{m.get('ioc_type')}:{m.get('ioc_value')}" for m in payload.get("matches", [])
        )
        return (
            f"OutPost watchlist hit — {payload.get('sample_name')} ({payload.get('platform')}) "
            f"run {payload.get('run_id')}: {vals}"
        )
    if payload.get("event") == "outpost.fleet":
        return f"OutPost fleet — {payload.get('kind')} · host {payload.get('host_id')}: {payload.get('detail')}"
    return (
        f"[{payload.get('severity', '').upper()}] {payload.get('rule_name')} "
        f"({payload.get('rule_id')}) — {payload.get('details')} — run {payload.get('run_id')}"
    )


# -- Per-channel senders --------------------------------------------------------


async def _send_generic_webhook(client: httpx.AsyncClient, url: str, payload: dict) -> None:
    await client.post(url, json=payload)


async def _send_slack(client: httpx.AsyncClient, url: str, payload: dict) -> None:
    await client.post(url, json={"text": _human_line(payload)})


async def _send_discord(client: httpx.AsyncClient, url: str, payload: dict) -> None:
    severity = payload.get("severity", "suspicious")
    color = 0xEF4444 if severity == "malicious" else 0xF59E0B
    await client.post(
        url,
        json={
            "embeds": [{
                "title": "OutPost — " + (_human_line(payload).split(" — ", 1)[0]),
                "description": _human_line(payload),
                "color": color,
                "footer": {"text": f"event {payload.get('event', 'outpost.alert')}"},
            }]
        },
    )


async def _send_telegram(client: httpx.AsyncClient, token: str, chat_id: str, payload: dict) -> None:
    await client.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": html.escape(_human_line(payload), quote=False),
            "disable_web_page_preview": True,
        },
    )


def _send_smtp_sync(settings: dict, payload: dict) -> None:
    """Blocking SMTP send — run inside a thread (never on the event loop).

    `settings` is the flat dict from `get_settings` (smtp_host, smtp_port, ...).
    """
    host = settings.get("smtp_host", "")
    port = int(settings.get("smtp_port") or "587")
    user, pwd = settings.get("smtp_user", ""), settings.get("smtp_pass", "")
    sender = settings.get("smtp_from") or user or "outpost@localhost"
    recipients = [r.strip() for r in settings.get("smtp_to", "").split(",") if r.strip()]
    if not host or not recipients:
        return

    msg = EmailMessage()
    msg["Subject"] = f"OutPost {payload.get('event', 'alert')} — {_human_line(payload)[:80]}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(
        _human_line(payload) + "\n\n"
        f"run_id: {payload.get('run_id', '-')}\n"
        f"triggered_at: {payload.get('triggered_at', payload.get('sent_at', '-'))}"
    )

    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=_TIMEOUT, context=ctx) as server:
            if user:
                server.login(user, pwd)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=_TIMEOUT) as server:
            server.ehlo()
            if port == 587:
                server.starttls(context=ctx)
                server.ehlo()
            if user:
                server.login(user, pwd)
            server.send_message(msg)


# -- Fan-out entry points -------------------------------------------------------


def _channels(settings: dict) -> list[tuple[str, dict]]:
    """Configured channels as (kind, params) pairs, in a stable order.

    `settings` is the flat dict from `get_settings` (webhook_url, slack_webhook,
    ...), so lookups use those keys.
    """
    out: list[tuple[str, dict]] = []
    if settings.get("webhook_url"):
        out.append(("webhook", {"url": settings["webhook_url"]}))
    if settings.get("slack_webhook"):
        out.append(("slack", {"url": settings["slack_webhook"]}))
    if settings.get("discord_webhook"):
        out.append(("discord", {"url": settings["discord_webhook"]}))
    if settings.get("telegram_bot_token") and settings.get("telegram_chat_id"):
        out.append(("telegram", {"token": settings["telegram_bot_token"], "chat_id": settings["telegram_chat_id"]}))
    if settings.get("smtp_host") and settings.get("smtp_to"):
        out.append(("smtp", {}))
    return out


def _target_label(kind: str, params: dict) -> str:
    if kind == "webhook":
        return params["url"]
    if kind == "slack":
        return f"slack:{params['url']}"
    if kind == "discord":
        return f"discord:{params['url']}"
    if kind == "telegram":
        return f"telegram:{params['chat_id']}"
    return "smtp"


async def notify_new_alerts(alerts: list[Alert]) -> list[str]:
    """Deliver each *malicious* alert to every configured channel.

    Reads settings from its own DB session (safe after the ingestion
    transaction commits). Returns the channel targets actually attempted.
    Quiet on failure — ingestion must never break because a channel is down.
    """
    from ..core.db import db_session

    with db_session() as conn:
        settings = get_settings(conn)
    channels = _channels(settings)
    if not channels:
        return []

    targets = [a for a in alerts if a.severity == "malicious"]
    if not targets:
        return []

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for alert in targets:
            payload = _payload(alert)
            for kind, params in channels:
                try:
                    if kind == "webhook":
                        await _send_generic_webhook(client, params["url"], payload)
                    elif kind == "slack":
                        await _send_slack(client, params["url"], payload)
                    elif kind == "discord":
                        await _send_discord(client, params["url"], payload)
                    elif kind == "telegram":
                        await _send_telegram(client, params["token"], params["chat_id"], payload)
                    else:  # smtp
                        await asyncio.to_thread(_send_smtp_sync, settings, payload)
                except Exception:
                    pass
    return [_target_label(kind, params) for kind, params in channels]


async def notify_fleet_event(kind: str, host_id: str, detail: str) -> list[str]:
    """Deliver a fleet-health event (host went silent, baseline anomaly) to
    every configured channel.

    Same contract as the other notifiers: reads settings from its own DB
    session, quiet on failure, returns the targets attempted. The payload
    reuses the channel senders with `outpost.fleet` event semantics.
    """
    from datetime import datetime, timezone

    from ..core.db import db_session

    with db_session() as conn:
        settings = get_settings(conn)
    channels = _channels(settings)
    if not channels:
        return []

    payload = {
        "event": "outpost.fleet",
        "kind": kind,
        "host_id": host_id,
        "detail": detail,
        "severity": "suspicious",
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for kind_name, params in channels:
            try:
                if kind_name == "webhook":
                    await _send_generic_webhook(client, params["url"], payload)
                elif kind_name == "slack":
                    await _send_slack(client, params["url"], payload)
                elif kind_name == "discord":
                    await _send_discord(client, params["url"], payload)
                elif kind_name == "telegram":
                    await _send_telegram(client, params["token"], params["chat_id"], payload)
                else:  # smtp
                    await asyncio.to_thread(_send_smtp_sync, settings, payload)
            except Exception:
                pass
    return [_target_label(kind_name, params) for kind_name, params in channels]


async def notify_watchlist_hits(
    run_id: str, sample_name: str, platform: str, matches: list[dict]
) -> list[str]:
    """Deliver a watched-IOC hit to every configured channel.

    Same contract as `notify_new_alerts`: reads settings from its own session,
    fire-and-forget, quiet on failure, returns the targets attempted.
    """
    from datetime import datetime, timezone

    from ..core.db import db_session

    with db_session() as conn:
        settings = get_settings(conn)
    channels = _channels(settings)
    if not channels or not matches:
        return []

    payload = _watchlist_payload(
        run_id,
        sample_name,
        platform,
        matches,
        datetime.now(timezone.utc).isoformat(),
    )
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for kind, params in channels:
            try:
                if kind == "webhook":
                    await _send_generic_webhook(client, params["url"], payload)
                elif kind == "slack":
                    await _send_slack(client, params["url"], payload)
                elif kind == "discord":
                    await _send_discord(client, params["url"], payload)
                elif kind == "telegram":
                    await _send_telegram(client, params["token"], params["chat_id"], payload)
                else:  # smtp
                    await asyncio.to_thread(_send_smtp_sync, settings, payload)
            except Exception:
                pass
    return [_target_label(kind, params) for kind, params in channels]
