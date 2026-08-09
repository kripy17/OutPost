"""Per-host behavioral baseline (roadmap 4.x) — the anomaly layer.

Threshold rules catch *known* patterns; baselines catch *unseen* ones. The
learner watches what a host actually does — which binaries execute
(kind='process') and which IPs it talks to (kind='net') — and the deviation
check flags first-time values once the baseline is established, so a host that
suddenly runs a binary it never ran before, or phones an IP it never phoned,
becomes an anomaly instead of silently blending into the noise.

The check-then-learn ordering inside a batch means each novel item fires
exactly once: it's not in the baseline when the batch arrives → alert → we
learn it → the next batch sees it as known. A brand-new host is quiet until
its baseline passes the min-events gate (BASELINE_MIN_EVENTS, default 100),
so first-day traffic never spams anomalies.
"""

import datetime
from typing import Iterator

from ..core.schema import Alert

RULE_ID = "baseline-anomaly"
RULE_NAME = "Baseline anomaly"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _kinds(event: dict) -> Iterator[tuple[str, str]]:
    """The baseline-able observations of one normalized event."""
    if event.get("event_type") == "process_create" and event.get("process_name"):
        yield "process", event["process_name"]
    elif event.get("event_type") == "network_connection" and event.get("dest_ip"):
        yield "net", event["dest_ip"]


def _named_host(event: dict) -> str | None:
    """The baseline only learns *named* agent hosts — the `local` fallback
    (webapp detonations, sandbox runs, seeded demos) is not a host with a
    behavioral baseline, and letting it learn would let shared demo data
    cross the gate and pollute every other run with anomalies."""
    host = event.get("host_id") or "local"
    return host if host != "local" else None


def learn(conn, events: list[dict]) -> None:
    """Upsert baseline counts for every (host, kind, value) in the batch."""
    ts = _now()
    seen: set[tuple] = set()
    for ev in events:
        host = _named_host(ev)
        if host is None:
            continue
        for kind, value in _kinds(ev):
            key = (host, kind, value)
            if key in seen:
                continue
            seen.add(key)
            conn.execute(
                """
                INSERT INTO host_baselines (host_id, kind, value, count, last_seen)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(host_id, kind, value) DO UPDATE SET
                    count = count + 1, last_seen = excluded.last_seen
                """,
                (host, kind, value, ts),
            )


def _established(conn, host_id: str, min_events: int) -> bool:
    total = conn.execute(
        "SELECT COALESCE(SUM(count), 0) FROM host_baselines WHERE host_id = ?",
        (host_id,),
    ).fetchone()[0]
    return total >= min_events


def check_deviations(conn, events: list[dict], min_events: int = 100) -> list[tuple[str, str, str, dict]]:
    """Novel (host, kind, value) observations in a batch.

    Returns one tuple per first-time observation (deduped within the batch).
    Quiet for hosts whose baseline isn't established yet.
    """
    found: list[tuple[str, str, str, dict]] = []
    seen: set[tuple] = set()
    for ev in events:
        host = _named_host(ev)
        if host is None or not _established(conn, host, min_events):
            continue
        for kind, value in _kinds(ev):
            key = (host, kind, value)
            if key in seen:
                continue
            seen.add(key)
            row = conn.execute(
                "SELECT 1 FROM host_baselines WHERE host_id = ? AND kind = ? AND value = ?",
                (host, kind, value),
            ).fetchone()
            if row is None:
                found.append((host, kind, value, ev))
    return found


def build_alert(run_id: str, host: str, kind: str, value: str, event: dict) -> Alert:
    """One baseline-anomaly alert for a first-time observation."""
    if kind == "net":
        details = f"First-time network destination on host {host}: {value}"
        related_ip = value
        related_pid = event.get("pid")
    else:
        details = f"First-time process on host {host}: {value}"
        related_ip = None
        related_pid = event.get("pid")
    return Alert(
        run_id=run_id,
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="suspicious",
        triggered_at=event.get("timestamp") or _now(),
        related_pid=related_pid,
        related_ip=related_ip,
        details=details,
    )
