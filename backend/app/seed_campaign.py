"""Seed a campaign-style pair of runs for the demo/portfolio walkthrough.

Two variants of the same attack chain share a C2 IP (203.0.113.88:4444) —
the same infrastructure the webapp's synthetic detonation beacons to
(frontend/src/lib/synthetic.ts). That makes the full walkthrough arc work
against one story:

    detonate → search the shared C2 → compare variants → watchlist → rules

Unlike seed_demo, alerts here are computed by the REAL detection engine
(services.detection.evaluate_batch), so they are exactly what live
monitoring would produce — including the first-seen-process rule when a
variant introduces novel binaries. Runs and events are backdated so the pair
reads as historical context for today's live detonation.

Variant A — "ACME_invoice.docm"   macro dropper: winword → powershell → cmd,
                                  beacons to the campaign C2 + a second C2
                                  already flagged by external threat intel.
Variant B — "invoice_lure.lnk"    LNK second-stage: wscript → powershell,
                                  plus a rapid file-write burst.

Run from backend/:  python -m app.seed_campaign
"""

import datetime
import uuid

from .core.db import db_session, init_db
from .models import event as event_store
from .models import run as run_store
from .services import detection

C2_CAMPAIGN = "203.0.113.88"   # shared by both variants + the webapp detonation
C2_SECONDARY = "185.220.101.34"  # variant A only; known malicious (intel cache)

VARIANT_A = "ACME_invoice.docm"
VARIANT_B = "invoice_lure.lnk"


def _ts(day: int, hour: int, minute: int, second: int = 0) -> str:
    return datetime.datetime(2026, 8, day, hour, minute, second, tzinfo=datetime.timezone.utc).isoformat()


def _beacons(run_id: str, pid: int, day: int, start: tuple[int, int, int], step_s: int, n: int = 5) -> list[dict]:
    h, m, s = start
    out = []
    for i in range(n):
        total = h * 3600 + m * 60 + s + i * step_s
        out.append(
            {
                "run_id": run_id, "platform": "windows", "event_type": "network_connection",
                "timestamp": _ts(day, total // 3600, (total % 3600) // 60, total % 60),
                "pid": pid, "dest_ip": C2_CAMPAIGN, "dest_port": 4444, "protocol": "TCP",
            }
        )
    return out


def _variant_a(run_id: str) -> list[dict]:
    """Macro dropper: winword → powershell -enc → cmd, C2 beacon + second C2."""
    return [
        {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(5, 10, 12, 1),
         "pid": 1000, "ppid": 4, "process_name": "winword.exe",
         "command_line": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE /q /n"},
        {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(5, 10, 12, 4),
         "pid": 1001, "ppid": 1000, "process_name": "powershell.exe",
         "command_line": "powershell.exe -enc SQBFAFgAAGgBdAA="},
        {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(5, 10, 12, 7),
         "pid": 1002, "ppid": 1000, "process_name": "cmd.exe",
         "command_line": r"C:\Windows\System32\cmd.exe /c whoami"},
        *(_beacons(run_id, 1002, 5, (10, 12, 20), 10)),
        {"run_id": run_id, "platform": "windows", "event_type": "network_connection", "timestamp": _ts(5, 10, 13, 2),
         "pid": 1002, "dest_ip": C2_SECONDARY, "dest_port": 4444, "protocol": "TCP"},
        {"run_id": run_id, "platform": "windows", "event_type": "network_connection", "timestamp": _ts(5, 10, 13, 5),
         "pid": 1000, "dest_ip": "1.1.1.1", "dest_port": 443, "protocol": "TCP"},
        {"run_id": run_id, "platform": "windows", "event_type": "registry_write", "timestamp": _ts(5, 10, 13, 10),
         "pid": 1000, "process_name": "winword.exe",
         "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"},
    ]


def _variant_b(run_id: str) -> list[dict]:
    """LNK second-stage: wscript → hidden powershell, beacon + file-write burst."""
    events = [
        {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(6, 9, 47, 1),
         "pid": 2000, "ppid": 4, "process_name": "wscript.exe",
         "command_line": r"wscript.exe C:\Users\Public\invoice_lure\setup.jse"},
        {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(6, 9, 47, 6),
         "pid": 2001, "ppid": 2000, "process_name": "powershell.exe",
         "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAAGgBdAA="},
        {"run_id": run_id, "platform": "windows", "event_type": "network_connection", "timestamp": _ts(6, 9, 47, 30),
         "pid": 2001, "dest_ip": "8.8.8.8", "dest_port": 443, "protocol": "TCP"},
        *(_beacons(run_id, 2001, 6, (9, 48, 0), 10)),
        {"run_id": run_id, "platform": "windows", "event_type": "registry_write", "timestamp": _ts(6, 9, 48, 50),
         "pid": 2000, "process_name": "wscript.exe",
         "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"},
    ]
    # 11 file writes within 10 seconds → rename-burst (threshold 10).
    for i in range(11):
        events.append(
            {"run_id": run_id, "platform": "windows", "event_type": "file_write",
             "timestamp": _ts(6, 9, 49, i),
             "pid": 2000, "file_path": f"C:\\Users\\victim\\Documents\\q3_report_{i:03d}.enc"}
        )
    return events


def _seed_variant(conn, run_id: str, sample_name: str, events: list[dict], first_ts: str, last_ts: str) -> list[str]:
    run_store.create_run(conn, run_id, sample_name=sample_name, platform="windows", session_type="analysis", source="seed")
    for ev in events:
        event_store.insert_event(conn, ev)
    new_alerts = detection.evaluate_batch(conn, run_id, events)

    # Backdate run + alert timestamps so the pair reads as history.
    conn.execute("UPDATE runs SET started_at = ?, completed_at = ? WHERE run_id = ?", (first_ts, last_ts, run_id))
    conn.execute("UPDATE alerts SET triggered_at = ? WHERE run_id = ?", (last_ts, run_id))
    return [a.rule_id for a in new_alerts]


def main() -> dict[str, str]:
    init_db()

    with db_session() as conn:
        # Same demo label as seed_demo — the webapp banner marks seeded data.
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('demo_mode', '1') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        )
        rid_a = uuid.uuid4().hex[:12]
        rid_b = uuid.uuid4().hex[:12]

        events_a = _variant_a(rid_a)
        events_b = _variant_b(rid_b)

        rules_a = _seed_variant(conn, rid_a, VARIANT_A, events_a, _ts(5, 10, 12, 1), _ts(5, 10, 13, 10))
        rules_b = _seed_variant(conn, rid_b, VARIANT_B, events_b, _ts(6, 9, 47, 1), _ts(6, 9, 49, 10))

        # Deterministic threat-intel cache (no API keys needed for the demo).
        event_store.upsert_cache(conn, C2_CAMPAIGN, 87, 64, "malicious")
        event_store.upsert_cache(conn, C2_SECONDARY, 92, 18, "malicious")
        event_store.upsert_cache(conn, "1.1.1.1", 0, 0, "clean")
        event_store.upsert_cache(conn, "8.8.8.8", 0, 0, "clean")

    print(f"Seeded campaign pair — both beacon to {C2_CAMPAIGN}:4444")
    print(f"  Variant A  {VARIANT_A:24s} {rid_a}  {len(events_a):2d} events, {len(rules_a)} alerts  {sorted(set(rules_a))}")
    print(f"  Variant B  {VARIANT_B:24s} {rid_b}  {len(events_b):2d} events, {len(rules_b)} alerts  {sorted(set(rules_b))}")
    print("Open the webapp, or run:  outpost show <run_id>")
    return {"variant_a": rid_a, "variant_b": rid_b}


if __name__ == "__main__":
    main()
