"""Seed a realistic demo run so the webapp and CLI work without a collector.

AGENTS.md rule 5: backend, frontend, and CLI are independently runnable —
the frontend and CLI must both work against a sample dataset without a live
collector. This creates a completed analysis run with a process tree, network
connections (enriched), a timeline, and several detection alerts.

Run from backend/:  python -m app.seed_demo
"""

import datetime
import uuid

from .core.db import db_session, init_db
from .core.schema import Alert
from .models import event as event_store
from .models import run as run_store


def _ts(day: int, hour: int, minute: int, second: int = 0) -> str:
    return datetime.datetime(2026, 8, day, hour, minute, second, tzinfo=datetime.timezone.utc).isoformat()


def main() -> str:
    init_db()
    run_id = uuid.uuid4().hex[:12]

    with db_session() as conn:
        # Demo mode stays OFF by default: seeding demo data must not flip the
        # banner on silently. The explicit onboarding "demo" choice sets the
        # flag itself (routes_setup); the per-run SEED badges keep every seeded
        # row honest regardless.
        run_store.create_run(conn, run_id, sample_name="demo-sample.exe", platform="windows", session_type="analysis", source="seed")

        events = [
            # Process tree: demo-sample.exe → cmd.exe → powershell.exe
            {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(1, 10, 0, 1),
             "pid": 1000, "ppid": 4, "process_name": "demo-sample.exe", "command_line": r"C:\temp\demo-sample.exe"},
            {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(1, 10, 0, 3),
             "pid": 1001, "ppid": 1000, "process_name": "cmd.exe", "command_line": r"C:\Windows\System32\cmd.exe /c whoami"},
            {"run_id": run_id, "platform": "windows", "event_type": "process_create", "timestamp": _ts(1, 10, 0, 5),
             "pid": 1002, "ppid": 1001, "process_name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"},
            # Network: one malicious, one clean
            {"run_id": run_id, "platform": "windows", "event_type": "network_connection", "timestamp": _ts(1, 10, 0, 10),
             "pid": 1002, "dest_ip": "185.220.101.34", "dest_port": 4444, "protocol": "TCP"},
            {"run_id": run_id, "platform": "windows", "event_type": "network_connection", "timestamp": _ts(1, 10, 0, 20),
             "pid": 1000, "dest_ip": "8.8.8.8", "dest_port": 443, "protocol": "TCP"},
            # Registry persistence
            {"run_id": run_id, "platform": "windows", "event_type": "registry_write", "timestamp": _ts(1, 10, 0, 30),
             "pid": 1000, "process_name": "demo-sample.exe",
             "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"},
        ]
        for ev in events:
            event_store.insert_event(conn, ev)

        alerts = [
            Alert(run_id=run_id, rule_id="suspicious-parent-child", rule_name="Suspicious parent-child process relationship",
                  severity="malicious", triggered_at=datetime.datetime(2026, 8, 1, 10, 0, 3, tzinfo=datetime.timezone.utc),
                  related_pid=1001, details="demo-sample.exe spawned cmd.exe — common macro-malware pattern"),
            Alert(run_id=run_id, rule_id="lolbin-abuse", rule_name="Living-off-the-land binary abuse",
                  severity="malicious", triggered_at=datetime.datetime(2026, 8, 1, 10, 0, 5, tzinfo=datetime.timezone.utc),
                  related_pid=1002, details="base64-encoded PowerShell command"),
            Alert(run_id=run_id, rule_id="registry-persistence", rule_name="Persistence via registry Run key",
                  severity="suspicious", triggered_at=datetime.datetime(2026, 8, 1, 10, 0, 30, tzinfo=datetime.timezone.utc),
                  related_pid=1000, details="Write to autorun key: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"),
        ]
        for alert in alerts:
            event_store.insert_alert(conn, alert)

        # Seed enrichment cache so the detail page shows reputations offline.
        event_store.upsert_cache(conn, "185.220.101.34", 92, 18, "malicious")
        event_store.upsert_cache(conn, "8.8.8.8", 0, 0, "clean")

        # Mark complete last so completed_at follows the events' timestamps.
        run_store.complete_run(conn, run_id)

    print(f"Seeded demo run: {run_id} — 6 events, 3 alerts")
    print("Open the webapp (frontend) or run `outpost show <run_id>`.")
    return run_id


if __name__ == "__main__":
    main()
