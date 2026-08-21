"""GET /meta — app metadata: demo-mode flag, version, and first-run state.

POST /setup/onboard — the first-run welcome's two paths: `demo` runs the same
labeled seed the CLI uses; `empty` records the choice without seeding. Either
way the choice is stored so the welcome never reappears, and a fresh install
never silently shows demo data as real (the Overview banner labels it).
"""


def test_meta_off_by_default(client):
    meta = client.get("/meta").json()
    assert meta["demo_mode"] is False
    assert meta["version"] == "1.0"
    assert meta["onboarding"] is None  # no choice recorded yet
    assert isinstance(meta["first_run"], bool)


def test_meta_reflects_demo_flag_after_seed(client, conn):
    """Exactly what the seed scripts do — one settings row flips the flag."""
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('demo_mode', '1') "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    )
    conn.commit()
    try:
        assert client.get("/meta").json()["demo_mode"] is True
    finally:
        conn.execute("DELETE FROM settings WHERE key = 'demo_mode'")
        conn.commit()
    assert client.get("/meta").json()["demo_mode"] is False


def test_onboard_empty_records_choice_without_seeding(client):
    resp = client.post("/setup/onboard", json={"choice": "empty"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "choice": "empty", "demo_mode": False}

    meta = client.get("/meta").json()
    assert meta["onboarding"] == "empty"
    assert meta["demo_mode"] is False
    assert meta["first_run"] is False  # the choice is recorded — no welcome again


def test_onboard_demo_seeds_labeled_campaign(client, conn):
    resp = client.post("/setup/onboard", json={"choice": "demo"})
    assert resp.status_code == 200
    assert resp.json()["demo_mode"] is True

    meta = client.get("/meta").json()
    assert meta["onboarding"] == "demo"
    assert meta["demo_mode"] is True

    # The seeded run actually exists (same seed the CLI runs).
    rows = conn.execute(
        "SELECT run_id FROM runs WHERE sample_name = 'demo-sample.exe' AND source = 'seed'"
    ).fetchall()
    assert rows, "demo seed should have created the demo-sample.exe run"
    rid = rows[0]["run_id"]
    events = conn.execute("SELECT COUNT(*) AS n FROM events WHERE run_id = ?", (rid,)).fetchone()["n"]
    alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE run_id = ?", (rid,)).fetchone()["n"]
    assert events == 6 and alerts == 3

    # Clean up so the shared test DB returns to its pre-test state (the demo
    # run's IP/alerts must not leak into other tests' global assertions).
    conn.execute("DELETE FROM alerts WHERE run_id = ?", (rid,))
    conn.execute("DELETE FROM events WHERE run_id = ?", (rid,))
    conn.execute("DELETE FROM runs WHERE run_id = ?", (rid,))
    conn.execute("DELETE FROM settings WHERE key IN ('demo_mode', 'onboarding')")
    conn.commit()
    meta2 = client.get("/meta").json()
    assert meta2["demo_mode"] is False
    assert meta2["onboarding"] is None


def test_onboard_rejects_unknown_choice(client):
    assert client.post("/setup/onboard", json={"choice": "maybe"}).status_code == 422


from .conftest import make_run


def _copy_db(src_path: str, dst_path: str) -> None:
    """SQLite backup API — copies src → dst safely even with open connections."""
    import sqlite3 as _sql

    src = _sql.connect(src_path)
    try:
        dst = _sql.connect(dst_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def test_reset_keeps_local_host_telemetry_only(client, conn):
    """POST /setup/reset — the start-fresh wipe.

    Runs whose events carry THIS machine's host id (the collector's host_id:
    lowercased hostname) survive; everything else — seeds, webapp-synthetic
    detonations, sandbox demos, CLI test runs — is deleted along with its
    child rows, and demo_mode flips off.

    The reset genuinely wipes the store, so the shared session DB is
    snapshotted first and restored afterwards — other tests' rows must
    survive this test. Assertions are relative to the runs this test creates
    (never absolute totals).
    """
    import os
    import socket

    from ..core import config

    local_host = socket.gethostname().lower()
    live_path = str(config.DATABASE_PATH)
    snap_path = live_path + ".reset-snap"
    _copy_db(live_path, snap_path)
    try:
        # A real-host run: events tagged with the local host id.
        real = make_run(client, sample_name="real-soak.bin", source="live")
        client.post(
            "/ingest/batch",
            json=[
                {
                    "run_id": real,
                    "platform": "linux",
                    "event_type": "process_create",
                    "timestamp": "2026-08-09T12:00:00Z",
                    "pid": 100,
                    "ppid": 1,
                    "process_name": "bash",
                    "command_line": "bash -c whoami",
                    "host_id": local_host,
                }
            ],
        )

        # A synthetic run: webapp-demo source, events without the local host id.
        syn = make_run(client, sample_name="fake-demo.exe", source="webapp-demo")
        client.post(
            "/ingest/batch",
            json=[
                {
                    "run_id": syn,
                    "platform": "windows",
                    "event_type": "process_create",
                    "timestamp": "2026-08-09T12:01:00Z",
                    "pid": 200,
                    "ppid": 1,
                    "process_name": "cmd.exe",
                    "command_line": "cmd.exe /c whoami",
                    "host_id": "ghost-box",
                }
            ],
        )
        # A second synthetic run with no host tag at all.
        seed = make_run(client, sample_name="demo-sample.exe", source="seed")
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('demo_mode', '1') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        )
        conn.commit()

        total_before = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]

        resp = client.post("/setup/reset")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["demo_mode"] is False
        # Relative to the pre-existing session state: exactly our three runs
        # change — two deleted, one kept (plus whatever the session already had).
        assert body["deleted_runs"] == total_before - 1
        assert body["kept_runs"] >= 1

        remaining = {r[0] for r in conn.execute("SELECT run_id FROM runs")}
        assert real in remaining
        assert syn not in remaining and seed not in remaining
        # Child rows for the deleted runs are gone too.
        assert conn.execute("SELECT COUNT(*) AS n FROM events WHERE run_id = ?", (syn,)).fetchone()["n"] == 0
        assert conn.execute("SELECT COUNT(*) AS n FROM events WHERE run_id = ?", (seed,)).fetchone()["n"] == 0
        assert conn.execute("SELECT COUNT(*) AS n FROM events WHERE run_id = ?", (real,)).fetchone()["n"] == 1
        # demo_mode cleared, so /meta reads honest.
        assert client.get("/meta").json()["demo_mode"] is False
    finally:
        # Restore the snapshot — the wipe must not leak into other tests.
        _copy_db(snap_path, live_path)
        if os.path.exists(snap_path):
            os.remove(snap_path)


def test_run_archive_hides_synthetic_by_default(client):
    """The History archive reads as real telemetry first: seed / webapp-demo /
    legacy monitor / sandbox:demo runs are hidden from the bare /runs list,
    while live-host and CLI analyses always show. include_synthetic=true
    reveals everything (the CLI uses this to keep parity)."""
    make_run(client, sample_name="host-real.bin", source="live")
    make_run(client, sample_name="cli-real.bin", source="cli")
    synth_names = ("demo-sample.exe", "synth-web.bin", "legacy-mon.bin", "sandbox-demo.exe")
    for src, name in (
        ("seed", "demo-sample.exe"),
        ("webapp-demo", "synth-web.bin"),
        ("monitor", "legacy-mon.bin"),
        ("sandbox:demo", "sandbox-demo.exe"),
    ):
        make_run(client, sample_name=name, source=src)

    # Bare endpoint (the History default): synthetic hidden, real visible.
    visible = {r["sample_name"] for r in client.get("/runs").json()}
    assert "host-real.bin" in visible and "cli-real.bin" in visible
    assert not visible.intersection(synth_names)

    # Opt-in: everything shows, including all four synthetic markers.
    shown = {r["sample_name"] for r in client.get("/runs", params={"include_synthetic": "true"}).json()}
    assert "host-real.bin" in shown
    assert set(synth_names).issubset(shown)
