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
