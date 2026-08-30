"""Tests for roadmap 1.1 — the global Events feed (Event Viewer).

The test DB is shared across the whole session, so every assertion scopes its
counts with a unique marker string (never asserts global totals).
"""

import datetime

from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _event(run_id: str, event_type: str, platform: str, **kw) -> dict:
    base = {
        "run_id": run_id, "platform": platform, "event_type": event_type,
        "timestamp": _ts(0), "pid": 1, "ppid": 0,
    }
    base.update(kw)
    return base


def test_events_source_facet_filters_by_provenance(client):
    """The Event Log's source tabs (Collectors / Webapp / Sandbox) map onto
    run provenance: `live` = host collectors, `sandbox:%` = external sandbox
    detonations, everything else = webapp/CLI/seeds."""
    live = make_run(client, sample_name="src-live.bin", session_type="live")
    web = make_run(client, sample_name="src-web.bin", source="monitor")
    sand = make_run(client, sample_name="src-sand.bin", source="sandbox:anyrun")
    for run_id, ev_type in ((live, "process_create"), (web, "process_create"), (sand, "process_create")):
        _ingest(client, run_id, [_event(run_id, ev_type, "windows", process_name=f"p-{run_id}.exe", timestamp=_ts(1))])

    # Each facet sees exactly its own run's event, and events carry `source`.
    # The shared test DB holds other runs, so scope each facet by the unique
    # process name to prove provenance routing (not global totals).
    live_hit = client.get("/events", params={"source": "live", "q": f"p-{live}.exe"}).json()
    assert live_hit["total"] == 1
    assert live_hit["events"][0]["source"] == "live"
    assert live_hit["events"][0]["sample_name"] == "src-live.bin"

    # The webapp tab is a deliberate provenance ask, so it opts into full
    # content (the legacy monitor run would otherwise be hidden as synthetic).
    web_hit = client.get("/events", params={"source": "webapp", "q": f"p-{web}.exe", "include_synthetic": "true"}).json()
    assert web_hit["total"] == 1
    assert web_hit["events"][0]["source"] == "monitor"
    assert web_hit["events"][0]["sample_name"] == "src-web.bin"

    sand_hit = client.get("/events", params={"source": "sandbox", "q": f"p-{sand}.exe"}).json()
    assert sand_hit["total"] == 1
    assert sand_hit["events"][0]["source"] == "sandbox:anyrun"
    assert sand_hit["events"][0]["sample_name"] == "src-sand.bin"

    # Facets are mutually exclusive: each scoped event only appears in its own.
    assert client.get("/events", params={"source": "webapp", "q": f"p-{live}.exe"}).json()["total"] == 0
    assert client.get("/events", params={"source": "live", "q": f"p-{sand}.exe"}).json()["total"] == 0

    # CSV export honors the facet and carries the source column.
    csv_resp = client.get("/events/export", params={"source": "sandbox", "q": f"p-{sand}.exe"})
    assert csv_resp.status_code == 200
    text = csv_resp.text
    assert text.splitlines()[0].startswith("timestamp,run_id,sample_name,platform,source")
    assert "src-sand.bin" in text and "src-live.bin" not in text

    # Unknown provenance is rejected loudly.
    assert client.get("/events", params={"source": "not-a-source"}).status_code == 422

    # Close the open live run so /runs/active-live's 404 contract holds for
    # the other tests (shared-DB interference, same pattern as test_agents).
    client.post(f"/runs/{live}/complete")


def test_events_channel_facets_split_collector_stream(client):
    """Collectors tag each event with its exact log channel (auditd/sysmon);
    the source tabs split on that tag — authoritative, not inferred from the
    platform label (a linux-platform webapp event is NOT auditd)."""
    aud = make_run(client, sample_name="chan-aud.bin", session_type="live")
    sys = make_run(client, sample_name="chan-sys.bin", session_type="live")
    web = make_run(client, sample_name="chan-web.bin", source="monitor")
    for run_id, chan, name in ((aud, "auditd", "aud"), (sys, "sysmon", "sys"), (web, None, "web")):
        ev = _event(
            run_id, "process_create", "windows" if run_id == sys else "linux",
            process_name=f"c-{run_id}.exe", timestamp=_ts(1),
        )
        if chan:
            ev["log_source"] = chan
        _ingest(client, run_id, [ev])

    # Each channel tab sees exactly its tagged event, and the tag rides out.
    aud_hit = client.get("/events", params={"source": "auditd", "q": f"c-{aud}.exe"}).json()
    assert aud_hit["total"] == 1 and aud_hit["events"][0]["log_source"] == "auditd"
    sys_hit = client.get("/events", params={"source": "sysmon", "q": f"c-{sys}.exe"}).json()
    assert sys_hit["total"] == 1 and sys_hit["events"][0]["log_source"] == "sysmon"
    web_hit = client.get("/events", params={"source": "webapp", "q": f"c-{web}.exe", "include_synthetic": "true"}).json()
    assert web_hit["total"] == 1 and web_hit["events"][0]["log_source"] is None

    # The tag is authoritative: the linux-platform webapp event is NOT auditd,
    # and channels are mutually exclusive.
    assert client.get("/events", params={"source": "auditd", "q": f"c-{web}.exe"}).json()["total"] == 0
    assert client.get("/events", params={"source": "sysmon", "q": f"c-{aud}.exe"}).json()["total"] == 0

    # Both tagged events still count under the coarse Collectors tab.
    assert client.get("/events", params={"source": "live", "q": f"c-{aud}.exe"}).json()["total"] == 1
    assert client.get("/events", params={"source": "live", "q": f"c-{sys}.exe"}).json()["total"] == 1

    # CSV export carries the channel and honors the facet.
    csv_resp = client.get("/events/export", params={"source": "sysmon", "q": f"c-{sys}.exe"})
    assert csv_resp.status_code == 200
    assert "sysmon" in csv_resp.text and f"c-{aud}.exe" not in csv_resp.text

    # Close the live runs so /runs/active-live's 404 contract holds.
    client.post(f"/runs/{aud}/complete")
    client.post(f"/runs/{sys}/complete")


def test_events_channel_counts_one_query_for_source_rail(client):
    """/events/channel-counts returns the whole source-tab rail in one query:
    the grand total plus per-bucket totals (live / auditd / sysmon / webapp /
    sandbox). The run-source buckets partition `total`; auditd/sysmon are
    cross-cutting log_source stamps that overlap live."""
    live = make_run(client, sample_name="cc-live.bin", session_type="live")
    sand = make_run(client, sample_name="cc-sand.bin", source="sandbox:anyrun")
    web = make_run(client, sample_name="cc-web.bin", source="cli")
    seed = make_run(client, sample_name="cc-seed.bin", source="seed")

    def _ev(run_id: str, name: str, platform: str = "linux", chan: str | None = None) -> dict:
        ev = _event(run_id, "process_create", platform, process_name=name, timestamp=_ts(1))
        if chan:
            ev["log_source"] = chan
        return ev

    _ingest(client, live, [_ev(live, "cc-aud.exe", chan="auditd"), _ev(live, "cc-live.exe")])
    _ingest(client, sand, [_ev(sand, "cc-sand.exe", platform="windows")])
    _ingest(client, web, [_ev(web, "cc-web.exe", platform="windows")])
    _ingest(client, seed, [_ev(seed, "cc-seed.exe")])

    # Default view (synthetic hidden): live 2 + sandbox 1 + cli 1; the seed
    # run's event is excluded. Buckets partition the total.
    data = client.get("/events/channel-counts", params={"q": "cc-"}).json()
    assert data["total"] == 4
    assert data["channels"]["live"] == 2
    assert data["channels"]["auditd"] == 1
    assert data["channels"]["sysmon"] == 0
    assert data["channels"]["sandbox"] == 1
    assert data["channels"]["webapp"] == 1
    src_sum = data["channels"]["live"] + data["channels"]["sandbox"] + data["channels"]["webapp"]
    assert src_sum == data["total"]

    # include_synthetic reveals the seed event (still the webapp bucket).
    full = client.get("/events/channel-counts", params={"q": "cc-", "include_synthetic": "true"}).json()
    assert full["total"] == 5
    assert full["channels"]["webapp"] == 2

    # Shared filters apply to the buckets — event_type narrows them all.
    typed = client.get("/events/channel-counts", params={"q": "cc-", "event_type": "network_connection"}).json()
    assert typed["total"] == 0
    assert all(v == 0 for v in typed["channels"].values())

    # Shared validation: unknown event_type → 422.
    assert client.get("/events/channel-counts", params={"event_type": "bogus"}).status_code == 422

    # Close the live run so /runs/active-live's 404 contract holds.
    client.post(f"/runs/{live}/complete")


def test_events_counts_one_query_for_whole_rail(client):
    """/events/counts returns the ENTIRE rail (category + channel) in one
    query: type buckets partition `types.all`, channel buckets mirror the
    channel-counts split, and an active `source` facet narrows the TYPE
    buckets (category badges reflect the selected tab) but never the CHANNEL
    buckets (source is the split dimension)."""
    live = make_run(client, sample_name="cnt-live.bin", session_type="live")
    sand = make_run(client, sample_name="cnt-sand.bin", source="sandbox:anyrun")
    web = make_run(client, sample_name="cnt-web.bin", source="cli")
    seed = make_run(client, sample_name="cnt-seed.bin", source="seed")

    def _ev(run_id: str, name: str, platform: str = "linux", etype: str = "process_create", chan: str | None = None) -> dict:
        ev = _event(run_id, etype, platform, process_name=name, timestamp=_ts(1))
        if chan:
            ev["log_source"] = chan
        return ev

    _ingest(
        client,
        live,
        [
            _ev(live, "cnt-aud.exe", chan="auditd"),
            _ev(live, "cnt-net.exe", etype="network_connection"),
            _ev(live, "cnt-live.exe"),
        ],
    )
    _ingest(client, sand, [_ev(sand, "cnt-sand.exe", platform="windows", etype="file_write")])
    _ingest(client, web, [_ev(web, "cnt-web.exe", platform="windows", etype="registry_write")])
    _ingest(client, seed, [_ev(seed, "cnt-seed.exe")])

    # Default view (synthetic hidden): 5 events, type buckets partition all.
    data = client.get("/events/counts", params={"q": "cnt-"}).json()
    assert data["total"] == 5
    types = data["types"]
    assert types["all"] == 5
    assert types["process_create"] == 2  # aud + live (seed excluded)
    assert types["network_connection"] == 1
    assert types["file_write"] == 1
    assert types["registry_write"] == 1
    assert sum(v for k, v in types.items() if k != "all") == types["all"]
    # Channel split mirrors channel-counts semantics.
    ch = data["channels"]
    assert ch["total"] == 5
    assert ch["live"] == 3 and ch["auditd"] == 1 and ch["sysmon"] == 0
    assert ch["sandbox"] == 1 and ch["webapp"] == 1
    assert ch["live"] + ch["sandbox"] + ch["webapp"] == ch["total"]

    # An active source facet narrows the TYPE buckets but not the CHANNEL
    # buckets (the split dimension): source=live shows only the 3 live events
    # in types, while channels still report the whole set.
    live_view = client.get("/events/counts", params={"q": "cnt-", "source": "live"}).json()
    assert live_view["total"] == 3
    assert live_view["types"]["all"] == 3
    assert live_view["types"]["process_create"] == 2
    assert live_view["types"]["network_connection"] == 1
    assert live_view["channels"]["total"] == 5
    assert live_view["channels"]["live"] == 3

    # include_synthetic reveals the seed event (webapp bucket + process_create).
    full = client.get("/events/counts", params={"q": "cnt-", "include_synthetic": "true"}).json()
    assert full["total"] == 6
    assert full["types"]["process_create"] == 3  # + the seed event
    assert full["channels"]["webapp"] == 2

    # The active category (event_type) narrows ONLY the CHANNEL buckets — the
    # source rail partitions the feed — never the TYPE buckets (each badge
    # counts its own type regardless of the selected category).
    typed = client.get("/events/counts", params={"q": "cnt-", "event_type": "network_connection"}).json()
    assert typed["total"] == 5  # types.all is category-independent
    assert typed["types"]["network_connection"] == 1
    assert typed["types"]["process_create"] == 2
    assert typed["channels"]["total"] == 1  # the rail narrows to the feed
    assert typed["channels"]["live"] == 1
    assert typed["channels"]["auditd"] == 0  # cnt-aud.exe is process_create

    # Shared validation: unknown event_type → 422, valid sources/platforms → 200
    assert client.get("/events/counts", params={"event_type": "bogus"}).status_code == 422
    assert client.get("/events/counts", params={"source": "bogus"}).status_code == 422
    assert client.get("/events/counts", params={"source": "endpointsecurity"}).status_code == 200
    assert client.get("/events/counts", params={"source": "ebpf"}).status_code == 200
    assert client.get("/events/counts", params={"platform": "macos"}).status_code == 200

    # Close the live run so /runs/active-live's 404 contract holds.
    client.post(f"/runs/{live}/complete")


def test_events_backfill_infers_channel_for_legacy_collector_events(client):
    """Events shipped before collectors stamped `log_source` read NULL, so
    the Auditd/Sysmon channels stayed empty despite the telemetry. The
    backfill infers the channel from the platform for legacy live-run events
    carrying a real host: linux → auditd, windows → sysmon, while webapp-
    'local' events (synthetic live sessions) are never touched."""
    from ..core.db import _backfill_events_log_source, db_session

    lin = make_run(client, sample_name="bf-lin.bin", platform="linux", session_type="live")
    win = make_run(client, sample_name="bf-win.bin", platform="windows", session_type="live")
    loc = make_run(client, sample_name="bf-loc.bin", platform="linux", session_type="live")

    def _ev(run_id: str, name: str, platform: str, host: str | None) -> dict:
        ev = _event(run_id, "process_create", platform, process_name=name, timestamp=_ts(1))
        if host is not None:
            ev["host_id"] = host
        return ev

    _ingest(client, lin, [_ev(lin, "bf-lin.exe", "linux", "legacy-host")])
    _ingest(client, win, [_ev(win, "bf-win.exe", "windows", "legacy-win")])
    _ingest(client, loc, [_ev(loc, "bf-loc.exe", "linux", None)])  # → 'local'

    # Pre-backfill: nothing carries a channel yet.
    assert client.get("/events", params={"source": "auditd", "q": "bf-lin.exe"}).json()["total"] == 0
    assert client.get("/events", params={"source": "sysmon", "q": "bf-win.exe"}).json()["total"] == 0

    with db_session() as conn:
        _backfill_events_log_source(conn)

    # Linux collector event → auditd; Windows → sysmon.
    aud = client.get("/events", params={"source": "auditd", "q": "bf-lin.exe"}).json()
    assert aud["total"] == 1 and aud["events"][0]["log_source"] == "auditd"
    sys = client.get("/events", params={"source": "sysmon", "q": "bf-win.exe"}).json()
    assert sys["total"] == 1 and sys["events"][0]["log_source"] == "sysmon"

    # The webapp-'local' event is NOT collector telemetry — stays unstamped.
    loc_hit = client.get("/events", params={"source": "live", "q": "bf-loc.exe"}).json()
    assert loc_hit["total"] == 1 and loc_hit["events"][0]["log_source"] is None

    # Idempotent: a second pass changes nothing.
    with db_session() as conn:
        _backfill_events_log_source(conn)
    assert client.get("/events", params={"source": "auditd", "q": "bf-lin.exe"}).json()["total"] == 1

    # Close the live runs so /runs/active-live's 404 contract holds.
    client.post(f"/runs/{lin}/complete")
    client.post(f"/runs/{win}/complete")
    client.post(f"/runs/{loc}/complete")


def test_events_feed_shape_and_pagination(client):
    marker = "feedshape-"
    a = make_run(client, sample_name="feed-a.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", process_name=f"{marker}one.exe", timestamp=_ts(1)),
        _event(a, "network_connection", "linux", dest_ip="198.51.100.4", command_line=marker, timestamp=_ts(2)),
    ])

    data = client.get("/events", params={"q": marker}).json()
    assert data["total"] == 2 and data["returned"] == 2
    assert all("sample_name" in e and "run_severity" in e for e in data["events"])
    types = {e["event_type"] for e in data["events"]}
    assert types == {"process_create", "network_connection"}

    # Pagination within the scoped set.
    page1 = client.get("/events", params={"q": marker, "limit": 1, "offset": 0}).json()
    page2 = client.get("/events", params={"q": marker, "limit": 1, "offset": 1}).json()
    assert page1["returned"] == 1 and page2["returned"] == 1
    assert page1["events"][0]["id"] != page2["events"][0]["id"]
    assert client.get("/events", params={"q": marker, "offset": 5}).json()["returned"] == 0


def test_events_filter_by_type_and_platform(client):
    marker = "feedfilter-"
    a = make_run(client, sample_name="feed-c.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", process_name=f"{marker}x.exe", timestamp=_ts(1)),
        _event(a, "network_connection", "windows", dest_ip="198.51.100.5", command_line=marker, timestamp=_ts(2)),
    ])

    only_net = client.get("/events", params={"q": marker, "event_type": "network_connection"}).json()
    assert only_net["total"] == 1
    assert {e["event_type"] for e in only_net["events"]} == {"network_connection"}

    only_lnx = client.get("/events", params={"q": marker, "platform": "linux"}).json()
    assert only_lnx["total"] == 0  # both events are windows — scoped marker is safe


def test_events_severity_filter_limits_to_findings_runs(client):
    marker = "feedsev-"
    clean = make_run(client, sample_name="feed-clean.bin")
    dirty = make_run(client, sample_name="feed-dirty.bin")
    _ingest(client, clean, [
        _event(clean, "file_write", "windows", file_path=f"C:\\tmp\\{marker}a.txt", timestamp=_ts(1)),
    ])
    # A malicious LOLBin write makes the whole run "malicious-severity".
    _ingest(client, dirty, [
        {
            "run_id": dirty, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(2), "pid": 1, "ppid": 0, "process_name": "powershell.exe",
            "command_line": f"powershell.exe -enc {marker}",  # marker so BOTH dirty events match q
        },
        _event(dirty, "file_write", "windows", file_path=f"C:\\tmp\\{marker}b.txt", timestamp=_ts(3)),
    ])

    resp = client.get("/events", params={"q": marker, "severity": "malicious"})
    data = resp.json()
    assert data["total"] == 2  # only the dirty run's two events
    assert {e["run_id"] for e in data["events"]} == {dirty}
    assert all(e["run_severity"] == "malicious" for e in data["events"])


def test_events_free_text_search(client):
    a = make_run(client, sample_name="feed-d.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", process_name="totally-unique-proc.exe", timestamp=_ts(1)),
        _event(a, "file_write", "windows", file_path=r"C:\Users\victim\Documents\report.docx", timestamp=_ts(2)),
        _event(a, "network_connection", "windows", dest_ip="198.51.100.77", timestamp=_ts(3)),
    ])

    assert client.get("/events", params={"q": "totally-unique-proc.exe"}).json()["total"] == 1
    assert client.get("/events", params={"q": "report.docx"}).json()["total"] == 1
    assert client.get("/events", params={"q": "198.51.100.77"}).json()["total"] == 1
    # Partial-IP substring must stay unique to THIS test: /events is a global
    # feed and the session DB is shared, so other tests' IPs (.4/.5/.201) would
    # legitimately match a broader "198.51.100" search.
    assert client.get("/events", params={"q": "51.100.77"}).json()["total"] == 1  # partial IP
    assert client.get("/events", params={"q": "no-such-thing"}).json()["total"] == 0


def test_events_hides_synthetic_by_default(client):
    """The Event Log reads real-first like the History archive: events from
    seed / webapp-demo / legacy monitor / sandbox:demo runs are hidden from
    the bare feed, while live-host and CLI runs always show.
    include_synthetic=true reveals everything, and the CSV export honors the
    same contract. Explicit provenance facets (the source tabs) show their
    full content — choosing a tab is a deliberate look at that provenance."""
    runs = {}
    for src, name in (
        ("live", "evh-live"), ("cli", "evh-cli"), ("seed", "evh-seed"),
        ("webapp-demo", "evh-web"), ("monitor", "evh-mon"), ("sandbox:demo", "evh-sand"),
    ):
        runs[name] = make_run(client, sample_name=f"{name}.bin", source=src)
    for name, rid in runs.items():
        _ingest(client, rid, [_event(rid, "process_create", "windows", process_name=f"{name}.exe", timestamp=_ts(1))])

    # Bare feed (the page's default): real telemetry visible, synthetic hidden.
    visible = {e["process_name"] for e in client.get("/events", params={"q": "evh-"}).json()["events"]}
    assert {"evh-live.exe", "evh-cli.exe"} <= visible
    assert not visible.intersection({"evh-seed.exe", "evh-web.exe", "evh-mon.exe", "evh-sand.exe"})

    # Opt-in reveals everything.
    shown = {e["process_name"] for e in client.get("/events", params={"q": "evh-", "include_synthetic": "true"}).json()["events"]}
    assert {"evh-live.exe", "evh-cli.exe", "evh-seed.exe", "evh-web.exe", "evh-mon.exe", "evh-sand.exe"} <= shown

    # An explicit webapp facet is a deliberate ask — it includes synthetic
    # provenance (the tab tooltip says so: synthetic detonations, CLI, seeds).
    web = {e["process_name"] for e in client.get("/events", params={"q": "evh-", "source": "webapp", "include_synthetic": "true"}).json()["events"]}
    assert "evh-web.exe" in web and "evh-seed.exe" in web

    # CSV export mirrors the feed's default hiding.
    csv = client.get("/events/export", params={"q": "evh-"}).text
    assert "evh-live.exe" in csv and "evh-seed.exe" not in csv
    csv_full = client.get("/events/export", params={"q": "evh-", "include_synthetic": "true"}).text
    assert "evh-seed.exe" in csv_full

    # Close the live run so /runs/active-live's 404 contract holds.
    client.post(f"/runs/{runs['evh-live']}/complete")


def test_events_invalid_filters_422(client):
    assert client.get("/events", params={"event_type": "bogus"}).status_code == 422
    assert client.get("/events", params={"platform": "plan9"}).status_code == 422
    assert client.get("/events", params={"severity": "fatal"}).status_code == 422
    assert client.get("/events", params={"limit": 0}).status_code == 422
    assert client.get("/events", params={"pid": 0}).status_code == 422
    assert client.get("/events", params={"pid": "1,2,three"}).status_code == 422


def test_events_pid_filter_scopes_to_one_process(client):
    """Process-centric drill-down: ?pid=N returns everything that PID did
    (children, files, network, registry) — the Event-Manager parity pivot."""
    marker = "feedpid-"
    a = make_run(client, sample_name="feed-pid.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", pid=9001, ppid=4, process_name=f"{marker}a.exe", command_line=marker, timestamp=_ts(1)),
        _event(a, "network_connection", "windows", pid=9001, dest_ip="198.51.100.201", command_line=marker, timestamp=_ts(2)),
        _event(a, "file_write", "windows", pid=9002, file_path=f"C:\\tmp\\{marker}b.txt", command_line=marker, timestamp=_ts(3)),
    ])

    only_9001 = client.get("/events", params={"q": marker, "pid": 9001}).json()
    assert only_9001["total"] == 2
    assert {e["pid"] for e in only_9001["events"]} == {9001}
    assert {e["event_type"] for e in only_9001["events"]} == {"process_create", "network_connection"}

    only_9002 = client.get("/events", params={"q": marker, "pid": 9002}).json()
    assert only_9002["total"] == 1
    assert only_9002["events"][0]["event_type"] == "file_write"

    # Comma-separated list — the recon-sweep jump (every enumerating PID).
    multi = client.get("/events", params={"q": marker, "pid": "9001,9002"}).json()
    assert multi["total"] == 3
    assert {e["pid"] for e in multi["events"]} == {9001, 9002}
    assert client.get("/events", params={"q": marker, "pid": "9002,9003"}).json()["total"] == 1
    # Invalid tokens are rejected, not silently ignored.
    assert client.get("/events", params={"q": marker, "pid": "abc"}).status_code == 422
    assert client.get("/events", params={"q": marker, "pid": "9001,-2"}).status_code == 422


def test_events_process_summary(client):
    """The hover-preview endpoint: process identity + run + impact counts."""
    marker = "procsum-"
    a = make_run(client, sample_name="feed-procsum.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", pid=9201, ppid=4, process_name=f"{marker}one.exe",
               command_line=f"{marker}one.exe --payload x", timestamp=_ts(1)),
        _event(a, "network_connection", "windows", pid=9201, dest_ip="198.51.100.231",
               command_line=marker, timestamp=_ts(2)),
    ])

    s = client.get("/events/process-summary", params={"pid": 9201}).json()
    assert s["process_name"] == f"{marker}one.exe"
    assert s["command_line"] == f"{marker}one.exe --payload x"
    assert s["event_count"] == 2
    assert s["run_id"] == a and s["sample_name"] == "feed-procsum.bin"
    assert s["alert_count"] == 0  # unique marker name → no detection fired

    # An alert naming the same PID in another run counts too.
    b = make_run(client, sample_name="feed-procsum2.bin")
    _ingest(client, b, [
        {"run_id": b, "platform": "windows", "event_type": "process_create",
         "timestamp": _ts(5), "pid": 9201, "ppid": 4, "process_name": "powershell.exe",
         "command_line": "powershell.exe -enc SQBFAFgAAGgBdAA="},
    ])
    s2 = client.get("/events/process-summary", params={"pid": 9201}).json()
    assert s2["alert_count"] == 1
    assert s2["run_id"] == b  # newest process-create row wins
    assert s2["event_count"] == 3

    assert client.get("/events/process-summary", params={"pid": 999999}).status_code == 404
    assert client.get("/events/process-summary", params={"pid": 0}).status_code == 422


def test_events_multi_pid_csv_export(client):
    marker = "feedmulticsv-"
    a = make_run(client, sample_name="feed-multicsv.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", pid=9101, ppid=4, process_name=f"{marker}a.exe", command_line=marker, timestamp=_ts(1)),
        _event(a, "file_write", "windows", pid=9102, file_path=f"C:\\tmp\\{marker}b.txt", command_line=marker, timestamp=_ts(2)),
        _event(a, "file_write", "windows", pid=9103, file_path=f"C:\\tmp\\{marker}c.txt", command_line=marker, timestamp=_ts(3)),
    ])
    csv = client.get("/events/export", params={"q": marker, "pid": "9101,9102"}).text
    assert "9101" in csv and "9102" in csv and "9103" not in csv


def test_events_carry_raw_record_from_collector_payload(client):
    """Ingest stores the collector's original payload as the event's raw
    record — the Event Viewer's side-by-side raw line."""
    import json as _json

    marker = "feedraw-"
    a = make_run(client, sample_name="feed-raw.bin")
    _ingest(client, a, [
        _event(a, "registry_write", "windows", pid=9003, command_line=marker, timestamp=_ts(1),
               registry_key=r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Bad"),
    ])

    ev = client.get("/events", params={"q": marker}).json()["events"][0]
    raw = _json.loads(ev["raw_record"])
    assert raw["event_type"] == "registry_write"
    assert raw["pid"] == 9003
    assert raw["registry_key"].endswith(r"Run\Bad")
    # The raw record and the normalized row agree on the event identity.
    assert raw["timestamp"] == ev["timestamp"]

    # CSV export honors the pid filter too.
    csv = client.get("/events/export", params={"q": marker, "pid": 9003}).text
    assert "registry_write" in csv and "Run\\Bad" in csv
