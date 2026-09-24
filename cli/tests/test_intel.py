"""Regression tests for `outpost intel import` rendering (mocked API).

The command is the terminal mirror of the webapp's threat-intel feed import;
these tests lock its output: the imported count + source label, kind
breakdown, and the matching-runs table when a value already appears in the
store.

Run from cli/:  ../.venv/bin/pytest
"""

import typer

from outpost.commands.intel import import_feed
from outpost.lib import api_client
from outpost.rendering.terminal_views import console


def _fixture() -> dict:
    return {
        "imported": 4,
        "source": "intel:stix",
        "kinds": {"ip": 1, "domain": 2, "hash": 1},
        "matched_values": 1,
        "matched_runs": {"203.0.113.88": ["c09f56bddca4", "0302aa600d1d"]},
    }


def test_intel_import_renders_counts_source_and_matching_runs(monkeypatch, capsys):
    monkeypatch.setattr(api_client, "intel_import", lambda source, content="", url="": _fixture())

    with console.capture() as capture:
        import_feed(source="stix", file=None, content='{"type": "bundle"}', url="")
    out = capture.get()

    assert "4 indicator(s) imported" in out
    assert "intel:stix" in out
    assert "ip=1" in out and "domain=2" in out and "hash=1" in out
    assert "1 value(s) already touch existing runs" in out
    assert "203.0.113.88" in out
    assert "c09f56bddca4" in out and "0302aa600d1d" in out


def test_intel_import_no_match_line(monkeypatch):
    fixture = _fixture()
    fixture["matched_values"] = 0
    fixture["matched_runs"] = {}
    monkeypatch.setattr(api_client, "intel_import", lambda source, content="", url="": fixture)

    with console.capture() as capture:
        import_feed(source="text", file=None, content="203.0.113.88\n", url="")
    out = capture.get()

    assert "4 indicator(s) imported" in out
    assert "No existing run touches any imported value." in out


def test_intel_import_requires_input(monkeypatch):
    monkeypatch.setattr(api_client, "intel_import", lambda source, content="", url="": _fixture())
    with console.capture() as capture:
        try:
            import_feed(source="auto", file=None, content="", url="")
        except typer.Exit:
            pass
    out = capture.get()
    assert "Provide --file/--content or --url" in out


def test_intel_hunt_renders_compromise_assessment(monkeypatch):
    hunt_fixture = {
        "ioc": {"value": "203.0.113.88", "type": "ip"},
        "total_events_matched": 12,
        "affected_runs_count": 2,
        "affected_hosts_count": 1,
        "first_seen": "2026-08-01T12:00:00Z",
        "last_seen": "2026-08-01T12:05:00Z",
        "affected_hosts": [
            {"host_id": "sensor-alpha", "event_count": 12, "first_seen": "2026-08-01T12:00:00Z", "last_seen": "2026-08-01T12:05:00Z"}
        ],
        "matching_events": [
            {
                "timestamp": "2026-08-01T12:00:00Z",
                "host_id": "sensor-alpha",
                "event_type": "network_connection",
                "process_name": "curl",
                "dest_ip": "203.0.113.88",
            }
        ],
    }

    monkeypatch.setattr(api_client, "ioc_fleet_hunt", lambda ioc: hunt_fixture)

    from outpost.commands.intel import hunt_ioc
    with console.capture() as capture:
        hunt_ioc("203.0.113.88")
    out = capture.get()

    assert "Fleet-Wide Compromise Assessment" in out
    assert "203.0.113.88" in out
    assert "COMPROMISE DETECTED" in out
    assert "sensor-alpha" in out
    assert "curl" in out


def test_intel_extract_from_text():
    from outpost.commands.intel import extract_ioc

    sample_text = """
    Incident Advisory:
    Beacon observed at hxxps[://]beacon-c2[.]com/payload[.]exe
    External IP: 198[.]51[.]100[.]44
    Internal lateral: 10.0.0.15
    Mail: attacker[@]evil-portal[.]xyz
    Hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    """

    with console.capture() as capture:
        extract_ioc(text=sample_text)
    out = capture.get()

    assert "Extracted Indicators" in out
    assert "198.51.100.44" in out
    assert "RFC1918 Private" in out
    assert "Public Routable" in out
    assert "https://beacon-c2.com/payload.exe" in out
    assert "attacker@evil-portal.xyz" in out
    assert "SHA256" in out


def test_intel_extract_defanged_flag():
    from outpost.commands.intel import extract_ioc

    sample_text = "C2 at https://malware-drop.com/payload.sh with IP 192.168.1.50"
    with console.capture() as capture:
        extract_ioc(text=sample_text, defang=True)
    out = capture.get()

    assert "hxxps://malware-drop[.]com" in out
    assert "192[.]168[.]1[.]50" in out


def test_intel_extract_json_output():
    import json
    from outpost.commands.intel import extract_ioc

    sample_text = "Contact bad@phish.org or 203.0.113.10"
    with console.capture() as capture:
        extract_ioc(text=sample_text, json_output=True)
    out = capture.get().strip()

    data = json.loads(out)
    assert isinstance(data, list)
    assert len(data) >= 2
    types = [d["type"] for d in data]
    assert "email" in types
    assert "ip" in types


def test_intel_extract_add_to_watchlist(monkeypatch):
    imported_records = []

    def mock_import(entries):
        imported_records.extend(entries)
        return {"imported": len(entries)}

    monkeypatch.setattr(api_client, "watchlist_import", mock_import)

    from outpost.commands.intel import extract_ioc

    sample_text = "Found 198.51.100.22 and https://evil-c2.net"
    with console.capture() as capture:
        extract_ioc(text=sample_text, add_to_watchlist=True)
    out = capture.get()

    assert "Successfully imported" in out
    assert len(imported_records) >= 2


def test_intel_extract_from_file(tmp_path):
    from outpost.commands.intel import extract_ioc

    report_file = tmp_path / "sample_report.txt"
    report_file.write_text("Report host 10.0.10.5 contacting evil-c2.com", encoding="utf-8")

    with console.capture() as capture:
        extract_ioc(file=report_file)
    out = capture.get()

    assert "Extracted Indicators" in out
    assert "10.0.10.5" in out
    assert "evil-c2.com" in out


def test_intel_extract_requires_input():
    from outpost.commands.intel import extract_ioc

    with console.capture() as capture:
        try:
            extract_ioc(text="")
        except typer.Exit:
            pass
    out = capture.get()
    assert "Provide text, --file, or piped input via stdin" in out


