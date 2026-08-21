"""Regression tests for `outpost yara` and `outpost footprint` — the terminal
mirrors of the webapp's signature lab and Footprint page.

Mock api_client and assert the rendered Rich output carries the payload's
signal (rule names / matched samples / seed IPs / cert CNs / ASN orgs), with
the honest empty and failure states.
"""

from unittest.mock import patch

from outpost.commands import footprint as footprint_cmd
from outpost.commands import yara as yara_cmd
from outpost.lib import api_client
from outpost.rendering.terminal_views import console


def _capture(fn) -> str:
    with console.capture() as capture:
        fn()
    return capture.get()


def test_yara_list_renders_rules_and_strings():
    payload = {
        "count": 1,
        "rules": [
            {
                "name": "shelf_lure_docm",
                "family": "custom",
                "description": "ACME invoice lure",
                "strings": ["$a = \"invoice\"", "$b = \"macro\""],
                "source": "rule shelf_lure_docm {}",
            }
        ],
    }
    with patch("outpost.commands.yara.api_client.yara_list", return_value=payload):
        out = _capture(yara_cmd.list_rules)
    assert "shelf_lure_docm" in out
    assert "custom" in out
    assert "$a = \"invoice\"" in out
    assert "ACME invoice lure" in out


def test_yara_list_empty_state():
    with patch("outpost.commands.yara.api_client.yara_list", return_value={"count": 0, "rules": []}):
        out = _capture(yara_cmd.list_rules)
    assert "No custom YARA rules yet" in out


def test_yara_test_matches_and_hits():
    payload = {
        "compiled": True,
        "rule_name": "detect_c2",
        "total": 3,
        "matched": 1,
        "samples": [
            {"sample_id": "s1", "original_name": "acme_invoice.docm", "platform": "windows", "matched": True, "hits": ["$a"]},
            {"sample_id": "s2", "original_name": "clean.exe", "platform": "windows", "matched": False, "hits": []},
        ],
    }
    with patch("outpost.commands.yara.api_client.yara_test", return_value=payload):
        out = _capture(lambda: yara_cmd.test_rule(rule="rule detect_c2 {}", file="", sample_ids=None))
    assert "compiled" in out
    assert "detect_c2" in out
    assert "acme_invoice.docm" in out
    assert "$a" in out


def test_yara_test_compile_error_exits():
    import typer

    payload = {"compiled": False, "error": "line 1: unknown token `@`"}
    with patch("outpost.commands.yara.api_client.yara_test", return_value=payload):
        with console.capture() as capture:
            try:
                yara_cmd.test_rule(rule="rule bad {}", file="", sample_ids=None)
            except typer.Exit as exc:
                assert exc.exit_code == 1
        out = capture.get()
    assert "failed to compile" in out
    assert "unknown token" in out


def test_footprint_renders_seed_ips_certs_and_asn():
    payload = {
        "sample": {"sample_id": "s1", "name": "detonate-demo.exe", "sha256": "ab" * 32, "platform": "windows"},
        "seed_ips": [{"ip": "203.0.113.88", "hits": 5, "first_seen": "2026-08-01T10:00:01Z", "last_seen": "2026-08-01T10:00:30Z"}],
        "passive": {
            "source": "live",
            "resolutions": [{"domain": "c2.shelf.example", "ip": "203.0.113.88", "first_seen": "2026-08-01", "last_seen": "2026-08-02"}],
            "certificates": [{"cn": "*.shelf.example", "issuer": "Let's Encrypt", "not_before": "2026-07-01", "not_after": "2026-09-30"}],
            "asn": [{"asn": 64512, "org": "Shelf-Stack Ops", "country": "US"}],
        },
        "runs": [{"run_id": "r1", "started_at": "2026-08-01T10:00:01Z", "completed_at": "2026-08-01T10:00:45Z"}],
    }
    with patch("outpost.commands.footprint.api_client.footprint", return_value=payload):
        out = _capture(lambda: footprint_cmd.show("s1"))
    assert "203.0.113.88" in out
    assert "c2.shelf.example" in out
    assert "*.shelf.example" in out
    assert "Shelf-Stack Ops" in out
    assert "live passive intel" in out
    assert "r1" in out
    assert "detonate-demo.exe" in out


def test_footprint_synthetic_flag_rendered():
    payload = {
        "sample": {"sample_id": "s1", "name": "demo.bin", "sha256": "cd" * 32, "platform": "linux"},
        "seed_ips": [],
        "passive": {"source": "synthetic_demo", "resolutions": [], "certificates": [], "asn": []},
        "runs": [],
    }
    with patch("outpost.commands.footprint.api_client.footprint", return_value=payload):
        out = _capture(lambda: footprint_cmd.show("s1"))
    assert "synthetic demo" in out


# -- `outpost footprint export` — the webapp Export buttons' terminal mirror --


def test_footprint_export_writes_json(monkeypatch, tmp_path):
    payload = {
        "exported_at": "2026-08-10T00:00:00+00:00",
        "sample": {"sample_id": "s1", "name": "detonate-demo.exe", "sha256": "ab" * 32, "platform": "windows"},
        "status": {"roadmap": True, "generated": None},
        "seed_ips": [{"ip": "203.0.113.88", "hits": 5, "run_count": 2, "first_seen": "2026-08-01T10:00:01Z", "last_seen": "2026-08-01T10:00:30Z"}],
        "passive": {
            "source": "live",
            "resolutions": [],
            "passive_dns": [{"domain": "panel.shelf.example", "first_seen": "2026-01-01", "last_seen": "2026-08-01", "source_ip": "203.0.113.88", "synthetic": False}],
            "certificates": [],
            "sibling_ips": [],
            "networks": [],
            "asn": [],
        },
    }
    import json

    monkeypatch.setattr(
        "outpost.commands.footprint.api_client.export_footprint",
        lambda *a, **k: json.dumps(payload, indent=2).encode(),
    )
    dest = tmp_path / "footprint.json"
    with console.capture() as capture:
        footprint_cmd.export("s1", format="json", output=dest)

    written = json.loads(dest.read_text())
    assert written["sample"]["name"] == "detonate-demo.exe"
    assert written["passive"]["passive_dns"][0]["source_ip"] == "203.0.113.88"
    assert "Exported footprint (json)" in capture.get()


def test_footprint_export_writes_csv_and_passes_mock(monkeypatch, tmp_path):
    csv_body = (
        "collection,indicator,source_ip,detail,first_seen,last_seen,synthetic\r\n"
        "seed,203.0.113.88,,malicious · 5 hit(s) · 2 run(s),2026-08-01,2026-08-01,false\r\n"
        "passive_dns,panel.shelf.example,203.0.113.88,,2026-01-01,2026-08-01,true\r\n"
    ).encode()
    calls = {}

    def fake(sample_id, format="json", mock=False):
        calls.update(sample_id=sample_id, format=format, mock=mock)
        return csv_body

    monkeypatch.setattr("outpost.commands.footprint.api_client.export_footprint", fake)
    dest = tmp_path / "footprint.csv"
    with console.capture() as capture:
        footprint_cmd.export("s1", format="csv", mock=True, output=dest)

    text = dest.read_text()
    assert "collection,indicator,source_ip" in text
    assert "panel.shelf.example" in text
    assert calls == {"sample_id": "s1", "format": "csv", "mock": True}
    assert "Exported footprint (csv)" in capture.get()


def test_footprint_export_bad_format_exits(tmp_path):
    import typer

    with console.capture() as capture:
        try:
            footprint_cmd.export("s1", format="xml", output=tmp_path / "x.xml")
        except typer.Exit as exc:
            assert exc.exit_code == 2
    assert "Unknown format: xml" in capture.get()


def test_footprint_export_api_error_exits(monkeypatch, tmp_path):
    import typer

    def boom(*a, **k):
        raise api_client.APIError("GET /footprint/s1/export → 404")

    monkeypatch.setattr("outpost.commands.footprint.api_client.export_footprint", boom)
    with console.capture() as capture:
        try:
            footprint_cmd.export("s1", format="json", output=tmp_path / "x.json")
        except typer.Exit as exc:
            assert exc.exit_code == 1
    assert "footprint export failed" in capture.get()
