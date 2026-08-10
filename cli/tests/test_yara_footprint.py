"""Regression tests for `outpost yara` and `outpost footprint` — the terminal
mirrors of the webapp's signature lab and Footprint page.

Mock api_client and assert the rendered Rich output carries the payload's
signal (rule names / matched samples / seed IPs / cert CNs / ASN orgs), with
the honest empty and failure states.
"""

from unittest.mock import patch

from outpost.commands import footprint as footprint_cmd
from outpost.commands import yara as yara_cmd
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
