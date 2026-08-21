"""CLI regression tests for the intelligence exports (mocked API): the
`outpost coverage` matrix + `--export-navigator` layer, and
`outpost campaigns --export-stix` bundle — the terminal mirrors of the
webapp's Coverage and Campaigns export buttons.

Run from cli/:  ../.venv/bin/pytest
"""

import json

import pytest
import typer
from rich.console import Console

import outpost.commands.campaigns as campaigns_mod
import outpost.commands.coverage as coverage_mod
from outpost.commands.campaigns import campaigns
from outpost.commands.coverage import coverage
from outpost.lib import api_client
from outpost.rendering.terminal_views import console


def _rule(rule_id: str, technique: str, tactic: str, weight: int, severity: str) -> dict:
    return {
        "rule_id": rule_id, "rule_name": f"{rule_id} display name", "technique": technique,
        "tactic": tactic, "weight": weight, "severity": severity,
    }


def rules_fixture() -> list[dict]:
    return [
        _rule("lolbin-abuse", "T1059", "Execution", 14, "malicious"),
        _rule("beaconing", "T1071.001", "Command and Control", 15, "suspicious"),
        _rule("enumeration-burst", "T1082", "Discovery", 14, "suspicious"),
    ]


def test_coverage_renders_tactic_matrix(monkeypatch):
    monkeypatch.setattr(api_client, "get_rules_meta", rules_fixture)

    wide = Console(width=140)
    monkeypatch.setattr(coverage_mod, "console", wide)
    with wide.capture() as capture:
        coverage()
    out = capture.get()

    # Tactic-grouped rows with technique, weight, severity.
    assert "Execution" in out
    assert "T1059" in out and "lolbin-abuse display name" in out and "+14" in out
    assert "● malicious" in out
    assert "Command and Control" in out and "T1071.001" in out
    assert "3 rules across 3 tactics" in out
    assert "--export-navigator" in out


def test_coverage_export_navigator_writes_layer(monkeypatch, tmp_path):
    layer = {
        "version": "4.3",
        "name": "OutPost detection coverage",
        "domain": "enterprise-attack",
        "techniques": [
            {"techniqueID": "T1059", "tactic": "execution", "score": 14,
             "color": "#c4453b", "comment": "lolbin-abuse (LOLBin)"},
        ],
    }
    monkeypatch.setattr(api_client, "get_navigator_layer", lambda: layer)

    dest = tmp_path / "layer.json"
    with console.capture() as capture:
        coverage(export_navigator=True, output=dest)
    out = capture.get()

    assert dest.exists()
    body = json.loads(dest.read_text())
    assert body["version"] == "4.3" and body["domain"] == "enterprise-attack"
    assert body["techniques"][0]["techniqueID"] == "T1059"
    assert "attack-navigator" in out
    assert "1 technique cell" in out


def test_campaigns_export_stix_writes_bundle(monkeypatch, tmp_path):
    def fake(key: str) -> dict:
        assert key == "203.0.113.88"
        return {
            "type": "bundle", "spec_version": "2.1",
            "id": "bundle--00000000000000000000000000000001",
            "objects": [
                {"type": "x-outpost-campaign", "id": "x-outpost-campaign--abc", "key": key, "member_count": 3},
            ],
        }

    monkeypatch.setattr(api_client, "export_campaign_stix", fake)

    dest = tmp_path / "camp.json"
    with console.capture() as capture:
        campaigns(export_stix="203.0.113.88", output=dest)
    out = capture.get()

    assert dest.exists()
    body = json.loads(dest.read_text())
    assert body["type"] == "bundle"
    assert body["objects"][0]["key"] == "203.0.113.88"
    assert "Exported STIX 2.1 bundle for campaign 203.0.113.88" in out


def test_campaigns_export_stix_api_error_exits(monkeypatch, tmp_path):
    def boom(key: str):
        raise api_client.APIError("GET /campaigns/x/export → 404")

    monkeypatch.setattr(api_client, "export_campaign_stix", boom)

    with console.capture() as capture:
        with pytest.raises(typer.Exit) as exc:
            campaigns(export_stix="x", output=tmp_path / "nope.json")

    assert exc.value.exit_code == 1
    assert "Campaign STIX export failed" in capture.get()
    assert not (tmp_path / "nope.json").exists()
