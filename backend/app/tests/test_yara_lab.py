"""Signature lab — user-authored YARA-subset rules.

Covers the parser (atoms + boolean conditions, with analyst-facing syntax
errors), the POST /yara/test vault scan (per-sample hits), persistence
(POST/GET/DELETE /yara/rules), and the live merge into upload scanning.
"""

import pytest

from ..services import yara as yara_service


def _upload(client, name: str, body: bytes):
    resp = client.post(f"/samples?name={name}", content=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x59\x41\x52\x41\x2d\x6c\x61\x62\x2d\x4d\x5a"
ELF = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x59\x41\x52\x41\x2d\x6c\x61\x62\x2d\x45\x4c\x46"
CLEAN = b"#!/bin/sh\necho yara-lab-unique-clean-sample\n"


# -- Parser ---------------------------------------------------------------------


def test_parse_ascii_and_hex_atoms_with_any_condition():
    rule = yara_service.parse_rule_text(
        """
        rule test_atoms {
            strings:
                $a = "hello"
                $b = { 4D 5A 90 }
            condition:
                any of them
        }
        """
    )
    assert rule.name == "test_atoms"
    matched, hits = rule.evaluate(MZ + b" say hello")
    assert matched is True
    assert set(hits) == {"$a", "$b"}


def test_parse_condition_and_or_not_parens():
    rule = yara_service.parse_rule_text(
        """
        rule cond {
            strings:
                $a = "alpha"
                $b = "beta"
            condition:
                ($a and not $b) or all of them
        }
        """
    )
    # Only $a present → ($a and not $b) true.
    matched, hits = rule.evaluate(b"alpha only here")
    assert matched is True and hits == ["$a"]
    # Both present → all of them true.
    matched, hits = rule.evaluate(b"alpha and beta")
    assert matched is True
    # Only $b → neither branch.
    assert rule.evaluate(b"just beta here")[0] is False


def test_parse_any_of_explicit_list():
    rule = yara_service.parse_rule_text(
        """
        rule explicit {
            strings:
                $a = "alpha"
                $b = "beta"
                $c = "gamma"
            condition:
                any of ($a, $b)
        }
        """
    )
    assert rule.evaluate(b"has gamma only")[0] is False
    assert rule.evaluate(b"has beta!")[0] is True


def test_parse_syntax_errors_are_analyst_facing():
    with pytest.raises(yara_service.RuleSyntaxError, match="rule <name>"):
        yara_service.parse_rule_text("not a rule at all")
    with pytest.raises(yara_service.RuleSyntaxError, match="both `strings:` and `condition:`"):
        yara_service.parse_rule_text("rule x { strings: $a = \"y\" }")
    with pytest.raises(yara_service.RuleSyntaxError, match="undefined string"):
        yara_service.parse_rule_text(
            "rule x { strings: $a = \"y\" condition: $zzz }"
        )
    with pytest.raises(yara_service.RuleSyntaxError, match="unparseable atom"):
        yara_service.parse_rule_text(
            "rule x { strings: garbage line condition: any of them }"
        )
    with pytest.raises(yara_service.RuleSyntaxError, match="condition: unexpected"):
        yara_service.parse_rule_text(
            "rule x { strings: $a = \"y\" condition: $a $b }"
        )


def test_parse_rejects_empty_strings_section():
    with pytest.raises(yara_service.RuleSyntaxError, match="no string atoms"):
        yara_service.parse_rule_text(
            "rule x { strings: condition: any of them }"
        )


# -- Test endpoint --------------------------------------------------------------


def test_yara_test_compiles_and_scans_vault(client):
    """Explicit sample_ids keep this deterministic even when the shared
    session DB holds hundreds of samples from other tests (the vault scan
    without ids is capped at 500)."""
    mz = _upload(client, "mz-one.exe", MZ)
    elf = _upload(client, "elf-one.bin", ELF)
    clean = _upload(client, "clean.txt", CLEAN)

    resp = client.post(
        "/yara/test",
        json={
            "rule": 'rule pe_check { strings: $mz = { 4D 5A } condition: $mz }',
            "sample_ids": [mz["sample_id"], elf["sample_id"], clean["sample_id"]],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["compiled"] is True and body["rule_name"] == "pe_check"
    by_name = {s["original_name"]: s for s in body["samples"]}
    assert by_name["mz-one.exe"]["matched"] is True
    assert by_name["mz-one.exe"]["hits"] == ["$mz"]
    assert by_name["elf-one.bin"]["matched"] is False
    assert by_name["clean.txt"]["matched"] is False
    assert body["matched"] == 1


def test_yara_test_restricted_to_sample_ids(client):
    a = _upload(client, "a.exe", MZ)
    _upload(client, "b.exe", MZ)

    body = client.post(
        "/yara/test",
        json={"rule": "rule mz { strings: $mz = { 4D 5A } condition: $mz }", "sample_ids": [a["sample_id"]]},
    ).json()
    assert body["total"] == 1
    assert body["samples"][0]["sample_id"] == a["sample_id"]


def test_yara_test_compile_error_does_not_touch_vault(client):
    resp = client.post(
        "/yara/test",
        json={"rule": "rule broken { strings: $a = \"x\" condition: $missing }"},
    )
    assert resp.status_code == 200  # compile errors are a 200 body, not an HTTP error
    body = resp.json()
    assert body["compiled"] is False
    assert "undefined string" in body["error"]


# -- Persistence + live merge ---------------------------------------------------


def test_save_validate_and_delete_roundtrip(client):
    rule_text = 'rule beacon_marker { strings: $b = "beacon here" condition: $b }'
    resp = client.post("/yara/rules", json={"rule": rule_text, "family": "c2", "description": "marker"})
    assert resp.status_code == 201
    assert resp.json()["name"] == "beacon_marker"

    got = client.get("/yara/rules").json()
    assert got["count"] == 1
    entry = got["rules"][0]
    assert entry["name"] == "beacon_marker"
    assert entry["family"] == "c2"
    assert entry["strings"] == ["$b"]
    assert entry["source"] == rule_text

    # Invalid rule → 422, nothing persisted.
    bad = client.post("/yara/rules", json={"rule": "rule z { strings: $a = \"x\" condition: $nope }"})
    assert bad.status_code == 422
    assert client.get("/yara/rules").json()["count"] == 1

    # Delete restores the empty set; deleting again 404s.
    assert client.delete("/yara/rules/beacon_marker").status_code == 204
    assert client.get("/yara/rules").json()["count"] == 0
    assert client.delete("/yara/rules/beacon_marker").status_code == 404


def test_custom_rule_merges_into_upload_scan(client):
    """A persisted custom rule fires on a fresh upload — no restart, and the
    sample's yara_rules carry the custom name."""
    client.post(
        "/yara/rules",
        json={"rule": 'rule lab_sig { strings: $s = "LAB-SIGNATURE-9" condition: $s }', "family": "custom"},
    )
    try:
        meta = _upload(client, "labeled.sh", b"#!/bin/sh\n" + b"x" * 8 + b"LAB-SIGNATURE-9" + b"\necho done\n")
        assert "lab_sig" in meta["yara_rules"]
        # Bundled rules still scan alongside.
        meta_elf = _upload(client, "elf.bin", ELF)
        assert "elf-header" in meta_elf["yara_rules"]
    finally:
        client.delete("/yara/rules/lab_sig")
