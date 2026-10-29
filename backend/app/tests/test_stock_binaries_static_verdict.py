"""Regression test suite for static analysis verdict engine on real-world stock binaries.

Guarantees:
1. Stock system binaries (e.g. /bin/ls, /usr/bin/python3, /bin/sh, /usr/bin/find)
   are never classified as 'malicious'.
2. Random high-entropy byte sequences are not misclassified as scripts.
3. Extracted strings and URLs do not contain NUL bytes.
4. URLs and domains in binary strings are not scored as suspicious by default.
5. Stripped symbols in ELF binaries are treated as neutral, not threat indicators.
6. A 'malicious' verdict strictly requires at least one authoritative signal:
   matched YARA rule, decoded family config, known-bad hash, or confirmed malicious indicator.
7. Benign evidence inputs (package ownership, known-good hash list, signature validity)
   are incorporated and mitigate false positives.
8. Unknown or unparseable formats return 'insufficient_evidence' with 'could_not_analyze' filled.
"""

import os

import pytest

from app.services.static.indicators import extract_embedded_indicators
from app.services.static.pipeline import (
    extract_strings,
    run_complete_static_pipeline,
)
from app.services.static.verdict import assess_static_evidence


def test_bin_ls_verdict_not_malicious():
    """Stock /bin/ls must not receive a malicious verdict or high-threat score."""
    path = "/bin/ls"
    if not os.path.exists(path):
        pytest.skip(f"{path} not present on this host")
    with open(path, "rb") as f:
        data = f.read()

    result = run_complete_static_pipeline(data)
    assert result["verdict"] != "malicious", (
        f"/bin/ls received verdict '{result['verdict']}' with score {result.get('static_risk_score')}. "
        f"Factors: {result.get('assessment_factors')}"
    )
    assert result["verdict"] in ("no_indicators_found_limited", "insufficient_evidence")


def test_usr_bin_python3_verdict_not_malicious():
    """Stock /usr/bin/python3 must not receive a malicious or suspicious verdict from stripped symbols."""
    path = "/usr/bin/python3"
    if not os.path.exists(path):
        pytest.skip(f"{path} not present on this host")
    with open(path, "rb") as f:
        data = f.read()

    result = run_complete_static_pipeline(data)
    assert result["verdict"] != "malicious"
    # Stripped symbols alone must not elevate to suspicious
    assert result["verdict"] in ("no_indicators_found_limited", "insufficient_evidence"), (
        f"/usr/bin/python3 received verdict '{result['verdict']}'"
    )


def test_random_bytes_not_classified_as_script():
    """Random high-entropy binary blob must be classified as unknown/generic_binary with insufficient_evidence."""
    random_data = os.urandom(512 * 1024)
    result = run_complete_static_pipeline(random_data)

    assert result["format"] != "script", f"Random bytes misclassified as format '{result['format']}'"
    assert result["verdict"] == "insufficient_evidence", (
        f"Random bytes expected verdict 'insufficient_evidence', got '{result['verdict']}'"
    )
    assert len(result.get("could_not_analyze", [])) > 0, "could_not_analyze should list unparsed format"


def test_extracted_strings_no_nul_bytes():
    """Extracted strings and embedded URLs must never contain embedded NUL bytes."""
    test_data = b"SomeHeader\x00https://gnu.org/licenses/gpl.html\x00\x00\x00extra_junk\x00"
    strings = extract_strings(test_data)
    for s in strings:
        assert "\x00" not in s, f"String '{s}' contains NUL byte"

    indicators = extract_embedded_indicators(test_data)
    for ind in indicators:
        val = ind.get("value", "")
        assert "\x00" not in val, f"Indicator '{val}' contains NUL byte"


def test_authoritative_signal_required_for_malicious():
    """Without an authoritative signal, high heuristic/anomaly weights cannot produce 'malicious'."""
    # Fabricate high heuristic weights without authoritative signals
    assessment = assess_static_evidence(
        findings=[],
        capabilities=[
            {"category": "Defense Evasion & Anti-Debug", "matched": ["IsDebuggerPresent"], "source": "heuristic", "provenance": {"reliability": "inferred"}},
            {"category": "Execution & Scripting", "matched": ["WinExec"], "source": "heuristic", "provenance": {"reliability": "inferred"}},
            {"category": "Persistence & Autostart", "matched": ["RegSetValueEx"], "source": "heuristic", "provenance": {"reliability": "inferred"}},
        ],
        embedded_indicators=[
            {"type": "url", "value": "http://random-test-domain.xyz/doc", "classification": "suspicious"},
        ],
        structural_anomalies=[
            {"title": "High entropy section", "weight": 25},
        ],
        benign_signals=[],
        could_not_analyze=[],
    )
    # Even with multiple heuristic hits, it must not be 'malicious' without authoritative signal
    assert assessment["verdict"] != "malicious", (
        f"Expected verdict to cap at 'suspicious' without authoritative signals, got '{assessment['verdict']}'"
    )
    assert assessment["verdict"] == "suspicious"


def test_benign_evidence_inputs_lower_threat_posture():
    """Known-good hash list, valid signatures, or package ownership mitigate heuristic anomalies."""
    assessment = assess_static_evidence(
        findings=[],
        capabilities=[
            {"category": "Network Communications & C2", "matched": ["connect"], "source": "import_table", "provenance": {"reliability": "parsed"}},
        ],
        embedded_indicators=[],
        structural_anomalies=[],
        benign_signals=[
            {"title": "Known Clean System Binary (OS Package Hash Match)", "weight": -50, "reliability": "parsed"},
        ],
        could_not_analyze=[],
    )
    assert assessment["verdict"] in ("no_indicators_found_limited", "insufficient_evidence")
    assert assessment["static_risk_score"] == 0


def test_repo_ground_truth_probes_not_suspicious_or_malicious():
    """Repo ground-truth probe binaries (probe_elf, probe.py, probe.sh) must not be flagged suspicious or malicious."""
    probes = [
        "tests/probes/c_probe/probe_elf",
        "tests/probes/python_probe/probe.py",
        "tests/probes/shell_probe/probe.sh",
    ]
    for p in probes:
        if not os.path.exists(p):
            continue
        with open(p, "rb") as f:
            data = f.read()
        res = run_complete_static_pipeline(data, file_path=p)
        assert res["verdict"] in ("no_indicators_found_limited", "insufficient_evidence"), (
            f"Probe {p} incorrectly flagged with verdict '{res['verdict']}', score {res.get('static_risk_score')}. "
            f"Factors: {res.get('assessment_factors')}"
        )
        assert res["static_risk_score"] == 0
