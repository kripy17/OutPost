"""Enrichment service — Task 6 acceptance: cache-first + reputation logic."""

from ..services.enrichment import _reputation_from_scores


def test_reputation_malicious_abuse():
    assert _reputation_from_scores(80, None) == "malicious"


def test_reputation_malicious_vt():
    assert _reputation_from_scores(None, 6) == "malicious"


def test_reputation_suspicious():
    assert _reputation_from_scores(30, 1) == "suspicious"
    assert _reputation_from_scores(None, 1) == "suspicious"


def test_reputation_clean():
    assert _reputation_from_scores(5, 0) == "clean"


def test_reputation_unknown():
    assert _reputation_from_scores(None, None) == "unknown"
