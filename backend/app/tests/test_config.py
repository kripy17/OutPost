"""Regression tests for config parsing — CORS_ORIGINS accepts both env forms.

The documented restart command passes the JSON-array form
(`'["http://localhost:5174"]'`); a naive comma split mangles it into one
never-matching origin, so the backend serves 200s the webapp can't read
(CORS block). Lock both forms.
"""

from ..core import config


def test_cors_origins_json_array_form():
    assert config._parse_origins('["http://localhost:5174"]') == ["http://localhost:5174"]


def test_cors_origins_comma_form():
    assert config._parse_origins("http://a.local, http://b.local") == ["http://a.local", "http://b.local"]


def test_cors_origins_malformed_json_falls_back_to_comma():
    # A bracket-prefixed but unparseable value degrades to the comma split —
    # never raises, never silently blocks startup.
    assert config._parse_origins('["unterminated') == ['["unterminated']


def test_cors_origins_blank_is_empty():
    assert config._parse_origins("") == []
