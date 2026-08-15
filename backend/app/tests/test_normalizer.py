"""Event normalizer — the backend's final safety net before storage.

Locks the normalize_event contract: only schema fields survive, string
numerics coerce to int, junk numerics become None, unknown fields drop,
and hostless events fall back to the local machine identity.
"""

from app.services.normalizer import normalize_event


def test_passthrough_fields_survive():
    raw = {
        "run_id": "run-1",
        "platform": "linux",
        "event_type": "process_create",
        "timestamp": "2026-08-01T10:00:00Z",
        "pid": 100,
        "ppid": 1,
        "process_name": "bash",
        "command_line": "bash -i",
        "exe_path": "/bin/bash",
        "dest_ip": "203.0.113.5",
        "dest_port": 4444,
        "protocol": "TCP",
        "file_path": "/tmp/x",
        "registry_key": None,
        "host_id": "host-a",
        "log_source": "auditd",
        "query": None,
        "tls_sni": None,
        "raw_record": '{"a":1}',
    }
    out = normalize_event(raw)
    for field, value in raw.items():
        assert out[field] == value


def test_string_numerics_coerce_to_int():
    """auditd/evtx XML often ships pid/ppid/port as strings."""
    out = normalize_event({"pid": "100", "ppid": "1", "dest_port": "443"})
    assert out["pid"] == 100
    assert out["ppid"] == 1
    assert out["dest_port"] == 443
    assert isinstance(out["pid"], int)


def test_non_digit_numeric_strings_become_none():
    out = normalize_event({"pid": "abc", "ppid": "-5", "dest_port": "12x4"})
    assert out["pid"] is None
    assert out["ppid"] is None
    assert out["dest_port"] is None


def test_real_int_values_are_untouched():
    out = normalize_event({"pid": 100, "ppid": 0, "dest_port": 22})
    assert out["pid"] == 100
    assert out["ppid"] == 0
    assert out["dest_port"] == 22


def test_timestamp_iso_string_passes_through():
    out = normalize_event({"timestamp": "2026-08-01T10:00:00Z"})
    assert out["timestamp"] == "2026-08-01T10:00:00Z"


def test_unknown_fields_are_dropped():
    out = normalize_event({"event_type": "process_create", "secret_field": "x", "unmapped": 42})
    assert "secret_field" not in out
    assert "unmapped" not in out
    assert out["event_type"] == "process_create"


def test_hostless_event_falls_back_to_local():
    out = normalize_event({"event_type": "network_connection"})
    assert out["host_id"] == "local"


def test_explicit_host_id_is_kept():
    out = normalize_event({"event_type": "network_connection", "host_id": "fleet-7"})
    assert out["host_id"] == "fleet-7"


def test_empty_raw_returns_schema_with_none():
    out = normalize_event({})
    for field in ("run_id", "platform", "event_type", "timestamp", "pid", "ppid",
                  "process_name", "command_line", "exe_path", "dest_ip", "dest_port",
                  "protocol", "file_path", "registry_key", "log_source", "query",
                  "tls_sni", "raw_record"):
        assert field in out
    # host_id always resolves — the one field with a default.
    assert out["host_id"] == "local"


def test_whitespace_only_numeric_string_coerces():
    out = normalize_event({"pid": "  42  "})
    assert out["pid"] == 42


def test_float_pid_string_becomes_none():
    out = normalize_event({"pid": "3.14"})
    assert out["pid"] is None
