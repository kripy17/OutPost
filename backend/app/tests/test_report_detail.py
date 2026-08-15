"""Report exporter — `_event_detail` unit tests.

`build_json_report`/`build_pdf_report` are exercised through the API
(test_intel, test_campaigns, test_tunable_rules hit /runs/{id}/export); this
file pins the one pure function directly so the PDF's event row text can't
silently drift from the Event Log's detail rendering.
"""

from app.services.report import _event_detail


def test_process_create_detail():
    ev = {
        "event_type": "process_create",
        "process_name": "powershell.exe",
        "pid": 1234,
        "command_line": "powershell -enc AAAA",
    }
    assert _event_detail(ev) == "powershell.exe (pid 1234) powershell -enc AAAA"


def test_process_create_missing_name_and_cmdline():
    ev = {"event_type": "process_create", "process_name": None, "pid": 1, "command_line": None}
    assert _event_detail(ev) == "? (pid 1)"


def test_network_connection_detail():
    ev = {"event_type": "network_connection", "dest_ip": "203.0.113.9", "dest_port": 4444, "protocol": "TCP"}
    assert _event_detail(ev) == "203.0.113.9:4444 [TCP]"


def test_file_write_detail():
    ev = {"event_type": "file_write", "file_path": "C:\\Users\\victim\\payload.dll"}
    assert _event_detail(ev) == "C:\\Users\\victim\\payload.dll"


def test_file_write_missing_path():
    assert _event_detail({"event_type": "file_write", "file_path": None}) == "-"


def test_registry_write_detail():
    ev = {
        "event_type": "registry_write",
        "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
    }
    assert _event_detail(ev) == r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"


def test_unknown_event_type_falls_back_to_dash():
    assert _event_detail({"event_type": "something_else"}) == "-"
