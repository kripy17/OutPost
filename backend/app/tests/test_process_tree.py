"""Process tree builder — Task 4 acceptance."""

from ..services.process_tree import build_process_tree


def test_nested_tree():
    events = [
        {"pid": 1, "ppid": None, "process_name": "launcher.exe", "command_line": "launcher.exe", "event_type": "process_create"},
        {"pid": 2, "ppid": 1, "process_name": "cmd.exe", "command_line": "cmd.exe /c dir", "event_type": "process_create"},
        {"pid": 3, "ppid": 2, "process_name": "powershell.exe", "command_line": "powershell -enc AAA", "event_type": "process_create"},
    ]
    roots = build_process_tree(events)
    assert len(roots) == 1
    launcher = roots[0]
    assert launcher.process_name == "launcher.exe"
    assert len(launcher.children) == 1
    assert launcher.children[0].process_name == "cmd.exe"
    assert launcher.children[0].children[0].process_name == "powershell.exe"


def test_multiple_roots():
    events = [
        {"pid": 1, "ppid": None, "process_name": "a.exe", "event_type": "process_create"},
        {"pid": 2, "ppid": None, "process_name": "b.exe", "event_type": "process_create"},
    ]
    roots = build_process_tree(events)
    assert {r.process_name for r in roots} == {"a.exe", "b.exe"}


def test_orphan_child_becomes_root():
    # ppid never appears in the run -> treated as a root (docs/02).
    events = [
        {"pid": 5, "ppid": 999, "process_name": "orphan.exe", "event_type": "process_create"},
    ]
    roots = build_process_tree(events)
    assert len(roots) == 1
    assert roots[0].process_name == "orphan.exe"


def test_duplicate_pid_merged():
    events = [
        {"pid": 7, "ppid": 1, "process_name": "p.exe", "command_line": None, "event_type": "process_create"},
        {"pid": 7, "ppid": 1, "process_name": "p.exe", "command_line": "p.exe --flag", "event_type": "process_create"},
    ]
    roots = build_process_tree(events)
    assert len(roots) == 1
    assert roots[0].command_line == "p.exe --flag"
