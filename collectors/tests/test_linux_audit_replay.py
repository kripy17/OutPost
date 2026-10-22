"""Tests replaying real Linux auditd lines for:
1. Successful file creation (openat with O_CREAT)
2. Successful write opens (openat with O_WRONLY/O_RDWR)
3. File rename (renameat2)
4. Permission changes (fchmodat/chmod)
5. Connect results (success vs refused/failed)
6. Documented noise controls and rules verification
"""

import sys
from pathlib import Path

_LINUX = Path(__file__).resolve().parent.parent / "linux"
sys.path.insert(0, str(_LINUX))

from collector_linux import parse_audit_line


def test_replay_successful_file_creation():
    """Real auditd sequence for successful file creation: SYSCALL (openat + O_CREAT) + PATH (CREATE)."""
    state = {}
    cache = {}

    # Real auditd: openat(AT_FDCWD, "/tmp/new_payload.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755)
    # syscall=257, success=yes, exit=3 (fd=3)
    syscall_line = (
        'type=SYSCALL msg=audit(1721234568.100:200): arch=c000003e syscall=257 '
        'success=yes exit=3 a0=ffffff9c a1=7ffd2a a2=241 a3=1ed items=2 ppid=100 '
        'pid=4500 auid=1000 uid=1000 gid=1000 euid=1000 comm="touch" exe="/usr/bin/touch" '
        'key="vantage_file_create"'
    )
    # Followed by cwd and path records
    cwd_line = 'type=CWD msg=audit(1721234568.100:200): cwd="/home/user"'
    path_line = (
        'type=PATH msg=audit(1721234568.100:200): item=1 name="/tmp/new_payload.sh" '
        'inode=524290 dev=08:01 mode=0100755 ouid=1000 ogid=1000 nametype=CREATE'
    )

    ev1 = parse_audit_line(syscall_line, cache, state)
    ev_cwd = parse_audit_line(cwd_line, cache, state)
    assert ev_cwd is None

    ev2 = parse_audit_line(path_line, cache, state)
    # The event must be produced (either on path line or syscall line)
    event = ev1 or ev2
    assert event is not None, "Failed to parse successful file creation event"
    assert event["event_type"] in ("file_create", "file_write")
    assert event["file_path"] == "/tmp/new_payload.sh"
    assert event["pid"] == 4500
    assert event["process_name"] == "touch"
    assert event["exe_path"] == "/usr/bin/touch"


def test_replay_successful_write_open():
    """Real auditd sequence for write open: SYSCALL (openat + O_WRONLY) + PATH (NORMAL)."""
    state = {}
    cache = {}

    # openat(AT_FDCWD, "/etc/config.conf", O_WRONLY|O_APPEND)
    syscall_line = (
        'type=SYSCALL msg=audit(1721234568.200:201): arch=c000003e syscall=257 '
        'success=yes exit=4 a0=ffffff9c a1=7ffd2b a2=441 a3=0 items=1 ppid=100 '
        'pid=4501 auid=1000 uid=1000 comm="writer" exe="/usr/bin/writer" '
        'key="vantage_file_write"'
    )
    path_line = (
        'type=PATH msg=audit(1721234568.200:201): item=0 name="/etc/config.conf" '
        'inode=12345 dev=08:01 mode=0100644 ouid=0 ogid=0 nametype=NORMAL'
    )

    ev1 = parse_audit_line(syscall_line, cache, state)
    ev2 = parse_audit_line(path_line, cache, state)
    event = ev1 or ev2
    assert event is not None, "Failed to parse write open event"
    assert event["event_type"] == "file_write"
    assert event["file_path"] == "/etc/config.conf"
    assert event["pid"] == 4501
    assert event["process_name"] == "writer"


def test_replay_file_rename():
    """Real auditd sequence for rename: SYSCALL (renameat2) + PATH (DELETE) + PATH (CREATE)."""
    state = {}
    cache = {}

    # renameat2(AT_FDCWD, "old.txt", AT_FDCWD, "new.txt", 0) -> syscall=316 (or renameat=264)
    syscall_line = (
        'type=SYSCALL msg=audit(1721234568.300:202): arch=c000003e syscall=316 '
        'success=yes exit=0 a0=ffffff9c a1=7ffd a2=ffffff9c a3=7ffe items=2 ppid=100 '
        'pid=4502 comm="mv" exe="/usr/bin/mv" key="vantage_file_rename"'
    )
    path_old = (
        'type=PATH msg=audit(1721234568.300:202): item=0 name="/tmp/old_malware.bin" '
        'nametype=DELETE'
    )
    path_new = (
        'type=PATH msg=audit(1721234568.300:202): item=1 name="/tmp/innocent.bin" '
        'nametype=CREATE'
    )

    ev_sys = parse_audit_line(syscall_line, cache, state)
    ev_old = parse_audit_line(path_old, cache, state)
    ev_new = parse_audit_line(path_new, cache, state)
    event = ev_sys or ev_old or ev_new
    assert event is not None, "Failed to parse rename event"
    assert event["event_type"] == "file_rename"
    assert event["file_path"] == "/tmp/innocent.bin"
    assert event["pid"] == 4502
    assert event["process_name"] == "mv"


def test_replay_permission_change():
    """Real auditd sequence for permission change: SYSCALL (fchmodat/chmod) + PATH."""
    state = {}
    cache = {}

    # fchmodat(AT_FDCWD, "/tmp/evil.sh", 0777) -> syscall=268
    syscall_line = (
        'type=SYSCALL msg=audit(1721234568.400:203): arch=c000003e syscall=268 '
        'success=yes exit=0 a0=ffffff9c a1=7ffd2d a2=1ff a3=0 items=1 ppid=100 '
        'pid=4503 comm="chmod" exe="/usr/bin/chmod" key="vantage_file_perm"'
    )
    path_line = (
        'type=PATH msg=audit(1721234568.400:203): item=0 name="/tmp/evil.sh" '
        'mode=0100777 nametype=NORMAL'
    )

    ev_sys = parse_audit_line(syscall_line, cache, state)
    ev_path = parse_audit_line(path_line, cache, state)
    event = ev_sys or ev_path
    assert event is not None, "Failed to parse permission change event"
    assert event["event_type"] == "file_permission"
    assert event["file_path"] == "/tmp/evil.sh"
    assert event["pid"] == 4503
    assert event["process_name"] == "chmod"


def test_replay_connect_results():
    """Real auditd connect results: established vs connection refused."""
    state = {}
    cache = {}

    # 1. Successful connect (success=yes, exit=0)
    sys_ok = (
        'type=SYSCALL msg=audit(1721234568.500:204): arch=c000003e syscall=42 '
        'success=yes exit=0 a0=3 a1=7ffd2e a2=10 items=0 ppid=100 pid=4504 '
        'comm="curl" exe="/usr/bin/curl" key="vantage_net"'
    )
    sock_ok = 'type=SOCKADDR msg=audit(1721234568.500:204): saddr=020001BB5DB8D822'  # 93.184.216.34:443
    parse_audit_line(sys_ok, cache, state)
    ev_ok = parse_audit_line(sock_ok, cache, state)
    assert ev_ok is not None
    assert ev_ok["event_type"] == "network_connection"
    assert ev_ok["dest_ip"] == "93.184.216.34"
    assert ev_ok["dest_port"] == 443
    assert ev_ok["connection_status"] == "established"

    # 2. Refused connect (success=no, exit=-111 / ECONNREFUSED)
    sys_fail = (
        'type=SYSCALL msg=audit(1721234568.600:205): arch=c000003e syscall=42 '
        'success=no exit=-111 a0=3 a1=7ffd2f a2=10 items=0 ppid=100 pid=4505 '
        'comm="nc" exe="/usr/bin/nc" key="vantage_net"'
    )
    sock_fail = 'type=SOCKADDR msg=audit(1721234568.600:205): saddr=0200115CC0A80101'  # 192.168.1.1:4444
    parse_audit_line(sys_fail, cache, state)
    ev_fail = parse_audit_line(sock_fail, cache, state)
    assert ev_fail is not None
    assert ev_fail["event_type"] == "network_connection"
    assert ev_fail["dest_ip"] == "192.168.1.1"
    assert ev_fail["dest_port"] == 4444
    assert ev_fail["connection_status"] in ("failed", "attempted", "refused")


def test_audit_rules_contain_required_syscalls_and_noise_controls():
    """audit.rules must contain rules for file creation, write opens, rename, permissions, and documented noise controls."""
    rules_file = _LINUX / "audit.rules"
    content = rules_file.read_text()

    # Successful file creation and write opens
    assert "vantage_file_create" in content or "vantage_file_write" in content
    assert "openat" in content
    assert "creat" in content

    # Renames
    assert "rename" in content
    assert "vantage_file_rename" in content

    # Permissions
    assert "chmod" in content
    assert "vantage_file_perm" in content

    # Connect
    assert "connect" in content
    assert "vantage_net" in content

    # Noise controls documentation in comments
    assert "noise" in content.lower() or "filter" in content.lower()
