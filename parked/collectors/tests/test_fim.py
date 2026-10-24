import sys
import time
from pathlib import Path

_COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(_COMMON))

from collector_local import FileIntegrityMonitor


def test_fim_baseline_and_modification_detection(tmp_path: Path):
    """Verify FIM detects file modifications, creations, and deletions."""
    sec_file = tmp_path / "passwd"
    sec_file.write_text("root:x:0:0:root:/root:/bin/bash\n")

    untracked_file = tmp_path / "sudoers"

    fim = FileIntegrityMonitor(watch_paths=[str(sec_file), str(untracked_file)])
    assert sec_file in fim.state
    assert fim.state[sec_file]["exists"] is True
    assert fim.state[untracked_file]["exists"] is False

    # 1. No changes -> empty poll
    events = fim.poll_changes()
    assert len(events) == 0

    # 2. Modify existing file
    time.sleep(0.05)
    sec_file.write_text("root:x:0:0:root:/root:/bin/bash\nhacker:x:0:0::/root:/bin/bash\n")
    events = fim.poll_changes()
    assert len(events) == 1
    assert events[0]["event_type"] == "file_modify"
    assert events[0]["file_name"] == "passwd"
    assert "prev_sha256" in events[0]
    assert events[0]["hash_sha256"] != events[0]["prev_sha256"]

    # 3. Create monitored file
    untracked_file.write_text("ALL ALL=(ALL:ALL) NOPASSWD: ALL\n")
    events = fim.poll_changes()
    assert len(events) == 1
    assert events[0]["event_type"] == "file_create"
    assert events[0]["file_name"] == "sudoers"

    # 4. Delete monitored file
    sec_file.unlink()
    events = fim.poll_changes()
    assert len(events) == 1
    assert events[0]["event_type"] == "file_delete"
    assert events[0]["file_name"] == "passwd"
