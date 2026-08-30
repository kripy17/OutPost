"""Sandbox detonation adapter (roadmap 3.3).

Covers the demo detonation pipeline end-to-end (upload → detonate → run with
real alerts), the platform override, per-provider report normalizers (pure
functions, no network), the provider registry listing, the live provider
adapters (fake httpx client — no network), and the error paths (unknown
sample / bad provider / unconfigured live provider / unknown task / vanished
run / provider outage).
"""

import asyncio
import datetime

import pytest

from ..services import sandbox as sandbox_service
from .conftest import make_run

MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x53\x41\x4e\x44\x42\x4f\x58\x2d\x4d\x5a"


def _upload(client, name: str, body: bytes = MZ):
    resp = client.post(f"/samples?name={name}", content=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# -- Demo detonation pipeline --------------------------------------------------


def test_demo_detonation_full_pipeline(client):
    sample = _upload(client, "sandbox-demo.exe")
    resp = client.post(
        "/sandbox/detonate",
        json={"sample_id": sample["sample_id"], "provider": "demo"},
    )
    assert resp.status_code == 202, resp.text
    task = resp.json()

    # Demo resolves inline — already completed with a real run behind it.
    assert task["status"] == "completed"
    assert task["provider"] == "demo"
    assert task["sample_name"] == "sandbox-demo.exe"
    assert task["platform"] == "windows"
    assert task["events"] >= 10
    assert task["alerts"] >= 3
    assert task["risk_score"] > 0
    assert task["highest_severity"] in ("suspicious", "malicious")

    # The run exists, is completed, and its detail carries the tree + alerts.
    run = client.get(f"/runs/{task['run_id']}").json()
    assert run["run"]["completed_at"] is not None
    # One root (the sample) with the cmd → powershell chain nested beneath it.
    assert len(run["process_tree"]) >= 1
    assert run["process_tree"][0]["children"], "expected a child process under the root"
    assert run["run"]["risk_score"] > 0

    # Same shape via the task status poll.
    again = client.get(f"/sandbox/tasks/{task['task_id']}").json()
    assert again["status"] == "completed"
    assert again["run_id"] == task["run_id"]


def test_demo_platform_override_runs_linux_scenario(client):
    sample = _upload(client, "cross-os.exe")
    resp = client.post(
        "/sandbox/detonate",
        json={"sample_id": sample["sample_id"], "provider": "demo", "platform": "linux"},
    )
    assert resp.status_code == 202, resp.text
    task = resp.json()
    assert task["platform"] == "linux"
    assert task["status"] == "completed"

    run = client.get(f"/runs/{task['run_id']}").json()
    assert run["run"]["platform"] == "linux"
    # The linux demo fires the LOLBin reverse-shell rule.
    rule_ids = {a["rule_id"] for a in run["alerts"]}
    assert "lolbin-abuse" in rule_ids
    # A reverse-shell connection to the C2 port is in the timeline.
    ips = {e["dest_ip"] for e in run["timeline"] if e["dest_ip"]}
    assert "198.51.100.10" in ips


def test_auto_resolves_to_demo_when_no_provider_configured(client):
    sample = _upload(client, "auto-demo.bin")
    resp = client.post(
        "/sandbox/detonate",
        json={"sample_id": sample["sample_id"], "provider": "auto"},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["provider"] == "demo"


# -- Error paths ---------------------------------------------------------------


def test_unknown_sample_404(client):
    resp = client.post("/sandbox/detonate", json={"sample_id": "nope00000000", "provider": "demo"})
    assert resp.status_code == 404


def test_bad_provider_422(client):
    sample = _upload(client, "bad-prov.bin")
    resp = client.post("/sandbox/detonate", json={"sample_id": sample["sample_id"], "provider": "mysterybox"})
    assert resp.status_code == 422
    assert "Unknown sandbox provider" in resp.json()["detail"]


def test_unconfigured_live_provider_422(client):
    sample = _upload(client, "nokey.bin")
    resp = client.post("/sandbox/detonate", json={"sample_id": sample["sample_id"], "provider": "anyrun"})
    assert resp.status_code == 422
    assert "ANYRUN_API_KEY" in resp.json()["detail"]


def test_unknown_task_404(client):
    resp = client.get("/sandbox/tasks/doesnotexist99")
    assert resp.status_code == 404


# -- Provider registry ---------------------------------------------------------


def test_providers_listing(client):
    data = client.get("/sandbox/providers").json()
    ids = [p["id"] for p in data["providers"]]
    assert ids == ["anyrun", "triage", "joe", "demo"]
    assert data["mode"] == "demo"  # no API keys in the test env
    assert data["active"] == ""


# -- Report normalizers (pure functions, no network) ---------------------------


def _base():
    return datetime.datetime(2026, 8, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)


def test_normalize_anyrun_report():
    report = {
        "process": [
            {"pid": 1, "ppid": 0, "processName": "evil.exe", "commandLine": r"C:\temp\evil.exe"},
            {"pid": 2, "ppid": 1, "processName": "powershell.exe", "commandLine": "powershell.exe -enc QUJD"},
        ],
        "files": [{"path": r"C:\Users\victim\Documents\invoice.enc"}],
        "registry": [{"path": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Bad"}],
    }
    net_report = {
        "network": [{"protocol": "TCP", "remoteHost": "203.0.113.99", "remotePort": 4444, "processPid": 2}]
    }
    report.update(net_report)
    events = sandbox_service.normalize_anyrun(report, "r1", "windows", _base())
    types = [e["event_type"] for e in events]
    assert types.count("process_create") == 2
    assert types.count("network_connection") == 1
    assert types.count("file_write") == 1
    assert types.count("registry_write") == 1
    net = next(e for e in events if e["event_type"] == "network_connection")
    assert net["dest_ip"] == "203.0.113.99" and net["dest_port"] == 4444
    proc = next(e for e in events if e["pid"] == 2)
    assert proc["process_name"] == "powershell.exe"


def test_normalize_triage_report_pid_keyed_processes():
    report = {
        "processes": {
            "10": {"pid": 10, "ppid": 1, "process_name": "bash", "command_line": "bash -i"},
            "11": {"pid": 11, "ppid": 10, "process_name": "curl", "command_line": "curl http://x"},
        },
        "network": {"tcp": [{"dst_ip": "198.51.100.7", "dst_port": 8080}]},
        "files": ["/tmp/staged.enc"],
    }
    events = sandbox_service.normalize_triage(report, "r2", "linux", _base())
    procs = [e for e in events if e["event_type"] == "process_create"]
    assert len(procs) == 2
    assert {p["pid"] for p in procs} == {10, 11}
    net = next(e for e in events if e["event_type"] == "network_connection")
    assert net["dest_ip"] == "198.51.100.7"
    assert any(e["file_path"] == "/tmp/staged.enc" for e in events)


def test_normalize_joe_report_nested_data():
    report = {
        "data": {
            "processes": [
                {"name": "svchost.exe", "pid": 3, "parent_pid": 1, "command_line": r"C:\Windows\System32\svchost.exe"}
            ],
            "network": {"udp": [{"dst_ip": "1.1.1.1", "dst_port": 53}]},
            "filesystem": [{"path": r"C:\temp\out.dat"}],
            "registry": [{"path": r"HKCU\Software\Run\Upd"}],
        }
    }
    events = sandbox_service.normalize_joe(report, "r3", "windows", _base())
    assert any(e["event_type"] == "process_create" and e["process_name"] == "svchost.exe" for e in events)
    assert any(e["event_type"] == "network_connection" and e["dest_ip"] == "1.1.1.1" for e in events)
    assert any(e["event_type"] == "registry_write" for e in events)


def test_normalize_report_dispatch_unknown_provider():
    try:
        sandbox_service.normalize_report("mysterybox", {}, "r", "windows", _base())
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_demo_events_are_normalized_shape():
    events = sandbox_service.demo_events("r9", "windows", "demo.exe", _base())
    assert events
    for ev in events:
        assert set(ev) == {
            "run_id", "platform", "event_type", "timestamp", "pid", "ppid",
            "process_name", "command_line", "dest_ip", "dest_port", "protocol",
            "file_path", "registry_key",
        }
        assert ev["run_id"] == "r9" and ev["platform"] == "windows"


# -- Provider registry internals -------------------------------------------------


def test_key_for_unknown_provider_returns_empty():
    assert sandbox_service._key_for("mysterybox") == ""


def test_active_provider_prefers_pinned_sandbox_provider(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "SANDBOX_PROVIDER", "triage")
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "ak")
    monkeypatch.setattr(sandbox_service.config, "TRIAGE_API_KEY", "tk")
    monkeypatch.setattr(sandbox_service.config, "JOE_API_KEY", "")
    assert sandbox_service.active_provider() == "triage"


def test_active_provider_falls_back_to_first_configured(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "SANDBOX_PROVIDER", "")
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "ak")
    monkeypatch.setattr(sandbox_service.config, "TRIAGE_API_KEY", "")
    monkeypatch.setattr(sandbox_service.config, "JOE_API_KEY", "")
    assert sandbox_service.active_provider() == "anyrun"


# -- Report normalizer edge shapes -------------------------------------------------


def test_process_rows_nested_process_shape():
    """A report whose key holds a dict wrapping a `process` list (a provider
    shape between Triage's pid-keyed dict and Any.Run's plain list)."""
    rows = sandbox_service._process_rows({"x": {"process": [{"pid": 1}, {"pid": 2}, "junk"]}}, "x")
    assert [r["pid"] for r in rows] == [1, 2]


def test_process_rows_neither_dict_nor_list_returns_empty():
    assert sandbox_service._process_rows({"x": "junk"}, "x") == []
    assert sandbox_service._process_rows({}, "missing") == []


def test_network_rows_list_shape_and_empty():
    assert [r["dst_ip"] for r in sandbox_service._network_rows({"network": [{"dst_ip": "1.1.1.1"}]})] == ["1.1.1.1"]
    assert sandbox_service._network_rows({"network": "junk"}) == []
    assert sandbox_service._network_rows({}) == []


def test_value_rows_non_list_returns_empty():
    assert sandbox_service._value_rows({"files": "junk"}, "files") == []


def test_as_ts_handles_epoch_iso_and_garbage():
    assert sandbox_service._as_ts(None) is None
    assert sandbox_service._as_ts("2026-08-08T12:00:00Z") == "2026-08-08T12:00:00Z"
    ms = 1_752_000_000_000  # ms epoch → ISO
    out = sandbox_service._as_ts(ms)
    assert out and out.startswith("2025-")
    assert sandbox_service._as_ts(1e300) is None  # OverflowError → None
    assert sandbox_service._as_ts("junk") == "junk"
    assert sandbox_service._as_ts(["list"]) is None  # non-int/float/str → None


def test_normalize_triage_registry_rows():
    report = {
        "processes": {},
        "network": {},
        "files": [],
        "registry": [{"path": r"HKCU\Software\Run\Upd"}],
    }
    events = sandbox_service.normalize_triage(report, "r2", "windows", _base())
    reg = [e for e in events if e["event_type"] == "registry_write"]
    assert reg and reg[0]["registry_key"].endswith("Upd")


def test_normalize_report_dispatches_each_provider():
    anyrun = sandbox_service.normalize_report(
        "anyrun", {"process": [{"pid": 1, "processName": "a.exe"}]}, "r", "windows", _base()
    )
    assert anyrun and anyrun[0]["process_name"] == "a.exe"
    triage = sandbox_service.normalize_report(
        "triage", {"processes": {"1": {"pid": 1}}}, "r", "windows", _base()
    )
    assert triage and triage[0]["pid"] == 1
    joe = sandbox_service.normalize_report(
        "joe", {"data": {"processes": [{"pid": 1}]}}, "r", "windows", _base()
    )
    assert joe and joe[0]["pid"] == 1


# -- Live provider adapters (fake httpx client — no network) -----------------------


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeAClient:
    def __init__(self, handler, **kw):
        self._handler = handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kw):
        return _FakeResp(self._handler("post", url))

    async def get(self, url, **kw):
        return _FakeResp(self._handler("get", url))


def _patch_httpx(monkeypatch, handler):
    monkeypatch.setattr(sandbox_service.httpx, "AsyncClient", lambda **kw: _FakeAClient(handler))


def test_live_detonate_anyrun_submits_polls_and_fetches(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "test-key")
    calls = []

    def handler(method, url):
        calls.append((method, url))
        if method == "post" and url == "https://api.any.run/v1/analysis":
            return {"data": {"id": "an1"}}
        if url == "https://api.any.run/v1/analysis/an1":
            return {"data": {"status": "finished"}}
        if url.endswith("/report/summary"):
            return {
                "data": {
                    "process": [{"pid": 1, "ppid": 0, "processName": "evil.exe", "commandLine": r"C:\tmp\evil.exe"}],
                    "files": [{"path": r"C:\tmp\a.enc"}],
                    "registry": [{"path": r"HKCU\Run\Bad"}],
                }
            }
        if url.endswith("/report/network"):
            return {"data": {"network": [{"protocol": "TCP", "remoteHost": "203.0.113.99", "remotePort": 4444, "processPid": 1}]}}
        return {"data": {}}

    _patch_httpx(monkeypatch, handler)
    task = {"platform": "windows", "sample_name": "evil.exe"}
    report = asyncio.run(sandbox_service._live_detonate("anyrun", task, b"MZ"))
    assert report["process"][0]["processName"] == "evil.exe"
    assert report["network"][0]["remoteHost"] == "203.0.113.99"
    assert ("post", "https://api.any.run/v1/analysis") in calls


def test_live_detonate_anyrun_submit_returns_no_id(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "test-key")
    _patch_httpx(monkeypatch, lambda m, u: {"data": {}})
    with pytest.raises(RuntimeError, match="no analysis id"):
        asyncio.run(sandbox_service._live_detonate("anyrun", {"platform": "windows", "sample_name": "x"}, b""))


def test_live_detonate_anyrun_failed_status(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "test-key")

    def handler(method, url):
        if method == "post":
            return {"data": {"id": "an2"}}
        return {"data": {"status": "failed"}}

    _patch_httpx(monkeypatch, handler)
    with pytest.raises(RuntimeError, match="failed"):
        asyncio.run(sandbox_service._live_detonate("anyrun", {"platform": "windows", "sample_name": "x"}, b""))


def test_live_detonate_anyrun_missing_report_part_is_tolerated(monkeypatch):
    """A failing report part must not fail the whole run — the part loop
    swallows it and the other parts still land in the merged report."""
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "test-key")

    def handler(method, url):
        if method == "post":
            return {"data": {"id": "an4"}}
        if url == "https://api.any.run/v1/analysis/an4":
            return {"data": {"status": "finished"}}
        if url.endswith("/report/summary"):
            return {"data": {"process": [{"pid": 1, "processName": "evil.exe"}]}}
        if url.endswith("/report/network"):
            return {"data": {"network": [{"protocol": "TCP", "remoteHost": "203.0.113.5", "remotePort": 4444, "processPid": 1}]}}
        raise RuntimeError("part fetch failed")  # process/files/registry parts

    _patch_httpx(monkeypatch, handler)
    report = asyncio.run(sandbox_service._live_detonate("anyrun", {"platform": "windows", "sample_name": "x"}, b""))
    assert report["process"][0]["processName"] == "evil.exe"
    assert report["network"][0]["remoteHost"] == "203.0.113.5"


def test_live_detonate_anyrun_times_out(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "test-key")

    async def _no_sleep(_):
        return None

    monkeypatch.setattr(sandbox_service.asyncio, "sleep", _no_sleep)

    def handler(method, url):
        if method == "post":
            return {"data": {"id": "an3"}}
        return {"data": {"status": "running"}}

    _patch_httpx(monkeypatch, handler)
    with pytest.raises(RuntimeError, match="timed out"):
        asyncio.run(sandbox_service._live_detonate("anyrun", {"platform": "windows", "sample_name": "x"}, b""))


def test_live_detonate_triage_submits_polls_and_fetches(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "TRIAGE_API_KEY", "test-key")

    def handler(method, url):
        if method == "post" and url == "https://api.tria.ge/v0/samples":
            return {"id": "s1"}
        if url == "https://api.tria.ge/v0/samples/s1":
            return {"status": "reported", "tasks": {"t1": {}}}
        if url.endswith("/reports/t1"):
            return {
                "processes": {"10": {"pid": 10, "ppid": 1, "process_name": "bash", "command_line": "bash -i"}},
                "network": {"tcp": [{"dst_ip": "198.51.100.7", "dst_port": 8080}]},
                "files": ["/tmp/staged.enc"],
                "registry": [{"path": "/etc/rc.local"}],
            }
        raise AssertionError(url)

    _patch_httpx(monkeypatch, handler)
    report = asyncio.run(sandbox_service._live_detonate("triage", {"platform": "linux", "sample_name": "x"}, b""))
    assert report["processes"]["10"]["process_name"] == "bash"
    assert report["network"]["tcp"][0]["dst_ip"] == "198.51.100.7"


def test_live_detonate_triage_no_task_id(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "TRIAGE_API_KEY", "test-key")

    def handler(method, url):
        if method == "post":
            return {"id": "s1"}
        return {"status": "reported", "tasks": {}}

    _patch_httpx(monkeypatch, handler)
    with pytest.raises(RuntimeError, match="no task id"):
        asyncio.run(sandbox_service._live_detonate("triage", {"platform": "linux", "sample_name": "x"}, b""))


def test_live_detonate_triage_no_sample_id(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "TRIAGE_API_KEY", "test-key")
    _patch_httpx(monkeypatch, lambda m, u: {})
    with pytest.raises(RuntimeError, match="no sample id"):
        asyncio.run(sandbox_service._live_detonate("triage", {"platform": "linux", "sample_name": "x"}, b""))


def test_live_detonate_triage_failed_status_and_timeout(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "TRIAGE_API_KEY", "test-key")

    async def _no_sleep(_):
        return None

    monkeypatch.setattr(sandbox_service.asyncio, "sleep", _no_sleep)

    def handler(method, url):
        if method == "post":
            return {"id": "s2"}
        return {"status": "failed", "tasks": {}}

    _patch_httpx(monkeypatch, handler)
    with pytest.raises(RuntimeError, match="failed"):
        asyncio.run(sandbox_service._live_detonate("triage", {"platform": "linux", "sample_name": "x"}, b""))

    def handler2(method, url):
        if method == "post":
            return {"id": "s3"}
        return {"status": "running", "tasks": {}}

    _patch_httpx(monkeypatch, handler2)
    with pytest.raises(RuntimeError, match="timed out"):
        asyncio.run(sandbox_service._live_detonate("triage", {"platform": "linux", "sample_name": "x"}, b""))


def test_live_detonate_joe_submits_polls_and_fetches(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "JOE_API_KEY", "test-key")

    def handler(method, url):
        if method == "post" and url == "https://jbxcloud.joesecurity.org/api/v2/analysis/submit":
            return {"data": {"webid": "w1"}}
        if url == "https://jbxcloud.joesecurity.org/api/v2/analysis/w1":
            return {"data": {"status": "finished"}}
        if url.endswith("/report"):
            return {
                "data": {
                    "processes": [{"name": "evil", "pid": 1, "parent_pid": 0}],
                    "network": {"udp": [{"dst_ip": "1.1.1.1", "dst_port": 53}]},
                    "filesystem": [{"path": "/tmp/x"}],
                    "registry": [{"path": "HKLM\\Run\\X"}],
                }
            }
        raise AssertionError(url)

    _patch_httpx(monkeypatch, handler)
    report = asyncio.run(sandbox_service._live_detonate("joe", {"platform": "windows", "sample_name": "x"}, b""))
    assert report["data"]["processes"][0]["name"] == "evil"


def test_live_detonate_joe_no_webid(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "JOE_API_KEY", "test-key")
    _patch_httpx(monkeypatch, lambda m, u: {"data": {}})
    with pytest.raises(RuntimeError, match="no webid"):
        asyncio.run(sandbox_service._live_detonate("joe", {"platform": "windows", "sample_name": "x"}, b""))


def test_live_detonate_joe_failed_status_and_timeout(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "JOE_API_KEY", "test-key")

    async def _no_sleep(_):
        return None

    monkeypatch.setattr(sandbox_service.asyncio, "sleep", _no_sleep)

    def handler(method, url):
        if method == "post":
            return {"data": {"webid": "w2"}}
        return {"data": {"status": "failed"}}

    _patch_httpx(monkeypatch, handler)
    with pytest.raises(RuntimeError, match="failed"):
        asyncio.run(sandbox_service._live_detonate("joe", {"platform": "windows", "sample_name": "x"}, b""))

    def handler2(method, url):
        if method == "post":
            return {"data": {"webid": "w3"}}
        return {"data": {"status": "running"}}

    _patch_httpx(monkeypatch, handler2)
    with pytest.raises(RuntimeError, match="timed out"):
        asyncio.run(sandbox_service._live_detonate("joe", {"platform": "windows", "sample_name": "x"}, b""))


def test_live_detonate_unconfigured_provider_raises(monkeypatch):
    monkeypatch.setattr(sandbox_service.config, "ANYRUN_API_KEY", "")
    with pytest.raises(RuntimeError, match="not configured"):
        asyncio.run(sandbox_service._live_detonate("anyrun", {"platform": "windows", "sample_name": "x"}, b""))


def test_live_detonate_unknown_provider_raises(monkeypatch):
    monkeypatch.setattr(sandbox_service, "_key_for", lambda p: "k")
    with pytest.raises(RuntimeError, match="Unknown provider"):
        asyncio.run(sandbox_service._live_detonate("mysterybox", {"platform": "windows", "sample_name": "x"}, b""))


# -- run_task branches (live ingest / vanished run / watchlist / error) ------------


def test_run_task_live_provider_ingests_and_completes(client, monkeypatch):
    sample = _upload(client, "live-ing.bin")
    run_id = make_run(client, sample_name="live-ing.bin")

    async def fake_live(provider, task_, sample_bytes):
        return {
            "process": [{"pid": 1, "ppid": 0, "processName": "evil.exe", "commandLine": r"C:\tmp\evil.exe"}],
            # Distinct IP: the session DB is shared, and test_tree_annotation
            # seeds 203.0.113.99 as malicious — colliding would break its
            # enrichment-cache INSERT (UNIQUE constraint).
            "network": [{"protocol": "TCP", "remoteHost": "198.51.100.250", "remotePort": 4444, "processPid": 1}],
        }

    monkeypatch.setattr(sandbox_service, "_live_detonate", fake_live)
    task = sandbox_service.create_task(run_id, sample["sample_id"], "live-ing.bin", "anyrun", "windows")
    asyncio.run(sandbox_service.run_task(task, b"MZ"))
    assert task["status"] == "completed"
    assert task["events"] >= 2
    run = client.get(f"/runs/{run_id}").json()
    assert run["run"]["completed_at"] is not None


def test_run_task_vanished_run_records_error():
    task = sandbox_service.create_task("nope00000000", "s1", "v.bin", "demo", "windows")
    asyncio.run(sandbox_service.run_task(task, b""))
    assert task["status"] == "error"
    assert "vanished" in task["error"]
    assert task["finished_at"]


def test_run_task_live_failure_records_error(monkeypatch):
    task = sandbox_service.create_task("nope00000000", "s1", "f.bin", "anyrun", "windows")

    async def boom(provider, task_, sample_bytes):
        raise RuntimeError("provider down")

    monkeypatch.setattr(sandbox_service, "_live_detonate", boom)
    asyncio.run(sandbox_service.run_task(task, b""))
    assert task["status"] == "error"
    assert "provider down" in task["error"]
    assert task["finished_at"]


def test_demo_detonation_publishes_watchlist_hits(client, conn, monkeypatch):
    """A watched IOC inside a demo detonation fires the live watchlist channel
    (SSE publish) and persists the first-seen hit — the same path a real
    provider report's events take through run_task."""
    from ..models import watchlist as watchlist_store
    from ..services import events_stream

    watchlist_store.add_watchlist(conn, "203.0.113.88", "C2")
    conn.commit()
    published = []
    monkeypatch.setattr(events_stream, "publish_watchlist", lambda *a: published.append(a))

    sample = _upload(client, "watch-demo.exe")
    resp = client.post("/sandbox/detonate", json={"sample_id": sample["sample_id"], "provider": "demo"})
    task = resp.json()
    assert task["status"] == "completed"
    assert published, "the watchlist hit must be pushed over SSE"
    rows = conn.execute(
        "SELECT ioc_value FROM watchlist_hits WHERE run_id = ?", (task["run_id"],)
    ).fetchall()
    assert any(r["ioc_value"] == "203.0.113.88" for r in rows)


def test_get_sandbox_drivers(client):
    resp = client.get("/sandbox/drivers")
    assert resp.status_code == 200
    drivers = resp.json()
    assert isinstance(drivers, list)
    driver_ids = [d["id"] for d in drivers]
    assert "tempdir" in driver_ids
    assert "bubblewrap" in driver_ids
    assert "wine" in driver_ids
    assert "container" in driver_ids


def test_dynamic_detonation_isolation_driver(client):
    sample = _upload(client, "isolation_test.py")
    resp = client.post(
        "/sandbox/detonate/dynamic",
        json={"sample_id": sample["sample_id"], "isolation_driver": "tempdir"},
    )
    assert resp.status_code == 200
    res = resp.json()
    assert "isolation_driver" in res
    assert res["isolation_driver"] in ("tempdir", "bubblewrap", "wine")

