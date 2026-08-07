"""Process-tree risk halos (docs/07 signature visual).

The run-detail endpoint annotates every process node with the worst reputation
of the destinations that pid reached (flagged_reputation + network_ips).
"""

import datetime

from .conftest import make_run


def _ts(offset: int = 0) -> str:
    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset)
    ).isoformat()


def _proc(run_id: str, pid: int, ppid: int, name: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": f"C:\\tmp\\{name}",
    }


def _net(run_id: str, pid: int, ip: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": pid, "dest_ip": ip, "dest_port": 4444,
        "protocol": "TCP",
    }


def _seed_reputation(conn, ip: str, reputation: str) -> None:
    conn.execute(
        "INSERT INTO enrichment_cache (ip, abuse_score, vt_malicious_count, reputation, checked_at) "
        "VALUES (?, NULL, NULL, ?, ?)",
        (ip, reputation, _ts()),
    )
    conn.commit()


def _find_node(nodes, pid: int):
    for n in nodes:
        if n["pid"] == pid:
            return n
        hit = _find_node(n.get("children", []), pid)
        if hit:
            return hit
    return None


def test_flagged_node_carries_malicious_halo(client, conn):
    run_id = make_run(client)
    _seed_reputation(conn, "203.0.113.99", "malicious")
    resp = client.post("/ingest/batch", json=[_proc(run_id, 100, 1, "evil.exe"), _net(run_id, 100, "203.0.113.99")])
    assert resp.status_code == 202

    detail = client.get(f"/runs/{run_id}").json()
    node = _find_node(detail["process_tree"], 100)
    assert node is not None
    assert node["flagged_reputation"] == "malicious"
    assert node["network_ips"] == ["203.0.113.99"]


def test_clean_node_has_no_halo(client):
    run_id = make_run(client)
    resp = client.post("/ingest/batch", json=[_proc(run_id, 200, 1, "benign.exe")])
    assert resp.status_code == 202

    detail = client.get(f"/runs/{run_id}").json()
    node = _find_node(detail["process_tree"], 200)
    assert node["flagged_reputation"] is None
    assert node["network_ips"] == []


def test_clean_only_node_has_network_but_no_halo(client, conn):
    # docs/07: a halo signals *risk*. Reaching only clean infrastructure is
    # NOT a finding — the destination list is populated (the analyst can see
    # where the process went) but flagged_reputation stays null, so no halo
    # badge renders and the tree's "N flagged" header doesn't count it.
    run_id = make_run(client)
    _seed_reputation(conn, "203.0.113.10", "clean")
    _seed_reputation(conn, "203.0.113.11", "clean")
    resp = client.post(
        "/ingest/batch",
        json=[
            _proc(run_id, 400, 1, "legit.exe"),
            _net(run_id, 400, "203.0.113.10"),
            _net(run_id, 400, "203.0.113.11"),
        ],
    )
    assert resp.status_code == 202

    detail = client.get(f"/runs/{run_id}").json()
    node = _find_node(detail["process_tree"], 400)
    assert node is not None
    assert sorted(node["network_ips"]) == ["203.0.113.10", "203.0.113.11"]
    assert node["flagged_reputation"] is None


def test_worst_reputation_wins_across_ips(client, conn):
    run_id = make_run(client)
    _seed_reputation(conn, "203.0.113.5", "clean")
    _seed_reputation(conn, "203.0.113.6", "suspicious")
    resp = client.post(
        "/ingest/batch",
        json=[_proc(run_id, 300, 1, "mixed.exe"), _net(run_id, 300, "203.0.113.5"), _net(run_id, 300, "203.0.113.6")],
    )
    assert resp.status_code == 202

    detail = client.get(f"/runs/{run_id}").json()
    node = _find_node(detail["process_tree"], 300)
    assert node["flagged_reputation"] == "suspicious"
    assert sorted(node["network_ips"]) == ["203.0.113.5", "203.0.113.6"]
