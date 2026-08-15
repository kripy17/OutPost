"""PDF report export + JSON-report robustness branches.

`build_pdf_report` (the reportlab path behind ?format=pdf) was shipped but
never exercised by any test — the API suites only hit the JSON default. This
pins the artifact: a real %PDF document for a real run, None for an unknown
run, and the route serving application/pdf. Also covers build_json_report's
error and corruption-tolerance branches (unknown run, malformed tuning
snapshot, malformed storm-cap payload).
"""

from ..services import report


def _make_run_with_events(client) -> str:
    run_id = client.post("/runs", json={"sample_name": "pdf-test.bin", "platform": "windows"}).json()["run_id"]
    client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run_id,
                "platform": "windows",
                "event_type": "process_create",
                "timestamp": "2026-08-15T10:00:00Z",
                "pid": 100,
                "process_name": "powershell.exe",
                "command_line": "powershell -enc AAAA",
            },
            {
                "run_id": run_id,
                "platform": "windows",
                "event_type": "network_connection",
                "timestamp": "2026-08-15T10:00:02Z",
                "pid": 100,
                "process_name": "powershell.exe",
                "dest_ip": "203.0.113.9",
                "dest_port": 4444,
                "protocol": "TCP",
            },
        ],
    )
    return run_id


def test_pdf_report_is_a_real_pdf_document(client):
    run_id = _make_run_with_events(client)
    pdf = report.build_pdf_report(run_id)
    # reportlab compresses the story text into object streams, so the bytes
    # aren't plaintext — the contract is a well-formed, non-trivial PDF.
    assert pdf and pdf[:4] == b"%PDF"
    assert len(pdf) > 500


def test_pdf_report_unknown_run_returns_none(client):
    assert report.build_pdf_report("does-not-exist") is None


def test_export_route_serves_pdf(client):
    run_id = _make_run_with_events(client)
    resp = client.get(f"/runs/{run_id}/export", params={"format": "pdf"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"


def test_json_report_unknown_run_returns_error(client):
    body = report.build_json_report("nope")
    assert "error" in body


def test_json_report_tolerates_corrupt_tuning_snapshot(client, conn):
    run_id = _make_run_with_events(client)
    conn.execute("INSERT OR REPLACE INTO run_tuning_snapshot (run_id, params) VALUES (?, ?)", (run_id, "not-json{"))
    conn.commit()
    body = report.build_json_report(run_id)
    assert body["effective_tuning"] == {}


def test_json_report_tolerates_corrupt_suppressed_alerts(client, conn):
    run_id = _make_run_with_events(client)
    conn.execute("UPDATE runs SET suppressed_alerts = ? WHERE run_id = ?", ("{{bad", run_id))
    conn.commit()
    body = report.build_json_report(run_id)
    assert body["suppressed_alerts"] == {}
