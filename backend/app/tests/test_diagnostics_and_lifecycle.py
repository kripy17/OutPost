"""Tests for internal diagnostics, support bundle, ordered schema migrations,
and investigation dossier import/export roundtrip.
"""

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from ..core.db import (
    ORDERED_MIGRATIONS,
    db_session,
    dry_run_migrations,
    get_schema_version,
    list_migrations,
)
from ..main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_diagnostics_endpoint_contract(client):
    """GET /diagnostics returns structured platform telemetry."""
    resp = client.get("/diagnostics")
    assert resp.status_code == 200
    data = resp.json()

    # Core top-level sections
    for key in ("platform", "ingest", "detection", "stream", "database", "evidence_integrity", "collectors", "background_tasks"):
        assert key in data, f"Missing section: {key}"

    # Ingest details
    assert "events_per_second" in data["ingest"]
    assert "total_events" in data["ingest"]
    assert data["ingest"]["queue_depth"] == 0

    # Database details
    assert data["database"]["engine"] in ("sqlite", "postgresql")
    assert "schema_version" in data["database"]
    assert data["database"]["schema_version"]["current_version"] > 0

    # Evidence integrity
    assert "audit_chain_length" in data["evidence_integrity"]
    assert data["evidence_integrity"]["status"] == "tamper-evident SHA-256 chain verified"


def test_support_bundle_export_contract(client):
    """GET /diagnostics/support-bundle yields valid zip archive with sanitized contents."""
    resp = client.get("/diagnostics/support-bundle")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert "outpost-support-bundle-" in resp.headers.get("content-disposition", "")

    # Inspect zip contents
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    filenames = zf.namelist()
    assert "diagnostics.json" in filenames
    assert "schema_migrations.json" in filenames
    assert "system_env.json" in filenames
    assert "README.txt" in filenames

    # Verify diagnostics.json inside zip is valid JSON
    diag_inside = json.loads(zf.read("diagnostics.json").decode("utf-8"))
    assert "platform" in diag_inside
    assert "database" in diag_inside


def test_ordered_migrations_engine_and_dry_run():
    """Verify ordered schema migrations tracking and dry-run execution."""
    with db_session() as conn:
        # Check current version
        ver_info = get_schema_version(conn)
        assert ver_info["current_version"] == ORDERED_MIGRATIONS[-1][0]
        assert ver_info["total_applied"] == len(ORDERED_MIGRATIONS)

        # Check list migrations
        migrations = list_migrations(conn)
        assert len(migrations) == len(ORDERED_MIGRATIONS)
        assert all(m["status"] == "applied" for m in migrations)
        assert all(m["downgrade_note"] for m in migrations)

        # Dry run against already applied DB reports applied
        dry_results = dry_run_migrations(conn)
        assert len(dry_results) == len(ORDERED_MIGRATIONS)
        assert all(r["status"] == "applied" for r in dry_results)


def test_admin_migrations_api(client):
    """GET /admin/migrations returns schema version, migrations list, and handles ?dry_run=true."""
    resp = client.get("/admin/migrations")
    assert resp.status_code == 200
    data = resp.json()
    assert "schema_version" in data
    assert data["schema_version"]["current_version"] > 0
    assert "migrations" in data
    assert len(data["migrations"]) > 0

    resp_dry = client.get("/admin/migrations?dry_run=true")
    assert resp_dry.status_code == 200
    assert resp_dry.json()["dry_run"] is True


def test_admin_retention_data_classes(client):
    """GET /admin/retention returns per-data-class storage footprint breakdown."""
    resp = client.get("/admin/retention")
    assert resp.status_code == 200
    data = resp.json()
    assert "data_classes" in data
    classes = data["data_classes"]
    assert "raw_events" in classes
    assert "alerts" in classes
    assert "snapshots" in classes
    assert "samples" in classes
    assert "audit" in classes

    # Audit data class must be marked permanent
    assert classes["audit"]["prunable"] is False
    assert "cryptographic" in classes["audit"]["policy"]


def test_investigation_import_and_export_roundtrip(client):
    """Create investigation, export JSON dossier, and import into fresh investigation record."""
    # 1. Create source investigation
    create_resp = client.post(
        "/investigations",
        json={"title": "Ransomware Lateral Movement Case", "tags": ["apt", "lockbit"]},
    )
    assert create_resp.status_code == 201
    source_inv = create_resp.json()
    inv_id = source_inv["id"]

    # 2. Add note and task
    client.post(f"/investigations/{inv_id}/notes", json={"note": "Initial staging detected at 10.0.0.15"})
    client.post(
        f"/investigations/{inv_id}/tasks",
        json={"title": "Isolate DC1", "category": "containment"},
    )

    # 3. Export dossier as JSON
    export_resp = client.get(f"/investigations/{inv_id}/export?format=json")
    assert export_resp.status_code == 200
    dossier = export_resp.json()
    assert dossier["case"]["id"] == inv_id
    assert len(dossier["notes"]) >= 1

    # 4. Import dossier into OutPost
    import_resp = client.post("/investigations/import", json=dossier)
    assert import_resp.status_code == 201
    import_result = import_resp.json()
    assert import_result["status"] == "imported"
    new_inv = import_result["investigation"]
    assert new_inv["title"] == "Ransomware Lateral Movement Case"
    assert "apt" in new_inv["tags"]
    assert import_result["notes_restored"] >= 1
