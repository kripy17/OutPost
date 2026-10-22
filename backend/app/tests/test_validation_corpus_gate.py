"""Test suite and regression gate for the local security validation corpus."""

from app.services import validation_corpus


def test_validation_corpus_regression_gate():
    """Verify that OutPost achieves 0% false positives on benign samples and >= 95% detection rate."""
    report = validation_corpus.evaluate_validation_corpus()

    assert report["total_samples"] >= 10
    metrics = report["metrics"]

    # Gate 1: Zero False Positives on legitimate administration tools and clean documents
    assert metrics["false_positives"] == 0, f"False positive regression: {metrics['false_positives']} benign files misidentified"
    assert metrics["false_positive_rate"] == 0.0

    # Gate 2: True positive detection rate must meet or exceed 95%
    assert metrics["detection_rate"] >= 0.95, f"Detection rate regression: {metrics['detection_rate']} < 0.95"

    # Gate 3: Zero parser crashes
    assert metrics["parser_crashes"] == 0, f"Parser crashed on {metrics['parser_crashes']} samples"

    # Gate 4: Master regression gate passes
    assert report["regression_gate"]["passed"] is True


def test_corpus_api_report_endpoint(client):
    """Verify the /corpus/report API endpoint returns valid metrics."""
    resp = client.get("/corpus/report")
    assert resp.status_code == 200
    data = resp.json()

    assert "metrics" in data
    assert data["metrics"]["false_positive_rate"] == 0.0
    assert data["metrics"]["detection_rate"] >= 0.95
    assert len(data["sample_results"]) >= 10


def test_stock_os_files_validation_gate():
    """Verify that OutPost evaluates at least 50 real OS system files with zero malicious false positives."""
    res = validation_corpus.evaluate_stock_os_files()
    assert res["total_files"] >= 50
    assert res["malicious_count"] == 0, f"Stock OS files flagged as malicious: {res['malicious_files']}"
    assert res["false_positive_rate"] == 0.0
    for file_res in res["files"]:
        assert "provenance" in file_res
        assert "sha256" in file_res["provenance"]
        assert "path" in file_res["provenance"]
        assert "format" in file_res
        assert file_res["verdict"] != "malicious"

