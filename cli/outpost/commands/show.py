"""`outpost show <run_id>` — full report for one session."""

from ..lib import api_client
from ..rendering.terminal_views import render_report


def show(run_id: str) -> None:
    report = api_client.get_run(run_id)
    # Best-effort ATT&CK map — a meta failure must never break the report.
    try:
        rules_meta = api_client.get_rules_meta()
    except api_client.APIError:
        rules_meta = None
    render_report(report, run_id=run_id, rules_meta=rules_meta)
