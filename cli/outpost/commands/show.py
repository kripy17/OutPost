"""`outpost show <run_id>` — full report for one session."""

from ..lib import api_client
from ..rendering.terminal_views import console, render_report


def show(run_id: str) -> None:
    try:
        report = api_client.get_run(run_id)
    except api_client.APIError as exc:
        if "Backend unreachable" in str(exc):
            from ..lib import offline_store
            report = offline_store.get_offline_run_detail(run_id)
            if not report:
                console.print(f"[bold #C4453B]Run {run_id} not found in database or API.[/bold #C4453B]")
                return
        else:
            console.print(f"[bold #C4453B]Run {run_id} failed: {exc}[/bold #C4453B]")
            return

    # Best-effort ATT&CK map — a meta failure must never break the report.
    try:
        rules_meta = api_client.get_rules_meta()
    except api_client.APIError:
        from ..lib import offline_store
        rules_meta = offline_store.get_offline_rules()
    render_report(report, run_id=run_id, rules_meta=rules_meta)
