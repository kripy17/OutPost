"""`outpost list` — table of all past sessions."""

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console, render_run_table


def list_runs() -> None:
    show_banner(primary=False)
    runs = None
    try:
        runs = api_client.list_runs()
    except api_client.APIError as exc:
        from ..lib import offline_store
        runs = offline_store.get_offline_runs()
        if runs is not None:
            console.print("[dim yellow]Notice: Backend offline — showing records directly from local SQLite database (offline mode)[/dim yellow]\n")
        else:
            console.print(f"[bold red]Connection Error:[/bold red] {exc}")
            return

    if not runs:
        console.print("[dim]No sessions yet — start one with `outpost watch` or `outpost run <sample>`.[/dim]")
        return
    console.print(render_run_table(runs))
