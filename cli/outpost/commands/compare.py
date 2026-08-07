"""`outpost compare <id1> <id2>` — diff two runs (Task 25, docs/10 #5).

Three-column view: only in A / shared / only in B, for processes and IPs.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console


def compare(
    run_id_a: str = typer.Argument(..., help="First run id"),
    run_id_b: str = typer.Argument(..., help="Second run id"),
) -> None:
    show_banner(primary=False)

    try:
        data = api_client.compare_runs(run_id_a, run_id_b)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Compare failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    ra, rb = data["run_a"], data["run_b"]
    console.print(
        f"Comparing [bold]{ra['sample_name']}[/bold] ({ra['run_id'][:8]}) vs "
        f"[bold]{rb['sample_name']}[/bold] ({rb['run_id'][:8]})"
    )

    for label, key in (("Processes", "processes"), ("IPs", "ips")):
        section = data[key]
        only_a, shared, only_b = section["only_a"], section["shared"], section["only_b"]
        table = Table(title=label, border_style="dim")
        table.add_column(f"Only in A ({ra['run_id'][:6]})")
        table.add_column("Shared")
        table.add_column(f"Only in B ({rb['run_id'][:6]})")
        for i in range(max(len(only_a), len(shared), len(only_b))):
            table.add_row(
                only_a[i] if i < len(only_a) else "",
                shared[i] if i < len(shared) else "",
                only_b[i] if i < len(only_b) else "",
            )
        console.print(table)
