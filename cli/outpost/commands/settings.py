"""`outpost settings` — console preferences, the terminal mirror of the
webapp's Settings page. `clear-prefs` is the one-click wipe of the saved
queue/archive preference keys (per-status-tab provenance split + the archive's
show-synthetic fallback), restoring the fresh-install defaults: every queue
tab shows all provenance and the archive reads real-telemetry-first.
"""

from __future__ import annotations

import typer

from ..lib import prefs
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Console preferences — read the saved queue/archive split and wipe it in one command.")

_TAB_LABELS = {
    "queue_provenance_open": "Open",
    "queue_provenance_acknowledged": "Acknowledged",
    "queue_provenance_resolved": "Resolved",
    "queue_provenance_all": "All",
}
_VALUE_LABELS = {"real": "real hosts", "synthetic": "synthetic"}


@app.command("clear-prefs")
def clear_prefs() -> None:
    """Wipe every saved queue/archive preference — the terminal twin of the
    Settings page's one-click clear."""
    show_banner(primary=False)

    cleared = prefs.clear_prefs()
    if not cleared:
        console.print("[dim]No saved preferences — nothing to clear.[/dim]")
        return

    console.print("[bold #D9A441]Cleared preferences:[/bold #D9A441]")
    for key, value in cleared.items():
        label = _TAB_LABELS.get(key, "Archive")
        shown = _VALUE_LABELS.get(value, value)
        console.print(f"  · {label}: {shown}")
    console.print(
        "[dim]Defaults restored — every queue tab shows all provenance; the archive reads real telemetry first.[/dim]"
    )
