"""outpost — Typer app entrypoint.

Registers all commands and shows the banner. Per docs/12, the primary banner
appears on no-args / --help / watch / run; read commands use the compact one.
"""

import typer

from .rendering.banners import show_banner
from .rendering.terminal_views import console

app = typer.Typer(
    name="outpost",
    help="OutPost — cross-platform behavioral security monitor",
    no_args_is_help=True,
    add_completion=False,
)


def _register_commands() -> None:
    from .commands.agent import app as agent_app
    from .commands.auth import app as auth_app
    from .commands.campaigns import campaigns
    from .commands.compare import compare
    from .commands.coverage import coverage
    from .commands.export import export
    from .commands.list_runs import list_runs
    from .commands.notes import app as notes_app
    from .commands.refresh import refresh
    from .commands.rules import app as rules_app
    from .commands.run import run
    from .commands.samples import samples
    from .commands.search import search
    from .commands.show import show
    from .commands.watch import watch
    from .commands.intel import app as intel_app
    from .commands.watchlist import app as watchlist_app
    from .commands.yara import app as yara_app
    from .commands.footprint import app as footprint_app

    app.command("list")(list_runs)
    app.command()(show)
    app.command()(export)
    app.command()(run)
    app.command()(watch)
    app.command("search")(search)
    app.command("compare")(compare)
    app.command("campaigns")(campaigns)
    app.command("coverage")(coverage)
    app.add_typer(rules_app, name="rules")
    app.command("samples")(samples)
    app.command("refresh")(refresh)
    app.add_typer(watchlist_app, name="watchlist")
    app.add_typer(intel_app, name="intel")
    app.add_typer(yara_app, name="yara")
    app.add_typer(footprint_app, name="footprint")
    app.add_typer(notes_app, name="notes")
    app.add_typer(agent_app, name="agent")
    app.add_typer(auth_app, name="auth")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    # Per docs/12: banner only when no subcommand ran — each command shows
    # its own banner (primary for watch/run, compact for read commands),
    # so we never print it twice.
    if ctx.invoked_subcommand is None:
        show_banner(primary=True)
        console.print("[dim]Run `outpost --help` to see commands.[/dim]")


_register_commands()


if __name__ == "__main__":
    # The installed `outpost` binary is wired to `outpost.main:app`, but
    # `python -m outpost.main` must also run the CLI — the generated systemd
    # summary unit uses it as ExecStart. Without this the module imported and
    # exited 0 silently, no-op'ing the daily summary.
    app()
