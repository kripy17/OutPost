"""outpost — Typer app entrypoint.

Registers all commands and shows the banner. Per docs/12, the primary banner
appears on no-args / --help / watch / run; read commands use the compact one.
"""

import typer

app = typer.Typer(
    name="outpost",
    help="OutPost — cross-platform behavioral security monitor",
    no_args_is_help=False,
    add_completion=False,
)


def _register_commands() -> None:
    from .commands.admin import app as admin_app
    from .commands.agent import app as agent_app
    from .commands.alerts import alerts, triage
    from .commands.allowlist import app as allowlist_app
    from .commands.analysis import app as analysis_app
    from .commands.audit import app as audit_app
    from .commands.auth import app as auth_app
    from .commands.campaigns import campaigns
    from .commands.compare import compare
    from .commands.coverage import coverage
    from .commands.decode import app as decode_app, hash_command
    from .commands.export import export
    from .commands.footprint import app as footprint_app
    from .commands.forensics import app as forensics_app
    from .commands.hosts import app as hosts_app
    from .commands.intel import app as intel_app
    from .commands.investigations import app as investigations_app
    from .commands.list_runs import list_runs
    from .commands.notes import app as notes_app
    from .commands.playbooks import app as playbooks_app
    from .commands.refresh import refresh
    from .commands.rules import app as rules_app
    from .commands.run import run
    from .commands.samples import samples
    from .commands.search import search
    from .commands.settings import app as settings_app
    from .commands.show import show
    from .commands.status import app as status_app, doctor
    from .commands.watch import watch
    from .commands.watchlist import app as watchlist_app
    from .commands.yara import app as yara_app

    app.command("list")(list_runs)
    app.command("alerts")(alerts)
    app.command("triage")(triage)
    app.command()(show)
    app.command()(export)
    app.command()(run)
    app.command()(watch)
    app.command("search")(search)
    app.command("compare")(compare)
    app.command("campaigns")(campaigns)
    app.command("coverage")(coverage)
    app.add_typer(rules_app, name="rules")
    app.add_typer(playbooks_app, name="playbooks")
    app.add_typer(playbooks_app, name="playbook")
    app.command("samples")(samples)
    app.command("refresh")(refresh)
    app.add_typer(forensics_app, name="forensics")
    app.add_typer(watchlist_app, name="watchlist")
    app.add_typer(allowlist_app, name="allowlist")
    app.add_typer(intel_app, name="intel")
    app.add_typer(yara_app, name="yara")
    app.add_typer(footprint_app, name="footprint")
    app.add_typer(hosts_app, name="hosts")
    app.add_typer(notes_app, name="notes")
    app.add_typer(investigations_app, name="investigations")
    app.add_typer(analysis_app, name="analysis")
    app.add_typer(agent_app, name="agent")
    app.add_typer(admin_app, name="admin")
    app.add_typer(auth_app, name="auth")
    app.add_typer(settings_app, name="settings")
    app.add_typer(status_app, name="status")
    app.command("doctor")(doctor)
    app.add_typer(audit_app, name="audit")
    app.add_typer(decode_app, name="decode")
    app.command("hash")(hash_command)

    @app.command("version", help="Show OutPost version and platform metadata")
    def version_command() -> None:
        import platform
        from .rendering.banners import show_banner
        from .rendering.terminal_views import console
        show_banner(primary=False)
        console.print(f"[bold white]OutPost[/bold white] v0.1.0 — [bold cyan]{platform.system()} {platform.machine()}[/bold cyan] (Python {platform.python_version()})")

    @app.command("tui", help="Launch the interactive SOC Terminal User Interface")
    @app.command("console", help="Launch the interactive SOC Terminal User Interface")
    def launch_tui() -> None:
        from .tui import OutPostTUI
        OutPostTUI().run()

    @app.command("seed", help="Seed realistic labeled demo telemetry, campaigns, and cases into SQLite")
    def seed_command() -> None:
        from .rendering.banners import show_banner
        from .rendering.terminal_views import console
        from .lib import offline_store
        show_banner(primary=False)
        console.print("[dim]Seeding realistic labeled demo runs, campaign clusters, investigations, and watchlist into SQLite...[/dim]")
        res = offline_store.seed_offline_demo()
        console.print("[#3FA796]✔ Demo telemetry seeded successfully into local SQLite database![/#3FA796]")
        console.print(f"  Demo Run:       [bold]{res.get('demo_run')}[/bold]")
        console.print(f"  Campaign Runs:  [bold]{', '.join(res.get('campaign_runs', []))}[/bold]")
        console.print("  Incident Case:  [bold]INC-2026-001[/bold] (Suspicious C2 Beaconing)")
        console.print("  Watchlist:      [bold]203.0.113.88[/bold], [bold]185.220.101.34[/bold]")
        console.print("[dim]You can now explore these in the SOC TUI (`./outpost.sh`) or via CLI commands.[/dim]")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show OutPost version and exit"),
) -> None:
    if version:
        import platform
        from .rendering.banners import show_banner
        from .rendering.terminal_views import console
        show_banner(primary=False)
        console.print(f"[bold white]OutPost[/bold white] v0.1.0 — [bold cyan]{platform.system()} {platform.machine()}[/bold cyan] (Python {platform.python_version()})")
        raise typer.Exit(0)

    if ctx.invoked_subcommand is None:
        import sys
        if not sys.stdin.isatty():
            from .rendering.banners import show_banner
            from .rendering.terminal_views import console
            show_banner(primary=True)
            console.print("Run [bold cyan]./outpost.sh --help[/bold cyan] for all commands, or run interactively in a terminal for the full-screen SOC TUI.")
            return
        from .tui import OutPostTUI
        OutPostTUI().run()


_register_commands()


if __name__ == "__main__":
    app()

