"""`outpost investigations` — the case workspace, terminal mirror of the
webapp's P1.1 investigation surfaces.

P0.3 investigation API parity: list / show / create / patch, evidence refs
(add/remove), analyst notes, close-with-conclusion / reopen, and finding
attach/detach. Attach/detach carries the finding's CURRENT status so the
link change never moves triage state (the same contract the webapp's
setAlertInvestigation enforces). Severity is derived by the backend — the
terminal renders it, never recomputes it.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Investigations (P0.3): the optional cross-workflow case overlay.")

_VALID_STATUS = ("created", "triage", "active", "contained", "resolved", "closed")
_VALID_REF_TYPES = ("artifact", "run", "host", "ioc", "campaign")
_SEV_STYLE = {"malicious": "bold #C4453B", "suspicious": "bold #D9A441"}


@app.command("list")
def investigations_list(
    status: str = typer.Option(None, "--status", "-s", help="created | triage | active | contained | resolved | closed"),
    q: str = typer.Option(None, "--q", help="search title / tags / notes"),
    limit: int = typer.Option(50, "--limit", "-l", min=1, max=200),
    offset: int = typer.Option(0, "--offset"),
) -> None:
    """List investigations (GET /investigations) — status filter + free text."""
    show_banner(primary=False)
    if status is not None and status not in _VALID_STATUS:
        console.print(f"[bold #C4453B]--status must be one of: {', '.join(_VALID_STATUS)}[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        data = api_client.list_investigations(status=status, q=q, limit=limit, offset=offset)
    except api_client.APIError as exc:
        if "Backend unreachable" in str(exc):
            from ..lib import offline_store
            data = offline_store.get_offline_investigations(status=status, q=q, limit=limit, offset=offset)
            if data is not None:
                console.print("[dim yellow]Notice: Backend offline — showing investigations directly from local SQLite database (offline mode)[/dim yellow]\n")
        else:
            data = None
        if data is None:
            console.print(f"[bold #C4453B]Investigations failed: {exc}[/bold #C4453B]")
            raise typer.Exit(1)

    rows = data.get("investigations") or []
    if not rows:
        console.print("[dim]No investigations match — the case queue is empty.[/dim]")
        return
    table = Table(title=f"{data.get('total', len(rows))} investigation(s)", border_style="dim")
    table.add_column("ID")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Findings")
    table.add_column("Refs")
    table.add_column("Tags")
    for inv in rows:
        sev = inv.get("severity")
        sev_cell = f"[{_SEV_STYLE[sev]}]{sev}[/]" if sev and sev in _SEV_STYLE else (sev or "-")
        table.add_row(
            inv["id"],
            (inv.get("status") or "-").upper(),
            sev_cell,
            (inv.get("title") or "-")[:60],
            str(inv.get("finding_count") or 0),
            str(inv.get("ref_count") or 0),
            ",".join(inv.get("tags") or [])[:40] or "-",
        )
    console.print(table)


@app.command("show")
def investigations_show(
    investigation_id: str = typer.Argument(..., help="investigation id"),
) -> None:
    """Show one investigation workspace (GET /investigations/{id}) — the
    header, attached findings, evidence refs, and analyst notes."""
    show_banner(primary=False)
    try:
        inv = api_client.get_investigation(investigation_id)
    except api_client.APIError as exc:
        if "Backend unreachable" in str(exc):
            from ..lib import offline_store
            inv = offline_store.get_offline_investigation(investigation_id)
        else:
            inv = None
        if not inv:
            console.print(f"[bold #C4453B]Investigation failed: {exc}[/bold #C4453B]")
            raise typer.Exit(1)

    sev = inv.get("severity")
    sev_cell = f"[{_SEV_STYLE[sev]}]{sev}[/]" if sev and sev in _SEV_STYLE else (sev or "none (no findings attached)")
    console.print(
        f"[bold]{inv['title']}[/bold]  ({inv['id']})\n"
        f"  status [bold]{inv.get('status', '-').upper()}[/bold] · severity {sev_cell} · "
        f"{inv.get('finding_count', 0)} findings · {inv.get('ref_count', 0)} refs"
    )
    if inv.get("tags"):
        console.print(f"  tags: {', '.join(inv['tags'])}")
    if inv.get("conclusion"):
        console.print(f"  conclusion: {inv['conclusion']}")
    if inv.get("closed_at"):
        console.print(f"  closed {inv['closed_at']}")
    console.print(f"  created {inv.get('created_at')} by {inv.get('created_by') or 'local'}")

    findings = inv.get("findings") or []
    if findings:
        ft = Table(title=f"{len(findings)} attached finding(s)", border_style="dim")
        ft.add_column("ID")
        ft.add_column("Severity")
        ft.add_column("Rule")
        ft.add_column("Status")
        ft.add_column("Detail")
        for a in findings:
            fsev = a.get("severity") or "suspicious"
            style = _SEV_STYLE.get(fsev, "")
            ft.add_row(
                str(a["id"]),
                f"[{style}]{fsev}[/]" if style else fsev,
                a.get("rule_id") or "-",
                (a.get("status") or "-").upper(),
                (a.get("details") or "-")[:70],
            )
        console.print(ft)
    else:
        console.print("[dim]No findings attached — an investigation is optional evidence overlay.[/dim]")

    refs = inv.get("refs") or []
    if refs:
        rt = Table(title=f"{len(refs)} evidence ref(s)", border_style="dim")
        rt.add_column("Type")
        rt.add_column("Ref id")
        rt.add_column("Added")
        for r in refs:
            rt.add_row(r.get("ref_type") or "-", r.get("ref_id") or "-", (r.get("added_at") or "-")[:19])
        console.print(rt)
    else:
        console.print("[dim]No evidence refs yet.[/dim]")

    notes = inv.get("notes") or []
    if notes:
        console.print(f"[bold]{len(notes)} note(s)[/bold]")
        for n in notes:
            console.print(f"  [{n.get('actor') or '-'}] {n.get('note')}  [dim]({(n.get('created_at') or '-')[:19]})[/dim]")
    else:
        console.print("[dim]No notes yet.[/dim]")


@app.command("create")
def investigations_create(
    title: str = typer.Argument(..., help="investigation title (required, non-blank)"),
    tags: str = typer.Option("", "--tags", help="comma-separated tags"),
) -> None:
    """Create an investigation (POST /investigations) — initial status is
    created, severity NULL until findings attach."""
    show_banner(primary=False)
    title = title.strip()
    if not title:
        console.print("[bold #C4453B]title must not be blank[/bold #C4453B]")
        raise typer.Exit(1)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    try:
        inv = api_client.create_investigation(title, tag_list)
    except api_client.APIError as exc:
        if "Backend unreachable" in str(exc):
            from ..lib import offline_store
            inv = offline_store.create_offline_investigation(title)
            if inv:
                console.print(f"[#3FA796]Created investigation {inv['id']} — {inv['title']} [dim](offline SQLite)[/dim][/#3FA796]")
                return
        console.print(f"[bold #C4453B]Create failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Created investigation {inv['id']} — {inv['title']}[/#3FA796]")



@app.command("patch")
def investigations_patch(
    investigation_id: str = typer.Argument(..., help="investigation id"),
    title: str = typer.Option(None, "--title", help="new title"),
    status: str = typer.Option(None, "--status", "-s", help="forward-only status transition"),
    conclusion: str = typer.Option(None, "--conclusion", help="set/clear the conclusion"),
    tags: str = typer.Option(None, "--tags", help="replace tags (comma-separated)"),
) -> None:
    """Update an investigation (PATCH /investigations/{id}) — forward-only
    status transitions; close/reopen are their own routes."""
    show_banner(primary=False)
    if status is not None and status not in _VALID_STATUS:
        console.print(f"[bold #C4453B]--status must be one of: {', '.join(_VALID_STATUS)}[/bold #C4453B]")
        raise typer.Exit(1)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags is not None else None
    try:
        inv = api_client.patch_investigation(
            investigation_id, title=title, status=status, conclusion=conclusion, tags=tag_list
        )
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Patch failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(
        f"[#3FA796]Updated {inv['id']} — {inv['title']} · status {inv.get('status', '-').upper()}[/#3FA796]"
    )


@app.command("attach")
def investigations_attach(
    alert_id: int = typer.Argument(..., help="finding id (alerts.id)"),
    investigation_id: str = typer.Argument(..., help="investigation id"),
    current_status: str = typer.Option("open", "--current-status", help="the finding's CURRENT status (open | acknowledged | resolved) — never moves triage state"),
) -> None:
    """Attach a finding to an investigation (PATCH /alerts/{id} with
    investigation_id). Pass the finding's current status so the link change
    never moves triage state."""
    show_banner(primary=False)
    try:
        api_client.set_alert_investigation(alert_id, investigation_id, current_status)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Attach failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Finding {alert_id} → investigation {investigation_id}[/#3FA796]")


@app.command("detach")
def investigations_detach(
    alert_id: int = typer.Argument(..., help="finding id (alerts.id)"),
    current_status: str = typer.Option("open", "--current-status", help="the finding's CURRENT status — never moves triage state"),
) -> None:
    """Detach a finding from its investigation (PATCH /alerts/{id} with
    investigation_id null)."""
    show_banner(primary=False)
    try:
        api_client.set_alert_investigation(alert_id, None, current_status)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Detach failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Finding {alert_id} ← (no investigation)[/#3FA796]")


@app.command("refs-add")
def investigations_refs_add(
    investigation_id: str = typer.Argument(..., help="investigation id"),
    ref_type: str = typer.Argument(..., help="artifact | run | host | ioc | campaign"),
    ref_id: str = typer.Argument(..., help="the referenced object's id"),
) -> None:
    """Attach an evidence ref (POST /investigations/{id}/refs) — a pointer,
    never a copy. Idempotent on duplicates."""
    show_banner(primary=False)
    if ref_type not in _VALID_REF_TYPES:
        console.print(f"[bold #C4453B]--ref-type must be one of: {', '.join(_VALID_REF_TYPES)}[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        ref = api_client.add_investigation_ref(investigation_id, ref_type, ref_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Add ref failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Ref added: {ref['ref_type']} {ref['ref_id']} on {ref['investigation_id']}[/#3FA796]")


@app.command("refs-remove")
def investigations_refs_remove(
    investigation_id: str = typer.Argument(..., help="investigation id"),
    ref_id: str = typer.Argument(..., help="the referenced object's id"),
) -> None:
    """Remove every ref of this investigation pointing at ref_id."""
    show_banner(primary=False)
    try:
        api_client.remove_investigation_ref(investigation_id, ref_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Remove ref failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Removed ref {ref_id} from {investigation_id}[/#3FA796]")


@app.command("note")
def investigations_note(
    investigation_id: str = typer.Argument(..., help="investigation id"),
    note: str = typer.Argument(..., help="the analyst note (non-blank)"),
) -> None:
    """Add an analyst note (POST /investigations/{id}/notes)."""
    show_banner(primary=False)
    note = note.strip()
    if not note:
        console.print("[bold #C4453B]note must not be blank[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        saved = api_client.add_investigation_note(investigation_id, note)
    except api_client.APIError as exc:
        if "Backend unreachable" in str(exc):
            from ..lib import offline_store
            saved = offline_store.add_offline_investigation_note(investigation_id, note)
            if saved:
                console.print(f"[#3FA796]Note added to {investigation_id} [dim](offline SQLite)[/dim][/#3FA796]")
                return
        console.print(f"[bold #C4453B]Add note failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Note #{saved['id']} added to {investigation_id}[/#3FA796]")


@app.command("close")
def investigations_close(
    investigation_id: str = typer.Argument(..., help="investigation id"),
    conclusion: str = typer.Argument(..., help="required conclusion — the backend rejects blank ones"),
) -> None:
    """Close an investigation (POST /investigations/{id}/close) — closing
    requires a conclusion; nothing is inferred."""
    show_banner(primary=False)
    conclusion = conclusion.strip()
    if not conclusion:
        console.print("[bold #C4453B]conclusion is required to close an investigation[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        inv = api_client.close_investigation(investigation_id, conclusion)
    except api_client.APIError as exc:
        if "Backend unreachable" in str(exc):
            from ..lib import offline_store
            inv = offline_store.update_offline_investigation_status(investigation_id, "closed")
            if inv:
                console.print(f"[#3FA796]Closed {inv['id']} [dim](offline SQLite)[/dim][/#3FA796]")
                return
        console.print(f"[bold #C4453B]Close failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Closed {inv['id']} — {inv['title']}[/#3FA796]")


@app.command("reopen")
def investigations_reopen(
    investigation_id: str = typer.Argument(..., help="investigation id"),
) -> None:
    """Reopen a closed investigation (POST /investigations/{id}/reopen) —
    returns to the active lifecycle state and clears closed_at."""
    show_banner(primary=False)
    try:
        inv = api_client.reopen_investigation(investigation_id)
    except api_client.APIError as exc:
        if "Backend unreachable" in str(exc):
            from ..lib import offline_store
            inv = offline_store.update_offline_investigation_status(investigation_id, "active")
            if inv:
                console.print(f"[#3FA796]Reopened {inv['id']} — status ACTIVE [dim](offline SQLite)[/dim][/#3FA796]")
                return
        console.print(f"[bold #C4453B]Reopen failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Reopened {inv['id']} — status {inv.get('status', '-').upper()}[/#3FA796]")



@app.command("synthesize")
def investigations_synthesize(
    investigation_id: str = typer.Argument(..., help="investigation id to synthesize"),
) -> None:
    """Synthesize an executive incident narrative, causality stages, and actionable remediation checklist."""
    show_banner(primary=False)
    try:
        data = api_client.synthesize_investigation(investigation_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Synthesis failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    title = data.get("title") or investigation_id
    status = data.get("status", "active").upper()
    sev = data.get("max_severity", "unknown").upper()
    console.print(f"[bold #3B82F6]Executive Incident Narrative[/bold #3B82F6] — [dim]{title} ({investigation_id})[/dim]")
    console.print(f"  [bold]Status:[/bold] {status} · [bold]Max Severity:[/bold] [bold red]{sev}[/bold red]\n")

    console.print("[bold white]Executive Summary:[/bold white]")
    console.print(f"  {data.get('executive_summary')}\n")

    tactics = data.get("tactics_involved", [])
    if tactics:
        console.print(f"  [bold]ATT&CK Phases:[/bold] {', '.join(tactics)}\n")

    timeline = data.get("causality_timeline", [])
    if timeline:
        t = Table(title="Attack Causality Sequence", border_style="dim")
        t.add_column("Step", style="dim")
        t.add_column("Rule / Heuristic", style="bold cyan")
        t.add_column("Severity")
        t.add_column("Details", style="dim")
        for c in timeline:
            t.add_row(
                f"#{c.get('step')}",
                c.get("rule", "-"),
                c.get("severity", "-"),
                (c.get("details") or "-")[:70],
            )
        console.print(t)

    checklist = data.get("remediation_checklist", [])
    if checklist:
        console.print("\n[bold green]Prescribed Remediation Checklist:[/bold green]")
        for item in checklist:
            console.print(f"  [ ] {item}")


@app.command("playbooks")
def investigations_playbooks() -> None:
    """List available Incident Response Playbooks for active cases."""
    show_banner(primary=False)
    try:
        playbooks = api_client.list_investigation_playbooks()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed to list playbooks: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    table = Table(title=f"Incident Response Playbooks ({len(playbooks)})", border_style="dim")
    table.add_column("Playbook ID", style="bold cyan")
    table.add_column("Playbook Name", style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Tactic", style="magenta")
    table.add_column("Tasks", justify="right")
    table.add_column("Recommended Probes", style="dim")

    for pb in playbooks:
        sev = pb.get("severity", "medium")
        sev_color = "red" if sev == "critical" else ("yellow" if sev == "high" else "cyan")
        table.add_row(
            pb["id"],
            pb["name"],
            f"[{sev_color}]{sev.upper()}[/{sev_color}]",
            pb.get("tactic", "-"),
            str(len(pb.get("tasks", []))),
            ", ".join(pb.get("recommended_probes", [])),
        )
    console.print(table)
    console.print("\n[dim]Execute automated SOAR playbook with:[/dim] [bold cyan]outpost investigations execute-playbook <inv_id> <playbook_id> [--contain][/bold cyan]")


@app.command("execute-playbook")
def investigations_execute_playbook(
    investigation_id: str = typer.Argument(..., help="Target investigation ID"),
    playbook_id: str = typer.Argument(..., help="Playbook ID to execute (e.g. ransomware_containment)"),
    contain: bool = typer.Option(False, "--contain", "-c", help="Automatically network-isolate target host"),
    no_probes: bool = typer.Option(False, "--no-probes", help="Skip running forensic hunt probes"),
    host: str = typer.Option("local", "--host", "-h", help="Target host identifier"),
) -> None:
    """Execute automated incident response playbook containment and triage actions."""
    from rich.panel import Panel
    show_banner(primary=False)
    console.print(f"[#D9A441]Executing SOAR Playbook '[bold]{playbook_id}[/bold]' on investigation '[bold]{investigation_id}[/bold]'...[/#D9A441]")

    try:
        res = api_client.execute_investigation_playbook(
            investigation_id=investigation_id,
            playbook_id=playbook_id,
            auto_contain=contain,
            run_probes=not no_probes,
            target_host=host,
        )
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Playbook execution failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    contained = res.get("contained", False)
    anomalies = res.get("total_anomalies_detected", 0)

    console.print(
        Panel(
            f"[bold]{res.get('playbook_name')}[/bold]\n"
            f"[dim]Investigation:[/dim] [cyan]{investigation_id}[/cyan]  ·  "
            f"[dim]Target Host:[/dim] [white]{host}[/white]\n"
            f"[dim]Containment Status:[/dim] [{'bold red]NETWORK ISOLATED (QUARANTINED)' if contained else 'dim green]Uncontained (No isolation requested)'}[/]\n"
            f"[dim]Tasks Instantiated:[/dim] [bold]{res.get('tasks_instantiated', 0)}[/bold]  ·  "
            f"[dim]Probes Executed:[/dim] [bold]{res.get('probes_executed_count', 0)}[/bold]  ·  "
            f"[dim]Anomalies Flagged:[/dim] [{'bold red' if anomalies > 0 else 'green'}]{anomalies}[/]",
            title="[bold green]✓ SOAR Playbook Execution Complete[/bold green]",
            border_style="red" if contained else "green",
        )
    )

    actions = res.get("actions_taken", [])
    if actions:
        console.print("\n[bold yellow]Actions Executed & Audited:[/bold yellow]")
        for a in actions:
            console.print(f"  • {a}")


@app.command("export")
def investigations_export(
    investigation_id: str = typer.Argument(..., help="Investigation ID to export"),
    format: str = typer.Option("markdown", "--format", "-f", help="Export format: markdown | json"),
    output: str | None = typer.Option(None, "--output", "-o", help="Optional output file path to write the export to"),
) -> None:
    """Export an investigation case dossier as structured Markdown brief or JSON (GET /investigations/{id}/export)."""
    show_banner(primary=False)
    fmt = format.lower().strip()
    if fmt not in ("markdown", "json"):
        console.print("[bold #C4453B]--format must be 'markdown' or 'json'[/bold #C4453B]")
        raise typer.Exit(1)

    try:
        content_bytes = api_client.export_investigation(investigation_id, format=fmt)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Investigation export failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    text = content_bytes.decode("utf-8", errors="replace")

    if output:
        try:
            with open(output, "w", encoding="utf-8") as f:
                f.write(text)
            console.print(f"[bold green]✓ Investigation dossier saved to {output}[/bold green]")
        except OSError as err:
            console.print(f"[bold #C4453B]Failed to write file {output}: {err}[/bold #C4453B]")
            raise typer.Exit(1)
    else:
        if fmt == "json":
            import json
            from rich.syntax import Syntax
            try:
                parsed = json.loads(text)
                pretty_json = json.dumps(parsed, indent=2)
                console.print(Syntax(pretty_json, "json", theme="monokai", word_wrap=True))
            except Exception:
                console.print(text)
        else:
            from rich.markdown import Markdown
            console.print(Markdown(text))

