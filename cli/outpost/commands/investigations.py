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
        console.print(f"[bold #C4453B]Investigations failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    rows = data.get("investigations") or []
    if not rows:
        console.print("[dim]No investigations match — the case queue is empty.[/dim]")
        return
    table = Table(title=f"{data['total']} investigation(s)", border_style="dim")
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
        console.print(f"[bold #C4453B]Reopen failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Reopened {inv['id']} — status {inv.get('status', '-').upper()}[/#3FA796]")
