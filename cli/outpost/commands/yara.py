"""`outpost yara` — the signature lab, terminal-side.

- `outpost yara list` — every persisted custom rule (name, family, strings).
- `outpost yara test --rule <text> | --file <path>` — compile a rule and scan
  it against the sample vault without persisting; shows which samples matched
  and which string atoms hit (the *why*, not just a boolean).

Mirror of the webapp's YARA lab on the Rules page — same endpoints, same
subset language (services/yara.parse_rule_text).
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(
    help="YARA signature lab — list persisted rules, test a rule against the vault",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        console.print(ctx.get_help())


@app.command("list")
def list_rules() -> None:
    """List persisted custom YARA rules."""
    show_banner(primary=False)
    data = api_client.yara_list()
    rules = data.get("rules", [])
    if not rules:
        console.print("[dim]No custom YARA rules yet — author one in the webapp lab or `outpost yara test`.[/dim]")
        return
    table = Table(title=f"{data.get('count', len(rules))} custom YARA rule(s)", box=None)
    table.add_column("Name", style="bold")
    table.add_column("Family", style="dim")
    table.add_column("Strings", style="#D9A441")
    table.add_column("Description", style="dim", overflow="fold", min_width=30)
    for r in rules:
        table.add_row(
            r.get("name") or "?",
            r.get("family") or "-",
            ", ".join(r.get("strings") or []) or "-",
            r.get("description") or "",
        )
    console.print(table)


@app.command("test")
def test_rule(
    rule: str = typer.Option("", "--rule", "-r", help="Rule source text (use --file for anything long)"),
    file: str = typer.Option("", "--file", "-f", help="Read the rule source from a file"),
    sample_ids: list[str] = typer.Option(None, "--sample", help="Restrict to these sample ids (repeatable)"),
) -> None:
    """Compile a rule and scan it against the vault (no persistence)."""
    show_banner(primary=False)
    if file:
        try:
            with open(file, "r", encoding="utf-8") as fh:
                rule = fh.read()
        except OSError as exc:
            console.print(f"[red]cannot read rule file:[/red] {exc}")
            raise typer.Exit(2)
    if not rule.strip():
        console.print("[red]rule source is empty[/red] — pass --rule or --file")
        raise typer.Exit(2)

    data = api_client.yara_test(rule, sample_ids=sample_ids or None)
    if not data.get("compiled"):
        console.print(f"[red]rule failed to compile:[/red] {data.get('error', 'unknown error')}")
        raise typer.Exit(1)

    console.print(
        f"[bold #3FA796]compiled[/bold #3FA796] [dim]rule `{data.get('rule_name', '?')}`[/dim] · "
        f"{data.get('total', 0)} vault sample(s) scanned, [bold]{data.get('matched', 0)}[/bold] matched"
    )
    samples = data.get("samples", [])
    if not samples:
        console.print("[dim]No matches — clean against the vault.[/dim]")
        return
    table = Table(box=None)
    table.add_column("Sample", style="bold")
    table.add_column("Platform", style="dim")
    table.add_column("Matched", style="#D9A441")
    table.add_column("Hits", style="dim")
    for s in samples:
        table.add_row(
            s.get("original_name") or s.get("sample_id") or "?",
            s.get("platform") or "-",
            "yes" if s.get("matched") else "no",
            ", ".join(s.get("hits") or []) or "-",
        )
    console.print(table)


@app.command("scan-memory")
def scan_memory_alias(
    limit: int = typer.Option(50, "--limit", "-l", min=1, max=200, help="Maximum number of active processes to inspect"),
) -> None:
    """Scan active process memory against OutPost YARA engine (alias for 'outpost forensics scan-memory')."""
    from .forensics import scan_memory
    return scan_memory(limit=limit)


@app.command("scan")
def scan_path(
    path: str = typer.Argument(..., help="Local file or directory path to scan"),
    rule: str = typer.Option("", "--rule", "-r", help="Rule source text"),
    file: str = typer.Option("", "--file", "-f", help="Read rule source from a file"),
    recursive: bool = typer.Option(True, "--recursive", "-R", help="Recursively scan directories"),
    max_size_mb: int = typer.Option(25, "--max-size", help="Maximum file size in MB to inspect"),
) -> None:
    """Scan local files or directories against YARA signatures on disk."""
    import hashlib
    import sys
    from pathlib import Path
    from rich.panel import Panel

    show_banner(primary=False)
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[bold #C4453B]Error: Path does not exist: {path}[/bold #C4453B]")
        raise typer.Exit(1)

    # Ensure backend services are importable for pure-python YARA engine
    root = Path(__file__).resolve().parent.parent.parent.parent
    backend_path = str(root / "backend")
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)

    try:
        from app.services import yara as yara_engine
    except Exception as e:
        console.print(f"[bold #C4453B]Failed to initialize YARA engine: {e}[/bold #C4453B]")
        raise typer.Exit(1)

    # Compile rules to scan with
    compiled_rules: list[yara_engine._Rule] = []
    rule_source = rule
    if file:
        try:
            with open(file, "r", encoding="utf-8") as fh:
                rule_source = fh.read()
        except OSError as exc:
            console.print(f"[bold #C4453B]Cannot read rule file:[/bold #C4453B] {exc}")
            raise typer.Exit(2)

    if rule_source.strip():
        parsed = yara_engine.parse_rule_text(rule_source)
        if not parsed:
            console.print("[bold #C4453B]Error: Rule failed to compile or contains syntax errors.[/bold #C4453B]")
            raise typer.Exit(1)
        r_name, r_fam, r_desc, r_strings, _ = parsed
        compiled_rules.append(yara_engine._Rule(r_name, r_fam, r_desc, r_strings))
        rule_desc = f"Custom rule '{r_name}'"
    else:
        # Use default rule catalog
        compiled_rules = list(yara_engine.RULES)
        # Also attempt to load saved custom rules from backend
        try:
            custom_data = api_client.yara_list()
            for cr in custom_data.get("rules", []):
                parsed = yara_engine.parse_rule_text(
                    f"rule {cr['name']} : {cr.get('family', 'custom')} {{ strings: "
                    + " ".join(f'$a = "{s}"' for s in cr.get("strings", []))
                    + " condition: any of them }"
                )
                if parsed:
                    cn, cf, cd, cs, _ = parsed
                    compiled_rules.append(yara_engine._Rule(cn, cf, cd, cs))
        except Exception:
            pass
        rule_desc = f"OutPost YARA catalog ({len(compiled_rules)} rules)"

    console.print(f"[#D9A441]Scanning '[bold]{path}[/bold]' against {rule_desc}...[/#D9A441]")

    max_bytes = max_size_mb * 1024 * 1024
    files_to_scan: list[Path] = []

    if target_path.is_file():
        files_to_scan.append(target_path)
    elif target_path.is_dir():
        walker = target_path.rglob("*") if recursive else target_path.glob("*")
        for p in walker:
            if p.is_file():
                try:
                    if p.stat().st_size <= max_bytes:
                        files_to_scan.append(p)
                except Exception:
                    pass

    total_scanned = 0
    threat_hits: list[dict] = []

    for fpath in files_to_scan:
        try:
            data = fpath.read_bytes()
            total_scanned += 1
            matches = []
            for r in compiled_rules:
                if r.matches(data):
                    matches.append(r.name)
            if matches:
                sha = hashlib.sha256(data).hexdigest()
                threat_hits.append({
                    "path": str(fpath),
                    "size": len(data),
                    "sha256": sha,
                    "matches": matches,
                })
        except Exception:
            continue

    hit_count = len(threat_hits)
    hit_color = "bold red" if hit_count > 0 else "bold green"

    console.print(
        Panel(
            f"[bold]Target:[/bold] [white]{path}[/white]\n"
            f"[dim]Files Scanned:[/dim] [bold]{total_scanned}[/bold]  ·  "
            f"[dim]Rules Applied:[/dim] [bold]{len(compiled_rules)}[/bold]\n"
            f"[dim]Threat Matches:[/dim] [{hit_color}]{hit_count} file(s) matched signature(s)[/{hit_color}]",
            title="[bold #3B82F6]Local Disk YARA Inspection Results[/bold #3B82F6]",
            border_style="red" if hit_count > 0 else "green",
        )
    )

    if threat_hits:
        table = Table(title="Detected YARA Threat Matches", border_style="dim")
        table.add_column("File Path", style="bold")
        table.add_column("Size", justify="right")
        table.add_column("SHA-256", style="dim")
        table.add_column("Matched Signatures", style="bold yellow")

        for th in threat_hits:
            table.add_row(
                th["path"],
                f"{th['size']} B",
                th["sha256"][:16] + "...",
                ", ".join(th["matches"]),
            )
        console.print(table)
    else:
        console.print("[green]✓ All scanned files passed YARA signature verification cleanly.[/green]")

