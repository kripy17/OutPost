"""`outpost intel import` — pull a threat-intel feed into the watchlist + IOC layer.

Terminal mirror of the webapp's feed import: paste a STIX 2.1 bundle or a
one-IOC-per-line list (or point at a feed URL) and every value lands in the
watchlist labeled `intel:<source>`. The response also reports which existing
runs already touch an imported value, so a fresh feed can be triaged
immediately.
"""

import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Optional

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Threat-intel feed import — watchlist + IOC layer", add_completion=False)


@app.command("import")
def import_feed(
    source: str = typer.Option("auto", "--source", help="stix | text | auto"),
    file: Path = typer.Option(None, "--file", "-f", help="Read the feed from this file instead of --content"),
    content: str = typer.Option("", "--content", "-c", help="Inline feed (STIX bundle JSON or IOC list)"),
    url: str = typer.Option("", "--url", "-u", help="Fetch a STIX feed from this URL"),
) -> None:
    show_banner(primary=False)
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except OSError as exc:
            console.print(f"[bold #C4453B]Cannot read {file}: {exc}[/bold #C4453B]")
            raise typer.Exit(1)
    if not content.strip() and not url:
        console.print("[bold #C4453B]Provide --file/--content or --url[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        result = api_client.intel_import(source, content=content, url=url)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Import failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    console.print(
        f"[#3FA796]{result['imported']} indicator(s) imported[/#3FA796] "
        f"[dim]as {result['source']}[/dim]"
    )
    if result.get("kinds"):
        kinds = ", ".join(f"{k}={v}" for k, v in sorted(result["kinds"].items()))
        console.print(f"[dim]kinds: {kinds}[/dim]")
    if result.get("matched_values"):
        console.print(
            f"[bold #D9A441]{result['matched_values']} value(s) already touch existing runs[/bold #D9A441]"
        )
        table = Table(title="Matching runs", border_style="dim")
        table.add_column("Value")
        table.add_column("Runs")
        for value, runs in result["matched_runs"].items():
            table.add_row(value, ", ".join(runs))
        console.print(table)
    else:
        console.print("[dim]No existing run touches any imported value.[/dim]")


@app.command("hunt")
def hunt_ioc(
    ioc: str = typer.Argument(..., help="IOC indicator ID or raw indicator value (IP, domain, hash)"),
) -> None:
    """Assess fleet-wide compromise for an IOC indicator across all hosts and stored telemetry."""
    from rich.panel import Panel
    show_banner(primary=False)

    try:
        data = api_client.ioc_fleet_hunt(ioc)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Fleet hunt failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    ioc_info = data.get("ioc", {})
    val = ioc_info.get("value") or ioc
    ioc_type = (ioc_info.get("type") or "indicator").upper()
    total_events = data.get("total_events_matched", 0)
    runs_count = data.get("affected_runs_count", 0)
    hosts_count = data.get("affected_hosts_count", 0)

    status_color = "red" if total_events > 0 else "green"
    status_text = f"[bold {status_color}]COMPROMISE DETECTED ({total_events} events across {hosts_count} host(s))[/bold {status_color}]" if total_events > 0 else "[bold green]CLEAN (No compromise detected)[/bold green]"

    console.print(Panel(
        f"Indicator: [bold]{val}[/bold] ({ioc_type})\n"
        f"Verdict: {status_text}\n"
        f"Total Matching Events: [bold]{total_events}[/bold]\n"
        f"Affected Hosts: [bold]{hosts_count}[/bold]  ·  Affected Sessions / Runs: [bold]{runs_count}[/bold]\n"
        f"First Seen: {data.get('first_seen') or 'N/A'}\n"
        f"Last Seen:  {data.get('last_seen') or 'N/A'}",
        title="[bold white]Fleet-Wide Compromise Assessment[/bold white]",
        border_style="#3B82F6",
    ))

    hosts = data.get("affected_hosts", [])
    if hosts:
        ht = Table(title="Compromised Fleet Hosts", border_style="dim")
        ht.add_column("Host ID", style="bold cyan")
        ht.add_column("Events Matched", style="bold red")
        ht.add_column("First Seen", style="dim")
        ht.add_column("Last Seen", style="dim")
        for h in hosts:
            ht.add_row(
                h.get("host_id", "-"),
                str(h.get("event_count", 0)),
                (h.get("first_seen") or "")[:19].replace("T", " "),
                (h.get("last_seen") or "")[:19].replace("T", " "),
            )
        console.print(ht)

    events = data.get("matching_events", [])
    if events:
        et = Table(title="Matching Telemetry Events (first 10)", border_style="dim")
        et.add_column("Timestamp", style="dim")
        et.add_column("Host", style="cyan")
        et.add_column("Type")
        et.add_column("Process", style="bold")
        et.add_column("Target / IP / Path", style="#D9A441")
        for e in events[:10]:
            target = e.get("dest_ip") or e.get("file_path") or e.get("registry_key") or "-"
            et.add_row(
                (e.get("timestamp") or "")[:19].replace("T", " "),
                e.get("host_id") or "local",
                e.get("event_type") or "-",
                e.get("process_name") or "-",
                str(target)[:40],
            )
        console.print(et)


def refang_text(text: str) -> str:
    """Normalize defanged indicators back to standard format."""
    t = re.sub(r"\[:\/\/\]", "://", text, flags=re.IGNORECASE)
    t = re.sub(r"\[:\]\/\/", "://", t, flags=re.IGNORECASE)
    t = re.sub(r"hxxps?:\/\/", lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://", t, flags=re.IGNORECASE)
    t = re.sub(r"hxxps?", lambda m: "https" if m.group(0).lower().startswith("hxxps") else "http", t, flags=re.IGNORECASE)
    t = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", t)
    t = re.sub(r"\[:\]|\{:\}", ":", t)
    t = re.sub(r"\[@\]|\(@\)|\{@\}", "@", t)
    return t


def defang_text(text: str) -> str:
    """Defang text indicators safely for sharing or reporting."""
    t = re.sub(r"https:\/\/", "hxxps://", text, flags=re.IGNORECASE)
    t = re.sub(r"http:\/\/", "hxxp://", t, flags=re.IGNORECASE)
    t = t.replace(".", "[.]").replace("@", "[@]")
    return t


def is_private_ipv4(ip_str: str) -> bool:
    """Check whether an IPv4 address is in RFC1918 private or loopback scope."""
    try:
        parts = [int(p) for p in ip_str.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except Exception:
        return False


def extract_indicators(raw_text: str) -> list[dict]:
    """Parse unstructured text for URLs, IPs, Hashes, Domains, and Emails."""
    if not raw_text.strip():
        return []

    normalized = refang_text(raw_text)
    seen = set()
    indicators: list[dict] = []

    # 1. URLs
    url_pattern = re.compile(r"https?://[^\s\"'<>\)\]\}]+", re.IGNORECASE)
    for match in url_pattern.finditer(normalized):
        u = match.group(0).rstrip(".,;!?")
        if u.lower() not in seen:
            seen.add(u.lower())
            indicators.append({
                "type": "url",
                "raw": u,
                "refanged": u,
                "defanged": defang_text(u),
                "subtype": "url",
                "is_private": False,
            })

    # 2. Emails
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    for match in email_pattern.finditer(normalized):
        e = match.group(0)
        if e.lower() not in seen:
            seen.add(e.lower())
            indicators.append({
                "type": "email",
                "raw": e,
                "refanged": e,
                "defanged": defang_text(e),
                "subtype": "email",
                "is_private": False,
            })

    # 3. Hashes
    # MD5 (32 hex)
    for m in re.finditer(r"\b[a-fA-F0-9]{32}\b", normalized):
        h = m.group(0).lower()
        if h not in seen:
            seen.add(h)
            indicators.append({
                "type": "hash",
                "raw": h,
                "refanged": h,
                "defanged": h,
                "subtype": "md5",
                "is_private": False,
            })

    # SHA1 (40 hex)
    for m in re.finditer(r"\b[a-fA-F0-9]{40}\b", normalized):
        h = m.group(0).lower()
        if h not in seen:
            seen.add(h)
            indicators.append({
                "type": "hash",
                "raw": h,
                "refanged": h,
                "defanged": h,
                "subtype": "sha1",
                "is_private": False,
            })

    # SHA256 (64 hex)
    for m in re.finditer(r"\b[a-fA-F0-9]{64}\b", normalized):
        h = m.group(0).lower()
        if h not in seen:
            seen.add(h)
            indicators.append({
                "type": "hash",
                "raw": h,
                "refanged": h,
                "defanged": h,
                "subtype": "sha256",
                "is_private": False,
            })

    # 4. IPv4
    ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for m in ipv4_pattern.finditer(normalized):
        ip = m.group(0)
        parts = [int(p) for p in ip.split(".")]
        if all(0 <= p <= 255 for p in parts):
            if ip.lower() not in seen:
                seen.add(ip.lower())
                priv = is_private_ipv4(ip)
                indicators.append({
                    "type": "ip",
                    "raw": ip,
                    "refanged": ip,
                    "defanged": defang_text(ip),
                    "subtype": "private_ipv4" if priv else "public_ipv4",
                    "is_private": priv,
                })

    # 5. Domains
    domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
    skip_exts = {".exe", ".dll", ".bin", ".txt", ".json", ".log", ".zip", ".tar", ".gz", ".py", ".ts", ".js", ".sh", ".so", ".md", ".png", ".jpg"}
    for m in domain_pattern.finditer(normalized):
        d = m.group(0).lower()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
            continue
        ext = "." + d.split(".")[-1]
        if ext in skip_exts:
            continue
        if d not in seen and not any(d in seen_val for seen_val in seen if "@" in seen_val):
            seen.add(d)
            indicators.append({
                "type": "domain",
                "raw": d,
                "refanged": d,
                "defanged": defang_text(d),
                "subtype": "domain",
                "is_private": False,
            })

    return indicators


@app.command("extract")
def extract_ioc(
    text: str = typer.Argument("", help="Raw text or incident report snippet containing IOCs"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Read raw report/text from file"),
    defang: bool = typer.Option(False, "--defang", help="Display or output indicators defanged"),
    refang: bool = typer.Option(False, "--refang", help="Display or output indicators refanged"),
    add_to_watchlist: bool = typer.Option(False, "--add-to-watchlist", "-w", help="Import extracted indicators into the OutPost Watchlist"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output extracted indicators as JSON"),
) -> None:
    """Extract, defang/refang, and classify IOCs (IPs, domains, URLs, hashes, emails) from unstructured text."""
    # Normalize typer defaults when invoked directly in Python
    if hasattr(file, "default"):
        file = file.default
    if hasattr(defang, "default"):
        defang = bool(defang.default)
    if hasattr(refang, "default"):
        refang = bool(refang.default)
    if hasattr(add_to_watchlist, "default"):
        add_to_watchlist = bool(add_to_watchlist.default)
    if hasattr(json_output, "default"):
        json_output = bool(json_output.default)
    if hasattr(text, "default"):
        text = str(text.default or "")

    content = ""
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except OSError as exc:
            console.print(f"[bold #C4453B]Cannot read {file}: {exc}[/bold #C4453B]")
            raise typer.Exit(1)
    elif text:
        content = text
    else:
        try:
            if sys.stdin is not None and not sys.stdin.isatty():
                content = sys.stdin.read()
        except (OSError, ValueError):
            content = ""

    if not content.strip():
        console.print("[bold #C4453B]Provide text, --file, or piped input via stdin[/bold #C4453B]")
        raise typer.Exit(1)

    indicators = extract_indicators(content)

    if json_output:
        output_data = []
        for ind in indicators:
            val = ind["defanged"] if defang else (ind["refanged"] if refang else ind["raw"])
            item = dict(ind)
            item["output_value"] = val
            output_data.append(item)
        console.print(json.dumps(output_data, indent=2))
        return

    show_banner(primary=False)

    if not indicators:
        console.print("[dim]No indicators detected in provided text.[/dim]")
        return

    table = Table(title=f"Extracted Indicators ({len(indicators)} total)", border_style="dim")
    table.add_column("Type", style="bold cyan", no_wrap=True)
    table.add_column("Indicator Value", style="bold white")
    table.add_column("Classification / Scope", style="dim")

    for ind in indicators:
        val = ind["defanged"] if defang else ind["refanged"]
        t_label = ind["type"].upper()
        if ind["type"] == "hash":
            t_label = f"HASH:{ind['subtype'].upper()}"
        elif ind["type"] == "ip":
            t_label = "IP:RFC1918" if ind["is_private"] else "IP:PUBLIC"

        if ind["type"] == "ip":
            scope = "[yellow]RFC1918 Private[/yellow]" if ind["is_private"] else "[green]Public Routable[/green]"
        elif ind["type"] == "url":
            scope = "HTTP(S) Endpoint"
        elif ind["type"] == "hash":
            scope = f"{ind['subtype'].upper()} Cryptographic Hash"
        elif ind["type"] == "email":
            scope = "RFC5322 Mailbox"
        else:
            scope = "FQDN Domain"
        table.add_row(t_label, val, scope)

    console.print(table)

    counts: dict[str, int] = {}
    for ind in indicators:
        counts[ind["type"]] = counts.get(ind["type"], 0) + 1
    counts_str = ", ".join(f"{k.upper()}={v}" for k, v in sorted(counts.items()))
    console.print(f"[dim]Breakdown: {counts_str}[/dim]\n")

    if add_to_watchlist:
        entries = [{"value": ind["refanged"], "label": f"extracted:{ind['type']}"} for ind in indicators]
        try:
            res = api_client.watchlist_import(entries)
            imported_cnt = res.get("imported", len(entries))
            console.print(f"[bold #3FA796]✔ Successfully imported {imported_cnt} indicator(s) into OutPost Watchlist[/bold #3FA796]")
        except api_client.APIError as exc:
            console.print(f"[bold #C4453B]Watchlist import failed: {exc}[/bold #C4453B]")
            raise typer.Exit(1)


