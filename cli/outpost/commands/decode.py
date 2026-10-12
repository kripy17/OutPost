"""`outpost decode` and `outpost hash` — Forensic payload decoder & hash analyzer.

Multi-stage forensic payload deobfuscation and analysis in the terminal:
- Base64 (UTF-8 & Windows UTF-16LE / PowerShell)
- Hex / shellcode representations (\\x41\\x42, 0x41, or raw hex)
- URL percent-encoding
- Defang / Refang IOCs
- Automated IOC extraction from decoded payloads
- File & string cryptographic hashing (MD5, SHA1, SHA256)
"""

import base64
import hashlib
import json
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Forensic payload deobfuscator and hash calculator", add_completion=False)


def _decode_b64_utf8(val: str) -> Optional[str]:
    cleaned = re.sub(r"\s+", "", val.strip())
    pad = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    try:
        raw = base64.b64decode(pad, validate=True)
        text = raw.decode("utf-8")
        if not re.search(r"[\x00-\x08\x0E-\x1F]", text):
            return text
        return None
    except Exception:
        return None


def _decode_b64_utf16le(val: str) -> Optional[str]:
    cleaned = re.sub(r"\s+", "", val.strip())
    pad = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    try:
        raw = base64.b64decode(pad, validate=True)
        if len(raw) >= 2 and len(raw) % 2 == 0:
            text = raw.decode("utf-16le")
            if text and not re.search(r"[\x00-\x08\x0E-\x1F]", text):
                return text
        return None
    except Exception:
        return None


def _decode_hex(val: str) -> Optional[str]:
    cleaned = val.strip()
    if "\\x" in cleaned or "\\X" in cleaned:
        h = re.sub(r"\\x", "", cleaned, flags=re.IGNORECASE)
        h = re.sub(r"\s+", "", h)
    elif "0x" in cleaned or "0X" in cleaned:
        h = re.sub(r"0x", "", cleaned, flags=re.IGNORECASE)
        h = re.sub(r"[\s,]+", "", h)
    elif re.match(r"^[0-9a-fA-F\s]+$", cleaned) and len(re.sub(r"\s+", "", cleaned)) >= 4:
        h = re.sub(r"\s+", "", cleaned)
    else:
        return None

    if len(h) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(h)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_url(val: str) -> Optional[str]:
    cleaned = val.strip()
    if "%" not in cleaned:
        return None
    try:
        decoded = urllib.parse.unquote(cleaned)
        return decoded if decoded != cleaned else None
    except Exception:
        return None


def _decode_jwt(val: str) -> Optional[tuple[str, str, str]]:
    cleaned = val.strip()
    parts = cleaned.split(".")
    if len(parts) != 3:
        return None
    if not all(re.match(r"^[A-Za-z0-9_-]+$", p) for p in parts if p):
        return None

    def _b64url_decode(s: str) -> Optional[str]:
        pad = s + "=" * ((4 - len(s) % 4) % 4)
        pad = pad.replace("-", "+").replace("_", "/")
        try:
            return base64.b64decode(pad).decode("utf-8")
        except Exception:
            return None

    try:
        hdr_raw = _b64url_decode(parts[0])
        payload_raw = _b64url_decode(parts[1])
        if not hdr_raw or not payload_raw:
            return None
        hdr = json.loads(hdr_raw)
        payload = json.loads(payload_raw)

        lines = [
            "[bold white]JWT Header:[/bold white] " + json.dumps(hdr, indent=2),
            "[bold white]JWT Payload / Claims:[/bold white] " + json.dumps(payload, indent=2),
        ]
        if "exp" in payload and isinstance(payload["exp"], (int, float)):
            exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat()
            now_ts = datetime.now(timezone.utc).timestamp()
            status = "EXPIRED" if now_ts > payload["exp"] else "VALID"
            lines.append(f"[bold cyan]Expiration:[/bold cyan] {exp_dt} ({status})")
        if "sub" in payload:
            lines.append(f"[bold cyan]Subject:[/bold cyan] {payload['sub']}")

        return ("JSON Web Token (JWT Claims)", "\n\n".join(lines), "Decoded RFC 7519 JWT header and claims payload")
    except Exception:
        return None


def _decode_rot13(val: str) -> Optional[tuple[str, str, str]]:
    cleaned = val.strip()
    if len(cleaned) < 4 or not re.search(r"[a-zA-Z]", cleaned):
        return None
    import codecs
    decoded = codecs.decode(cleaned, "rot_13")
    if decoded != cleaned and re.search(r"powershell|cmd|http|/bin/|curl|wget|select|exec", decoded, re.IGNORECASE):
        return ("ROT13 Deobfuscated", decoded, "Caesar cipher rotation by 13 positions")
    return None


def _scan_single_byte_xor(val: str) -> Optional[tuple[str, str, str]]:
    cleaned = val.strip()
    raw_bytes = None
    if re.match(r"^(\\x[0-9a-fA-F]{2})+$", cleaned, re.IGNORECASE):
        h = re.sub(r"\\x", "", cleaned, flags=re.IGNORECASE)
        raw_bytes = bytes.fromhex(h)
    elif re.match(r"^[0-9a-fA-F]{8,}$", cleaned) and len(cleaned) % 2 == 0:
        raw_bytes = bytes.fromhex(cleaned)
    elif 8 <= len(cleaned) <= 512:
        raw_bytes = cleaned.encode("latin-1", errors="ignore")

    if not raw_bytes or len(raw_bytes) < 4:
        return None

    sigs = [b"http://", b"https://", b"powershell", b"cmd.exe", b"/bin/sh", b"/bin/bash", b"whoami", b"curl ", b"wget "]
    for key in range(1, 256):
        xored = bytes(b ^ key for b in raw_bytes)
        x_lower = xored.lower()
        if any(sig in x_lower for sig in sigs):
            try:
                text = xored.decode("utf-8", errors="replace")
                key_hex = f"0x{key:02X}"
                return (f"XOR Decrypted (Key: {key_hex})", text, f"Payload deobfuscated via single-byte XOR key {key_hex}")
            except Exception:
                pass
    return None


def _decode_timestamp(val: str) -> Optional[tuple[str, str, str]]:
    cleaned = val.strip()
    ts_sec = None
    if re.match(r"^\d{10}$", cleaned):
        num = int(cleaned)
        if 946684800 <= num <= 2500000000:
            ts_sec = num
    elif re.match(r"^\d{13}$", cleaned):
        num = int(cleaned)
        if 946684800000 <= num <= 2500000000000:
            ts_sec = num / 1000.0

    if ts_sec is not None:
        try:
            dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
            return ("Unix Epoch Timestamp", f"UTC: {dt.isoformat()}", "Parsed Unix epoch timestamp to ISO-8601 UTC date")
        except Exception:
            return None
    return None



def _defang(val: str) -> str:
    s = val
    s = re.sub(r"https?://", lambda m: "hxxps://" if "https" in m.group(0).lower() else "hxxp://", s, flags=re.IGNORECASE)
    s = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[.]\2[.]\3[.]\4", s)
    s = re.sub(r"([a-zA-Z0-9_-]+)\.(com|org|net|io|top|xyz|ru|cn|cc|info|biz|site|live|pw|me)\b", r"\1[.]\2", s, flags=re.IGNORECASE)
    return s


def _refang(val: str) -> str:
    s = val
    s = re.sub(r"hxxps://", "https://", s, flags=re.IGNORECASE)
    s = re.sub(r"hxxp://", "http://", s, flags=re.IGNORECASE)
    s = s.replace("[.]", ".").replace("[:]", ":").replace("(dot)", ".").replace("[dot]", ".")
    return s


def _extract_iocs(text: str) -> list[tuple[str, str]]:
    iocs: list[tuple[str, str]] = []
    seen = set()

    def add(t: str, v: str):
        v_clean = v.strip()
        if v_clean and v_clean.lower() not in seen:
            seen.add(v_clean.lower())
            iocs.append((t, v_clean))

    for m in re.finditer(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", text):
        if m.group(0) not in ("127.0.0.1", "0.0.0.0"):
            add("IPv4", m.group(0))

    for m in re.finditer(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b", text):
        add("Hash", m.group(0))

    for m in re.finditer(r"\bhttps?://[^\s\"'<>]+", text, re.IGNORECASE):
        add("URL", m.group(0))

    for m in re.finditer(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|io|top|xyz|ru|cn|cc|info|biz|site|live|pw|me|gov|edu)\b", text, re.IGNORECASE):
        add("Domain", m.group(0))

    return iocs


@app.callback(invoke_without_command=True)
def decode(
    payload: str = typer.Argument(..., help="Encoded payload, PowerShell -enc, Hex, URL, or defanged string"),
) -> None:
    """Analyze and deobfuscate an encoded string or command-line."""
    show_banner(primary=False)

    trimmed = payload.strip()
    sha256 = hashlib.sha256(trimmed.encode("utf-8")).hexdigest()

    candidates: list[tuple[str, str, str]] = []

    is_defanged = bool(re.search(r"hxxp|\[\.\]|\[:\]|\(dot\)", trimmed, re.IGNORECASE))
    if is_defanged:
        candidates.append(("Refanged IOCs", _refang(trimmed), "Reconstructed actionable indicators"))
    else:
        candidates.append(("Defanged Output", _defang(trimmed), "Safe-to-share indicators"))

    utf16 = _decode_b64_utf16le(trimmed)
    if utf16 and utf16 != trimmed:
        candidates.append(("PowerShell UTF-16LE Base64", utf16, "Windows PowerShell EncodedCommand stream"))

    utf8 = _decode_b64_utf8(trimmed)
    if utf8 and utf8 != trimmed and utf8 != utf16:
        candidates.append(("Base64 (UTF-8 / ASCII)", utf8, "Standard Base64 text string"))

    hx = _decode_hex(trimmed)
    if hx and hx != trimmed:
        candidates.append(("Hex / Shellcode Bytes", hx, "Decoded from byte representation"))

    url_dec = _decode_url(trimmed)
    if url_dec and url_dec != trimmed:
        candidates.append(("URL Percent-Decoded", url_dec, "Decoded web query string"))

    jwt_res = _decode_jwt(trimmed)
    if jwt_res:
        candidates.append(jwt_res)

    xor_res = _scan_single_byte_xor(trimmed)
    if xor_res:
        candidates.append(xor_res)

    rot_res = _decode_rot13(trimmed)
    if rot_res:
        candidates.append(rot_res)

    ts_res = _decode_timestamp(trimmed)
    if ts_res:
        candidates.append(ts_res)

    # Extract IOCs
    combined = trimmed + "\n" + "\n".join(c[1] for c in candidates)
    iocs = _extract_iocs(combined)

    console.print(Panel(
        f"[bold white]Target Payload:[/bold white] {trimmed[:120]}{'…' if len(trimmed) > 120 else ''}\n"
        f"[dim]Input Length: {len(trimmed)} chars · SHA-256: {sha256}[/dim]",
        title="[bold cyan]CyberDecoder · Payload Inspector[/bold cyan]",
        border_style="cyan",
    ))

    if iocs:
        ioc_table = Table(title=f"Extracted Indicators ({len(iocs)})", border_style="dim")
        ioc_table.add_column("Type", style="bold yellow")
        ioc_table.add_column("Indicator", style="bold cyan")
        for t, v in iocs:
            ioc_table.add_row(t, v)
        console.print(ioc_table)

    if candidates:
        for title, text, desc in candidates:
            console.print(Panel(
                f"[bold green]{text}[/bold green]\n\n[dim]{desc}[/dim]",
                title=f"[bold white]{title}[/bold white]",
                border_style="green" if "PowerShell" in title or "Refanged" in title else "blue",
            ))
    else:
        console.print("[yellow]No standard obfuscated encoding recognized.[/yellow]")


@app.command("hash")
def hash_command(
    target: str = typer.Argument(..., help="File path or text string to hash"),
) -> None:
    """Compute MD5, SHA1, and SHA256 hashes of a file or string."""
    show_banner(primary=False)

    p = Path(target)
    if p.exists() and p.is_file():
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        total_bytes = 0
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                total_bytes += len(chunk)
        source_label = f"File: [bold]{p.resolve()}[/bold] ({total_bytes} bytes)"
        m_hex, s1_hex, s256_hex = md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    else:
        data = target.encode("utf-8")
        m_hex = hashlib.md5(data).hexdigest()
        s1_hex = hashlib.sha1(data).hexdigest()
        s256_hex = hashlib.sha256(data).hexdigest()
        source_label = f"Text input ({len(data)} bytes)"

    table = Table(title=f"Cryptographic Hashes — {source_label}", border_style="dim")
    table.add_column("Algorithm", style="bold yellow")
    table.add_column("Digest", style="bold cyan")
    table.add_row("MD5", m_hex)
    table.add_row("SHA-1", s1_hex)
    table.add_row("SHA-256", s256_hex)
    console.print(table)
