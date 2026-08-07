"""Sample binary upload + OS auto-detection (roadmap 1.4).

- POST /samples?name=<original>  — raw bytes in the body; the signature is
  sniffed (PE `MZ` → windows, ELF `\\x7fELF` → linux, Mach-O → macos, LNK →
  windows, ZIP → container peek for an OS hint, `#!` → interpreter mapping),
  SHA-256 computed and stored, truly unrecognized bytes → 422 with a hint.
- GET /samples/{sample_id}       — fetch a previously uploaded sample's meta.

The webapp Monitor page uploads here to pre-fill the detonation platform and
sample name — the "sample binary auto-detection (OS sniffing)" roadmap item.
"""

import hashlib
import json
import uuid
from typing import Optional

import httpx

from fastapi import APIRouter, HTTPException, Query, Request

from ..core.db import db_session
from ..models import samples as samples_store
from ..services import enrichment, yara as yara_service

router = APIRouter(tags=["samples"])

# (magic prefix, platform, human family) — checked in order. Fixed headers
# first; containers and scripts need their own (cheap) content peek.
_BINARY_MAGIC: list[tuple[bytes, str, str]] = [
    (b"MZ", "windows", "PE (Windows executable)"),
    (b"\x7fELF", "linux", "ELF (Linux executable)"),
    (b"\xfe\xed\xfa\xce", "macos", "Mach-O (macOS, 32-bit)"),
    (b"\xfe\xed\xfa\xcf", "macos", "Mach-O (macOS, 64-bit)"),
    (b"\xca\xfe\xba\xbe", "macos", "Mach-O universal/fat"),
    (b"L\x00\x00\x00", "windows", "Windows shortcut (.lnk)"),
]

_MAX_SIZE = 50 * 1024 * 1024  # 50 MB

# Shebang interpreters we recognize, mapped to a platform guess. Scripts are
# cross-platform-ish, but a malware analyst wants the *most likely* detonation
# host: POSIX shells/interpreters → linux, Windows script hosts → windows.
_UNIX_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "python", "python2",
    "python3", "perl", "ruby", "node", "php", "awk", "sed", "lua", "expect",
    "env", "run-parts", "busybox",
}
_WINDOWS_INTERPRETERS = {"powershell", "pwsh", "cmd", "wscript", "cscript"}


def _guess_zip_platform(data: bytes) -> tuple[str, str]:
    """Peek inside a ZIP (PK..) for an OS hint — office documents and Windows
    payloads are the common malicious archives, so those are rewarded first.
    Walks up to 8 local file headers (each header self-declares its sizes, so
    the walk is bounds-safe)."""
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "unknown", "ZIP-like container"
    if data.startswith((b"PK\x05\x06", b"PK\x07\x08")):
        return "unknown", "ZIP archive (empty/spanned)"

    entries: list[str] = []
    off = 0
    while len(entries) < 8 and off + 30 <= len(data):
        if data[off : off + 4] != b"PK\x03\x04":
            break
        # Local header offsets: compsize at 18-22, namelen at 26-28, extra at 28-30.
        comp_size = int.from_bytes(data[off + 18 : off + 22], "little")
        name_len = int.from_bytes(data[off + 26 : off + 28], "little")
        extra_len = int.from_bytes(data[off + 28 : off + 30], "little")
        # Advance past header + name + extra + the entry's compressed data —
        # skipping compsize is what lets the walk reach the *next* header on
        # real zips (with data between entries), not just the first one.
        end = off + 30 + name_len + extra_len + comp_size
        if end > len(data):
            break
        entries.append(data[off + 30 : off + 30 + name_len].decode("utf-8", errors="replace"))
        off = end

    joined = " ".join(entries).lower()
    if any(p in joined for p in ("word/", "xl/", "ppt/")):
        return "windows", "Office document (zip)"
    if any(s in joined for s in (".exe", ".dll", ".lnk", ".docm", ".docx", ".bat", ".ps1")):
        return "windows", "ZIP containing Windows artifacts"
    if ".sh" in joined or "/bin/" in joined or ".elf" in joined:
        return "linux", "ZIP containing Unix artifacts"
    return "unknown", "ZIP archive (untyped)"


def _guess_shebang(data: bytes) -> Optional[tuple[str, str]]:
    """Map a `#!` first line to a platform guess, else None (bare shebang)."""
    line = data.split(b"\n", 1)[0][:200].decode("utf-8", errors="replace").strip()
    parts = line[2:].strip().split()
    if not parts:
        return None
    interp = parts[0].rsplit("/", 1)[-1].lower()
    if interp == "env":  # #!/usr/bin/env python3, or `env -S python3 …`
        for part in parts[1:]:
            if not part.startswith("-"):
                interp = part.rsplit("/", 1)[-1].lower()
                break
    if interp in _UNIX_INTERPRETERS:
        return "linux", f"script ({interp})"
    if interp in _WINDOWS_INTERPRETERS:
        return "windows", f"script ({interp})"
    return "unknown", f"script (shebang: {interp})"


def sniff_platform(data: bytes) -> Optional[tuple[str, str]]:
    """Return (platform, family) for a recognized signature, else None.

    Fixed magic bytes first, then ZIP and shebang content peeks. `unknown` is a
    valid platform (accepted upload with an honest "can't tell" guess) — only
    `None` means the bytes are unrecognized enough to 422."""
    for magic, platform, family in _BINARY_MAGIC:
        if data.startswith(magic):
            return platform, family
    if data.startswith(b"PK"):
        return _guess_zip_platform(data)
    if data.startswith(b"#!"):
        return _guess_shebang(data) or ("unknown", "script (bare shebang)")
    return None


@router.post("/samples", status_code=201)
async def upload_sample(
    request: Request,
    name: str = Query("", max_length=255, description="Original file name (for display)"),
):
    body = await request.body()
    if not body:
        raise HTTPException(status_code=422, detail="Empty upload — send the sample bytes in the request body")
    if len(body) > _MAX_SIZE:
        raise HTTPException(status_code=413, detail="Sample exceeds the 50 MB upload limit")

    sniffed = sniff_platform(body)
    if sniffed is None:
        preview = body[:8].hex()
        raise HTTPException(
            status_code=422,
            detail=(
                "Unrecognized file signature — expected PE (MZ), ELF (\\x7fELF), "
                "Mach-O, ZIP, LNK, or a #! script; "
                f"first bytes were 0x{preview}"
            ),
        )
    detected_platform, family = sniffed

    sha256 = hashlib.sha256(body).hexdigest()

    # Roadmap 2.2 — reputation evidence attached at upload time: a YARA scan
    # (pure-Python, always available) plus a cache-first VirusTotal file
    # lookup by SHA-256 (no API key → all-None, honest "no intel").
    yara_hits = yara_service.scan_sample(body)
    yara_names = [h["name"] for h in yara_hits]

    with db_session() as conn:
        async with httpx.AsyncClient() as client:
            hash_intel = await enrichment.enrich_hash(client, conn, sha256)

        existing = samples_store.find_by_sha(conn, sha256)
        if existing:
            # Idempotent: same bytes → same sample. Re-sniff the (identical)
            # body for family so the response shape matches a fresh upload —
            # a single source of truth for the sniff, no reverse-lookup table.
            # Persist the label too: samples uploaded before the vault got a
            # NULL family, and re-uploading them is the honest backfill path.
            _, family = sniff_platform(body)
            samples_store.set_family(conn, existing["sample_id"], family)
            return {
                **dict(existing),
                "family": family,
                "yara_rules": json.dumps(yara_names),
                "malware_family": hash_intel["malware_family"],
                "vt_detections": hash_intel["vt_detections"],
            }

        sample_id = uuid.uuid4().hex[:12]
        row = samples_store.add_sample(
            conn,
            sample_id,
            (name.strip() or f"sample-{sha256[:8]}"),
            sha256,
            detected_platform,
            len(body),
            family,
        )
        samples_store.set_sample_reputation(
            conn,
            sample_id,
            hash_intel["vt_detections"],
            hash_intel["malware_family"],
            json.dumps(yara_names),
        )
        row = samples_store.get_sample(conn, sample_id)

    return {**row, "family": family}


@router.get("/samples", response_model=None)
def list_samples(
    q: str = Query("", max_length=200, description="Filter by name / hash prefix / family"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Sample library — every uploaded binary with its reputation evidence.

    Each row carries the parsed YARA hits, VirusTotal detection count, and how
    many runs used the same sample name (so the webapp can link a binary to
    its detonations). Powers the webapp /samples library page.
    """
    with db_session() as conn:
        rows = samples_store.list_samples(conn, q=q.strip(), limit=limit, offset=offset)
        total = samples_store.count_samples(conn, q=q.strip())
        out = []
        for r in rows:
            try:
                yara_rules = json.loads(r["yara_rules"] or "[]")
            except (ValueError, TypeError):
                yara_rules = []
            runs_count = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE sample_name = ?", (r["original_name"],)
            ).fetchone()[0]
            out.append(
                {
                    "sample_id": r["sample_id"],
                    "original_name": r["original_name"],
                    "sha256": r["sha256"],
                    "detected_platform": r["detected_platform"],
                    "size": r["size"],
                    "created_at": r["created_at"],
                    "family": r.get("family"),
                    "yara_rules": yara_rules,
                    "vt_detections": r["vt_detections"],
                    "malware_family": r["malware_family"],
                    "runs_count": runs_count,
                }
            )
    return {"total": total, "returned": len(out), "samples": out}


@router.get("/samples/{sample_id}", response_model=None)
def get_sample(sample_id: str):
    """One sample with the same parsed shape as the list endpoint — YARA rules
    as an array (not the stored JSON string), plus its detonation count."""
    with db_session() as conn:
        row = samples_store.get_sample(conn, sample_id)
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
        try:
            yara_rules = json.loads(row["yara_rules"] or "[]")
        except (ValueError, TypeError):
            yara_rules = []
        runs_count = conn.execute(
            "SELECT COUNT(*) FROM runs WHERE sample_name = ?", (row["original_name"],)
        ).fetchone()[0]
    return {**row, "yara_rules": yara_rules, "runs_count": runs_count}


@router.get("/samples/{sample_id}/reputation", response_model=None)
def get_sample_reputation(sample_id: str):
    """Roadmap 2.2 — the reputation evidence attached to an uploaded sample.

    YARA matches (parsed from the stored JSON) + VirusTotal detection counts.
    Missing sample → 404; a sample with no signatures/reputation simply
    returns empty lists/Nones — honest "no intel", not an error.
    """
    with db_session() as conn:
        row = samples_store.get_sample(conn, sample_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
    try:
        yara_rules = json.loads(row["yara_rules"] or "[]")
    except (ValueError, TypeError):
        yara_rules = []
    return {
        "sample_id": sample_id,
        "sha256": row["sha256"],
        "yara_rules": yara_rules,
        "vt_detections": row["vt_detections"],
        "malware_family": row["malware_family"],
    }
