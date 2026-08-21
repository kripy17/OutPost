"""Sample binary upload + OS auto-detection (roadmap 1.4).

- POST /samples?name=<original>  — raw bytes in the body; the signature is
  sniffed (PE `MZ` → windows, ELF `\\x7fELF` → linux, Mach-O → macos, LNK →
  windows, ZIP → container peek for an OS hint, `#!` → interpreter mapping),
  SHA-256 computed and stored, truly unrecognized bytes → 422 with a hint.
- GET /samples/{sample_id}       — fetch a previously uploaded sample's meta.

The webapp Monitor page uploads here to pre-fill the detonation platform and
sample name — the "sample binary auto-detection (OS sniffing)" roadmap item.
"""

import csv
import hashlib
import io
import json
import uuid

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse

from ..core import config
from ..core.db import db_session
from ..models import samples as samples_store
from ..models.run import SYNTHETIC_SOURCES
from ..services import enrichment, static_analysis
from ..services import yara as yara_service

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


def _guess_shebang(data: bytes) -> tuple[str, str] | None:
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


def _store_bytes(sample_id: str, body: bytes) -> None:
    """Persist the raw bytes to disk for later static analysis / download.

    Idempotent — re-uploading identical bytes (dedup path) just overwrites
    the same file. A failed write must not fail the upload; the sample's
    metadata is still valid, static analysis just reports bytes unavailable.
    """
    try:
        config.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
        (config.SAMPLES_DIR / f"{sample_id}.bin").write_bytes(body)
    except OSError:
        pass


def _load_bytes(sample_id: str) -> bytes | None:
    """Read a stored sample's raw bytes; None when absent (pre-persistence
    uploads, or a failed write)."""
    try:
        return (config.SAMPLES_DIR / f"{sample_id}.bin").read_bytes()
    except OSError:
        return None


def sniff_platform(data: bytes) -> tuple[str, str] | None:
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
    # (pure-Python, always available; bundled + persisted custom lab rules)
    # plus a cache-first VirusTotal file lookup by SHA-256 (no API key →
    # all-None, honest "no intel").
    with db_session() as conn:
        yara_hits = yara_service.scan_sample_with_custom(body, conn)
        yara_names = [h["name"] for h in yara_hits]
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
            # Backfill bytes on re-upload: samples stored before persistence
            # landed have no .bin on disk — static analysis would report
            # "bytes unavailable" until the same file comes back through.
            _store_bytes(existing["sample_id"], body)
            return {
                **dict(existing),
                "family": family,
                "yara_rules": json.dumps(yara_names),
                "malware_family": hash_intel["malware_family"],
                "vt_detections": hash_intel["vt_detections"],
            }

        sample_id = uuid.uuid4().hex[:12]
        # Persist the raw bytes before/independent of the DB row — static
        # analysis (strings/IOCs/PE/ELF) and the download endpoint read them.
        _store_bytes(sample_id, body)
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


def _sample_synthetic_map(conn) -> dict[str, bool]:
    """Per original-name: whether every detonation of that binary came from
    synthetic-provenance runs. A binary with no runs is NOT synthetic (a
    genuine analyst upload is indistinguishable from a demo one until it's
    detonated, so we don't guess). One GROUP BY instead of a query per row."""
    marks = ",".join("?" for _ in SYNTHETIC_SOURCES)
    rows = conn.execute(
        f"""
        SELECT r.sample_name AS name,
               COUNT(*) AS total,
               SUM(CASE WHEN r.source NOT IN ({marks}) THEN 1 ELSE 0 END) AS real_n
        FROM runs r
        GROUP BY r.sample_name
        """,
        list(SYNTHETIC_SOURCES),
    ).fetchall()
    return {r["name"]: (r["total"] > 0 and r["real_n"] == 0) for r in rows}


@router.get("/samples", response_model=None)
def list_samples(
    q: str = Query("", max_length=200, description="Filter by name / hash prefix / family"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    include_synthetic: bool = Query(
        False,
        description="Show binaries whose entire detonation history is demo/synthetic (seed / webapp-demo / sandbox demo)",
    ),
):
    """Sample library — every uploaded binary with its reputation evidence.

    Each row carries the parsed YARA hits, VirusTotal detection count, how
    many runs used the same sample name, and whether that history is entirely
    synthetic. Synthetic-provenance binaries are hidden by default (archive
    parity); `include_synthetic` reveals them. Powers the webapp /samples
    library page.
    """
    with db_session() as conn:
        rows = samples_store.list_samples(conn, q=q.strip(), limit=limit, offset=offset, include_synthetic=include_synthetic)
        total = samples_store.count_samples(conn, q=q.strip(), include_synthetic=include_synthetic)
        synth_map = _sample_synthetic_map(conn)
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
                    "synthetic": synth_map.get(r["original_name"], False),
                }
            )
    return {"total": total, "returned": len(out), "samples": out}


@router.get("/samples/export", response_model=None)
def export_samples(
    q: str = Query("", max_length=200),
    limit: int = Query(1000, ge=1, le=5000),
    include_synthetic: bool = Query(
        False,
        description="Show binaries whose entire detonation history is demo/synthetic",
    ),
):
    """CSV of the sample vault (same filter as GET /samples) — name, hash,
    platform, size, family, YARA hits, VT detections, detonation count.
    Honors the synthetic-hiding default so the export matches the page."""
    data = list_samples(q=q, limit=limit, offset=0, include_synthetic=include_synthetic)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["sample_id", "original_name", "sha256", "detected_platform", "size", "family", "yara_rules", "vt_detections", "malware_family", "runs_count", "created_at"])
    for s in data["samples"]:
        writer.writerow([
            s["sample_id"], s["original_name"], s["sha256"], s["detected_platform"],
            s["size"], s["family"], "|".join(s["yara_rules"]), s["vt_detections"],
            s["malware_family"], s["runs_count"], s["created_at"],
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="outpost-samples.csv"'},
    )


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


@router.get("/samples/{sample_id}/static", response_model=None)
def get_sample_static(sample_id: str):
    """Static analysis of a stored sample — strings, candidate IOCs, and
    PE/ELF metadata (machine, sections, imports).

    Computed on demand from the persisted bytes; no external tooling.
    404 only when the sample is unknown; a known sample whose bytes were
    never stored (uploads from before byte persistence) returns 200 with
    `available: false` so the sample-detail panel renders its re-upload state
    from data instead of the browser logging a 404 for a normal condition.
    """
    with db_session() as conn:
        row = samples_store.get_sample(conn, sample_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
    body = _load_bytes(sample_id)
    if body is None:
        return {
            "sample_id": sample_id,
            "sha256": row["sha256"],
            "available": False,
            "size": 0,
            "strings": [],
            "iocs": {"urls": [], "ips": [], "domains": [], "hashes": [], "emails": []},
            "pe": None,
            "elf": None,
        }
    analysis = static_analysis.analyze_sample(body)
    return {
        "sample_id": sample_id,
        "sha256": row["sha256"],
        "available": True,
        "size": len(body),
        **analysis,
    }


@router.get("/samples/{sample_id}/download")
def download_sample(sample_id: str):
    """Hand the stored bytes back to the analyst (FileResponse).

    The filename carries the original name; the `x-outpost-sha256` header lets
    a client verify integrity without a second round-trip. 404 when the sample
    is unknown or its bytes were never stored.
    """
    with db_session() as conn:
        row = samples_store.get_sample(conn, sample_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
    path = config.SAMPLES_DIR / f"{sample_id}.bin"
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Sample bytes are not stored — re-upload the file to enable download.",
        )
    safe_name = "".join(c for c in row["original_name"] if c not in '"/\\:?*<>|').strip() or "sample.bin"
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=safe_name,
        headers={"x-outpost-sha256": row["sha256"]},
    )


@router.delete("/samples/{sample_id}", response_model=None)
def delete_sample_endpoint(sample_id: str) -> dict:
    """Delete a sample record and its stored binary file."""
    with db_session() as conn:
        deleted = samples_store.delete_sample(conn, sample_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
    path = config.SAMPLES_DIR / f"{sample_id}.bin"
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass
    return {"status": "ok", "sample_id": sample_id}


@router.delete("/samples", response_model=None)
def delete_all_samples_endpoint() -> dict:
    """Wipe all sample records and stored binaries."""
    with db_session() as conn:
        count = samples_store.delete_all_samples(conn)
    if config.SAMPLES_DIR.exists():
        for f in config.SAMPLES_DIR.glob("*.bin"):
            try:
                f.unlink()
            except Exception:
                pass
    return {"status": "ok", "deleted": count}

