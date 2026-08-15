"""Uploaded sample binaries (roadmap 1.4) — OS sniffed from magic bytes.

Stores the original name, SHA-256, detected platform, and size so the webapp
can pre-fill a detonation and the hash is searchable via IOC search.
"""

import sqlite3
from datetime import datetime, timezone

from .run import SYNTHETIC_SOURCES


def add_sample(
    conn: sqlite3.Connection,
    sample_id: str,
    original_name: str,
    sha256: str,
    detected_platform: str,
    size: int,
    family: str | None = None,
) -> dict:
    created_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO samples (sample_id, original_name, sha256, detected_platform, size, created_at, family)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (sample_id, original_name, sha256, detected_platform, size, created_at, family),
    )
    return {
        "sample_id": sample_id,
        "original_name": original_name,
        "sha256": sha256,
        "detected_platform": detected_platform,
        "size": size,
        "created_at": created_at,
        "family": family,
    }


def get_sample(conn: sqlite3.Connection, sample_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM samples WHERE sample_id = ?", (sample_id,)).fetchone()
    return dict(row) if row else None


def _visibility_clause(include_synthetic: bool) -> tuple[str, list]:
    """A sample is synthetic when its *entire* detonation history comes from
    synthetic-provenance runs (seed / webapp-demo / legacy monitor /
    sandbox:demo); a run-less upload or one with any real run is real. The
    clause keeps exactly the non-synthetic set: samples with no runs, or with
    at least one run outside the synthetic markers."""
    if include_synthetic:
        return "", []
    marks = ",".join("?" for _ in SYNTHETIC_SOURCES)
    return (
        "(NOT EXISTS (SELECT 1 FROM runs r WHERE r.sample_name = samples.original_name)"
        f" OR EXISTS (SELECT 1 FROM runs r WHERE r.sample_name = samples.original_name"
        f" AND r.source NOT IN ({marks})))",
        list(SYNTHETIC_SOURCES),
    )


def list_samples(
    conn: sqlite3.Connection,
    q: str = "",
    limit: int = 100,
    offset: int = 0,
    include_synthetic: bool = False,
) -> list[dict]:
    """Sample library — newest first, optional name/hash/family filter.
    Synthetic-provenance binaries are hidden by default (archive parity)."""
    base = "SELECT * FROM samples"
    params: list = []
    conds: list[str] = []
    if q:
        like = f"%{q}%"
        conds.append("(original_name LIKE ? OR sha256 LIKE ? OR malware_family LIKE ?)")
        params += [like, like, like]
    vis, vis_args = _visibility_clause(include_synthetic)
    if vis:
        conds.append(vis)
        params += vis_args
    if conds:
        base += " WHERE " + " AND ".join(conds)
    base += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    return [dict(r) for r in conn.execute(base, params).fetchall()]


def count_samples(conn: sqlite3.Connection, q: str = "", include_synthetic: bool = False) -> int:
    base = "SELECT COUNT(*) FROM samples"
    params: list = []
    conds: list[str] = []
    if q:
        like = f"%{q}%"
        conds.append("(original_name LIKE ? OR sha256 LIKE ? OR malware_family LIKE ?)")
        params += [like, like, like]
    vis, vis_args = _visibility_clause(include_synthetic)
    if vis:
        conds.append(vis)
        params += vis_args
    if conds:
        base += " WHERE " + " AND ".join(conds)
    return conn.execute(base, params).fetchone()[0]


def find_by_sha(conn: sqlite3.Connection, sha256: str) -> dict | None:
    row = conn.execute("SELECT * FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
    return dict(row) if row else None


def list_by_sha_prefix(conn: sqlite3.Connection, prefix: str, limit: int = 20) -> list[dict]:
    """IOC search helper — match a (possibly partial) hash prefix."""
    rows = conn.execute(
        "SELECT * FROM samples WHERE sha256 LIKE ? ORDER BY created_at DESC LIMIT ?",
        (f"{prefix}%", limit),
    ).fetchall()
    return [dict(r) for r in rows]


def set_family(conn: sqlite3.Connection, sample_id: str, family: str | None) -> None:
    """Persist the sniffed family label (the vault displays it per row)."""
    conn.execute("UPDATE samples SET family = ? WHERE sample_id = ?", (family, sample_id))


def set_sample_reputation(
    conn: sqlite3.Connection,
    sample_id: str,
    vt_detections: int | None,
    malware_family: str | None,
    yara_rules: str | None,  # JSON array of matched rule names
) -> None:
    """Attach roadmap-2.2 reputation evidence to an uploaded sample."""
    conn.execute(
        "UPDATE samples SET vt_detections = ?, malware_family = ?, yara_rules = ? WHERE sample_id = ?",
        (vt_detections, malware_family, yara_rules, sample_id),
    )


# -- hash_cache (roadmap 2.2) ---------------------------------------------------
def get_hash_cache(conn: sqlite3.Connection, sha256: str) -> dict | None:
    row = conn.execute("SELECT * FROM hash_cache WHERE sha256 = ?", (sha256,)).fetchone()
    return dict(row) if row else None


def upsert_hash_cache(
    conn: sqlite3.Connection,
    sha256: str,
    vt_detections: int | None,
    malware_family: str | None,
) -> None:
    from datetime import datetime, timezone

    checked_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO hash_cache (sha256, vt_detections, malware_family, checked_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(sha256) DO UPDATE SET
            vt_detections = excluded.vt_detections,
            malware_family = excluded.malware_family,
            checked_at = excluded.checked_at
        """,
        (sha256, vt_detections, malware_family, checked_at),
    )
