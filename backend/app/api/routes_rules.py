"""Rule tuning (roadmap 2.3) — inspect and edit detection thresholds live.

The detection engine reads `rule_tuning` on every batch (see
services/detection.py); an empty table behaves exactly like the module
defaults. This router exposes:

- GET  /rules/tuning          — every tunable knob + baseline + current value
- PUT  /rules/tuning/{param}  — set an override (validated against the type)
- DELETE /rules/tuning/{param} — restore the default

Tuning takes effect on the *next* ingested batch — no backend restart needed.
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..core.db import db_session
from ..core.schema import Suppression, SuppressionIn
from ..services.detection import ENUM_PATTERNS, TUNABLE_DEFAULTS, load_enum_patterns
from ..services.risk import RULE_META

# Valid rule ids — the engine's RULE_META registry, so a typo'd suppression
# is rejected instead of silently never matching anything.
_KNOWN_RULES = set(RULE_META.keys())

router = APIRouter(tags=["rules"])


class TunableIn(BaseModel):
    value: str  # parsed by the knob's declared type; invalid → 422


def _parse_value(name: str, raw: str):
    _rule_id, type_name, default = TUNABLE_DEFAULTS[name]
    try:
        if type_name == "int":
            return int(raw)
        if type_name == "float":
            return float(raw)
        return str(raw)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=422,
            detail=f"{name} expects a {type_name} value, got {raw!r}",
        )


@router.get("/rules/tuning", response_model=None)
def list_tuning() -> dict:
    """Every knob with its baseline and current (possibly overridden) value."""
    with db_session() as conn:
        rows = conn.execute("SELECT rule_id, param, value FROM rule_tuning").fetchall()
    overrides = {(r["rule_id"], r["param"]): r["value"] for r in rows}

    knobs = []
    for name, (rule_id, type_name, default) in TUNABLE_DEFAULTS.items():
        raw = overrides.get((rule_id, name))
        current = default if raw is None else _parse_value(name, raw)
        knobs.append(
            {
                "param": name,
                "rule_id": rule_id,
                "type": type_name,
                "default": default,
                "current": current,
                "tuned": raw is not None,
            }
        )
    return {"count": len(knobs), "knobs": knobs}


@router.put("/rules/tuning/{param}", response_model=None)
def set_tuning(param: str, body: TunableIn) -> dict:
    """Set an override for one knob. Takes effect on the next batch."""
    if param not in TUNABLE_DEFAULTS:
        raise HTTPException(status_code=404, detail=f"Unknown tuning knob: {param}")
    rule_id = TUNABLE_DEFAULTS[param][0]
    value = str(_parse_value(param, body.value.strip()))
    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO rule_tuning (rule_id, param, value) VALUES (?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET value = excluded.value
            """,
            (rule_id, param, value),
        )
    return {"param": param, "rule_id": rule_id, "current": value, "tuned": True}


@router.delete("/rules/tuning/{param}", status_code=204)
def reset_tuning(param: str) -> None:
    """Restore the default for one knob (delete the override row)."""
    if param not in TUNABLE_DEFAULTS:
        raise HTTPException(status_code=404, detail=f"Unknown tuning knob: {param}")
    rule_id = TUNABLE_DEFAULTS[param][0]
    with db_session() as conn:
        conn.execute("DELETE FROM rule_tuning WHERE rule_id = ? AND param = ?", (rule_id, param))
    return None


# ---------------------------------------------------------------------------
# Enumeration patterns (rule 15, T1082) — the per-OS recon command tables
# behind the discovery enumeration-burst rule. Operators add/remove recon
# commands per platform here; the engine reads them on every batch
# (detection.load_enum_patterns), so edits apply to the next run with no
# backend restart. Absent / invalid stored values behave like the defaults.
# ---------------------------------------------------------------------------

_PLATFORMS = list(ENUM_PATTERNS.keys())


def _default_patterns_dict() -> dict[str, list[dict]]:
    return {
        platform: [{"pattern": pat, "label": label} for pat, label in rows]
        for platform, rows in ENUM_PATTERNS.items()
    }


class EnumPatternsIn(BaseModel):
    patterns: dict[str, list[dict]]  # platform -> [{pattern, label}]


@router.get("/rules/enum-patterns", response_model=None)
def list_enum_patterns() -> dict:
    """Every platform's effective pattern table, plus the module defaults so
    the editor can mark which rows are operator-added/edited vs stock."""
    with db_session() as conn:
        effective = load_enum_patterns(conn)
    payload = {
        platform: [{"pattern": pat, "label": label} for pat, label in rows]
        for platform, rows in effective.items()
    }
    return {"platforms": payload, "defaults": _default_patterns_dict()}


@router.put("/rules/enum-patterns", response_model=None)
def set_enum_patterns(body: EnumPatternsIn) -> dict:
    """Replace the per-platform pattern tables wholesale (last write wins —
    partial merges are intentionally out of scope, matching the tuning
    endpoint's whole-knob semantics). Validation mirrors load_enum_patterns
    so the engine and the editor agree on shape; unknown platforms are
    rejected rather than silently dropped."""
    for platform in body.patterns:
        if platform not in _PLATFORMS:
            raise HTTPException(status_code=422, detail=f"Unknown platform: {platform}")
    clean = {}
    for platform in _PLATFORMS:
        rows = body.patterns.get(platform, [])
        cleaned = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            pattern = item.get("pattern")
            label = item.get("label")
            if isinstance(pattern, str) and pattern.strip() and isinstance(label, str) and label.strip():
                cleaned.append({"pattern": pattern.strip(), "label": label.strip()})
        clean[platform] = cleaned
    with db_session() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('enum_patterns', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (json.dumps(clean),),
        )
    return {"platforms": clean}


@router.delete("/rules/enum-patterns", status_code=204)
def reset_enum_patterns() -> None:
    """Restore stock enumeration patterns for every platform."""
    with db_session() as conn:
        conn.execute("DELETE FROM settings WHERE key = 'enum_patterns'")
    return None


# ---------------------------------------------------------------------------
# Alert triage — per-rule suppressions (run_id NULL = global; set = one run)
# The detection engine loads these on every batch (detection.load_suppressions)
# so a suppression applies to the next ingested batch — no backend restart.
# ---------------------------------------------------------------------------


@router.get("/rules/suppressions", response_model=list[Suppression])
def list_suppressions() -> list[Suppression]:
    """Every active suppression (global and per-run), oldest first."""
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM rule_suppressions ORDER BY id ASC"
        ).fetchall()
    return [Suppression(**dict(r)) for r in rows]


@router.post("/rules/suppressions", status_code=201, response_model=Suppression)
def add_suppression(body: SuppressionIn) -> Suppression:
    """Suppress a rule — globally (run_id omitted) or for one run. Adding the
    same (rule_id, scope) twice replaces the earlier row; unknown rules 422."""
    if body.rule_id not in _KNOWN_RULES:
        raise HTTPException(status_code=422, detail=f"Unknown rule_id: {body.rule_id}")
    if body.run_id is not None and not body.run_id.strip():
        raise HTTPException(status_code=422, detail="run_id must be non-empty when set")
    now = datetime.now(timezone.utc).isoformat()
    run_id = body.run_id.strip() if body.run_id else None
    with db_session() as conn:
        # `IS` (not `=`) is deliberate: with a NULL bound it becomes `IS NULL`,
        # matching the global row; with a string it behaves like `=`. Either
        # way the same (rule, scope) can only ever have one active row.
        conn.execute(
            "DELETE FROM rule_suppressions WHERE rule_id = ? AND run_id IS ?",
            (body.rule_id, run_id),
        )
        cur = conn.execute(
            "INSERT INTO rule_suppressions (rule_id, run_id, reason, created_at) VALUES (?, ?, ?, ?)",
            (body.rule_id, run_id, (body.reason or "").strip() or None, now),
        )
        row = conn.execute(
            "SELECT * FROM rule_suppressions WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
    return Suppression(**dict(row))


@router.delete("/rules/suppressions/{entry_id}", status_code=204)
def delete_suppression(entry_id: int) -> None:
    """Remove a suppression — the rule starts firing again on the next batch."""
    with db_session() as conn:
        cur = conn.execute(
            "DELETE FROM rule_suppressions WHERE id = ?", (entry_id,)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Unknown suppression: {entry_id}")
    return None
