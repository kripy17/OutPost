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

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..core import auth
from ..core.db import db_session
from ..core.schema import Suppression, SuppressionIn
from ..models import audit
from ..services.detection import (
    ENUM_PATTERNS,
    LOG_CLEAR_PATTERNS,
    LOG_SERVICE_STOP_PATTERNS,
    TUNABLE_DEFAULTS,
    load_enum_patterns,
    load_log_patterns,
)
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
# False-positive feedback, surfaced on the Rules page: every rule's FP counter
# (fed by the "mark as false positive" loop on run detail) plus an automatic
# threshold-raise suggestion once a rule's FPs pass a tunable threshold. The
# threshold itself is a setting (FP_SUGGEST_THRESHOLD, default 3) so operators
# can tune when a rule is considered "noisy" without touching code.
# ---------------------------------------------------------------------------

FP_THRESHOLD_KEY = "FP_SUGGEST_THRESHOLD"
FP_DEFAULT_THRESHOLD = 3


def _fp_threshold(conn) -> int:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (FP_THRESHOLD_KEY,)).fetchone()
    try:
        return max(1, int(row["value"])) if row else FP_DEFAULT_THRESHOLD
    except (TypeError, ValueError):
        return FP_DEFAULT_THRESHOLD


def _threshold_suggestion(conn, rule_id: str, fp_count: int) -> dict | None:
    """A concrete raise for the rule's int tunable (if it has one and a raise
    is warranted): the knob, its current value, and max(current+1, fp+1)."""
    for name, (rid, type_name, default) in TUNABLE_DEFAULTS.items():
        if rid != rule_id or type_name != "int":
            continue
        row = conn.execute(
            "SELECT value FROM rule_tuning WHERE rule_id = ? AND param = ?",
            (rule_id, name),
        ).fetchone()
        current = int(row["value"]) if row else int(default)
        suggested = max(current + 1, fp_count + 1)
        if suggested > current:
            return {
                "kind": "threshold",
                "param": name,
                "rule_id": rule_id,
                "current": current,
                "suggested": suggested,
                "detail": f"{fp_count} false positive(s) — raise {name} from {current} to {suggested}",
            }
    return None


class FpThresholdIn(BaseModel):
    threshold: int


@router.get("/rules/fp", response_model=None)
def list_rule_fp() -> dict:
    """Every rule's FP counter, the tunable suggestion threshold, and — for
    rules over it — a ready-to-apply threshold raise. Each rule also carries
    its 14-day fired/FP history so the Rules page can render the FP-rate
    trend (FP ÷ fired over time), which is what makes the threshold
    suggestion defensible instead of a guess."""
    from datetime import datetime, timedelta, timezone

    with db_session() as conn:
        threshold = _fp_threshold(conn)
        rows = conn.execute("SELECT * FROM rule_fp ORDER BY count DESC").fetchall()

        # Fired + FP counts per rule per UTC day (FP = resolved with an FP:
        # comment, which is exactly how mark-false-positive resolves alerts).
        fired_rows = conn.execute(
            "SELECT rule_id, substr(triggered_at, 1, 10) AS day, COUNT(*) AS n "
            "FROM alerts GROUP BY rule_id, day"
        ).fetchall()
        fp_rows = conn.execute(
            "SELECT rule_id, substr(triggered_at, 1, 10) AS day, COUNT(*) AS n "
            "FROM alerts WHERE status = 'resolved' AND status_comment LIKE 'FP%' "
            "GROUP BY rule_id, day"
        ).fetchall()
        fired_by_rule_day = {(r["rule_id"], r["day"]): r["n"] for r in fired_rows}
        fp_by_rule_day = {(r["rule_id"], r["day"]): r["n"] for r in fp_rows}
        fired_total = {}
        for (rid, _day), n in fired_by_rule_day.items():
            fired_total[rid] = fired_total.get(rid, 0) + n

        today = datetime.now(timezone.utc).date()
        days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]

        rules = []
        for r in rows:
            count = r["count"]
            rules.append(
                {
                    "rule_id": r["rule_id"],
                    "count": count,
                    "fired_count": fired_total.get(r["rule_id"], 0),
                    "last_fp_at": r["last_fp_at"],
                    "over_threshold": count >= threshold,
                    "suggestion": _threshold_suggestion(conn, r["rule_id"], count) if count >= threshold else None,
                    "history": [
                        {
                            "day": d,
                            "fired": fired_by_rule_day.get((r["rule_id"], d), 0),
                            "fp": fp_by_rule_day.get((r["rule_id"], d), 0),
                        }
                        for d in days
                    ],
                }
            )
    return {"threshold": threshold, "default_threshold": FP_DEFAULT_THRESHOLD, "rules": rules}


@router.put("/rules/fp-threshold", response_model=None)
def set_fp_threshold(body: FpThresholdIn, request: Request) -> dict:
    """Tune when a rule counts as noisy — FPs at or above this value trigger
    the threshold-raise suggestion on the Rules page."""
    if body.threshold < 1:
        raise HTTPException(status_code=422, detail="threshold must be >= 1")
    actor = auth.role_from_request(request)
    with db_session() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (FP_THRESHOLD_KEY, str(body.threshold)),
        )
        audit.log(
            conn, actor, "rules.fp-threshold",
            target_type="settings", target_id=FP_THRESHOLD_KEY,
            detail=f"FP suggestion threshold → {body.threshold}",
        )
    return {"threshold": body.threshold}


@router.delete("/rules/fp-threshold", status_code=204)
def reset_fp_threshold(request: Request) -> None:
    """Restore the default FP suggestion threshold (3)."""
    actor = auth.role_from_request(request)
    with db_session() as conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (FP_THRESHOLD_KEY,))
        audit.log(conn, actor, "rules.fp-threshold", target_type="settings", target_id=FP_THRESHOLD_KEY, detail="FP suggestion threshold → default")
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
# Anti-forensics pattern tables (log-service-stop / log-clearing) — the same
# operator-editable-per-platform pattern treatment as enumeration, so the
# signatures behind the log rules can be tuned without touching code.
# ---------------------------------------------------------------------------
_LOG_PATTERN_KINDS = ("service_stop", "log_clear")
_LOG_PATTERN_DEFAULTS = {
    "service_stop": LOG_SERVICE_STOP_PATTERNS,
    "log_clear": LOG_CLEAR_PATTERNS,
}


class LogPatternsIn(BaseModel):
    patterns: dict[str, dict[str, list[dict]]]  # kind -> platform -> [{pattern, label}]


@router.get("/rules/log-patterns", response_model=None)
def list_log_patterns() -> dict:
    """Effective anti-forensics pattern tables per kind/platform, plus the
    stock defaults so the editor can mark operator changes."""
    with db_session() as conn:
        effective = load_log_patterns(conn)
    payload = {
        kind: {
            platform: [{"pattern": pat, "label": label} for pat, label in rows]
            for platform, rows in tables.items()
        }
        for kind, tables in effective.items()
    }
    defaults = {
        kind: {
            platform: [{"pattern": pat, "label": label} for pat, label in rows]
            for platform, rows in tables.items()
        }
        for kind, tables in _LOG_PATTERN_DEFAULTS.items()
    }
    return {"kinds": payload, "defaults": defaults}


@router.put("/rules/log-patterns", response_model=None)
def set_log_patterns(body: LogPatternsIn) -> dict:
    """Replace the per-kind/per-platform pattern tables wholesale. Unknown
    kinds or platforms are rejected; validation mirrors load_log_patterns so
    the engine and the editor agree on shape."""
    for kind in body.patterns:
        if kind not in _LOG_PATTERN_KINDS:
            raise HTTPException(status_code=422, detail=f"Unknown pattern kind: {kind}")
    clean = {}
    for kind in _LOG_PATTERN_KINDS:
        kind_rows = body.patterns.get(kind, {})
        per = {}
        for platform in _PLATFORMS:
            rows = kind_rows.get(platform, [])
            cleaned = []
            for item in rows:
                if not isinstance(item, dict):
                    continue
                pattern = item.get("pattern")
                label = item.get("label")
                if isinstance(pattern, str) and pattern.strip() and isinstance(label, str) and label.strip():
                    cleaned.append({"pattern": pattern.strip(), "label": label.strip()})
            per[platform] = cleaned
        clean[kind] = per
    with db_session() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('log_patterns', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (json.dumps(clean),),
        )
    return {"kinds": clean}


@router.delete("/rules/log-patterns", status_code=204)
def reset_log_patterns() -> None:
    """Restore stock anti-forensics patterns for every kind/platform."""
    with db_session() as conn:
        conn.execute("DELETE FROM settings WHERE key = 'log_patterns'")
    return None


@router.delete("/rules/reset", response_model=None)
def factory_reset_rules(request: Request) -> dict:
    """Factory reset of the whole operational rule surface — one atomic call.

    Clears every tuning override (rule_tuning), every suppression
    (rule_suppressions), and the operator-edited pattern tables + FP
    threshold (enum_patterns / log_patterns / FP_SUGGEST_THRESHOLD settings
    keys), restoring the engine to stock behavior. Runs in one transaction so
    a partial clear can never leave the engine in a half-tuned state, and is
    audited. Idempotent — resetting an already-stock store clears 0 rows.
    """
    actor = auth.role_from_request(request)
    with db_session() as conn:
        tuning = conn.execute("DELETE FROM rule_tuning").rowcount
        suppressions = conn.execute("DELETE FROM rule_suppressions").rowcount
        patterns = 0
        for key in ("enum_patterns", "log_patterns", FP_THRESHOLD_KEY):
            patterns += conn.execute("DELETE FROM settings WHERE key = ?", (key,)).rowcount
        audit.log(
            conn, actor, "rules.reset",
            target_type="rules", target_id="factory",
            detail=f"{tuning} tuning override(s), {suppressions} suppression(s), {patterns} pattern/threshold key(s) cleared",
        )
    return {"tuning_cleared": tuning, "suppressions_cleared": suppressions, "settings_cleared": patterns}


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
def add_suppression(body: SuppressionIn, request: Request) -> Suppression:
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
        audit.log(
            conn, auth.role_from_request(request), "suppression.add",
            target_type="suppression", target_id=str(cur.lastrowid),
            detail=f"{body.rule_id}" + (f" on run {run_id}" if run_id else " (global)"),
        )
    return Suppression(**dict(row))


@router.delete("/rules/suppressions/{entry_id}", status_code=204)
def delete_suppression(entry_id: int, request: Request) -> None:
    """Remove a suppression — the rule starts firing again on the next batch."""
    with db_session() as conn:
        cur = conn.execute(
            "DELETE FROM rule_suppressions WHERE id = ?", (entry_id,)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Unknown suppression: {entry_id}")
        audit.log(
            conn, auth.role_from_request(request), "suppression.remove",
            target_type="suppression", target_id=str(entry_id),
        )
    return None


# ---------------------------------------------------------------------------
# Rule packs (the WHIDS lesson) — versioned, diffable, file-based rule sets.
# GET /rules/pack exports the whole operational rule surface — tuning
# overrides, suppressions, enum-pattern tables, FP threshold — as ONE JSON
# document; POST /rules/pack re-applies it. Because a pack is a plain JSON
# file, operators can keep it in git, diff revisions, and roll back by
# re-importing the previous export: the Rules page's operational surface,
# captured as an artifact instead of living only in the DB.
# ---------------------------------------------------------------------------

PACK_SCHEMA = 1


def _suppressions_payload(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM rule_suppressions ORDER BY id ASC").fetchall()
    return [dict(r) for r in rows]


def _tuning_payload(conn) -> list[dict]:
    rows = conn.execute("SELECT rule_id, param, value FROM rule_tuning").fetchall()
    overrides = {(r["rule_id"], r["param"]): r["value"] for r in rows}
    knobs = []
    for name, (rule_id, type_name, default) in TUNABLE_DEFAULTS.items():
        raw = overrides.get((rule_id, name))
        knobs.append(
            {
                "param": name,
                "rule_id": rule_id,
                "type": type_name,
                "default": default,
                "current": default if raw is None else _parse_value(name, raw),
                "tuned": raw is not None,
            }
        )
    return knobs


@router.get("/rules/pack", response_model=None)
def export_rule_pack() -> dict:
    """The full operational rule surface as one versioned JSON document."""
    from datetime import datetime, timezone

    with db_session() as conn:
        pack = {
            "schema": PACK_SCHEMA,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "tuning": _tuning_payload(conn),
            "suppressions": _suppressions_payload(conn),
            "enum_patterns": _default_patterns_dict(),
            "fp_threshold": _fp_threshold(conn),
        }
        # Effective enum patterns (operator-edited tables), not just defaults.
        pack["enum_patterns"] = {
            platform: [{"pattern": pat, "label": label} for pat, label in rows]
            for platform, rows in load_enum_patterns(conn).items()
        }
        # Same for the anti-forensics pattern tables (log rules).
        pack["log_patterns"] = {
            kind: {
                platform: [{"pattern": pat, "label": label} for pat, label in rows]
                for platform, rows in tables.items()
            }
            for kind, tables in load_log_patterns(conn).items()
        }
    return pack


class RulePackIn(BaseModel):
    # `schema` aliased to schema_ — the raw name shadows pydantic's BaseModel
    # attribute, which warns and breaks validation in older versions.
    schema_: int = Field(default=PACK_SCHEMA, alias="schema")
    tuning: list[dict] = []
    suppressions: list[dict] = []
    enum_patterns: dict[str, list[dict]] | None = None
    log_patterns: dict[str, dict[str, list[dict]]] | None = None
    fp_threshold: int | None = None
    exported_at: str | None = None

    model_config = {"populate_by_name": True}


@router.post("/rules/pack", response_model=None)
def import_rule_pack(body: RulePackIn, request: Request) -> dict:
    """Re-apply a rule pack. Tuning is a full sync (the pack's `tuned` flag
    decides override vs default), enum patterns + FP threshold replace
    wholesale, and suppressions apply additively (identical scope is
    idempotent — never clobbers live triage). Unknown knobs/rules 422 so a
    pack from a newer schema can't silently half-apply."""
    if body.schema_ != PACK_SCHEMA:
        raise HTTPException(status_code=422, detail=f"Unsupported pack schema {body.schema_} (want {PACK_SCHEMA})")

    # Tuning — full sync: tuned=True → upsert override, tuned=False → restore
    # default. Every param must exist, or the pack is from a different engine.
    tuning_applied = 0
    for knob in body.tuning:
        param = knob.get("param")
        if param not in TUNABLE_DEFAULTS:
            raise HTTPException(status_code=422, detail=f"Unknown tuning knob: {param}")
        rule_id = TUNABLE_DEFAULTS[param][0]
        if knob.get("tuned"):
            _parse_value(param, str(knob["current"]))  # validates; 422 on bad type
            with db_session() as conn:
                conn.execute(
                    "INSERT INTO rule_tuning (rule_id, param, value) VALUES (?, ?, ?) "
                    "ON CONFLICT(rule_id) DO UPDATE SET value = excluded.value",
                    (rule_id, param, str(knob["current"])),
                )
        else:
            with db_session() as conn:
                conn.execute("DELETE FROM rule_tuning WHERE rule_id = ? AND param = ?", (rule_id, param))
        tuning_applied += 1

    # Suppressions — additive + idempotent (skip an identical scope that
    # already exists; never remove live triage state).
    added = 0
    skipped = 0
    now = datetime.now(timezone.utc).isoformat()
    for s in body.suppressions:
        rule_id = s.get("rule_id")
        if rule_id not in _KNOWN_RULES:
            raise HTTPException(status_code=422, detail=f"Unknown rule_id: {rule_id}")
        run_id = s.get("run_id") or None
        with db_session() as conn:
            existing = conn.execute(
                "SELECT id FROM rule_suppressions WHERE rule_id = ? AND run_id IS ?",
                (rule_id, run_id),
            ).fetchone()
            if existing:
                skipped += 1
                continue
            conn.execute(
                "INSERT INTO rule_suppressions (rule_id, run_id, reason, created_at) VALUES (?, ?, ?, ?)",
                (rule_id, run_id, (s.get("reason") or "").strip() or None, now),
            )
        added += 1

    # Enum patterns + FP threshold — wholesale replace when present.
    enum_applied = False
    if body.enum_patterns is not None:
        for platform in body.enum_patterns:
            if platform not in _PLATFORMS:
                raise HTTPException(status_code=422, detail=f"Unknown platform: {platform}")
        clean = {}
        for platform in _PLATFORMS:
            rows = body.enum_patterns.get(platform, [])
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
        enum_applied = True

    # Log anti-forensics pattern tables — wholesale replace when present.
    log_applied = False
    if body.log_patterns is not None:
        for kind in body.log_patterns:
            if kind not in _LOG_PATTERN_KINDS:
                raise HTTPException(status_code=422, detail=f"Unknown pattern kind: {kind}")
        clean_logs = {}
        for kind in _LOG_PATTERN_KINDS:
            kind_rows = body.log_patterns.get(kind, {})
            per = {}
            for platform in _PLATFORMS:
                rows = kind_rows.get(platform, [])
                cleaned = []
                for item in rows:
                    if not isinstance(item, dict):
                        continue
                    pattern = item.get("pattern")
                    label = item.get("label")
                    if isinstance(pattern, str) and pattern.strip() and isinstance(label, str) and label.strip():
                        cleaned.append({"pattern": pattern.strip(), "label": label.strip()})
                per[platform] = cleaned
            clean_logs[kind] = per
        with db_session() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('log_patterns', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps(clean_logs),),
            )
        log_applied = True

    fp_applied = False
    if body.fp_threshold is not None:
        if body.fp_threshold < 1:
            raise HTTPException(status_code=422, detail="fp_threshold must be >= 1")
        with db_session() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (FP_THRESHOLD_KEY, str(body.fp_threshold)),
            )
        fp_applied = True

    actor = auth.role_from_request(request)
    with db_session() as conn:
        audit.log(
            conn, actor, "rules.pack.import",
            target_type="rules", target_id=f"schema:{PACK_SCHEMA}",
            detail=(
                f"{tuning_applied} tuning knob(s) synced, {added} suppression(s) added "
                f"({skipped} skipped), enum_patterns={enum_applied}, "
                f"log_patterns={log_applied}, fp_threshold={fp_applied}"
            ),
        )
    return {
        "schema": PACK_SCHEMA,
        "tuning_applied": tuning_applied,
        "suppressions_added": added,
        "suppressions_skipped": skipped,
        "enum_patterns_applied": enum_applied,
        "fp_threshold_applied": fp_applied,
    }
