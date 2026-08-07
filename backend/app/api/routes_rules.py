"""Rule tuning (roadmap 2.3) — inspect and edit detection thresholds live.

The detection engine reads `rule_tuning` on every batch (see
services/detection.py); an empty table behaves exactly like the module
defaults. This router exposes:

- GET  /rules/tuning          — every tunable knob + baseline + current value
- PUT  /rules/tuning/{param}  — set an override (validated against the type)
- DELETE /rules/tuning/{param} — restore the default

Tuning takes effect on the *next* ingested batch — no backend restart needed.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..core.db import db_session
from ..services.detection import TUNABLE_DEFAULTS

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
