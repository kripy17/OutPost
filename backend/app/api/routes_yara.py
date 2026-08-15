"""YARA signature lab — author, test, and persist custom detection rules.

- POST /yara/test      — compile a rule text and scan it against vault samples
                         (or a chosen subset) without persisting anything;
                         returns per-sample match results + which strings hit.
- GET  /yara/rules     — the persisted custom rules (parsed + source text).
- POST /yara/rules     — validate and persist a custom rule (name replaces on
                         collision); it applies to future uploads immediately.
- DELETE /yara/rules/{name} — remove a stored rule.

Rules use the YARA-subset language in services/yara.parse_rule_text (named
rule, `strings:` atoms, boolean `condition:`). The webapp's Rules page drives
these endpoints; the CLI mirrors the format via the same service.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..core.db import db_session
from ..models import samples as samples_store
from ..services import yara as yara_service

router = APIRouter(tags=["yara"])


class RuleTextIn(BaseModel):
    rule: str = Field(min_length=1, max_length=20_000)


class YaraTestIn(RuleTextIn):
    # Optional subset of sample_ids; omitted → test against every sample
    # whose bytes are stored.
    sample_ids: list[str] | None = None


class RuleIn(RuleTextIn):
    family: str = Field(default="custom", max_length=80)
    description: str = Field(default="", max_length=300)


def _load_bytes(sample_id: str) -> bytes | None:
    """Same storage contract as routes_samples._load_bytes — the sample vault
    persists raw bytes under SAMPLES_DIR/{id}.bin for static analysis and the
    signature lab to share."""
    from ..core import config

    try:
        return (config.SAMPLES_DIR / f"{sample_id}.bin").read_bytes()
    except OSError:
        return None


@router.post("/yara/test", response_model=None)
def test_rule(body: YaraTestIn) -> dict:
    """Compile the rule and scan it against stored vault samples.

    Response: { compiled, rule_name, error?, total, matched, samples: [...] }
    Each sample carries original_name, platform, size, matched, and hits
    (the string ids that matched — so the analyst sees *why*). A compile
    error returns compiled:false with the analyst-facing message; the vault
    is never touched in that case.
    """
    try:
        rule = yara_service.parse_rule_text(body.rule)
    except yara_service.RuleSyntaxError as exc:
        return {"compiled": False, "rule_name": "", "error": str(exc)}

    with db_session() as conn:
        if body.sample_ids:
            rows = []
            for sid in body.sample_ids:
                row = samples_store.get_sample(conn, sid)
                if row:
                    rows.append(row)
        else:
            rows = samples_store.list_samples(conn, q="", limit=500, offset=0)

        results = []
        matched_count = 0
        for row in rows:
            data = _load_bytes(row["sample_id"])
            if data is None:
                continue  # pre-persistence upload — no bytes to scan
            matched, hits = rule.evaluate(data)
            if matched:
                matched_count += 1
            results.append(
                {
                    "sample_id": row["sample_id"],
                    "original_name": row["original_name"],
                    "detected_platform": row["detected_platform"],
                    "size": len(data),
                    "matched": matched,
                    "hits": hits,
                }
            )

    return {
        "compiled": True,
        "rule_name": rule.name,
        "total": len(results),
        "matched": matched_count,
        "samples": results,
    }


@router.get("/yara/rules", response_model=None)
def list_rules() -> dict:
    """Persisted custom rules, parsed — each with its atoms, source text,
    family, and description (so the lab can re-open an editor on them)."""
    with db_session() as conn:
        rules = yara_service.load_custom_rules(conn)
    return {
        "count": len(rules),
        "rules": [
            {
                "name": r.name,
                "family": r.family,
                "description": r.description,
                "strings": sorted(r.strings.keys()),
                "source": r.source,
            }
            for r in rules
        ],
    }


@router.post("/yara/rules", status_code=201, response_model=None)
def save_rule(body: RuleIn) -> dict:
    """Validate the rule text; persist it (same name replaces). Applies to
    the next upload — the scanner merges custom rules on every call."""
    try:
        rule = yara_service.parse_rule_text(body.rule)
    except yara_service.RuleSyntaxError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    rule.family = (body.family or "custom").strip() or "custom"
    rule.description = (body.description or "").strip() or rule.description
    with db_session() as conn:
        yara_service.add_custom_rule(conn, rule)
    return {"name": rule.name, "strings": sorted(rule.strings.keys())}


@router.delete("/yara/rules/{name}", status_code=204)
def delete_rule(name: str) -> None:
    with db_session() as conn:
        if not yara_service.delete_custom_rule(conn, name):
            raise HTTPException(status_code=404, detail=f"Unknown custom rule: {name}")
