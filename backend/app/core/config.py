"""Application configuration — environment-driven, keys never hardcoded.

Matches the env vars specified in docs/02-BACKEND-SPEC.md. API keys live only
in `.env` (see AGENTS.md repo hygiene) and default to empty strings so the
backend runs fine without them (enrichment then reports "unknown").
"""

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # backend/
DATA_DIR = BASE_DIR / "data"

DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "outpost.db"))


def _parse_origins(raw: str) -> list[str]:
    """Accept CORS_ORIGINS as a comma list OR a JSON array of origins.

    The run doc's restart command passes the JSON-array form
    (`'["http://localhost:5174"]'`); older setups use a plain comma list. A
    naive `str.split(",")` on the JSON form yields one mangled origin
    (`["http://localhost:5174"]`) that never matches a browser origin — the
    server 200s but the frontend CORS-blocks every fetch. Parse both.
    """
    raw = (raw or "").strip()
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            return [str(o).strip() for o in parsed if str(o).strip()]
    return [o.strip() for o in raw.split(",") if o.strip()]


CORS_ORIGINS = _parse_origins(os.getenv("CORS_ORIGINS", "http://localhost:5173"))

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Enrichment cache TTL in days — free-tier quotas are small, cache aggressively.
ENRICHMENT_TTL_DAYS = int(os.getenv("ENRICHMENT_TTL_DAYS", "7"))
