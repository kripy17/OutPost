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

# Tier 4 — live Postgres runtime (docs/16). Empty = SQLite (the zero-config
# default). Set to a psycopg3 URL (e.g. postgresql://user:pass@host:5432/
# outpost) and core/db.py routes through the Postgres dialect; requires
# psycopg installed (the backend's optional `pg` extra). The schema comes up
# automatically at startup via the translated DDL.
DATABASE_URL = os.getenv("OUTPOST_DATABASE_URL", "").strip()

# Stored sample bytes (static analysis + download). Each uploaded sample is
# persisted as {sample_id}.bin here so triage can re-scan it without holding
# the upload in memory. Tests override SAMPLES_DIR to a temp dir.
SAMPLES_DIR = Path(os.getenv("SAMPLES_DIR", str(DATA_DIR / "samples")))

# Run artifacts (detonation screenshots). Screenshots land under
# ARTIFACTS_DIR/<run_id>/ as shot_NNNN.png + manifest.json.
ARTIFACTS_DIR = Path(os.getenv("OUTPOST_ARTIFACTS_DIR", str(DATA_DIR / "artifacts")))

# Detonation screenshot capture (docs/10-STANDOUT-FEATURES.md #4).
# OUTPOST_SCREENSHOT_CMD is a shell-free command template whose {output}
# placeholder is replaced by the target PNG path, e.g.:
#   VBoxManage controlvm <vm> screenshotpng {output}
#   grim -o DP-1 {output}     (Wayland / wlroots)
#   scrot -z {output}         (X11)
# Unset = capture unavailable (reported honestly, never faked).
SCREENSHOT_CMD = os.getenv("OUTPOST_SCREENSHOT_CMD", "").strip()
SCREENSHOT_INTERVAL = float(os.getenv("OUTPOST_SCREENSHOT_INTERVAL", "10"))

# Volatility3 memory forensics (docs/08-INTEGRATIONS.md #7). OUTPOST_VOLATILITY_PATH
# pins an explicit vol binary; empty = look up `vol` / `volatility3` on PATH.
VOLATILITY_PATH = os.getenv("OUTPOST_VOLATILITY_PATH", "").strip()
VOLATILITY_TIMEOUT = float(os.getenv("OUTPOST_VOLATILITY_TIMEOUT", "300"))


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


CORS_ORIGINS = [
    # A wildcard origin combined with the middleware's allow_credentials=True
    # is a browser-trusted cross-origin credential leak — refuse to boot with it.
    o
    for o in _parse_origins(
        os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174")
    )
    if o != "*"
]

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# abuse.ch feeds (URLhaus / ThreatFox) are keyless but still third-party
# egress. Opt-in so a default install makes zero external calls (the
# no-config egress gate asserts this); set OUTPOST_ABUSECH_ENABLED=1 to turn
# domain/hash reputation lookups on.
ABUSECH_ENABLED = os.getenv("OUTPOST_ABUSECH_ENABLED", "").strip().lower() in (
    "1",
    "true",
    "yes",
)

# Sandbox detonation adapters (roadmap 3.3). Provider keys are optional: with
# none configured the webapp's sandbox panel falls back to a clearly-labeled
# deterministic demo detonation (same honest-fallback pattern as footprint).
# SANDBOX_PROVIDER pins the active provider ("anyrun" | "triage" | "joe");
# empty = auto-pick the first configured one.
SANDBOX_PROVIDER = os.getenv("SANDBOX_PROVIDER", "").strip().lower()
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY", "")
TRIAGE_API_KEY = os.getenv("TRIAGE_API_KEY", "")
JOE_API_KEY = os.getenv("JOE_API_KEY", "")

# Enrichment cache TTL in days — free-tier quotas are small, cache aggressively.
ENRICHMENT_TTL_DAYS = int(os.getenv("ENRICHMENT_TTL_DAYS", "7"))
