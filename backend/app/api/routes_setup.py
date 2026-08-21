"""First-run onboarding (roadmap polish) — the welcome screen's two paths.

- POST /setup/onboard  {choice: "demo" | "empty"}

A fresh install has zero sessions and no recorded choice, so `/meta` reports
`first_run: true` and the webapp shows the welcome screen instead of an empty
deck. Choosing **demo** runs the same seed the CLI's `seed_demo` module uses
(realistic detonation + campaigns + alerts, `demo_mode` set so the banner
labels it honestly); choosing **empty** just records the choice and leaves
the console empty for real host telemetry. Either way the choice is stored,
so the welcome never reappears — new installs never silently show demo data
as real.
"""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..core.db import db_session
from ..models import iocs as iocs_store

router = APIRouter(tags=["setup"])


class OnboardIn(BaseModel):
    choice: str = Field(pattern="^(demo|empty)$", description="demo = seed the labeled demo campaign; empty = start clean")


@router.post("/setup/onboard", response_model=None)
def onboard(body: OnboardIn) -> dict:
    """Record the first-run choice; `demo` also seeds the labeled campaign."""
    from contextlib import redirect_stdout
    from io import StringIO

    if body.choice == "demo":
        # Same seed the CLI runs — in-process, stdout suppressed so the
        # server log doesn't fill with the seed's banner lines.
        from ..seed_demo import main as seed_demo_main

        with redirect_stdout(StringIO()):
            seed_demo_main()
        demo_mode = "1"
    else:
        demo_mode = "0"

    with db_session() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('onboarding', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (body.choice,),
        )
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('demo_mode', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (demo_mode,),
        )

    return {"status": "ok", "choice": body.choice, "demo_mode": body.choice == "demo"}


class ResetIn(BaseModel):
    scope: str = Field(default="demo", description="demo = keep real host sessions; all = complete wipe")
    purge_samples: bool = Field(default=False, description="Whether to also wipe samples in vault")


@router.post("/setup/reset", response_model=None)
def reset_store(body: ResetIn | None = None) -> dict:
    """Start fresh — wipe every run that isn't local-host telemetry (or all runs on scope='all').

    Keeps only runs whose events were shipped by THIS machine's collector
    (events tagged `host_id` == the local host id: lowercased hostname, or
    OUTPOST_HOST_ID when set). Seeds, webapp-synthetic detonations, sandbox
    demos, CLI test runs, and simulated host-watch sessions are deleted along
    with their events, alerts, notes, allowlists, and watchlist hits. Flips
    `demo_mode` off so the banner stops labeling the store as seeded.

    Auth-gated like every non-public path: with role passwords configured this
    needs a token; zero-config default has no barrier.
    """
    import os
    import socket

    from ..core import config
    from ..models.run import SYNTHETIC_SOURCES

    scope = body.scope if body else "demo"
    purge_samples = body.purge_samples if body else False

    host_id = os.getenv("OUTPOST_HOST_ID", "").strip() or socket.gethostname().lower()
    with db_session() as conn:
        marks_syn = ",".join("?" for _ in SYNTHETIC_SOURCES)
        if scope == "all":
            kept = set()
        else:
            kept = {
                r[0]
                for r in conn.execute(
                    f"SELECT DISTINCT r.run_id FROM runs r JOIN events e ON e.run_id = r.run_id WHERE e.host_id = ? AND r.source NOT IN ({marks_syn})",
                    (host_id, *SYNTHETIC_SOURCES),
                )
            }
        all_runs = [r[0] for r in conn.execute("SELECT run_id FROM runs")]
        doomed = [rid for rid in all_runs if rid not in kept]
        counts: dict[str, int] = {"deleted_runs": len(doomed)}
        if doomed:
            marks = ",".join("?" * len(doomed))
            # IOC linkage first — ioc_findings has an FK into alerts, and
            # provenance must not outlive the evidence it points at (P3.1).
            counts.update(iocs_store.purge_for_runs(conn, doomed))
            for table in ("investigation_refs",):
                conn.execute(f"DELETE FROM {table} WHERE ref_type = 'run' AND ref_id IN ({marks})", doomed)
            for table in ("analysis_jobs", "rule_suppressions", "alerts", "run_notes", "run_allowlist", "watchlist_hits"):
                counts[f"deleted_{table}"] = conn.execute(f"DELETE FROM {table} WHERE run_id IN ({marks})", doomed).rowcount
            counts["deleted_events"] = conn.execute(f"DELETE FROM events WHERE run_id IN ({marks})", doomed).rowcount
            counts["deleted_runs"] = conn.execute(f"DELETE FROM runs WHERE run_id IN ({marks})", doomed).rowcount

        if purge_samples or scope == "all":
            counts["deleted_samples"] = conn.execute("DELETE FROM samples").rowcount
            if config.SAMPLES_DIR.exists():
                for f in config.SAMPLES_DIR.glob("*.bin"):
                    try:
                        f.unlink()
                    except Exception:
                        pass

        # Seeded data is gone — the store is no longer demo-labeled.
        conn.execute("DELETE FROM settings WHERE key = 'demo_mode'")

    return {
        "status": "ok",
        "host_id": host_id,
        "kept_runs": len(kept),
        "demo_mode": False,
        **counts,
    }
