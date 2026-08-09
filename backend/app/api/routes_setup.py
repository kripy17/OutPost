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

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..core.db import db_session

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
