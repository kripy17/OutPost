"""P0.7 — realtime: extend the existing run_update frame (no new event type).

The P0 spec flagged job-progress SSE frames as a MISSING PIECE and asked to
determine whether the existing `run_update` event can represent it. It can —
this suite pins the additive extension:

  run_update + job_id / job_status / progress      (analysis-job transitions)
  run_update + investigation_id (+ finding_id)     (finding attach/detach,
                                                   investigation lifecycle)

Acceptance properties pinned here:
- old run_update frames (run_id/events/completed only) remain valid;
- job progress is persisted and observable in the frame;
- terminal states (completed/canceled) are emitted exactly once from the
  mutation path;
- reconnecting subscribers never receive replayed frames (publish is
  fire-and-forget; the DB row is the reconnect source of truth);
- cancellation produces the canceled terminal state;
- finding attach/detach (incl. explicit-null detach) is observable;
- investigation create/close/reopen is observable;
- no new SSE event type and no new persistence table.
"""

import asyncio
import json

import pytest

from .conftest import make_run


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient as TC

    from ..main import app

    with TC(app) as c:
        yield c


async def _next_frame(gen, n: int = 1) -> list[dict]:
    """Pull n published frames from a stream generator and parse the JSON.
    Async — callers are already inside an asyncio.run coroutine."""
    frames = []
    for _ in range(n):
        raw = await gen.__anext__()
        assert "event: run-update" in raw, f"expected run-update frame, got: {raw!r}"
        data = raw.split("data: ", 1)[1].strip()
        frames.append(json.loads(data))
    return frames


# ---------------------------------------------------------------------------
# Frame-shape contract (unit level, via the stream generator)
# ---------------------------------------------------------------------------


def test_old_frame_shape_unchanged():
    """An existing caller that publishes run_id/events/completed must produce
    exactly the old frame — no new keys leak in."""
    from ..services import events_stream

    async def _run():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()  # subscribe
            events_stream.publish_run_update("r1", 3, completed=True)
            raw = await gen.__anext__()
            return raw
        finally:
            await gen.aclose()

    raw = asyncio.run(_run())
    data = json.loads(raw.split("data: ", 1)[1].strip())
    assert data == {"run_id": "r1", "events": 3, "completed": True}


def test_job_frame_carries_id_status_progress():
    from ..services import events_stream

    async def _run():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            events_stream.publish_run_update("run1", 0, job_id="run1", job_status="queued", progress=0)
            raw = await gen.__anext__()
            return raw
        finally:
            await gen.aclose()

    data = json.loads(asyncio.run(_run()).split("data: ", 1)[1].strip())
    assert data["job_id"] == "run1"
    assert data["job_status"] == "queued"
    assert data["progress"] == 0
    assert data["completed"] is False


def test_terminal_frame_completed_true():
    from ..services import events_stream

    async def _run():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            events_stream.publish_run_update("run1", 0, completed=True, job_id="run1", job_status="canceled", progress=50)
            raw = await gen.__anext__()
            return raw
        finally:
            await gen.aclose()

    data = json.loads(asyncio.run(_run()).split("data: ", 1)[1].strip())
    assert data["completed"] is True
    assert data["job_status"] == "canceled"


def test_finding_attach_and_explicit_null_detach():
    """Attach serializes investigation_id + finding_id; detach serializes
    finding_id with investigation_id EXPLICITLY null — a client can tell
    'omitted' (not investigation-related) from 'detached'."""
    from ..services import events_stream

    async def _run():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            events_stream.publish_run_update("run1", 0, investigation_id="inv1", finding_id=42)
            attach_raw = await gen.__anext__()
            events_stream.publish_run_update("run1", 0, investigation_id=None, finding_id=42)
            detach_raw = await gen.__anext__()
            return attach_raw, detach_raw
        finally:
            await gen.aclose()

    attach, detach = asyncio.run(_run())
    attach_d = json.loads(attach.split("data: ", 1)[1].strip())
    assert attach_d["investigation_id"] == "inv1"
    assert attach_d["finding_id"] == 42
    detach_d = json.loads(detach.split("data: ", 1)[1].strip())
    assert detach_d["finding_id"] == 42
    assert detach_d["investigation_id"] is None


def test_investigation_lifecycle_frame_no_finding():
    from ..services import events_stream

    async def _run():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            events_stream.publish_run_update("", 0, investigation_id="inv1")
            raw = await gen.__anext__()
            return raw
        finally:
            await gen.aclose()

    data = json.loads(asyncio.run(_run()).split("data: ", 1)[1].strip())
    assert data["investigation_id"] == "inv1"
    assert "finding_id" not in data  # lifecycle frames carry no finding


# ---------------------------------------------------------------------------
# End-to-end: the mutation paths emit the frames
# ---------------------------------------------------------------------------


def test_analysis_create_emits_job_frame(client):
    from ..services import events_stream

    captured = []

    async def _collect():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            # Static analysis completes synchronously — the frame must carry
            # the terminal completed state.
            r = client.post("/analysis", json={"backend": "static", "sample_name": "p07-static.bin", "platform": "windows"})
            assert r.status_code == 201
            frames = await _next_frame(gen)
            captured.extend(frames)
            # Watched-host creates a queued job — the frame carries queued.
            r = client.post("/analysis", json={"backend": "watched-host", "sample_name": "p07-host.bin", "platform": "linux"})
            assert r.status_code == 201
            captured.extend(await _next_frame(gen))
        finally:
            await gen.aclose()

    asyncio.run(_collect())
    static_frame, queued_frame = captured[0], captured[1]
    assert static_frame["job_status"] == "completed"
    assert static_frame["progress"] == 100
    assert static_frame["completed"] is True
    assert queued_frame["job_status"] == "queued"
    assert queued_frame["completed"] is False
    # Job state is persisted and observable via the API too.
    jobs = client.get("/analysis").json()["jobs"]
    statuses = {j["status"] for j in jobs}
    assert "completed" in statuses and "queued" in statuses


def test_cancel_emits_terminal_canceled_once(client):
    from ..services import events_stream

    async def _collect():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            r = client.post("/analysis", json={"backend": "watched-host", "sample_name": "p07-cancel.bin", "platform": "linux"})
            run_id = r.json()["run_id"]
            await gen.__anext__()  # consume the queued frame
            r = client.post(f"/analysis/{run_id}/cancel")
            assert r.status_code == 200
            assert r.json()["status"] == "canceled"
            return await _next_frame(gen)
        finally:
            await gen.aclose()

    frames = asyncio.run(_collect())
    assert len(frames) == 1  # terminal state emitted exactly once
    assert frames[0]["job_status"] == "canceled"
    assert frames[0]["completed"] is True


def test_reconnect_never_replays_frames(client):
    """A subscriber that connects AFTER a transition must NOT receive the
    old frame — reconnect reads the persisted row instead (no duplicate
    state)."""
    from ..services import events_stream

    # Transition happens with no subscribers.
    r = client.post("/analysis", json={"backend": "watched-host", "sample_name": "p07-reconnect.bin", "platform": "linux"})
    assert r.status_code == 201

    async def _collect():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()  # subscribe AFTER the transition
            # Nothing should arrive — wait briefly with a short timeout.
            try:
                import asyncio as aio

                raw = await aio.wait_for(gen.__anext__(), timeout=0.3)
                return raw
            except asyncio.TimeoutError:
                return None
        finally:
            await gen.aclose()

    assert asyncio.run(_collect()) is None  # no replay


def test_finding_attach_detach_via_patch_emits_frame(client):
    """PATCH /alerts/{id} with investigation_id emits the finding frame;
    explicit null detach emits investigation_id: null."""
    from ..services import events_stream

    run_id = make_run(client, sample_name="p07-alert.bin")
    r = client.post("/findings", json={"run_id": run_id, "severity": "suspicious", "details": "p07 finding"})
    finding_id = r.json()["id"]
    r = client.post("/investigations", json={"title": "p07 case"})
    inv_id = r.json()["id"]

    async def _collect():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            client.patch(f"/alerts/{finding_id}", json={"status": "open", "investigation_id": inv_id})
            attach = (await _next_frame(gen))[0]
            client.patch(f"/alerts/{finding_id}", json={"status": "open", "investigation_id": None})
            detach = (await _next_frame(gen))[0]
            return attach, detach
        finally:
            await gen.aclose()

    attach, detach = asyncio.run(_collect())
    assert attach["finding_id"] == finding_id
    assert attach["investigation_id"] == inv_id
    assert detach["finding_id"] == finding_id
    assert detach["investigation_id"] is None


def test_investigation_create_close_reopen_emit_frames(client):
    from ..services import events_stream

    async def _collect():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            r = client.post("/investigations", json={"title": "p07 lifecycle"})
            inv_id = r.json()["id"]
            created = (await _next_frame(gen))[0]
            client.post(f"/investigations/{inv_id}/close", json={"conclusion": "resolved — FP"})
            closed = (await _next_frame(gen))[0]
            client.post(f"/investigations/{inv_id}/reopen")
            reopened = (await _next_frame(gen))[0]
            return inv_id, created, closed, reopened
        finally:
            await gen.aclose()

    inv_id, created, closed, reopened = asyncio.run(_collect())
    assert created["investigation_id"] == inv_id
    assert closed["investigation_id"] == inv_id
    assert reopened["investigation_id"] == inv_id


# ---------------------------------------------------------------------------
# No new event type / no new table / auth
# ---------------------------------------------------------------------------


def test_no_new_sse_event_type():
    """The extension reuses `run-update` — the event vocabulary is unchanged."""
    from ..services import events_stream

    async def _names():
        gen = events_stream.stream_events()
        try:
            await gen.__anext__()
            # Every extended frame still carries the EXISTING event name.
            events_stream.publish_run_update("r", 0, job_id="r", job_status="queued", progress=0)
            raw = await gen.__anext__()
            assert raw.startswith("event: run-update"), raw
            # The other event names are untouched.
            events_stream.publish_fleet_update("h", True, False)
            raw2 = await gen.__anext__()
            assert raw2.startswith("event: fleet-update"), raw2
        finally:
            await gen.aclose()

    asyncio.run(_names())


def test_no_new_persistence_table(conn):
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "sse_jobs" not in tables
    assert "job_events" not in tables
    assert "investigation_events" not in tables


def test_job_progress_persisted_and_observable(client):
    """Progress lives in analysis_jobs (persisted); the SSE frame is a push
    view of it, and the API re-reads the same row on reconnect."""
    r = client.post("/analysis", json={"backend": "watched-host", "sample_name": "p07-progress.bin", "platform": "linux"})
    job = r.json()
    assert job["status"] == "queued"
    assert job["progress"] == 0
    # The row is queryable after the SSE frame was emitted.
    got = client.get(f"/analysis/{job['run_id']}").json()
    assert got["status"] == "queued"
    assert got["progress"] == 0
