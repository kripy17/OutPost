"""Tests for per-run analyst notes (docs/10 Tier 2 #7)."""

from .conftest import make_run


def test_notes_empty_on_new_run(client):
    run_id = make_run(client)
    assert client.get(f"/runs/{run_id}/notes").json() == []


def test_notes_add_and_list(client):
    run_id = make_run(client)

    resp = client.post(f"/runs/{run_id}/notes", json={"note": "Hypothesis: same C2 as variant A"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["run_id"] == run_id
    assert body["note"] == "Hypothesis: same C2 as variant A"
    assert body["created_at"]

    client.post(f"/runs/{run_id}/notes", json={"note": "Follow up on rename-burst pid"})

    notes = client.get(f"/runs/{run_id}/notes").json()
    assert len(notes) == 2
    # Chronological — a running log of observations.
    assert [n["note"] for n in notes] == [
        "Hypothesis: same C2 as variant A",
        "Follow up on rename-burst pid",
    ]


def test_notes_empty_or_whitespace_rejected(client):
    run_id = make_run(client)
    assert client.post(f"/runs/{run_id}/notes", json={"note": ""}).status_code == 422
    assert client.post(f"/runs/{run_id}/notes", json={"note": "   "}).status_code == 422


def test_notes_unknown_run_404(client):
    assert client.get("/runs/nope/notes").status_code == 404
    assert client.post("/runs/nope/notes", json={"note": "x"}).status_code == 404
