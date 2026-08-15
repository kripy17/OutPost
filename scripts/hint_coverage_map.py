#!/usr/bin/env python3
"""Single source of truth: hint-emitting gate -> repair self-test coverage.

Every gate under scripts/ that prints a `→ fix:` hint must be covered by a
self-test that pins the hint AND proves it repairs (exit-1 + hint presence +
applied-fix-goes-green). That pairing lives in exactly ONE place — this
module — and is shared by three consumers:

  * the hint-coverage guard (gate_hint_coverage.py) — requires every
    hint-emitting gate to appear in HINT_COVERAGE and every mapped
    self-test to be wired into verify.sh;
  * the two repair self-tests (test_image_budget_hints.py,
    test_badge_hints.py) — each resolves the gate file it pins from this
    map via gate_for(), instead of hardcoding its own gate path.

Adding a new hint-emitting gate is therefore a one-line change in
HINT_COVERAGE: write the paired self-test (it derives its gate source from
this map), register the pair here, and wire the test into verify.sh — the
guard and the new test both pick the mapping up automatically.
"""

# gate file (relative to scripts/) -> self-test (relative to scripts/) that
# pins its hints and proves they repair.
HINT_COVERAGE = {
    "gate_image_budget_docs.py": "test_image_budget_hints.py",
    "refresh-badges.sh": "test_badge_hints.py",
}


def gate_for(test_name: str) -> str:
    """The gate file mapped to `test_name` (raises when unmapped).

    Self-tests call this with their own filename so the gate they pin is
    derived from the map — the pairing never lives in the test itself.
    """
    for gate, test in HINT_COVERAGE.items():
        if test == test_name:
            return gate
    raise KeyError(
        f"no gate mapped to self-test {test_name!r} — register the pair in "
        "scripts/hint_coverage_map.py:HINT_COVERAGE"
    )
