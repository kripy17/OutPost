"""The Postgres runtime dialect (``core/db_pg``) — pure translation tests.

No Postgres server and no psycopg required: ``_translate`` and the
``RETURNING`` decision are pure string logic, and ``PgRow`` is a plain
wrapper. The live runtime (schema init + real queries through the shim) is
exercised for real in CI — the ``pg-runtime`` job spins up a postgres
service container and runs ``scripts/gate_pg_runtime.py`` against it.
"""

from app.core import db_pg


# -- placeholders ------------------------------------------------------------


def test_placeholders_convert():
    assert db_pg._translate("SELECT * FROM runs WHERE run_id = ?") == (
        "SELECT * FROM runs WHERE run_id = %s"
    )


def test_placeholders_multiple_and_limit():
    sql = "SELECT * FROM alerts WHERE run_id = ? AND severity = ? ORDER BY id LIMIT ? OFFSET ?"
    assert db_pg._translate(sql) == (
        "SELECT * FROM alerts WHERE run_id = %s AND severity = %s "
        "ORDER BY id LIMIT %s OFFSET %s"
    )


# -- LIKE → ILIKE (SQLite LIKE is case-insensitive; keep the behavior) ------


def test_like_becomes_ilike():
    out = db_pg._translate("SELECT * FROM events WHERE process_name LIKE ?")
    assert out == "SELECT * FROM events WHERE process_name ILIKE %s"


def test_not_like_becomes_not_ilike():
    out = db_pg._translate("SELECT * FROM runs WHERE sample_name NOT LIKE ?")
    assert out == "SELECT * FROM runs WHERE sample_name NOT ILIKE %s"


def test_ilike_not_double_mapped_and_escape_preserved():
    sql = "SELECT * FROM samples WHERE original_name LIKE ? ESCAPE '\\' OR sha256 LIKE ?"
    out = db_pg._translate(sql)
    assert out.count("ILIKE") == 2
    assert "ESCAPE '\\'" in out
    # a literal ILIKE must not be re-matched by the LIKE rule
    assert db_pg._translate("SELECT 1 WHERE 'a' ILIKE 'A'") == "SELECT 1 WHERE 'a' ILIKE 'A'"


# -- INSERT OR IGNORE → ON CONFLICT DO NOTHING ------------------------------


def test_insert_or_ignore():
    out = db_pg._translate(
        "INSERT OR IGNORE INTO run_tuning_snapshot (run_id, params) VALUES (?, ?)"
    )
    assert out == (
        "INSERT INTO run_tuning_snapshot (run_id, params) VALUES (%s, %s) "
        "ON CONFLICT DO NOTHING"
    )


def test_insert_or_ignore_trailing_semicolon_stripped():
    out = db_pg._translate(
        "INSERT OR IGNORE INTO watchlist_hits (run_id, ioc_type, ioc_value, first_seen) "
        "VALUES (?, ?, ?, ?);"
    )
    assert out.endswith("ON CONFLICT DO NOTHING")
    assert "; ON CONFLICT" not in out


def test_plain_insert_untouched_by_or_ignore_rule():
    out = db_pg._translate("INSERT INTO alerts (run_id, rule_id) VALUES (?, ?)")
    assert out == "INSERT INTO alerts (run_id, rule_id) VALUES (%s, %s)"


# -- GROUP_CONCAT → string_agg ----------------------------------------------


def test_group_concat_distinct():
    assert db_pg._translate(
        "SELECT GROUP_CONCAT(DISTINCT e.platform) AS platforms FROM events e"
    ) == "SELECT string_agg(DISTINCT e.platform, ',') AS platforms FROM events e"


def test_group_concat_with_function_arg():
    out = db_pg._translate(
        "SELECT GROUP_CONCAT(DISTINCT COALESCE(e.log_source, 'webapp')) AS channels FROM events e"
    )
    assert out == (
        "SELECT string_agg(DISTINCT COALESCE(e.log_source, 'webapp'), ',') AS channels "
        "FROM events e"
    )


def test_group_concat_nested_subquery():
    """The agents-page shape: GROUP_CONCAT(run_id) over a GROUP BY subquery —
    the balanced-paren scan must not swallow the FROM subquery. The inner
    query uses GROUP BY run_id ORDER BY MAX(timestamp) (not SELECT DISTINCT
    + ORDER BY timestamp), which is legal on both SQLite and Postgres."""
    sql = (
        "SELECT (SELECT GROUP_CONCAT(run_id) FROM "
        "(SELECT run_id FROM events WHERE host_id = e.host_id "
        "GROUP BY run_id ORDER BY MAX(timestamp) DESC LIMIT 5)) AS recent_run_ids FROM events e"
    )
    expected = (
        "SELECT (SELECT string_agg(run_id, ',') FROM "
        "(SELECT run_id FROM events WHERE host_id = e.host_id "
        "GROUP BY run_id ORDER BY MAX(timestamp) DESC LIMIT 5)) AS recent_run_ids FROM events e"
    )
    assert db_pg._translate(sql) == expected


# -- INSERT target + RETURNING decision -------------------------------------


def test_insert_table():
    assert db_pg._insert_table("INSERT INTO alerts (run_id) VALUES (?)") == "alerts"
    assert db_pg._insert_table("INSERT INTO events (run_id) VALUES (?)") == "events"
    assert db_pg._insert_table("SELECT 1") is None
    assert db_pg._insert_table("UPDATE alerts SET status = 'open'") is None


def test_returning_applied_only_when_table_has_id_pk():
    """The shim appends RETURNING id only for single-column-PK-named-id
    tables; TEXT-PK tables (run_tuning_snapshot, watchlist_hits, runs) and
    ON CONFLICT statements never get one."""
    assert db_pg._insert_table("INSERT INTO alerts (run_id) VALUES (?)") == "alerts"
    assert db_pg._insert_table("INSERT INTO runs (run_id, sample_name) VALUES (?, ?)") == "runs"
    # the shim's guard combines: table has id PK  AND  no RETURNING  AND  no ON CONFLICT
    for sql in (
        "INSERT INTO alerts (run_id) VALUES (?)",
        "INSERT INTO run_notes (run_id, note) VALUES (?, ?)",
        "INSERT INTO rule_suppressions (rule_id, run_id) VALUES (?, ?)",
        "INSERT INTO audit_log (ts, actor, action) VALUES (?, ?, ?)",
    ):
        assert db_pg._insert_table(sql) is not None
    # OR IGNORE sites translate to ON CONFLICT DO NOTHING → never RETURNING
    assert "ON CONFLICT" in db_pg._translate(
        "INSERT OR IGNORE INTO watchlist_hits (run_id, ioc_type) VALUES (?, ?)"
    )
    # upserts keep their existing ON CONFLICT clause and gain no RETURNING
    out = db_pg._translate(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    )
    assert out.endswith("DO UPDATE SET value = excluded.value")


# -- PgRow: sqlite3.Row contract ---------------------------------------------


def test_pgrow_key_and_index_access():
    row = db_pg.PgRow(("a", 42), ["name", "n"])
    assert row["name"] == "a"
    assert row[1] == 42
    assert row[0] == "a"
    assert len(row) == 2
    assert list(row) == ["a", 42]
    assert list(row.keys()) == ["name", "n"]


def test_pgrow_dict_compat():
    row = db_pg.PgRow(("x", 7), ["k", "v"])
    assert dict(row) == {"k": "x", "v": 7}


def test_pgrow_equality():
    assert db_pg.PgRow(("x", 7), ["k", "v"]) == {"k": "x", "v": 7}


# -- executescript statement splitting ---------------------------------------


def test_split_statements_ignores_comment_semicolons():
    """Regression: the schema's comments contain their own semicolons
    ("…count; the run-detail UI reads these to…") — a naive split would
    produce a bogus standalone statement and CI caught it live
    (``syntax error at or near "the"``)."""
    script = """
-- False-positive feedback loop: per-rule FP counters. Every "mark as false
-- positive" increments the rule's count; the run-detail UI reads these to
-- suggest threshold nudges / suppressions for noisy rules.
CREATE TABLE IF NOT EXISTS rule_fp (
    rule_id TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 1,
    last_fp_at TEXT NOT NULL
);

-- Inline comment with; semicolon.
CREATE INDEX IF NOT EXISTS idx_allowlist_run ON run_allowlist(run_id);
"""
    stmts = db_pg._split_statements(script)
    assert len(stmts) == 2, stmts
    assert stmts[0].startswith("CREATE TABLE IF NOT EXISTS rule_fp")
    assert stmts[1].startswith("CREATE INDEX IF NOT EXISTS idx_allowlist_run")


def test_split_statements_plain_script():
    script = "CREATE TABLE a (id BIGSERIAL PRIMARY KEY);\nCREATE INDEX i1 ON a(id);\n"
    assert db_pg._split_statements(script) == [
        "CREATE TABLE a (id BIGSERIAL PRIMARY KEY)",
        "CREATE INDEX i1 ON a(id)",
    ]


def test_split_statements_full_schema_starts_are_creates():
    """The whole translated DDL must split into statements that all begin
    with CREATE — a comment fragment leaking through would fail here."""
    from app.core.db import SCHEMA
    from app.services.pg_migrate import translate_schema

    for stmt in db_pg._split_statements(translate_schema(SCHEMA)):
        assert stmt.startswith("CREATE "), stmt[:60]


# -- executemany rowcount (psycopg3 keeps only the last statement's) --------


def test_executemany_rowcount_sums():
    """psycopg3 leaves rowcount at the LAST statement's count after
    executemany; sqlite3's is undefined. The shim sums explicitly so a
    DELETE-by-list consumer (routes_runs.py:57) gets the total affected.
    No psycopg needed — a fake raw cursor records the calls."""

    class _FakeRawCur:
        rowcount = 1
        description = None

        def execute(self, sql, params=None):
            pass

        def fetchone(self):
            return None

    class _FakeRawConn:
        def cursor(self):
            return _FakeRawCur()

    conn = db_pg._PgConnection(_FakeRawConn())
    cur = conn.executemany(
        "DELETE FROM enrichment_cache WHERE ip = ?", [("9.9.9.9",), ("8.8.8.8",)]
    )
    assert cur.rowcount == 2, cur.rowcount
