"""Tier 4 Postgres migration path (roadmap) — the pure core.

Locks the port contract without needing a live Postgres:
- translate_schema turns the shipped SQLite DDL into valid Postgres DDL
  (identity keys, the macOS CHECK the runtime applies, no SQLite-only tokens).
- copy_format encodes values in Postgres COPY text format — NULL vs empty
  string stay distinct, backslash/tab/newline escape, a literal ``\\N``
  string can never be mistaken for NULL.
- export_table streams rows in the exact format load.sql consumes, and
  build_load_sql wires schema + data into one transactional psql script.
"""

import re
import sqlite3

from app.core.db import SCHEMA
from app.core.db_pg import _split_statements
from app.services import pg_migrate

# ---------------------------------------------------------------------------
# Schema translation
# ---------------------------------------------------------------------------


def test_translate_schema_swaps_autoincrement_for_identity():
    pg = pg_migrate.translate_schema()
    assert "BIGSERIAL PRIMARY KEY" in pg
    assert "INTEGER PRIMARY KEY AUTOINCREMENT" not in pg
    # Every table survives, every index survives.
    assert len(pg_migrate.tables_in_schema()) == len(pg_migrate.tables_in_schema(pg))


def test_translate_schema_applies_macos_check_the_runtime_does():
    # The SCHEMA string predates the macOS CHECK rebuild core/db.py applies
    # at runtime; the translated DDL must match the final runtime shape.
    pg = pg_migrate.translate_schema()
    assert "CHECK(platform IN ('windows', 'linux', 'macos'))" in pg
    assert "CHECK(platform IN ('windows', 'linux'))" not in pg


def test_translate_schema_keeps_constraints_and_foreign_keys():
    pg = pg_migrate.translate_schema()
    # CHECK constraints and REFERENCES survive verbatim.
    assert "CHECK(status IN ('open', 'acknowledged', 'resolved'))" in pg
    assert "REFERENCES runs(run_id)" in pg
    assert "CREATE TABLE IF NOT EXISTS" in pg
    assert "CREATE INDEX IF NOT EXISTS" in pg


def test_pg_ddl_declares_fk_targets_before_referencers():
    """Postgres resolves FK targets at CREATE TABLE time (SQLite resolves
    them lazily), so the translated DDL must declare every referenced table
    before the table that references it.

    Regression: the P0 alerts.investigation_id FK referenced `investigations`
    while that table was declared at the schema tail — SQLite was fine, but
    the pg-runtime job's init_db() failed with "relation investigations does
    not exist". Self-references (recursive FKs) are legal on PG and skipped.
    """
    pg = pg_migrate.translate_schema()
    declared: set[str] = set()
    for stmt in _split_statements(pg):
        m = re.search(r"CREATE TABLE IF NOT EXISTS (\w+)", stmt)
        if not m:
            continue
        table = m.group(1)
        targets = set(re.findall(r"REFERENCES (\w+)\s*\(", stmt)) - {table}
        missing = targets - declared
        assert not missing, (
            f"{table} references {sorted(missing)} before they are declared — "
            "move the referenced table earlier in SCHEMA (Postgres requires "
            "FK targets to exist at CREATE TABLE time)"
        )
        declared.add(table)


def test_tables_in_schema_matches_runtime_tables(tmp_path):
    # The exporter's table list is introspected from the live DB, but the DDL
    # comes from SCHEMA — prove the two agree on a fresh database.
    db = sqlite3.connect(tmp_path / "fresh.db")
    db.executescript(SCHEMA)
    from_schema = set(pg_migrate.tables_in_schema())
    from_runtime = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    assert from_schema == from_runtime


# ---------------------------------------------------------------------------
# COPY text format
# ---------------------------------------------------------------------------


def test_copy_format_null_vs_empty_string():
    assert pg_migrate.copy_format(None) == "\\N"
    assert pg_migrate.copy_format("") == ""
    # A literal backslash-N string must load as data, not NULL.
    assert pg_migrate.copy_format("\\N") == "\\\\N"


def test_copy_format_escapes_copy_specials():
    assert pg_migrate.copy_format("a\tb") == "a\\tb"
    assert pg_migrate.copy_format("a\nb") == "a\\nb"
    assert pg_migrate.copy_format("a\rb") == "a\\rb"
    assert pg_migrate.copy_format("a\\b") == "a\\\\b"


def test_copy_format_scalars():
    assert pg_migrate.copy_format(42) == "42"
    assert pg_migrate.copy_format(0) == "0"
    assert pg_migrate.copy_format(1.5) == "1.5"
    assert pg_migrate.copy_format(True) == "t"
    assert pg_migrate.copy_format(False) == "f"


# ---------------------------------------------------------------------------
# Export + load script
# ---------------------------------------------------------------------------


def _make_db(tmp_path) -> tuple[sqlite3.Connection, str]:
    path = str(tmp_path / "src.db")
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS things (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            note TEXT
        );
        """
    )
    db.executemany(
        "INSERT INTO things (name, note) VALUES (?, ?)",
        [("plain", "ok"), ("tab\there", None), ("nl\nhere", "\\N"), ("bs\\here", ""), ("quote'x\"y", "back\\slash")],
    )
    db.commit()
    return db, path


def test_export_table_streams_copy_format_rows(tmp_path):
    db, _ = _make_db(tmp_path)
    lines = list(pg_migrate.export_table(db, "things"))
    db.close()
    # 5 rows; each is one line ending in \n.
    assert len(lines) == 5
    assert all(line.endswith("\n") for line in lines)
    # The escaping contract on the trickiest rows (id, name, note):
    assert "\t".join(["2", "tab\\there", "\\N"]) in lines[1]
    assert "\t".join(["3", "nl\\nhere", "\\\\N"]) in lines[2]
    assert "\t".join(["4", "bs\\\\here", ""]) in lines[3]
    assert "\t".join(["5", "quote'x\"y", "back\\\\slash"]) in lines[4]
    # Row 1 — plain values, note present.
    assert "\t".join(["1", "plain", "ok"]) in lines[0]


def test_row_count_and_load_sql(tmp_path):
    db, _ = _make_db(tmp_path)
    assert pg_migrate.row_count(db, "things") == 5
    db.close()

    load = pg_migrate.build_load_sql(["things", "alerts"], data_dir="data")
    assert "\\i schema.sql" in load
    assert "BEGIN;" in load
    assert "COMMIT;" in load
    assert "\\copy things FROM 'data/things.copy' WITH (FORMAT text)" in load
    assert "\\copy alerts FROM 'data/alerts.copy' WITH (FORMAT text)" in load
