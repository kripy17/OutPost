"""SQLite → Postgres migration path (Tier 4, roadmap).

OutPost ships on a single SQLite file (`core/db.py` — raw ``sqlite3`` by
design). That is the scale ceiling: a real fleet (dozens of hosts × 10k
events/hr) wants Postgres. This module is the pure core of the port:

- ``translate_schema``  — the shipped SQLite DDL (``core.db.SCHEMA``) → the
  equivalent Postgres DDL, statement by statement.
- ``copy_format``       — one Python value → Postgres COPY text format
  (tab-separated, backslash-escaped, ``\\N`` = NULL), so data files load
  with ``\\copy … WITH (FORMAT text)`` and NULL/empty-string stay distinct.
- ``export_table``      — stream a table's rows as COPY-format lines.
- ``build_load_sql``    — a psql script that applies schema.sql then loads
  every exported table with ``\\copy``.

The exporter is deliberately **stdlib-only** (sqlite3 + csv-style escaping):
no psycopg dependency, no new runtime requirement — the artifacts it writes
(schema.sql + data/*.copy + load.sql) are consumed by ``psql`` on the target,
and the whole runbook is documented in docs/16-POSTGRES-MIGRATION.md.

Design contract: the port preserves *behavior*, not style. Timestamps stay
TEXT (ISO-8601 strings the code already parses), JSON payloads stay TEXT
(JSONB is a documented upgrade path, not a blocker), every table/index/CHECK
migrates 1:1 — the backend's queries are all simple, so the data is what
matters.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Iterator

from ..core.db import SCHEMA

# ---------------------------------------------------------------------------
# Schema translation — the shipped SQLite DDL → Postgres DDL
# ---------------------------------------------------------------------------

# ``INTEGER PRIMARY KEY AUTOINCREMENT`` (the only AUTOINCREMENT use in the
# schema) → Postgres identity. BIGSERIAL keeps the API's int ids, and rows
# load in order so id continuity holds for FK-referencing tables.
_AUTOINCREMENT = re.compile(r"\bINTEGER PRIMARY KEY AUTOINCREMENT\b")
# The SCHEMA string predates the macOS CHECK rebuild that core/db.py applies
# at runtime (SQLite can't ALTER a CHECK, so every DB gets rebuilt). The
# translated DDL must match the *final runtime* shape, so the same drift is
# fixed textually — a fresh Postgres install gets 'macos' from the start.
_MACOS_CHECK = re.compile(r"CHECK\(platform IN \('windows', 'linux'\)\)", re.IGNORECASE)
# SQLite-only tokens that must never reach Postgres.
_STRICT = re.compile(r"\bSTRICT\b")


def translate_schema(sqlite_schema: str = SCHEMA) -> str:
    """The Postgres DDL for the shipped schema — same tables, same columns,
    same CHECKs and indexes, with the SQLite-only pieces swapped:

    - ``INTEGER PRIMARY KEY AUTOINCREMENT`` → ``BIGSERIAL PRIMARY KEY``
    - the runs.platform CHECK gains ``'macos'`` (the runtime rebuild the
      SQLite path applies — fresh PG installs start correct instead of
      migrating later)
    - ``STRICT`` table option (if ever used) is dropped
    """
    out = _AUTOINCREMENT.sub("BIGSERIAL PRIMARY KEY", sqlite_schema)
    out = _MACOS_CHECK.sub("CHECK(platform IN ('windows', 'linux', 'macos'))", out)
    out = _STRICT.sub("", out)
    return out


def tables_in_schema(sqlite_schema: str = SCHEMA) -> list[str]:
    """Ordered table names as declared in the schema (creation order)."""
    return re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", sqlite_schema)


# ---------------------------------------------------------------------------
# COPY text format — one value → one field
# ---------------------------------------------------------------------------

def copy_format(value: object) -> str:
    """Encode one value in Postgres COPY *text* format.

    - ``None`` → ``\\N`` (NULL) — distinct from the empty string.
    - ints/ints-as-float → plain decimal.
    - strings → escaped: backslash, tab, newline, CR. A literal two-char
      ``\\N`` string becomes ``\\\\N`` (escaped backslash + N) so it loads as
      data, not NULL.
    - anything else (bool, bytes, datetime) → str() — none appear in the
      current schema, but a future BLOB/JSONB column must not silently corrupt.
    """
    if value is None:
        return "\\N"
    if isinstance(value, bool):
        return "t" if value else "f"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    text = str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def export_table(conn: sqlite3.Connection, table: str, columns: Iterable[str] | None = None) -> Iterator[str]:
    """Yield every row of `table` as one COPY-format line.

    Column order is the cursor's (``SELECT *`` order == CREATE order), which
    matches the ``\\copy table FROM …`` column-less load.
    """
    cols = list(columns) if columns is not None else None
    sql = "SELECT * FROM %s" % table
    if cols:
        sql = "SELECT %s FROM %s" % (", ".join(f'"{c}"' for c in cols), table)
    cur = conn.execute(sql)
    for row in cur:
        yield "\t".join(copy_format(v) for v in row) + "\n"


def row_count(conn: sqlite3.Connection, table: str) -> int:
    return conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]


# ---------------------------------------------------------------------------
# The load script — psql consumes it
# ---------------------------------------------------------------------------

def build_load_sql(tables: Iterable[str], data_dir: str = "data") -> str:
    """A psql script: apply the schema, then ``\\copy`` each table from its
    data file inside one transaction (all-or-nothing load).

    `data_dir` is relative to the script's location (load.sql sits next to
    data/ after an export).
    """
    lines = ["-- OutPost — load the exported SQLite data into Postgres.",
             "-- Run:  psql \"$DATABASE_URL\" -f load.sql",
             "-- Applies schema.sql first (idempotent), then loads every",
             "-- data/<table>.copy inside one transaction.",
             "\\i schema.sql",
             "BEGIN;"]
    for table in tables:
        # FORMAT text: COPY's native text format defaults to \N for NULL,
        # which is exactly what copy_format() writes — no NULL option needed.
        lines.append(
            f"\\copy {table} FROM '{data_dir}/{table}.copy' WITH (FORMAT text)"
        )
    lines.append("COMMIT;")
    return "\n".join(lines) + "\n"
