"""Postgres runtime dialect for ``core/db.py`` (Tier 4, roadmap).

OutPost ships on a single SQLite file (raw ``sqlite3`` in ``core/db.py``,
deliberately dependency-light). When ``OUTPOST_DATABASE_URL`` is set,
``get_connection()`` / ``init_db()`` route here instead and the whole backend
runs against a real Postgres server — same ``db_session()`` interface, no
caller changes. This module is a thin sqlite3-compatible shim over psycopg3:

- ``Connection.execute`` / ``executemany`` / ``executescript`` with the same
  commit/rollback/close lifecycle (and ``with conn:`` context-manager
  semantics: commit on success, rollback on error).
- cursors with ``fetchone`` / ``fetchall`` / ``fetchmany`` / ``__iter__`` /
  ``rowcount`` / ``lastrowid``.
- rows with both ``row["name"]`` and ``row[0]`` access plus ``dict(row)``,
  ``keys()``, ``len()``, iteration — the ``sqlite3.Row`` contract the app
  relies on.

plus a small translation layer that makes the app's SQLite-shaped SQL run on
Postgres untouched:

- ``?`` placeholders → ``%s`` (psycopg's client-side binding).
- ``LIKE`` → ``ILIKE`` — SQLite's ``LIKE`` is case-insensitive for ASCII;
  ``ILIKE`` keeps search behavior identical on Postgres.
- ``INSERT OR IGNORE`` → ``INSERT ... ON CONFLICT DO NOTHING`` — same
  "only actually-inserted rows count" semantics the rowcount callers depend
  on (watchlist live-alerting, run-tuning snapshot).
- ``GROUP_CONCAT(x)`` → ``string_agg(x, ',')`` with ``DISTINCT`` preserved
  (balanced-paren scan, so nested subqueries translate correctly).
- ``lastrowid`` → the shim appends ``RETURNING id`` to INSERTs into tables
  whose primary key is a single column named ``id`` (looked up once in the
  PG catalog and cached). TEXT-PK tables (runs, settings, watchlist, …) are
  untouched — no phantom ``RETURNING`` on columns that don't exist.

psycopg is imported lazily (only when a DATABASE_URL is configured), so the
zero-config SQLite default keeps its dependency-light install. The pure
translation functions are unit-tested without a server
(``backend/app/tests/test_pg_runtime.py``); the live runtime is exercised in
CI by the ``pg-runtime`` job (postgres service container →
``scripts/gate_pg_runtime.py``).
"""

from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from . import config

# ---------------------------------------------------------------------------
# SQL translation — pure string logic, unit-testable without a server
# ---------------------------------------------------------------------------


def _translate_group_concat(sql: str) -> str:
    """``GROUP_CONCAT(x)`` → ``string_agg(x, ',')`` for every occurrence.

    Uses a balanced-paren scan rather than a regex so the argument may itself
    contain parentheses — the agents page nests ``GROUP_CONCAT(run_id)``
    inside a subquery (``(SELECT GROUP_CONCAT(run_id) FROM (SELECT …))``).
    ``DISTINCT`` is preserved: ``string_agg(DISTINCT x, ',')``.
    """
    out: list[str] = []
    i = 0
    n = len(sql)
    while True:
        start = sql.find("GROUP_CONCAT(", i)
        if start == -1:
            out.append(sql[i:])
            return "".join(out)
        out.append(sql[i:start])
        open_paren = start + len("GROUP_CONCAT(") - 1
        depth = 0
        k = open_paren
        while k < n:
            ch = sql[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        if k >= n:  # unbalanced — leave as-is, let Postgres raise the real error
            out.append(sql[start:])
            return "".join(out)
        inner = sql[open_paren + 1 : k]
        stripped = inner.strip()
        if stripped.startswith("DISTINCT "):
            out.append(f"string_agg(DISTINCT {stripped[len('DISTINCT '):]}, ',')")
        else:
            out.append(f"string_agg({inner}, ',')")
        i = k + 1


def _translate(sql: str) -> str:
    """One app SQL string → Postgres-compatible form (order matters:

    1. ``INSERT OR IGNORE`` → plain INSERT with ``ON CONFLICT DO NOTHING``
       appended (the conflict target is implicit — any constraint).
    2. ``NOT LIKE`` / ``LIKE`` → ``ILIKE`` (word-boundary; ``ILIKE`` itself
       is not re-matched because there is no boundary inside the word).
    3. ``GROUP_CONCAT`` → ``string_agg``.
    4. ``?`` → ``%s`` — last, after the rewrites above, so positional params
       map 1:1 and no placeholder appears inside a rewritten fragment.
    """
    out = sql
    if "INSERT OR IGNORE" in out:
        out = out.replace("INSERT OR IGNORE INTO", "INSERT INTO", 1)
        out = out.rstrip().rstrip(";").rstrip() + " ON CONFLICT DO NOTHING"
    out = re.sub(r"\bNOT LIKE\b", "NOT ILIKE", out)
    out = re.sub(r"\bLIKE\b", "ILIKE", out)
    out = _translate_group_concat(out)
    out = out.replace("?", "%s")
    return out


_INSERT_INTO = re.compile(r"\bINSERT\s+(?:OR\s+IGNORE\s+)?INTO\s+(\w+)", re.IGNORECASE)


def _insert_table(sql: str) -> Optional[str]:
    """The target table of an INSERT statement (None for anything else)."""
    m = _INSERT_INTO.search(sql)
    return m.group(1) if m else None


def _split_statements(sql_script: str) -> list[str]:
    """Split a multi-statement DDL script into individual statements.

    SQL line comments are stripped first — the schema's comments contain
    semicolons ("…count; the run-detail UI…"), so a naive ``split(';')``
    would split mid-comment into a bogus statement (caught live in CI:
    ``syntax error at or near "the"`` from a comment fragment)."""
    cleaned = re.sub(r"--[^\n]*", "", sql_script)
    return [s.strip() for s in cleaned.split(";") if s.strip()]


# ---------------------------------------------------------------------------
# sqlite3.Row-compatible result wrapper
# ---------------------------------------------------------------------------


class PgRow:
    """One result row with both ``row["name"]`` and ``row[0]`` access.

    Also supports ``dict(row)``, ``row.keys()``, ``len(row)``, and iteration
    over values — the ``sqlite3.Row`` surface the app and tests use.
    """

    __slots__ = ("_values", "_names")

    def __init__(self, values: tuple, names: list[str]):
        self._values = tuple(values)
        self._names = list(names)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._names.index(key)]

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def keys(self) -> list[str]:
        return self._names

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            return dict(zip(self._names, self._values)) == other
        return tuple(self._values) == tuple(other)

    def __repr__(self) -> str:
        return f"PgRow({dict(zip(self._names, self._values))})"


# ---------------------------------------------------------------------------
# The cursor + connection shim
# ---------------------------------------------------------------------------


def _column_names(description: Any) -> list[str]:
    """Column names from a cursor description, tolerating both psycopg3's
    Column objects (``.name``) and plain tuples (psycopg2-style)."""
    names: list[str] = []
    for col in (description or []):
        name = getattr(col, "name", None)
        if name is None and isinstance(col, (tuple, list)) and col:
            name = col[0]
        if name is not None:
            names.append(str(name))
    return names


class _Cursor:
    """sqlite3.Cursor-compatible wrapper over one psycopg cursor."""

    def __init__(self, conn: "_PgConnection", raw: Any):
        self._conn = conn
        self._raw = raw
        self._names: list[str] = []
        self.lastrowid: Optional[int] = None

    @property
    def rowcount(self) -> int:
        return self._raw.rowcount

    @property
    def description(self) -> Any:
        return self._raw.description

    def _wrap(self, row: Any) -> PgRow:
        return PgRow(row, self._names)

    def fetchone(self) -> Optional[PgRow]:
        row = self._raw.fetchone()
        return self._wrap(row) if row is not None else None

    def fetchall(self) -> list[PgRow]:
        return [self._wrap(r) for r in self._raw.fetchall()]

    def fetchmany(self, size: int = 1) -> list[PgRow]:
        return [self._wrap(r) for r in self._raw.fetchmany(size)]

    def __iter__(self) -> Iterator[PgRow]:
        return iter(self.fetchall())

    def close(self) -> None:  # pragma: no cover — trivial passthrough
        self._raw.close()


class _PgConnection:
    """sqlite3.Connection-compatible facade over one psycopg connection.

    ``execute`` translates the SQL, appends ``RETURNING id`` for INSERTs into
    id-PK tables (so ``lastrowid`` works), and returns a ``_Cursor``.
    """

    def __init__(self, raw: Any):
        self._raw = raw
        self._pk_cache: dict[str, Optional[str]] = {}

    # -- the shim's core -----------------------------------------------------

    def execute(self, sql: str, params: Any = None) -> _Cursor:
        translated = _translate(sql)
        table = _insert_table(translated)
        cur = self._raw.cursor()
        pcur = _Cursor(self, cur)
        args = params if params is not None else ()
        if (
            table is not None
            and "RETURNING" not in translated.upper()
            and "ON CONFLICT" not in translated.upper()
            and self._primary_key(table) == "id"
        ):
            translated += " RETURNING id"
            cur.execute(translated, args)
            row = cur.fetchone()
            pcur.lastrowid = row[0] if row is not None else None
        else:
            cur.execute(translated, args)
        pcur._names = _column_names(cur.description)
        return pcur

    def executemany(self, sql: str, seq_of_params: Any) -> _Cursor:
        translated = _translate(sql)
        cur = self._raw.cursor()
        cur.executemany(translated, seq_of_params)
        pcur = _Cursor(self, cur)
        pcur._names = _column_names(cur.description)
        return pcur

    def executescript(self, sql_script: str) -> None:
        """Run a multi-statement DDL script (psycopg runs one statement per
        execute). Comment lines must be stripped before splitting on ``;``:
        the app's schema comments contain semicolons of their own
        ("…increments the rule's count; the run-detail UI reads these…"),
        which would otherwise split mid-comment into a bogus statement."""
        cur = self._raw.cursor()
        for stmt in _split_statements(sql_script):
            cur.execute(stmt)

    # -- primary-key catalog lookup (RETURNING decision) ---------------------

    def _primary_key(self, table: str) -> Optional[str]:
        """The single-column primary key of `table`, cached per connection.

        Only a single-column PK named exactly ``id`` triggers a ``RETURNING
        id`` clause — every ``lastrowid`` consumer in the app reads ``id``,
        and TEXT-PK tables (runs, settings, watchlist, …) must never get one.
        """
        if table in self._pk_cache:
            return self._pk_cache[table]
        pk: Optional[str] = None
        try:
            cur = self._raw.cursor()
            cur.execute(
                """
                SELECT a.attname
                FROM pg_index i
                JOIN pg_class t ON t.oid = i.indrelid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(i.indkey)
                WHERE t.relname = %s AND i.indisprimary AND i.indnkeyatts = 1
                """,
                (table,),
            )
            row = cur.fetchone()
            if row is not None and row[0] == "id":
                pk = "id"
        except Exception:
            pk = None
        self._pk_cache[table] = pk
        return pk

    # -- transaction lifecycle ------------------------------------------------

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()

    def __enter__(self) -> "_PgConnection":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        return False


# ---------------------------------------------------------------------------
# Factory — lazy psycopg import keeps the SQLite default dependency-free
# ---------------------------------------------------------------------------


def pg_connection() -> _PgConnection:
    """Open a shimmed psycopg connection to ``config.DATABASE_URL``."""
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover — env-specific
        raise ImportError(
            "OUTPOST_DATABASE_URL is set but psycopg is not installed — "
            "install it with: pip install 'psycopg[binary]' (the backend's "
            "`pg` optional extra)"
        ) from exc
    raw = psycopg.connect(config.DATABASE_URL)
    return _PgConnection(raw)


def pg_init_db() -> None:
    """Create the Postgres schema — the translated DDL is the final runtime
    shape (all current columns, macOS CHECK included), so a fresh PG install
    starts correct instead of running the SQLite ALTER migrations. Idempotent
    (``IF NOT EXISTS`` everywhere)."""
    from ..services.pg_migrate import translate_schema  # lazy: breaks the core↔services cycle

    with pg_connection() as conn:
        conn.executescript(translate_schema())
