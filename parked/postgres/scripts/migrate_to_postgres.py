#!/usr/bin/env python3
"""OutPost SQLite → Postgres migration tool (Tier 4).

Exports the SQLite database into Postgres-loadable artifacts — a translated
schema (schema.sql), one COPY-format data file per table (data/<table>.copy),
and a psql load script (load.sql) — and, when a Postgres URL is given, can
run the import and verify row counts on the other side.

Why files instead of a live connection: the migration must not require new
runtime dependencies. The exporter is stdlib-only (sqlite3); the target side
only needs `psql`, which any Postgres host already has. The output directory
is fully self-contained, so the load can run from a different machine than
the one holding the SQLite file.

Runbook (see docs/16-POSTGRES-MIGRATION.md for the full port):

  1. Export:    .venv/bin/python scripts/migrate_to_postgres.py
                (writes ./pg-migrate/{schema.sql,data/*.copy,load.sql})
  2. Create:    createdb outpost
  3. Load:      psql "$DATABASE_URL" -f pg-migrate/load.sql
  4. Verify:    .venv/bin/python scripts/migrate_to_postgres.py --verify \\
                  --psql-url "$DATABASE_URL" --out pg-migrate

CLI parity: `outpost admin pg-migrate` wraps this script (same interpreter).
"""

import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.core import config  # noqa: E402
from app.services import pg_migrate  # noqa: E402

DEFAULT_SQLITE = os.getenv("DATABASE_PATH", str(Path(config.DATA_DIR) / "outpost.db"))
DEFAULT_OUT = Path("pg-migrate")


def _tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def _export(sqlite_path: str, out_dir: Path) -> dict[str, int]:
    """Write schema.sql + data/<table>.copy + load.sql; return rows per table."""
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    try:
        tables = _tables(conn)
        if not tables:
            print(f"FAIL — {sqlite_path} has no tables (is this the OutPost DB?)", file=sys.stderr)
            sys.exit(2)
        data_dir = out_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        (out_dir / "schema.sql").write_text(pg_migrate.translate_schema())
        counts: dict[str, int] = {}
        for table in tables:
            with (data_dir / f"{table}.copy").open("w", encoding="utf-8") as fh:
                for line in pg_migrate.export_table(conn, table):
                    fh.write(line)
            counts[table] = pg_migrate.row_count(conn, table)
        (out_dir / "load.sql").write_text(pg_migrate.build_load_sql(tables))
        return counts
    finally:
        conn.close()


def _verify(psql_url: str, out_dir: Path, expected: dict[str, int]) -> bool:
    """Compare Postgres row counts against the exported SQLite counts."""
    ok = True
    for table, want in sorted(expected.items()):
        try:
            res = subprocess.run(
                ["psql", psql_url, "-tA", "-c", f'SELECT COUNT(*) FROM "{table}"'],
                capture_output=True, text=True, timeout=120,
            )
        except FileNotFoundError:
            print("FAIL — psql not found on PATH (needed for --import/--verify)", file=sys.stderr)
            return False
        if res.returncode != 0:
            print(f"  ✗ {table}: psql error: {res.stderr.strip()[:160]}", file=sys.stderr)
            ok = False
            continue
        got = int(res.stdout.strip() or "0")
        if got == want:
            print(f"  ✓ {table}: {got} rows")
        else:
            print(f"  ✗ {table}: PG has {got}, SQLite had {want}", file=sys.stderr)
            ok = False
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sqlite", default=DEFAULT_SQLITE, help=f"SQLite database path (default: {DEFAULT_SQLITE})")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help=f"Output directory (default: {DEFAULT_OUT})")
    ap.add_argument("--psql-url", default=os.getenv("DATABASE_URL", ""), help="Postgres URL (loads with --import, checks with --verify)")
    ap.add_argument("--import", dest="do_import", action="store_true", help="Run load.sql against --psql-url after exporting")
    ap.add_argument("--verify", action="store_true", help="Compare row counts between SQLite and Postgres")
    args = ap.parse_args()

    out_dir = Path(args.out)
    print(f"exporting {args.sqlite} → {out_dir}/ (schema.sql, data/*.copy, load.sql)")
    counts = _export(args.sqlite, out_dir)
    total = sum(counts.values())
    print(f"  {len(counts)} tables, {total} rows")
    for table, n in sorted(counts.items()):
        print(f"    {table:<22} {n}")

    if args.do_import:
        if not args.psql_url:
            print("FAIL — --import needs --psql-url (or DATABASE_URL)", file=sys.stderr)
            return 2
        print(f"importing via psql → {args.psql_url}")
        res = subprocess.run(["psql", args.psql_url, "-v", "ON_ERROR_STOP=1", "-f", str(out_dir / "load.sql")])
        if res.returncode != 0:
            print("FAIL — psql load failed (transaction rolled back)", file=sys.stderr)
            return 1

    if args.verify:
        if not args.psql_url:
            print("FAIL — --verify needs --psql-url (or DATABASE_URL)", file=sys.stderr)
            return 2
        print("verifying row counts:")
        ok = _verify(args.psql_url, out_dir, counts)
        if not ok:
            return 1

    print("✓ export complete — load with:  psql \"$DATABASE_URL\" -f {}/load.sql".format(out_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
