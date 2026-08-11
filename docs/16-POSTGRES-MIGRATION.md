# Postgres migration path (Tier 4)

OutPost ships on a single SQLite file (`backend/data/outpost.db`, raw
`sqlite3` in `backend/app/core/db.py`). That is the deliberate lab-scale
choice, and it is also the scale ceiling: a real fleet (dozens of hosts ×
10k events/hr) wants a real server database. This document is the port
plan — the schema inventory, the exact dialect mapping, what the runtime
must change, and the migration runbook that already works today.

Status: **export/import tooling shipped** (`outpost admin pg-migrate`,
`scripts/migrate_to_postgres.py`, pure core in
`backend/app/services/pg_migrate.py`, unit-tested). The live-Postgres
runtime (a psycopg dialect for `core/db.py`) is the remaining piece —
nothing in the app can run against Postgres yet.

## Why files, not a live connection

The exporter is stdlib-only on purpose: the migration must not add a
runtime dependency. It writes three self-contained artifacts that any
Postgres host can consume with `psql` — no psycopg on the source machine,
no network hop from the box holding the SQLite file:

```
pg-migrate/
├── schema.sql        # the translated Postgres DDL
├── data/<table>.copy # per-table rows in Postgres COPY text format
└── load.sql          # psql script: \i schema.sql + BEGIN + \copy… + COMMIT
```

## Schema inventory (20 tables)

| Group | Tables |
|---|---|
| Core telemetry | `runs`, `alerts`, `events`, `enrichment_cache` |
| Analysis | `run_process_maps`, `run_notes`, `run_tuning_snapshot`, `rule_tuning`, `rule_fp` |
| Analyst ops | `run_allowlist`, `rule_suppressions`, `watchlist`, `watchlist_hits`, `audit_log`, `settings` |
| Fleet | `agent_heartbeats`, `host_snapshots`, `host_baselines` |
| Vault / intel | `samples`, `hash_cache` |

## Dialect mapping (what the port must translate)

| SQLite construct (shipped schema) | Postgres equivalent |
|---|---|
| `INTEGER PRIMARY KEY AUTOINCREMENT` (6 tables) | `BIGSERIAL PRIMARY KEY` — rows load in order, so id continuity holds for FK-referencing tables |
| `TEXT` (timestamps, JSON payloads, every string) | `TEXT` — **timestamps stay ISO strings** (the code parses them already; no behavior change), **JSON stays TEXT** (`run_process_maps.pids_json`, `events.raw_record`, `run_tuning_snapshot.params`, `samples.yara_rules`) |
| `INTEGER` / `REAL` | `INTEGER` / `DOUBLE PRECISION` |
| `CHECK(...)` constraints | verbatim (e.g. status enums, platform enums) |
| `REFERENCES runs(run_id)` FKs | verbatim |
| `CREATE TABLE / INDEX IF NOT EXISTS` | verbatim (idempotent reloads) |
| `STRICT` table option (unused today) | dropped |

**Two deliberate fixes the translator applies** (mirroring what the SQLite
runtime already does):

1. `runs.platform CHECK` gains `'macos'` — the SCHEMA string predates the
   macOS CHECK rebuild that `core/db.py` applies at startup (SQLite can't
   ALTER a CHECK). The translated DDL is the **final runtime shape**, so a
   fresh Postgres install starts correct instead of migrating later.
2. Nothing else — every column and index in the runtime schema already
   exists in the SCHEMA constant (the ALTER-added columns from the older
   migrations were folded in), so the translated DDL == a migrated SQLite
   DB's shape.

**JSONB upgrade path** (optional, later): the JSON-as-TEXT columns can
become `JSONB` with zero query changes — the backend only ever writes and
reads them whole. Doing it later is a `ALTER TABLE … ALTER COLUMN TYPE
JSONB USING value::jsonb` away.

## What the runtime must change (the remaining piece)

`core/db.py` exposes a small, explicit surface — the natural seam for a
Postgres dialect:

| sqlite3 API used | Postgres equivalent |
|---|---|
| `sqlite3.connect(DATABASE_PATH)` | `psycopg.connect(DATABASE_URL)` (or pg8000) |
| `conn.execute / executemany` (param style `?`) | same calls, `%s` placeholders |
| `conn.row_factory = sqlite3.Row` | `dict_row` / `RealDictRow` |
| `cur.lastrowid` | `cursor.returning` or `INSERT … RETURNING id` |
| `PRAGMA foreign_keys = ON` | `SET session_replication_role` off (FKs are on by default) |
| `PRAGMA journal_mode = WAL` / `busy_timeout` | drop (Postgres handles concurrency) |
| `sqlite_master` introspection (migrations) | `information_schema.columns` — the idempotent `ALTER TABLE ADD COLUMN` guards already check `PRAGMA table_info`; swap for a `column_exists()` helper |
| `config.DATABASE_PATH` | `config.DATABASE_URL` — one config switch; every call site goes through `db_session()` already |

The `db_session()` context manager is the single choke point — all models
and routes use it, so a dialect wrapper behind it contains the change.

## Migration runbook (works today)

```bash
# 0. (Recommended) back up first — retention panel or:
#    cp backend/data/outpost.db backend/data/outpost.pre-pg.db

# 1. Export — writes ./pg-migrate/ (schema.sql + data/*.copy + load.sql)
outpost admin pg-migrate
#    or directly:
.venv/bin/python scripts/migrate_to_postgres.py

# 2. Create the target database
createdb outpost

# 3. Load — schema + all rows in one transaction (all-or-nothing)
psql "$DATABASE_URL" -f pg-migrate/load.sql

# 4. Verify — every table's Postgres count must equal its SQLite count
outpost admin pg-migrate --verify --psql-url "$DATABASE_URL"
```

`--import` runs step 3 from the tool: `outpost admin pg-migrate --import
--psql-url "$DATABASE_URL"` (needs `psql` on PATH). The load is idempotent
(`CREATE TABLE IF NOT EXISTS`), so a failed load can be re-run after
`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`.

**Verification beyond counts** (post-load, before cutover):
- FK integrity: `SELECT count(*) FROM alerts a LEFT JOIN runs r USING
  (run_id) WHERE r.run_id IS NULL;` → 0.
- Spot-check an escaped row: a Windows `file_path` with backslashes loads
  backslash-for-backslash; a literal `\N` string in `command_line` stays a
  string, not NULL.
- Then flip the backend: `DATABASE_URL=… uvicorn app.main:app` (once the
  dialect wrapper exists) or keep SQLite as the live source and use the PG
  copy for analytics.

**Rollback**: the SQLite file was never touched by any of this — export,
import, and verify are read-only on the source. Point the backend back at
`DATABASE_PATH` and nothing changed.

## Contract locked by tests

`backend/app/tests/test_pg_migrate.py` locks: identity-key translation,
the macOS CHECK, constraints/FKs/indexes surviving, `\N`-vs-`""` NULL
distinction, COPY escaping (tab/newline/CR/backslash, literal `\N`), row
streaming in load order, and the load.sql shape. The exporter was run
against the real 12,460-row database during development — 20 tables,
every row exported without loss.
