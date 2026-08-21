# Postgres migration path (Tier 4)

OutPost ships on a single SQLite file (`backend/data/outpost.db`, raw
`sqlite3` in `backend/app/core/db.py`). That is the deliberate lab-scale
choice, and it is also the scale ceiling: a real fleet (dozens of hosts ×
10k events/hr) wants a real server database. This document is the port
plan — the schema inventory, the exact dialect mapping, what the runtime
must change, and the migration runbook that already works today.

Status: **the full Tier-4 path is shipped.** Export/import tooling
(`outpost admin pg-migrate`, `scripts/migrate_to_postgres.py`, pure core in
`backend/app/services/pg_migrate.py`, unit-tested) **and** the live
Postgres runtime: set `OUTPOST_DATABASE_URL` (psycopg3 URL) and install the
backend's optional `pg` extra — `core/db.py` then routes through
`core/db_pg.py`, a sqlite3-compatible shim over psycopg3 that translates
placeholders, LIKE/ILIKE, `INSERT OR IGNORE`, `GROUP_CONCAT` and `lastrowid`
(RETURNING) semantics with zero caller changes. The schema comes up
automatically at startup from the translated DDL (the final runtime shape).
Verified for real in CI by the `pg-runtime` job (postgres service container
→ `scripts/gate_pg_runtime.py`); locally `verify.sh` includes the same gate
and SKIPs cleanly when no URL is set.

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

## How the live runtime works (what changed)

`core/db.py` exposes a small, explicit surface — the seam the dialect lives
behind. `get_connection()` / `init_db()` branch on `config.DATABASE_URL`:
empty → the zero-config sqlite3 path; set → `core/db_pg.py`, a
sqlite3-compatible shim over psycopg3 (lazy-imported, so the SQLite default
keeps its dependency-light install — psycopg comes from the backend's
optional `pg` extra). Every model and route goes through `db_session()`, so
the wrapper contains the change with zero caller edits:

| sqlite3 API used | What the shim does |
|---|---|
| `sqlite3.connect(DATABASE_PATH)` | `psycopg.connect(DATABASE_URL)` |
| `conn.execute / executemany` (`?` style) | translates `?` → `%s` |
| `conn.row_factory = sqlite3.Row` | rows wrapped in `PgRow` — `row["name"]`, `row[0]`, `dict(row)`, `keys()`, iteration |
| `cur.lastrowid` | appends `INSERT … RETURNING id` for tables whose single-column PK is `id` (PG catalog lookup, cached per connection) |
| `LIKE` (case-insensitive in SQLite) | `ILIKE` — identical search behavior |
| `INSERT OR IGNORE` | `INSERT … ON CONFLICT DO NOTHING` — same rowcount contract (1 when inserted, 0 when ignored) |
| `GROUP_CONCAT(x)` / `GROUP_CONCAT(DISTINCT x)` | `string_agg(x, ',')` / `string_agg(DISTINCT x, ',')` (balanced-paren scan handles nested subqueries) |
| `PRAGMA foreign_keys = ON` | FKs are on by default in Postgres |
| `PRAGMA journal_mode = WAL` / `busy_timeout` | dropped (Postgres handles concurrency) |
| `sqlite_master` / `PRAGMA table_info` migrations | skipped — the translated DDL is the final runtime shape, so a fresh PG install starts correct |
| `config.DATABASE_PATH` | `config.DATABASE_URL` — one config switch |

Verified for real in CI: the `pg-runtime` job runs a postgres:16 service
container and exercises the shim end to end through
`scripts/gate_pg_runtime.py` (schema init, RETURNING-id lastrowid, upserts,
OR-IGNORE rowcounts, the agents-page GROUP_CONCAT query verbatim, ILIKE
search, LIMIT/OFFSET, executemany, FK enforcement). Locally `verify.sh`
runs the same gate and SKIPs cleanly when no URL is set. The translation
layer is additionally unit-tested without a server
(`backend/app/tests/test_pg_runtime.py`).

**Known SQLite-only surfaces on the PG runtime:** the Settings backup/restore
endpoints return 400 with a pointer to `pg_dump`/`pg_restore`, and the seed
demo/campaign scripts (dev tooling) still target SQLite.

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

# 4. Point the backend at Postgres (psycopg comes from the `pg` extra)
pip install -e "./backend[pg]"
OUTPOST_DATABASE_URL="$DATABASE_URL" uvicorn app.main:app
#    On boot, init_db() applies the translated DDL idempotently and the
#    whole app — live monitoring, detonation, triage — runs against PG.

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
