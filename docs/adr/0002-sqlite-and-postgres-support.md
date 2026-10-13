# ADR 0002: Dual SQLite and PostgreSQL Storage Engine Support

## Status
Accepted

## Context
OutPost targets two distinct operational deployments:
1. **Air-gapped and local incident response laptops / homelabs:** Operators need zero external database setup, portable `.db` files, and immediate execution without managing database daemon permissions.
2. **Enterprise SOC production infrastructure:** Teams require concurrent ingest at thousands of events per second, enterprise backup procedures (`pg_dump`), and multi-user concurrent analyst sessions without database lock contention.

## Decision
OutPost provides native dual-engine database support:
- **Default (Zero-Config): SQLite 3 with Write-Ahead Logging (WAL)**:
  - Enabled by default with `PRAGMA journal_mode = WAL`, `PRAGMA synchronous = NORMAL`, and `PRAGMA busy_timeout = 5000`.
  - Supports concurrent readers while a single writer commits batches.
  - Portable single-file storage with online atomic backup (`PRAGMA backup`).
- **Production (Tier 4): PostgreSQL via psycopg3-compatible translation shim**:
  - Activated when `OUTPOST_DATABASE_URL` is set.
  - Automatically translates SQL DDL, param placeholders (`?` to `%s`), `INSERT OR IGNORE` to `ON CONFLICT DO NOTHING`, and `GROUP_CONCAT` to `string_agg`.
  - Built-in migration script (`scripts/migrate_to_postgres.py`) exports existing SQLite state directly into Postgres COPY tables.

## Alternatives Rejected
1. **PostgreSQL Only:**
   - *Reason for Rejection:* Breaks the zero-dependency promise; makes OutPost impossible to run directly from a USB stick or portable forensic analysis VM without spinning up a PostgreSQL daemon.
2. **Heavyweight ORM (SQLAlchemy / Tortoise):**
   - *Reason for Rejection:* Massive dependency tree, substantial import and startup latency, abstraction leaks in raw forensic query execution, and difficulty maintaining byte-level cryptographic integrity triggers.

## Consequences & Known Costs
- **Pros:**
  - Complete portability across single-host triage and large SOC environments.
  - Zero setup for 90% of development, testing, and isolated lab environments.
- **Cons / Limitations:**
  - Dual DDL maintenance requires ensuring all queries conform to both SQLite dialect and Postgres translation syntax.
  - SQLite concurrent write throughput is bounded by filesystem lock contention during high-volume spikes.
