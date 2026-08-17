"""Global search (P0.5) — one endpoint, every analyst-facing resource.

The approved P0 contract (GET /search) asks for grouped results across
findings, IOCs, artifacts, hosts, sessions/jobs, investigations, and
campaigns, with free text plus qualifiers (`type:` `status:` `severity:`
`disposition:` `host:` `rule:` `case:`).

Deliberately NOT a search engine: every group is a plain SQLite LIKE query
over its existing table (the same literal-matching convention as `/ioc/search`
and the IOC list), with the qualified filters applied where the group has the
column. The datastore is a single-file SQLite DB — an FTS/Elastic-style index
was explicitly ruled out by the P0 spec unless the repository already used
one, and it does not.

Campaigns have no table (they are derived from events by
`services/campaigns.py`), so the campaign group derives the same way: the
candidate anchor IPs from events, matched by key. Runs are exposed as the
'sessions' group (kind monitoring_session/analysis_job), artifacts map to the
existing `samples` table (the P0-deferred artifacts table does not exist).
"""

import sqlite3
from typing import Any

# Qualifier token -> the filters we apply per group.
_QUALIFIER_ALIASES = {
    "type": "type",
    "status": "status",
    "severity": "severity",
    "disposition": "disposition",
    "host": "host",
    "rule": "rule",
    "case": "case",
}

# type: value -> group name.
_GROUP_ALIASES = {
    "finding": "findings",
    "findings": "findings",
    "ioc": "iocs",
    "iocs": "iocs",
    "artifact": "artifacts",
    "artifacts": "artifacts",
    "host": "hosts",
    "hosts": "hosts",
    "session": "sessions",
    "sessions": "sessions",
    "run": "sessions",
    "runs": "sessions",
    "investigation": "investigations",
    "investigations": "investigations",
    "campaign": "campaigns",
    "campaigns": "campaigns",
}

_SEARCH_GROUPS = ("findings", "iocs", "artifacts", "hosts", "sessions", "investigations", "campaigns")

# The IOC entity's own type vocabulary — `type:ip` filters the iocs group by
# the entity type, while `type:ioc` (a group alias) restricts the search.
_IOC_TYPE_VALUES = {
    "ip", "domain", "url", "hash", "email", "filepath", "registry", "mutex", "certificate", "other",
}


def _like(value: str) -> str:
    """Escape LIKE metacharacters so user input is matched literally."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def parse_query(q: str) -> tuple[str, dict[str, str]]:
    """Split `q` into free text + qualifiers.

    Qualifiers are `key:value` tokens anywhere in the string; a token whose
    key is not a known qualifier stays free text. Returns (free_text, quals)
    with qualifier values trimmed. `type:` values resolve to the canonical
    group name (findings / iocs / artifacts / hosts / sessions /
    investigations / campaigns) or stay as an IOC entity type (ip / domain /
    hash / …) for the iocs searcher; anything else stays free text.
    """
    tokens = q.split()
    free: list[str] = []
    quals: dict[str, str] = {}
    for tok in tokens:
        if ":" in tok:
            key, _, value = tok.partition(":")
            key = key.lower().strip()
            value = value.strip()
            if key in _QUALIFIER_ALIASES and value:
                canon = _QUALIFIER_ALIASES[key]
                if canon == "type":
                    lowered = value.lower()
                    group = _GROUP_ALIASES.get(lowered)
                    if group:
                        # Group alias → restrict the search to that group.
                        quals["type"] = group
                    elif lowered in _IOC_TYPE_VALUES:
                        # An IOC entity type (ip/domain/…) — the iocs searcher
                        # applies it as its own type filter.
                        quals["type"] = lowered
                    else:
                        free.append(tok)
                    continue
                quals[canon] = value.lower()
                continue
        free.append(tok)
    return " ".join(free).strip(), quals


def _esc_like(value: str) -> str:
    return _like(value)


def search_findings(
    conn: sqlite3.Connection, text: str, quals: dict[str, str], limit: int
) -> tuple[int, list[dict[str, Any]]]:
    where: list[str] = []
    params: list = []
    if text:
        like = _esc_like(text)
        where.append(
            "(a.rule_name LIKE ? ESCAPE '\\' OR a.details LIKE ? ESCAPE '\\' "
            "OR a.related_ip LIKE ? ESCAPE '\\' OR a.rule_id LIKE ? ESCAPE '\\' "
            "OR r.sample_name LIKE ? ESCAPE '\\')"
        )
        params.extend([like] * 5)
    if quals.get("status"):
        where.append("a.status = ?")
        params.append(quals["status"])
    if quals.get("severity"):
        where.append("a.severity = ?")
        params.append(quals["severity"])
    if quals.get("disposition"):
        where.append("a.disposition = ?")
        params.append(quals["disposition"])
    if quals.get("host"):
        where.append("a.run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)")
        params.append(quals["host"])
    if quals.get("rule"):
        where.append("a.rule_id = ?")
        params.append(quals["rule"])
    if quals.get("case"):
        where.append("a.investigation_id = ?")
        params.append(quals["case"])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(
        f"SELECT COUNT(*) FROM alerts a JOIN runs r ON r.run_id = a.run_id {where_sql}",
        params,
    ).fetchone()[0]
    rows = conn.execute(
        f"""SELECT a.id, a.rule_name, a.severity, a.status, a.triggered_at, a.related_ip,
                   a.details, a.run_id, r.sample_name
            FROM alerts a JOIN runs r ON r.run_id = a.run_id
            {where_sql}
            ORDER BY a.triggered_at DESC
            LIMIT {limit}""",
        params,
    ).fetchall()
    hits = [
        {
            "group": "findings",
            "id": str(r["id"]),
            "kind": r["severity"],
            "title": r["rule_name"],
            "subtitle": r["sample_name"] or r["run_id"],
            "payload": {
                "alert_id": r["id"],
                "run_id": r["run_id"],
                "severity": r["severity"],
                "status": r["status"],
                "related_ip": r["related_ip"],
                "triggered_at": r["triggered_at"],
                "details": r["details"],
            },
        }
        for r in rows
    ]
    return total, hits


def search_iocs(
    conn: sqlite3.Connection, text: str, quals: dict[str, str], limit: int
) -> tuple[int, list[dict[str, Any]]]:
    where: list[str] = []
    params: list = []
    if text:
        like = _esc_like(text)
        where.append("(value LIKE ? ESCAPE '\\' OR label LIKE ? ESCAPE '\\')")
        params.extend([like, like])
    # The `type:` qualifier is the GROUP selector (iocs / findings / …) — not
    # the IOC entity's own type — so it is consumed by parse_query and is not
    # present here unless the caller wrote a literal IOC type (ip/domain/…).
    if quals.get("type") in _IOC_TYPE_VALUES:
        where.append("type = ?")
        params.append(quals["type"])
    if quals.get("disposition"):
        where.append("disposition = ?")
        params.append(quals["disposition"])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM iocs {where_sql}", params).fetchone()[0]
    rows = conn.execute(
        f"""SELECT ioc_id, value, type, disposition, label, first_seen, last_seen, reputation
            FROM iocs {where_sql}
            ORDER BY first_seen DESC
            LIMIT {limit}""",
        params,
    ).fetchall()
    hits = [
        {
            "group": "iocs",
            "id": r["ioc_id"],
            "kind": r["type"],
            "title": r["value"],
            "subtitle": r["label"] or r["disposition"],
            "payload": {
                "ioc_id": r["ioc_id"],
                "value": r["value"],
                "type": r["type"],
                "disposition": r["disposition"],
                "first_seen": r["first_seen"],
                "reputation": r["reputation"],
            },
        }
        for r in rows
    ]
    return total, hits


def search_artifacts(
    conn: sqlite3.Connection, text: str, quals: dict[str, str], limit: int
) -> tuple[int, list[dict[str, Any]]]:
    """Artifacts map to the existing `samples` table (the P0 artifacts table
    does not exist yet) — same mapping the analysis-job API uses."""
    where: list[str] = []
    params: list = []
    if text:
        like = _esc_like(text)
        where.append("(original_name LIKE ? ESCAPE '\\' OR sha256 LIKE ? ESCAPE '\\' OR family LIKE ? ESCAPE '\\')")
        params.extend([like, like, like])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM samples {where_sql}", params).fetchone()[0]
    rows = conn.execute(
        f"""SELECT sample_id, original_name, sha256, size, detected_platform, created_at
            FROM samples {where_sql}
            ORDER BY created_at DESC
            LIMIT {limit}""",
        params,
    ).fetchall()
    hits = [
        {
            "group": "artifacts",
            "id": r["sample_id"],
            "kind": r["detected_platform"],
            "title": r["original_name"],
            "subtitle": f"{r['sha256'][:16]}… · {r['size']} bytes",
            "payload": {
                "sample_id": r["sample_id"],
                "original_name": r["original_name"],
                "sha256": r["sha256"],
                "detected_platform": r["detected_platform"],
                "created_at": r["created_at"],
            },
        }
        for r in rows
    ]
    return total, hits


def search_hosts(
    conn: sqlite3.Connection, text: str, quals: dict[str, str], limit: int
) -> tuple[int, list[dict[str, Any]]]:
    """Hosts = distinct fleet host_ids: heartbeat rows plus any event host_id
    (event-only hosts such as webapp detonations have no heartbeat row)."""
    where: list[str] = []
    params: list = []
    if text:
        like = _esc_like(text)
        where.append("(host_id LIKE ? ESCAPE '\\')")
        params.append(like)
    if quals.get("host"):
        where.append("host_id = ?")
        params.append(quals["host"])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM (SELECT host_id FROM agent_heartbeats {where_sql} UNION SELECT DISTINCT host_id FROM events {where_sql})", params + params).fetchone()[0]
    rows = conn.execute(
        f"""SELECT host_id, platform, version, last_heartbeat FROM agent_heartbeats {where_sql}
            ORDER BY last_heartbeat DESC
            LIMIT {limit}""",
        params,
    ).fetchall()
    hits = [
        {
            "group": "hosts",
            "id": r["host_id"],
            "kind": "host",
            "title": r["host_id"],
            "subtitle": r["platform"] or "unknown",
            "payload": {
                "host_id": r["host_id"],
                "platform": r["platform"],
                "version": r["version"],
                "last_heartbeat": r["last_heartbeat"],
            },
        }
        for r in rows
    ]
    # Event-only hosts (no heartbeat row) — surface them too when the free
    # text or host filter matches, so a host with telemetry but no agent row
    # is still findable.
    if not hits:
        ev_where: list[str] = []
        ev_params: list = []
        if text:
            like = _esc_like(text)
            ev_where.append("host_id LIKE ? ESCAPE '\\'")
            ev_params.append(like)
        if quals.get("host"):
            ev_where.append("host_id = ?")
            ev_params.append(quals["host"])
        ev_sql = ("WHERE " + " AND ".join(ev_where)) if ev_where else ""
        ev_rows = conn.execute(
            f"SELECT DISTINCT host_id FROM events {ev_sql} ORDER BY host_id LIMIT {limit}",
            ev_params,
        ).fetchall()
        hits = [
            {
                "group": "hosts",
                "id": r["host_id"],
                "kind": "host",
                "title": r["host_id"],
                "subtitle": "telemetry only",
                "payload": {"host_id": r["host_id"], "platform": None},
            }
            for r in ev_rows
        ]
    return total, hits


def search_sessions(
    conn: sqlite3.Connection, text: str, quals: dict[str, str], limit: int
) -> tuple[int, list[dict[str, Any]]]:
    """Sessions/jobs = the `runs` table (kind monitoring_session/analysis_job).
    `status` qualifier maps to the run's completion state (active = not
    completed)."""
    where: list[str] = []
    params: list = []
    if text:
        like = _esc_like(text)
        where.append("(run_id LIKE ? ESCAPE '\\' OR sample_name LIKE ? ESCAPE '\\')")
        params.extend([like, like])
    if quals.get("status"):
        if quals["status"] == "active":
            where.append("completed_at IS NULL")
        elif quals["status"] == "completed":
            where.append("completed_at IS NOT NULL")
        else:
            where.append("1 = 0")
    if quals.get("host"):
        where.append("run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)")
        params.append(quals["host"])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM runs {where_sql}", params).fetchone()[0]
    rows = conn.execute(
        f"""SELECT run_id, sample_name, platform, kind, session_type, started_at, completed_at, source
            FROM runs {where_sql}
            ORDER BY started_at DESC
            LIMIT {limit}""",
        params,
    ).fetchall()
    hits = [
        {
            "group": "sessions",
            "id": r["run_id"],
            "kind": r["kind"],
            "title": r["sample_name"] or r["run_id"],
            "subtitle": f"{r['kind']} · {r['platform']} · {'completed' if r['completed_at'] else 'active'}",
            "payload": {
                "run_id": r["run_id"],
                "sample_name": r["sample_name"],
                "kind": r["kind"],
                "platform": r["platform"],
                "started_at": r["started_at"],
                "completed_at": r["completed_at"],
            },
        }
        for r in rows
    ]
    return total, hits


def search_investigations(
    conn: sqlite3.Connection, text: str, quals: dict[str, str], limit: int
) -> tuple[int, list[dict[str, Any]]]:
    where: list[str] = []
    params: list = []
    if text:
        like = _esc_like(text)
        where.append(
            "(title LIKE ? ESCAPE '\\' OR EXISTS (SELECT 1 FROM investigation_tags t "
            "WHERE t.investigation_id = i.id AND t.tag LIKE ? ESCAPE '\\') "
            "OR EXISTS (SELECT 1 FROM investigation_notes n "
            "WHERE n.investigation_id = i.id AND n.note LIKE ? ESCAPE '\\'))"
        )
        params.extend([like, like, like])
    if quals.get("status"):
        where.append("i.status = ?")
        params.append(quals["status"])
    if quals.get("case"):
        where.append("i.id = ?")
        params.append(quals["case"])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM investigations i {where_sql}", params).fetchone()[0]
    rows = conn.execute(
        f"""SELECT i.id, i.title, i.status, i.severity, i.created_at, i.updated_at, i.closed_at,
                   i.conclusion, i.created_by,
                   (SELECT COUNT(*) FROM alerts a WHERE a.investigation_id = i.id) AS finding_count,
                   (SELECT COUNT(*) FROM investigation_refs r WHERE r.investigation_id = i.id) AS ref_count
            FROM investigations i
            {where_sql}
            ORDER BY i.updated_at DESC
            LIMIT {limit}""",
        params,
    ).fetchall()
    hits = [
        {
            "group": "investigations",
            "id": r["id"],
            "kind": r["status"],
            "title": r["title"],
            "subtitle": f"{r['status']} · {r['finding_count']} findings · {r['ref_count']} refs",
            "payload": {
                "investigation_id": r["id"],
                "status": r["status"],
                "severity": r["severity"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "finding_count": r["finding_count"],
                "ref_count": r["ref_count"],
            },
        }
        for r in rows
    ]
    return total, hits


def search_campaigns(
    conn: sqlite3.Connection, text: str, quals: dict[str, str], limit: int
) -> tuple[int, list[dict[str, Any]]]:
    """Campaigns are derived entities (no table): candidate anchor IPs shared
    by >= 2 runs. We reuse the same derivation and match by key/IP."""
    from ..services import campaigns as campaigns_service

    all_campaigns = campaigns_service.build_campaigns(conn)
    matched = []
    for c in all_campaigns:
        key = c["key"]
        if text and text.lower() not in key.lower():
            continue
        if quals.get("host") and key != quals["host"]:
            continue
        matched.append(c)
    total = len(matched)
    hits = [
        {
            "group": "campaigns",
            "id": c["key"],
            "kind": "campaign",
            "title": c["key"],
            "subtitle": f"{c['reputation'] or 'unknown'} · {len(c['runs'])} runs",
            "payload": {
                "key": c["key"],
                "reputation": c["reputation"],
                "runs": [r["run_id"] for r in c["runs"]],
                "chain_label": c.get("chain_label"),
            },
        }
        for c in matched[:limit]
    ]
    return total, hits


_SEARCHERS = {
    "findings": search_findings,
    "iocs": search_iocs,
    "artifacts": search_artifacts,
    "hosts": search_hosts,
    "sessions": search_sessions,
    "investigations": search_investigations,
    "campaigns": search_campaigns,
}


def search_all(
    conn: sqlite3.Connection, q: str, limit: int = 10
) -> dict[str, Any]:
    """Run the grouped search. `q` may carry qualifiers; `type:` restricts to
    one group (the others are still present in the envelope, empty)."""
    text, quals = parse_query(q)
    groups: dict[str, dict[str, Any]] = {}
    # `type:` restricts the search to one group. The raw value may be a group
    # alias (ioc → iocs) or an IOC entity type (ip/domain/… — which the iocs
    # searcher applies as its own type filter). Resolve the group restriction
    # here; the searchers see the raw value.
    only = _GROUP_ALIASES.get(quals.get("type", ""))
    for group in _SEARCH_GROUPS:
        if only and group != only:
            groups[group] = {"total": 0, "hits": []}
            continue
        total, hits = _SEARCHERS[group](conn, text, quals, limit)
        groups[group] = {"total": total, "hits": hits}
    return {"q": text, "qualifiers": quals, "groups": groups}
