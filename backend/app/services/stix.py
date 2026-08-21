"""STIX 2.1 export (roadmap 3.3) — findings as a shareable intelligence bundle.

Builds a STIX 2.1 Bundle from a run's observed IOCs and alerts:

- one `indicator` object per distinct IOC (IP/domain/hash/file path/process),
  with a label derived from the alert severity that touched it;
- one `observed-data` object per alert (the detection itself, with the
  triggered_at timestamp and a reference to the run);
- `x-outpost-run` custom object carrying run metadata.

The bundle validates structurally against the 2.1 schema conventions (id
format `{type}--{uuid}` everywhere, required fields present). This is the
export surface for analyst teams; the watchlist import/export lives alongside
it in routes_watchlist.
"""

import hashlib
import uuid

from ..models import event as event_store
from ..models import run as run_store


def _stix_id(obj_type: str, seed: str) -> str:
    """Deterministic, valid STIX id from a seed — same run → same bundle ids."""
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    return f"{obj_type}--{uuid.UUID(digest[:32])}"


def _indicator(
    obj_type: str,
    value: str,
    label: str,
    pattern: str,
    run_id: str,
    created: str,
    modified: str,
) -> dict:
    return {
        "type": "indicator",
        "id": _stix_id("indicator", f"{run_id}:{obj_type}:{value}"),
        "spec_version": "2.1",
        "created": created,
        "modified": modified,
        "name": f"{value} ({label})",
        "pattern": pattern,
        "valid_from": created,
        "labels": [label],
    }


def _indicator_pattern(ioc_type: str, value: str) -> str:
    """A minimal, spec-shaped STIX patterning for the IOC type."""
    escaped = value.replace("'", "''")
    if ioc_type == "ip":
        return f"[ipv4-addr:value = '{escaped}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{escaped}']"
    if ioc_type == "hash":
        return f"[file:hashes.'SHA-256' = '{escaped}']"
    if ioc_type == "process":
        return f"[process:name = '{escaped}']"
    if ioc_type == "registry":
        return f"[windows-registry-key:key = '{escaped}']"
    # File paths (full Windows paths) use the same custom SCP as the run
    # bundle — `file:name` is semantically a basename, so a full path there
    # would be misleading.
    return f"[x-outpost-file-path:value = '{escaped}']"


def build_stix_bundle(run_id: str) -> dict:
    """Return a STIX 2.1 Bundle dict for one run's findings."""
    from ..core.db import db_session

    with db_session() as conn:
        run_row = run_store.get_run(conn, run_id)
        if not run_row:
            return {"error": f"Unknown run_id: {run_id}"}
        alerts = event_store.list_alerts_for_run(conn, run_id)
        # Sample hash indicators (uploaded binaries sharing the run's name).
        sample_rows = conn.execute(
            "SELECT sha256, original_name, vt_detections FROM samples WHERE original_name = ? "
            "ORDER BY created_at DESC LIMIT 5",
            (run_row["sample_name"],),
        ).fetchall()

    objects: list[dict] = []

    # Real timestamps: indicators/observations are created when the run started
    # and modified when the bundle is built (analyst-team exports should carry
    # actual dates, not placeholders).
    from datetime import datetime, timezone

    created = run_row["started_at"]
    modified = datetime.now(timezone.utc).isoformat()

    # Run identity.
    objects.append(
        {
            "type": "x-outpost-run",
            "id": _stix_id("x-outpost-run", run_id),
            "spec_version": "2.1",
            "name": run_row["sample_name"],
            "platform": run_row["platform"],
            "started_at": run_row["started_at"],
            "completed_at": run_row["completed_at"],
        }
    )

    # One indicator per distinct IOC, labeled by the worst severity touching it.
    alert_by_ioc: dict[str, str] = {}
    for a in alerts:
        if a["related_ip"]:
            cur = alert_by_ioc.get(a["related_ip"])
            if not cur or a["severity"] == "malicious":
                alert_by_ioc[a["related_ip"]] = a["severity"]
    for ip, severity in sorted(alert_by_ioc.items()):
        label = "malicious" if severity == "malicious" else "suspicious"
        objects.append(
            _indicator("ip", ip, label, _indicator_pattern("ip", ip), run_id, created, modified)
        )

    for s in sample_rows:
        objects.append(
            _indicator(
                "hash", s["sha256"], "sample", _indicator_pattern("hash", s["sha256"]), run_id, created, modified
            )
        )

    # One observed-data object per alert (the detection event).
    for a in alerts:
        objects.append(
            {
                "type": "observed-data",
                "id": _stix_id("observed-data", f"{run_id}:{a['rule_id']}:{a['id']}"),
                "spec_version": "2.1",
                "created": created,
                "modified": modified,
                "first_observed": a["triggered_at"],
                "last_observed": a["triggered_at"],
                "number_observed": 1,
                "labels": [a["severity"]],
                "x_outpost": {
                    "rule_id": a["rule_id"],
                    "rule_name": a["rule_name"],
                    "details": a["details"],
                },
            }
        )

    return {
        "type": "bundle",
        "id": _stix_id("bundle", run_id),
        "spec_version": "2.1",
        "objects": objects,
    }


# -- Campaign-level bundles (clusters of runs sharing infrastructure) --------


def build_campaign_stix_bundle(campaign_key: str) -> dict:
    """STIX 2.1 Bundle for one campaign (webapp Campaigns view parity).

    A campaign is a cluster of runs sharing a signature IP. The bundle carries
    the cluster itself (`x-outpost-campaign`), every shared IOC as an
    `indicator` (so a threat-intel team can hunt the whole cluster, not one
    run), one `x-outpost-run` per member, and `related-to`/`indicates`
    relationships linking them.
    """
    from datetime import datetime, timezone

    from ..core.db import db_session
    from .campaigns import build_campaigns

    with db_session() as conn:
        matches = [c for c in build_campaigns(conn) if c["key"] == campaign_key]
    if not matches:
        return {"error": f"Unknown campaign key: {campaign_key}"}
    camp = matches[0]

    created = camp["span_start"] or datetime.now(timezone.utc).isoformat()
    modified = datetime.now(timezone.utc).isoformat()

    objects: list[dict] = []

    # The cluster itself.
    campaign_id = _stix_id("x-outpost-campaign", camp["key"])
    objects.append(
        {
            "type": "x-outpost-campaign",
            "id": campaign_id,
            "spec_version": "2.1",
            "name": f"{camp['key']} — shared-infrastructure campaign",
            "key": camp["key"],
            "reputation": camp.get("reputation"),
            "watchlist": camp.get("watchlist", False),
            "watchlist_label": camp.get("watchlist_label"),
            "span_start": camp.get("span_start"),
            "span_end": camp.get("span_end"),
            "member_count": len(camp["runs"]),
            "chain_label": camp.get("chain_label"),
        }
    )

    # One indicator per distinct shared IOC, labeled by cluster reputation.
    label = "malicious" if camp.get("reputation") == "malicious" else "suspicious"
    ioc_patterns = {
        "ips": "ip",
        "registry_keys": "registry",
        "file_paths": "file",
        "processes": "process",
    }
    for bucket, ioc_type in ioc_patterns.items():
        for ioc in camp["iocs"].get(bucket, []):
            value = ioc["value"]
            objects.append(
                _indicator(
                    ioc_type,
                    value,
                    label,
                    _indicator_pattern(ioc_type, value),
                    f"campaign:{camp['key']}",
                    created,
                    modified,
                )
            )

    # Member runs + relationships: run → campaign (related-to) and each
    # indicator → campaign (indicates), so the cluster graph is navigable.
    indicator_ids = {o["id"] for o in objects if o["type"] == "indicator"}
    for member in camp["runs"]:
        run_ref = _stix_id("x-outpost-run", member["run_id"])
        objects.append(
            {
                "type": "x-outpost-run",
                "id": run_ref,
                "spec_version": "2.1",
                "name": member["sample_name"],
                "platform": member.get("platform"),
                "started_at": member.get("started_at"),
                "completed_at": member.get("completed_at"),
                "alert_count": member.get("alert_count"),
                "highest_severity": member.get("highest_severity"),
            }
        )
        objects.append(
            {
                "type": "relationship",
                "id": _stix_id("relationship", f"{member['run_id']}->{camp['key']}"),
                "spec_version": "2.1",
                "relationship_type": "related-to",
                "source_ref": run_ref,
                "target_ref": campaign_id,
                "created": created,
                "modified": modified,
            }
        )
    for indicator_id in indicator_ids:
        objects.append(
            {
                "type": "relationship",
                "id": _stix_id("relationship", f"{indicator_id}->{camp['key']}"),
                "spec_version": "2.1",
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": campaign_id,
                "created": created,
                "modified": modified,
            }
        )

    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"campaign:{camp['key']}"),
        "spec_version": "2.1",
        "objects": objects,
    }
