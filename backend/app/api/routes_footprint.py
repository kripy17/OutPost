"""Digital footprinting — GET /footprint/{sample_id} + export.

Passive domain/IP footprint for one uploaded sample. The seed (the sample's
observed infrastructure) is real; the passive expansion layer pulls real
reverse-DNS + crt.sh CT + RDAP data (services/footprint.py) with an honest
offline fallback. `?mock=1` forces clearly-labeled synthetic data instead.

`GET /footprint/{sample_id}/export?format=csv|json` — threat-intel handoff:
JSON keeps the full structured payload (sample identity, seed IPs, every
passive collection); CSV flattens the same rows into one filterable sheet
with a `collection` discriminator column (seed / resolution / passive_dns /
certificate / sibling / network / asn).
"""

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Response

from ..core.db import db_session
from ..services import footprint as footprint_service

router = APIRouter(tags=["footprint"])

_EXPORT_FILENAME = "outpost-footprint"


@router.get("/footprint/topology", response_model=None)
async def get_footprint_topology():
    """Cross-sample infra topology — every IP that ≥2 samples reached, with
    the member samples and run ids. The campaign-correlation view: one C2
    box, several binaries. Pure local SQL, no external calls."""
    with db_session() as conn:
        return footprint_service.cross_sample_topology(conn)


@router.get("/footprint/{sample_id}", response_model=None)
async def get_footprint(
    sample_id: str,
    mock: int = Query(0, ge=0, le=1, description="Force clearly-labeled synthetic data instead of live lookups"),
):
    with db_session() as conn:
        data = await footprint_service.build_footprint(conn, sample_id, mock=bool(mock))
    if data is None:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
    return data


def _flatten_rows(data: dict) -> list[tuple[str, str, str, str, str, str, str]]:
    """One row per observation: (collection, indicator, source_ip, detail, first, last, synthetic).

    All collections collapse onto the same seven columns so the CSV stays a
    single filterable sheet (`collection` = which card the row came from;
    `source_ip` = the seed/sibling IP a passive-DNS name was observed from).
    Seed IPs lead the sheet — the observed infrastructure anchors the passive
    expansion in a handoff artifact.
    """
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    passive = data.get("passive", {})

    for s in data.get("seed_ips", []):
        rows.append(
            (
                "seed",
                s["ip"],
                "",
                f"{s['reputation']} · {s['hits']} hit(s) · {s['run_count']} run(s)",
                (s.get("first_seen") or "")[:10],
                (s.get("last_seen") or "")[:10],
                "false",
            )
        )

    for r in passive.get("resolutions", []):
        rows.append(("resolution", r["domain"], "", "", r.get("first_seen", ""), r.get("last_seen", ""), str(bool(r.get("synthetic"))).lower()))
    for d in passive.get("passive_dns", []):
        rows.append(("passive_dns", d["domain"], d.get("source_ip", ""), "", d.get("first_seen", ""), d.get("last_seen", ""), str(bool(d.get("synthetic"))).lower()))
    for d in passive.get("subdomains", []):
        rows.append(("subdomain", d["domain"], d.get("source_ip", ""), f"subdomain of {d.get('apex', '')} (CT)", d.get("first_seen", ""), d.get("last_seen", ""), str(bool(d.get("synthetic"))).lower()))
    for c in passive.get("certificates", []):
        rows.append(
            ("certificate", c.get("cn", ""), "", c.get("issuer", ""), c.get("not_before", ""), c.get("not_after", ""), str(bool(c.get("synthetic"))).lower())
        )
    for sib in passive.get("sibling_ips", []):
        rows.append(("sibling", sib["ip"], "", sib.get("relation", ""), "", "", str(bool(sib.get("synthetic"))).lower()))
    for n in passive.get("networks", []):
        detail = " · ".join(x for x in (n.get("netname"), n.get("org"), n.get("country")) if x)
        rows.append(("network", n.get("cidr", n.get("ip", "")), "", detail, "", "", str(bool(n.get("synthetic"))).lower()))
    for a in passive.get("asn", []):
        detail = " · ".join(x for x in (a.get("as_name"), a.get("org"), a.get("country")) if x)
        rows.append(("asn", a.get("asn") or a.get("ip", ""), "", detail, "", "", "false"))

    return rows


@router.get("/footprint/{sample_id}/export", response_model=None)
async def export_footprint(
    sample_id: str,
    format: str = Query("json", pattern="^(json|csv)$", description="json (structured) or csv (flat IOC sheet)"),
    mock: int = Query(0, ge=0, le=1, description="Force clearly-labeled synthetic data instead of live lookups"),
):
    """Threat-intel handoff: the footprint's IOC rows as JSON or CSV.

    CSV flattens every collection (seed IPs, resolutions, passive DNS,
    certificates, siblings, registration networks, ASN) onto one sheet with a
    `collection` discriminator; JSON keeps the full structured payload.
    """
    with db_session() as conn:
        data = await footprint_service.build_footprint(conn, sample_id, mock=bool(mock))
    if data is None:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = f"{_EXPORT_FILENAME}-{data['sample']['name'].replace(' ', '_')}-{stamp}"

    if format == "json":
        payload = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "sample": data["sample"],
            "status": data["status"],
            "seed_ips": data["seed_ips"],
            "passive": data["passive"],
        }
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{base}.json"'},
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["collection", "indicator", "source_ip", "detail", "first_seen", "last_seen", "synthetic"])
    writer.writerows(_flatten_rows(data))
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{base}.csv"'},
    )
