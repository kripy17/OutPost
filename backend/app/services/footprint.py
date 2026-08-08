"""Digital footprinting — roadmap scaffold.

Threat-intel concept: seed a sample's observed infrastructure (its C2 IPs)
and passively expand outward — passive-DNS resolutions, TLS certificates,
sibling infrastructure sharing a network — so one sample sketches the whole
campaign's infrastructure.

**Current state (roadmap):** the *seed* is real — every distinct destination
IP across the sample's runs, aggregated with hit counts, first/last seen,
affected runs, and cache-first reputations from the existing enrichment
cache. The *passive* layer (resolutions / certificates / sibling IPs) is a
stubbed interface: it returns empty collections with `source:
"not_configured"` until a real passive-intel provider (VirusTotal, Censys,
SecurityTrails, …) is wired in behind the same interface.

`mock=True` fabricates a deterministic, clearly-labeled synthetic footprint
from the seed IPs so the webapp can render and demo the UI shape. Synthetic
nodes carry `synthetic: true` and the response sets `status.generated =
"mock"` — never confusable with real intel.
"""

import hashlib
import ipaddress
from typing import Any, Optional

from ..models import samples as samples_store


def _seed_ips(conn, sample_name: str) -> list[dict]:
    """Aggregate every distinct destination IP the sample's runs reached.

    Real data, straight from the event store; reputation is a cache-first
    read of the existing enrichment cache (no new external calls here).
    """
    rows = conn.execute(
        """
        SELECT e.dest_ip,
               COUNT(*) AS hits,
               MIN(e.timestamp) AS first_seen,
               MAX(e.timestamp) AS last_seen,
               COUNT(DISTINCT e.run_id) AS run_count
        FROM events e
        JOIN runs r ON r.run_id = e.run_id
        WHERE r.sample_name = ? AND e.dest_ip IS NOT NULL
        GROUP BY e.dest_ip
        ORDER BY hits DESC, e.dest_ip
        """,
        (sample_name,),
    ).fetchall()

    seeds = []
    for row in rows:
        cached = conn.execute(
            "SELECT abuse_score, vt_malicious_count, reputation FROM enrichment_cache WHERE ip = ?",
            (row["dest_ip"],),
        ).fetchone()
        seeds.append(
            {
                "ip": row["dest_ip"],
                "hits": row["hits"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "run_count": row["run_count"],
                "reputation": cached["reputation"] if cached else "unknown",
                "abuse_score": cached["abuse_score"] if cached else None,
                "vt_malicious_count": cached["vt_malicious_count"] if cached else None,
            }
        )
    return seeds


# ---------------------------------------------------------------------------
# Passive layer — the stubbed interface. A real provider plugs in here.
# ---------------------------------------------------------------------------

def _mock_resolutions(seed: dict) -> list[dict]:
    """Deterministic fake passive-DNS rows for one seed IP (synthetic)."""
    digest = hashlib.sha256(seed["ip"].encode()).hexdigest()[:8]
    return [
        {
            "domain": f"c2-{digest}.cdn.shelf.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "synthetic": True,
        },
        {
            "domain": f"update-{digest[:6]}.victim-panel.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "synthetic": True,
        },
    ]


def _mock_certificates(seed: dict) -> list[dict]:
    digest = hashlib.sha256(seed["ip"].encode()).hexdigest()[:6]
    return [
        {
            "cn": f"*.cdn-{digest}.shelf.example",
            "issuer": "Synthetic CA",
            "not_before": seed["first_seen"],
            "not_after": seed["last_seen"],
            "synthetic": True,
        }
    ]


def _mock_sibling_ips(seed: dict) -> list[dict]:
    """Same-/24 neighbors, synthetically marked — 'shared host' hypothesis."""
    try:
        net = ipaddress.ip_network(f"{seed['ip']}/24", strict=False)
        hosts = list(net.hosts())
    except ValueError:
        return []
    pick = hosts[1:4]  # stable, deterministic neighbors
    return [
        {
            "ip": str(h),
            "relation": "same /24",
            "synthetic": True,
        }
        for h in pick
        if str(h) != seed["ip"]
    ]


def _passive_layer(seeds: list[dict], mock: bool) -> dict:
    """The stubbed passive surface. `mock` fills it with synthetic rows."""
    if not mock:
        return {
            "source": "not_configured",
            "resolutions": [],
            "certificates": [],
            "sibling_ips": [],
        }
    resolutions = [r for s in seeds for r in _mock_resolutions(s)]
    certificates = [c for s in seeds for c in _mock_certificates(s)]
    sibling_ips = [sib for s in seeds for sib in _mock_sibling_ips(s)]
    return {
        "source": "synthetic_demo",
        "resolutions": resolutions,
        "certificates": certificates,
        "sibling_ips": sibling_ips,
    }


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def build_footprint(conn, sample_id: str, mock: bool = False) -> Optional[dict]:
    """Build the footprint for an uploaded sample, or None if unknown."""
    sample = samples_store.get_sample(conn, sample_id)
    if not sample:
        return None

    seeds = _seed_ips(conn, sample["original_name"])
    passive = _passive_layer(seeds, mock)

    return {
        "sample": {
            "sample_id": sample["sample_id"],
            "name": sample["original_name"],
            "sha256": sample["sha256"],
            "platform": sample["detected_platform"],
            "family": sample.get("family"),
        },
        "runs": [
            dict(r)
            for r in conn.execute(
                "SELECT run_id, sample_name, started_at, completed_at FROM runs WHERE sample_name = ? ORDER BY started_at DESC",
                (sample["original_name"],),
            ).fetchall()
        ],
        "seed_ips": seeds,
        "passive": passive,
        "status": {
            "roadmap": True,
            "generated": "mock" if mock else None,
        },
    }
