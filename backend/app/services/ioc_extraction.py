"""Detection-side IOC population (P3.1) — the missing producer for the IOC
entity system.

The pipeline: a persisted finding's structured fields + details text are
scraped for unambiguous indicator token classes, each value is normalized
into the canonical representation, and the canonical IOC entity is created
or reused (UNIQUE(value, type) — five detections of one IP yield ONE entity
with multiple provenance rows). Provenance records where it came from:
always the finding, plus the triggering event when the rule is per-event.

Scope discipline: only token classes with precise regexes are extracted
(ip / url / domain-from-URL-host / hash / email). Bare-domain scraping of
free text is deliberately excluded — too many false positives — and
filepath/registry extraction waits for rules to expose those values as
structured fields. Volume stays proportional to detections, not raw events.

Failure isolation: `record_for_alert` never raises. IOC persistence is an
enrichment of the detection pipeline, not a single point of failure — an
unexpected error is logged and the detection result stands.
"""

import logging
import re

from ..core.schema import Alert  # noqa: F401  (type only)
from ..models import iocs as iocs_store

log = logging.getLogger("outpost.ioc_extraction")

_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_URL_RE = re.compile(r"\b(https?://[^\s\"'<>\\]+)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# Hex digests by length — longest first so a sha256 inside other hex is not
# partially matched as something shorter.
_HASH_RES = [
    (re.compile(r"\b([a-fA-F0-9]{64})\b"), "sha256"),
    (re.compile(r"\b([a-fA-F0-9]{40})\b"), "sha1"),
    (re.compile(r"\b([a-fA-F0-9]{32})\b"), "md5"),
]

_TRIM = ".,;:)\"']}"


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    if any(not p.isdigit() or int(p) > 255 for p in parts):
        return False
    # Loopback / unspecified / link-local broadcast are never meaningful IOCs.
    return not value.startswith(("127.", "0.0.0.0", "255.255.255.255"))


def _url_host(url: str) -> str | None:
    m = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
    return m.group(1) if m else None


def extract_from_alert(alert) -> list[tuple[str, str]]:
    """Pull (value, ioc_type) pairs from one alert: the structured
    `related_ip` first, then unambiguous tokens from the details text.
    Deduped on the canonical identity."""
    found: list[tuple[str, str]] = []
    if alert.related_ip and _valid_ipv4(alert.related_ip):
        found.append((alert.related_ip, "ip"))

    text = alert.details or ""
    urls = [u.rstrip(_TRIM) for u in _URL_RE.findall(text)]
    for url in urls:
        found.append((url, "url"))
        host = _url_host(url)
        # A URL contributes its host domain too — distinct indicators, both
        # analyst-useful — unless the host is itself an IP (already covered).
        if host and not _IPV4_RE.fullmatch(host):
            found.append((host, "domain"))
    for regex, _digest in _HASH_RES:
        found.extend((h, "hash") for h in regex.findall(text))
    found.extend((e, "email") for e in _EMAIL_RE.findall(text))
    found.extend(
        (ip, "ip") for ip in _IPV4_RE.findall(text) if _valid_ipv4(ip)
    )

    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for value, ioc_type in found:
        normalized = iocs_store.normalize_value(value, ioc_type)
        key = (normalized, ioc_type)
        if key not in seen:
            seen.add(key)
            out.append((normalized, ioc_type))
    return out


def record_for_alert(conn, alert, finding_id: int, event_id: int | None = None) -> None:
    """Best-effort IOC population for one persisted finding. NEVER raises —
    a persistence problem must not lose the detection that surfaced it."""
    try:
        pairs = extract_from_alert(alert)
        if not pairs:
            return
        for value, ioc_type in pairs:
            ioc = iocs_store.observe_ioc(conn, value, ioc_type)
            iocs_store.add_provenance(conn, ioc["ioc_id"], "finding", finding_id)
            if event_id is not None:
                iocs_store.add_provenance(conn, ioc["ioc_id"], "event", event_id)
            iocs_store.link_finding(conn, ioc["ioc_id"], finding_id)
    except Exception:
        log.warning(
            "IOC population failed for finding %s (rule %s) — detection result preserved",
            finding_id,
            getattr(alert, "rule_id", "?"),
            exc_info=True,
        )
