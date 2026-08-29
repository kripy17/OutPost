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

import ipaddress
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


def _plausible_text_ipv4(value: str) -> bool:
    """Stricter gate for IPs harvested from free text — RFC1918 / CGNAT /
    loopback / multicast ranges and version-number lookalikes (1.2.3.4) stay
    out of the IOC workspace. Structured `related_ip` bypasses this gate:
    lateral-movement provenance on a private address is a real, analyst-useful
    indicator. Deliberately NOT a blanket `is_private` — modern Python folds
    TEST-NET documentation ranges (198.51.100.0/24, 203.0.113.0/24, …) into
    that flag, and OutPost's demo data uses them as stand-in public C2s."""
    if not _valid_ipv4(value):
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_loopback or addr.is_link_local or addr.is_multicast
        or addr.is_unspecified
        or any(
            addr in n
            for n in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("100.64.0.0/10"),
                ipaddress.ip_network("0.0.0.0/8"),
            )
        )
    )


# A token immediately preceded by version-ish context is software metadata,
# not an address ("version 1.2.3.4", "v=6.7.8.9").
_VERSION_CONTEXT_RE = re.compile(r"(?:version|ver\.?|v)\s*[:=]?\s*$", re.IGNORECASE)


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
    for m in _IPV4_RE.finditer(text):
        ip = m.group(1)
        prefix = text[max(0, m.start() - 12):m.start()]
        if _VERSION_CONTEXT_RE.search(prefix):
            continue  # version number in context — not an address
        if _plausible_text_ipv4(ip):
            found.append((ip, "ip"))

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
