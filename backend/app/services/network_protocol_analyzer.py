"""Network Protocol & C2 Beaconing Analytics Engine.

Provides automated network protocol inspection and traffic reconstruction
inspired by top-tier sandbox and digital forensics frameworks:
- DNS Conversation Ledger: domain parsing, DGA entropy analysis, tunneling heuristics.
- HTTP / Web Request Ledger: method, URL, host header, status, suspicious path indicators.
- TLS Handshake Analysis: SNI domain, JA3 client fingerprint matching against known C2 profiles.
- C2 Beaconing Heuristics: inter-arrival interval regularity, jitter analysis, and beaconing confidence.
- Connection Flow Table: unified protocol tuple aggregation with process attribution and threat classification.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
import sqlite3
from typing import Any

from ..core.schema import Reputation

# Suspicious Top-Level Domains frequently abused by threat actors
SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".cc", ".su", ".tk", ".buzz", ".club", ".bid",
    ".onion", ".bit", ".live", ".rest", ".casa", ".icu", ".loan", ".work",
    ".gq", ".cf", ".ml", ".ga",
}

# Dynamic DNS providers commonly leveraged for disposable C2 infrastructure
DYNAMIC_DNS_DOMAINS = {
    "duckdns.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org",
    "ngrok.io", "ngrok-free.app", "localtunnel.me", "serveo.net",
}

# Known TLS JA3 / Client Hello signatures for offensive and C2 tooling
KNOWN_JA3_SIGNATURES: dict[str, dict[str, str]] = {
    "a0e9f5d64349fb13191bc781f81f42e1": {"tool": "Cobalt Strike Malleable C2", "severity": "malicious"},
    "72a589da586844d7f0818ce684948eea": {"tool": "Cobalt Strike Default HTTPS", "severity": "malicious"},
    "6526330830184e2e98218177a4565780": {"tool": "Cobalt Strike Beacon", "severity": "malicious"},
    "e7d705a3286e19ea42f587b344ee6865": {"tool": "Metasploit Meterpreter HTTPS", "severity": "malicious"},
    "eb1d94de9e816633501a2f6430fae39d": {"tool": "Metasploit Reverse HTTPS", "severity": "malicious"},
    "4d7a28d6f22da2d1491e0a29486c8f94": {"tool": "Emotet Banking Trojan / C2", "severity": "malicious"},
    "b386946a5a44d1ddcc843bc75336df1a": {"tool": "AsyncRAT / Quasar Client", "severity": "malicious"},
    "573e04512e0a221ee3e4a107ef414777": {"tool": "Go Offensive Framework / C2", "severity": "suspicious"},
    "b32309a26951912be7dba376398abc3b": {"tool": "Scripted Python / CLI Client", "severity": "suspicious"},
}

# Known C2 URI path patterns
C2_PATH_PATTERNS = [
    re.compile(r"/gate\.php", re.IGNORECASE),
    re.compile(r"/api/v[0-9]+/beacon", re.IGNORECASE),
    re.compile(r"/beacon/?$", re.IGNORECASE),
    re.compile(r"/tasks/poll", re.IGNORECASE),
    re.compile(r"/submit\.php\?id=", re.IGNORECASE),
    re.compile(r"/admin\.php\?c=", re.IGNORECASE),
    re.compile(r"/pixel\.gif\?session=", re.IGNORECASE),
    re.compile(r"/connect\.ashx", re.IGNORECASE),
    re.compile(r"/payloads?/[a-f0-9]{16,64}", re.IGNORECASE),
]

SUSPICIOUS_USER_AGENTS = [
    "curl/", "python-requests", "powershell", "wget", "go-http-client",
    "winhttp", "bitsadmin", "certutil",
]


def calculate_string_entropy(text: str) -> float:
    """Compute Shannon entropy on a string (e.g. domain label)."""
    if not text:
        return 0.0
    text_lower = text.lower()
    counts = Counter(text_lower)
    total = len(text_lower)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return round(entropy, 3)


def evaluate_dga_score(domain: str) -> tuple[float, list[str]]:
    """Compute DGA (Domain Generation Algorithm) confidence score (0.0 to 1.0)
    and return specific threat indicators."""
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return 0.0, []

    indicators: list[str] = []
    labels = clean_domain.split(".")
    base_name = labels[0] if labels else clean_domain

    entropy = calculate_string_entropy(base_name)
    score = 0.0

    # 1. High Shannon entropy
    if entropy >= 3.6:
        score += 0.45
        indicators.append(f"High Shannon entropy ({entropy})")
    elif entropy >= 3.2:
        score += 0.25
        indicators.append(f"Elevated Shannon entropy ({entropy})")

    # 2. Length check (DGA domains are frequently 12-25 chars in base name)
    if len(base_name) >= 15:
        score += 0.20
        indicators.append(f"Unusually long domain base ({len(base_name)} chars)")
    elif len(base_name) >= 10:
        score += 0.10

    # 3. Consonant to vowel ratio
    vowels = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")
    v_count = sum(1 for c in base_name if c in vowels)
    c_count = sum(1 for c in base_name if c in consonants)
    if c_count > 0 and v_count == 0 and len(base_name) >= 5:
        score += 0.35
        indicators.append("Zero vowels in domain label (consonant clustering)")
    elif v_count > 0 and (c_count / v_count) >= 4.0:
        score += 0.20
        indicators.append(f"High consonant-to-vowel ratio ({c_count}:{v_count})")

    # 4. Digits mixed in domain name
    digit_count = sum(1 for c in base_name if c.isdigit())
    if digit_count >= 3:
        score += 0.15
        indicators.append(f"Multiple randomized digits ({digit_count}) in domain")

    # 5. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if clean_domain.endswith(tld):
            score += 0.25
            indicators.append(f"Abused high-risk TLD: {tld}")
            break

    # 6. Dynamic DNS
    for ddns in DYNAMIC_DNS_DOMAINS:
        if clean_domain.endswith(ddns):
            score += 0.20
            indicators.append(f"Dynamic DNS host: {ddns}")
            break

    final_score = min(round(score, 2), 1.0)
    return final_score, indicators


def analyze_beaconing_intervals(timestamps_iso: list[str]) -> dict[str, Any]:
    """Calculate inter-arrival regularity, jitter percentage, and C2 beaconing score.
    A low jitter (< 25%) indicates regular, clock-based periodic beaconing."""
    if len(timestamps_iso) < 3:
        return {
            "is_beaconing": False,
            "beaconing_score": 0,
            "connection_count": len(timestamps_iso),
            "interval_mean_sec": 0.0,
            "interval_stdev_sec": 0.0,
            "jitter_pct": 100.0,
            "verdict": "Insufficient observations (<3 connections)",
        }

    # Parse and sort timestamps
    parsed: list[datetime] = []
    for ts in timestamps_iso:
        try:
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts)
            parsed.append(dt)
        except Exception:
            continue

    if len(parsed) < 3:
        return {
            "is_beaconing": False,
            "beaconing_score": 0,
            "connection_count": len(parsed),
            "interval_mean_sec": 0.0,
            "interval_stdev_sec": 0.0,
            "jitter_pct": 100.0,
            "verdict": "Timestamp parse failure",
        }

    parsed.sort()
    intervals = [(parsed[i + 1] - parsed[i]).total_seconds() for i in range(len(parsed) - 1)]

    # Filter out immediate bursts (<0.2 sec) to find underlying sleep interval
    filtered_intervals = [x for x in intervals if x >= 0.2]
    if len(filtered_intervals) < 2:
        return {
            "is_beaconing": False,
            "beaconing_score": 10,
            "connection_count": len(parsed),
            "interval_mean_sec": round(sum(intervals) / len(intervals), 2) if intervals else 0.0,
            "interval_stdev_sec": 0.0,
            "jitter_pct": 0.0,
            "verdict": "High-frequency burst traffic",
        }

    n = len(filtered_intervals)
    mean_val = sum(filtered_intervals) / n
    variance = sum((x - mean_val) ** 2 for x in filtered_intervals) / n
    stdev_val = math.sqrt(variance)

    jitter_pct = round((stdev_val / mean_val) * 100.0, 1) if mean_val > 0 else 100.0

    # Score beaconing: low jitter + reasonable count gives high score
    score = 0
    if jitter_pct <= 15.0:
        score += 65
    elif jitter_pct <= 30.0:
        score += 45
    elif jitter_pct <= 50.0:
        score += 25

    if len(parsed) >= 10:
        score += 25
    elif len(parsed) >= 5:
        score += 15

    score = min(score, 100)
    is_beaconing = score >= 50 and len(parsed) >= 4

    if is_beaconing and jitter_pct <= 20.0:
        verdict = f"High Confidence C2 Beacon (mean interval: {mean_val:.1f}s, jitter: {jitter_pct}%)"
    elif is_beaconing:
        verdict = f"Suspicious Periodic Heartbeat (mean interval: {mean_val:.1f}s, jitter: {jitter_pct}%)"
    elif score >= 30:
        verdict = f"Low Jitter Activity (jitter: {jitter_pct}%)"
    else:
        verdict = "Normal Interactive Traffic"

    return {
        "is_beaconing": is_beaconing,
        "beaconing_score": score,
        "connection_count": len(parsed),
        "interval_mean_sec": round(mean_val, 2),
        "interval_stdev_sec": round(stdev_val, 2),
        "jitter_pct": jitter_pct,
        "verdict": verdict,
    }


def analyze_run_network_telemetry(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform comprehensive network protocol analysis over a batch of run/telemetry events."""
    dns_records_by_query: dict[str, dict[str, Any]] = {}
    http_requests: list[dict[str, Any]] = []
    tls_handshakes: list[dict[str, Any]] = []
    flows_map: dict[tuple, dict[str, Any]] = {}
    timestamps_by_ip: dict[str, list[str]] = defaultdict(list)

    for ev in events:
        dest_ip = ev.get("dest_ip")
        dest_port = ev.get("dest_port")
        protocol = (ev.get("protocol") or "").upper() or "TCP"
        timestamp = ev.get("timestamp") or ""
        proc_name = ev.get("process_name") or "unknown"
        pid = ev.get("pid")
        cmdline = ev.get("command_line") or ""
        query = ev.get("query")
        tls_sni = ev.get("tls_sni")
        ja3 = ev.get("tls_ja3") or ev.get("ja3")
        raw_record = ev.get("raw_record") or ""

        # Track timestamps per destination for beaconing analysis
        if dest_ip and timestamp:
            timestamps_by_ip[dest_ip].append(timestamp)

        # 1. DNS Parsing
        dns_query_candidate = query
        if not dns_query_candidate and ("dns" in protocol.lower() or dest_port == 53):
            # Check if domain is in command_line or raw_record
            m = re.search(r"(?:nslookup|dig|host|ping)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", cmdline)
            if m:
                dns_query_candidate = m.group(1)

        if dns_query_candidate:
            q_clean = dns_query_candidate.strip().lower().rstrip(".")
            if q_clean not in dns_records_by_query:
                dga_score, dga_indicators = evaluate_dga_score(q_clean)
                is_tunneling = len(q_clean) > 45 or any(len(label) > 30 for label in q_clean.split("."))
                if is_tunneling:
                    dga_indicators.append("Suspected DNS tunneling (label length > 30 bytes)")

                category = "Standard"
                if is_tunneling:
                    category = "DNS Tunneling Suspect"
                elif dga_score >= 0.65:
                    category = "DGA Suspect"
                elif any(q_clean.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    category = "Suspicious TLD"
                elif any(q_clean.endswith(ddns) for ddns in DYNAMIC_DNS_DOMAINS):
                    category = "Dynamic DNS"

                dns_records_by_query[q_clean] = {
                    "query": q_clean,
                    "record_type": "A",
                    "resolved_ips": [],
                    "query_count": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "dga_score": dga_score,
                    "is_dga_suspect": dga_score >= 0.65 or is_tunneling,
                    "threat_indicators": dga_indicators,
                    "category": category,
                }
            rec = dns_records_by_query[q_clean]
            rec["query_count"] += 1
            rec["last_seen"] = timestamp
            if dest_ip and dest_ip != "127.0.0.1" and dest_ip not in rec["resolved_ips"]:
                rec["resolved_ips"].append(dest_ip)

        # 2. TLS Handshakes & JA3 Fingerprinting
        if tls_sni or ja3 or dest_port in (443, 8443) or "tls" in protocol.lower() or "ssl" in protocol.lower():
            if tls_sni or ja3:
                ja3_clean = (ja3 or "").lower().strip()
                known = KNOWN_JA3_SIGNATURES.get(ja3_clean)
                is_sus = bool(known) or (tls_sni and any(tls_sni.endswith(tld) for tld in SUSPICIOUS_TLDS))
                tls_handshakes.append({
                    "timestamp": timestamp,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port or 443,
                    "sni": tls_sni,
                    "ja3": ja3_clean or None,
                    "known_tool": known["tool"] if known else None,
                    "severity": known["severity"] if known else ("suspicious" if is_sus else "info"),
                    "process_name": proc_name,
                    "pid": pid,
                })

        # 3. HTTP / Web Requests
        is_web = dest_port in (80, 8080, 8000, 8888, 3000) or any(
            x in cmdline.lower() for x in ("http://", "https://", "curl ", "wget ", "urllib")
        )
        if is_web or any(p.search(cmdline) for p in C2_PATH_PATTERNS):
            method = "GET"
            if "-X POST" in cmdline or "--data" in cmdline or "POST" in raw_record:
                method = "POST"
            elif "-X PUT" in cmdline:
                method = "PUT"

            url_match = re.search(r"https?://[^\s\"']+", cmdline)
            target_url = url_match.group(0) if url_match else f"http://{dest_ip or 'unknown'}:{dest_port or 80}/"
            
            # Extract path
            path = "/"
            pm = re.search(r"https?://[^/]+(/[^?\s\"']*)", target_url)
            if pm:
                path = pm.group(1)

            threats: list[str] = []
            for p in C2_PATH_PATTERNS:
                if p.search(path):
                    threats.append(f"Known C2 path pattern matched: {path}")
                    break

            if dest_ip and not tls_sni and not query:
                # Direct IP connection
                threats.append("Direct IP address destination (no domain name)")

            if any(ua in cmdline.lower() for ua in SUSPICIOUS_USER_AGENTS):
                threats.append("Scripted / automated client user-agent")

            http_requests.append({
                "timestamp": timestamp,
                "method": method,
                "url": target_url,
                "host": dest_ip or "unknown",
                "path": path,
                "dest_ip": dest_ip,
                "dest_port": dest_port or 80,
                "status_code": 200,
                "is_suspicious": len(threats) > 0,
                "threat_indicators": threats,
                "process_name": proc_name,
                "pid": pid,
            })

        # 4. Connection Flow Aggregation
        if dest_ip:
            flow_key = (protocol, dest_ip, dest_port, pid)
            if flow_key not in flows_map:
                flows_map[flow_key] = {
                    "flow_id": f"{protocol}-{dest_ip}-{dest_port}-{pid}",
                    "protocol": protocol,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "process_name": proc_name,
                    "pid": pid,
                    "direction": "outbound",
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "connection_count": 0,
                    "reputation": "clean" if dest_ip.startswith("127.") or dest_ip == "::1" else "unknown",
                    "threat_indicators": [],
                }
            f = flows_map[flow_key]
            f["connection_count"] += 1
            f["last_seen"] = timestamp

    # Compute C2 Beaconing Heuristics per destination IP
    beaconing_analysis_by_ip: dict[str, dict[str, Any]] = {}
    high_confidence_beacons: list[dict[str, Any]] = []

    for ip, ts_list in timestamps_by_ip.items():
        if len(ts_list) >= 3:
            stats = analyze_beaconing_intervals(ts_list)
            stats["dest_ip"] = ip
            beaconing_analysis_by_ip[ip] = stats
            if stats["is_beaconing"]:
                high_confidence_beacons.append(stats)
                # Update flow reputation
                for f in flows_map.values():
                    if f["dest_ip"] == ip:
                        f["reputation"] = "malicious"
                        f["threat_indicators"].append(f"Automated C2 Beaconing: {stats['verdict']}")

    # Check for known malicious JA3s on flows
    for hs in tls_handshakes:
        if hs.get("severity") == "malicious":
            for f in flows_map.values():
                if f["dest_ip"] == hs["dest_ip"]:
                    f["reputation"] = "malicious"
                    f["threat_indicators"].append(f"Malicious TLS Fingerprint: {hs.get('known_tool')}")

    # Build summary metrics
    return {
        "dns_conversations": list(dns_records_by_query.values()),
        "http_requests": http_requests,
        "tls_handshakes": tls_handshakes,
        "flows": list(flows_map.values()),
        "c2_beaconing": {
            "evaluated_endpoints": len(timestamps_by_ip),
            "beaconing_detected": len(high_confidence_beacons) > 0,
            "beacon_count": len(high_confidence_beacons),
            "beacons": high_confidence_beacons,
            "details_by_ip": beaconing_analysis_by_ip,
        },
        "metrics": {
            "total_dns_queries": sum(r["query_count"] for r in dns_records_by_query.values()),
            "dga_suspect_count": sum(1 for r in dns_records_by_query.values() if r["is_dga_suspect"]),
            "http_request_count": len(http_requests),
            "suspicious_http_count": sum(1 for r in http_requests if r["is_suspicious"]),
            "tls_handshake_count": len(tls_handshakes),
            "unique_destinations_count": len(timestamps_by_ip),
            "unique_flows_count": len(flows_map),
        },
    }


def analyze_run(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    """Load all events for a given run and run the protocol analyzer."""
    rows = conn.execute(
        "SELECT * FROM events WHERE run_id = ? ORDER BY timestamp ASC",
        (run_id,),
    ).fetchall()
    events = [dict(r) for r in rows]
    return analyze_run_network_telemetry(events)


def analyze_sample(conn: sqlite3.Connection, sample_id: str) -> dict[str, Any]:
    """Load all events across all runs of a sample and return aggregated network analysis."""
    sample = conn.execute(
        "SELECT sample_id, original_name, sha256 FROM samples WHERE sample_id = ?",
        (sample_id,),
    ).fetchone()
    if not sample:
        return {"error": "Sample not found"}

    rows = conn.execute(
        "SELECT e.* FROM events e JOIN runs r ON e.run_id = r.run_id "
        "WHERE r.sample_name = ? ORDER BY e.timestamp ASC",
        (sample["original_name"],),
    ).fetchall()
    events = [dict(r) for r in rows]
    result = analyze_run_network_telemetry(events)
    result["sample_id"] = sample_id
    result["sample_name"] = sample["original_name"]
    return result
