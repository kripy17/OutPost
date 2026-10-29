"""OutPost Static Analysis: In-Memory YARA Scanner.

Provides fast, offline YARA rule evaluation with:
- Bundled MIT-licensed rules (EICAR, UPX/ASPack/MPRESS packers, script cradles, webshells)
- Extensible custom rule compilation
- Exact string offset and matched byte extraction
- 5-second per-scan execution timeout to protect against catastrophic regex backtracking
- Categorized impact evaluation: Authoritative (Malicious) vs Informational (Packers/Stubs)
"""

import glob
import os
import time
from typing import Any, TypedDict

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False


class YaraMatchedString(TypedDict):
    identifier: str
    offset: int
    offset_hex: str
    length: int
    matched_bytes: str  # Hex-encoded string


class YaraMatch(TypedDict):
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[YaraMatchedString]


class YaraScanResult(TypedDict):
    matches: list[YaraMatch]
    matched_rule_names: list[str]
    has_authoritative_match: bool
    has_informational_match: bool
    scan_time_ms: float
    rules_count: int
    timed_out: bool
    error: str | None


_COMPILED_RULES_CACHE: Any = None
_DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def get_bundled_rule_filepaths() -> dict[str, str]:
    """Discover all bundled .yar rule files grouped by namespace."""
    if not os.path.isdir(_DEFAULT_RULES_DIR):
        return {}
    rule_files = glob.glob(os.path.join(_DEFAULT_RULES_DIR, "*.yar"))
    namespaces: dict[str, str] = {}
    for rf in sorted(rule_files):
        ns = os.path.splitext(os.path.basename(rf))[0]
        namespaces[ns] = rf
    return namespaces


def compile_bundled_rules() -> Any:
    """Compile bundled YARA rules into an in-memory Rules object."""
    global _COMPILED_RULES_CACHE
    if _COMPILED_RULES_CACHE is not None:
        return _COMPILED_RULES_CACHE

    if not _YARA_AVAILABLE:
        return None

    filepaths = get_bundled_rule_filepaths()
    if not filepaths:
        return None

    try:
        _COMPILED_RULES_CACHE = yara.compile(filepaths=filepaths)
    except Exception as exc:
        _COMPILED_RULES_CACHE = None
        raise RuntimeError(f"Failed to compile bundled YARA rules: {exc}") from exc

    return _COMPILED_RULES_CACHE


def scan_payload_yara(
    data: bytes,
    custom_rule_sources: list[str] | None = None,
    timeout_seconds: int = 5,
) -> YaraScanResult:
    """Scan raw payload bytes against bundled and custom YARA rules.

    Execution is bounded by timeout_seconds (default 5s) to guarantee worker responsiveness.
    """
    t0 = time.perf_counter()

    if not _YARA_AVAILABLE:
        # Fallback to pure-Python scanner from legacy services.yara if libyara is missing
        from ..yara import scan_sample
        legacy_hits = scan_sample(data)
        matches: list[YaraMatch] = []
        for h in legacy_hits:
            is_eicar = "eicar" in h["name"].lower()
            matches.append({
                "rule": h["name"],
                "namespace": "legacy",
                "tags": ["malware" if is_eicar else "suspicious"],
                "meta": {
                    "description": h.get("description", ""),
                    "author": "OutPost",
                    "severity": "high" if is_eicar else "medium",
                    "verdict_impact": "authoritative" if is_eicar else "informational",
                },
                "strings": [],
            })
        has_auth = any(m["meta"].get("verdict_impact") == "authoritative" for m in matches)
        has_info = any(m["meta"].get("verdict_impact") == "informational" for m in matches)
        t1 = time.perf_counter()
        return {
            "matches": matches,
            "matched_rule_names": [m["rule"] for m in matches],
            "has_authoritative_match": has_auth,
            "has_informational_match": has_info,
            "scan_time_ms": round((t1 - t0) * 1000, 2),
            "rules_count": len(legacy_hits),
            "timed_out": False,
            "error": "yara-python not installed; fallback scanner evaluated",
        }

    rules_obj = compile_bundled_rules()
    if rules_obj is None and not custom_rule_sources:
        return {
            "matches": [],
            "matched_rule_names": [],
            "has_authoritative_match": False,
            "has_informational_match": False,
            "scan_time_ms": 0.0,
            "rules_count": 0,
            "timed_out": False,
            "error": "No YARA rules available",
        }

    # If custom rules provided, compile combined ruleset via sources
    if custom_rule_sources:
        try:
            sources_dict: dict[str, str] = {}
            for ns, fpath in get_bundled_rule_filepaths().items():
                with open(fpath, "r", encoding="utf-8") as fh:
                    sources_dict[ns] = fh.read()
            for i, src in enumerate(custom_rule_sources):
                sources_dict[f"custom_{i}"] = src
            rules_obj = yara.compile(sources=sources_dict)
        except Exception:
            # Fallback to bundled rules if custom rule fails compilation
            rules_obj = compile_bundled_rules()

    timed_out = False
    raw_matches = []
    try:
        raw_matches = rules_obj.match(data=data, timeout=timeout_seconds)
    except yara.TimeoutError:
        timed_out = True
    except Exception:
        pass

    matches: list[YaraMatch] = []
    for rm in raw_matches:
        meta_dict = dict(rm.meta) if rm.meta else {}
        # Default verdict_impact to authoritative unless tagged or meta says informational
        if "verdict_impact" not in meta_dict:
            if "informational" in rm.tags or "packer" in rm.tags:
                meta_dict["verdict_impact"] = "informational"
            else:
                meta_dict["verdict_impact"] = "authoritative"

        string_matches: list[YaraMatchedString] = []
        for s in rm.strings:
            # yara-python 4.x StringMatch object
            ident = getattr(s, "identifier", str(s))
            instances = getattr(s, "instances", [])
            for inst in instances:
                off = getattr(inst, "offset", 0)
                mdata = getattr(inst, "matched_data", b"")
                string_matches.append({
                    "identifier": ident,
                    "offset": off,
                    "offset_hex": f"0x{off:08X}",
                    "length": len(mdata),
                    "matched_bytes": mdata[:64].hex(),
                })

        matches.append({
            "rule": rm.rule,
            "namespace": rm.namespace,
            "tags": list(rm.tags),
            "meta": meta_dict,
            "strings": string_matches,
        })

    has_auth = any(m["meta"].get("verdict_impact") == "authoritative" for m in matches)
    has_info = any(m["meta"].get("verdict_impact") == "informational" for m in matches)
    t1 = time.perf_counter()

    return {
        "matches": matches,
        "matched_rule_names": [m["rule"] for m in matches],
        "has_authoritative_match": has_auth,
        "has_informational_match": has_info,
        "scan_time_ms": round((t1 - t0) * 1000, 2),
        "rules_count": len(matches),
        "timed_out": timed_out,
        "error": "scan timed out" if timed_out else None,
    }
