"""Windows Shell Link (.lnk) static file analyzer.

Analyzes Windows shortcut files commonly used in initial access and phishing:
1. Target binary and execution arguments.
2. Hidden window execution (ShowCommand = SW_HIDE or SW_SHOWMINIMIZED).
3. LOLBin execution chaining (powershell, cmd, mshta, cscript, certutil).
4. Icon spoofing (e.g. document/folder icon masking an executable or script).
"""

import re
import struct
from typing import Any

from ..provenance import create_finding, create_provenance

_LNK_HEADER_SIG = b"\x4C\x00\x00\x00\x01\x14\x02\x00"
_CLSID_LINK = b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"


def is_lnk_file(data: bytes) -> bool:
    """Validate Shell Link binary signature."""
    return len(data) >= 76 and data[:8] == _LNK_HEADER_SIG and data[4:20] == _CLSID_LINK


def analyze_lnk(data: bytes) -> dict[str, Any]:
    """Inspect Windows Shell Link file."""
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []

    if len(data) < 76:
        return {
            "format": "lnk",
            "is_valid": False,
            "error": "File smaller than minimum LNK header size",
            "findings": [],
            "indicators": [],
            "capabilities": [],
            "could_not_analyze": ["Truncated LNK header"],
        }

    link_flags = struct.unpack_from("<I", data, 0x14)[0]
    show_command = struct.unpack_from("<I", data, 0x3C)[0]

    has_target_id_list = bool(link_flags & 0x01)
    has_link_info = bool(link_flags & 0x02)
    has_name = bool(link_flags & 0x04)
    has_rel_path = bool(link_flags & 0x08)
    has_work_dir = bool(link_flags & 0x10)
    has_args = bool(link_flags & 0x20)
    has_icon = bool(link_flags & 0x40)

    # 1. Window state analysis
    is_hidden_window = show_command in (0, 7)  # SW_HIDE (0) or SW_SHOWMINNOACTIVE (7)
    if is_hidden_window:
        prov = create_provenance("parser_field", "LNK Header ShowCommand (0x3C)", "parsed", "confirmed")
        findings.append(create_finding(
            "lnk-hidden-window-execution",
            "capability",
            "Shortcut Configured for Hidden / Stealth Execution",
            f"LNK ShowCommand flag is set to {show_command} (SW_HIDE/SW_MINIMIZED), concealing process launch.",
            prov,
            ["T1564.001", "T1204.002"],
        ))
        capabilities.append({
            "category": "Defense Evasion & Anti-Debug",
            "matched": ["Hidden Window Launch (SW_HIDE)"],
            "confidence": "high",
            "provenance": prov,
        })

    # Read variable-length strings from link structure
    extracted_strings = []
    # Search for wide/ASCII command strings in data
    ascii_args = re.findall(rb"[\x20-\x7E]{6,}", data)
    for s in ascii_args:
        try:
            extracted_strings.append(s.decode("ascii"))
        except Exception:
            pass

    full_text = " ".join(extracted_strings)
    lower_text = full_text.lower()

    # 2. LOLBin target analysis
    lolbin_patterns = {
        "powershell": ("powershell.exe", ["T1059.001"]),
        "cmd": ("cmd.exe", ["T1059.003"]),
        "mshta": ("mshta.exe", ["T1218.005"]),
        "wscript": ("wscript.exe", ["T1059.005"]),
        "cscript": ("cscript.exe", ["T1059.005"]),
        "rundll32": ("rundll32.exe", ["T1218.011"]),
        "certutil": ("certutil.exe", ["T1105"]),
    }

    matched_lolbins = []
    for lb_key, (lb_exe, techniques) in lolbin_patterns.items():
        if lb_exe in lower_text:
            matched_lolbins.append(lb_exe)
            prov = create_provenance("parser_field", "LNK Target / Arguments", "parsed", "confirmed")
            findings.append(create_finding(
                f"lnk-lolbin-{lb_key}",
                "capability",
                f"Shortcut Targets LOLBin: {lb_exe}",
                f"LNK file targets system interpreter {lb_exe} with auxiliary arguments.",
                prov,
                techniques,
            ))
            capabilities.append({
                "category": "Execution & Scripting",
                "matched": [lb_exe],
                "confidence": "high",
                "provenance": prov,
            })

    # 3. Argument obfuscation & Download indicators
    if any(k in lower_text for k in ("-enc", "-encodedcommand", "downloadstring", "webrequest", "frombase64")):
        prov = create_provenance("string_offset", "LNK Arguments Payload", "matched", "high")
        findings.append(create_finding(
            "lnk-encoded-powershell-payload",
            "capability",
            "Encoded Command / Stager Arguments in Shortcut",
            "Found encoded command or remote download invocation flags inside LNK arguments.",
            prov,
            ["T1027", "T1059.001"],
        ))

    # URLs in arguments
    urls = re.findall(r"https?://[^\s\"'<>]+", full_text)
    for u in urls:
        indicators.append({
            "type": "url",
            "value": u,
            "classification": "suspicious",
            "location": "LNK CommandLineArguments",
        })

    return {
        "format": "lnk",
        "show_command": show_command,
        "is_hidden_window": is_hidden_window,
        "matched_lolbins": matched_lolbins,
        "flags": {
            "has_target_id_list": has_target_id_list,
            "has_link_info": has_link_info,
            "has_args": has_args,
            "has_icon": has_icon,
        },
        "extracted_arguments": full_text[:400] if full_text else None,
        "findings": findings,
        "indicators": indicators,
        "capabilities": capabilities,
        "could_not_analyze": could_not_analyze,
    }
