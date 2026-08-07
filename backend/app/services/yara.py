"""Dependency-free YARA-style sample scanner (roadmap 2.2).

`yara-python` is intentionally NOT a dependency (the backend is deliberately
dependency-light; see AGENTS.md). This service implements the subset of YARA
that matters for malware triage — named rules of ASCII/hex string patterns,
scanned against uploaded sample bytes — and returns the matched rule names,
which become the sample's `yara_rules` reputation evidence.

Rules live in `RULES` below (name → patterns + family + description). Pattern
syntax mirrors YARA's string atoms: ASCII substrings are matched case-
insensitively, and `{ 4D 5A 90 }`-style hex blocks are matched literally with
optional `??` wildcards.
"""

import re
from typing import Optional

# Matched-rule shape returned to callers / surfaced on the detail page.
MATCHED_RULE = tuple[str, str]  # (rule_name, family)


def _hex_block_to_regex(block: str) -> Optional[bytes]:
    """Translate a YARA-style `{ 4D 5A ?? 90 }` hex block to a regex pattern
    (bytes). `??` becomes a single-byte wildcard. Returns None if invalid."""
    cleaned = block.strip().strip("{}").replace(" ", "").replace("\n", "")
    if not cleaned or len(cleaned) % 2 != 0:
        return None
    out = bytearray()
    for i in range(0, len(cleaned), 2):
        pair = cleaned[i : i + 2]
        if pair == "??":
            out.append(ord("."))
        elif re.fullmatch(r"[0-9a-fA-F]{2}", pair):
            out += re.escape(bytes.fromhex(pair))
        else:
            return None
    return bytes(out)


def _compile_rule(patterns: list[str]) -> list[re.Pattern]:
    compiled: list[re.Pattern] = []
    for p in patterns:
        if p.startswith("{"):
            rx = _hex_block_to_regex(p)
            if rx is not None:
                compiled.append(re.compile(rx))
        else:
            # ASCII substring — case-insensitive across the whole blob.
            compiled.append(re.compile(re.escape(p.encode("latin1", errors="ignore")), re.IGNORECASE))
    return compiled


class _Rule:
    __slots__ = ("name", "family", "description", "patterns")

    def __init__(self, name: str, family: str, description: str, patterns: list[str]):
        self.name = name
        self.family = family
        self.description = description
        self.patterns = _compile_rule(patterns)

    def matches(self, data: bytes) -> bool:
        return any(rx.search(data) for rx in self.patterns)


# Bundled signature set — recognizable malware / implant artifacts. Kept small
# and explainable; each rule carries the family label shown to analysts.
RULES: list[_Rule] = [
    _Rule(
        "mz-header",
        "generic-windows",
        "PE executable header (MZ) — Windows binary",
        ["{ 4D 5A }"],
    ),
    _Rule(
        "elf-header",
        "generic-linux",
        "ELF executable header — Linux binary",
        ["{ 7F 45 4C 46 }"],
    ),
    _Rule(
        "macho-header",
        "generic-macos",
        "Mach-O binary header — macOS executable",
        ["{ FE ED FA CE }", "{ FE ED FA CF }", "{ CA FE BA BE }"],
    ),
    _Rule(
        "powershell-download-cradle",
        "download-cradle",
        "PowerShell IEX/WebClient download-and-execute cradle",
        ["IEX(", "Invoke-Expression", "Net.WebClient", "DownloadString"],
    ),
    _Rule(
        "encoded-powershell",
        "encoded-powershell",
        "Base64-encoded PowerShell command line",
        ["-EncodedCommand", "-enc ", " -enc\""],
    ),
    _Rule(
        "meterpreter",
        "metasploit",
        "Metasploit Meterpreter payload strings",
        ["METERPRETER", "meterpreter", "ReflectiveLoader"],
    ),
    _Rule(
        "cobaltstrike",
        "cobalt-strike",
        "Cobalt Strike beacon artifact strings",
        ["\x00\x00beacon", "windows/beacon_", "WSAStartup\\x00", "kerberos\\x00ticket"],
    ),
    _Rule(
        "mimikatz",
        "credential-theft",
        "Mimikatz credential-dumping artifact strings",
        ["sekurlsa", "kerberos::", "privilege::debug", "lsadump::"],
    ),
    _Rule(
        "ransom-note",
        "ransomware",
        "Ransom note marker (demand text embedded in the payload)",
        ["bitcoin", "your files have been encrypted", "decryptor", "wallet address"],
    ),
    _Rule(
        "reverse-shell-bash",
        "reverse-shell",
        "Bash /dev/tcp reverse-shell idiom",
        ["/dev/tcp/", "bash -i >&", "0>&1"],
    ),
    _Rule(
        "office-macro",
        "office-macro",
        "VBA macro auto-open marker",
        ["Auto_Open", "Workbook_Open", "Document_Open", "VBA"],
    ),
    _Rule(
        "lnk-command",
        "lnk-lure",
        "Windows shortcut invoking a command/script",
        ["powershell", "cmd /c", "wscript", "rundll32"],
    ),
]


def scan_sample(data: bytes) -> list[dict]:
    """Scan sample bytes against the bundled rules.

    Returns the matched rules as dicts (name, family, description) in rule
    order — empty list means no signature matched (honest "no hit", not an
    error).
    """
    hits: list[dict] = []
    for rule in RULES:
        if rule.matches(data):
            hits.append(
                {
                    "name": rule.name,
                    "family": rule.family,
                    "description": rule.description,
                }
            )
    return hits
