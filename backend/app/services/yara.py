"""Dependency-free YARA-style sample scanner (roadmap 2.2 + signature lab).

`yara-python` is intentionally NOT a dependency (the backend is deliberately
dependency-light; see AGENTS.md). This service implements the subset of YARA
that matters for malware triage — named rules of ASCII/hex string patterns,
scanned against uploaded sample bytes — and returns the matched rule names,
which become the sample's `yara_rules` reputation evidence.

Two rule sources:

1. **Bundled** `RULES` (name → patterns + family + description) — the built-in
   signature set. Pattern syntax mirrors YARA's string atoms: ASCII
   substrings are matched case-insensitively, and `{ 4D 5A 90 }`-style hex
   blocks are matched literally with optional `??` wildcards.

2. **Custom** rules authored in the webapp's signature lab and persisted in
   the `settings` table (`custom_yara_rules`). They're parsed by
   `parse_rule_text` (a YARA-subset: named rule, `strings:` of ASCII/hex
   atoms, and a boolean `condition:` over `$id`s with any/all/none/not/and/
   or/parens) and merged into every `scan_sample` call — so a saved rule
   applies to future uploads live, no restart.
"""

import json
import re

# Matched-rule shape returned to callers / surfaced on the detail page.
MATCHED_RULE = tuple[str, str]  # (rule_name, family)


def _hex_block_to_regex(block: str) -> bytes | None:
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
    __slots__ = ("description", "family", "name", "patterns")

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


# ---------------------------------------------------------------------------
# Signature lab — user-authored rules (persisted in the settings table)
# ---------------------------------------------------------------------------

# settings-table key holding the custom rules JSON array.
CUSTOM_RULES_KEY = "custom_yara_rules"


class RuleSyntaxError(ValueError):
    """A user rule failed to parse; `message` is analyst-facing."""


class CompiledRule:
    """A parsed custom rule — named, with string atoms and a boolean
    condition. `evaluate(data)` returns (matched, hits) where `hits` is the
    list of string ids that matched (so the lab can show *why*). The original
    rule text is kept as `source` so persistence is lossless."""

    __slots__ = ("condition", "description", "family", "name", "source", "strings")

    def __init__(self, name: str, family: str, description: str, strings: dict[str, re.Pattern], condition, source: str = ""):
        self.name = name
        self.family = family
        self.description = description
        self.strings = strings
        self.condition = condition
        self.source = source

    def evaluate(self, data: bytes) -> tuple[bool, list[str]]:
        hits = [sid for sid, rx in self.strings.items() if rx.search(data)]
        matched = bool(self.condition(hits))
        return matched, hits


# -- Condition parsing (YARA subset) ------------------------------------------
# Grammar:
#   expr   := or_expr
#   or_expr:= and_expr ('or' and_expr)*
#   and_expr:= unary ('and' unary)*
#   unary  := 'not' unary | primary
#   primary:= '(' expr ')' | 'any of them' | 'all of them' | 'none of them'
#             | 'any of' '(' $id (, $id)* ')' | 'all of' '(' $id (, $id)* ')'
#             | '$id'
# `them` in any/all/none refers to every string in the rule.

_COND_TOKENS = re.compile(r"\(|\)|,|\$[A-Za-z0-9_]+|\bany of them\b|\ball of them\b|\bnone of them\b|\bany of\b|\ball of\b|\bnot\b|\band\b|\bor\b")


def _tokenize_condition(text: str) -> list[str]:
    return _COND_TOKENS.findall(text)


class _CondParser:
    def __init__(self, tokens: list[str], string_ids: set[str]):
        self.tokens = tokens
        self.pos = 0
        self.string_ids = string_ids

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str | None:
        tok = self.peek()
        if tok is not None:
            self.pos += 1
        return tok

    def expect(self, tok: str):
        got = self.take()
        if got != tok:
            raise RuleSyntaxError(f"condition: expected '{tok}', got {got or 'end of condition'}")

    def _string_ids(self, sids: list[str]) -> list[str]:
        unknown = [s for s in sids if s not in self.string_ids]
        if unknown:
            raise RuleSyntaxError(f"condition references undefined string(s): {', '.join(unknown)}")
        return sids

    def parse(self):
        node = self._or_expr()
        if self.peek() is not None:
            raise RuleSyntaxError(f"condition: unexpected token '{self.peek()}'")
        return node

    def _or_expr(self):
        node = self._and_expr()
        while self.peek() == "or":
            self.take()
            right = self._and_expr()
            left = node
            node = lambda s, l=left, r=right: l(s) or r(s)
        return node

    def _and_expr(self):
        node = self._unary()
        while self.peek() == "and":
            self.take()
            right = self._unary()
            left = node
            node = lambda s, l=left, r=right: l(s) and r(s)
        return node

    def _unary(self):
        if self.peek() == "not":
            self.take()
            inner = self._unary()
            return lambda s: not inner(s)
        return self._primary()

    def _primary(self):
        tok = self.peek()
        if tok is None:
            raise RuleSyntaxError("condition: unexpected end of expression")
        if tok == "(":
            self.take()
            node = self._or_expr()
            self.expect(")")
            return node
        if tok in ("any of", "all of"):
            self.take()
            self.expect("(")
            sids: list[str] = []
            while True:
                nxt = self.take()
                if nxt is None or not nxt.startswith("$"):
                    raise RuleSyntaxError(f"condition: expected $id in {tok}(...), got {nxt}")
                sids.append(nxt)
                if self.peek() == ",":
                    self.take()
                    continue
                break
            self.expect(")")
            ids = self._string_ids(sids)
            if tok == "any of":
                return lambda s, ids=ids: any(i in s for i in ids)
            return lambda s, ids=ids: all(i in s for i in ids)
        if tok in ("any of them", "all of them", "none of them"):
            self.take()
            ids = sorted(self.string_ids)
            if tok == "any of them":
                return lambda s, ids=ids: any(i in s for i in ids)
            if tok == "all of them":
                return lambda s, ids=ids: all(i in s for i in ids)
            return lambda s, ids=ids: not any(i in s for i in ids)
        if tok.startswith("$"):
            self.take()
            self._string_ids([tok])
            return lambda s, tok=tok: tok in s
        raise RuleSyntaxError(f"condition: unexpected token '{tok}'")


def parse_rule_text(text: str) -> CompiledRule:
    """Parse a YARA-subset rule into a CompiledRule.

    Accepted shape (loosely whitespace-insensitive):

        rule <name> {
            strings:
                $a = "ascii substring"
                $b = { 4D 5A ?? }
            condition:
                any of them        # or all of them / none of them / $a and $b / ...
        }

    Raises RuleSyntaxError (analyst-facing message) on any malformed input.
    """
    m = re.match(r"\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", text)
    if not m:
        raise RuleSyntaxError("rule must start with `rule <name> {`")
    name = m.group(1)
    rest = text[m.end() :]

    strings_m = re.search(r"\bstrings\s*:\s*(.*?)\bcondition\s*:\s*(.*?)\}\s*$", rest, re.DOTALL)
    if not strings_m:
        raise RuleSyntaxError("rule needs both `strings:` and `condition:` sections (and a closing `}`)")
    strings_body, condition_body = strings_m.group(1), strings_m.group(2)

    strings: dict[str, re.Pattern] = {}
    for line in strings_body.splitlines():
        line = line.strip()
        if not line:
            continue
        sm = re.match(r"^(\$[A-Za-z0-9_]+)\s*=\s*(.+)$", line)
        if not sm:
            raise RuleSyntaxError(f"strings: unparseable atom `{line}` — expected `$id = \"text\"` or `$id = {{ hex }}`")
        sid, value = sm.group(1), sm.group(2).strip()
        if sid in strings:
            raise RuleSyntaxError(f"strings: duplicate string id {sid}")
        if value.startswith("{"):
            rx = _hex_block_to_regex(value)
            if rx is None:
                raise RuleSyntaxError(f"strings: {sid} has an invalid hex block (must be `{{ 4D 5A ?? }}`-style)")
            strings[sid] = re.compile(rx)
        elif value.startswith('"') and value.endswith('"') and len(value) >= 2:
            strings[sid] = re.compile(re.escape(value[1:-1].encode("latin1", errors="ignore")), re.IGNORECASE)
        else:
            raise RuleSyntaxError(f"strings: {sid} value must be a quoted string or a {{ hex }} block")
    if not strings:
        raise RuleSyntaxError("strings: rule has no string atoms")

    tokens = _tokenize_condition(condition_body)
    if not tokens:
        raise RuleSyntaxError("condition: empty condition")
    condition = _CondParser(tokens, set(strings)).parse()

    return CompiledRule(
        name=name,
        family="custom",
        description=f"Custom signature: {name}",
        strings=strings,
        condition=condition,
        source=text,
    )


# -- Persistence (settings table) ----------------------------------------------


def load_custom_rules(conn) -> list[CompiledRule]:
    """Parse every stored custom rule; rules that no longer parse are dropped
    (a bad edit must never break the scanner). Stored as JSON under
    CUSTOM_RULES_KEY — [{name, family, description, source}] where `source` is
    the original rule text, re-parsed on load so edits stay live."""
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (CUSTOM_RULES_KEY,)).fetchone()
    if not row:
        return []
    try:
        stored = json.loads(row["value"] or "[]")
    except ValueError:
        return []
    out: list[CompiledRule] = []
    for entry in stored:
        try:
            rule = parse_rule_text(entry["source"])
        except (RuleSyntaxError, KeyError, TypeError):
            continue
        rule.family = entry.get("family") or "custom"
        rule.description = entry.get("description") or rule.description
        out.append(rule)
    return out


def save_custom_rules(conn, rules: list[CompiledRule]) -> None:
    """Persist custom rules (whole set — last write wins)."""
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (CUSTOM_RULES_KEY, json.dumps([
            {"name": r.name, "family": r.family, "description": r.description, "source": r.source}
            for r in rules
        ])),
    )


def add_custom_rule(conn, rule: CompiledRule) -> None:
    """Append one parsed rule to the stored set (name collision replaces)."""
    rules = load_custom_rules(conn)
    rules = [r for r in rules if r.name != rule.name]
    rules.append(rule)
    save_custom_rules(conn, rules)


def delete_custom_rule(conn, name: str) -> bool:
    """Remove a stored custom rule by name; False when it wasn't there."""
    rules = load_custom_rules(conn)
    kept = [r for r in rules if r.name != name]
    if len(kept) == len(rules):
        return False
    save_custom_rules(conn, kept)
    return True


def scan_sample_with_custom(data: bytes, conn) -> list[dict]:
    """Bundled + custom rules in one pass (custom first — lab rules win the
    analyst's attention). Callers pass their DB session; on any custom-rule
    failure the bundled scan still runs."""
    hits: list[dict] = []
    try:
        for rule in load_custom_rules(conn):
            matched, _ = rule.evaluate(data)
            if matched:
                hits.append({"name": rule.name, "family": rule.family, "description": rule.description})
    except Exception:
        pass
    hits.extend(scan_sample(data))
    return hits
