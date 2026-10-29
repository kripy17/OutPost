"""Archive and container static file analyzer (ZIP, TAR, GZIP, BZIP2, XZ, 7z, ISO, CAB, RAR).

Provides safe container inspection with strict resource constraints:
1. Recursive extraction depth limit (max 3 levels).
2. Uncompressed total size limit (250 MB), single member limit (50 MB), and compression ratio guard (max 100:1).
3. Member extraction count limit (max 100 members).
4. Path traversal attack neutralization and detection.
5. Password-protected / encrypted payload detection.
6. Mark-of-the-Web (MOTW) evasion container detection (e.g. ISO/IMG mounting).
7. Nested payload analysis: Format identification, YARA scanning, deep PE/ELF/Script analysis,
   and threat propagation to container verdict.
"""

import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import tarfile
from typing import Any

from ..provenance import create_finding, create_provenance
from ..yara_scanner import scan_payload_yara

MAX_MEMBERS = 100
MAX_MEMBER_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_TOTAL_UNCOMPRESSED = 250 * 1024 * 1024  # 250 MB
MAX_DECOMPRESSION_RATIO = 100.0
MAX_RECURSION_DEPTH = 3

_DANGEROUS_EXTENSIONS = (
    ".exe", ".dll", ".scr", ".pif", ".cpl", ".sys", ".ocx",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".sh", ".bash", ".elf", ".bin", ".so",
    ".lnk", ".iso", ".img", ".vhd",
)


def sanitize_member_path(name: str) -> tuple[str, bool]:
    """Sanitize archive member path to neutralize directory traversal and absolute roots.

    Returns (sanitized_path, has_traversal_anomaly).
    """
    has_anomaly = False
    if "\0" in name:
        has_anomaly = True
        name = name.replace("\0", "")

    # Windows drive root prefix (e.g. C:)
    if re.match(r"^[a-zA-Z]:", name):
        has_anomaly = True
        name = re.sub(r"^[a-zA-Z]:[\\/]?", "", name)

    # Relative directory escape or absolute root
    if ".." in name or name.startswith(("/", "\\")):
        has_anomaly = True

    name = name.replace("\\", "/")
    parts = [p for p in name.split("/") if p and p != "."]
    safe_parts = []
    for p in parts:
        if p == "..":
            continue
        safe_parts.append(p)

    clean = "/".join(safe_parts) if safe_parts else os.path.basename(name) or "unnamed_member"
    return clean, has_anomaly


def is_archive_or_container(data: bytes) -> bool:
    """Check for standard archive and container signatures."""
    if data.startswith(b"PK\x03\x04"):
        return True
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return True
    if data.startswith(b"\x1F\x8B"):
        return True
    if data.startswith(b"BZh"):
        return True
    if data.startswith(b"\xFD7zXZ\x00"):
        return True
    if len(data) > 262 and data[257:262] == b"ustar":
        return True
    # ISO 9660 volume descriptor at offset 0x8000 (32768)
    if len(data) > 32774 and data[32769:32774] == b"CD001":
        return True
    if data.startswith(b"MSCF"):
        return True
    if data.startswith((b"Rar!\x1A\x07\x00", b"Rar!\x1A\x07\x01\x00")):
        return True
    return False


def _detect_member_format(data: bytes, name: str) -> str:
    """Identify binary or document format of an extracted member."""
    from .pe import is_pe
    from .elf import is_elf
    from .script import is_script
    from .office import is_office_document
    from .pdf import is_pdf_document
    from .lnk import is_lnk_file

    if is_pe(data):
        return "pe"
    if is_elf(data):
        return "elf"
    if is_office_document(data):
        return "office"
    if is_pdf_document(data):
        return "pdf"
    if is_lnk_file(data):
        return "lnk"
    if is_script(data):
        return "script"
    if is_archive_or_container(data):
        return "container"

    low = name.lower()
    if low.endswith((".txt", ".md", ".json", ".xml", ".csv", ".log", ".yaml", ".yml", ".ini", ".cfg", ".html", ".htm")):
        return "text"
    try:
        data.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


def _inspect_member_bytes(
    sanitized_name: str,
    raw_name: str,
    data: bytes,
    depth: int,
) -> dict[str, Any]:
    """Perform security and format inspection over extracted member bytes."""
    import hashlib
    from .pe import parse_deep_pe
    from .elf import parse_deep_elf
    from .script import analyze_script

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    fmt = _detect_member_format(data, sanitized_name)

    # 1. YARA Scanning
    yara_res = scan_payload_yara(data)
    has_auth = yara_res.get("has_authoritative_match", False)
    matched_rules = yara_res.get("matched_rule_names", [])

    verdict = "clean"
    verdict_reason = ""
    nested_res = None
    capabilities: list[str] = []

    if has_auth:
        verdict = "malicious"
        verdict_reason = f"YARA authoritative rule match: {', '.join(matched_rules)}"

    # 2. Deep Format Inspection
    if fmt == "pe":
        pe_info = parse_deep_pe(data)
        has_rwx = any("rwx" in a.get("title", "").lower() for a in pe_info.get("structural_anomalies", []))
        has_inj = any(c.get("category") == "Process Injection" for c in pe_info.get("capabilities", []))
        if has_rwx and has_inj:
            verdict = "malicious"
            verdict_reason = "PE Process Injection capability combined with non-standard RWX memory section"
        elif pe_info.get("packer"):
            if verdict == "clean":
                verdict = "insufficient_evidence"
                verdict_reason = f"Packed executable code ({pe_info.get('packer')})"
        capabilities.extend(c.get("category", "") for c in pe_info.get("capabilities", []))

    elif fmt == "elf":
        elf_info = parse_deep_elf(data)
        if elf_info.get("packer"):
            if verdict == "clean":
                verdict = "insufficient_evidence"
                verdict_reason = f"Packed ELF binary ({elf_info.get('packer')})"

    elif fmt == "script":
        script_info = analyze_script(data)
        if any("malicious" in f.get("category", "") or "ioc" in f.get("category", "") for f in script_info.get("findings", [])):
            verdict = "malicious"
            verdict_reason = "Script threat payload confirmed"

    elif fmt == "container" and (depth + 1) < MAX_RECURSION_DEPTH:
        nested_res = analyze_archive(data, depth=depth + 1)
        if any(m.get("verdict") == "malicious" for m in nested_res.get("members", [])):
            verdict = "malicious"
            verdict_reason = "Nested archive member contains malicious payload"

    return {
        "name": sanitized_name,
        "original_name": raw_name,
        "size": len(data),
        "sha256": sha256,
        "md5": md5,
        "format": fmt,
        "is_encrypted": False,
        "is_dir": False,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "yara_rules": matched_rules,
        "capabilities": sorted(list(set(capabilities))),
        "nested_archive": nested_res,
    }


def _analyze_zip(data: bytes, depth: int) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []
    file_entries: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    dangerous_payloads: list[str] = []
    is_encrypted = False
    is_bomb = False

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infolist = zf.infolist()
            total_uncompressed = sum(info.file_size for info in infolist)
            compressed_size = len(data)

            # Ratio guard (Zip bomb detection)
            if compressed_size >= 1024 and (total_uncompressed / compressed_size) > MAX_DECOMPRESSION_RATIO:
                is_bomb = True
                prov = create_provenance("parser_field", "ZIP Central Directory", "parsed", "confirmed")
                findings.append(create_finding(
                    "archive-decompression-bomb-detected",
                    "structure",
                    "Decompression Bomb (Zip Bomb) Ratio Detected",
                    f"Uncompressed ratio is {total_uncompressed / compressed_size:.1f}:1 (> 100:1 limit).",
                    prov,
                    ["T1499"],
                ))
                could_not_analyze.append("Decompression aborted: zip bomb safety threshold exceeded")
                return {
                    "format": "archive",
                    "container_type": "zip",
                    "file_count": len(infolist),
                    "extracted_count": 0,
                    "is_encrypted": False,
                    "is_bomb": True,
                    "dangerous_payloads": [],
                    "file_entries": [],
                    "members": [],
                    "findings": findings,
                    "indicators": indicators,
                    "structural_anomalies": [{
                        "title": "Decompression Bomb (Zip Bomb) Ratio Detected",
                        "weight": 35,
                        "reliability": "parsed",
                        "evidence": f"Uncompressed ratio is {total_uncompressed / compressed_size:.1f}:1 (> 100:1 limit)",
                    }],
                    "could_not_analyze": could_not_analyze,
                }

            cum_extracted = 0
            for idx, info in enumerate(infolist):
                if idx >= MAX_MEMBERS:
                    could_not_analyze.append(f"Member extraction limit ({MAX_MEMBERS}) reached; {len(infolist) - MAX_MEMBERS} members omitted")
                    break

                raw_name = info.filename
                clean_name, has_traversal = sanitize_member_path(raw_name)
                is_dir = info.is_dir()
                enc_entry = bool(info.flag_bits & 0x1)
                if enc_entry:
                    is_encrypted = True

                file_entries.append({
                    "filename": clean_name,
                    "uncompressed_size": info.file_size,
                    "compressed_size": info.compress_size,
                    "is_dir": is_dir,
                    "is_encrypted": enc_entry,
                })

                if has_traversal:
                    prov = create_provenance("archive_member", f"Archive Member: {clean_name}", "parsed", "confirmed")
                    findings.append(create_finding(
                        f"archive-traversal-{clean_name}",
                        "anomaly",
                        "Archive Member Path Traversal Attempt",
                        f"Archive member '{raw_name}' contained directory traversal or absolute root patterns.",
                        prov,
                        ["T1027"],
                    ))

                if is_dir:
                    continue

                if clean_name.lower().endswith(_DANGEROUS_EXTENSIONS):
                    dangerous_payloads.append(clean_name)

                if enc_entry:
                    could_not_analyze.append(f"encrypted archive member payload: {clean_name} (password required)")
                    continue

                if info.file_size > MAX_MEMBER_SIZE:
                    could_not_analyze.append(f"archive member {clean_name} exceeds max size ({info.file_size} > {MAX_MEMBER_SIZE})")
                    continue

                if cum_extracted + info.file_size > MAX_TOTAL_UNCOMPRESSED:
                    could_not_analyze.append(f"cumulative uncompressed size exceeds limit ({MAX_TOTAL_UNCOMPRESSED} bytes)")
                    break

                try:
                    member_bytes = zf.read(info)
                    cum_extracted += len(member_bytes)
                    mem_res = _inspect_member_bytes(clean_name, raw_name, member_bytes, depth)
                    members.append(mem_res)

                    if mem_res["verdict"] == "malicious":
                        prov = create_provenance("archive_member", f"Archive Member: {clean_name}", "matched", "confirmed")
                        findings.append(create_finding(
                            f"archive-malicious-member-{mem_res['sha256'][:8]}",
                            "ioc",
                            f"Malicious Payload Inside Archive Member: {clean_name}",
                            f"Extracted member '{clean_name}' evaluated as malicious: {mem_res.get('verdict_reason')}",
                            prov,
                            ["T1204.002", "T1027"],
                        ))
                        indicators.append({
                            "type": "archive_member_threat",
                            "value": clean_name,
                            "classification": "malicious",
                            "location": f"Archive member: {clean_name} (SHA256: {mem_res['sha256']})",
                            "location_rank": 1,
                            "provenance": prov,
                        })

                except Exception as exc:
                    could_not_analyze.append(f"failed to extract archive member {clean_name}: {exc}")

    except zipfile.BadZipFile:
        could_not_analyze.append("Corrupted or malformed ZIP central directory header")

    if is_encrypted:
        prov = create_provenance("archive_header", "ZIP General Purpose Bit Flags", "parsed", "confirmed")
        findings.append(create_finding(
            "archive-password-protected",
            "capability",
            "Password-Protected / Encrypted Archive Detected",
            "Archive contains one or more encrypted members requiring a decryption passphrase.",
            prov,
            ["T1027"],
        ))

    if dangerous_payloads:
        prov = create_provenance("parser_field", "ZIP Central Directory Entries", "parsed", "confirmed")
        findings.append(create_finding(
            "archive-dangerous-executables-packaged",
            "metadata",
            "Executable Payloads Packaged Inside Archive",
            f"Archive contains {len(dangerous_payloads)} executable or script payload(s): {', '.join(dangerous_payloads[:3])}.",
            prov,
            ["T1204.002"],
        ))

    return {
        "format": "archive",
        "container_type": "zip",
        "file_count": len(file_entries),
        "extracted_count": len(members),
        "is_encrypted": is_encrypted,
        "is_bomb": is_bomb,
        "dangerous_payloads": dangerous_payloads,
        "file_entries": file_entries[:50],
        "members": members,
        "findings": findings,
        "indicators": indicators,
        "could_not_analyze": could_not_analyze,
    }


def _analyze_tar(data: bytes, depth: int) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []
    file_entries: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    dangerous_payloads: list[str] = []
    is_bomb = False

    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            tar_members = tf.getmembers()
            total_uncompressed = sum(m.size for m in tar_members)
            compressed_size = len(data)

            if compressed_size >= 1024 and (total_uncompressed / compressed_size) > MAX_DECOMPRESSION_RATIO:
                is_bomb = True
                prov = create_provenance("parser_field", "TAR Headers", "parsed", "confirmed")
                findings.append(create_finding(
                    "archive-decompression-bomb-detected",
                    "structure",
                    "Decompression Bomb (Tar Bomb) Ratio Detected",
                    f"Uncompressed ratio is {total_uncompressed / compressed_size:.1f}:1 (> 100:1 limit).",
                    prov,
                    ["T1499"],
                ))
                could_not_analyze.append("Decompression aborted: tar bomb safety threshold exceeded")
                return {
                    "format": "archive",
                    "container_type": "tar",
                    "file_count": len(tar_members),
                    "extracted_count": 0,
                    "is_encrypted": False,
                    "is_bomb": True,
                    "dangerous_payloads": [],
                    "file_entries": [],
                    "members": [],
                    "findings": findings,
                    "indicators": indicators,
                    "structural_anomalies": [{
                        "title": "Decompression Bomb (Tar Bomb) Ratio Detected",
                        "weight": 35,
                        "reliability": "parsed",
                        "evidence": f"Uncompressed ratio is {total_uncompressed / compressed_size:.1f}:1 (> 100:1 limit)",
                    }],
                    "could_not_analyze": could_not_analyze,
                }

            cum_extracted = 0
            for idx, tm in enumerate(tar_members):
                if idx >= MAX_MEMBERS:
                    could_not_analyze.append(f"Member extraction limit ({MAX_MEMBERS}) reached; {len(tar_members) - MAX_MEMBERS} members omitted")
                    break

                raw_name = tm.name
                clean_name, has_traversal = sanitize_member_path(raw_name)
                is_dir = tm.isdir()

                file_entries.append({
                    "filename": clean_name,
                    "uncompressed_size": tm.size,
                    "compressed_size": tm.size,
                    "is_dir": is_dir,
                    "is_encrypted": False,
                })

                if has_traversal:
                    prov = create_provenance("archive_member", f"TAR Member: {clean_name}", "parsed", "confirmed")
                    findings.append(create_finding(
                        f"archive-traversal-{clean_name}",
                        "anomaly",
                        "Archive Member Path Traversal Attempt",
                        f"TAR member '{raw_name}' contained directory traversal or absolute root patterns.",
                        prov,
                        ["T1027"],
                    ))

                if is_dir:
                    continue

                if clean_name.lower().endswith(_DANGEROUS_EXTENSIONS):
                    dangerous_payloads.append(clean_name)

                if tm.size > MAX_MEMBER_SIZE:
                    could_not_analyze.append(f"archive member {clean_name} exceeds max size ({tm.size} > {MAX_MEMBER_SIZE})")
                    continue

                if cum_extracted + tm.size > MAX_TOTAL_UNCOMPRESSED:
                    could_not_analyze.append(f"cumulative uncompressed size exceeds limit ({MAX_TOTAL_UNCOMPRESSED} bytes)")
                    break

                try:
                    f = tf.extractfile(tm)
                    if f:
                        member_bytes = f.read()
                        cum_extracted += len(member_bytes)
                        mem_res = _inspect_member_bytes(clean_name, raw_name, member_bytes, depth)
                        members.append(mem_res)

                        if mem_res["verdict"] == "malicious":
                            prov = create_provenance("archive_member", f"TAR Member: {clean_name}", "matched", "confirmed")
                            findings.append(create_finding(
                                f"archive-malicious-member-{mem_res['sha256'][:8]}",
                                "ioc",
                                f"Malicious Payload Inside Archive Member: {clean_name}",
                                f"Extracted TAR member '{clean_name}' evaluated as malicious: {mem_res.get('verdict_reason')}",
                                prov,
                                ["T1204.002", "T1027"],
                            ))
                            indicators.append({
                                "type": "archive_member_threat",
                                "value": clean_name,
                                "classification": "malicious",
                                "location": f"TAR member: {clean_name} (SHA256: {mem_res['sha256']})",
                                "location_rank": 1,
                                "provenance": prov,
                            })
                except Exception as exc:
                    could_not_analyze.append(f"failed to extract TAR member {clean_name}: {exc}")

    except tarfile.TarError as exc:
        could_not_analyze.append(f"Corrupted or malformed TAR archive: {exc}")

    if dangerous_payloads:
        prov = create_provenance("parser_field", "TAR Header Entries", "parsed", "confirmed")
        findings.append(create_finding(
            "archive-dangerous-executables-packaged",
            "metadata",
            "Executable Payloads Packaged Inside Archive",
            f"Archive contains {len(dangerous_payloads)} executable or script payload(s): {', '.join(dangerous_payloads[:3])}.",
            prov,
            ["T1204.002"],
        ))

    return {
        "format": "archive",
        "container_type": "tar",
        "file_count": len(file_entries),
        "extracted_count": len(members),
        "is_encrypted": False,
        "is_bomb": is_bomb,
        "dangerous_payloads": dangerous_payloads,
        "file_entries": file_entries[:50],
        "members": members,
        "findings": findings,
        "indicators": indicators,
        "could_not_analyze": could_not_analyze,
    }


def _analyze_7z(data: bytes, depth: int) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []
    file_entries: list[dict[str, Any]] = []
    members: list[dict[str, Any]] = []
    dangerous_payloads: list[str] = []
    is_encrypted = False
    is_bomb = False

    seven_zip = shutil.which("7z") or shutil.which("7za")
    if not seven_zip:
        could_not_analyze.append("7-Zip utility not available on host system")
        return {
            "format": "archive",
            "container_type": "7z",
            "file_count": 0,
            "extracted_count": 0,
            "is_encrypted": False,
            "is_bomb": False,
            "dangerous_payloads": [],
            "file_entries": [],
            "members": [],
            "findings": findings,
            "indicators": indicators,
            "could_not_analyze": could_not_analyze,
        }

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".7z") as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        proc = subprocess.run([seven_zip, "l", "-slt", tmp_path], capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            could_not_analyze.append("Corrupted or invalid 7z archive structure")
            return {
                "format": "archive",
                "container_type": "7z",
                "file_count": 0,
                "extracted_count": 0,
                "is_encrypted": False,
                "is_bomb": False,
                "dangerous_payloads": [],
                "file_entries": [],
                "members": [],
                "findings": findings,
                "indicators": indicators,
                "could_not_analyze": could_not_analyze,
            }

        entries: list[dict[str, str]] = []
        cur: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k == "Path":
                    if cur.get("Path") and cur["Path"] != tmp_path:
                        entries.append(cur)
                    cur = {"Path": v}
                elif cur:
                    cur[k] = v
        if cur.get("Path") and cur["Path"] != tmp_path:
            entries.append(cur)

        # Bomb check
        total_uncompressed = 0
        for e in entries:
            try:
                total_uncompressed += int(e.get("Size", 0))
            except ValueError:
                pass
        compressed_size = len(data)
        if compressed_size >= 1024 and (total_uncompressed / compressed_size) > MAX_DECOMPRESSION_RATIO:
            is_bomb = True
            prov = create_provenance("parser_field", "7z Headers", "parsed", "confirmed")
            findings.append(create_finding(
                "archive-decompression-bomb-detected",
                "structure",
                "Decompression Bomb (7z Bomb) Ratio Detected",
                f"Uncompressed ratio is {total_uncompressed / compressed_size:.1f}:1 (> 100:1 limit).",
                prov,
                ["T1499"],
            ))
            could_not_analyze.append("Decompression aborted: 7z bomb safety threshold exceeded")
            return {
                "format": "archive",
                "container_type": "7z",
                "file_count": len(entries),
                "extracted_count": 0,
                "is_encrypted": False,
                "is_bomb": True,
                "dangerous_payloads": [],
                "file_entries": [],
                "members": [],
                "findings": findings,
                "indicators": indicators,
                "structural_anomalies": [{
                    "title": "Decompression Bomb (7z Bomb) Ratio Detected",
                    "weight": 35,
                    "reliability": "parsed",
                    "evidence": f"Uncompressed ratio is {total_uncompressed / compressed_size:.1f}:1 (> 100:1 limit)",
                }],
                "could_not_analyze": could_not_analyze,
            }

        cum_extracted = 0
        for idx, e in enumerate(entries):
            if idx >= MAX_MEMBERS:
                could_not_analyze.append(f"Member extraction limit ({MAX_MEMBERS}) reached; {len(entries) - MAX_MEMBERS} members omitted")
                break

            raw_name = e.get("Path", "")
            clean_name, has_traversal = sanitize_member_path(raw_name)
            is_dir = "D" in e.get("Attributes", "")
            enc_entry = (e.get("Encrypted") == "+")
            if enc_entry:
                is_encrypted = True

            try:
                u_size = int(e.get("Size", 0))
            except ValueError:
                u_size = 0

            file_entries.append({
                "filename": clean_name,
                "uncompressed_size": u_size,
                "compressed_size": u_size,
                "is_dir": is_dir,
                "is_encrypted": enc_entry,
            })

            if has_traversal:
                prov = create_provenance("archive_member", f"7z Member: {clean_name}", "parsed", "confirmed")
                findings.append(create_finding(
                    f"archive-traversal-{clean_name}",
                    "anomaly",
                    "Archive Member Path Traversal Attempt",
                    f"7z member '{raw_name}' contained directory traversal or absolute root patterns.",
                    prov,
                    ["T1027"],
                ))

            if is_dir:
                continue

            if clean_name.lower().endswith(_DANGEROUS_EXTENSIONS):
                dangerous_payloads.append(clean_name)

            if enc_entry:
                could_not_analyze.append(f"encrypted archive member payload: {clean_name} (password required)")
                continue

            if u_size > MAX_MEMBER_SIZE:
                could_not_analyze.append(f"archive member {clean_name} exceeds max size ({u_size} > {MAX_MEMBER_SIZE})")
                continue

            if cum_extracted + u_size > MAX_TOTAL_UNCOMPRESSED:
                could_not_analyze.append(f"cumulative uncompressed size exceeds limit ({MAX_TOTAL_UNCOMPRESSED} bytes)")
                break

            try:
                eproc = subprocess.run([seven_zip, "e", "-so", tmp_path, raw_name], capture_output=True, timeout=5)
                if eproc.returncode == 0 and eproc.stdout:
                    member_bytes = eproc.stdout
                    cum_extracted += len(member_bytes)
                    mem_res = _inspect_member_bytes(clean_name, raw_name, member_bytes, depth)
                    members.append(mem_res)

                    if mem_res["verdict"] == "malicious":
                        prov = create_provenance("archive_member", f"7z Member: {clean_name}", "matched", "confirmed")
                        findings.append(create_finding(
                            f"archive-malicious-member-{mem_res['sha256'][:8]}",
                            "ioc",
                            f"Malicious Payload Inside Archive Member: {clean_name}",
                            f"Extracted 7z member '{clean_name}' evaluated as malicious: {mem_res.get('verdict_reason')}",
                            prov,
                            ["T1204.002", "T1027"],
                        ))
                        indicators.append({
                            "type": "archive_member_threat",
                            "value": clean_name,
                            "classification": "malicious",
                            "location": f"7z member: {clean_name} (SHA256: {mem_res['sha256']})",
                            "location_rank": 1,
                            "provenance": prov,
                        })
            except Exception as exc:
                could_not_analyze.append(f"failed to extract 7z member {clean_name}: {exc}")

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if is_encrypted:
        prov = create_provenance("archive_header", "7z Encryption Header", "parsed", "confirmed")
        findings.append(create_finding(
            "archive-password-protected",
            "capability",
            "Password-Protected / Encrypted Archive Detected",
            "Archive contains one or more encrypted members requiring a decryption passphrase.",
            prov,
            ["T1027"],
        ))

    if dangerous_payloads:
        prov = create_provenance("parser_field", "7z Directory Entries", "parsed", "confirmed")
        findings.append(create_finding(
            "archive-dangerous-executables-packaged",
            "metadata",
            "Executable Payloads Packaged Inside Archive",
            f"Archive contains {len(dangerous_payloads)} executable or script payload(s): {', '.join(dangerous_payloads[:3])}.",
            prov,
            ["T1204.002"],
        ))

    return {
        "format": "archive",
        "container_type": "7z",
        "file_count": len(file_entries),
        "extracted_count": len(members),
        "is_encrypted": is_encrypted,
        "is_bomb": is_bomb,
        "dangerous_payloads": dangerous_payloads,
        "file_entries": file_entries[:50],
        "members": members,
        "findings": findings,
        "indicators": indicators,
        "could_not_analyze": could_not_analyze,
    }


def analyze_archive(data: bytes, depth: int = 0) -> dict[str, Any]:
    """Safely inspect archive and disk container contents."""
    if depth >= MAX_RECURSION_DEPTH:
        return {
            "format": "archive",
            "container_type": "nested_limit",
            "file_count": 0,
            "extracted_count": 0,
            "is_encrypted": False,
            "is_bomb": False,
            "dangerous_payloads": [],
            "file_entries": [],
            "members": [],
            "findings": [],
            "indicators": [],
            "could_not_analyze": [f"archive recursion depth limit ({MAX_RECURSION_DEPTH}) reached"],
        }

    # ISO 9660 Check
    if len(data) > 32774 and data[32769:32774] == b"CD001":
        prov = create_provenance("parser_field", "ISO 9660 Header (CD001)", "parsed", "confirmed")
        return {
            "format": "archive",
            "container_type": "iso",
            "is_motw_evasion_container": True,
            "file_count": 1,
            "extracted_count": 0,
            "is_encrypted": False,
            "is_bomb": False,
            "dangerous_payloads": [],
            "file_entries": [],
            "members": [],
            "findings": [create_finding(
                "container-motw-evasion-iso",
                "capability",
                "Disk Image Container (Mark-of-the-Web Evasion Potential)",
                "ISO/IMG disk images mount automatically in modern OS without propagating Mark-of-the-Web zone flags.",
                prov,
                ["T1553.005", "T1204.002"],
            )],
            "indicators": [],
            "could_not_analyze": ["ISO internal filesystem hierarchy requires kernel loopback mount"],
        }

    # ZIP check
    if data.startswith(b"PK\x03\x04"):
        return _analyze_zip(data, depth)

    # 7-Zip check
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return _analyze_7z(data, depth)

    # TAR check
    if (len(data) > 262 and data[257:262] == b"ustar") or data.startswith((b"\x1F\x8B", b"BZh", b"\xFD7zXZ\x00")):
        try:
            return _analyze_tar(data, depth)
        except Exception:
            pass

    # Fallback to 7z for CAB or RAR if available
    if data.startswith((b"MSCF", b"Rar!")):
        return _analyze_7z(data, depth)

    return {
        "format": "archive",
        "container_type": "unknown",
        "file_count": 0,
        "extracted_count": 0,
        "is_encrypted": False,
        "is_bomb": False,
        "dangerous_payloads": [],
        "file_entries": [],
        "members": [],
        "findings": [],
        "indicators": [],
        "could_not_analyze": ["unrecognized or unsupported archive container format"],
    }
