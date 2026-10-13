"""Office document static analyzer (docx, docm, xlsx, xlsm, pptx, doc).

Analyzes Office Open XML (OOXML) and legacy OLE2 formats for:
1. Macro presence (vbaProject.bin, AutoOpen, Workbook_Open).
2. External template and hyperlink injection (CVE-2017-0199, template injection).
3. DDE / DDEAUTO command execution markers.
4. Embedded OLE objects and executables.
"""

import io
import re
import zipfile
from typing import Any
from xml.etree import ElementTree

from ..provenance import create_finding, create_provenance

_OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


def is_office_document(data: bytes) -> bool:
    """Check if binary data represents an Office document."""
    if data.startswith(_OLE_MAGIC):
        return True
    if data.startswith(b"PK\x03\x04"):
        # Check for standard Office ZIP entries
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()
                return any(
                    n.startswith(("word/", "xl/", "ppt/", "customXml/"))
                    or n in ("[Content_Types].xml", "_rels/.rels")
                    for n in names
                )
        except Exception:
            return False
    return False


def analyze_office(data: bytes) -> dict[str, Any]:
    """Inspect an Office document for macros, templates, DDE, and suspicious payloads."""
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []

    has_macros = False
    macro_streams: list[str] = []
    external_templates: list[str] = []
    dde_commands: list[str] = []
    embedded_objects: list[str] = []

    if data.startswith(_OLE_MAGIC):
        # Legacy OLE document
        could_not_analyze.append("Legacy OLE2 compound structure decompressed via heuristic stream scanning")
        lower_data = data.lower()
        if b"autoopen" in lower_data or b"workbook_open" in lower_data or b"document_open" in lower_data:
            has_macros = True
            macro_streams.append("Root Entry / Macros")
            prov = create_provenance("parser_field", "OLE Stream / VBA Storage", "parsed", "confirmed")
            findings.append(create_finding(
                "office-ole-macro-autostart",
                "capability",
                "Legacy OLE Document with Auto-Executing Macro Hooks",
                "Found AutoOpen or Document_Open procedure hooks inside compound document streams.",
                prov,
                ["T1059.005", "T1204.002"],
            ))
            capabilities.append({
                "category": "Persistence & Autostart",
                "matched": ["AutoOpen", "Document_Open"],
                "confidence": "high",
                "provenance": prov,
            })
        return {
            "format": "office_ole2",
            "has_macros": has_macros,
            "macro_streams": macro_streams,
            "external_templates": external_templates,
            "dde_commands": dde_commands,
            "embedded_objects": embedded_objects,
            "findings": findings,
            "indicators": indicators,
            "capabilities": capabilities,
            "could_not_analyze": could_not_analyze,
        }

    # OOXML (ZIP-based)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            file_list = zf.namelist()

            for name in file_list:
                # 1. Macro presence
                if "vbaProject.bin" in name or name.endswith((".bin", ".vba")):
                    has_macros = True
                    macro_streams.append(name)
                    # Read macro binary for suspicious keywords
                    try:
                        vba_bytes = zf.read(name).lower()
                        auto_keywords = [kw for kw in (b"autoopen", b"document_open", b"workbook_open") if kw in vba_bytes]
                        exec_keywords = [kw for kw in (b"wscript.shell", b"shell.application", b"powershell", b"cmd.exe", b"urlmon", b"urldownloadtofile") if kw in vba_bytes]

                        prov = create_provenance("parser_field", f"OOXML Part: {name}", "parsed", "confirmed")
                        findings.append(create_finding(
                            "office-vba-macro-present",
                            "structure",
                            "VBA Macro Storage Present in Document",
                            f"Identified VBA macro binary storage component at '{name}'.",
                            prov,
                            ["T1059.005"],
                        ))

                        if auto_keywords or exec_keywords:
                            matched_terms = [k.decode("ascii") for k in (auto_keywords + exec_keywords)]
                            cap_prov = create_provenance("parser_field", f"OOXML Part: {name}", "parsed", "high")
                            capabilities.append({
                                "category": "Execution & Scripting",
                                "matched": matched_terms,
                                "confidence": "high",
                                "provenance": cap_prov,
                            })
                            findings.append(create_finding(
                                "office-vba-execution-primitives",
                                "capability",
                                "Suspicious VBA Process Invocation & Download Primitives",
                                f"Macro contains direct execution hooks: {', '.join(matched_terms)}.",
                                cap_prov,
                                ["T1204.002", "T1059.005"],
                            ))
                    except Exception:
                        pass

                # 2. External Template & Relationship Injection
                if name.endswith(".rels"):
                    try:
                        rels_content = zf.read(name)
                        root = ElementTree.fromstring(rels_content)
                        for elem in root.iter():
                            target = elem.attrib.get("Target", "")
                            mode = elem.attrib.get("TargetMode", "")
                            rel_type = elem.attrib.get("Type", "")

                            if mode == "External" or target.startswith(("http://", "https://")):
                                external_templates.append(target)
                                if "attachedTemplate" in rel_type or target.endswith((".dotm", ".docm", ".dot")):
                                    prov = create_provenance("parser_field", f"OOXML Part: {name}", "parsed", "confirmed")
                                    findings.append(create_finding(
                                        "office-remote-template-injection",
                                        "ioc",
                                        "Remote Template Injection Reference",
                                        f"Document requests remote execution template from external URL: {target}",
                                        prov,
                                        ["T1221"],
                                    ))
                                indicators.append({
                                    "type": "url",
                                    "value": target,
                                    "classification": "suspicious",
                                    "location": f"OOXML Relationship in {name}",
                                })
                    except Exception:
                        pass

                # 3. DDE (Dynamic Data Exchange) command execution
                if name.endswith(".xml") and name.startswith(("word/", "xl/")):
                    try:
                        xml_bytes = zf.read(name)
                        if b"DDE" in xml_bytes or b"DDEAUTO" in xml_bytes:
                            # Extract potential DDE text
                            dde_matches = re.findall(rb'(?:DDE|DDEAUTO)\s+"([^"]+)"\s+"([^"]+)"', xml_bytes)
                            for app, cmd in dde_matches:
                                dde_str = f"{app.decode('latin1', 'ignore')} {cmd.decode('latin1', 'ignore')}"
                                dde_commands.append(dde_str)
                                prov = create_provenance("parser_field", f"OOXML Part: {name}", "parsed", "confirmed")
                                findings.append(create_finding(
                                    "office-dde-command-execution",
                                    "capability",
                                    "Dynamic Data Exchange (DDE) Command Injection",
                                    f"Found DDE invocation payload: {dde_str}",
                                    prov,
                                    ["T1204.002", "T1559.001"],
                                ))
                                capabilities.append({
                                    "category": "Execution & Scripting",
                                    "matched": ["DDEAUTO", app.decode("latin1", "ignore")],
                                    "confidence": "high",
                                    "provenance": prov,
                                })
                    except Exception:
                        pass

                # 4. Embedded OLE Objects & Executables
                if name.startswith("word/embeddings/") or name.startswith("xl/embeddings/"):
                    embedded_objects.append(name)
                    prov = create_provenance("parser_field", f"OOXML Embedding: {name}", "parsed", "medium")
                    findings.append(create_finding(
                        "office-embedded-object-package",
                        "structure",
                        "Embedded OLE / Binary Package",
                        f"Document contains embedded foreign payload at '{name}'.",
                        prov,
                        ["T1204.002"],
                    ))

    except Exception as e:
        could_not_analyze.append(f"Failed to decompress OOXML structure: {e}")

    return {
        "format": "office_ooxml",
        "has_macros": has_macros,
        "macro_streams": macro_streams,
        "external_templates": external_templates,
        "dde_commands": dde_commands,
        "embedded_objects": embedded_objects,
        "findings": findings,
        "indicators": indicators,
        "capabilities": capabilities,
        "could_not_analyze": could_not_analyze,
    }
