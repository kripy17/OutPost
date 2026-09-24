#!/usr/bin/env python3
"""OutPost Adversary Sample — Simulated Canary File Encryptor & Ransomware Stager.

Safe, contained adversarial test payload designed to trigger OutPost behavioral EDR heuristics:
  1. Rapid file mutation burst (10+ canary files)
  2. In-place canary encryption with .locked extension
  3. Dropping ransom note HOW_TO_RECOVER_FILES.txt with Bitcoin wallet & recovery instructions
  4. C2 beaconing attempt to high port 4444 (203.0.113.88:4444)

Detonation Outcome:
  - Exit Code: 0
  - Behavioral Risk Score: 60-100/100 (Critical / Malicious)
  - Detection Alerts: Rapid File Burst / Unusual Network Port / Ransomware Staging
  - Verdict: MALICIOUS
"""

import os
import socket
import sys
import time


def main():
    print("=================================================================")
    print("  OutPost Threat Simulation: Ransomware Stager Canary Test       ")
    print("  Purpose: Positive Detection Validation & Behavioral EDR Test   ")
    print("=================================================================")

    target_dir = os.path.join(os.getcwd(), "canary_vault")
    os.makedirs(target_dir, exist_ok=True)

    # 1. Create canary documents (rapid write burst)
    print(f"[*] Staging canary documents in {target_dir}...")
    canaries = [f"document_{i}.docx" for i in range(12)]
    for c in canaries:
        with open(os.path.join(target_dir, c), "w") as f:
            f.write(f"CONFIDENTIAL BUSINESS RECORD {c}\n" * 40)

    # 2. Encrypt & rename with .locked extension
    print("[*] Encrypting canary documents with XOR key...")
    time.sleep(0.02)
    for c in canaries:
        src = os.path.join(target_dir, c)
        dst = src + ".locked"
        with open(src, "rb") as f_in, open(dst, "wb") as f_out:
            data = f_in.read()
            f_out.write(bytes(b ^ 0x5A for b in data))
        os.remove(src)
        print(f"  > Encrypted {c} -> {c}.locked")

    # 3. Drop ransom note
    note_path = os.path.join(target_dir, "HOW_TO_RECOVER_FILES.txt")
    with open(note_path, "w") as f:
        f.write("YOUR FILES HAVE BEEN ENCRYPTED AS PART OF AN OUTPOST SIMULATION TEST.\n")
        f.write("To recover your files, contact: decryptor@threat-actor.xyz\n")
        f.write("Payment: 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
    print(f"[!] Ransom note dropped at: {note_path}")

    # 4. Outbound C2 beacon attempt
    print("[*] Contacting C2 controller at 203.0.113.88:4444...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect_ex(("127.0.0.1", 4444))
        s.close()
    except Exception:
        pass

    print("[✓] Adversary staging complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
