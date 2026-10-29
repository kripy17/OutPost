"""Capture high-resolution screenshots of OutPost Malware Analysis Workbench for documentation."""

import os
import subprocess
import time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS_SS = ROOT / "docs" / "screenshots"
DOCS_SS.mkdir(parents=True, exist_ok=True)

BACKEND_PORT = 8000
FRONTEND_PORT = 5173

# Seed demo data first
print("[*] Seeding demo threat samples & telemetry...")
subprocess.run([sys.executable, "-m", "app.seed_demo"], cwd=ROOT / "backend", check=True)

# Build frontend to ensure preview is 100% up to date
print("[*] Ensuring frontend production build is current...")
subprocess.run(["npm", "run", "build"], cwd=ROOT / "frontend", check=True, stdout=subprocess.DEVNULL)

# Start backend
print("[*] Launching backend server on port 8000...")
backend_proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(BACKEND_PORT), "--log-level", "error"],
    cwd=ROOT / "backend",
)

# Start frontend preview
print("[*] Launching frontend preview on port 5173...")
frontend_proc = subprocess.Popen(
    ["npm", "run", "preview", "--", "--host", "127.0.0.1", "--port", str(FRONTEND_PORT), "--strictPort"],
    cwd=ROOT / "frontend",
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

def wait_for(url, timeout=15):
    import urllib.request
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1) as res:
                if res.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False

try:
    print("[*] Waiting for backend and frontend...")
    if not wait_for(f"http://127.0.0.1:{BACKEND_PORT}/health"):
        raise RuntimeError("Backend failed to start")
    if not wait_for(f"http://127.0.0.1:{FRONTEND_PORT}"):
        raise RuntimeError("Frontend failed to start")

    print("[✓] Both servers running! Capturing high-resolution screenshots...")
    time.sleep(1)

    pages = [
        ("01_malware_vault.png", f"http://127.0.0.1:{FRONTEND_PORT}/samples"),
        ("02_sample_detail.png", f"http://127.0.0.1:{FRONTEND_PORT}/samples/sample_remcos_01"),
        ("03_simulation_lab.png", f"http://127.0.0.1:{FRONTEND_PORT}/monitor"),
        ("04_detonation_runs.png", f"http://127.0.0.1:{FRONTEND_PORT}/analysis"),
        ("05_run_detail.png", f"http://127.0.0.1:{FRONTEND_PORT}/runs/dyn_db3a8da614ef"),
        ("06_telemetry_stream.png", f"http://127.0.0.1:{FRONTEND_PORT}/events"),
        ("07_rules_studio.png", f"http://127.0.0.1:{FRONTEND_PORT}/rules"),
        ("08_mitre_coverage.png", f"http://127.0.0.1:{FRONTEND_PORT}/coverage"),
        ("09_threat_watchlist.png", f"http://127.0.0.1:{FRONTEND_PORT}/watchlist"),
        ("10_ioc_search.png", f"http://127.0.0.1:{FRONTEND_PORT}/search"),
        ("11_settings_airgap.png", f"http://127.0.0.1:{FRONTEND_PORT}/settings"),
    ]

    for fname, url in pages:
        out_path = DOCS_SS / fname
        cmd = [
            "chromium",
            "--headless",
            "--ozone-platform=headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-extensions",
            "--window-size=1440,900",
            "--virtual-time-budget=2500",
            f"--screenshot={out_path}",
            url,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if out_path.exists() and out_path.stat().st_size > 0:
            print(f" [✓] Captured {fname} ({out_path.stat().st_size // 1024} KB)")
        else:
            print(f" [-] Failed capturing {fname}: {res.stderr}")

    print("[✓] All screenshots captured successfully!")

finally:
    print("[*] Cleaning up processes...")
    frontend_proc.terminate()
    backend_proc.terminate()
    try:
        frontend_proc.wait(timeout=3)
        backend_proc.wait(timeout=3)
    except Exception:
        pass
