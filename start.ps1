param (
    [switch]$Demo,
    [switch]$WithAgent
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      OutPost Security Monitor" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "[*] Backend API:  http://localhost:8001" -ForegroundColor Yellow
Write-Host "[*] Web Console:  http://localhost:5174" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[-] Virtual environment not found. Running .\setup.ps1..." -ForegroundColor Red
    .\setup.ps1
}

if ($Demo) {
    Write-Host "[*] Initializing database with demo telemetry..." -ForegroundColor Yellow
    & ".\.venv\Scripts\python.exe" -m app.seed_demo | Out-Null
} else {
    Write-Host "[*] Initializing clean database schema (zero demo data)..." -ForegroundColor Yellow
    & ".\.venv\Scripts\python.exe" -c "from app.core.db import init_db, db_session; init_db(); conn = db_session().__enter__(); conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (''onboarding'', ''empty''), (''demo_mode'', ''0'')'); conn.commit()" | Out-Null
}

$backendProc = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8001 --log-level warning" -WorkingDirectory "backend" -PassThru
Set-Location frontend
$frontendProc = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev -- --port 5174" -PassThru
Set-Location ..

Start-Sleep -Seconds 3
Write-Host "[*] Opening web browser at http://localhost:5174..." -ForegroundColor Yellow
Start-Process "http://localhost:5174"

Write-Host "[✓] OutPost is running live!" -ForegroundColor Green
Write-Host "Press enter in this window to stop both services..." -ForegroundColor White
Read-Host

Stop-Process -Id $frontendProc.Id -ErrorAction SilentlyContinue
Stop-Process -Id $backendProc.Id -ErrorAction SilentlyContinue
Write-Host "[✓] OutPost services stopped." -ForegroundColor Green
