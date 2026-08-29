# OutPost — Universal Startup Script (Windows PowerShell)
#
# Launches Backend on port 8001, Web Console on port 5174, and auto-opens the browser.
# Usage: .\start.ps1

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

Write-Host "[*] Initializing database & demo telemetry..." -ForegroundColor Yellow
Push-Location backend
& "..\.venv\Scripts\python.exe" -m app.seed_demo | Out-Null
Pop-Location

$backendProc = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8001 --log-level warning" -WorkingDirectory "backend" -PassThru
Push-Location frontend
$frontendProc = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev -- --port 5174" -PassThru
Pop-Location

Start-Sleep -Seconds 3
Write-Host "[*] Opening web browser at http://localhost:5174..." -ForegroundColor Yellow
Start-Process "http://localhost:5174"

Write-Host "[✓] OutPost is running live!" -ForegroundColor Green
Write-Host "Press enter in this window to stop both services..." -ForegroundColor White
Read-Host

Stop-Process -Id $frontendProc.Id -ErrorAction SilentlyContinue
Stop-Process -Id $backendProc.Id -ErrorAction SilentlyContinue
Write-Host "[✓] OutPost services stopped." -ForegroundColor Green
