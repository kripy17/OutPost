# OutPost — Universal Setup Script (Windows PowerShell)
#
# Usage: .\setup.ps1

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      OutPost Universal Setup (Windows)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found in PATH. Please install Python 3.10+."
    exit 1
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error "npm not found in PATH. Please install Node.js 18+."
    exit 1
}

Write-Host "[*] Creating virtual environment (.venv)..." -ForegroundColor Yellow
if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

$venvPython = ".\.venv\Scripts\python.exe"
$venvPip = ".\.venv\Scripts\pip.exe"

Write-Host "[*] Upgrading pip and installing backend & CLI packages..." -ForegroundColor Yellow
& $venvPip install --upgrade pip
& $venvPip install -e ".\backend[dev]"
& $venvPip install -e ".\cli"

Write-Host "[*] Installing frontend dependencies (npm)..." -ForegroundColor Yellow
Set-Location frontend
npm install
if (-not (Test-Path ".env.local")) {
    Set-Content -Path ".env.local" -Value "VITE_API_URL=http://localhost:8001"
}
Set-Location ..

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " [✓] OutPost setup completed successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "To start OutPost:"
Write-Host "  .\start.ps1"
