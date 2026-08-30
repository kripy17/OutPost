<#
.SYNOPSIS
    OutPost — one-command Windows installer & developer environment setup.

.DESCRIPTION
    Creates a virtual environment (.venv), installs the backend (+ dev tools) and CLI
    as editable packages, installs frontend dependencies, writes frontend/.env.local,
    and seeds initial demo data.
    Optionally checks for and provisions Microsoft Sysmon with SwiftOnSecurity baseline.

.PARAMETER ApiPort
    Backend API port (default: 8001).

.PARAMETER WebPort
    Frontend webapp port (default: 5174).

.PARAMETER Seed
    Whether to seed initial demo data (default: 1).
#>

[CmdletBinding()]
param(
    [int]$ApiPort = 8001,
    [int]$WebPort = 5174,
    [int]$Seed = 1
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $ProjectRoot

function Say([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Green
}

function Warn([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Yellow
}

# ---- prereq checks ---------------------------------------------------------
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3 is required. Please install Python from https://www.python.org/ or winget."
    exit 1
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js & npm are required. Please install Node.js from https://nodejs.org/ or winget."
    exit 1
}

# ---- virtual environment ---------------------------------------------------
$VenvPath = Join-Path $ProjectRoot ".venv"
if (Test-Path $VenvPath) {
    Say "Reusing existing virtual environment (.venv)"
} else {
    Say "Creating virtual environment (.venv)"
    & python -m venv $VenvPath
}

$VenvPython = Join-Path $VenvPath "Scripts\python.exe"
$VenvPip = Join-Path $VenvPath "Scripts\pip.exe"

Say "Upgrading pip"
& $VenvPython -m pip install --upgrade pip

Say "Installing backend (editable) + dev tools (pytest, ruff, black)"
& $VenvPip install -e "$ProjectRoot\backend[dev]"

Say "Installing CLI (editable) — the 'outpost' command"
& $VenvPip install -e "$ProjectRoot\cli"

# ---- frontend --------------------------------------------------------------
$FrontendDir = Join-Path $ProjectRoot "frontend"
if (Test-Path "$FrontendDir\node_modules") {
    Say "Reusing frontend/node_modules"
} else {
    Say "Installing frontend dependencies"
    Push-Location $FrontendDir
    & npm install
    Pop-Location
}

# ---- demo tooling (Playwright) ---------------------------------------------
$DemoDir = Join-Path $ProjectRoot "demo"
if (Test-Path "$DemoDir\node_modules") {
    Say "Reusing demo/node_modules (Playwright)"
} else {
    Say "Installing demo dependencies (Playwright)"
    Push-Location $DemoDir
    & npm install
    try {
        & npx playwright install chromium
    } catch {
        Warn "Chromium download skipped — run 'cd demo; npx playwright install chromium' if needed."
    }
    Pop-Location
}

# ---- frontend API target ---------------------------------------------------
$EnvLocal = Join-Path $FrontendDir ".env.local"
if (-not (Test-Path $EnvLocal)) {
    Say "Writing frontend/.env.local (VITE_API_URL=http://localhost:$ApiPort)"
    "VITE_API_URL=http://localhost:$ApiPort" | Out-File -FilePath $EnvLocal -Encoding utf8
} else {
    Say "frontend/.env.local already exists (left untouched)"
}

# ---- demo data -------------------------------------------------------------
if ($Seed -eq 1) {
    Say "Seeding demo data (campaign pair + demo run)"
    Push-Location (Join-Path $ProjectRoot "backend")
    try {
        & $VenvPython -m app.seed_campaign
    } catch {
        Warn "seed_campaign warning — you can re-seed later."
    }
    try {
        & $VenvPython -m app.seed_demo
    } catch {}
    Pop-Location
} else {
    Say "Skipping demo data (Seed=0)"
}

# ---- summary ---------------------------------------------------------------
Write-Host ""
Write-Host "OutPost Windows install complete." -ForegroundColor Green -NoNewline
Write-Host ""
Write-Host ""
Write-Host "  Start the stack:      powershell -ExecutionPolicy Bypass -File scripts\dev.ps1 start"
Write-Host "  Webapp:               http://localhost:$WebPort"
Write-Host "  API:                  http://localhost:$ApiPort"
Write-Host ""
Write-Host "  Or run components individually (.venv active first: .venv\Scripts\Activate.ps1):"
Write-Host "    backend:  cd backend; uvicorn app.main:app --reload --port $ApiPort"
Write-Host "    frontend: cd frontend; npm run dev -- --port $WebPort"
Write-Host "    CLI:      outpost --help"
Write-Host ""
Write-Host "  Tip: Set-Item env:OUTPOST_API_URL `"http://localhost:$ApiPort`"; outpost list"
