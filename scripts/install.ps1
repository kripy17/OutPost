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
    [int]$Seed = 1,
    [switch]$InstallSysmon,
    [switch]$NonInteractive
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

function Err([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Red
}

function Info([string]$msg) {
    Write-Host "==> $msg" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  OutPost — Windows System Diagnostics & Automated Environment Setup     " -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# 1. Dependency Diagnostics
# -----------------------------------------------------------------------------
$MissingDeps = @()

# Check Python
$hasPython = $false
$pythonVer = ""
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if ($pyCmd) {
    $hasPython = $true
    try {
        $pythonVer = (& python --version 2>&1).Trim()
    } catch {
        $pythonVer = "Python 3"
    }
} else {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $hasPython = $true
        $pythonVer = (& py -3 --version 2>&1).Trim()
    } else {
        $MissingDeps += "Python 3 (>=3.10)"
    }
}

# Check Node.js
$hasNode = $false
$nodeVer = ""
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($nodeCmd) {
    $hasNode = $true
    $nodeVer = (& node -v 2>&1).Trim()
} else {
    $MissingDeps += "Node.js (>=18)"
}

# Check npm
$hasNpm = $false
$npmVer = ""
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if ($npmCmd) {
    $hasNpm = $true
    $npmVer = (& npm -v 2>&1).Trim()
} else {
    $MissingDeps += "npm package manager"
}

# Check Git
$hasGit = $false
$gitVer = ""
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    $hasGit = $true
    $gitVer = (& git --version 2>&1).Trim()
} else {
    $MissingDeps += "Git version control"
}

# Check Sysmon (Optional / Recommended)
$hasSysmon = $false
$sysmonVer = "Not detected"
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sysmonService -and $sysmonService.Status -eq "Running") {
    $hasSysmon = $true
    $sysmonVer = "$($sysmonService.Name) (Active Service)"
}

# -----------------------------------------------------------------------------
# 2. Render Diagnostic Matrix
# -----------------------------------------------------------------------------
Write-Host ("  {0,-24} {1,-16} {2}" -f "COMPONENT", "STATUS", "DETAILS") -ForegroundColor DarkGray
Write-Host ("  {0,-24} {1,-16} {2}" -f "------------------------", "----------------", "----------------------------------") -ForegroundColor DarkGray

if ($hasPython) {
    Write-Host ("  {0,-24} " -f "Python 3") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $pythonVer
} else {
    Write-Host ("  {0,-24} " -f "Python 3") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Required for OutPost backend & CLI" -ForegroundColor Yellow
}

if ($hasNode) {
    Write-Host ("  {0,-24} " -f "Node.js") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $nodeVer
} else {
    Write-Host ("  {0,-24} " -f "Node.js") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Required for OutPost React webapp" -ForegroundColor Yellow
}

if ($hasNpm) {
    Write-Host ("  {0,-24} " -f "npm package manager") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host "v$npmVer"
} else {
    Write-Host ("  {0,-24} " -f "npm package manager") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Required for frontend bundling" -ForegroundColor Yellow
}

if ($hasGit) {
    Write-Host ("  {0,-24} " -f "Git") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $gitVer
} else {
    Write-Host ("  {0,-24} " -f "Git") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Required for repository management" -ForegroundColor Yellow
}

if ($hasSysmon) {
    Write-Host ("  {0,-24} " -f "Microsoft Sysmon") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $sysmonVer
} else {
    Write-Host ("  {0,-24} " -f "Microsoft Sysmon") -NoNewline
    Write-Host "[○ OPTIONAL]    " -ForegroundColor Cyan -NoNewline
    Write-Host "SwiftOnSecurity baseline recommended for host telemetry" -ForegroundColor Gray
}

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# 3. Automated Dependency Installation
# -----------------------------------------------------------------------------
if ($MissingDeps.Count -gt 0) {
    Warn "Missing $($MissingDeps.Count) required component(s): $($MissingDeps -join ', ')"
    Write-Host ""

    $doInstall = $true
    if (-not $NonInteractive -and [Environment]::UserInteractive) {
        $prompt = Read-Host "==> Would you like OutPost to install missing packages automatically? [Y/n]"
        if ($prompt -match '^[nN]') {
            $doInstall = $false
        }
    }

    if (-not $doInstall) {
        Err "Installation aborted by user. Please install missing prerequisites manually."
        exit 1
    }

    # Check for winget
    $hasWinget = Get-Command winget -ErrorAction SilentlyContinue
    $hasChoco = Get-Command choco -ErrorAction SilentlyContinue

    if ($hasWinget) {
        Say "Installing missing components via Windows Package Manager (winget)..."
        if (-not $hasPython) {
            Say "  -> Installing Python 3.12..."
            & winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements --silent
        }
        if (-not $hasNode -or -not $hasNpm) {
            Say "  -> Installing Node.js LTS..."
            & winget install --id OpenJS.NodeJS.LTS -e --accept-package-agreements --accept-source-agreements --silent
        }
        if (-not $hasGit) {
            Say "  -> Installing Git..."
            & winget install --id Git.Git -e --accept-package-agreements --accept-source-agreements --silent
        }
    } elseif ($hasChoco) {
        Say "Installing missing components via Chocolatey..."
        if (-not $hasPython) { & choco install -y python }
        if (-not $hasNode -or -not $hasNpm) { & choco install -y nodejs }
        if (-not $hasGit) { & choco install -y git }
    } else {
        Say "Downloading and running official Windows installers..."
        $tempDir = [System.IO.Path]::GetTempPath()
        if (-not $hasPython) {
            $pyInstaller = Join-Path $tempDir "python-installer.exe"
            Say "  -> Downloading Python 3.12 installer..."
            Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe" -OutFile $pyInstaller -UseBasicParsing
            Say "  -> Installing Python 3.12 silently..."
            Start-Process -FilePath $pyInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
        }
        if (-not $hasNode) {
            $nodeInstaller = Join-Path $tempDir "node-installer.msi"
            Say "  -> Downloading Node.js LTS installer..."
            Invoke-WebRequest -Uri "https://nodejs.org/dist/v20.18.1/node-v20.18.1-x64.msi" -OutFile $nodeInstaller -UseBasicParsing
            Say "  -> Installing Node.js silently..."
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$nodeInstaller`" /quiet" -Wait
        }
    }

    # Refresh current session PATH from Registry
    Say "Refreshing session environment PATH..."
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# -----------------------------------------------------------------------------
# 4. Optional / Interactive Microsoft Sysmon + SwiftOnSecurity Setup
# -----------------------------------------------------------------------------
if (-not $hasSysmon) {
    $doSysmon = $false
    if ($InstallSysmon) {
        $doSysmon = $true
    } elseif (-not $NonInteractive -and [Environment]::UserInteractive) {
        Write-Host ""
        $promptSysmon = Read-Host "==> Would you like OutPost to install Microsoft Sysmon with SwiftOnSecurity baseline? [Y/n]"
        if ($promptSysmon -notmatch '^[nN]') {
            $doSysmon = $true
        }
    }

    if ($doSysmon) {
        Say "Provisioning Microsoft Sysmon with SwiftOnSecurity gold-standard baseline..."
        $SysmonDir = Join-Path $ProjectRoot ".sysmon"
        if (-not (Test-Path $SysmonDir)) {
            New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null
        }
        $SysmonZip = Join-Path $SysmonDir "Sysmon.zip"
        $ConfigFile = Join-Path $SysmonDir "sysmonconfig-export.xml"

        try {
            Say "  -> Downloading Sysinternals Sysmon..."
            Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $SysmonZip -UseBasicParsing
            Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
            $SysmonExe = if (Test-Path "$SysmonDir\Sysmon64.exe") { "$SysmonDir\Sysmon64.exe" } else { "$SysmonDir\Sysmon.exe" }

            Say "  -> Downloading SwiftOnSecurity sysmonconfig-export.xml..."
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $ConfigFile -UseBasicParsing

            Say "  -> Installing Sysmon service (with Administrator elevation)..."
            Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$ConfigFile`"" -Wait -Verb RunAs
            Say "  ✔ Microsoft Sysmon configured with SwiftOnSecurity profile."
        } catch {
            Warn "Sysmon automated setup encountered an error: $_"
        }
    }
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
