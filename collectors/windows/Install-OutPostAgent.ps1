<#
.SYNOPSIS
    OutPost Windows Sensor Agent & SwiftOnSecurity Sysmon Automated Installer.

.DESCRIPTION
    Automates the complete deployment of the OutPost Windows Sensor Collector:
    1. Verifies Administrator privileges.
    2. Checks for Microsoft Sysmon; if missing, downloads Sysmon from Sysinternals.
    3. Downloads and applies the SwiftOnSecurity gold-standard sysmonconfig-export.xml.
    4. Configures and registers OutPost Windows telemetry shipper.

.PARAMETER BackendUrl
    The OutPost backend API URL (e.g. http://192.168.1.100:8000).

.PARAMETER AgentToken
    Optional agent authorization token (OUTPOST_AGENT_TOKEN).
#>

[CmdletBinding()]
param(
    [string]$BackendUrl = "http://127.0.0.1:8000",
    [string]$AgentToken = "",
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  OutPost Windows Sensor Collector & Sysmon Auto-Installer              " -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[!] Running without elevation. Administrator privileges are required to configure Sysmon and sensor services."
    if (-not $NonInteractive -and [Environment]::UserInteractive) {
        $elevate = Read-Host "==> Elevate to Administrator now? [Y/n]"
        if ($elevate -notmatch '^[nN]') {
            Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -BackendUrl `"$BackendUrl`" -AgentToken `"$AgentToken`""
            exit 0
        }
    }
}

$InstallDir = "$env:ProgramData\OutPost"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# -----------------------------------------------------------------------------
# 2. Dependency Diagnostics
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
        $MissingDeps += "Python 3"
    }
}

# Check Sysmon
$hasSysmon = $false
$sysmonVer = "Not detected"
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sysmonService -and $sysmonService.Status -eq "Running") {
    $hasSysmon = $true
    $sysmonVer = "$($sysmonService.Name) (Active Service)"
} else {
    $MissingDeps += "Microsoft Sysmon"
}

# Render Table
Write-Host ("  {0,-24} {1,-16} {2}" -f "COMPONENT", "STATUS", "DETAILS") -ForegroundColor DarkGray
Write-Host ("  {0,-24} {1,-16} {2}" -f "------------------------", "----------------", "----------------------------------") -ForegroundColor DarkGray

if ($hasPython) {
    Write-Host ("  {0,-24} " -f "Python Runtime") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $pythonVer
} else {
    Write-Host ("  {0,-24} " -f "Python Runtime") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Required for collector agent" -ForegroundColor Yellow
}

if ($hasSysmon) {
    Write-Host ("  {0,-24} " -f "Microsoft Sysmon") -NoNewline
    Write-Host "[✔ INSTALLED]   " -ForegroundColor Green -NoNewline
    Write-Host $sysmonVer
} else {
    Write-Host ("  {0,-24} " -f "Microsoft Sysmon") -NoNewline
    Write-Host "[✖ MISSING]     " -ForegroundColor Red -NoNewline
    Write-Host "Required for deep endpoint telemetry" -ForegroundColor Yellow
}

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# 3. Automated Dependency Installation
# -----------------------------------------------------------------------------
if ($MissingDeps.Count -gt 0) {
    Write-Host "==> Missing $($MissingDeps.Count) component(s): $($MissingDeps -join ', ')" -ForegroundColor Yellow
    Write-Host ""

    $doInstall = $true
    if (-not $NonInteractive -and [Environment]::UserInteractive) {
        $prompt = Read-Host "==> Would you like OutPost to install missing components automatically? [Y/n]"
        if ($prompt -match '^[nN]') {
            $doInstall = $false
        }
    }

    if (-not $doInstall) {
        Write-Error "Setup aborted by user. Missing dependencies required."
        exit 1
    }

    # Install Python if missing
    if (-not $hasPython) {
        Write-Host "[*] Installing Python runtime..." -ForegroundColor Cyan
        $hasWinget = Get-Command winget -ErrorAction SilentlyContinue
        if ($hasWinget) {
            & winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements --silent
        } else {
            $pyInstaller = "$InstallDir\python-installer.exe"
            Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe" -OutFile $pyInstaller -UseBasicParsing
            Start-Process -FilePath $pyInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }

    # Install Sysmon with SwiftOnSecurity if missing
    if (-not $hasSysmon) {
        Write-Host "[*] Provisioning Microsoft Sysmon with SwiftOnSecurity baseline..." -ForegroundColor Cyan
        $SysmonZip = "$InstallDir\Sysmon.zip"
        $SysmonDir = "$InstallDir\Sysmon"
        $SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
        $ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
        $ConfigFile = "$InstallDir\sysmonconfig-export.xml"

        Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonZip -UseBasicParsing
        Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
        $SysmonExe = if (Test-Path "$SysmonDir\Sysmon64.exe") { "$SysmonDir\Sysmon64.exe" } else { "$SysmonDir\Sysmon.exe" }

        Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigFile -UseBasicParsing
        Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$ConfigFile`"" -Wait -NoNewWindow
        Write-Host "[+] Sysmon successfully configured and running." -ForegroundColor Green
    }
}

# Setup Python packages
Write-Host "[*] Configuring Python collector dependencies (requests, psutil, pywin32)..." -ForegroundColor Yellow
try {
    & python -m pip install --quiet --upgrade pip
    & python -m pip install --quiet requests psutil pywin32
    Write-Host "[+] Collector Python packages installed." -ForegroundColor Green
} catch {
    Write-Warning "Could not verify pip packages. Ensure 'requests', 'psutil', and 'pywin32' are available."
}

# 4. OutPost Collector Execution Script
$CollectorScript = "$InstallDir\Start-OutPostCollector.ps1"
$ScriptContent = @"
`$env:OUTPOST_API_URL = "$BackendUrl"
if ("$AgentToken" -ne "") {
    `$env:OUTPOST_AGENT_TOKEN = "$AgentToken"
}
Write-Host "[*] Starting OutPost Windows Sensor Collector connected to $BackendUrl..." -ForegroundColor Cyan
python "$PSScriptRoot\collector_win.py" --backend-url "$BackendUrl" --mode live
"@

Set-Content -Path $CollectorScript -Value $ScriptContent

Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  ✔ OutPost Windows Sensor Agent Successfully Configured!                " -ForegroundColor Green
Write-Host "  Telemetry Channel: Microsoft-Windows-Sysmon/Operational               " -ForegroundColor White
Write-Host "  Target Backend:    $BackendUrl                                        " -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "To start live event streaming immediately, run:" -ForegroundColor Yellow
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$CollectorScript`"" -ForegroundColor Cyan
