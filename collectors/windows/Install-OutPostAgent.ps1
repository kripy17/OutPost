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
    [string]$AgentToken = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  OutPost Windows Sensor Collector & Sysmon Auto-Installer       " -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Please run this script as Administrator in an elevated PowerShell session."
    exit 1
}

$InstallDir = "$env:ProgramData\OutPost"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# 2. Check Sysmon installation
Write-Host "[*] Checking Microsoft Sysmon installation status..." -ForegroundColor Yellow
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Host "[+] Sysmon service is installed and running ($($sysmonService.Name))." -ForegroundColor Green
} else {
    Write-Host "[*] Sysmon not detected. Provisioning Sysmon with SwiftOnSecurity baseline..." -ForegroundColor Yellow
    $SysmonZip = "$InstallDir\Sysmon.zip"
    $SysmonDir = "$InstallDir\Sysmon"
    $SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    $ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $ConfigFile = "$InstallDir\sysmonconfig-export.xml"

    Write-Host "    -> Downloading Sysinternals Sysmon..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonZip -UseBasicParsing

    Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
    $SysmonExe = if (Test-Path "$SysmonDir\Sysmon64.exe") { "$SysmonDir\Sysmon64.exe" } else { "$SysmonDir\Sysmon.exe" }

    Write-Host "    -> Downloading SwiftOnSecurity sysmonconfig-export.xml..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigFile -UseBasicParsing

    Write-Host "    -> Installing and starting Sysmon with SwiftOnSecurity profile..." -ForegroundColor Cyan
    Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$ConfigFile`"" -Wait -NoNewWindow

    Write-Host "[+] Sysmon successfully configured with SwiftOnSecurity profile." -ForegroundColor Green
}

# 3. Setup Python dependencies
Write-Host "[*] Verifying Python and PyWin32 environment..." -ForegroundColor Yellow
try {
    & python -m pip install --quiet requests psutil pywin32
    Write-Host "[+] Python collector dependencies satisfied." -ForegroundColor Green
} catch {
    Write-Warning "Could not verify pip dependencies automatically. Ensure 'requests', 'psutil', and 'pywin32' are installed."
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

Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  ✔ OutPost Windows Sensor Agent Successfully Configured!         " -ForegroundColor Green
Write-Host "  Telemetry Channel: Microsoft-Windows-Sysmon/Operational        " -ForegroundColor White
Write-Host "  Target Backend:    $BackendUrl                                 " -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "To start live event streaming immediately, run:" -ForegroundColor Yellow
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$CollectorScript`"" -ForegroundColor Cyan
