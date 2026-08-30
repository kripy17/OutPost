<#
.SYNOPSIS
    OutPost — start / stop / status for the webapp stack on Windows PowerShell.

.DESCRIPTION
    start   Launch backend (:8001) + frontend (:5174) in background processes.
    stop    Stop background OutPost servers.
    status  Check if backend and frontend are responsive.
    logs    View latest server output.

.PARAMETER Action
    start | stop | status | logs (default: start)
#>

[CmdletBinding()]
param(
    [ValidateSet("start", "stop", "status", "logs")]
    [string]$Action = "start",
    [int]$ApiPort = 8001,
    [int]$WebPort = 5174
)

$ProjectRoot = (Resolve-Path "$PSScriptRoot\..").Path
$LogDir = Join-Path $ProjectRoot ".freebuff"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

$ApiLog = Join-Path $LogDir "backend.log"
$WebLog = Join-Path $LogDir "frontend.log"
$ApiPidFile = Join-Path $LogDir "backend.pid"
$WebPidFile = Join-Path $LogDir "frontend.pid"

function Test-ApiHealth {
    try {
        $res = Invoke-WebRequest -Uri "http://127.0.0.1:$ApiPort/health" -UseBasicParsing -TimeoutSec 2
        return ($res.StatusCode -eq 200)
    } catch {
        return $false
    }
}

function Test-WebHealth {
    try {
        $res = Invoke-WebRequest -Uri "http://localhost:$WebPort" -UseBasicParsing -TimeoutSec 2
        return ($res.StatusCode -eq 200)
    } catch {
        return $false
    }
}

switch ($Action) {
    "start" {
        if ((Test-ApiHealth) -or (Test-WebHealth)) {
            Write-Host "Something is already running on :$ApiPort or :$WebPort." -ForegroundColor Red
            exit 1
        }

        Write-Host "==> Starting backend on :$ApiPort" -ForegroundColor Green
        $VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
        if (-not (Test-Path $VenvPython)) { $VenvPython = "python" }

        $backendProc = Start-Process -FilePath $VenvPython -ArgumentList "-m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port $ApiPort" -RedirectStandardOutput $ApiLog -RedirectStandardError $ApiLog -PassThru -NoNewWindow
        $backendProc.Id | Out-File -FilePath $ApiPidFile -Encoding ascii

        Write-Host "==> Starting frontend on :$WebPort" -ForegroundColor Green
        $frontendProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c cd /d `"$ProjectRoot\frontend`" && npm run dev -- --port $WebPort" -RedirectStandardOutput $WebLog -RedirectStandardError $WebLog -PassThru -NoNewWindow
        $frontendProc.Id | Out-File -FilePath $WebPidFile -Encoding ascii

        Start-Sleep -Seconds 3
        Write-Host "==> OutPost Stack Launched!" -ForegroundColor Green
        Write-Host "    Webapp: http://localhost:$WebPort" -ForegroundColor Cyan
        Write-Host "    API:    http://localhost:$ApiPort" -ForegroundColor Cyan
    }

    "stop" {
        Write-Host "==> Stopping OutPost stack..." -ForegroundColor Green
        if (Test-Path $ApiPidFile) {
            $pidToKill = Get-Content $ApiPidFile -ErrorAction SilentlyContinue
            if ($pidToKill) { Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue }
            Remove-Item $ApiPidFile -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $WebPidFile) {
            $pidToKill = Get-Content $WebPidFile -ErrorAction SilentlyContinue
            if ($pidToKill) { Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue }
            Remove-Item $WebPidFile -Force -ErrorAction SilentlyContinue
        }
        Get-Process -Name "uvicorn", "node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*OutPost*" } | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "==> Stack stopped." -ForegroundColor Green
    }

    "status" {
        $apiUp = Test-ApiHealth
        $webUp = Test-WebHealth
        Write-Host "Backend API (: $ApiPort): " -NoNewline
        if ($apiUp) { Write-Host "ONLINE" -ForegroundColor Green } else { Write-Host "OFFLINE" -ForegroundColor Red }
        Write-Host "Frontend Web (: $WebPort): " -NoNewline
        if ($webUp) { Write-Host "ONLINE" -ForegroundColor Green } else { Write-Host "OFFLINE" -ForegroundColor Red }
    }

    "logs" {
        if (Test-Path $ApiLog) { Get-Content $ApiLog -Tail 20 }
        if (Test-Path $WebLog) { Get-Content $WebLog -Tail 20 }
    }
}
