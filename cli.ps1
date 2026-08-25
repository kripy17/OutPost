# OutPost — Universal CLI & SOC Terminal Launcher (Windows PowerShell)
#
# Launches the OutPost Typer/Rich CLI or interactive SOC Terminal TUI.
#
# Usage:
#   .\cli.ps1                   # Launch the interactive full-screen SOC Terminal (TUI)
#   .\cli.ps1 <command> [args]  # Run any OutPost CLI command
#   .\cli.ps1 --help            # Show all available commands

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[-] Virtual environment not found. Running .\setup.ps1..." -ForegroundColor Red
    .\setup.ps1
}

& ".\.venv\Scripts\python.exe" -m outpost.main @args
