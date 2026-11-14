# Offline demo: runs the Docker-free parts of the pipeline end to end.
# Usage:  .\scripts\demo.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "Creating virtual environment with Python 3.11..." -ForegroundColor Cyan
    py -3.11 -m venv .venv
    & $python -m pip install --quiet --upgrade pip
    & $python -m pip install --quiet -r requirements.txt
}

Write-Host "`n[1/6] Linting rule metadata" -ForegroundColor Cyan
& $python -m pipeline.lint

Write-Host "`n[2/6] Compiling Sigma -> EQL/KQL" -ForegroundColor Cyan
& $python -m pipeline.compile

Write-Host "`n[3/6] Building ATT&CK coverage" -ForegroundColor Cyan
& $python -m pipeline.coverage

Write-Host "`n[4/6] Generating synthetic telemetry" -ForegroundColor Cyan
& $python -m pipeline.labgen --scenario all --out lab/logs

Write-Host "`n[5/6] Running correlation over the Linux log" -ForegroundColor Cyan
& $python -m pipeline.correlate --input lab/logs/linux.ndjson

Write-Host "`n[6/6] Running tests" -ForegroundColor Cyan
& $python -m pytest

Write-Host "`nDone. For the live path: docker compose up -d, then python -m pipeline.ingest --reset" -ForegroundColor Green
