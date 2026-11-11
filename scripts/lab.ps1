# Live lab control.
# Usage:  .\scripts\lab.ps1 up|down|reset|run|status
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("up", "down", "reset", "run", "status")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$python = ".\.venv\Scripts\python.exe"

switch ($Action) {
    "up" {
        docker compose up -d
        Write-Host "Waiting for Elasticsearch..." -ForegroundColor Cyan
        for ($i = 0; $i -lt 60; $i++) {
            try {
                $health = Invoke-RestMethod -Uri "http://localhost:9200/_cluster/health" -TimeoutSec 3
                if ($health.status -in @("green", "yellow")) {
                    Write-Host "Elasticsearch is $($health.status). Kibana: http://localhost:5601" -ForegroundColor Green
                    break
                }
            } catch { Start-Sleep -Seconds 2 }
        }
    }
    "down" { docker compose down }
    "reset" {
        & $python -m pipeline.labgen --scenario all --out lab/logs
        & $python -m pipeline.ingest --reset
    }
    "run" { & $python -m pipeline.detect --hours 24 }
    "status" {
        Invoke-RestMethod -Uri "http://localhost:9200/_cat/indices/lab-*?v"
    }
}
