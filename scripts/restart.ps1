#Requires -Version 5.1
<#
.SYNOPSIS
    Restart Home Network Watcher so it picks up new code (database updates run on start).

.DESCRIPTION
    Run from an ADMIN PowerShell window. Your data is not touched.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\restart.ps1
#>
[CmdletBinding()]
param(
    [string]$DataDir = $(if ($env:NETWATCH_DATA_DIR) { $env:NETWATCH_DATA_DIR } else { 'C:\NetWatchData' }),
    [string]$TaskName = 'Home Network Watcher',
    [int]$Port = 8766
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not (Test-Admin)) {
    Write-Host 'Run this from an admin PowerShell window.' -ForegroundColor Red
    exit 1
}
if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    Write-Host "Scheduled task '$TaskName' not found. Run install.ps1 first." -ForegroundColor Red
    exit 1
}

if (-not (Stop-Netwatch $TaskName $Port)) {
    Write-Host "Something is still using port $Port; not starting a second copy." -ForegroundColor Red
    exit 1
}
Start-ScheduledTask -TaskName $TaskName
if (Wait-Healthy $Port) {
    Write-Host "App restarted and answering (running as: $(Get-PortOwner $Port))." -ForegroundColor Green
} else {
    Write-Host "The app did not answer. Copy this message to Claude and check $DataDir\logs\app.log" -ForegroundColor Red
    exit 1
}
