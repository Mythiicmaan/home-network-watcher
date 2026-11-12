#Requires -Version 5.1
<#
.SYNOPSIS
    Restore the database from a backup file.

.DESCRIPTION
    Run from an ADMIN PowerShell window (it stops and restarts the scheduled task).
    Asks for confirmation. The current database is renamed aside, never deleted.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\restore.ps1 X:\Backups\NetWatch\netwatch-2027-01-31.db
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BackupFile,
    [string]$DataDir = $(if ($env:NETWATCH_DATA_DIR) { $env:NETWATCH_DATA_DIR } else { 'C:\NetWatchData' }),
    [string]$ServiceUser = 'netwatchsvc',
    [string]$TaskName = 'Home Network Watcher',
    [int]$Port = 8766
)
$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoDir '.venv\Scripts\python.exe'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not (Test-Path $BackupFile)) { Write-Host "Backup file not found: $BackupFile" -ForegroundColor Red; exit 1 }
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task -and -not (Test-Admin)) {
    Write-Host 'Run this from an admin PowerShell window (it needs to stop the app).' -ForegroundColor Red
    exit 1
}

Write-Host "This replaces $DataDir\netwatch.db with:" -ForegroundColor Yellow
Write-Host "    $BackupFile ($((Get-Item $BackupFile).LastWriteTime))" -ForegroundColor Yellow
Write-Host 'Scans and changes after that backup will not be in the restored database' -ForegroundColor Yellow
Write-Host '(the current database is kept as netwatch-before-restore-<time>.db).' -ForegroundColor Yellow
if ((Read-Host 'Type RESTORE to continue') -cne 'RESTORE') { Write-Host 'Cancelled. Nothing changed.'; exit 1 }

if (-not (Stop-Netwatch $TaskName $Port)) {
    Write-Host "The app is still running on port $Port (close any window running it). Nothing changed." -ForegroundColor Red
    if ($task) { Start-ScheduledTask -TaskName $TaskName }
    exit 1
}

$env:NETWATCH_DATA_DIR = $DataDir
& $Python -m netwatch restore $BackupFile --yes
$ok = ($LASTEXITCODE -eq 0)
if ($task) {
    # The restored file was copied by you; keep it writable by the service account.
    icacls $DataDir /grant "${ServiceUser}:(OI)(CI)M" /T /C /Q | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    if (Wait-Healthy $Port) { Write-Host 'App restarted and answering.' -ForegroundColor Green }
    else { Write-Host "App did not answer; check $DataDir\logs\app.log" -ForegroundColor Red; exit 1 }
}
if (-not $ok) { exit 1 }
Write-Host 'Restore complete.' -ForegroundColor Green
