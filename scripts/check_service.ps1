#Requires -Version 5.1
<#
.SYNOPSIS
    Show whether Home Network Watcher is running as a background service, how scans and
    backups are doing, and whether phone access (and the budget app's) is set up.
    Works without admin (some details need admin and are skipped otherwise).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\check_service.ps1
#>
[CmdletBinding()]
param(
    [string]$DataDir = $(if ($env:NETWATCH_DATA_DIR) { $env:NETWATCH_DATA_DIR } else { 'C:\NetWatchData' }),
    [string]$TaskName = 'Home Network Watcher',
    [int]$Port = 8766,
    [int]$TailscalePort = 8443,
    [int]$BudgetPort = 8765
)
. (Join-Path $PSScriptRoot 'common.ps1')

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$signIn = (Get-Process -Name explorer -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1).StartTime
Write-Host "PC started:        $boot"
Write-Host "You signed in:     $signIn"

try {
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
    Write-Host "Task last started: $($info.LastRunTime)  (result $($info.LastTaskResult); 267009 = running)"
} catch {
    Write-Host 'Task details:      need an admin window (or the task is not installed).' -ForegroundColor Yellow
}

# Find the app by the process listening on the port. (Without admin, Windows hides other
# accounts' command lines, so matching on "-m netwatch" would miss the service.)
$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) {
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
    $owner = (Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue).User
    if (-not $owner) { $owner = 'another account (run as admin to see which)' }
    Write-Host "App process:       running since $($proc.CreationDate) as $owner"
    if ($signIn -and $proc.CreationDate -lt $signIn) {
        Write-Host '  -> Started BEFORE you signed in: startup without sign-in works.' -ForegroundColor Green
    }
} else {
    Write-Host "App process:       nothing is listening on port $Port" -ForegroundColor Red
}

try {
    $h = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 5
    Write-Host "Health:            $($h.status), monitor running: $($h.monitor_running)" -ForegroundColor Green
    if ($h.last_scan) {
        $color = if ($h.last_scan.ok -and -not $h.last_scan.degraded) { 'Green' } else { 'Yellow' }
        Write-Host "Last scan:         $([datetime]$h.last_scan.at)  ok=$($h.last_scan.ok) degraded=$($h.last_scan.degraded)" -ForegroundColor $color
    }
    if ($h.alerts.failing) { Write-Host "Alerts:            $($h.alerts.failing) failing to send" -ForegroundColor Red }
    else { Write-Host "Alerts:            email set up: $($h.alerts.channel_configured), waiting: $($h.alerts.unsent)" }
    if (-not $h.backup.configured) { Write-Host 'Backups:           not set up ([backup] dir in config.toml)' -ForegroundColor Yellow }
    elseif ($h.backup.ok) { Write-Host "Backups:           OK, last $($h.backup.last_ok_at)" -ForegroundColor Green }
    else { Write-Host "Backups:           PROBLEM: $($h.backup.problem)" -ForegroundColor Red }
} catch {
    Write-Host "Health:            no answer on http://127.0.0.1:$Port" -ForegroundColor Red
}

$ts = Get-TailscaleExe
if ($ts) {
    $serve = Get-ServeConfig $ts
    $ours = Get-ServeProxy $serve $TailscalePort
    $budget = Get-ServeProxy $serve 443
    if ($ours) { Write-Host "Phones (:$TailscalePort):   -> $ours" -ForegroundColor Green }
    else { Write-Host "Phones (:$TailscalePort):   not set up" -ForegroundColor Yellow }
    if ($budget -eq "http://127.0.0.1:$BudgetPort") { Write-Host "Budget app (:443): -> $budget" -ForegroundColor Green }
    else { Write-Host "Budget app (:443): $(if ($budget) { "-> $budget (unexpected)" } else { 'not served' })" -ForegroundColor Yellow }
}
if (Test-Listening $BudgetPort) { Write-Host "Budget app:        answering on port $BudgetPort" -ForegroundColor Green }
else { Write-Host "Budget app:        nothing on port $BudgetPort" -ForegroundColor Yellow }

$log = Join-Path $DataDir 'logs\app.log'
if (Test-Path $log) {
    Write-Host "`nLast lines of $log"
    Get-Content $log -Tail 8 | ForEach-Object { Write-Host "  $_" }
}
