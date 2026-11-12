#Requires -Version 5.1
<#
.SYNOPSIS
    Undo install.ps1: remove the scheduled task, phone access on port 8443, and the
    service account's permissions.

.DESCRIPTION
    Run from an ADMIN PowerShell window. Your data and backups are NOT touched, and the
    household-budget app's `tailscale serve` on 443 is left alone.
    Add -RemoveUser to also delete the 'netwatchsvc' account.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1 -RemoveUser
#>
[CmdletBinding()]
param(
    [string]$DataDir = $(if ($env:NETWATCH_DATA_DIR) { $env:NETWATCH_DATA_DIR } else { 'C:\NetWatchData' }),
    [string]$BackupDir = '',
    [string]$ServiceUser = 'netwatchsvc',
    [string]$TaskName = 'Home Network Watcher',
    [int]$Port = 8766,
    [int]$TailscalePort = 8443,
    [switch]$RemoveUser
)
$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not (Test-Admin)) {
    Write-Host 'Run this from an admin PowerShell window.' -ForegroundColor Red
    exit 1
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-Netwatch $TaskName $Port | Out-Null
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'."
}

$ts = Get-TailscaleExe
if ($ts -and (Get-ServeProxy (Get-ServeConfig $ts) $TailscalePort) -eq "http://127.0.0.1:$Port") {
    # Only our port. Never `tailscale serve reset`: that would also remove the budget app's 443.
    & $ts serve "--https=$TailscalePort" off | Out-Null
    Write-Host "Turned off phone access on port $TailscalePort (443 untouched)."
}

$PyHome = Get-PythonHome $RepoDir
if (-not $BackupDir) { $BackupDir = Get-BackupDir (Join-Path $RepoDir '.venv\Scripts\python.exe') $DataDir }
foreach ($p in @($DataDir, $BackupDir, $RepoDir, $PyHome)) {
    if ($p -and (Test-Path $p)) {
        icacls $p /remove:g $ServiceUser /T /C /Q | Out-Null
        Write-Host "Removed '$ServiceUser' permissions from $p"
    }
}

if ($RemoveUser -and (Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue)) {
    $sid = (Get-LocalUser -Name $ServiceUser).SID.Value
    Revoke-BatchLogonRight $sid | Out-Null
    Remove-LocalUser -Name $ServiceUser
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' `
        -Name $ServiceUser -ErrorAction SilentlyContinue
    Write-Host "Removed account '$ServiceUser'. (Its empty profile folder under C:\Users can be deleted by hand.)"
}
Write-Host 'Done. Data and backups were not touched.' -ForegroundColor Green
