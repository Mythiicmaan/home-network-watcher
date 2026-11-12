#Requires -Version 5.1
<#
.SYNOPSIS
    One-time setup so Home Network Watcher runs 24/7 on this PC, before anyone signs in.

.DESCRIPTION
    Run from an ADMIN PowerShell window. Safe to run again (it updates what exists).
      1. Creates a standard (non-admin) local account that runs the app.
      2. Lets that account run scheduled tasks ("Log on as a batch job").
      3. Gives it Modify on the data and backup folders, Read on the code and Python.
      4. Registers the "Home Network Watcher" scheduled task: at startup, whether or not
         anyone is signed in, restart on failure (3 tries, 1 minute apart).
      5. Makes a first backup, starts the app, and checks that it answers.
      6. Phones: `tailscale serve` on HTTPS port 8443, leaving the household-budget
         app's `tailscale serve` on 443 exactly as it was (checked before and after).
    The app listens on 127.0.0.1 only. No firewall rules or port forwarding are added.
    Discovery needs no admin rights (ping sweep + the Windows neighbor table), and the
    port check is an Nmap TCP connect scan, so the service account stays a standard user.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
#>
[CmdletBinding()]
param(
    [string]$DataDir = $(if ($env:NETWATCH_DATA_DIR) { $env:NETWATCH_DATA_DIR } else { 'C:\NetWatchData' }),
    [string]$BackupDir = '',
    [string]$ServiceUser = 'netwatchsvc',
    [string]$TaskName = 'Home Network Watcher',
    [int]$Port = 8766,
    [int]$TailscalePort = 8443,
    [int]$BudgetPort = 8765,
    [switch]$SkipTailscale,
    [switch]$ShowUserOnSignInScreen
)

$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'common.ps1')

# --------------------------------------------------------------------------- 0. checks
Step 'Checking prerequisites'
if (-not (Test-Admin)) {
    Stop-Install 'This must run as administrator. Right-click Windows PowerShell > Run as administrator.'
}
Ok 'Running as administrator'

$Python = Join-Path $RepoDir '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) { Stop-Install "Virtual environment not found at $Python." }
$PyHome = Get-PythonHome $RepoDir
if (-not $PyHome -or -not (Test-Path $PyHome)) { Stop-Install "Python install folder not found: $PyHome" }
Ok "Python: $PyHome"

if (-not (Test-Path (Join-Path $DataDir 'netwatch.db'))) { Stop-Install "No database at $DataDir\netwatch.db." }
if (-not (Test-Path (Join-Path $DataDir 'config.toml'))) { Stop-Install "No config at $DataDir\config.toml." }
Ok "Data folder: $DataDir"

# The backup folder comes from [backup] dir in the private config.toml.
if (-not $BackupDir) { $BackupDir = Get-BackupDir $Python $DataDir }
if (-not $BackupDir) { Stop-Install "Set [backup] dir in $DataDir\config.toml." }
$BackupDrive = Split-Path -Qualifier $BackupDir
if (-not (Test-Path "$BackupDrive\")) {
    Stop-Install "Backup drive $BackupDrive is not connected. Plug in the backup drive (it must show as $BackupDrive)."
}
Ok "Backup drive $BackupDrive is connected"

$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Note "Task '$TaskName' already exists; stopping it so it can be updated."
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}
if (Test-Listening $Port) {
    $holders = @(Get-NetwatchProcesses)
    if (-not $holders) {
        Stop-Install "Something other than NetWatch is using port $Port. Close it and run this script again."
    }
    Note "NetWatch is already running (started by hand, PID $($holders.ProcessId -join ', '))."
    $answer = Read-Host '    Stop it so the scheduled task can take over? [Y/n]'
    if ($answer -and $answer -notmatch '^[Yy]') { Stop-Install 'Left the running copy alone.' }
    $holders | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    for ($i = 0; $i -lt 15 -and (Test-Listening $Port); $i++) { Start-Sleep -Seconds 1 }
    if (Test-Listening $Port) { Stop-Install "Port $Port is still in use." }
}
Ok "Port $Port is free"

# --------------------------------------------------------------------------- 1. account
Step "Setting up the standard (non-admin) account '$ServiceUser'"
$user = Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue
if ($user) {
    Note "Account '$ServiceUser' already exists. Enter its current password."
    $secure = Read-Host -AsSecureString "Password for $ServiceUser"
} else {
    Write-Host '    Choose a strong password and save it in your password manager.'
    Write-Host '    Nobody signs in with this account; it only runs the app.'
    $secure = Read-Host -AsSecureString "New password for $ServiceUser"
    $again = Read-Host -AsSecureString 'Type it again'
    if ((ConvertTo-Plain $secure) -cne (ConvertTo-Plain $again)) { Stop-Install 'The two passwords did not match.' }
    if ((ConvertTo-Plain $secure).Length -lt 12) { Stop-Install 'Please use at least 12 characters.' }
    New-LocalUser -Name $ServiceUser -Password $secure -FullName 'Home Network Watcher service' `
        -Description 'Runs Home Network Watcher (not an admin)' `
        -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires | Out-Null
    Ok "Created account '$ServiceUser'"
}
# Standard user: member of Users (by SID, works in any Windows language), never Administrators.
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $ServiceUser -ErrorAction SilentlyContinue
$admins = Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -like "*\$ServiceUser" }
if ($admins) { Stop-Install "'$ServiceUser' is an administrator. Remove it from Administrators first." }
Ok "'$ServiceUser' is a standard user"

$userListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if (-not $ShowUserOnSignInScreen) {
    New-Item -Path $userListKey -Force | Out-Null
    New-ItemProperty -Path $userListKey -Name $ServiceUser -Value 0 -PropertyType DWord -Force | Out-Null
    Ok 'Hidden from the sign-in screen'
}

# --------------------------------------------------------------------------- 2. batch logon right
Step "Allowing '$ServiceUser' to run scheduled tasks (Log on as a batch job)"
$sid = (New-Object Security.Principal.NTAccount($ServiceUser)).Translate([Security.Principal.SecurityIdentifier]).Value
if (Grant-BatchLogonRight $sid) { Ok 'Allowed' } else { Stop-Install 'Windows refused the "Log on as a batch job" change.' }

# --------------------------------------------------------------------------- 3. folder permissions
Step 'Setting folder permissions (least privilege)'
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'logs') | Out-Null
$grants = @(
    @{ Path = $DataDir;   Right = '(OI)(CI)M';  Why = 'modify (database, config, logs, vendor list)' },
    @{ Path = $BackupDir; Right = '(OI)(CI)M';  Why = 'modify (backups)' },
    @{ Path = $RepoDir;   Right = '(OI)(CI)RX'; Why = 'read and run (the code)' },
    @{ Path = $PyHome;    Right = '(OI)(CI)RX'; Why = 'read and run (Python)' }
)
foreach ($g in $grants) {
    icacls $g.Path /grant "${ServiceUser}:$($g.Right)" /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Install "Could not set permissions on $($g.Path)." }
    Ok "$($g.Path): $($g.Why)"
}
if ($DataDir -ne 'C:\NetWatchData') {
    [Environment]::SetEnvironmentVariable('NETWATCH_DATA_DIR', $DataDir, 'Machine')
    Ok "NETWATCH_DATA_DIR set to $DataDir for all users"
}

# --------------------------------------------------------------------------- 4. scheduled task
Step "Registering scheduled task '$TaskName'"
$action = New-ScheduledTaskAction -Execute $Python -Argument '-m netwatch serve' -WorkingDirectory $RepoDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$plain = ConvertTo-Plain $secure
try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -User "$env:COMPUTERNAME\$ServiceUser" -Password $plain -RunLevel Limited -Force `
        -Description "Home Network Watcher on 127.0.0.1:$Port (reached from phones via Tailscale)." | Out-Null
} catch {
    Stop-Install "Could not register the task. If '$ServiceUser' already existed, the password may be wrong. ($($_.Exception.Message))"
} finally {
    $plain = $null
}
Ok 'Runs at startup, whether or not anyone is signed in; restarts on failure (3 x 1 min)'

# --------------------------------------------------------------------------- 5. first backup, start, verify
Step "First backup to $BackupDir"
$env:NETWATCH_DATA_DIR = $DataDir
& $Python -m netwatch backup
if ($LASTEXITCODE -ne 0) { Note 'The first backup failed (see above). The app will retry and show a banner.' }
else { Ok 'Backup written' }
# Files the backup (run as you) just created must stay writable by the service account.
icacls $DataDir /grant "${ServiceUser}:(OI)(CI)M" /T /C /Q | Out-Null

Step 'Starting the app'
$startedAt = Get-Date
Start-ScheduledTask -TaskName $TaskName
$health = Wait-Healthy $Port
if (-not $health) {
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    Stop-Install ("The app did not answer. Task result code: $($info.LastTaskResult). " +
        "Check $DataDir\logs\app.log and Task Scheduler > '$TaskName' > History.")
}
$owner = Get-PortOwner $Port
Ok "App is up at http://localhost:$Port (running as: $owner)"
if ($owner -and $owner -ne $ServiceUser) { Note "Expected it to run as $ServiceUser." }
if ($health.backup.ok) { Ok "Backups OK (last: $($health.backup.last_ok_at))" } else { Note "Backup status: $($health.backup.problem)" }

# Wait for the first scan as the service account: proves discovery works without admin.
Write-Host '    Waiting for the first scan (up to 90 seconds)...'
$scan = $null
for ($i = 0; $i -lt 45 -and -not $scan; $i++) {
    Start-Sleep -Seconds 2
    try { $scan = (Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 3).last_scan } catch { }
    # /health gives UTC with a Z; [datetime] turns it into local time.
    if ($scan -and [datetime]$scan.at -lt $startedAt) { $scan = $null }
}
if (-not $scan) { Note "No scan yet. Check $DataDir\logs\app.log in a few minutes." }
elseif ($scan.ok -and -not $scan.degraded) { Ok 'First scan as the service account: OK' }
else { Note "First scan: ok=$($scan.ok) degraded=$($scan.degraded). Check the dashboard." }

# --------------------------------------------------------------------------- 6. phones (Tailscale)
if ($SkipTailscale) {
    Note 'Skipped Tailscale (-SkipTailscale).'
} else {
    Step "Phone access: tailscale serve on HTTPS port $TailscalePort"
    $ts = Get-TailscaleExe
    if (-not $ts) {
        Note 'Tailscale is not installed; skipped. Phones can still be set up later by running this again.'
    } else {
        $before = Get-ServeConfig $ts
        $budgetBefore = Get-ServeProxy $before 443
        if ($budgetBefore) { Ok "Budget app on 443 before: $budgetBefore" } else { Note 'Nothing is served on 443 right now.' }
        & $ts serve --bg "--https=$TailscalePort" "http://127.0.0.1:$Port" | Out-Null
        if ($LASTEXITCODE -ne 0) { Stop-Install 'tailscale serve failed. Is Tailscale signed in and HTTPS turned on for the tailnet?' }
        $after = Get-ServeConfig $ts
        $ours = Get-ServeProxy $after $TailscalePort
        $budgetAfter = Get-ServeProxy $after 443
        if ($ours -ne "http://127.0.0.1:$Port") { Stop-Install "Port $TailscalePort is not pointing at the app (it shows: $ours)." }
        Ok "Port $TailscalePort -> $ours"
        if ($budgetAfter -ne $budgetBefore) {
            Write-Host "    WARNING: the budget app's 443 setting changed ($budgetBefore -> $budgetAfter)." -ForegroundColor Red
            Write-Host "    Put it back with:  tailscale serve --bg $BudgetPort" -ForegroundColor Red
        } else {
            Ok "Budget app on 443 unchanged"
        }
        $url = Get-PhoneUrl $ts $TailscalePort
        if ($url) { Ok "Phones (signed in to Tailscale): $url" }
    }
}

Write-Host "`nAll set. Next: restart the PC and DON'T sign in for 2 minutes. Then sign in and run:" -ForegroundColor Cyan
Write-Host '    powershell -ExecutionPolicy Bypass -File .\scripts\check_service.ps1' -ForegroundColor Cyan
