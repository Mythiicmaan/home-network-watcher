# Shared helpers for install.ps1, uninstall.ps1, restart.ps1, restore.ps1, check_service.ps1.
# Dot-source it: . (Join-Path $PSScriptRoot 'common.ps1')

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Ok([string]$Message) { Write-Host "    OK    $Message" -ForegroundColor Green }
function Note([string]$Message) { Write-Host "    NOTE  $Message" -ForegroundColor Yellow }
function Stop-Install([string]$Message) {
    Write-Host "`n    STOPPED: $Message" -ForegroundColor Red
    Write-Host '    Nothing else was changed. Fix the above and run this script again.' -ForegroundColor Red
    exit 1
}

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-Plain([Security.SecureString]$Secure) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Test-Listening([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Get-PythonHome([string]$RepoDir) {
    $cfg = Join-Path $RepoDir '.venv\pyvenv.cfg'
    if (-not (Test-Path $cfg)) { return '' }
    return (Get-Content $cfg | Where-Object { $_ -match '^\s*home\s*=' } | Select-Object -First 1) -replace '^\s*home\s*=\s*', ''
}

function Get-BackupDir([string]$Python, [string]$DataDir) {
    # [backup] dir from the private config.toml (empty when not set).
    $env:NETWATCH_DATA_DIR = $DataDir
    return "$(& $Python -c 'from netwatch.config import load_config; print(load_config().backup_dir or str())')".Trim()
}

function Get-NetwatchProcesses {
    # Needs admin to see other accounts' command lines.
    return Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -like '*-m netwatch*' -and $_.CommandLine -notlike '*--sample*' }
}

function Stop-Netwatch([string]$TaskName, [int]$Port) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    Get-NetwatchProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    for ($i = 0; $i -lt 15 -and (Test-Listening $Port); $i++) { Start-Sleep -Seconds 1 }
    return -not (Test-Listening $Port)
}

function Wait-Healthy([int]$Port, [int]$Seconds = 60) {
    for ($i = 0; $i -lt ($Seconds / 2); $i++) {
        Start-Sleep -Seconds 2
        try {
            $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 3
            if ($r.status -eq 'ok') { return $r }
        } catch { }
    }
    return $null
}

function Get-PortOwner([int]$Port) {
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $listener) { return '' }
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
    return (Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue).User
}

# ---------------------------------------------------------------- "Log on as a batch job"

function Edit-BatchLogonRight([string]$Sid, [bool]$Grant) {
    $inf = Join-Path $env:TEMP ("nw-rights-{0}.inf" -f [guid]::NewGuid())
    $sdb = Join-Path $env:TEMP ("nw-rights-{0}.sdb" -f [guid]::NewGuid())
    try {
        secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
        $lines = @(Get-Content $inf)
        $idx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*SeBatchLogonRight\s*=') { $idx = $i } }
        $has = $idx -ge 0 -and $lines[$idx] -match ([regex]::Escape("*$Sid") + '(?![\d-])')
        if ($Grant -eq $has) { return $true }
        if ($Grant) {
            if ($idx -ge 0) {
                $lines[$idx] = $lines[$idx].TrimEnd() + ",*$Sid"
            } else {
                $at = [array]::IndexOf($lines, '[Privilege Rights]')
                if ($at -lt 0) { return $false }
                $before = @($lines[0..$at])
                $after = if ($at -lt $lines.Count - 1) { @($lines[($at + 1)..($lines.Count - 1)]) } else { @() }
                $lines = $before + @("SeBatchLogonRight = *$Sid") + $after
            }
        } else {
            $lines[$idx] = ($lines[$idx] -replace (',?\*' + [regex]::Escape($Sid) + '(?![\d-])'), '') -replace '=\s*,', '= '
        }
        Set-Content -Path $inf -Value $lines -Encoding Unicode
        secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally {
        Remove-Item $inf, $sdb, ($sdb -replace '\.sdb$', '.jfm') -ErrorAction SilentlyContinue
    }
}
function Grant-BatchLogonRight([string]$Sid) { return Edit-BatchLogonRight $Sid $true }
function Revoke-BatchLogonRight([string]$Sid) { return Edit-BatchLogonRight $Sid $false }

# ---------------------------------------------------------------- Tailscale

function Get-TailscaleExe {
    $default = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
    if (Test-Path $default) { return $default }
    $cmd = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return ''
}

function Get-ServeConfig([string]$Ts) {
    $raw = & $Ts serve status --json 2>$null
    if (-not $raw) { return $null }
    return ($raw | Out-String | ConvertFrom-Json)
}

function Get-ServeProxy($Config, [int]$Port) {
    # The proxy target served at https://<this PC>:<Port>/ (empty when nothing is).
    if (-not $Config -or -not $Config.Web) { return '' }
    foreach ($site in $Config.Web.PSObject.Properties) {
        if ($site.Name -like "*:$Port") {
            $root = $site.Value.Handlers.PSObject.Properties | Where-Object { $_.Name -eq '/' }
            if ($root) { return [string]$root.Value.Proxy }
        }
    }
    return ''
}

function Get-PhoneUrl([string]$Ts, [int]$Port) {
    $status = & $Ts status --json 2>$null | Out-String | ConvertFrom-Json
    $dns = if ($status) { [string]$status.Self.DNSName } else { '' }
    if (-not $dns) { return '' }
    return "https://$($dns.TrimEnd('.')):$Port"
}
