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

> [!important] **The engagement default loop:** After ANY successful crack → `./sprayr.sh --from-creds`. After spray → read `next_steps.txt` for pre-built follow-on commands. This is the credential loop.

> [!warning] Lockout risk — read before running
> Domain sprays with a user file can trigger lockouts. Always check the lockout policy first with `adr.sh --quick`. Use `--safe` when spraying domain accounts.

---

## Quick Reference

```bash
# ★ Re-spray ALL creds after any crack (THE engagement default — one command covers everything)
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
| `--threads N` | 20 | nxc thread count |
| `--timeout N` | 30 | Per-protocol timeout in seconds |
| `--outdir DIR` | `$TOOLKIT_ROOT/spray/<timestamp>/` | Output directory |
| `--from-creds` | off | Spray all creds from `$TOOLKIT_ROOT/creds.txt` against all recon targets |

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
| SMB `Pwn3d!` | `impacket-psexec`, `impacket-wmiexec`, `impacket-smbexec`, `--sam` dump, `impacket-secretsdump` |
| WinRM `Pwn3d!` | `evil-winrm -i TARGET -u USER [-p PASS \| -H HASH]` |
| RDP hit | `xfreerdp3` with correct `/pth:` or `/p:` and `/d:` flags |
| SSH hit | `ssh USER@TARGET` |
| MSSQL hit | `nxc mssql ... -q 'SELECT @@version'` |
| LDAP hit | `./adr.sh -d DOMAIN -u USER [-p PASS \| -H :HASH] -dc TARGET` |

All commands are pre-filled with the actual credentials, hashes, IPs, and domain from the spray.

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

### ★ Re-spray all known creds (THE engagement default)
```bash
# After crackr.sh cracks anything — spray every cred in creds.txt
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
# After adr.sh → users/all_users.txt
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
# No hits — credential may be wrong
# Sanity check manually:
nxc smb 192.168.1.10 -u admin -p 'Password1' --local-auth

# "MISS: auth failed" — credential rejected by target
# → verify password/hash, check if account is locked, try --local-auth

# "No definitive auth-failure marker" — target responded oddly
# → check raw nxc output: cat spray/<ts>/raw/smb_spray.txt

# Port closed messages on every target
# → verify targets are up: nmap -sn 192.168.1.0/24

# Domain spray — worried about lockouts
# → get lockout policy: ./adr.sh -d corp.local -u USER -p PASS -dc DC_IP --quick
# → use --safe for sequential + jitter
# → spray ONE password at a time (this script sprays one cred per run by design)
```

---

## Related

- [[adr.sh]] — run first to get users/all_users.txt and check lockout policy
- [[crackr]] — crack the hashes that sprayr.sh then validates
- [[Active_Directory_PtH_PtT]] — what to do after Pwn3d! hits
- [[Active_Directory]] — broader AD attack methodology
- [[OffSec_AD_Mental_Model_Bus_Review]] — decision-tree for lateral movement
