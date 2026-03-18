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
Active Directory enumeration and attack-prep script. OffSec-focused, Kali-side only. Given valid domain credentials, it runs eight enumeration phases across users, groups, Kerberos targets, computers, SMB signing, BloodHound, shares, and sessions — then produces a `summary.txt` and a `attack_commands.txt` with fully resolved copy-paste next steps.

> [!important] Enumeration only — no exploitation
> OffSec compliant. Resume-safe — re-running skips completed phases unless `--force` is passed.

---

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
| `--threads N` | 10 | nxc thread count |
| `--quick` | off | Phases 1–3 only |
| `--skip-bloodhound` | off | Skip BloodHound collection |
| `--skip-shares` | off | Skip share enumeration |
| `--force` | off | Re-run all phases (ignore progress.log) |
| `--chain` | off | Interactive 7-step AD kill chain walkthrough |

---

## Output Structure

```
$TOOLKIT_ROOT/ad/<DOMAIN>/
├── summary.txt                  # ★ READ FIRST — structured findings
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
| 9 | Spray cracked passwords | `--chain` | PTH spray with cracked hashes against all users × all hosts |

> [!tip] `--quick` runs phases 1–3 only — use it for a fast initial sweep then decide whether to go deeper.

---

## Key Output Files (Check in This Order)

```bash
DOMAIN=corp.local

# Always read first
cat $TOOLKIT_ROOT/ad/$DOMAIN/summary.txt
cat $TOOLKIT_ROOT/ad/$DOMAIN/attack_commands.txt

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

## What Gets Auto-Generated in `attack_commands.txt`

The script writes fully resolved commands as each phase finds something. Always review before running:

| Finding | Commands Generated |
|---------|--------------------|
| Always | `impacket-secretsdump` template |
| Users collected | `nxc` password spray + hash spray against `all_users.txt` |
| AS-REP hashes | `hashcat -m 18200` + `crackr.sh` one-liner |
| Kerberoast hashes | `hashcat -m 13100` + `crackr.sh` one-liner |
| SMB signing disabled | `responder` + `impacket-ntlmrelayx` with payload template |
| Groups.xml in SYSVOL | `gpp-decrypt` + `impacket-GetGPPPassword` |

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

# 2. Open BloodHound CE in browser
# 3. File Ingest → upload zip

# 4. Mark your current user as Owned
# 5. Run pre-built queries:
#    - Shortest Path to Domain Admins from Owned Principals
#    - Find AS-REP Roastable Users
#    - Find Kerberoastable Users with Most Privileges
#    - Computers Where DA is Logged On
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

## Related

- [[Active_Directory]] — manual AD attack techniques
- [[OffSec_AD_Operational_Addendum]] — engagement-day AD reference
- [[OffSec_AD_Mental_Model_Bus_Review]] — decision-tree for AD attack paths
- [[crackr]] — crack the hashes from `hashes/asreproast.txt` and `hashes/kerberoast.txt`
- [[PtH_PtT]] — use cracked hashes for lateral movement
- [[Tunneling_Pivoting]] — pivot to reach internal DC
