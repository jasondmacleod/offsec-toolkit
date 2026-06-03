---
tags:
  - phase/recon
  - phase/enumeration
  - tool/toolkit-recon
  - tool/nmap
  - tool/rustscan
  - type/tool-docs
---

# recon.sh

## What It Is
Automated enumeration orchestrator for OffSec. Runs rustscan with nmap full-TCP fallback → nmap TCP service detection → targeted quick UDP plus top-port UDP → targeted service enumeration in parallel. Generates `summary.txt`, a high-confidence `loot/quick_wins.txt`, and a finding-driven `loot/next_steps.txt` per target.

`next_steps.txt` is intentionally evidence-gated: commands are emitted only when the script has concrete support from nmap results or non-empty output files. It does not print anonymous SMB commands unless anonymous/readable shares were actually found, and it does not treat WinRM/HTTPAPI ports as real web app targets.

> [!important] Enumeration only — no exploitation
> OffSec compliant. Finds the doors, you walk through them.

---

## engagement workflow

```bash
# 0. Triage first — rank targets by quick-win score before deep scanning
sudo ./recon.sh --auto --quick-wins-only 10.10.10.1 10.10.10.2 10.10.10.3
cat $TOOLKIT_ROOT/recon/target_priority.txt   # attack highest-score target first

# 1. Fire deep recon on all targets simultaneously
sudo ./recon.sh --auto 10.10.10.1 10.10.10.2 10.10.10.3

# 2. Read engagement instructions while it runs, then check summaries
# summary.txt includes a short high-value preview of grounded next steps
# next_steps.txt has the full evidence-backed follow-up command library
# quick_wins.txt has only high-confidence actionable findings, not plain service detections
cat $TOOLKIT_ROOT/recon/*/summary.txt
cat $TOOLKIT_ROOT/recon/*/loot/next_steps.txt
cat $TOOLKIT_ROOT/recon/*/loot/quick_wins.txt

# 3. Start with the box that has the most findings

# 4. If stuck, launch deep UDP on that target
sudo ./recon.sh --auto --udp-full 10.10.10.X

# 5. Resume safely after interruption — completed phases are skipped
sudo ./recon.sh --auto 10.10.10.1

# 6. Force full re-run
rm $TOOLKIT_ROOT/recon/10.10.10.1/progress.log && sudo ./recon.sh --auto 10.10.10.1
```

---

## Usage

```bash
# Single target
sudo ./recon.sh --auto 10.10.10.1

# Multiple targets
sudo ./recon.sh --auto 10.10.10.1 10.10.10.2 10.10.10.3

# Targets from file (one IP per line, # comments ok)
sudo ./recon.sh -f targets.txt

# Fast/high-bandwidth network
sudo ./recon.sh --auto --batch-size 3000 10.10.10.1

# Deep UDP (slow — use when stuck)
sudo ./recon.sh --auto --udp-full 10.10.10.1

# Custom output directory
sudo ./recon.sh --auto --outdir ~/engagement/recon 10.10.10.1
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--auto` | off | Skip confirmation prompts |
| `--batch-size N` | 1500 (1-65535) | Rustscan batch size; nmap full-TCP fallback is used if rustscan is missing, fails, or finds no ports |
| `--udp-ports N` | 200 | Top N UDP ports to scan |
| `--udp-full` | off | Also scan all 65535 UDP ports |
| `--outdir DIR` | `$TOOLKIT_ROOT/recon` | Output directory |
| `--quick-wins` | off | Run 5-min triage per target before deep recon |
| `--quick-wins-only` | off | Triage only — rank targets, skip deep scan |
| `--max-parallel N` | 5 (1-32) | Max concurrent service enumerations per target |
| `--max-parallel-targets N` | 3 | Max simultaneous target scans |
| `--sequential` | off | Process targets one at a time (default: parallel) |
| `-f FILE` | — | Read targets from file |
| `--rate N` | 1500 | Deprecated alias for `--batch-size` |
| `--no-sudo` | off | Skip automatic sudo re-exec (run without root — UDP/OS detection disabled) |
| `--no-color` | off | Disable ANSI colors (also: `export NO_COLOR=1`; auto-off when not a TTY) |

When launched through `sudo`, the default `$TOOLKIT_ROOT` resolves to the invoking
user's home directory instead of `/root/toolkit`.

> [!note] Always `sudo`
> UDP scanning and OS detection (`-O`) require root. Non-root mode skips both automatically with a warning — no crash.

---

## Output Structure

```
$TOOLKIT_ROOT/recon/
├── target_priority.txt        # ★ Ranked target list from --quick-wins-only
└── <IP>/
    ├── scans/
    │   ├── rustscan_tcp.txt       # Raw rustscan output
    │   ├── nmap_full_tcp_discovery.* # nmap fallback when rustscan is unavailable or empty
    │   ├── tcp_ports.txt          # Comma-separated open TCP ports
    │   ├── nmap_tcp.*             # nmap TCP scan (all formats)
    │   ├── nmap_udp_quick.*       # High-signal UDP ports
    │   ├── nmap_udp.*             # nmap UDP top-port scan
    │   └── udp_ports.txt          # Open UDP ports
    ├── tcp/
    │   ├── http/port_<N>/         # Per-port: whatweb, TLS/WAF hints, nikto, gobuster, ffuf
    │   ├── smb/                   # enum4linux-ng, smbmap, smbclient, nxc, NetBIOS hints
    │   ├── ftp/                   # Anon login check + file mirror
    │   ├── ssh/                   # Banner, auth methods, version flags
    │   ├── mysql/                 # Empty/root no-pass check
    │   ├── postgres/              # Default creds
    │   ├── dns/                   # Zone transfer attempt, dnsrecon when a domain is known
    │   ├── smtp/                  # VRFY user enum
    │   ├── ldap/                  # Anonymous bind, directory dump
    │   ├── rpc/                   # Null sessions, NFS exports
    │   └── redis/                 # No-auth access check
    ├── udp/
    │   └── snmp/                  # onesixtyone, snmpwalk, snmpcheck (processes, software, ARP)
    ├── loot/
    │   ├── quick_wins.txt         # ★ High-confidence wins only, not service detections
    │   ├── next_steps.txt         # ★ Evidence-backed follow-up command library
    │   ├── smtp_valid_users.txt   # Created only when SMTP VRFY finds users
    │   └── snmp_windows_users.txt # Created only when SNMP exposes Windows users
    ├── progress.log               # Phase tracking (START/DONE/FAIL/SKIP)
    └── summary.txt                # Human-readable findings report
```

---

## Key Output Files (Check in This Order)

```bash
IP=10.10.10.1

# Big picture — always read first; NEXT-STEP COMMANDS is a short preview
cat $TOOLKIT_ROOT/recon/$IP/summary.txt

# ★ Full finding-driven command library — commands only appear when backed by evidence
cat $TOOLKIT_ROOT/recon/$IP/loot/next_steps.txt

# ★ Prioritize these — anonymous access, valid users, default creds, and no-auth findings
cat $TOOLKIT_ROOT/recon/$IP/loot/quick_wins.txt

# Web findings
cat $TOOLKIT_ROOT/recon/$IP/tcp/http/port_80/gobuster_dir.txt
cat $TOOLKIT_ROOT/recon/$IP/tcp/http/port_80/whatweb.txt
cat $TOOLKIT_ROOT/recon/$IP/tcp/http/port_80/nikto.txt
cat $TOOLKIT_ROOT/recon/$IP/tcp/http/port_80/ffuf_vhosts.json   # vhost fuzzing results

# SMB
cat $TOOLKIT_ROOT/recon/$IP/tcp/smb/smb_quick_findings.txt       # READ/WRITE shares
cat $TOOLKIT_ROOT/recon/$IP/tcp/smb/enum4linux_console.txt

# SNMP — ★ privesc goldmine
cat $TOOLKIT_ROOT/recon/$IP/udp/snmp/running_processes.txt
cat $TOOLKIT_ROOT/recon/$IP/udp/snmp/installed_software.txt
cat $TOOLKIT_ROOT/recon/$IP/udp/snmp/network_interfaces.txt

# Across ALL targets at once
cat $TOOLKIT_ROOT/recon/*/loot/next_steps.txt
cat $TOOLKIT_ROOT/recon/*/loot/quick_wins.txt
cat $TOOLKIT_ROOT/recon/*/summary.txt

# Target priority ranking (after --quick-wins-only)
cat $TOOLKIT_ROOT/recon/target_priority.txt
```

---

## What It Enumerates

| Service | Ports | Tools | Quick Win Flags |
|---------|-------|-------|-----------------|
| HTTP/HTTPS | 80, 443, 8080, 8443, 8000, 8888+ | whatweb, sslscan, wafw00f, nikto, gobuster, feroxbuster, ffuf | robots.txt, TLS names, vhosts |
| SMB | 139, 445 | nmblookup, nbtscan, enum4linux-ng, smbmap, smbclient, nxc | READ/WRITE shares |
| FTP | 21 | banner, anon login, wget mirror | Anonymous login |
| SSH | 22 | banner, nmap scripts | Old/vulnerable version + `searchsploit`, `ssh-audit`, `crackr.sh --hydra` suggestion |
| SNMP | 161/UDP | onesixtyone, snmpwalk, snmpcheck | Community strings, processes + `grep -iE pass` on `process_args.txt` |
| MySQL | 3306 | nmap scripts, mysql client | Empty/root no-password; if fails → `crackr.sh --hydra mysql` |
| PostgreSQL | 5432 | nmap scripts, psql | Default creds; if fails → `crackr.sh --hydra postgres` |
| DNS | 53 | dig, dnsrecon | Zone transfer; if successful → auto-generates `/etc/hosts` entries per hostname |
| SMTP | 25, 587, 465 | nmap scripts, VRFY | Valid usernames → saved to `loot/smtp_valid_users.txt` + `sprayr.sh`/`crackr.sh` commands |
| LDAP | 389, 636, 3268 | nmap scripts, ldapsearch | Anonymous bind |
| Redis | 6379 | nc, nmap scripts | No-auth access + full SSH-key write trick with `ssh -i` follow-on |
| RPC/NFS | 111, 2049 | rpcclient, rpcinfo, showmount | NFS exports |
| MSSQL | 1433 | nmap detection | Grounded `netexec` / `impacket-mssqlclient` follow-ups |
| RDP | 3389 | nmap detection | Grounded `netexec rdp`, `xfreerdp`, and RDP nmap follow-ups |
| Kerberos/AD | 88, 464 + SMB/LDAP | nmap detection | Kerberos user/SPN checks and AD workflow commands |

> [!tip] SNMP & FTP are high-value
> Anonymous FTP auto-mirrors the entire share. SNMP process list frequently reveals running services, credentials in command args, and pivot targets.

> [!tip] `loot/next_steps.txt` is the most important action file
> `summary.txt` prints only a short high-value preview. The full library is in `loot/next_steps.txt`, and every command is tied to a concrete finding.

---

## Finding-Driven Next Steps

`loot/next_steps.txt` is a small rule-based command library generated per host. Each rule has:

1. a finding name
2. the evidence file or nmap condition that triggered it
3. 3-6 practical commands to run next

Rules are intentionally strict:

- **No absent service, no command.**
- **Weak evidence gets verification commands.**
- **Strong evidence gets direct follow-up commands.**
- **Anonymous examples only appear after anonymous access/readable output is proven.**
- **WinRM/HTTPAPI ports (`5985`, `5986`, `47001`) are not treated as real web apps by default.**

Current host/service rules include:

| Trigger | Commands Generated |
|---------|--------------------|
| SMTP `vrfy_users.txt` contains `VALID:` | Save `loot/smtp_valid_users.txt`, `cat`, spray/brute SMB, WinRM, SMTP |
| SMB detected | Credentialed `netexec`, `smbmap`, `smbclient`, AD recon |
| SMB `smbmap_null.txt`/`smbmap_guest.txt` contains `READ`/`WRITE` | Anonymous `smbmap`, `smbclient`, CIFS mount |
| WinRM/WSMan detected | `netexec winrm`, `evil-winrm` password/hash examples |
| Real web target identified | `webenum.sh --url`, `curl -I`, `whatweb` |
| Risky HTTP method found | `curl OPTIONS`, `nmap http-methods`, TRACE check |
| POP3/IMAP detected | Capability probes and Hydra templates |
| Anonymous FTP succeeded | FTP login, recursive `wget`, mirror inspection |
| SNMP community string found | `snmpwalk` and process-argument OID checks |
| SNMP process args contain secret keywords | Focused `grep` and process review commands |
| SNMP Windows users found | Save user list and spray/brute WinRM |
| NFS export found | `showmount`, mount, file listing |
| LDAP anonymous bind returned data | `ldapsearch` and anonymous AD recon |
| Redis no-auth found | `redis-cli INFO`, `KEYS`, `CONFIG` |
| MySQL detected / no-password access | Default login or verified no-password database commands |
| PostgreSQL detected / login found | Default login or verified `psql` commands |
| DNS detected / zone transfer success | `dig`, `dnsrecon`, zone parsing, `/etc/hosts` entries |
| MSSQL detected | `netexec mssql`, `impacket-mssqlclient`, nmap MSSQL scripts |
| RDP detected | `netexec rdp`, `xfreerdp`, RDP nmap scripts |
| Kerberos or AD service combination | Kerberos enum, AS-REP/SPN checks, `adr.sh` workflow |
| Old SSH banner flagged | `ssh-audit`, `searchsploit` |
| rsync detected | Module listing and recursive pull commands |
| VNC detected | VNC nmap scripts, `vncviewer`, Hydra template |
| Docker API detected | Version/container checks and host mount escape test |
| Kubernetes API/kubelet detected | Version/pod checks with `curl`/`kubectl` |
| Squid/open proxy detected | Proxy curl checks and pivot scan reminder |
| TFTP detected | `tftp-enum` and common config pulls |
| Legacy rlogin/rexec/rsh detected | r-service probes and login attempts |

---

## Scan Phases

1. **rustscan** — full 65535 TCP port sweep (fast)
2. **nmap full-TCP fallback** — runs if rustscan is missing, fails, or finds no ports
3. **nmap TCP** — `-sV --version-intensity 7 --script default,vulners --reason [-O]` on found ports only (vulners maps banners → CVEs)
4. **nmap UDP quick** — high-signal UDP ports first (`53,69,111,123,137,161,500,623,1434`, etc.)
5. **nmap UDP top ports** — top 200 ports by default (background, runs in parallel)
6. **Service triage** — auto-launches modules based on findings (up to 5 parallel)
7. **Post-UDP SNMP check** — re-checks for UDP 161 after UDP scan completes
8. **Next-step library** — generates `loot/next_steps.txt` from concrete findings
9. **Summary** — generates `summary.txt` with a short preview from `next_steps.txt`

UDP scan runs in background and does **not** count against the `--max-parallel` slot limit.

---

## Troubleshooting

```bash
# No ports found — reduce batch size (congested network)
sudo ./recon.sh --auto --batch-size 500 10.10.10.1

# See what's still running
ps aux | grep -E 'nmap|rustscan|gobuster|nikto|enum4linux|snmpwalk|feroxbuster'

# Check phase progress for a target
cat $TOOLKIT_ROOT/recon/10.10.10.1/progress.log

# See failed phases
grep 'FAIL' $TOOLKIT_ROOT/recon/10.10.10.1/progress.log

# Ctrl+C kills all background jobs cleanly — no zombies
# Resume anytime — completed phases are skipped automatically
```

---

## Required Tools

```bash
# Critical (script exits if missing)
sudo apt install nmap

# Strongly recommended TCP discovery accelerator
sudo apt install rustscan

# Recommended — install all before an engagement
sudo apt install -y gobuster nikto whatweb smbclient smbmap \
  httpx-toolkit sslscan wafw00f dnsrecon jq davtest cadaver \
  samba-common-bin nbtscan snmp snmpcheck onesixtyone feroxbuster netexec ldap-utils \
  postgresql-client default-mysql-client rpcbind nfs-common \
  dnsutils wget curl seclists

pip install enum4linux-ng
```

> [!warning] ffuf vhost fuzzing only runs when the target is a hostname (not a bare IP), and requires `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

---

---

## What the Script Won't Find — Manual Follow-Up

> [!important] The script handles broad discovery. These are the gaps it doesn't cover. If you're stuck or the summary looks thin, work through the relevant sections below.

---

### Services With No Auto-Enum Module

The script has no module for these ports. If they show up open, enumerate manually:

**MSSQL (1433)**
```bash
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info -p 1433 IP
nxc mssql IP -u '' -p ''                          # null auth
nxc mssql IP -u sa -p ''                          # blank sa password
impacket-mssqlclient IP -port 1433 -windows-auth  # interactive
```

**Kerberos (88) — presence indicates AD**
```bash
nmap -p 88 IP                                      # open = DC
kerbrute userenum --dc IP -d DOMAIN /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
# If no domain known yet — check nmap output for DNS name / SMB domain
```

**RDP (3389)**
```bash
nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 IP
nxc rdp IP -u user -p pass                        # test creds
xfreerdp /u:user /p:pass /v:IP /cert-ignore        # connect
```

**WinRM already noted as exposed (5985/5986/47001) — test auth:**
```bash
evil-winrm -i IP -u user -p 'pass'
evil-winrm -i IP -u user -H NTHASH
nxc winrm IP -u user -p pass
```

**VNC (5900-5910)**
```bash
nmap --script vnc-info,vnc-brute -p 5900 IP
vncviewer IP::5900                                 # GUI — try blank password first
```

**Redis (6379) — script covers it but here's manual:**
```bash
redis-cli -h IP ping
redis-cli -h IP INFO server
redis-cli -h IP CONFIG GET dir                     # find write path
redis-cli -h IP KEYS '*'
```

**Elasticsearch (9200/9300)**
```bash
curl http://IP:9200/                               # version + cluster info
curl http://IP:9200/_cat/indices                   # list all indices
curl http://IP:9200/_all/_search?pretty            # dump all data
```

**MongoDB (27017)**
```bash
mongosh --host IP --port 27017 --quiet
> show dbs
> use admin; db.auth('admin','')
```

---

### SMTP — When VRFY Returns Nothing

Some servers disable VRFY and EXPN but respond to RCPT TO. If VRFY found 0 users:

```bash
# RCPT TO enumeration
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t IP -p 25

# Try both methods against both ports
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t IP -p 25
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t IP -p 587

# Manual RCPT TO test
nc -nv IP 25
EHLO test
MAIL FROM:<test@test.com>
RCPT TO:<administrator>         # 250 = valid, 550 = invalid
QUIT
```

---

### SMB — When Null/Guest Sessions Fail

The script tries null and guest sessions. If both fail:

```bash
# Confirm signing status (important for relay setup later)
nmap --script smb2-security-mode -p 445 IP
nxc smb IP                                          # shows signing: True/False

# Enumerate with any creds you have (even low-priv)
nxc smb IP -u user -p pass --shares
nxc smb IP -u user -p pass --users
nxc smb IP -u user -p pass --groups
nxc smb IP -u user -p pass --pass-pol

# rpcclient with creds
rpcclient -U 'domain/user%pass' IP
> enumdomusers
> enumdomgroups
> getdompwinfo
> queryuserinfo 0x[RID]       # replace RID from enumdomusers output

# Try guest with a made-up username (some servers accept any username)
smbclient -L //IP -U "FakeUser%"
```

---

### RPC — Deep Endpoint Mapping

The script runs `rpcclient` and `rpcinfo`. For deeper RPC analysis:

```bash
# Dump all RPC endpoints (finds services not listening on standard ports)
impacket-rpcdump IP | grep -E 'Protocol|Endpoint|UUID'

# MS-RPC named pipes (can reach even without SMB shares)
nmap --script msrpc-enum -p 135 IP

# Access via specific pipe
rpcclient -U '' -N IP -c 'lsaquery'              # LSA info without auth
rpcclient -U '' -N IP -c 'dsroledominfo'         # domain role
```

---

### IIS-Specific Manual Checks (Port 80/443 on Windows)

When nmap shows IIS and the web enum looks thin:

```bash
# HTTP TRACE enabled — useful for credential theft via XST
curl -sk -X TRACE http://IP/ -v 2>&1 | grep -i trace

# IIS ShortName (tilde) enumeration — finds hidden files/dirs
java -jar ~/tools/IIS-ShortName-Scanner.jar 2 20 http://IP/
# Or: python3 iis_shortname_scan.py http://IP/

# WebDAV probe
davtest -url http://IP                             # checks writable WebDAV
curl -sk -X OPTIONS http://IP/ -v 2>&1 | grep Allow

# ASP/ASPX check if gobuster found nothing
curl -sk http://IP/iisstart.htm                   # default IIS page = fresh install
curl -sk http://IP/default.aspx                   # common default
curl -sk http://IP/web.config                     # sometimes readable, leaks app config
curl -sk http://IP/web.config.bak                 # backup of config

# Check for IIS authentication type
curl -ski http://IP/ 2>&1 | grep -i 'WWW-Authenticate\|401\|403'
```

---

### LDAP — When Anonymous Bind Returns Nothing

The script tries an anonymous bind. If it returns 0 entries:

```bash
# Try with null credentials explicitly
ldapsearch -x -H ldap://IP -D '' -w '' -b 'DC=domain,DC=com' 2>&1 | head -20

# Try to enumerate naming contexts even without a domain
ldapsearch -x -H ldap://IP -s base -b '' namingContexts 2>/dev/null

# If you have creds
ldapsearch -x -H ldap://IP -D 'user@domain.com' -w 'pass' -b 'DC=domain,DC=com' \
  '(objectClass=*)' sAMAccountName mail description memberOf 2>/dev/null | head -50

# Check for LDAP signing requirements
nmap --script ldap-rootdse -p 389 IP
```

---

### DNS — Manual Zone Transfer and Brute Force

The script attempts zone transfer if it finds a domain name. If it didn't find one:

```bash
# Try zone transfer against common domain guesses from the box name
dig @IP AXFR domain.local
dig @IP AXFR $(hostname -f 2>/dev/null)

# Brute-force subdomains if you have a domain name
gobuster dns -d domain.local -r IP:53 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Reverse lookup — find the hostname from the IP
dig -x IP @IP

# Check for any DNS records (A, MX, NS, TXT)
dig @IP any domain.local
dig @IP TXT domain.local                          # sometimes contains passwords or hints
```

---

### UDP — When Top-200 Scan Returns Nothing

The script scans top 200 UDP ports. If you get nothing:

```bash
# Targeted UDP checks for the most common OffSec services
sudo nmap -sU -p 161,162,500,514,623,1433,1434 --open IP

# Full UDP (use --udp-full flag in the script, or manually)
sudo nmap -sU -p- --min-rate 500 --open IP -oN udp_full.nmap

# SNMP check with expanded community strings
for c in public private manager community admin cisco monitor snmp read write; do
  echo -n "$c: "
  snmpget -v2c -c "$c" -t 1 IP sysDescr.0 2>/dev/null || echo "no response"
done

# TFTP check
echo "q" | tftp IP                                # connects if TFTP is open
```

---

### NetBIOS / Windows Name Service

Not covered by the script:

```bash
nmblookup -A IP                                   # get NetBIOS name, workgroup, MAC
nbtscan IP                                        # NetBIOS scan
nmap --script nbstat -p 137 IP                    # NetBIOS stat

# If you see the domain name here but AD ports look closed:
# this host may be a workgroup member, not domain-joined
```

---

### When the Entire Scan Comes Back Empty

If rustscan and nmap both find nothing:

```bash
# 1. Confirm the host is actually up (ICMP may be blocked)
sudo nmap -Pn -n -p 22,80,443,445,3389 IP         # probe without ping

# 2. Try with -Pn (no host discovery) in case ICMP is firewalled
sudo nmap -Pn --open -p- --min-rate 1000 IP

# 3. Run recon with smaller batch size (network congestion drops packets)
sudo ./recon.sh --batch-size 200 --auto IP

# 4. Check if the target responds to TCP at all
nc -zvw 3 IP 80
nc -zvw 3 IP 443
nc -zvw 3 IP 22

# 5. Try IPv6 if the environment supports it
sudo nmap -6 -Pn --open --top-ports 100 IP6_ADDR
ip -6 neigh                                        # find IPv6 neighbors on the local segment
```

---

## Related

- [[Engagement_Methodology]] — where recon fits in the overall attack chain (Phase 2)
- [[Toolkit_Strategy]] — engagement run order: recon → `orient` → decision tools
- [[Active_Recon]] — manual recon to supplement or fill gaps
- [[Web_App]] — manual follow-up on HTTP findings
- [[webenum]] — deeper web enumeration (webenum.sh)
- [[Passwords]] — crack anything surfaced in quick_wins
- [[Active_Directory]] — AD-specific enumeration after initial access
