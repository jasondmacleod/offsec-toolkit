---
tags:
  - phase/recon
  - phase/enumeration
  - tool/offsec-recon
  - tool/nmap
  - tool/rustscan
  - type/tool-docs
---

# recon.sh

## What It Is
Automated enumeration orchestrator for OffSec. Runs rustscan → nmap TCP → nmap UDP → targeted service enumeration in parallel. Generates `summary.txt` (with a **NEXT-STEP COMMANDS** section containing ready-to-run follow-on commands per service) and `loot/quick_wins.txt` (anonymous access, default creds, zone transfers, and copy-paste exploit commands) per target.

> [!important] Enumeration only — no exploitation
> OffSec compliant. Finds the doors, you walk through them.

---

## engagement Day Workflow

```bash
# 0. Triage first — rank targets by quick-win score before deep scanning
sudo ./recon.sh --auto --quick-wins-only 10.10.10.1 10.10.10.2 10.10.10.3
cat $TOOLKIT_ROOT/recon/target_priority.txt   # attack highest-score target first

# 1. Fire deep recon on all targets simultaneously
sudo ./recon.sh --auto 10.10.10.1 10.10.10.2 10.10.10.3

# 2. Read engagement instructions while it runs, then check summaries
# summary.txt includes a NEXT-STEP COMMANDS section — copy-paste follow-ons per service
# quick_wins.txt has anonymous access, default creds, zone transfers + ready-to-run commands
cat $TOOLKIT_ROOT/recon/*/summary.txt
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
| `--batch-size N` | 1500 | Rustscan batch size (concurrent sockets) |
| `--udp-ports N` | 200 | Top N UDP ports to scan |
| `--udp-full` | off | Also scan all 65535 UDP ports |
| `--outdir DIR` | `$TOOLKIT_ROOT/recon` | Output directory |
| `--quick-wins` | off | Run 5-min triage per target before deep recon |
| `--quick-wins-only` | off | Triage only — rank targets, skip deep scan |
| `--max-parallel N` | 5 | Max concurrent service enumerations per target |
| `-f FILE` | — | Read targets from file |
| `--rate N` | 1500 | Deprecated alias for `--batch-size` |

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
    │   ├── tcp_ports.txt          # Comma-separated open TCP ports
    │   ├── nmap_tcp.*             # nmap TCP scan (all formats)
    │   ├── nmap_udp.*             # nmap UDP scan
    │   └── udp_ports.txt          # Open UDP ports
    ├── tcp/
    │   ├── http/port_<N>/         # Per-port: whatweb, nikto, gobuster, ffuf
    │   ├── smb/                   # enum4linux-ng, smbmap, smbclient, nxc
    │   ├── ftp/                   # Anon login check + file mirror
    │   ├── ssh/                   # Banner, auth methods, version flags
    │   ├── mysql/                 # Empty/root no-pass check
    │   ├── postgres/              # Default creds
    │   ├── dns/                   # Zone transfer attempt
    │   ├── smtp/                  # VRFY user enum
    │   ├── ldap/                  # Anonymous bind, directory dump
    │   ├── rpc/                   # Null sessions, NFS exports
    │   └── redis/                 # No-auth access check
    ├── udp/
    │   └── snmp/                  # onesixtyone, snmpwalk (processes, software, ARP)
    ├── loot/
    │   └── quick_wins.txt         # ★ Anon access, default creds, zone xfers, etc.
    ├── progress.log               # Phase tracking (START/DONE/FAIL/SKIP)
    └── summary.txt                # Human-readable findings report
```

---

## Key Output Files (Check in This Order)

```bash
IP=10.10.10.1

# Big picture — always read first; scroll to NEXT-STEP COMMANDS section for ready-to-run follow-ons
cat $TOOLKIT_ROOT/recon/$IP/summary.txt

# ★ Prioritize these — anonymous access, default creds, and copy-paste exploit commands
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
cat $TOOLKIT_ROOT/recon/*/loot/quick_wins.txt
cat $TOOLKIT_ROOT/recon/*/summary.txt

# Target priority ranking (after --quick-wins-only)
cat $TOOLKIT_ROOT/recon/target_priority.txt
```

---

## What It Enumerates

| Service | Ports | Tools | Quick Win Flags |
|---------|-------|-------|-----------------|
| HTTP/HTTPS | 80, 443, 8080, 8443, 8000, 8888+ | whatweb, nikto, gobuster, feroxbuster, ffuf | robots.txt, vhosts |
| SMB | 139, 445 | enum4linux-ng, smbmap, smbclient, nxc | READ/WRITE shares |
| FTP | 21 | banner, anon login, wget mirror | Anonymous login |
| SSH | 22 | banner, nmap scripts | Old/vulnerable version + `searchsploit`, `ssh-audit`, `crackr.sh --hydra` suggestion |
| SNMP | 161/UDP | onesixtyone, snmpwalk | Community strings, processes + `grep -iE pass` on `process_args.txt` |
| MySQL | 3306 | nmap scripts, mysql client | Empty/root no-password; if fails → `crackr.sh --hydra mysql` |
| PostgreSQL | 5432 | nmap scripts, psql | Default creds; if fails → `crackr.sh --hydra postgres` |
| DNS | 53 | dig | Zone transfer; if successful → auto-generates `/etc/hosts` entries per hostname |
| SMTP | 25, 587, 465 | nmap scripts, VRFY | Valid usernames → saved to `loot/smtp_valid_users.txt` + `sprayr.sh`/`crackr.sh` commands |
| LDAP | 389, 636, 3268 | nmap scripts, ldapsearch | Anonymous bind |
| Redis | 6379 | nc, nmap scripts | No-auth access + full SSH-key write trick with `ssh -i` follow-on |
| RPC/NFS | 111, 2049 | rpcclient, rpcinfo, showmount | NFS exports |

> [!tip] SNMP & FTP are high-value
> Anonymous FTP auto-mirrors the entire share. SNMP process list frequently reveals running services, credentials in command args, and pivot targets.

> [!tip] NEXT-STEP COMMANDS section is the most important output
> Every service with a finding generates resolved copy-paste commands in `summary.txt`. VHosts get `/etc/hosts` + `webenum` commands. DNS zone transfers extract hostnames. SMTP valid users go to `loot/smtp_valid_users.txt` ready for spray. Redis no-auth includes the full SSH-key write attack + `ssh -i` follow-on. WinRM includes `crackr --hydra winrm` fallback when no creds are available.

---

## Scan Phases

1. **rustscan** — full 65535 TCP port sweep (fast)
2. **nmap TCP** — `-sC -sV [-O]` on found ports only
3. **nmap UDP** — top 200 ports (background, runs in parallel)
4. **Service triage** — auto-launches modules based on findings (up to 5 parallel)
5. **Post-UDP SNMP check** — re-checks for UDP 161 after UDP scan completes
6. **Summary** — generates `summary.txt`

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
sudo apt install rustscan nmap

# Recommended — install all before engagement
sudo apt install -y gobuster nikto whatweb smbclient smbmap \
  snmp onesixtyone feroxbuster netexec ldap-utils \
  postgresql-client default-mysql-client rpcbind nfs-common \
  dnsutils wget curl seclists

pip install enum4linux-ng
```

> [!warning] ffuf vhost fuzzing only runs when the target is a hostname (not a bare IP), and requires `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

---

## Related

- [[OffSec_Exam_Methodology_Complete]] — where recon fits in the overall attack chain
- [[Active_Recon]] — manual recon to supplement or fill gaps
- [[Web_App]] — manual follow-up on HTTP findings
- [[webenum]] — deeper web enumeration (webenum.sh)
- [[Passwords]] — crack anything surfaced in quick_wins
- [[Active_Directory]] — AD-specific enumeration after initial access
