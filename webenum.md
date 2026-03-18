---
tags:
  - phase/enumeration
  - phase/web
  - tool/webenum
  - tool/ffuf
  - tool/whatweb
  - type/tool-docs
---

# webenum.sh

## What It Is
Deep web enumeration wrapper designed to run **after** `recon.sh`. Where recon does a quick HTTP pass (gobuster with dirbuster-medium, nikto, whatweb), webenum goes deeper: larger wordlists, recursive fuzzing, vhost fuzzing, parameter discovery, and a structured summary report.

> [!important] Enumeration only — no exploitation
> OffSec compliant. Resume-safe — re-running skips completed phases.

---

## When to Use

```
recon.sh  →  found HTTP/HTTPS ports
webenum.sh     →  go deeper on each one
```

Run webenum on every HTTP/HTTPS endpoint recon surfaces. If you hit a wall, re-run with `--deep`.

---

## Usage

```bash
# Standard run — covers 80% of cases
./webenum.sh --url http://10.10.10.5

# Pull URL directly from recon.sh output (auto-detects HTTP ports)
./webenum.sh --from-recon 10.10.10.5

# Non-standard port / HTTPS
./webenum.sh --url http://10.10.10.5:8080
./webenum.sh --url https://10.10.10.5:8443

# With vhost fuzzing (requires knowing the domain name)
./webenum.sh --url http://10.10.10.5 --vhost target.htb

# Deep mode — adds recursive fuzzing, parameter discovery, raft-large wordlist
./webenum.sh --url http://10.10.10.5 --deep

# Full — deep + vhost (use when stuck)
./webenum.sh --url http://10.10.10.5 --deep --vhost target.htb

# Custom output root
./webenum.sh --url http://10.10.10.5 --root ~/pg

# Throttle on unstable targets
./webenum.sh --url http://10.10.10.5 --threads 20 --rate 50
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--url URL` | required* | Target URL including scheme |
| `--from-recon IP` | — | Auto-detect HTTP URLs from `$TOOLKIT_ROOT/recon/<IP>/` |
| `--deep` | off | Recursive fuzzing + parameter discovery + raft-large |
| `--vhost DOMAIN` | off | Vhost fuzzing against base domain (e.g. `target.htb`) |
| `--root DIR` | `$TOOLKIT_ROOT/web` | Output root directory |
| `--threads N` | 40 | ffuf thread count |
| `--rate N` | 0 (unlimited) | Max ffuf requests/sec — throttle for unstable targets |

*`--url` or `--from-recon` required.

> [!note] No scheme in URL? Script assumes `http://` and warns you.

---

## Output Structure

```
$TOOLKIT_ROOT/web/<host>_<port>_<proto>/artifacts/web/
├── fingerprint/
│   ├── whatweb.txt              # WhatWeb aggressive scan
│   ├── whatweb_verbose.txt      # WhatWeb verbose plugin output
│   ├── headers.txt              # Full HTTP headers (follows redirects)
│   ├── homepage_source.html     # First 500 lines of homepage
│   ├── source_hints.txt         # HTML comments, relative paths, emails, version strings
│   ├── robots.txt               # robots.txt (or note if absent)
│   ├── sitemap.xml              # sitemap.xml (or note if absent)
│   ├── security_txt.txt         # /.well-known/security.txt
│   └── sensitive_paths.txt      # Probe results for common sensitive paths
├── content/
│   ├── dirs_medium.json/.txt    # raft-medium directory fuzzing
│   ├── files_medium.json/.txt   # raft-medium file fuzzing (with extensions)
│   ├── dirs_large.json/.txt     # raft-large directories (--deep only)
│   └── recursive/               # Per-directory recursive fuzzing (--deep only)
├── vhosts/
│   ├── vhosts.json/.txt         # Vhost fuzzing results
│   └── hosts_entries.txt        # Ready-to-paste /etc/hosts entries
├── params/                      # GET parameter discovery per endpoint (--deep only)
├── summary/
│   ├── summary.md               # ★ Read this first — structured findings report
│   └── quick_wins.txt           # High-value lines only (sensitive paths, 200s, auth, vhosts)
└── progress.log                 # Phase tracking (START/DONE/FAIL/SKIP)
```

---

## Key Output Files (Check in This Order)

```bash
# Always start here
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/summary/summary.md
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/summary/quick_wins.txt

# Sensitive path probes (200/301/302/401/403)
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/fingerprint/sensitive_paths.txt

# Directory/file hits
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/content/dirs_medium.txt
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/content/files_medium.txt

# Vhosts (add to /etc/hosts)
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/vhosts/hosts_entries.txt

# Source code clues
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/fingerprint/source_hints.txt
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/fingerprint/robots.txt

# Technology stack
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/fingerprint/whatweb.txt
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/fingerprint/headers.txt
```

---

## Phases

| Phase | Name | Mode | What It Does |
|-------|------|------|-------------|
| 1 | Fingerprinting | Standard | whatweb (aggressive + verbose), full headers, homepage source, source hints (comments/paths/emails/versions), robots.txt, sitemap.xml, security.txt, sensitive path probes |
| 2 | Content fuzzing | Standard | ffuf dir fuzzing (raft-medium), ffuf file fuzzing with tech-matched extensions, raft-large dirs (deep only) |
| 3 | Recursive fuzzing | Deep only | ffuf on every 200/301/302 directory from phase 2, capped at 20 dirs |
| 4 | Vhost fuzzing | `--vhost` only | Baseline-filtered ffuf, outputs ready-to-paste /etc/hosts entries |
| 5 | Parameter discovery | Deep only | GET param fuzzing on 200 OK endpoints (scripts/pages only), baseline-filtered |
| 6 | Summary | Always | summary.md + quick_wins.txt |

---

## Tech-Stack Extension Selection

Script auto-detects from whatweb output and picks extensions accordingly:

| Detected Stack | Extensions Used |
|----------------|----------------|
| Windows / IIS / ASP.NET | `asp, aspx, ashx, asmx, config, txt, bak` |
| Java / Tomcat / Spring / Jenkins | `jsp, jspx, do, action, xml, properties, war` |
| PHP / WordPress / Joomla | `php, html, txt, bak, old, conf, xml, json, sql, log, zip` |
| Generic / unknown | `php, html, txt, js, json, xml, conf, bak, old, zip, tar, gz, sql, log, env` |

---

## Sensitive Paths Probed (Phase 1)

These are hit directly before any fuzzing — fast wins:

```
/.git/HEAD  /.git/config  /.env  /.htaccess  /.htpasswd
/web.config  /config.php  /configuration.php  /wp-config.php
/phpinfo.php  /.DS_Store  /backup.zip  /backup.tar.gz
/admin  /administrator  /login  /wp-admin  /manager
/phpmyadmin  /adminer  /console  /api  /api/v1
/swagger.json  /swagger-ui  /openapi.json
/_profiler  /debug  /.well-known
```

> [!tip] 401/403 on `/admin` or `/console` is still a finding — flag it for auth bypass attempts.

---

## Vhost Workflow

```bash
# 1. Run with --vhost
./webenum.sh --url http://10.10.10.5 --vhost target.htb

# 2. Check discovered vhosts
cat $TOOLKIT_ROOT/web/.../vhosts/hosts_entries.txt
# Output: 10.10.10.5  dev.target.htb

# 3. Add to /etc/hosts
echo "10.10.10.5  dev.target.htb" >> /etc/hosts

# 4. Re-run webenum on each discovered vhost
./webenum.sh --url http://dev.target.htb --vhost target.htb
```

Baseline filtering: script requests a random nonexistent vhost first, measures response size, then filters that size out of results. Avoids false positives from catch-all responses.

---

## ffuf Design Decisions

**`-ac` (autocalibration) is intentionally disabled.** It silently drops valid results on some targets by over-filtering. The script uses explicit `-mc 200,201,204,301,302,307,401,403,405` instead.

**`-v` (verbose) is intentionally disabled.** It floods output and breaks grep pipelines.

**JSON output + Python parser.** All ffuf runs save `.json` alongside `.txt`. The Python converter produces a clean sortable table (status / size / words / lines). Recursive and parameter phases read the JSON directly for reliable URL extraction.

---

## Resume / Re-run

```bash
# Safe re-run — skips completed phases
./webenum.sh --url http://10.10.10.5

# Force full re-run
rm $TOOLKIT_ROOT/web/<target>/artifacts/web/progress.log
./webenum.sh --url http://10.10.10.5
```

---

## Troubleshooting

```bash
# Target not responding
curl -sk http://10.10.10.5        # sanity check — does curl see anything?
curl -skIL http://10.10.10.5      # check redirect chain

# Getting no results from ffuf — check baseline
# Possible soft 404: everything returns 200 with same size
# → ffuf's -ac would help here, but may also over-filter
# → Manually check: curl -sk http://IP/nonexistentXXX | wc -c

# Rate-limiting / connection resets
./webenum.sh --url http://10.10.10.5 --threads 10 --rate 30

# Stuck — go deeper
./webenum.sh --url http://10.10.10.5 --deep

# Check what ran
cat $TOOLKIT_ROOT/web/<target>/artifacts/web/progress.log
grep 'FAIL' webenum/<target>/artifacts/web/progress.log
```

---

## Required Tools

```bash
# Required (script exits if missing)
sudo apt install ffuf curl python3

# Strongly recommended
sudo apt install whatweb seclists
```

**Wordlists used:**

| Wordlist | Used For |
|----------|----------|
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` | Directory fuzzing (primary) |
| `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt` | File fuzzing |
| `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` | Deep dir fuzzing (`--deep`) |
| `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Dir fuzzing fallback |
| `/usr/share/wordlists/dirb/common.txt` | Fast fallback |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | Vhost fuzzing |
| `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` | Parameter discovery (`--deep`) |

> [!warning] If raft-medium is missing, script falls back to dirbuster-medium then dirb/common.txt. Install seclists for best results: `sudo apt install seclists`

---

## Related

- [[recon]] — run first; webenum goes deeper on what recon finds
- [[Web_App]] — manual web exploitation techniques
- [[Burp_Suite]] — manual testing of findings from webenum
- [[SQL_Injection]] — parameter discovery findings → test for SQLi
- [[Active_Recon]] — if vhosts found, DNS enumeration to find more
