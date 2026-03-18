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
cat $TOOLKIT_ROOT/web/192.168.50.100/artifacts/web/summary/summary.md
cat $TOOLKIT_ROOT/web/192.168.50.100/artifacts/web/summary/quick_wins.txt
```

`summary.md` is structured: tech stack → headers → sensitive paths → directory findings → vhosts → source hints. `quick_wins.txt` gives you just the high-value lines grouped by category.

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

---

## Output Structure

```
$TOOLKIT_ROOT/web/<host>/artifacts/web/
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

### WordPress Detected
```bash
# webenum Phase 1 whatweb shows WordPress
# Follow up with:
wpscan --url http://TARGET --enumerate ap,at,u --plugins-detection aggressive
```

### Login Page Found
```bash
# Check for default creds, then look for:
# - SQL injection in login form
# - Password reset functionality
# - User enumeration via error messages
# - Timing-based user enumeration
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
rm $TOOLKIT_ROOT/web/TARGET/artifacts/web/progress.log
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

## Related

- [[recon_usage]] — run this first to find HTTP services
- [[Web_App]] — web attack vectors after enumeration
- [[SQL_Injection]] — if webenum finds login/search forms
- [[Burp_Suite]] — manual testing after webenum finds endpoints
- [[OffSec_Methodology]] — where web enum fits in the attack chain
- [[Reverse_Shells]] — use Penelope with -O flag after exploitation
