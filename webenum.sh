#!/usr/bin/env bash
#==============================================================================
# WEBENUM — Deep Web Enumeration Wrapper
#==============================================================================
# Designed to run AFTER recon.sh, which performs a quick HTTP pass
# (whatweb, curl, robots.txt, nikto, gobuster with dirbuster-medium).
#
# This script goes deeper:
#   Phase 1 — Technology fingerprinting (whatweb aggressive, headers, cookies)
#   Phase 2 — Directory/file fuzzing with larger wordlists + extension targeting
#   Phase 3 — Recursive fuzzing on interesting paths
#   Phase 4 — Virtual host / subdomain fuzzing
#   Phase 5 — Parameter discovery on found endpoints
#   Phase 6 — Content analysis + summary generation
#
# DESIGN:
#   - Mirrors recon.sh conventions (colors, logging, progress, cleanup)
#   - Single file — nothing to lose on engagement day
#   - Enumeration only — no exploitation, OffSec compliant
#   - Timeouts on everything — nothing hangs the engagement
#   - Graceful degradation — skips tools that aren't installed
#   - Resume support — re-run safely; skips completed phases
#
# USAGE:
#   ./webenum.sh --url http://10.10.10.5           # single URL
#   ./webenum.sh --url http://10.10.10.5:8080      # non-standard port
#   ./webenum.sh --url https://10.10.10.5          # HTTPS
#   ./webenum.sh --url http://10.10.10.5 --deep    # full recursive + param fuzzing
#   ./webenum.sh --url http://10.10.10.5 --vhost target.htb  # vhost fuzzing
#   ./webenum.sh --url http://10.10.10.5 --root ~/pg         # custom output root
#
# OUTPUT:
#   <root>/<host>/artifacts/web/
#     fingerprint/          whatweb, headers, cookies, source hints
#     content/              directory + file fuzzing results
#     content/recursive/    recursive ffuf on interesting paths (--deep)
#     vhosts/               vhost fuzzing results
#     params/               parameter discovery (--deep)
#     summary/
#       summary.md          READ THIS FIRST — structured findings
#       quick_wins.txt      high-value lines: 200s, auth prompts, interesting paths
#==============================================================================

set -o pipefail
# NOT set -e — handle errors individually; one failure must not kill the run

#==============================================================================
# CONFIGURATION
#==============================================================================
TOOLKIT_ROOT="${TOOLKIT_ROOT:-${HOME}/offsec}"
OUTPUT_ROOT="${TOOLKIT_ROOT}/web"
THREADS=40
FFUF_TIMEOUT=30                      # per-request timeout (seconds)
FFUF_RATE=0                          # 0 = no rate limit; set to e.g. 100 to throttle
WHATWEB_TIMEOUT=60
CURL_TIMEOUT=15
PHASE_FINGERPRINT_TIMEOUT=120
PHASE_CONTENT_TIMEOUT=900            # 15 min — large wordlists take time
PHASE_RECURSIVE_TIMEOUT=600
PHASE_VHOST_TIMEOUT=600
PHASE_PARAM_TIMEOUT=300

DEEP_MODE=false
VHOST_DOMAIN=""                      # e.g. "target.htb" — enables vhost fuzzing

# Wordlists — ordered fast→slow within each phase
WL_DIR_FAST="/usr/share/wordlists/dirb/common.txt"
WL_DIR_MEDIUM="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
WL_DIR_LARGE="/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
WL_DIR_DIRBUSTER="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

WL_FILES_MEDIUM="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"

WL_VHOSTS="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
WL_PARAMS="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

# Extensions targeted per tech stack — auto-detected where possible
EXT_WINDOWS="asp,aspx,ashx,asmx,config,txt,bak"
EXT_JAVA="jsp,jspx,do,action,xml,properties,war"
EXT_GENERIC="php,html,txt,js,json,xml,conf,bak,old,zip,tar,gz,sql,log,env"

#==============================================================================
# COLORS & LOGGING
#==============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

disable_colors() { RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''; }
[[ "${NO_COLOR:-0}" == "1" ]] || [[ ! -t 1 ]] && disable_colors

ts()      { date '+%H:%M:%S'; }
info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}";
            echo -e "${BOLD}${CYAN}  $*${NC}";
            echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; }
phase()   { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }

#==============================================================================
# PROGRESS TRACKING (mirrors recon.sh)
#==============================================================================
progress_log() {
    local logfile="$1/progress.log"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $2 | $3 | $4" >> "$logfile"
}

is_phase_done() {
    grep -q "| DONE | $2 |" "$1/progress.log" 2>/dev/null
}

#==============================================================================
# CHILD PROCESS MANAGEMENT
#==============================================================================
declare -a CHILD_PIDS=()

register_pid() { CHILD_PIDS+=("$1"); }

wait_all() {
    if (( ${#CHILD_PIDS[@]} > 0 )); then
        info "Waiting for ${#CHILD_PIDS[@]} background job(s)..."
        for pid in "${CHILD_PIDS[@]}"; do
            wait "$pid" 2>/dev/null
        done
    fi
    CHILD_PIDS=()
}

cleanup() {
    echo ""
    warn "Caught interrupt — cleaning up..."
    for pid in "${CHILD_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "${CHILD_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null
    done
    warn "Cleanup complete. Partial results saved in ${OUTPUT_DIR}/"
    exit 130
}
trap cleanup INT TERM

#==============================================================================
# TOOL CHECK
#==============================================================================
check_tool() {
    command -v "$1" &>/dev/null
}

require_tool() {
    if ! check_tool "$1"; then
        error "Required tool missing: $1"
        return 1
    fi
    return 0
}

check_wordlist() {
    # Returns the first wordlist in the list that actually exists
    # Usage: wl=$(check_wordlist "$WL_DIR_MEDIUM" "$WL_DIR_FAST")
    for wl in "$@"; do
        if [[ -f "$wl" ]]; then
            echo "$wl"
            return 0
        fi
    done
    warn "No wordlist found from candidates: $*"
    return 1
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

is_nonnegative_integer() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

#==============================================================================
# URL PARSING HELPERS
#==============================================================================
get_proto() {
    # Extract http or https from URL
    echo "$1" | grep -oP '^https?'
}

get_host() {
    # Extract host (no port, no path) from URL
    echo "$1" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1
}

get_port() {
    local url="$1"
    local proto=""
    proto=$(get_proto "$url")
    # Check for explicit port
    if echo "$url" | grep -qP ':\d+'; then
        echo "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f2
    else
        [[ "$proto" == "https" ]] && echo "443" || echo "80"
    fi
}

get_base_url() {
    # Strip trailing path — return proto://host:port
    local url="$1"
    echo "$url" | grep -oP '^https?://[^/]+'
}

detect_tech() {
    # Returns rough tech stack hint from whatweb output for extension selection
    local whatweb_file="$1"
    if [[ ! -f "$whatweb_file" ]]; then echo "generic"; return; fi
    if grep -qi "ASP.NET\|IIS\|Windows" "$whatweb_file"; then
        echo "windows"
    elif grep -qi "Tomcat\|Struts\|Spring\|JBoss\|Jenkins\|Java" "$whatweb_file"; then
        echo "java"
    elif grep -qi "PHP\|WordPress\|Joomla\|Drupal" "$whatweb_file"; then
        echo "php"
    else
        echo "generic"
    fi
}

get_extensions() {
    local tech="$1"
    case "$tech" in
        windows) echo "$EXT_WINDOWS" ;;
        java)    echo "$EXT_JAVA" ;;
        php)     echo "php,html,txt,bak,old,conf,xml,json,sql,log,zip" ;;
        *)       echo "$EXT_GENERIC" ;;
    esac
}

#==============================================================================
# PHASE 1 — FINGERPRINTING
#==============================================================================
phase_fingerprint() {
    local url="$1"
    local outdir="$2/fingerprint"
    mkdir -p "$outdir"

    local phase_name="fingerprint"
    if is_phase_done "$2" "$phase_name"; then
        info "Fingerprinting already done — skipping"
        return 0
    fi
    progress_log "$2" "START" "$phase_name" "url=$url"
    phase "Phase 1 — Fingerprinting: $url"

    # --- WhatWeb aggressive ---
    if check_tool whatweb; then
        info "  → whatweb (aggressive) $url"
        timeout "$WHATWEB_TIMEOUT" whatweb -a 3 --color never "$url" \
            > "$outdir/whatweb.txt" 2>&1 || true
        # Also run in verbose mode for plugin detail
        timeout "$WHATWEB_TIMEOUT" whatweb -a 3 -v --color never "$url" \
            > "$outdir/whatweb_verbose.txt" 2>&1 || true
    fi

    # --- Full HTTP headers (follow redirects) ---
    info "  → curl headers (follow redirects)"
    timeout "$CURL_TIMEOUT" curl -skIL \
        --max-redirs 5 \
        -A "Mozilla/5.0 (X11; Linux x86_64)" \
        "$url" > "$outdir/headers.txt" 2>&1 || true

    # --- Homepage source (first 500 lines) ---
    info "  → fetching homepage source"
    timeout "$CURL_TIMEOUT" curl -sk \
        -A "Mozilla/5.0 (X11; Linux x86_64)" \
        "$url" 2>/dev/null | head -500 > "$outdir/homepage_source.html" || true

    # --- Extract comments and hints from source ---
    info "  → extracting source hints (comments, paths, emails)"
    {
        echo "=== HTML Comments ==="
        grep -oP '<!--.*?-->' "$outdir/homepage_source.html" 2>/dev/null | head -20

        echo ""
        echo "=== Relative Paths Found ==="
        grep -oP '(?:href|src|action)=["\x27][^"'\''#>]{3,}' \
            "$outdir/homepage_source.html" 2>/dev/null | \
            grep -v 'http' | sort -u | head -30

        echo ""
        echo "=== Emails Found ==="
        grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
            "$outdir/homepage_source.html" 2>/dev/null | sort -u

        echo ""
        echo "=== Version Strings ==="
        grep -oiP 'version["\s:=]+[\d.]+' "$outdir/homepage_source.html" 2>/dev/null | \
            sort -u | head -20
    } > "$outdir/source_hints.txt" 2>/dev/null

    # --- robots.txt ---
    info "  → robots.txt"
    timeout "$CURL_TIMEOUT" curl -sk "${url%/}/robots.txt" > "$outdir/robots.txt" 2>&1 || true
    if grep -qiE '<!DOCTYPE|<html|404|not found' "$outdir/robots.txt" 2>/dev/null; then
        echo "# No robots.txt (received HTML/404)" > "$outdir/robots.txt"
    fi

    # --- sitemap.xml ---
    info "  → sitemap.xml"
    timeout "$CURL_TIMEOUT" curl -sk "${url%/}/sitemap.xml" > "$outdir/sitemap.xml" 2>&1 || true
    if grep -qiE '<!DOCTYPE|<html|404|not found' "$outdir/sitemap.xml" 2>/dev/null; then
        echo "# No sitemap.xml" > "$outdir/sitemap.xml"
    fi

    # --- security.txt ---
    info "  → security.txt"
    timeout "$CURL_TIMEOUT" curl -sk "${url%/}/.well-known/security.txt" \
        > "$outdir/security_txt.txt" 2>&1 || true

    # --- Check for common sensitive paths directly ---
    info "  → probing common sensitive paths"
    # shellcheck disable=SC2016  # $1 is expanded by the inner bash -c
    timeout "$PHASE_FINGERPRINT_TIMEOUT" bash -c '
        url="$1"
        echo "# Sensitive path probes — 200/301/302/401/403 = potentially interesting"
        echo ""
        for path in \
            "/.git/HEAD" "/.git/config" "/.env" "/.htaccess" "/.htpasswd" \
            "/web.config" "/config.php" "/configuration.php" "/wp-config.php" \
            "/phpinfo.php" "/.DS_Store" "/backup.zip" "/backup.tar.gz" \
            "/admin" "/administrator" "/login" "/wp-admin" "/manager" \
            "/phpmyadmin" "/adminer" "/console" "/api" "/api/v1" \
            "/swagger.json" "/swagger-ui" "/openapi.json" \
            "/_profiler" "/debug" "/.well-known"; do
            resp=$(timeout 5 curl -sk -o /dev/null -w "%{http_code}" \
                -A "Mozilla/5.0" "${url%/}${path}" 2>/dev/null || echo "ERR")
            if echo "$resp" | grep -qE "^(200|301|302|401|403)$"; then
                echo "  [${resp}] ${url%/}${path}"
            fi
        done
    ' -- "$url" > "$outdir/sensitive_paths.txt" 2>&1 || warn "Sensitive path probing timed out"

    progress_log "$2" "DONE" "$phase_name" ""
    success "Fingerprinting complete"
}

#==============================================================================
# PHASE 2 — DIRECTORY & FILE FUZZING
#==============================================================================
phase_content() {
    local url="$1"
    local outdir="$2/content"
    mkdir -p "$outdir"

    local phase_name="content"
    if is_phase_done "$2" "$phase_name"; then
        info "Content fuzzing already done — skipping"
        return 0
    fi
    progress_log "$2" "START" "$phase_name" "url=$url"
    phase "Phase 2 — Directory & File Fuzzing: $url"

    if ! check_tool ffuf; then
        warn "ffuf not found — skipping content fuzzing (install: sudo apt install ffuf)"
        progress_log "$2" "FAIL" "$phase_name" "ffuf not found"
        return 1
    fi

    # Detect tech stack for extension selection
    local tech=""
    tech=$(detect_tech "$2/fingerprint/whatweb.txt")
    local extensions=""
    extensions=$(get_extensions "$tech")
    info "  Detected tech hint: $tech → extensions: $extensions"

    # Determine SSL flag
    local proto=""
    proto=$(get_proto "$url")
    local -a ssl_flag=()
    [[ "$proto" == "https" ]] && ssl_flag=(-k)

    # Build base ffuf flags
    # NOTE: -ac (autocalibration) intentionally omitted — it silently drops valid
    # results on some targets by over-filtering. Use explicit -mc instead.
    # NOTE: -v (verbose) intentionally omitted — floods output and breaks grep pipe.
    # shellcheck disable=SC2054  # commas in -mc value are ffuf syntax, not array separators
    local base_flags=(-t "$THREADS" -timeout "$FFUF_TIMEOUT" \
        -mc 200,201,204,301,302,307,401,403,405 \
        -c -noninteractive "${ssl_flag[@]}")
    [[ "$FFUF_RATE" -gt 0 ]] && base_flags+=(-rate "$FFUF_RATE")

    local phase_ok=true

    # --- 2a: Directory fuzzing with raft-medium ---
    local wl_dir=""
    wl_dir=$(check_wordlist "$WL_DIR_MEDIUM" "$WL_DIR_DIRBUSTER" "$WL_DIR_FAST") || true
    if [[ -n "$wl_dir" ]]; then
        info "  → ffuf directory fuzzing (wordlist: $(basename "$wl_dir"))"
        timeout "$PHASE_CONTENT_TIMEOUT" ffuf \
            "${base_flags[@]}" \
            -w "${wl_dir}:FUZZ" \
            -u "${url%/}/FUZZ" \
            -o "$outdir/dirs_medium.json" -of json \
            > "$outdir/dirs_medium_console.txt" 2>&1 || phase_ok=false

        # Also save human-readable version
        ffuf_json_to_text "$outdir/dirs_medium.json" > "$outdir/dirs_medium.txt" 2>/dev/null || true
    fi

    # --- 2b: File fuzzing with extensions ---
    local wl_files=""
    wl_files=$(check_wordlist "$WL_FILES_MEDIUM" "$WL_DIR_MEDIUM" "$WL_DIR_FAST") || true
    if [[ -n "$wl_files" ]]; then
        info "  → ffuf file fuzzing (extensions: $extensions)"
        timeout "$PHASE_CONTENT_TIMEOUT" ffuf \
            "${base_flags[@]}" \
            -w "${wl_files}:FUZZ" \
            -u "${url%/}/FUZZ" \
            -e ".${extensions//,/,.}" \
            -o "$outdir/files_medium.json" -of json \
            > "$outdir/files_medium_console.txt" 2>&1 || phase_ok=false

        ffuf_json_to_text "$outdir/files_medium.json" > "$outdir/files_medium.txt" 2>/dev/null || true
    fi

    # --- 2c: If raft-large exists AND we're in deep mode, run it too ---
    if [[ "$DEEP_MODE" == "true" ]] && [[ -f "$WL_DIR_LARGE" ]]; then
        info "  → ffuf deep directory fuzzing (raft-large — this is slow)"
        timeout "$PHASE_CONTENT_TIMEOUT" ffuf \
            "${base_flags[@]}" \
            -w "${WL_DIR_LARGE}:FUZZ" \
            -u "${url%/}/FUZZ" \
            -o "$outdir/dirs_large.json" -of json \
            > "$outdir/dirs_large_console.txt" 2>&1 || phase_ok=false

        ffuf_json_to_text "$outdir/dirs_large.json" > "$outdir/dirs_large.txt" 2>/dev/null || true
    fi

    if [[ "$phase_ok" == "true" ]]; then
        progress_log "$2" "DONE" "$phase_name" "tech=$tech"
    else
        progress_log "$2" "FAIL" "$phase_name" "tech=$tech"
    fi
    success "Content fuzzing complete"
}

#==============================================================================
# PHASE 3 — RECURSIVE FUZZING (deep mode only)
#==============================================================================
phase_recursive() {
    local url="$1"
    local outdir="$2/content/recursive"
    mkdir -p "$outdir"

    if [[ "$DEEP_MODE" != "true" ]]; then
        info "Skipping recursive fuzzing (use --deep to enable)"
        return 0
    fi

    local phase_name="recursive"
    if is_phase_done "$2" "$phase_name"; then
        info "Recursive fuzzing already done — skipping"
        return 0
    fi
    progress_log "$2" "START" "$phase_name" "url=$url"
    phase "Phase 3 — Recursive Fuzzing (deep mode): $url"

    if ! check_tool ffuf; then
        warn "ffuf not found — skipping"
        return 1
    fi

    # Find interesting directories from phase 2 to recurse into
    local interesting_dirs=()
    local path_part=""

    # Extract URLs directly from ffuf JSON (reliable) for 200/301/302 results
    if [[ -f "$2/content/dirs_medium.json" ]]; then
        while IFS= read -r dir_url; do
            [[ -z "$dir_url" ]] && continue
            # Skip root URL itself
            # shellcheck disable=SC2001  # regex replacement not expressible as param expansion
            path_part=$(echo "$dir_url" | sed 's|https\?://[^/]*||')
            [[ "$path_part" == "/" || -z "$path_part" ]] && continue
            interesting_dirs+=("$dir_url")
        done < <(python3 << PYEOF
import json, sys
try:
    with open('$2/content/dirs_medium.json') as f:
        data = json.load(f)
    for r in data.get('results', []):
        status = r.get('status', 0)
        if status in (200, 301, 302):
            print(r.get('url', ''))
except Exception as e:
    print(f'webenum: JSON parse error (dirs_medium): {e}', file=sys.stderr)
PYEOF
        )
    fi

    if (( ${#interesting_dirs[@]} == 0 )); then
        info "No interesting directories found to recurse into"
        progress_log "$2" "DONE" "$phase_name" "no-dirs"
        return 0
    fi

    # Cap at 20 to avoid spending the whole engagement recursing
    if (( ${#interesting_dirs[@]} > 20 )); then
        warn "  Too many dirs (${#interesting_dirs[@]}) — capping at 20"
        interesting_dirs=("${interesting_dirs[@]:0:20}")
    fi

    info "  Found ${#interesting_dirs[@]} directory/ies to recurse into"

    local wl_dir=""
    wl_dir=$(check_wordlist "$WL_DIR_MEDIUM" "$WL_DIR_FAST") || return 1

    local proto=""
    proto=$(get_proto "$url")
    local -a ssl_flag=()
    [[ "$proto" == "https" ]] && ssl_flag=(-k)

    local tech=""
    tech=$(detect_tech "$2/fingerprint/whatweb.txt")
    local extensions=""
    extensions=$(get_extensions "$tech")

    local phase_ok=true
    local safe_name=""
    local i=0
    for dir_url in "${interesting_dirs[@]}"; do
        (( i++ ))
        safe_name=$(echo "$dir_url" | sed 's|https\?://||;s|[/:]|_|g')
        info "  → recursing into: $dir_url ($i/${#interesting_dirs[@]})"

        # shellcheck disable=SC2054  # commas in -mc value are ffuf syntax, not array separators
        timeout "$PHASE_RECURSIVE_TIMEOUT" ffuf \
            -t "$THREADS" -timeout "$FFUF_TIMEOUT" \
            -mc 200,201,204,301,302,307,401,403 \
            -c -noninteractive "${ssl_flag[@]}" \
            -w "${wl_dir}:FUZZ" \
            -u "${dir_url%/}/FUZZ" \
            -e ".${extensions//,/,.}" \
            -o "$outdir/${safe_name}.json" -of json \
            > "$outdir/${safe_name}_console.txt" 2>&1 || phase_ok=false

        ffuf_json_to_text "$outdir/${safe_name}.json" > "$outdir/${safe_name}.txt" 2>/dev/null || true
    done

    if [[ "$phase_ok" == "true" ]]; then
        progress_log "$2" "DONE" "$phase_name" "dirs=${#interesting_dirs[@]}"
    else
        progress_log "$2" "FAIL" "$phase_name" "dirs=${#interesting_dirs[@]}"
    fi
    success "Recursive fuzzing complete"
}

#==============================================================================
# PHASE 4 — VHOST FUZZING
#==============================================================================
phase_vhosts() {
    local url="$1"
    local outdir="$2/vhosts"
    mkdir -p "$outdir"

    if [[ -z "$VHOST_DOMAIN" ]]; then
        info "Skipping vhost fuzzing (use --vhost <domain> to enable)"
        return 0
    fi

    local phase_name="vhosts"
    if is_phase_done "$2" "$phase_name"; then
        info "Vhost fuzzing already done — skipping"
        return 0
    fi
    progress_log "$2" "START" "$phase_name" "domain=$VHOST_DOMAIN"
    phase "Phase 4 — VHost Fuzzing: *.${VHOST_DOMAIN}"

    if ! check_tool ffuf; then
        warn "ffuf not found — skipping"
        return 1
    fi

    local wl=""
    wl=$(check_wordlist "$WL_VHOSTS" "/usr/share/wordlists/dirb/common.txt") || return 1

    local proto=""
    proto=$(get_proto "$url")
    local -a ssl_flag=()
    [[ "$proto" == "https" ]] && ssl_flag=(-k)

    # Step 1: Get baseline response size to filter on
    info "  → getting baseline response size for filtering"
    local baseline_size=""
    baseline_size=$(timeout "$CURL_TIMEOUT" curl -sk -o /dev/null -w "%{size_download}" \
        -H "Host: nonexistent12345.${VHOST_DOMAIN}" \
        -A "Mozilla/5.0" "$url" 2>/dev/null || echo "")
    if [[ -z "$baseline_size" || "$baseline_size" == "0" ]]; then
        warn "  Baseline size is 0 or empty — vhost filtering may be unreliable"
        warn "  If all vhosts are filtered out, re-run without -fs or check target manually"
    fi
    info "  Baseline size: ${baseline_size:-0} bytes (will filter this out)"

    # Step 2: Vhost fuzz with size filter
    info "  → ffuf vhost fuzzing (Host: FUZZ.${VHOST_DOMAIN})"
    local phase_ok=true
    local -a fs_flag=()
    if [[ -n "$baseline_size" && "$baseline_size" != "0" ]]; then
        fs_flag=(-fs "$baseline_size")
    fi
    # shellcheck disable=SC2054  # commas in -mc value are ffuf syntax, not array separators
    timeout "$PHASE_VHOST_TIMEOUT" ffuf \
        -t "$THREADS" -timeout "$FFUF_TIMEOUT" \
        -mc 200,201,204,301,302,307,401,403 \
        "${fs_flag[@]}" \
        -c -noninteractive "${ssl_flag[@]}" \
        -w "${wl}:FUZZ" \
        -u "$url" \
        -H "Host: FUZZ.${VHOST_DOMAIN}" \
        -o "$outdir/vhosts.json" -of json \
        > "$outdir/vhosts_console.txt" 2>&1 || phase_ok=false

    ffuf_json_to_text "$outdir/vhosts.json" > "$outdir/vhosts.txt" 2>/dev/null || true

    # Report discovered vhosts for /etc/hosts
    # Use ffuf_json_fuzz_words to extract the FUZZ input (vhost name), not the URL
    local found_vhosts=""
    found_vhosts=$(ffuf_json_fuzz_words "$outdir/vhosts.json" 2>/dev/null)
    local found_count=""
    found_count=$(echo "$found_vhosts" | grep -c '.' 2>/dev/null || echo "0")

    if (( found_count > 0 )); then
        local ip=""
        ip=$(get_host "$url")
        echo ""
        success "  ★ Found ${found_count} vhost(s) — add to /etc/hosts:"
        echo "$found_vhosts" | while read -r vhost; do
            [[ -z "$vhost" ]] && continue
            echo "  ${ip}  ${vhost}.${VHOST_DOMAIN}"
        done | tee "$outdir/hosts_entries.txt"
    fi

    if [[ "$phase_ok" == "true" ]]; then
        progress_log "$2" "DONE" "$phase_name" "found=$found_count"
    else
        progress_log "$2" "FAIL" "$phase_name" "found=$found_count"
    fi
    success "VHost fuzzing complete"
}

#==============================================================================
# PHASE 5 — PARAMETER DISCOVERY (deep mode only)
#==============================================================================
phase_params() {
    local url="$1"
    local outdir="$2/params"
    mkdir -p "$outdir"

    if [[ "$DEEP_MODE" != "true" ]]; then
        info "Skipping parameter discovery (use --deep to enable)"
        return 0
    fi

    local phase_name="params"
    if is_phase_done "$2" "$phase_name"; then
        info "Parameter discovery already done — skipping"
        return 0
    fi
    progress_log "$2" "START" "$phase_name" "url=$url"
    phase "Phase 5 — Parameter Discovery (deep mode)"

    if ! check_tool ffuf; then
        warn "ffuf not found — skipping"
        return 1
    fi

    if [[ ! -f "$WL_PARAMS" ]]; then
        warn "Parameter wordlist not found: $WL_PARAMS — skipping"
        progress_log "$2" "SKIP" "$phase_name" "no wordlist"
        return 0
    fi

    local proto=""
    proto=$(get_proto "$url")
    local -a ssl_flag=()
    [[ "$proto" == "https" ]] && ssl_flag=(-k)

    # Collect interesting endpoints from content phase to fuzz params on
    local endpoints=("${url%/}/")
    if [[ -f "$2/content/dirs_medium.json" ]]; then
        while IFS= read -r ep_url; do
            [[ -z "$ep_url" ]] && continue
            endpoints+=("$ep_url")
        done < <(python3 << PYEOF
import json, sys
try:
    with open('$2/content/dirs_medium.json') as f:
        data = json.load(f)
    for r in data.get('results', []):
        if r.get('status') == 200:
            print(r.get('url', ''))
except Exception as e:
    print(f'webenum: JSON parse error (dirs_medium params): {e}', file=sys.stderr)
PYEOF
        )
    fi
    # Also pull from files scan
    if [[ -f "$2/content/files_medium.json" ]]; then
        while IFS= read -r ep_url; do
            [[ -z "$ep_url" ]] && continue
            endpoints+=("$ep_url")
        done < <(python3 << PYEOF
import json, sys
try:
    with open('$2/content/files_medium.json') as f:
        data = json.load(f)
    for r in data.get('results', []):
        if r.get('status') == 200:
            url = r.get('url', '')
            # Only fuzz endpoints that look like scripts/pages, not static files
            if any(url.endswith(ext) for ext in ('.php','.asp','.aspx','.jsp','.do','.action','.cgi','.pl')):
                print(url)
except Exception as e:
    print(f'webenum: JSON parse error (files_medium): {e}', file=sys.stderr)
PYEOF
        )
    fi
    # Deduplicate and cap
    mapfile -t endpoints < <(printf '%s\n' "${endpoints[@]}" | sort -u | head -15)

    info "  Fuzzing GET parameters on ${#endpoints[@]} endpoint(s)"

    local phase_ok=true
    local safe_name=""
    local baseline=""
    local i=0
    for endpoint in "${endpoints[@]}"; do
        (( i++ ))
        safe_name=$(echo "$endpoint" | sed 's|https\?://||;s|[/:]|_|g')

        # Get baseline to filter on
        baseline=$(timeout "$CURL_TIMEOUT" curl -sk -o /dev/null -w "%{size_download}" \
            -A "Mozilla/5.0" "${endpoint}?nonexistent12345=test" 2>/dev/null || echo "")

        local -a param_fs_flag=()
        if [[ -n "$baseline" && "$baseline" != "0" ]]; then
            param_fs_flag=(-fs "$baseline")
        fi

        info "  → param fuzzing: $endpoint ($i/${#endpoints[@]})"
        # shellcheck disable=SC2054  # -mc all is not comma-separated — no SC2054 here anyway
        timeout "$PHASE_PARAM_TIMEOUT" ffuf \
            -t "$THREADS" -timeout "$FFUF_TIMEOUT" \
            -mc all "${param_fs_flag[@]}" \
            -c -noninteractive "${ssl_flag[@]}" \
            -w "${WL_PARAMS}:FUZZ" \
            -u "${endpoint}?FUZZ=testvalue" \
            -o "$outdir/params_${safe_name}.json" -of json \
            > "$outdir/params_${safe_name}_console.txt" 2>&1 || phase_ok=false

        ffuf_json_to_text "$outdir/params_${safe_name}.json" \
            > "$outdir/params_${safe_name}.txt" 2>/dev/null || true
    done

    if [[ "$phase_ok" == "true" ]]; then
        progress_log "$2" "DONE" "$phase_name" "endpoints=${#endpoints[@]}"
    else
        progress_log "$2" "FAIL" "$phase_name" "endpoints=${#endpoints[@]}"
    fi
    success "Parameter discovery complete"
}

#==============================================================================
# JSON → TEXT HELPER (parse ffuf JSON output to human-readable table)
#==============================================================================
ffuf_json_to_text() {
    local json_file="$1"
    [[ ! -f "$json_file" ]] && return 1

    python3 << PYEOF
import json, sys
try:
    with open('${json_file}') as f:
        data = json.load(f)
    results = data.get('results', [])
    if not results:
        print('No results.')
        sys.exit(0)
    # Check if any result has an input/FUZZ field (vhost mode)
    has_input = any(r.get('input', {}).get('FUZZ') for r in results)
    if has_input:
        hdr = f"{'FUZZ':<30} {'URL':<40} | {'Status':>6} | {'Size':>8} | {'Words':>6} | {'Lines':>5}"
        print(hdr)
        print('-' * len(hdr))
        for r in sorted(results, key=lambda x: (x.get('status',0), x.get('input',{}).get('FUZZ',''))):
            fuzz = r.get('input', {}).get('FUZZ', '')
            print(f"{fuzz:<30} {r.get('url',''):<40} | {r.get('status',0):>6} | {r.get('length',0):>8} | {r.get('words',0):>6} | {r.get('lines',0):>5}")
    else:
        hdr = f"{'URL':<60} | {'Status':>6} | {'Size':>8} | {'Words':>6} | {'Lines':>5}"
        print(hdr)
        print('-' * len(hdr))
        for r in sorted(results, key=lambda x: (x.get('status',0), x.get('url',''))):
            print(f"{r.get('url',''):<60} | {r.get('status',0):>6} | {r.get('length',0):>8} | {r.get('words',0):>6} | {r.get('lines',0):>5}")
except Exception as e:
    print(f'Parse error: {e}')
PYEOF
}

# Extract just the FUZZ words from ffuf JSON (for vhost names, etc.)
ffuf_json_fuzz_words() {
    local json_file="$1"
    [[ ! -f "$json_file" ]] && return 1

    python3 << PYEOF
import json, sys
try:
    with open('${json_file}') as f:
        data = json.load(f)
    for r in data.get('results', []):
        fuzz = r.get('input', {}).get('FUZZ', '')
        if fuzz:
            print(fuzz)
except Exception as e:
    print(f'webenum: JSON parse error (fuzz_words): {e}', file=sys.stderr)
PYEOF
}

# Extract URLs from ffuf JSON (for recursive/param endpoint discovery)
ffuf_json_urls() {
    local json_file="$1"
    [[ ! -f "$json_file" ]] && return 1

    python3 << PYEOF
import json, sys
try:
    with open('${json_file}') as f:
        data = json.load(f)
    for r in data.get('results', []):
        url = r.get('url', '')
        if url:
            print(url)
except Exception as e:
    print(f'webenum: JSON parse error (urls): {e}', file=sys.stderr)
PYEOF
}

#==============================================================================
# PHASE 6 — SUMMARY GENERATION
#==============================================================================
generate_summary() {
    local url="$1"
    local work_dir="$2"
    local summary_dir="$work_dir/summary"
    mkdir -p "$summary_dir"

    phase "Phase 6 — Generating Summary"

    local proto=""
    proto=$(get_proto "$url")

    {
        echo "# webenum Summary"
        echo ""
        echo "**Target:** \`${url}\`"
        echo "**Date:** $(date '+%Y-%m-%d %H:%M')"
        echo "**Mode:** $(if [[ "$DEEP_MODE" == "true" ]]; then echo 'DEEP'; else echo 'STANDARD'; fi)"
        echo ""
        echo "---"
        echo ""

        # --- Technology Stack ---
        echo "## Technology Fingerprint"
        echo ""
        if [[ -f "$work_dir/fingerprint/whatweb.txt" ]]; then
            echo '```'
            head -5 "$work_dir/fingerprint/whatweb.txt" 2>/dev/null
            echo '```'
        fi
        echo ""

        # --- Headers of Interest ---
        echo "## Notable Headers"
        echo ""
        if [[ -f "$work_dir/fingerprint/headers.txt" ]]; then
            echo '```'
            grep -iE 'Server:|X-Powered-By:|X-Frame|Content-Security|Location:|Set-Cookie|WWW-Auth' \
                "$work_dir/fingerprint/headers.txt" 2>/dev/null | head -20
            echo '```'
        fi
        echo ""

        # --- Sensitive Paths ---
        echo "## Sensitive Path Probes"
        echo ""
        if [[ -f "$work_dir/fingerprint/sensitive_paths.txt" ]]; then
            echo '```'
            grep -v '^#\|^$' "$work_dir/fingerprint/sensitive_paths.txt" 2>/dev/null
            echo '```'
        fi
        echo ""

        # --- Robots.txt ---
        if [[ -f "$work_dir/fingerprint/robots.txt" ]] && \
           ! grep -q '# No robots' "$work_dir/fingerprint/robots.txt" 2>/dev/null; then
            echo "## robots.txt"
            echo ""
            echo '```'
            cat "$work_dir/fingerprint/robots.txt" 2>/dev/null | head -30
            echo '```'
            echo ""
        fi

        # --- Directory Findings ---
        echo "## Directory / File Findings"
        echo ""
        local count=""
        for f in "$work_dir/content/"*.txt; do
            [[ -f "$f" ]] || continue
            count=$(grep -c '|' "$f" 2>/dev/null || echo "0")
            (( count > 0 )) || continue
            echo "### $(basename "$f") ($count results)"
            echo ""
            echo '```'
            # Show 200s first, then 301/302, then 401/403
            grep '| 200 |' "$f" 2>/dev/null | head -20
            grep '| 30[12] |' "$f" 2>/dev/null | head -10
            grep '| 40[13] |' "$f" 2>/dev/null | head -10
            echo '```'
            echo ""
        done

        # --- VHost Findings ---
        if [[ -f "$work_dir/vhosts/vhosts.txt" ]]; then
            local vhost_count=""
            vhost_count=$(grep -c '|' "$work_dir/vhosts/vhosts.txt" 2>/dev/null || echo "0")
            if (( vhost_count > 0 )); then
                echo "## VHosts Discovered ★"
                echo ""
                echo '```'
                cat "$work_dir/vhosts/hosts_entries.txt" 2>/dev/null
                echo '```'
                echo ""
                echo "> Add the above to /etc/hosts and re-run webenum for each vhost."
                echo ""
            fi
        fi

        # --- Source Hints ---
        if [[ -f "$work_dir/fingerprint/source_hints.txt" ]]; then
            local hints_content=""
            hints_content=$(grep -v '===\|^$' "$work_dir/fingerprint/source_hints.txt" | head -30)
            if [[ -n "$hints_content" ]]; then
                echo "## Source Code Hints"
                echo ""
                echo '```'
                echo "$hints_content"
                echo '```'
                echo ""
            fi
        fi

        # --- Recursive Findings ---
        if [[ "$DEEP_MODE" == "true" ]] && [[ -d "$work_dir/content/recursive" ]]; then
            local rec_total=0
            local cnt=""
            for f in "$work_dir/content/recursive/"*.txt; do
                [[ -f "$f" ]] || continue
                rec_total=$(( rec_total + $(grep -c '|' "$f" 2>/dev/null || echo 0) ))
            done
            if (( rec_total > 0 )); then
                echo "## Recursive Findings ($rec_total total)"
                echo ""
                for f in "$work_dir/content/recursive/"*.txt; do
                    [[ -f "$f" ]] || continue
                    cnt=$(grep -c '|' "$f" 2>/dev/null || echo "0")
                    (( cnt > 0 )) || continue
                    echo "### $(basename "$f") ($cnt)"
                    echo '```'
                    grep '| 200 |' "$f" 2>/dev/null | head -10
                    echo '```'
                    echo ""
                done
            fi
        fi

        # --- Param Findings ---
        if [[ "$DEEP_MODE" == "true" ]] && [[ -d "$work_dir/params" ]]; then
            local param_total=0
            for f in "$work_dir/params/"*.txt; do
                [[ -f "$f" ]] || continue
                param_total=$(( param_total + $(grep -c '|' "$f" 2>/dev/null || echo 0) ))
            done
            if (( param_total > 0 )); then
                echo "## Parameter Discovery ($param_total found)"
                echo ""
                for f in "$work_dir/params/"*.txt; do
                    [[ -f "$f" ]] || continue
                    grep -v '^No\|^-\|^URL' "$f" 2>/dev/null | head -20
                done | sort -u
                echo ""
            fi
        fi

        # --- Next Steps ---
        echo "## Next Steps"
        echo ""
        echo "1. Open \`summary.md\` findings in Burp Suite for manual testing"
        echo "2. Check 401/403 endpoints — try authentication bypass techniques"
        echo "3. Check redirect destinations — 301/302 may point to interesting paths"
        echo "4. Review source_hints.txt for hardcoded paths, version strings"
        echo "5. If vhosts found: add to /etc/hosts and run webenum per vhost"
        if [[ "$DEEP_MODE" != "true" ]]; then
            echo "6. If stuck: re-run with \`--deep\` for recursive + parameter fuzzing"
        fi
        echo ""
        echo "---"
        echo "*Generated by webenum — enumeration only, no exploitation*"

    } > "$summary_dir/summary.md"

    # Generate quick_wins.txt — just the high-value lines for fast review
    {
        echo "# Quick Wins — $(date '+%Y-%m-%d %H:%M') — $url"
        echo ""

        echo "## Sensitive Paths"
        grep -v '^#\|^$' "$work_dir/fingerprint/sensitive_paths.txt" 2>/dev/null | \
            head -20 | sed 's/^/  /'

        echo ""
        echo "## Robots.txt"
        grep -i 'Disallow:' "$work_dir/fingerprint/robots.txt" 2>/dev/null | \
            sed 's/^/  ROBOTS: /'

        echo ""
        echo "## 200 OK Hits"
        for f in "$work_dir/content/"*.txt; do
            [[ -f "$f" ]] || continue
            grep '| 200 |' "$f" 2>/dev/null | head -10 | sed 's/^/  /'
        done

        echo ""
        echo "## Auth Required (401)"
        for f in "$work_dir/content/"*.txt "$work_dir/content/recursive/"*.txt; do
            [[ -f "$f" ]] || continue
            grep '| 401 |' "$f" 2>/dev/null | head -5 | sed 's/^/  AUTH: /'
        done

        echo ""
        echo "## VHosts"
        sed 's/^/  VHOST: /' "$work_dir/vhosts/hosts_entries.txt" 2>/dev/null || true

    } > "$summary_dir/quick_wins.txt"

    success "Summary written to $summary_dir/summary.md"
    success "Quick wins written to $summary_dir/quick_wins.txt"
}

#==============================================================================
# USAGE
#==============================================================================
usage() {
    cat <<'EOF'
WEBENUM — Deep Web Enumeration Wrapper
Designed to run after recon.sh for thorough web-layer coverage.

USAGE:
  ./webenum.sh --url <URL> [OPTIONS]

OPTIONS:
  --url URL          Target URL (required). e.g. http://10.10.10.5:8080
  --deep             Enable deep mode: recursive fuzzing + parameter discovery
  --vhost DOMAIN     Enable vhost fuzzing against this base domain
                       e.g. --vhost target.htb
  --root DIR         Output root directory (default: ./webenum)
  --threads N        ffuf thread count (default: 40)
  --rate N           ffuf max requests/sec, 0=unlimited (default: 0)
  -h, --help         Show this help

EXAMPLES:
  # Standard run after recon finds HTTP
  ./webenum.sh --url http://10.10.10.5

  # HTTPS non-standard port
  ./webenum.sh --url https://10.10.10.5:8443

  # With vhost fuzzing (if you know the domain name)
  ./webenum.sh --url http://10.10.10.5 --vhost target.htb

  # Full deep mode — recursive + params + large wordlists
  ./webenum.sh --url http://10.10.10.5 --deep --vhost target.htb

  # Custom output directory (mirror recon layout)
  ./webenum.sh --url http://10.10.10.5 --root ~/pg

OUTPUT:
  <root>/<host>_<port>_<proto>/artifacts/web/
    fingerprint/     whatweb, headers, cookies, source hints, sensitive paths
    content/         ffuf directory and file fuzzing (JSON + text)
    content/recursive/  recursive fuzzing on interesting dirs (--deep)
    vhosts/          vhost fuzzing results + /etc/hosts entries
    params/          GET parameter discovery (--deep)
    summary/
      summary.md     Structured findings — read this first
      quick_wins.txt High-value lines only

MODES:
  standard (default)
    Phase 1: Fingerprinting (whatweb, headers, source hints, sensitive paths)
    Phase 2: Directory + file fuzzing (raft-medium wordlists)
    Phase 4: VHost fuzzing (if --vhost specified)
    Phase 6: Summary

  deep (--deep)
    All standard phases plus:
    Phase 3: Recursive fuzzing on discovered directories
    Phase 5: GET parameter discovery on found endpoints
    Phase 2: Also runs raft-large wordlist

NOTES:
  - Enumeration only — no exploitation, OffSec compliant
  - Re-run safely: completed phases are skipped
  - Ctrl+C cleans up all background jobs
  - Requires: ffuf, curl, python3 (for JSON parsing)
  - Optional: whatweb — fingerprinting degrades gracefully if missing
EOF
}

#==============================================================================
# ARGUMENT PARSING
#==============================================================================
TARGET_URL=""
FROM_RECON_IP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --url)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            TARGET_URL="$2"
            shift 2
            ;;
        --from-recon)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            FROM_RECON_IP="$2"
            shift 2
            ;;
        --no-color)
            disable_colors
            shift
            ;;
        --deep)
            DEEP_MODE=true
            shift
            ;;
        --vhost)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            VHOST_DOMAIN="$2"
            shift 2
            ;;
        --root)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        --threads)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            THREADS="$2"
            shift 2
            ;;
        --rate)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            FFUF_RATE="$2"
            shift 2
            ;;
        -*)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            # Allow bare URL as positional arg
            TARGET_URL="$1"
            shift
            ;;
    esac
done

# --from-recon: auto-detect HTTP URLs from recon.sh output
if [[ -n "$FROM_RECON_IP" && -z "$TARGET_URL" ]]; then
    recon_dir="${TOOLKIT_ROOT}/recon/${FROM_RECON_IP}"
    if [[ ! -d "$recon_dir" ]]; then
        error "No recon data at ${recon_dir}. Run: ./recon.sh ${FROM_RECON_IP}"
        exit 1
    fi
    declare -a found_urls=()
    for nmap_file in "${recon_dir}/scans/"*nmap*; do
        [[ -f "$nmap_file" ]] || continue
        while IFS= read -r line; do
            port=$(echo "$line" | grep -oP '\d+(?=/tcp.*http)' | head -1)
            [[ -z "$port" ]] && continue
            if echo "$line" | grep -qi "ssl\|https"; then
                proto="https"
            else
                proto="http"
            fi
            url="${proto}://${FROM_RECON_IP}"
            [[ "$port" != "80" && "$port" != "443" ]] && url="${url}:${port}"
            # Deduplicate
            dup=false
            for u in "${found_urls[@]+"${found_urls[@]}"}"; do
                [[ "$u" == "$url" ]] && dup=true
            done
            [[ "$dup" == false ]] && found_urls+=("$url")
        done < <(grep -iE 'open.*http' "$nmap_file" 2>/dev/null || true)
    done
    if (( ${#found_urls[@]} == 0 )); then
        error "No HTTP services found in recon data for ${FROM_RECON_IP}"
        exit 1
    elif (( ${#found_urls[@]} == 1 )); then
        TARGET_URL="${found_urls[0]}"
        info "Auto-detected from recon: ${TARGET_URL}"
    else
        info "Multiple HTTP services found for ${FROM_RECON_IP}:"
        for i in "${!found_urls[@]}"; do
            echo "  $((i+1)). ${found_urls[$i]}"
        done
        TARGET_URL="${found_urls[0]}"
        info "Using first URL: ${TARGET_URL} (run again with --url for others)"
    fi
fi

if [[ -z "$TARGET_URL" ]]; then
    error "No URL specified. Use --url or --from-recon."
    usage
    exit 1
fi

# Ensure URL has a scheme
if ! echo "$TARGET_URL" | grep -qP '^https?://'; then
    TARGET_URL="http://${TARGET_URL}"
    warn "No scheme detected — assuming http: ${TARGET_URL}"
fi

if ! is_positive_integer "$THREADS"; then
    error "--threads must be a positive integer"
    exit 1
fi

if ! is_nonnegative_integer "$FFUF_RATE"; then
    error "--rate must be a non-negative integer"
    exit 1
fi

#==============================================================================
# OUTPUT DIRECTORY SETUP
#==============================================================================
PROTO=$(get_proto "$TARGET_URL")
HOST=$(get_host "$TARGET_URL")
PORT=$(get_port "$TARGET_URL")
if [[ -z "$PROTO" || -z "$HOST" || ! "$PORT" =~ ^[0-9]+$ ]]; then
    error "Could not parse target URL: $TARGET_URL"
    exit 1
fi
TARGET_TAG="${HOST}_${PORT}_${PROTO}"
OUTPUT_DIR="${OUTPUT_ROOT}/${TARGET_TAG}/artifacts/web"
mkdir -p "${OUTPUT_DIR}"/{fingerprint,content,content/recursive,vhosts,params,summary}

# Reachability precheck — fail fast instead of wasting engagement time on a dead host
if ! curl -sS -o /dev/null --max-time 5 -k "$TARGET_URL" 2>/dev/null; then
    error "Target unreachable: $TARGET_URL (curl --max-time 5 failed)"
    error "Verify host/port/scheme before running webenum."
    exit 1
fi

#==============================================================================
# PRE-FLIGHT
#==============================================================================
header "WEBENUM — Deep Web Enumeration"

echo ""
info "Target:   $TARGET_URL"
info "Host:     $HOST"
info "Port:     $PORT"
info "Output:   $OUTPUT_DIR"
info "Mode:     $(if [[ "$DEEP_MODE" == "true" ]]; then echo 'DEEP (recursive + params)'; else echo 'STANDARD'; fi)"
info "Threads:  $THREADS"
[[ -n "$VHOST_DOMAIN" ]] && info "VHosts:   *.${VHOST_DOMAIN}"
echo ""

# Tool checks
info "Checking tools..."
TOOLS_PRESENT=()
TOOLS_MISSING=()
for t in ffuf whatweb curl python3; do
    if check_tool "$t"; then
        TOOLS_PRESENT+=("$t")
        echo -e "  ${GREEN}✓${NC} $t"
    else
        TOOLS_MISSING+=("$t")
        echo -e "  ${YELLOW}✗${NC} $t (missing)"
    fi
done

if (( ${#TOOLS_MISSING[@]} > 0 )); then
    warn "Missing tools: ${TOOLS_MISSING[*]}"
    warn "Install: sudo apt install ${TOOLS_MISSING[*]}"
fi

for required_tool in ffuf curl python3; do
    if ! check_tool "$required_tool"; then
        error "Required tool missing: $required_tool"
        exit 1
    fi
done

echo ""
info "Wordlist status:"
for wl in "$WL_DIR_FAST" "$WL_DIR_MEDIUM" "$WL_DIR_LARGE" "$WL_FILES_MEDIUM" "$WL_VHOSTS" "$WL_PARAMS"; do
    if [[ -f "$wl" ]]; then
        local_count=$(wc -l < "$wl" 2>/dev/null || echo "?")
        echo -e "  ${GREEN}✓${NC} $(basename "$wl") (${local_count} lines)"
    else
        echo -e "  ${YELLOW}✗${NC} $(basename "$wl") — not found"
    fi
done

echo ""

# --- Connectivity pre-flight ---
info "Checking target connectivity..."
HTTP_CHECK_CODE=$(timeout 10 curl -sk -o /dev/null -w "%{http_code}" \
    -A "Mozilla/5.0 (X11; Linux x86_64)" \
    "$TARGET_URL" 2>/dev/null || echo "000")
HTTP_CHECK_SIZE=$(timeout 10 curl -sk -o /dev/null -w "%{size_download}" \
    -A "Mozilla/5.0 (X11; Linux x86_64)" \
    "$TARGET_URL" 2>/dev/null || echo "0")

if [[ "$HTTP_CHECK_CODE" == "000" ]]; then
    error "Target $TARGET_URL is NOT responding (connection failed)"
    error "Check: Is the target up? Is your VPN connected? Is the URL correct?"
    error "  Try: curl -sk $TARGET_URL"
    echo ""
    warn "Proceeding anyway — some phases may fail..."
elif [[ "$HTTP_CHECK_CODE" =~ ^[45] ]]; then
    warn "Target responded with HTTP $HTTP_CHECK_CODE (${HTTP_CHECK_SIZE} bytes)"
    warn "This may be normal (custom error page) or indicate the wrong URL"
    success "Target is reachable — proceeding"
else
    success "Target responded: HTTP $HTTP_CHECK_CODE (${HTTP_CHECK_SIZE} bytes) — good to go"
fi
echo ""

#==============================================================================
# MAIN EXECUTION
#==============================================================================
START_TIME=$(date +%s)

phase_fingerprint "$TARGET_URL" "$OUTPUT_DIR"
phase_content     "$TARGET_URL" "$OUTPUT_DIR"
phase_recursive   "$TARGET_URL" "$OUTPUT_DIR"
phase_vhosts      "$TARGET_URL" "$OUTPUT_DIR"
phase_params      "$TARGET_URL" "$OUTPUT_DIR"

wait_all

generate_summary  "$TARGET_URL" "$OUTPUT_DIR"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
MINUTES=$(( ELAPSED / 60 ))
SECS=$(( ELAPSED % 60 ))

header "WEBENUM COMPLETE"
echo ""
success "Total time: ${MINUTES}m ${SECS}s"
success "Results:    ${OUTPUT_DIR}/summary/summary.md"
echo ""
echo -e "${BOLD}Quick wins:${NC}"
cat "${OUTPUT_DIR}/summary/quick_wins.txt" 2>/dev/null | grep -v '^#\|^$' | \
    while IFS= read -r line; do
        echo -e "  ${GREEN}★${NC} $line"
    done
echo ""
