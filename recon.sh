#!/usr/bin/env bash
#==============================================================================
# OffSec RECON WRAPPER - Automated Enumeration Orchestrator
#==============================================================================
# Single-file design: no external modules to lose on engagement day.
#
# WORKFLOW:
#   1. Fast TCP port discovery via rustscan
#   2. Targeted nmap service/version scan on found ports
#   3. UDP top-port scan (SNMP is OffSec gold)
#   4. Auto-launch service-specific enumeration based on findings
#   5. Generate summary report
#
# DESIGN DECISIONS:
#   - Single file: reliability > elegance on engagement day
#   - Background jobs: enumeration runs in parallel so you can work
#   - Trap handlers: Ctrl+C kills children cleanly, no zombies
#   - Timeouts on everything: nothing hangs your engagement
#   - Idempotent: re-run safely; skips completed phases
#   - Structured output: easy to grep/review under pressure
#
# USAGE:
#   ./recon.sh <IP>                  # Single target
#   ./recon.sh <IP1> <IP2> <IP3>     # Multiple targets
#   ./recon.sh -f targets.txt        # File with one IP per line
#   ./recon.sh --auto <IP>           # Skip confirmation prompts
#   ./recon.sh --udp-ports 50 <IP>   # Custom UDP top-port count
#   ./recon.sh --udp-full <IP>        # Full 65535 UDP scan (when stuck)
#
# OUTPUT STRUCTURE:
#   recon/<IP>/
#   ├── scans/          # Raw nmap/rustscan output
#   ├── tcp/            # TCP service enumeration
#   │   ├── http/       # gobuster, nikto, whatweb
#   │   ├── smb/        # enum4linux-ng, smbmap, smbclient
#   │   ├── ftp/        # Anonymous login checks
#   │   ├── ssh/        # Version/key info
#   │   ├── snmp/       # snmpwalk, onesixtyone
#   │   ├── mysql/      # MySQL enumeration
#   │   ├── postgres/   # PostgreSQL enumeration
#   │   ├── dns/        # DNS enumeration
#   │   ├── smtp/       # SMTP user enumeration
#   │   └── rpc/        # RPC enumeration
#   ├── udp/            # UDP scan results and enumeration
#   ├── loot/           # Extracted creds, keys, interesting files
#   │   └── next_steps.txt  # Finding-driven follow-up command library
#   ├── progress.log    # What's done, what's running
#   └── summary.txt     # Quick-reference findings
#==============================================================================

set -o pipefail
set -u
# NOT set -e: we handle errors ourselves so one failure doesn't kill everything

#------------------------------------------------------------------------------
# CONFIGURATION — Tune these for your environment / engagement needs
#------------------------------------------------------------------------------
# Resolve workspace root — three-level priority:
#   1. Explicit TOOLKIT_ROOT already set in environment (user override)
#   2. Invoking user's home when running under sudo (prevents /root/offsec after re-exec)
#   3. Current HOME as final fallback
if [[ -z "${TOOLKIT_ROOT:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        _inv_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        TOOLKIT_ROOT="${_inv_home:-$HOME}/offsec"
        unset _inv_home
    else
        TOOLKIT_ROOT="${HOME}/offsec"
    fi
fi
RECON_DIR="${TOOLKIT_ROOT}/recon"         # Base output directory
# When running as root via sudo, prepend invoking user's bin dirs so user-installed
# tools (rustscan in ~/.cargo/bin, etc.) are found regardless of secure_path.
if [[ $EUID -eq 0 ]] && [[ -n "${SUDO_USER:-}" ]]; then
    _inv_home_p=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    if [[ -n "$_inv_home_p" ]]; then
        PATH="${_inv_home_p}/.cargo/bin:${_inv_home_p}/.local/bin:${_inv_home_p}/go/bin:${_inv_home_p}/snap/bin:${PATH}"
        export PATH
    fi
    unset _inv_home_p
fi
# Rustscan batch size — derived from current ulimit to avoid "Too many open files" noise
_ulimit_n=$(ulimit -n 2>/dev/null || echo 1024)
RUSTSCAN_BATCH_SIZE=$(( _ulimit_n / 2 ))
(( RUSTSCAN_BATCH_SIZE < 100  )) && RUSTSCAN_BATCH_SIZE=100
(( RUSTSCAN_BATCH_SIZE > 5000 )) && RUSTSCAN_BATCH_SIZE=5000
unset _ulimit_n
RUSTSCAN_TIMEOUT=4000                  # Connection timeout in ms
NMAP_TCP_TIMEOUT=600                   # Seconds for TCP service scan
NMAP_UDP_TIMEOUT=900                   # Seconds for UDP scan (slow by nature)
UDP_TOP_PORTS=200                      # Top N UDP ports to scan (200 balances coverage vs speed)
GOBUSTER_THREADS=20                    # Directory brute threads (lighter for first-pass OffSec recon)
GOBUSTER_TIMEOUT=10                    # Per-request timeout seconds (--timeout flag)
GOBUSTER_RUNTIME=300                   # Max total runtime for the gobuster process
GOBUSTER_WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
GOBUSTER_EXTENSIONS="php,asp,aspx,txt,html"   # Trimmed for first-pass speed; add cgi,jsp,bak manually if needed
NIKTO_TIMEOUT=120                      # Seconds
FEROX_RUNTIME=300                      # Max total runtime for the feroxbuster process
ENUM4LINUX_TIMEOUT=300                 # Seconds
SMBMAP_TIMEOUT=120                     # Seconds
SNMPWALK_TIMEOUT=120                   # Seconds
FTP_TIMEOUT=30                         # Seconds
MYSQL_TIMEOUT=30                       # Seconds
GENERIC_TIMEOUT=120                    # Fallback timeout for misc tools
MAX_PARALLEL_SERVICES=5                # Max concurrent service enumerations per target
MAX_PARALLEL_TARGETS=3                 # Max targets scanned simultaneously
SEQUENTIAL_TARGETS=false               # Process targets one at a time
AUTO_MODE=false                        # Skip confirmation prompts
UDP_FULL=false                         # Scan all 65535 UDP ports (slow but thorough)
NO_SUDO=false                          # Skip sudo auto-reexec (pass --no-sudo to disable)
SNMP_COMMUNITY_STRINGS=("public" "private" "manager" "community")

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS
#------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

disable_colors() { RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''; }
[[ "${NO_COLOR:-0}" == "1" ]] || [[ ! -t 1 ]] && disable_colors

# Timestamp for log entries
ts() { date '+%H:%M:%S'; }

info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; }
phase()       { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }
_tool_start() { echo -e "${CYAN}[$(ts)] [~]${NC} ${BOLD}$1${NC} → $2  ${YELLOW}(budget: $3)${NC}"; }
_tool_done()  { local _e=$(( $(date +%s) - $2 )); echo -e "${GREEN}[$(ts)] [✓]${NC} $1 done — ${_e}s"; }

#------------------------------------------------------------------------------
# PROGRESS TRACKING
# Each target gets a progress.log so you can resume or see what's done.
# Format: TIMESTAMP | STATUS | PHASE | DETAIL
#------------------------------------------------------------------------------
progress_log() {
    # $1=target_dir, $2=status(START|DONE|FAIL|SKIP), $3=phase, $4=detail
    local logfile="$1/progress.log"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $2 | $3 | $4" >> "$logfile"
}

is_phase_done() {
    # Check if a phase already completed (for resume support)
    # $1=target_dir, $2=phase_name
    grep -qF "| DONE | $2 |" "$1/progress.log" 2>/dev/null
}

#------------------------------------------------------------------------------
# CHILD PROCESS MANAGEMENT
# Track all background PIDs so Ctrl+C cleans up everything.
#------------------------------------------------------------------------------
declare -a CHILD_PIDS=()
# Separate array for PIDs that need cleanup kills but do NOT count toward RUNNING_JOBS
# (e.g. the UDP background scan).
declare -a CLEANUP_ONLY_PIDS=()

# In-process set of phase keys already queued this target run.
# Prevents double-launch when two ports map to the same once-only module (e.g. 139+445→SMB).
declare -A QUEUED_PHASES=()

register_pid() {
    CHILD_PIDS+=("$1")
}

register_cleanup_pid() {
    CLEANUP_ONLY_PIDS+=("$1")
}

unregister_cleanup_pid() {
    local remove_pid="$1"
    local new_pids=()
    local pid=""
    for pid in ${CLEANUP_ONLY_PIDS[@]+"${CLEANUP_ONLY_PIDS[@]}"}; do
        if [[ "$pid" != "$remove_pid" ]]; then
            new_pids+=("$pid")
        fi
    done
    CLEANUP_ONLY_PIDS=("${new_pids[@]+"${new_pids[@]}"}")
}

# Semaphore for limiting parallel jobs
declare -i RUNNING_JOBS=0

wait_for_slot() {
    while (( RUNNING_JOBS >= MAX_PARALLEL_SERVICES )); do
        # Reap any finished children to avoid zombies
        local new_pids=()
        for pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"}; do
            if kill -0 "$pid" 2>/dev/null; then
                new_pids+=("$pid")
            else
                wait "$pid" 2>/dev/null || true
                (( RUNNING_JOBS-- )) || true
            fi
        done
        CHILD_PIDS=("${new_pids[@]+"${new_pids[@]}"}")
        if (( RUNNING_JOBS >= MAX_PARALLEL_SERVICES )); then
            sleep 1
        fi
    done
}

# Launch a background enumeration function with slot management
launch_enum() {
    # $1=function_name, remaining args passed to function
    wait_for_slot
    "$@" &
    local pid=$!
    register_pid "$pid"
    (( RUNNING_JOBS++ )) || true
    info "Launched $1 (PID: $pid)"
}

# Wait for all background enumerations, reporting every 30s so the user knows what's running
wait_all_enum() {
    if (( ${#CHILD_PIDS[@]} > 0 )); then
        local _total=${#CHILD_PIDS[@]}
        info "Waiting for $_total background job(s) to finish..."
        local _w0
        _w0=$(date +%s)
        local _last_report=0
        while (( ${#CHILD_PIDS[@]} > 0 )); do
            local _alive=()
            local _pid
            for _pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"}; do
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
    RUNNING_JOBS=0
}

#------------------------------------------------------------------------------
# CLEANUP TRAP — kill all children on exit/interrupt
#------------------------------------------------------------------------------
cleanup() {
    echo ""
    warn "Caught interrupt — cleaning up background jobs..."
    local pid=""
    for pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"} ${CLEANUP_ONLY_PIDS[@]+"${CLEANUP_ONLY_PIDS[@]}"}; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
        fi
    done
    # Give them a moment, then force-kill
    sleep 1
    for pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"} ${CLEANUP_ONLY_PIDS[@]+"${CLEANUP_ONLY_PIDS[@]}"}; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
        fi
    done
    warn "Cleanup complete. Partial results are in ${RECON_DIR}/"
    exit 130
}

trap cleanup INT TERM

#------------------------------------------------------------------------------
# INPUT VALIDATION
#------------------------------------------------------------------------------
is_valid_ip() {
    local ip="$1"
    # Accept IPv4. Also accept hostnames (useful for OffSec boxes).
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Validate each octet
        IFS='.' read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            (( octet > 255 )) && return 1
        done
        return 0
    elif [[ "$ip" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$ ]]; then
        # Hostname format — must resolve via DNS or /etc/hosts
        if getent hosts "$ip" >/dev/null 2>&1; then
            return 0
        fi
        return 1
    fi
    return 1
}

check_tool() {
    if command -v "$1" &>/dev/null; then
        return 0
    else
        warn "Tool not found: $1 (some enumeration will be skipped)"
        return 1
    fi
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

#------------------------------------------------------------------------------
# PORT CLASSIFICATION HELPERS
#------------------------------------------------------------------------------
is_http_port() {
    local port="$1"
    local service="$2"
    # Match by common port numbers OR by nmap service name
    case "$port" in
        80|443|8080|8443|8000|8888|8081|9090|3000|5000|8180|4443|9443) return 0 ;;
    esac
    [[ "$service" =~ http|https|ssl/http|web ]] && return 0
    return 1
}

is_ssl_port() {
    local port="$1"
    local service="$2"
    case "$port" in
        443|8443|4443|9443) return 0 ;;
    esac
    [[ "$service" =~ ssl|https|tls ]] && return 0
    return 1
}

is_web_brute_target() {
    # Returns 1 for HTTP-like management ports that are not real web apps.
    # WinRM (5985/5986) and Windows HTTPAPI (47001) respond to HTTP requests
    # but have no web content worth brute-forcing — nikto/gobuster/ferox waste
    # minutes on them and find nothing meaningful.
    local port="$1"
    case "$port" in
        5985|5986|47001) return 1 ;;
    esac
    return 0
}

is_nonempty_file() {
    [[ -f "$1" && -s "$1" ]]
}

tcp_service_lines() {
    local target_dir="$1"
    [[ -f "$target_dir/scans/nmap_tcp.nmap" ]] || return 0
    grep -P '^\d+/tcp\s+open\s' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null || true
}

detected_tcp_port() {
    local target_dir="$1"
    local port="$2"
    tcp_service_lines "$target_dir" | grep -qP "^${port}/tcp\s+open\s"
}

first_detected_port() {
    local target_dir="$1"
    local pattern="$2"
    tcp_service_lines "$target_dir" | awk -v pat="$pattern" 'BEGIN{IGNORECASE=1} $0 ~ pat {sub(/\/tcp.*/, "", $1); print $1; exit}'
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

http_proto_for_port() {
    local port="$1"
    case "$port" in
        443|8443|4443|9443|5986) echo "https" ;;
        *) echo "http" ;;
    esac
}

#------------------------------------------------------------------------------
# QUICK-WINS TRIAGE — 5-minute fast check per target
#------------------------------------------------------------------------------
QUICK_WINS_MODE=false
QUICK_WINS_ONLY=false

# Score tracking: associative array ip→score
declare -A QW_SCORES=()
declare -A QW_REASONS=()

qw_triage_target() {
    local ip="$1"
    local target_dir="${RECON_DIR}/${ip}"
    local qw_file="${target_dir}/loot/quick_wins.txt"
    local score=0
    local reasons=""

    mkdir -p "$target_dir"/{scans,loot}

    phase "Quick-Wins Triage → ${ip}"

    # 1. Fast nmap scan (top 100 ports, version detect, 90s timeout)
    local nmap_quick="${target_dir}/scans/nmap_quick.nmap"
    if [[ ! -f "$nmap_quick" ]]; then
        info "Fast port scan (top 100)..."
        timeout 90 nmap -sV -sC --top-ports 100 -T4 --open -oN "$nmap_quick" "$ip" 2>/dev/null || true
    fi

    if [[ ! -s "$nmap_quick" ]]; then
        warn "  No nmap output — target may be down"
        echo "SCORE: 0 — no open ports or target down" > "$qw_file"
        QW_SCORES["$ip"]=0
        QW_REASONS["$ip"]="no response"
        return
    fi

    # Count open ports (more ports = more attack surface)
    local port_count
    port_count=$(grep -cP '^\d+/tcp\s+open' "$nmap_quick" 2>/dev/null); port_count=${port_count:-0}
    (( score += port_count ))

    # 2. Check anonymous FTP
    if grep -qP '21/tcp\s+open' "$nmap_quick" 2>/dev/null; then
        if grep -qi "Anonymous FTP login allowed" "$nmap_quick" 2>/dev/null; then
            (( score += 5 ))
            reasons+="ANON_FTP "
            success "  ★ Anonymous FTP allowed!"
        fi
    fi

    # 3. Check anonymous SMB
    if grep -qP '445/tcp\s+open' "$nmap_quick" 2>/dev/null; then
        local smb_out
        smb_out=$(timeout 15 smbclient -L "//${ip}" -N 2>&1) || true
        if echo "$smb_out" | grep -qiE 'Sharename|IPC\$'; then
            local share_count
            share_count=$(echo "$smb_out" | grep -c 'Disk' 2>/dev/null); share_count=${share_count:-0}
            if (( share_count > 0 )); then
                (( score += 3 + share_count ))
                reasons+="ANON_SMB(${share_count}_shares) "
                success "  ★ Anonymous SMB — ${share_count} share(s) visible!"
            fi
        fi
    fi

    # 4. Check for HTTP services and probe for easy wins
    local http_ports
    http_ports=$(grep -oP '(\d+)/tcp\s+open\s+\S*http' "$nmap_quick" 2>/dev/null | grep -oP '^\d+' | head -5)
    for hp in $http_ports; do
        local proto="http"
        (( hp == 443 || hp == 8443 )) && proto="https"

        # robots.txt
        local robots
        robots=$(timeout 10 curl -sk "${proto}://${ip}:${hp}/robots.txt" 2>/dev/null) || true
        if [[ -n "$robots" ]] && echo "$robots" | grep -qiE 'Disallow|Allow'; then
            (( score += 2 ))
            reasons+="ROBOTS(${hp}) "
            echo "$robots" >> "$qw_file"
            # Check for sensitive paths
            if echo "$robots" | grep -qiE 'admin|backup|secret|password|private|config|database|upload'; then
                (( score += 3 ))
                reasons+="SENSITIVE_PATHS(${hp}) "
                success "  ★ Sensitive paths in robots.txt on port ${hp}!"
            fi
        fi

        # HTML comments with passwords
        local index
        index=$(timeout 10 curl -sk "${proto}://${ip}:${hp}/" 2>/dev/null) || true
        if [[ -n "$index" ]]; then
            local pw_comments
            pw_comments=$(echo "$index" | grep -oP '<!--.*?-->' | grep -iE 'pass|pwd|cred|secret|login|admin|TODO|FIXME|hack' 2>/dev/null) || true
            if [[ -n "$pw_comments" ]]; then
                (( score += 5 ))
                reasons+="HTML_COMMENT(${hp}) "
                success "  ★ Interesting HTML comments on port ${hp}!"
                echo "$pw_comments" >> "$qw_file"
            fi
        fi

        # Default creds on common login pages
        local login_page
        for path in "/login" "/admin" "/wp-login.php" "/phpmyadmin/"; do
            login_page=$(timeout 5 curl -sk -o /dev/null -w "%{http_code}" "${proto}://${ip}:${hp}${path}" 2>/dev/null) || true
            if [[ "$login_page" == "200" || "$login_page" == "301" || "$login_page" == "302" ]]; then
                (( score += 2 ))
                reasons+="LOGIN_PAGE(${hp}${path}) "
                info "  Login page found: ${proto}://${ip}:${hp}${path}"
            fi
        done
    done

    # 5. Searchsploit against service versions
    if command -v searchsploit &>/dev/null; then
        local services
        services=$(grep -oP '\d+/tcp\s+open\s+\S+\s+\K.+' "$nmap_quick" 2>/dev/null | head -10)
        if [[ -n "$services" ]]; then
            local sploit_out
            sploit_out=$(timeout 30 searchsploit --nmap "$nmap_quick" 2>/dev/null) || true
            if [[ -n "$sploit_out" ]] && echo "$sploit_out" | grep -qvE '^$|No Results|Exploit Title'; then
                local exploit_count
                exploit_count=$(echo "$sploit_out" | grep -cP '\S+\s+\|' 2>/dev/null); exploit_count=${exploit_count:-0}
                if (( exploit_count > 0 )); then
                    (( score += exploit_count * 3 ))
                    reasons+="EXPLOITS(${exploit_count}) "
                    success "  ★ ${exploit_count} potential exploit(s) found via searchsploit!"
                    echo "$sploit_out" >> "$qw_file"
                fi
            fi
        fi
    fi

    # Write results
    {
        echo "QUICK-WINS TRIAGE: ${ip}"
        echo "Score: ${score}"
        echo "Reasons: ${reasons:-none}"
        echo "Open ports: ${port_count}"
        echo ""
    } >> "$qw_file"

    QW_SCORES["$ip"]=$score
    QW_REASONS["$ip"]="${reasons:-none}"
    success "Triage score for ${ip}: ${BOLD}${score}${NC} [${reasons:-clean}]"
}

qw_rank_targets() {
    local priority_file="${RECON_DIR}/target_priority.txt"

    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  TARGET PRIORITY — Attack easiest first${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Sort by score descending
    local sorted
    sorted=$(for ip in "${!QW_SCORES[@]}"; do
        echo "${QW_SCORES[$ip]} $ip ${QW_REASONS[$ip]}"
    done | sort -rn)

    local rank=1
    {
        echo "TARGET PRIORITY — $(date)"
        echo "═══════════════════════════════"
        echo ""
    } > "$priority_file"

    while read -r score ip reasons; do
        [[ -z "$ip" ]] && continue
        local color="$NC"
        if (( score >= 10 )); then
            color="$GREEN"
        elif (( score >= 5 )); then
            color="$YELLOW"
        else
            color="$RED"
        fi
        echo -e "  ${BOLD}#${rank}${NC} ${color}${ip}${NC}  score=${score}  ${CYAN}[${reasons}]${NC}"
        echo "#${rank}  ${ip}  score=${score}  [${reasons}]" >> "$priority_file"
        (( rank++ ))
    done <<< "$sorted"

    echo ""
    echo -e "${BOLD}Recommendation:${NC} Start with #1 (highest attack surface)"
    echo -e "Priority file: ${CYAN}${priority_file}${NC}"
    echo ""
}

#------------------------------------------------------------------------------
# PHASE 1: RUSTSCAN — Fast TCP Port Discovery
#------------------------------------------------------------------------------
run_rustscan() {
    local ip="$1"
    local target_dir="$2"
    local outfile="$target_dir/scans/rustscan_tcp.txt"

    if is_phase_done "$target_dir" "rustscan"; then
        info "Rustscan already completed for $ip — skipping (delete progress.log to re-run)"
        return 0
    fi

    phase "TCP Port Discovery (rustscan) → $ip"
    progress_log "$target_dir" "START" "rustscan" "batch_size=$RUSTSCAN_BATCH_SIZE"
    _tool_start "rustscan" "$ip" "300s  batch: $RUSTSCAN_BATCH_SIZE"
    local _rs_t0
    _rs_t0=$(date +%s)

    # rustscan 2.4.x outputs "Open <IP>:<PORT>" lines when NOT in greppable mode.
    # --scripts none = skip nmap handoff (replaces deprecated --no-nmap)
    # NO --greppable: we need the "Open IP:PORT" lines for parsing.
    # Final summary line "IP -> [port,port]" is also printed with --scripts none.
    timeout 300 rustscan -a "$ip" \
        --range 1-65535 \
        -b "$RUSTSCAN_BATCH_SIZE" \
        --timeout "$RUSTSCAN_TIMEOUT" \
        --scripts none \
        --no-banner \
        2>&1 | tee "$outfile"
    local rustscan_exit=$?
    _tool_done "rustscan" "$_rs_t0"
    if [[ $rustscan_exit -ne 0 ]]; then
        error "Rustscan failed or timed out for $ip"
        progress_log "$target_dir" "FAIL" "rustscan" "exit=$rustscan_exit"
        return 1
    fi

    # Parse open ports from rustscan output
    # Format 1 (per-port): "Open 10.10.10.5:22"
    local ports=""
    ports=$(grep -oP 'Open \S+:\K[0-9]+' "$outfile" 2>/dev/null | sort -un | tr '\n' ',' | sed 's/,$//')

    if [[ -z "$ports" ]]; then
        # Format 2 (summary line): "10.10.10.5 -> [22,80,443]"
        ports=$(grep -oP '\->\s*\[\K[^\]]+' "$outfile" 2>/dev/null | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
    fi

    if [[ -z "$ports" ]]; then
        # Format 3 (older rustscan): lines with port/open
        ports=$(grep -oP '(?:^|\s)(\d+)(?:/open)' "$outfile" 2>/dev/null | grep -oP '\d+' | sort -un | tr '\n' ',' | sed 's/,$//')
    fi

    if [[ -z "$ports" ]]; then
        warn "No open TCP ports found on $ip"
        echo "NO_OPEN_PORTS" > "$target_dir/scans/tcp_ports.txt"
        progress_log "$target_dir" "DONE" "rustscan" "ports=NONE"
        return 0
    fi

    echo "$ports" > "$target_dir/scans/tcp_ports.txt"
    local port_count=""
    port_count=$(echo "$ports" | tr ',' '\n' | wc -l)
    success "Found $port_count open TCP port(s) on $ip: $ports"
    progress_log "$target_dir" "DONE" "rustscan" "ports=$ports"
    return 0
}

#------------------------------------------------------------------------------
# PHASE 2: NMAP TCP — Service Detection on Found Ports
#------------------------------------------------------------------------------
run_nmap_tcp() {
    local ip="$1"
    local target_dir="$2"
    local ports_file="$target_dir/scans/tcp_ports.txt"
    local outbase="$target_dir/scans/nmap_tcp"

    if is_phase_done "$target_dir" "nmap_tcp"; then
        info "Nmap TCP already completed for $ip — skipping"
        return 0
    fi

    local ports=""
    ports=$(cat "$ports_file" 2>/dev/null)
    if [[ -z "$ports" || "$ports" == "NO_OPEN_PORTS" ]]; then
        warn "No TCP ports to scan for $ip"
        return 0
    fi

    phase "TCP Service Detection (nmap) → $ip"
    progress_log "$target_dir" "START" "nmap_tcp" "ports=$ports"

    # -sC: default scripts, -sV: version detection, -O: OS detection (requires root)
    # -oA: output in all formats (grep, xml, nmap) — nmap XML is useful for parsing
    local nmap_flags=(-sC -sV -p "$ports" --open -oA "$outbase")

    if [[ $EUID -eq 0 ]]; then
        # Running as root — include OS detection
        nmap_flags+=(-O)
    else
        # Not root — -O would fail and could break the scan
        warn "Not running as root — skipping nmap -O (OS detection). Run as root for full results."
    fi

    _tool_start "nmap -sCV" "$ip" "${NMAP_TCP_TIMEOUT}s  ports: $ports"
    local _nmap_t0
    _nmap_t0=$(date +%s)
    local tcp_scan_ok=true
    if ! timeout "$NMAP_TCP_TIMEOUT" nmap "${nmap_flags[@]}" \
        "$ip" 2>&1 | tee "$target_dir/scans/nmap_tcp_console.txt"; then
        tcp_scan_ok=false
        error "Nmap TCP scan failed or timed out for $ip"
        progress_log "$target_dir" "FAIL" "nmap_tcp" "timeout=${NMAP_TCP_TIMEOUT}s"
        warn "Partial TCP scan output may still exist in $target_dir/scans/"
    fi
    _tool_done "nmap -sCV" "$_nmap_t0"

    if [[ "$tcp_scan_ok" == "true" ]]; then
        success "Nmap TCP scan complete for $ip"
        progress_log "$target_dir" "DONE" "nmap_tcp" "output=$outbase"
        return 0
    fi

    return 1
}

#------------------------------------------------------------------------------
# PHASE 3: NMAP UDP — Top Ports (SNMP is OffSec gold)
#------------------------------------------------------------------------------
run_nmap_udp() {
    local ip="$1"
    local target_dir="$2"
    local outbase="$target_dir/scans/nmap_udp"

    if is_phase_done "$target_dir" "nmap_udp"; then
        info "Nmap UDP already completed for $ip — skipping"
        return 0
    fi

    phase "UDP Top-Port Scan (nmap) → $ip"
    progress_log "$target_dir" "START" "nmap_udp" "top_ports=$UDP_TOP_PORTS"

    # UDP scanning requires root. Do not prompt with sudo from a background job.
    if [[ $EUID -ne 0 ]]; then
        warn "UDP scan requires root privileges — skipping in non-root mode"
        progress_log "$target_dir" "SKIP" "nmap_udp" "requires_root=true"
        return 0
    fi

    # --- Pass 1: Top ports (fast, gets you going) ---
    _tool_start "nmap -sU" "$ip" "${NMAP_UDP_TIMEOUT}s  top: $UDP_TOP_PORTS ports"
    local _udp_t0
    _udp_t0=$(date +%s)
    info "Scanning top $UDP_TOP_PORTS UDP ports (this runs in background)"

    local udp_scan_ok=true
    timeout "$NMAP_UDP_TIMEOUT" nmap -sU -sV \
        --top-ports "$UDP_TOP_PORTS" \
        --open \
        --version-intensity 0 \
        -oA "$outbase" \
        "$ip" 2>&1 | tee "$target_dir/scans/nmap_udp_console.txt" || udp_scan_ok=false
    _tool_done "nmap -sU" "$_udp_t0"
    if [[ "$udp_scan_ok" == "false" ]]; then
        warn "Nmap UDP scan failed or timed out for $ip (this is normal if not root)"
        progress_log "$target_dir" "FAIL" "nmap_udp" "timeout=${NMAP_UDP_TIMEOUT}s"
    fi

    # --- Pass 2: Full UDP scan (only if --udp-full flag set) ---
    if [[ "$UDP_FULL" == "true" ]] && ! is_phase_done "$target_dir" "nmap_udp_full"; then
        info "Full UDP scan requested (--udp-full) — scanning all 65535 ports"
        info "This will take a LONG time. Results saved as nmap_udp_full.*"
        warn "Tip: if you're stuck on a box, this is worth the wait"
        progress_log "$target_dir" "START" "nmap_udp_full" "ports=1-65535"

        # Use aggressive timing and skip version detection to speed it up
        # --max-retries 1 cuts time dramatically (at slight accuracy cost)
        timeout 3600 nmap -sU \
            -p 1-65535 \
            --open \
            --max-retries 1 \
            --min-rate 500 \
            -T4 \
            -oA "${outbase}_full" \
            "$ip" 2>&1 | tee "$target_dir/scans/nmap_udp_full_console.txt" || true

        # Merge any new ports into udp_ports.txt
        local full_udp_ports=""
        full_udp_ports=$(grep -P '^\d+/udp\s+open\s' "${outbase}_full.nmap" 2>/dev/null | \
            awk '{print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$full_udp_ports" ]]; then
            success "Full UDP scan found ports: $full_udp_ports"
            # Merge with existing
            {
                cat "$target_dir/scans/udp_ports.txt" 2>/dev/null
                echo "$full_udp_ports"
            } | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//' \
                > "$target_dir/scans/udp_ports_merged.txt"
            mv "$target_dir/scans/udp_ports_merged.txt" "$target_dir/scans/udp_ports.txt"
        fi
        progress_log "$target_dir" "DONE" "nmap_udp_full" "ports=${full_udp_ports:-NONE}"
    fi

    # Parse UDP findings
    local udp_ports=""
    udp_ports=$(grep -P '^\d+/udp\s+open\s' "${outbase}.nmap" 2>/dev/null | awk '{print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
    if [[ -n "$udp_ports" ]]; then
        echo "$udp_ports" > "$target_dir/scans/udp_ports.txt"
        success "Found open UDP port(s): $udp_ports"
    else
        info "No open UDP ports found (or all filtered)"
    fi

    if [[ "$udp_scan_ok" == "true" ]]; then
        progress_log "$target_dir" "DONE" "nmap_udp" "ports=${udp_ports:-NONE}"
    fi
    return 0
}

#------------------------------------------------------------------------------
# SERVICE ENUMERATION MODULES
# Each function:
#   - Takes (ip, port, target_dir) as arguments
#   - Handles its own timeout and error handling
#   - Writes to its own subdirectory
#   - Logs progress
#   - Never crashes the parent
#------------------------------------------------------------------------------

#--- HTTP/HTTPS ENUMERATION ---------------------------------------------------
enum_http() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local nmap_service="$4"
    local proto="http"
    local outdir="$target_dir/tcp/http/port_${port}"
    mkdir -p "$outdir"

    local phase_name="http_${port}"
    if is_phase_done "$target_dir" "$phase_name"; then
        info "HTTP enum already done for $ip:$port — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "$phase_name" ""

    # Determine HTTP vs HTTPS
    if is_ssl_port "$port" "$nmap_service"; then
        proto="https"
    fi
    local url="${proto}://${ip}:${port}"

    info "HTTP enumeration starting: $url"

    # --- WhatWeb (quick fingerprint) ---
    if check_tool whatweb; then
        info "  → whatweb $url"
        timeout "$GENERIC_TIMEOUT" whatweb -a 3 "$url" \
            > "$outdir/whatweb.txt" 2>&1 || true
    fi

    # --- Curl headers (always useful, fast) ---
    info "  → curl headers $url"
    timeout 15 curl -skIL "$url" > "$outdir/curl_headers.txt" 2>&1 || true

    # --- HTTP methods (only recorded; next-step logic decides if risky) ---
    info "  → HTTP OPTIONS methods $url"
    timeout 15 curl -skIX OPTIONS "$url" > "$outdir/http_methods.txt" 2>&1 || true

    # --- Check for robots.txt ---
    info "  → checking robots.txt"
    timeout 15 curl -sk "${url}/robots.txt" > "$outdir/robots.txt" 2>&1 || true
    # If robots.txt is a 404-like response, note it
    if grep -qiE '<!DOCTYPE|<html|not found|404' "$outdir/robots.txt" 2>/dev/null; then
        echo "# No robots.txt found (got HTML/404 response)" > "$outdir/robots.txt"
    fi

    # --- Nikto / Gobuster / Feroxbuster ---
    # Skip brute-force tools on WinRM/management HTTP endpoints (5985, 5986, 47001).
    # These respond with HTTP but have no meaningful web content to enumerate.
    if is_web_brute_target "$port"; then
        # --- Nikto (vulnerability scanner) ---
        if check_tool nikto; then
            _tool_start "nikto" "$url" "${NIKTO_TIMEOUT}s"
            local _nikto_t0
            _nikto_t0=$(date +%s)
            # Note: do NOT pass -Format txt when -o already ends in .txt — older nikto
            # versions produce nikto.txt.txt with both flags set.
            timeout "$NIKTO_TIMEOUT" nikto -h "$url" -o "$outdir/nikto.txt" \
                -nointeractive 2>&1 | tail -5 || true
            _tool_done "nikto" "$_nikto_t0"
        fi

        # --- Gobuster (directory brute-force) ---
        if check_tool gobuster; then
            if [[ -f "$GOBUSTER_WORDLIST" ]]; then
                _tool_start "gobuster" "$url" "${GOBUSTER_RUNTIME}s  req-timeout: ${GOBUSTER_TIMEOUT}s"
                local _gobuster_t0
                _gobuster_t0=$(date +%s)
                local gobuster_flags=(-u "$url" -w "$GOBUSTER_WORDLIST" \
                    -t "$GOBUSTER_THREADS" \
                    --timeout "${GOBUSTER_TIMEOUT}s" \
                    -o "$outdir/gobuster_dir.txt" \
                    -x "$GOBUSTER_EXTENSIONS" \
                    --no-error -q)
                # Add -k for HTTPS (skip cert verification)
                [[ "$proto" == "https" ]] && gobuster_flags+=(-k)

                timeout "$GOBUSTER_RUNTIME" gobuster dir "${gobuster_flags[@]}" 2>&1 | tail -3 || true
                _tool_done "gobuster" "$_gobuster_t0"
            else
                warn "  Gobuster wordlist not found: $GOBUSTER_WORDLIST"
            fi
        fi

        # --- Feroxbuster (recursive, only when gobuster is sparse on a real web port) ---
        if check_tool feroxbuster; then
            local gobuster_hits=""
            # Count only actual result lines (start with /) — wc -l is unreliable due to gobuster headers
            gobuster_hits=$(grep -c '^/' "$outdir/gobuster_dir.txt" 2>/dev/null); gobuster_hits=${gobuster_hits:-0}
            if (( gobuster_hits < 5 )); then
                info "  → feroxbuster $url (gobuster found <5 results, trying recursive)"
                _tool_start "feroxbuster" "$url" "${FEROX_RUNTIME}s"
                local _ferox_t0
                _ferox_t0=$(date +%s)
                local ferox_flags=(-u "$url" -w "$GOBUSTER_WORDLIST" \
                    -t 30 --timeout 30 -d 2 -q \
                    -o "$outdir/feroxbuster.txt")
                [[ "$proto" == "https" ]] && ferox_flags+=(-k)
                timeout "$FEROX_RUNTIME" feroxbuster "${ferox_flags[@]}" 2>&1 | tail -3 || true
                _tool_done "feroxbuster" "$_ferox_t0"
            fi
        fi
    else
        info "  → skipping nikto/gobuster/feroxbuster on port $port (WinRM/management HTTP — not a web app)"
        echo "# Port $port: WinRM/HTTPAPI endpoint — brute-force tools skipped" > "$outdir/brute_skip.txt"
    fi

    # --- ffuf vhost fuzz (if hostname detected) ---
    # Runs before progress_log DONE so phase resume re-runs it if interrupted
    if check_tool ffuf && [[ -f "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" ]]; then
        # Only run if we have a hostname (not a bare IP)
        if [[ "$ip" =~ [a-zA-Z] ]]; then
            info "  → ffuf vhost fuzz $url"
            local baseline_size=""
            baseline_size=$(curl -sk "${url}/$(tr -dc '[:lower:]' </dev/urandom | head -c12)" -o /dev/null -w '%{size_download}' 2>/dev/null || echo "0")
            timeout 300 ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
                -u "$url" -H "Host: FUZZ.${ip}" -fs "$baseline_size" \
                -t 30 -noninteractive -of json -o "$outdir/ffuf_vhosts.json" \
                2>/dev/null || true
            if [[ -f "$outdir/ffuf_vhosts.json" ]]; then
                local vhost_count=""
                if command -v jq &>/dev/null; then
                    vhost_count=$(jq '.results | length' "$outdir/ffuf_vhosts.json" 2>/dev/null || echo "0")
                else
                    # Count result objects by their unique "url" field (one per result)
                    vhost_count=$(grep -c '"url"' "$outdir/ffuf_vhosts.json" 2>/dev/null); vhost_count=${vhost_count:-0}
                fi
                if (( vhost_count > 0 )); then
                    success "  ★ ffuf found $vhost_count potential vhost(s) → $outdir/ffuf_vhosts.json"
                    echo "VHOSTS found on $ip:$port — see $outdir/ffuf_vhosts.json" >> "$target_dir/loot/quick_wins.txt"
                else
                    info "  ffuf vhost fuzz complete — no vhosts found"
                fi
            fi
        fi
    fi

    success "HTTP enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "$phase_name" "proto=$proto"
}

#--- SMB ENUMERATION ----------------------------------------------------------
enum_smb() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/smb"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "smb"; then
        info "SMB enum already done for $ip — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "smb" "port=$port"

    info "SMB enumeration starting: $ip"

    # --- enum4linux-ng (comprehensive SMB enumeration) ---
    if check_tool enum4linux-ng; then
        _tool_start "enum4linux-ng" "$ip" "${ENUM4LINUX_TIMEOUT}s"
        local _e4l_t0
        _e4l_t0=$(date +%s)
        timeout "$ENUM4LINUX_TIMEOUT" enum4linux-ng -A "$ip" \
            -oJ "$outdir/enum4linux" 2>&1 | tee "$outdir/enum4linux_console.txt" | tail -10 || true
        _tool_done "enum4linux-ng" "$_e4l_t0"
    elif check_tool enum4linux; then
        # Fallback to classic enum4linux
        _tool_start "enum4linux" "$ip" "${ENUM4LINUX_TIMEOUT}s"
        local _e4l_t0
        _e4l_t0=$(date +%s)
        timeout "$ENUM4LINUX_TIMEOUT" enum4linux -a "$ip" \
            > "$outdir/enum4linux.txt" 2>&1 || true
        _tool_done "enum4linux" "$_e4l_t0"
    fi

    # --- smbmap (share enumeration with access levels) ---
    if check_tool smbmap; then
        info "  → smbmap $ip (null session)"
        timeout "$SMBMAP_TIMEOUT" smbmap -H "$ip" \
            > "$outdir/smbmap_null.txt" 2>&1 || true

        # Guest access too
        info "  → smbmap $ip (guest session)"
        timeout "$SMBMAP_TIMEOUT" smbmap -H "$ip" -u 'guest' -p '' \
            > "$outdir/smbmap_guest.txt" 2>&1 || true
    fi

    # --- smbclient (list shares with null session) ---
    if check_tool smbclient; then
        info "  → smbclient list shares $ip"
        timeout 30 smbclient -L "//$ip" -N \
            > "$outdir/smbclient_list.txt" 2>&1 || true
    fi

    # --- netexec for quick wins ---
    if check_tool netexec; then
        info "  → netexec smb $ip"
        timeout "$GENERIC_TIMEOUT" netexec smb "$ip" --shares -u '' -p '' \
            > "$outdir/netexec_shares.txt" 2>&1 || true
    fi

    # --- Extract notable findings ---
    {
        echo "=== SMB Quick Findings for $ip ==="
        echo ""
        if [[ -f "$outdir/smbmap_null.txt" ]]; then
            echo "--- Readable Shares (null session) ---"
            grep -E 'READ|WRITE' "$outdir/smbmap_null.txt" 2>/dev/null || echo "  (none)"
        fi
        if [[ -f "$outdir/smbmap_guest.txt" ]]; then
            echo ""
            echo "--- Readable Shares (guest session) ---"
            grep -E 'READ|WRITE' "$outdir/smbmap_guest.txt" 2>/dev/null || echo "  (none)"
        fi
    } > "$outdir/smb_quick_findings.txt"

    success "SMB enumeration complete for $ip"
    progress_log "$target_dir" "DONE" "smb" ""
}

#--- FTP ENUMERATION ----------------------------------------------------------
enum_ftp() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/ftp"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "ftp"; then
        info "FTP enum already done for $ip — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "ftp" "port=$port"

    info "FTP enumeration starting: $ip:$port"

    if ! check_tool nc; then
        warn "  nc (netcat) not found — FTP banner/anonymous checks will be skipped"
    else
        # --- Banner grab ---
        info "  → banner grab"
        # shellcheck disable=SC2016
        timeout "$FTP_TIMEOUT" bash -c 'printf "QUIT\r\n" | nc -w 5 "$1" "$2"' \
            -- "$ip" "$port" > "$outdir/banner.txt" 2>&1 || true

        # --- Anonymous login check ---
        info "  → anonymous login check"
        # shellcheck disable=SC2016
        timeout "$FTP_TIMEOUT" bash -c '
            (
                sleep 1; printf "USER anonymous\r\n";
                sleep 1; printf "PASS anonymous@test.com\r\n";
                sleep 1; printf "PASV\r\n";
                sleep 1; printf "LIST\r\n";
                sleep 2; printf "QUIT\r\n";
            ) | nc -w 10 "$1" "$2"
        ' -- "$ip" "$port" > "$outdir/anonymous_check.txt" 2>&1 || true
    fi

    # Check if anonymous login succeeded — anchor ^230 to avoid false positive on version strings
    if [[ -f "$outdir/anonymous_check.txt" ]] && \
       grep -qiE '^230 |Login successful|logged in' "$outdir/anonymous_check.txt" 2>/dev/null; then
        success "  ★ ANONYMOUS FTP LOGIN SUCCESSFUL on $ip:$port ★"
        echo "ANONYMOUS FTP LOGIN SUCCESSFUL" > "$outdir/ANONYMOUS_ACCESS.txt"
        echo "ANONYMOUS FTP LOGIN SUCCESSFUL on $ip:$port" >> "$target_dir/loot/quick_wins.txt"

        # Try to download everything with wget
        if check_tool wget; then
            info "  → mirroring FTP content (anonymous)"
            mkdir -p "$outdir/mirror"
            timeout 120 wget -r -l 3 --no-passive-ftp \
                "ftp://anonymous:anon@${ip}:${port}/" \
                -P "$outdir/mirror/" 2>&1 | tail -5 || true
        fi
    else
        info "  Anonymous login not available"
    fi

    # --- Nmap FTP scripts for deeper checks ---
    info "  → nmap FTP scripts"
    timeout 120 nmap --script=ftp-anon,ftp-bounce,ftp-syst \
        -p "$port" -oN "$outdir/nmap_ftp_scripts.txt" "$ip" 2>&1 | tail -5 || true

    success "FTP enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "ftp" ""
}

#--- SSH ENUMERATION ----------------------------------------------------------
enum_ssh() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/ssh"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "ssh"; then
        info "SSH enum already done for $ip — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "ssh" "port=$port"

    info "SSH enumeration starting: $ip:$port"

    # --- Version/Banner grab ---
    if check_tool nc; then
        info "  → banner grab"
        # shellcheck disable=SC2016
        timeout 10 bash -c 'echo "" | nc -w 5 "$1" "$2"' \
            -- "$ip" "$port" > "$outdir/banner.txt" 2>&1 || true
    fi

    # --- Nmap SSH scripts ---
    info "  → nmap SSH scripts"
    timeout 120 nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods \
        -p "$port" -oN "$outdir/nmap_ssh_scripts.txt" "$ip" 2>&1 | tail -5 || true

    # --- Note version for known vulnerabilities ---
    local ssh_version=""
    ssh_version=$(head -1 "$outdir/banner.txt" 2>/dev/null | tr -d '\r\n')
    if [[ -n "$ssh_version" ]]; then
        echo "SSH Version: $ssh_version" > "$outdir/version_info.txt"
        success "  SSH version: $ssh_version"

        # Flag old/vulnerable versions
        if echo "$ssh_version" | grep -qiE 'OpenSSH_[1-6]\.|OpenSSH_7\.[0-1]|dropbear'; then
            warn "  ★ Potentially vulnerable SSH version: $ssh_version"
            echo "POTENTIALLY VULNERABLE SSH: $ssh_version on $ip:$port" \
                >> "$target_dir/loot/quick_wins.txt"
            warn "  → Next steps for vulnerable SSH:"
            warn "    searchsploit openssh $(echo "$ssh_version" | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+')"
            warn "    ssh-audit $ip -p $port               # detailed vuln report"
            warn "    ./crackr.sh --hydra ssh --target $ip  # if no creds yet"
        fi
    fi

    success "SSH enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "ssh" "version=${ssh_version:-unknown}"
}

#--- SNMP ENUMERATION ---------------------------------------------------------
enum_snmp() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/udp/snmp"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "snmp"; then
        info "SNMP enum already done for $ip — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "snmp" "port=$port"

    info "SNMP enumeration starting: $ip:$port"

    # --- Brute-force community strings with onesixtyone ---
    if check_tool onesixtyone; then
        info "  → onesixtyone community string brute"
        # Create temp community list
        local comm_file=""
        comm_file=$(mktemp)
        printf '%s\n' "${SNMP_COMMUNITY_STRINGS[@]}" > "$comm_file"
        # Also try the kali default list if it exists
        if [[ -f /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt ]]; then
            cat /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt >> "$comm_file"
        elif [[ -f /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt ]]; then
            cat /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt >> "$comm_file"
        fi
        sort -u "$comm_file" -o "$comm_file"
        timeout 60 onesixtyone -c "$comm_file" "$ip" \
            > "$outdir/onesixtyone.txt" 2>&1 || true
        rm -f "$comm_file"

        # Check for found community strings
        local found_strings=""
        found_strings=$(grep -oP '\[\K[^\]]+' "$outdir/onesixtyone.txt" 2>/dev/null | sort -u)
        if [[ -n "$found_strings" ]]; then
            success "  ★ Found SNMP community string(s): $found_strings"
            echo "$found_strings" > "$outdir/valid_community_strings.txt"
            echo "SNMP community strings found on $ip: $found_strings" \
                >> "$target_dir/loot/quick_wins.txt"
        fi
    fi

    # --- SNMPwalk with common community strings ---
    if check_tool snmpwalk; then
        for community in "${SNMP_COMMUNITY_STRINGS[@]}"; do
            info "  → snmpwalk $ip (community: $community)"

            # SNMPv1
            timeout "$SNMPWALK_TIMEOUT" snmpwalk -v1 -c "$community" "$ip" \
                > "$outdir/snmpwalk_v1_${community}.txt" 2>&1 || true

            # SNMPv2c
            timeout "$SNMPWALK_TIMEOUT" snmpwalk -v2c -c "$community" "$ip" \
                > "$outdir/snmpwalk_v2c_${community}.txt" 2>&1 || true

            # Check if we got useful output (not just errors)
            if [[ -s "$outdir/snmpwalk_v2c_${community}.txt" ]] && \
               ! grep -q 'Timeout\|No Response' "$outdir/snmpwalk_v2c_${community}.txt" 2>/dev/null; then
                success "  ★ SNMP accessible with community '$community' (v2c)"

                # Targeted OID walks for juicy info
                info "  → extracting system info, processes, software, network info..."

                # System info
                timeout 30 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.2.1.1 > "$outdir/system_info.txt" 2>&1 || true

                # Running processes
                timeout 60 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.2.1.25.4.2.1.2 > "$outdir/running_processes.txt" 2>&1 || true

                # Installed software
                timeout 60 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.2.1.25.6.3.1.2 > "$outdir/installed_software.txt" 2>&1 || true

                # TCP listening ports
                timeout 30 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.2.1.6.13.1.3 > "$outdir/tcp_ports.txt" 2>&1 || true

                # Network interfaces
                timeout 30 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.2.1.2.2.1.2 > "$outdir/network_interfaces.txt" 2>&1 || true

                # ARP table (find other hosts)
                timeout 30 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.2.1.4.22.1.2 > "$outdir/arp_table.txt" 2>&1 || true

                # Process command-line arguments (may contain cleartext creds like mysql -u root -pSecret)
                timeout 60 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.2.1.25.4.2.1.5 > "$outdir/process_args.txt" 2>&1 || true

                # Windows user accounts via SNMP
                timeout 30 snmpwalk -v2c -c "$community" "$ip" \
                    1.3.6.1.4.1.77.1.2.25 > "$outdir/windows_users.txt" 2>&1 || true

                # Flag process args containing potential credentials
                if [[ -s "$outdir/process_args.txt" ]] && \
                   grep -qiE 'pass|pwd|secret|key|token|cred' "$outdir/process_args.txt" 2>/dev/null; then
                    success "  ★ Process command-line args may contain credentials!"
                    echo "SNMP process args may contain credentials on $ip — see $outdir/process_args.txt" \
                        >> "$target_dir/loot/quick_wins.txt"
                fi

                break  # Found working string, don't need to try more
            fi
        done
    fi

    success "SNMP enumeration complete for $ip"
    progress_log "$target_dir" "DONE" "snmp" ""
}

#--- MYSQL ENUMERATION --------------------------------------------------------
enum_mysql() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/mysql"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "mysql_${port}"; then
        info "MySQL enum already done for $ip:$port — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "mysql_${port}" ""

    info "MySQL enumeration starting: $ip:$port"

    # --- Banner/version ---
    if check_tool nc; then
        info "  → banner grab"
        # shellcheck disable=SC2016
        timeout 10 bash -c 'echo "" | nc -w 5 "$1" "$2"' \
            -- "$ip" "$port" > "$outdir/banner.txt" 2>&1 || true
    fi

    # --- Nmap MySQL scripts ---
    info "  → nmap MySQL scripts"
    timeout 120 nmap --script=mysql-info,mysql-enum,mysql-empty-password,mysql-databases \
        -p "$port" -oN "$outdir/nmap_mysql_scripts.txt" "$ip" 2>&1 | tail -5 || true

    # Check for empty password root login
    if grep -qi 'empty password' "$outdir/nmap_mysql_scripts.txt" 2>/dev/null; then
        success "  ★ MySQL EMPTY PASSWORD found on $ip:$port ★"
        echo "MySQL EMPTY PASSWORD on $ip:$port" >> "$target_dir/loot/quick_wins.txt"
    fi

    # --- Try anonymous/root login ---
    if check_tool mysql; then
        info "  → trying root with no password"
        timeout "$MYSQL_TIMEOUT" mysql -h "$ip" -P "$port" -u root --password='' \
            -e "SELECT version(); SHOW DATABASES; SELECT user,host FROM mysql.user;" \
            > "$outdir/root_nopass.txt" 2>&1 || true
        if ! grep -qi 'ERROR\|denied\|refused' "$outdir/root_nopass.txt" 2>/dev/null && \
           [[ -s "$outdir/root_nopass.txt" ]]; then
            success "  ★ MySQL ROOT NO-PASSWORD LOGIN SUCCESSFUL ★"
            echo "MySQL ROOT NO-PASSWORD LOGIN on $ip:$port" >> "$target_dir/loot/quick_wins.txt"
        fi
    fi

    success "MySQL enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "mysql_${port}" ""
}

#--- POSTGRESQL ENUMERATION ---------------------------------------------------
enum_postgres() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/postgres"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "postgres_${port}"; then
        info "PostgreSQL enum already done for $ip:$port — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "postgres_${port}" ""

    info "PostgreSQL enumeration starting: $ip:$port"

    # --- Nmap scripts ---
    info "  → nmap PostgreSQL scripts"
    timeout 120 nmap --script=pgsql-brute \
        --script-args='pgsql-brute.threads=5' \
        -p "$port" -oN "$outdir/nmap_pgsql_scripts.txt" "$ip" 2>&1 | tail -5 || true

    # --- Try default credentials ---
    if check_tool psql; then
        for user in postgres admin; do
            for pass in postgres admin password ""; do
                info "  → trying $user:${pass:-<empty>}"
                PGPASSWORD="$pass" timeout "$MYSQL_TIMEOUT" psql \
                    -h "$ip" -p "$port" -U "$user" \
                    -c 'SELECT version();' -c '\l' -c 'SELECT usename FROM pg_user;' \
                    > "$outdir/login_${user}_${pass:-empty}.txt" 2>&1 || true
                if ! grep -qi 'FATAL\|refused\|denied\|error' \
                    "$outdir/login_${user}_${pass:-empty}.txt" 2>/dev/null && \
                   [[ -s "$outdir/login_${user}_${pass:-empty}.txt" ]]; then
                    success "  ★ PostgreSQL LOGIN: $user:${pass:-<empty>} on $ip:$port ★"
                    echo "PostgreSQL LOGIN: $user:${pass:-<empty>} on $ip:$port" \
                        >> "$target_dir/loot/quick_wins.txt"
                    break 2
                fi
            done
        done
    fi

    success "PostgreSQL enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "postgres_${port}" ""
}

#--- DNS ENUMERATION ----------------------------------------------------------
enum_dns() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/dns"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "dns"; then
        info "DNS enum already done for $ip — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "dns" "port=$port"

    info "DNS enumeration starting: $ip:$port"

    # --- Version query ---
    if check_tool dig; then
        info "  → DNS version query"
        timeout 30 dig @"$ip" -p "$port" version.bind chaos txt \
            > "$outdir/version.txt" 2>&1 || true

        # --- Zone transfer attempt ---
        info "  → zone transfer attempt (need domain name — checking nmap output)"
        # Try to extract domain from nmap results
        local domain=""
        domain=$(grep -oP 'commonName=\K[^\s/]+' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null | head -1)
        if [[ -z "$domain" ]]; then
            domain=$(grep -oP 'Domain:\s*\K\S+' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null | head -1)
        fi
        if [[ -n "$domain" ]]; then
            info "  → attempting zone transfer for $domain"
            timeout 30 dig @"$ip" -p "$port" "$domain" axfr \
                > "$outdir/zone_transfer_${domain}.txt" 2>&1 || true
            if grep -q 'XFR size' "$outdir/zone_transfer_${domain}.txt" 2>/dev/null; then
                success "  ★ DNS ZONE TRANSFER SUCCESSFUL for $domain ★"
                echo "DNS ZONE TRANSFER SUCCESSFUL: $domain via $ip" \
                    >> "$target_dir/loot/quick_wins.txt"
            fi
        else
            info "  No domain found for zone transfer — try manually if you discover one"
            echo "# Run manually: dig @$ip <DOMAIN> axfr" > "$outdir/zone_transfer_manual.txt"
        fi
    fi

    # --- Nmap DNS scripts ---
    info "  → nmap DNS scripts"
    timeout 120 nmap --script=dns-nsid,dns-service-discovery,dns-recursion \
        -p "$port" -oN "$outdir/nmap_dns_scripts.txt" "$ip" 2>&1 | tail -5 || true

    success "DNS enumeration complete for $ip"
    progress_log "$target_dir" "DONE" "dns" ""
}

#--- SMTP ENUMERATION ---------------------------------------------------------
enum_smtp() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/smtp"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "smtp_${port}"; then
        info "SMTP enum already done for $ip:$port — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "smtp_${port}" ""

    info "SMTP enumeration starting: $ip:$port"

    # --- Banner ---
    if check_tool nc; then
        info "  → banner grab"
        # shellcheck disable=SC2016
        timeout 15 bash -c 'printf "QUIT\r\n" | nc -w 5 "$1" "$2"' \
            -- "$ip" "$port" > "$outdir/banner.txt" 2>&1 || true
    fi

    # --- Nmap SMTP scripts (VRFY, EXPN, relay check) ---
    info "  → nmap SMTP scripts"
    timeout 180 nmap --script=smtp-commands,smtp-enum-users,smtp-open-relay \
        -p "$port" -oN "$outdir/nmap_smtp_scripts.txt" "$ip" 2>&1 | tail -5 || true

    # --- VRFY user enumeration (host-level, runs once regardless of how many SMTP ports exist) ---
    # Sentinel prevents duplicate VRFY runs when both port 25 and 587 are open.
    local vrfy_sentinel="$target_dir/tcp/smtp/vrfy_done"
    if [[ ! -f "$vrfy_sentinel" ]]; then
        info "  → SMTP VRFY enumeration (host-level, port $port)"
        local users_file="/usr/share/seclists/Usernames/Names/names.txt"
        if [[ ! -f "$users_file" ]]; then
            users_file="/usr/share/wordlists/metasploit/unix_users.txt"
        fi
        if [[ -f "$users_file" ]] && check_tool nc; then
            # shellcheck disable=SC2016
            timeout 120 bash -c '
                ip="$1"; port="$2"; users_file="$3"
                while IFS= read -r user; do
                    response=$(printf "VRFY %s\r\nQUIT\r\n" "$user" | nc -w 3 "$ip" "$port" 2>/dev/null)
                    if printf "%s\n" "$response" | grep -qE "^2[0-9]{2}"; then
                        echo "VALID: $user — $response"
                    fi
                done < <(head -100 "$users_file")
            ' -- "$ip" "$port" "$users_file" > "$outdir/vrfy_users.txt" 2>&1 || true

            local valid_count=""
            valid_count=$(grep -c "^VALID:" "$outdir/vrfy_users.txt" 2>/dev/null); valid_count=${valid_count:-0}
            if (( valid_count > 0 )); then
                success "  ★ Found $valid_count valid SMTP user(s) via port $port"
                echo "SMTP VRFY found $valid_count valid users on $ip (via port $port)" \
                    >> "$target_dir/loot/quick_wins.txt"
            fi
            touch "$vrfy_sentinel"
        fi
    else
        info "  → SMTP VRFY already completed (host-level sentinel found) — skipping on port $port"
    fi

    success "SMTP enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "smtp_${port}" ""
}

#--- RPC ENUMERATION ----------------------------------------------------------
enum_rpc() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/rpc"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "rpc"; then
        info "RPC enum already done for $ip — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "rpc" "port=$port"

    info "RPC enumeration starting: $ip:$port"

    # --- rpcclient (null session) ---
    if check_tool rpcclient; then
        info "  → rpcclient null session"
        timeout 60 rpcclient -U '' -N "$ip" -c \
            'srvinfo; enumdomusers; enumdomgroups; getdompwinfo; querydispinfo' \
            > "$outdir/rpcclient_null.txt" 2>&1 || true
    fi

    # --- rpcinfo ---
    if check_tool rpcinfo; then
        info "  → rpcinfo"
        timeout 30 rpcinfo -p "$ip" > "$outdir/rpcinfo.txt" 2>&1 || true
    fi

    # --- Check for NFS shares ---
    if check_tool showmount; then
        info "  → showmount (NFS exports)"
        timeout 30 showmount -e "$ip" > "$outdir/nfs_exports.txt" 2>&1 || true
        # Look for actual export lines (paths starting with /) rather than
        # using inverted grep which false-positives on header lines
        if grep -qP '^\s*/' "$outdir/nfs_exports.txt" 2>/dev/null; then
            success "  ★ NFS exports found on $ip ★"
            echo "NFS EXPORTS on $ip:" >> "$target_dir/loot/quick_wins.txt"
            grep -P '^\s*/' "$outdir/nfs_exports.txt" >> "$target_dir/loot/quick_wins.txt"
            while IFS= read -r export_line; do
                local export_path
                export_path=$(echo "${export_line}" | awk '{print $1}')
                [[ -z "${export_path}" ]] && continue
                echo "NEXT: mkdir /mnt/nfs_${ip//\./_} && mount -t nfs ${ip}:${export_path} /mnt/nfs_${ip//\./_}" \
                    >> "$target_dir/loot/quick_wins.txt"
                echo "NEXT (no_root_squash): cp /bin/bash /mnt/nfs_${ip//\./_}/bash && chmod +s /mnt/nfs_${ip//\./_}/bash && /mnt/nfs_${ip//\./_}/bash -p" \
                    >> "$target_dir/loot/quick_wins.txt"
            done < <(grep -P '^\s*/' "$outdir/nfs_exports.txt" 2>/dev/null | head -3)
        fi
    fi

    success "RPC enumeration complete for $ip"
    progress_log "$target_dir" "DONE" "rpc" ""
}

#--- LDAP ENUMERATION ---------------------------------------------------------
enum_ldap() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/ldap"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "ldap"; then
        info "LDAP enum already done for $ip — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "ldap" "port=$port"

    info "LDAP enumeration starting: $ip:$port"

    # --- Nmap LDAP scripts ---
    info "  → nmap LDAP scripts"
    timeout 120 nmap --script=ldap-rootdse,ldap-search \
        -p "$port" -oN "$outdir/nmap_ldap_scripts.txt" "$ip" 2>&1 | tail -5 || true

    # --- ldapsearch (anonymous bind) ---
    if check_tool ldapsearch; then
        info "  → ldapsearch anonymous bind"
        # Get naming contexts first
        timeout 30 ldapsearch -x -H "ldap://${ip}:${port}" -s base \
            namingContexts > "$outdir/naming_contexts.txt" 2>&1 || true

        local base_dn=""
        base_dn=$(grep -oP 'namingContexts:\s*\K.*' "$outdir/naming_contexts.txt" 2>/dev/null | head -1)
        if [[ -n "$base_dn" ]]; then
            info "  → full anonymous dump (base: $base_dn)"
            timeout 120 ldapsearch -x -H "ldap://${ip}:${port}" -b "$base_dn" \
                > "$outdir/ldap_full_dump.txt" 2>&1 || true
            local entry_count=""
            entry_count=$(grep -c '^dn:' "$outdir/ldap_full_dump.txt" 2>/dev/null); entry_count=${entry_count:-0}
            if (( entry_count > 0 )); then
                success "  ★ LDAP anonymous bind: $entry_count entries found"
                echo "LDAP anonymous bind on $ip: $entry_count entries" \
                    >> "$target_dir/loot/quick_wins.txt"
                echo "NEXT: ldapsearch -x -H ldap://${ip}:${port} -b '${base_dn}' '(objectClass=*)' | grep -iE 'sAMAccountName|mail|description|memberOf'" \
                    >> "$target_dir/loot/quick_wins.txt"
                echo "NEXT (if domain-joined): ./adr.sh -d <DOMAIN> -u '' -p '' -dc ${ip}" \
                    >> "$target_dir/loot/quick_wins.txt"
            fi
        fi
    fi

    success "LDAP enumeration complete for $ip"
    progress_log "$target_dir" "DONE" "ldap" ""
}

#--- REDIS ENUMERATION --------------------------------------------------------
enum_redis() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/redis"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "redis_${port}"; then
        info "Redis enum already done for $ip:$port — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "redis_${port}" ""

    info "Redis enumeration starting: $ip:$port"

    # --- Info command (no auth check) ---
    if check_tool nc; then
        info "  → Redis INFO (no-auth check)"
        # shellcheck disable=SC2016
        timeout 15 bash -c 'printf "INFO\r\nQUIT\r\n" | nc -w 5 "$1" "$2"' \
            -- "$ip" "$port" > "$outdir/info_noauth.txt" 2>&1 || true

        if grep -qi 'redis_version' "$outdir/info_noauth.txt" 2>/dev/null; then
            success "  ★ Redis NO-AUTH ACCESS on $ip:$port ★"
            echo "REDIS NO-AUTH on $ip:$port" >> "$target_dir/loot/quick_wins.txt"

            # Get config and keys
            # shellcheck disable=SC2016
            timeout 15 bash -c 'printf "CONFIG GET *\r\nQUIT\r\n" | nc -w 5 "$1" "$2"' \
                -- "$ip" "$port" > "$outdir/config.txt" 2>&1 || true
            # shellcheck disable=SC2016
            timeout 15 bash -c 'printf "KEYS *\r\nQUIT\r\n" | nc -w 5 "$1" "$2"' \
                -- "$ip" "$port" > "$outdir/keys.txt" 2>&1 || true
        fi
    fi

    # --- Nmap scripts ---
    info "  → nmap Redis scripts"
    timeout 60 nmap --script=redis-info \
        -p "$port" -oN "$outdir/nmap_redis.txt" "$ip" 2>&1 | tail -3 || true

    success "Redis enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "redis_${port}" ""
}

#--- POP3 / IMAP ENUMERATION --------------------------------------------------
enum_pop3_imap() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local proto="$4"   # "pop3" or "imap"
    local outdir="$target_dir/tcp/${proto}"
    mkdir -p "$outdir"

    local phase_key="${proto}_${port}"
    if is_phase_done "$target_dir" "$phase_key"; then
        info "${proto^^} enum already done for $ip:$port — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "$phase_key" "port=$port"

    info "${proto^^} enumeration starting: $ip:$port"

    # --- Banner grab ---
    if check_tool nc; then
        info "  → banner grab"
        # shellcheck disable=SC2016
        timeout 10 bash -c 'printf "QUIT\r\n" | nc -w 5 "$1" "$2"' \
            -- "$ip" "$port" > "$outdir/banner_${port}.txt" 2>&1 || true

        local banner
        banner=$(head -1 "$outdir/banner_${port}.txt" 2>/dev/null | tr -d '\r\n')
        [[ -n "$banner" ]] && success "  Banner: $banner"

        # --- CAPABILITIES probe ---
        if [[ "$proto" == "pop3" ]]; then
            info "  → POP3 CAPA"
            # shellcheck disable=SC2016
            timeout 10 bash -c 'printf "CAPA\r\nQUIT\r\n" | nc -w 5 "$1" "$2"' \
                -- "$ip" "$port" > "$outdir/capa_${port}.txt" 2>&1 || true
        else
            info "  → IMAP CAPABILITY"
            # shellcheck disable=SC2016
            timeout 10 bash -c 'printf ". CAPABILITY\r\n. LOGOUT\r\n" | nc -w 5 "$1" "$2"' \
                -- "$ip" "$port" > "$outdir/capability_${port}.txt" 2>&1 || true
        fi
    fi

    # --- Nmap scripts ---
    if [[ "$proto" == "pop3" ]]; then
        info "  → nmap POP3 scripts"
        timeout 60 nmap --script=pop3-capabilities,pop3-ntlm-info \
            -p "$port" -oN "$outdir/nmap_pop3_${port}.txt" "$ip" 2>&1 | tail -3 || true
    else
        info "  → nmap IMAP scripts"
        timeout 60 nmap --script=imap-capabilities,imap-ntlm-info \
            -p "$port" -oN "$outdir/nmap_imap_${port}.txt" "$ip" 2>&1 | tail -3 || true
    fi

    echo "${proto^^} detected on $ip:$port — check $outdir/ for capabilities/banner" \
        >> "$target_dir/loot/quick_wins.txt"

    success "${proto^^} enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "$phase_key" ""
}

#------------------------------------------------------------------------------
# PHASE 4: SERVICE TRIAGE — Decide what to enumerate based on nmap results
#------------------------------------------------------------------------------
triage_and_enumerate() {
    local ip="$1"
    local target_dir="$2"
    local nmap_file="$target_dir/scans/nmap_tcp.nmap"

    phase "Service Triage & Auto-Enumeration → $ip"
    # Reset per-target in-process queue tracker (prevents double-launch for
    # services like SMB that appear on multiple ports: 139 and 445).
    QUEUED_PHASES=()

    if [[ ! -f "$nmap_file" ]]; then
        warn "No nmap results found for $ip — cannot triage services"
        return 1
    fi

    # Parse nmap output: extract port/proto/state/service/version lines
    # Format: "22/tcp open ssh OpenSSH 8.2p1 Ubuntu..."
    local services_found=()
    local port="" proto="" state="" service="" version=""
    while IFS= read -r line; do
        port=$(echo "$line" | awk -F'/' '{print $1}')
        proto=$(echo "$line" | awk '{print $1}' | awk -F'/' '{print $2}')
        state=$(echo "$line" | awk '{print $2}')
        service=$(echo "$line" | awk '{print $3}')
        version=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)

        [[ "$state" != "open" ]] && continue
        [[ -z "$port" ]] && continue

        services_found+=("$port:$service:$version")

        info "Found: $port/$proto → $service $version"

        # --- Decide which enumeration to launch ---
        # HTTP/HTTPS
        if is_http_port "$port" "$service"; then
            launch_enum enum_http "$ip" "$port" "$target_dir" "$service"

        # SMB
        elif [[ "$port" == "139" || "$port" == "445" ]] || [[ "$service" =~ smb|microsoft-ds|netbios ]]; then
            # Only launch once for SMB (139 and 445 are the same service).
            # Check QUEUED_PHASES (in-process) AND is_phase_done (resume) to avoid
            # double-launch race: both ports appear before the async job writes DONE.
            if [[ -z "${QUEUED_PHASES[smb]+x}" ]] && ! is_phase_done "$target_dir" "smb"; then
                QUEUED_PHASES[smb]=1
                launch_enum enum_smb "$ip" "$port" "$target_dir"
            fi

        # FTP
        elif [[ "$service" =~ ftp ]] || [[ "$port" == "21" ]]; then
            launch_enum enum_ftp "$ip" "$port" "$target_dir"

        # SSH
        elif [[ "$service" =~ ssh ]] || [[ "$port" == "22" ]]; then
            launch_enum enum_ssh "$ip" "$port" "$target_dir"

        # SNMP (TCP — rare but possible)
        elif [[ "$service" =~ snmp ]] || [[ "$port" == "161" || "$port" == "162" ]]; then
            launch_enum enum_snmp "$ip" "$port" "$target_dir" "false"

        # MySQL
        elif [[ "$service" =~ mysql ]] || [[ "$port" == "3306" ]]; then
            launch_enum enum_mysql "$ip" "$port" "$target_dir"

        # PostgreSQL
        elif [[ "$service" =~ postgres ]] || [[ "$port" == "5432" ]]; then
            launch_enum enum_postgres "$ip" "$port" "$target_dir"

        # DNS
        elif [[ "$service" =~ domain|dns ]] || [[ "$port" == "53" ]]; then
            launch_enum enum_dns "$ip" "$port" "$target_dir"

        # SMTP
        elif [[ "$service" =~ smtp ]] || [[ "$port" == "25" || "$port" == "587" || "$port" == "465" ]]; then
            launch_enum enum_smtp "$ip" "$port" "$target_dir"

        # RPC / NFS
        elif [[ "$service" =~ rpcbind|nfs|msrpc ]] || [[ "$port" == "111" || "$port" == "2049" ]]; then
            if [[ -z "${QUEUED_PHASES[rpc]+x}" ]] && ! is_phase_done "$target_dir" "rpc"; then
                QUEUED_PHASES[rpc]=1
                launch_enum enum_rpc "$ip" "$port" "$target_dir"
            fi

        # LDAP
        elif [[ "$service" =~ ldap ]] || [[ "$port" == "389" || "$port" == "636" || "$port" == "3268" ]]; then
            if [[ -z "${QUEUED_PHASES[ldap]+x}" ]] && ! is_phase_done "$target_dir" "ldap"; then
                QUEUED_PHASES[ldap]=1
                launch_enum enum_ldap "$ip" "$port" "$target_dir"
            fi

        # Redis
        elif [[ "$service" =~ redis ]] || [[ "$port" == "6379" ]]; then
            launch_enum enum_redis "$ip" "$port" "$target_dir"

        # POP3
        elif [[ "$service" =~ pop3 ]] || [[ "$port" == "110" || "$port" == "995" ]]; then
            launch_enum enum_pop3_imap "$ip" "$port" "$target_dir" "pop3"

        # IMAP
        elif [[ "$service" =~ imap ]] || [[ "$port" == "143" || "$port" == "993" ]]; then
            launch_enum enum_pop3_imap "$ip" "$port" "$target_dir" "imap"

        # Unknown/other — log it
        else
            info "  (no auto-enum module for $service on port $port — manual follow-up)"
        fi

    done < <(grep -P '^\d+/(tcp|udp)\s+open\s' "$nmap_file" 2>/dev/null)

    # --- Also check UDP results for SNMP ---
    local udp_file="$target_dir/scans/nmap_udp.nmap"
    if [[ -f "$udp_file" ]]; then
        if grep -qP '161/udp\s+open' "$udp_file" 2>/dev/null; then
            if [[ -z "${QUEUED_PHASES[snmp]+x}" ]] && ! is_phase_done "$target_dir" "snmp"; then
                QUEUED_PHASES[snmp]=1
                success "SNMP found on UDP 161 — launching enumeration"
                launch_enum enum_snmp "$ip" "161" "$target_dir" "true"
            fi
        fi
    fi

    if (( ${#services_found[@]} == 0 )); then
        warn "No services to enumerate for $ip"
    else
        info "Launched enumeration for ${#services_found[@]} service(s) on $ip"
    fi
}

#------------------------------------------------------------------------------
# FINDING-DRIVEN NEXT STEPS
# Writes concise commands only when backed by nmap detections or non-empty result
# files produced by this script.
#------------------------------------------------------------------------------
generate_next_steps() {
    local ip="$1"
    local target_dir="$2"
    local next_file="$target_dir/loot/next_steps.txt"
    mkdir -p "$target_dir/loot"

    {
        echo "# Finding-Driven Next Steps — $ip"
        echo "# Generated: $(date)"
        echo "# Commands below are emitted only from concrete findings in this target directory."
        echo ""
    } > "$next_file"

    local vrfy_file="$target_dir/tcp/smtp/vrfy_users.txt"
    if is_nonempty_file "$vrfy_file" && grep -q '^VALID:' "$vrfy_file" 2>/dev/null; then
        local smtp_users_loot="$target_dir/loot/smtp_valid_users.txt"
        grep -oP '^VALID:\s*\K\S+' "$vrfy_file" 2>/dev/null | sort -u > "$smtp_users_loot" || true
        if is_nonempty_file "$smtp_users_loot"; then
            local smtp_ucount
            smtp_ucount=$(wc -l < "$smtp_users_loot" 2>/dev/null); smtp_ucount=${smtp_ucount:-0}
            append_next_finding "$next_file" \
                "SMTP valid users found" \
                "${smtp_ucount} usernames in ${smtp_users_loot}" \
                "cat $smtp_users_loot" \
                "./sprayr.sh -U $smtp_users_loot -p 'Password1' -t $ip" \
                "./crackr.sh --hydra smb --target $ip -U $smtp_users_loot -P /usr/share/wordlists/rockyou.txt" \
                "./crackr.sh --hydra winrm --target $ip -U $smtp_users_loot -P /usr/share/wordlists/rockyou.txt" \
                "./crackr.sh --hydra smtp --target $ip -U $smtp_users_loot -P /usr/share/wordlists/rockyou.txt"
        fi
    fi

    if is_phase_done "$target_dir" "smb" || detected_tcp_port "$target_dir" "445" || detected_tcp_port "$target_dir" "139"; then
        local smb_anon=false
        if grep -qiE 'READ|WRITE' "$target_dir/tcp/smb/smbmap_null.txt" 2>/dev/null || \
           grep -qiE 'READ|WRITE' "$target_dir/tcp/smb/smbmap_guest.txt" 2>/dev/null; then
            smb_anon=true
        fi
        if [[ "$smb_anon" == "true" ]]; then
            append_next_finding "$next_file" \
                "Readable SMB share found" \
                "$target_dir/tcp/smb/smbmap_null.txt or smbmap_guest.txt contains READ/WRITE" \
                "smbmap -H $ip -u '' -p ''" \
                "smbclient -L //$ip -N" \
                "smbclient //$ip/<SHARE> -N -c 'recurse; ls'" \
                "mkdir -p /mnt/smb_${ip//./_} && mount -t cifs //$ip/<SHARE> /mnt/smb_${ip//./_} -o guest"
        else
            append_next_finding "$next_file" \
                "SMB detected" \
                "nmap/progress indicates SMB on $ip" \
                "netexec smb $ip" \
                "smbmap -H $ip -u <USER> -p '<PASS>'" \
                "smbclient -L //$ip -U '<DOMAIN>/<USER>%<PASS>'" \
                "./adr.sh -d <DOMAIN> -u <USER> -p '<PASS>' -dc $ip"
        fi
    fi

    local winrm_port
    winrm_port=$(first_detected_port "$target_dir" '(^5985/tcp|^5986/tcp|^47001/tcp|winrm|wsman)')
    if [[ -n "$winrm_port" ]]; then
        append_next_finding "$next_file" \
            "WinRM/WSMan detected" \
            "nmap service line includes port ${winrm_port}" \
            "netexec winrm $ip -u <USER> -p '<PASS>'" \
            "netexec winrm $ip -u <USER> -H '<NTLM_HASH>'" \
            "evil-winrm -i $ip -u <USER> -p '<PASS>'" \
            "evil-winrm -i $ip -u <USER> -H '<NTLM_HASH>'"
    fi

    local httpdir
    for httpdir in "$target_dir/tcp/http"/port_*; do
        [[ -d "$httpdir" ]] || continue
        local p proto url evidence
        p=$(basename "$httpdir" | sed 's/port_//')
        proto=$(http_proto_for_port "$p")
        url="${proto}://${ip}:${p}"

        if is_web_brute_target "$p" && is_phase_done "$target_dir" "http_${p}"; then
            evidence="HTTP enum completed for port ${p}"
            if is_nonempty_file "$httpdir/whatweb.txt"; then
                evidence="$evidence; whatweb result exists"
            fi
            append_next_finding "$next_file" \
                "Real web target identified" \
                "$evidence" \
                "./webenum.sh --url $url" \
                "curl -skI $url/" \
                "whatweb -a 3 $url"
        fi

        if is_nonempty_file "$httpdir/http_methods.txt" && \
           grep -qiE 'Allow:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)|Public:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)' "$httpdir/http_methods.txt" 2>/dev/null; then
            append_next_finding "$next_file" \
                "Risky HTTP method found on port ${p}" \
                "$httpdir/http_methods.txt contains risky method in Allow/Public header" \
                "curl -skIX OPTIONS $url/" \
                "nmap --script http-methods -p $p $ip" \
                "curl -skI -X TRACE $url/ 2>/dev/null | sed -n '1,20p'"
        fi

        local vhost_json="$httpdir/ffuf_vhosts.json"
        if is_nonempty_file "$vhost_json"; then
            local vhosts
            vhosts=$(jq -r '.results[].host // .results[].input.VHOST // empty' "$vhost_json" 2>/dev/null | grep -v '^$' | sort -u | head -3)
            if [[ -n "$vhosts" ]]; then
                while IFS= read -r vhost; do
                    [[ -z "$vhost" ]] && continue
                    append_next_finding "$next_file" \
                        "Discovered vhost" \
                        "$vhost_json contains $vhost" \
                        "echo '$ip $vhost' | sudo tee -a /etc/hosts" \
                        "./webenum.sh --url ${proto}://${vhost}:${p}"
                done <<< "$vhosts"
            fi
        fi
    done

    if is_nonempty_file "$target_dir/tcp/ftp/ANONYMOUS_ACCESS.txt"; then
        append_next_finding "$next_file" \
            "Anonymous FTP access succeeded" \
            "$target_dir/tcp/ftp/ANONYMOUS_ACCESS.txt exists" \
            "ftp $ip" \
            "wget -r --no-passive-ftp ftp://anonymous:anon@$ip/" \
            "find $target_dir/tcp/ftp/mirror -maxdepth 5 -type f 2>/dev/null | sort"
    fi

    local pop3_port imap_port
    pop3_port=$(first_detected_port "$target_dir" 'pop3|^110/tcp|^995/tcp')
    if [[ -n "$pop3_port" ]] || grep -q "| DONE | pop3_" "$target_dir/progress.log" 2>/dev/null; then
        [[ -z "$pop3_port" ]] && pop3_port="110"
        append_next_finding "$next_file" \
            "POP3 detected" \
            "nmap/progress indicates POP3" \
            "nc -nv $ip $pop3_port" \
            "printf 'CAPA\\r\\nQUIT\\r\\n' | nc -nv $ip $pop3_port" \
            "hydra -L <users.txt> -P /usr/share/wordlists/rockyou.txt pop3://$ip"
    fi

    imap_port=$(first_detected_port "$target_dir" 'imap|^143/tcp|^993/tcp')
    if [[ -n "$imap_port" ]] || grep -q "| DONE | imap_" "$target_dir/progress.log" 2>/dev/null; then
        [[ -z "$imap_port" ]] && imap_port="143"
        append_next_finding "$next_file" \
            "IMAP detected" \
            "nmap/progress indicates IMAP" \
            "nc -nv $ip $imap_port" \
            "printf '. CAPABILITY\\r\\n. LOGOUT\\r\\n' | nc -nv $ip $imap_port" \
            "hydra -L <users.txt> -P /usr/share/wordlists/rockyou.txt imap://$ip"
    fi

    if is_nonempty_file "$target_dir/udp/snmp/valid_community_strings.txt"; then
        local community
        community=$(head -1 "$target_dir/udp/snmp/valid_community_strings.txt")
        append_next_finding "$next_file" \
            "SNMP community string found" \
            "$target_dir/udp/snmp/valid_community_strings.txt is non-empty" \
            "cat $target_dir/udp/snmp/valid_community_strings.txt" \
            "snmpwalk -v2c -c '${community}' $ip" \
            "snmpwalk -v2c -c '${community}' $ip 1.3.6.1.2.1.25.4.2.1.5"
    fi

    if grep -qP '^\s*/' "$target_dir/tcp/rpc/nfs_exports.txt" 2>/dev/null; then
        local export_path
        export_path=$(grep -P '^\s*/' "$target_dir/tcp/rpc/nfs_exports.txt" 2>/dev/null | head -1 | awk '{print $1}')
        append_next_finding "$next_file" \
            "NFS export found" \
            "$target_dir/tcp/rpc/nfs_exports.txt contains export path ${export_path}" \
            "showmount -e $ip" \
            "mkdir -p /mnt/nfs_${ip//./_}" \
            "mount -t nfs $ip:${export_path} /mnt/nfs_${ip//./_}" \
            "find /mnt/nfs_${ip//./_} -maxdepth 3 -type f -ls 2>/dev/null"
    fi

    if grep -qi 'REDIS NO-AUTH' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "Redis no-auth access succeeded" \
            "$target_dir/loot/quick_wins.txt contains REDIS NO-AUTH" \
            "redis-cli -h $ip INFO" \
            "redis-cli -h $ip KEYS '*'" \
            "redis-cli -h $ip CONFIG GET '*'"
    fi

    if grep -qi 'LDAP anonymous bind' "$target_dir/loot/quick_wins.txt" 2>/dev/null && \
       is_nonempty_file "$target_dir/tcp/ldap/naming_contexts.txt"; then
        local base_dn
        base_dn=$(grep -oP 'namingContexts:\s*\K.*' "$target_dir/tcp/ldap/naming_contexts.txt" 2>/dev/null | head -1)
        append_next_finding "$next_file" \
            "LDAP anonymous bind returned data" \
            "$target_dir/tcp/ldap/naming_contexts.txt contains ${base_dn}" \
            "ldapsearch -x -H ldap://$ip -s base namingContexts" \
            "ldapsearch -x -H ldap://$ip -b '${base_dn}' '(objectClass=*)' | grep -iE 'sAMAccountName|mail|description|memberOf'" \
            "./adr.sh -d <DOMAIN> -u '' -p '' -dc $ip"
    fi

    local mysql_port
    mysql_port=$(first_detected_port "$target_dir" 'mysql|^3306/tcp')
    if grep -qi 'MySQL ROOT NO-PASSWORD\|MySQL EMPTY PASSWORD' "$target_dir/loot/quick_wins.txt" 2>/dev/null || \
       (is_nonempty_file "$target_dir/tcp/mysql/root_nopass.txt" && ! grep -qi 'ERROR\|denied\|refused' "$target_dir/tcp/mysql/root_nopass.txt" 2>/dev/null); then
        [[ -z "$mysql_port" ]] && mysql_port="3306"
        append_next_finding "$next_file" \
            "MySQL no-password access succeeded" \
            "$target_dir/tcp/mysql/root_nopass.txt or quick_wins shows empty/root no-password access" \
            "mysql -h $ip -P $mysql_port -u root --password='' -e 'SHOW DATABASES;'" \
            "mysql -h $ip -P $mysql_port -u root --password='' -e 'SELECT user,host FROM mysql.user;'" \
            "mysql -h $ip -P $mysql_port -u root --password='' -e \"SHOW VARIABLES LIKE 'secure_file_priv';\""
    elif [[ -n "$mysql_port" ]]; then
        append_next_finding "$next_file" \
            "MySQL detected" \
            "nmap service line includes port ${mysql_port}" \
            "mysql -h $ip -P $mysql_port -u root --password=''" \
            "mysql -h $ip -P $mysql_port -u root" \
            "./crackr.sh --hydra mysql --target $ip -u root -P /usr/share/wordlists/rockyou.txt"
    fi

    local pg_port
    pg_port=$(first_detected_port "$target_dir" 'postgres|pgsql|^5432/tcp')
    if grep -qi 'PostgreSQL LOGIN' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        [[ -z "$pg_port" ]] && pg_port="5432"
        local pg_creds pg_user pg_pass
        pg_creds=$(grep -oP 'PostgreSQL LOGIN:\s*\K\S+' "$target_dir/loot/quick_wins.txt" 2>/dev/null | head -1)
        pg_user="${pg_creds%%:*}"
        pg_pass="${pg_creds#*:}"
        [[ "$pg_pass" == "<empty>" || "$pg_pass" == "$pg_creds" ]] && pg_pass=""
        append_next_finding "$next_file" \
            "PostgreSQL login succeeded" \
            "$target_dir/loot/quick_wins.txt contains PostgreSQL LOGIN" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c '\\l'" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c 'SELECT usename,usesuper FROM pg_user;'" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user'"
    elif [[ -n "$pg_port" ]]; then
        append_next_finding "$next_file" \
            "PostgreSQL detected" \
            "nmap service line includes port ${pg_port}" \
            "psql -h $ip -p $pg_port -U postgres" \
            "PGPASSWORD=postgres psql -h $ip -p $pg_port -U postgres -c '\\l'" \
            "./crackr.sh --hydra postgres --target $ip -u postgres -P /usr/share/wordlists/rockyou.txt"
    fi

    local zt_file
    zt_file=$(find "$target_dir/tcp/dns" -name 'zone_transfer_*.txt' -type f 2>/dev/null | head -1)
    if is_nonempty_file "$zt_file" && grep -q 'XFR size' "$zt_file" 2>/dev/null; then
        append_next_finding "$next_file" \
            "DNS zone transfer succeeded" \
            "$zt_file contains XFR size" \
            "cat $zt_file" \
            "awk '/^[^;]/ && \$4 ~ /^A$/ {print \$1}' $zt_file | sed 's/\\.\$//'" \
            "awk '/^[^;]/ && \$4 ~ /^A$/ {print \"$ip \" \$1}' $zt_file | sed 's/\\.\$//' | sudo tee -a /etc/hosts"
    else
        local dns_port
        dns_port=$(first_detected_port "$target_dir" 'domain|dns|^53/tcp')
        if [[ -n "$dns_port" ]]; then
            append_next_finding "$next_file" \
                "DNS detected" \
                "nmap service line includes port ${dns_port}" \
                "dig @$ip -p $dns_port version.bind chaos txt" \
                "dig @$ip -p $dns_port <DOMAIN> axfr" \
                "dnsrecon -d <DOMAIN> -n $ip"
        fi
    fi

    if is_nonempty_file "$target_dir/udp/snmp/process_args.txt" && \
       grep -qiE 'pass|pwd|secret|key|token|cred|-p[[:space:]]' "$target_dir/udp/snmp/process_args.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "SNMP process arguments may contain secrets" \
            "$target_dir/udp/snmp/process_args.txt contains credential keywords" \
            "grep -iE 'pass|pwd|secret|key|token|cred|-p[[:space:]]' $target_dir/udp/snmp/process_args.txt" \
            "cat $target_dir/udp/snmp/process_args.txt" \
            "grep -iE 'mysql|postgres|mssql|ssh|ftp|backup|script' $target_dir/udp/snmp/process_args.txt"
    fi

    if is_nonempty_file "$target_dir/udp/snmp/windows_users.txt"; then
        local snmp_users_loot="$target_dir/loot/snmp_windows_users.txt"
        grep -oP 'STRING:\s*\"?\K[^"]+' "$target_dir/udp/snmp/windows_users.txt" 2>/dev/null | sort -u > "$snmp_users_loot" || true
        if is_nonempty_file "$snmp_users_loot"; then
            append_next_finding "$next_file" \
                "Windows usernames found via SNMP" \
                "$snmp_users_loot is non-empty" \
                "cat $snmp_users_loot" \
                "./sprayr.sh -U $snmp_users_loot -p 'Password1' -t $ip" \
                "./crackr.sh --hydra winrm --target $ip -U $snmp_users_loot -P /usr/share/wordlists/rockyou.txt"
        fi
    fi

    local mssql_port
    mssql_port=$(first_detected_port "$target_dir" 'ms-sql|mssql|^1433/tcp')
    if [[ -n "$mssql_port" ]]; then
        append_next_finding "$next_file" \
            "MSSQL detected" \
            "nmap service line includes port ${mssql_port}" \
            "netexec mssql $ip -u <USER> -p '<PASS>'" \
            "impacket-mssqlclient '<DOMAIN>/<USER>:<PASS>@$ip' -windows-auth" \
            "impacket-mssqlclient '<USER>:<PASS>@$ip' -port $mssql_port" \
            "nmap --script ms-sql-info,ms-sql-empty-password -p $mssql_port $ip"
    fi

    local rdp_port
    rdp_port=$(first_detected_port "$target_dir" 'ms-wbt-server|rdp|^3389/tcp')
    if [[ -n "$rdp_port" ]]; then
        append_next_finding "$next_file" \
            "RDP detected" \
            "nmap service line includes port ${rdp_port}" \
            "netexec rdp $ip -u <USER> -p '<PASS>'" \
            "xfreerdp /v:$ip:$rdp_port /u:<USER> /p:'<PASS>' /cert:ignore" \
            "nmap --script rdp-enum-encryption,rdp-ntlm-info -p $rdp_port $ip"
    fi

    local kerberos_port
    kerberos_port=$(first_detected_port "$target_dir" 'kerberos|^88/tcp|^464/tcp')
    if [[ -n "$kerberos_port" ]]; then
        append_next_finding "$next_file" \
            "Kerberos detected" \
            "nmap service line includes port ${kerberos_port}" \
            "nmap --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>' -p $kerberos_port $ip" \
            "impacket-GetNPUsers '<DOMAIN>/' -dc-ip $ip -usersfile <users.txt> -no-pass" \
            "impacket-GetUserSPNs '<DOMAIN>/<USER>:<PASS>' -dc-ip $ip -request"
    fi

    if detected_tcp_port "$target_dir" "445" && [[ -n "$kerberos_port" || -n "$(first_detected_port "$target_dir" 'ldap|^389/tcp|^636/tcp|^3268/tcp')" ]]; then
        append_next_finding "$next_file" \
            "AD service combination detected" \
            "SMB plus Kerberos/LDAP appears in nmap results" \
            "netexec smb $ip" \
            "netexec smb $ip -u <USER> -p '<PASS>' --shares --users --groups" \
            "./adr.sh -d <DOMAIN> -u <USER> -p '<PASS>' -dc $ip"
    fi

    if is_nonempty_file "$target_dir/tcp/ssh/version_info.txt" && \
       grep -qi 'POTENTIALLY VULNERABLE SSH' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "Potentially vulnerable SSH banner found" \
            "$target_dir/tcp/ssh/version_info.txt and quick_wins flag old SSH" \
            "cat $target_dir/tcp/ssh/version_info.txt" \
            "ssh-audit $ip" \
            "searchsploit \"$(head -1 "$target_dir/tcp/ssh/version_info.txt" 2>/dev/null | sed 's/^SSH Version: //')\""
    fi

    if ! grep -q '^## ' "$next_file" 2>/dev/null; then
        echo "(no grounded next-step commands generated)" >> "$next_file"
    fi
}

#------------------------------------------------------------------------------
# GENERATE SUMMARY REPORT
#------------------------------------------------------------------------------
generate_summary() {
    local ip="$1"
    local target_dir="$2"
    local summary="$target_dir/summary.txt"

    header "Generating Summary Report → $ip"
    generate_next_steps "$ip" "$target_dir"

    {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║           OffSec RECON SUMMARY — $ip"
        echo "║           Generated: $(date)"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""

        # --- Open Ports ---
        echo "═══ OPEN PORTS ════════════════════════════════════════════════"
        echo ""
        echo "TCP Ports:"
        if [[ -f "$target_dir/scans/tcp_ports.txt" ]]; then
            echo "  $(cat "$target_dir/scans/tcp_ports.txt")"
        else
            echo "  (no TCP scan results)"
        fi
        echo ""
        echo "UDP Ports:"
        if [[ -f "$target_dir/scans/udp_ports.txt" ]]; then
            echo "  $(cat "$target_dir/scans/udp_ports.txt")"
        else
            echo "  (no open UDP ports found)"
        fi
        echo ""

        # --- Service Details (from nmap) ---
        echo "═══ SERVICES ══════════════════════════════════════════════════"
        echo ""
        if [[ -f "$target_dir/scans/nmap_tcp.nmap" ]]; then
            grep -P '^\d+/(tcp|udp)\s+open\s' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null | \
                while IFS= read -r line; do echo "  $line"; done
        fi
        echo ""

        # --- OS Detection ---
        echo "═══ OS DETECTION ════════════════════════════════════════════"
        echo ""
        if [[ -f "$target_dir/scans/nmap_tcp.nmap" ]]; then
            grep -A2 'OS details\|Running:' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null | \
                while IFS= read -r line; do echo "  $line"; done
        fi
        echo ""

        # --- Quick Wins / Loot ---
        echo "═══ ★ QUICK WINS ★ ═════════════════════════════════════════"
        echo ""
        if [[ -f "$target_dir/loot/quick_wins.txt" && -s "$target_dir/loot/quick_wins.txt" ]]; then
            while IFS= read -r line; do echo "  ★ $line"; done < "$target_dir/loot/quick_wins.txt"
        else
            echo "  (no quick wins found — deeper manual enumeration may be needed)"
        fi
        echo ""

        # --- HTTP Findings ---
        echo "═══ WEB FINDINGS ════════════════════════════════════════════"
        echo ""
        for httpdir in "$target_dir/tcp/http"/port_*; do
            [[ -d "$httpdir" ]] || continue
            local p=""
            p=$(basename "$httpdir" | sed 's/port_//')
            echo "  --- Port $p ---"
            if [[ -f "$httpdir/whatweb.txt" ]]; then
                echo "  WhatWeb: $(head -1 "$httpdir/whatweb.txt" 2>/dev/null)"
            fi
            if [[ -f "$httpdir/gobuster_dir.txt" ]]; then
                local hits=""
                hits=$(grep -c '^/' "$httpdir/gobuster_dir.txt" 2>/dev/null); hits=${hits:-0}
                echo "  Gobuster: $hits directories/files found"
                # Show top interesting hits
                grep -iE '/admin|/login|/upload|/config|/backup|/shell|/api|/console|/phpmyadmin|/wp-|/cgi' \
                    "$httpdir/gobuster_dir.txt" 2>/dev/null | head -10 | \
                    while IFS= read -r line; do echo "    → $line"; done
            fi
            if [[ -f "$httpdir/robots.txt" ]] && ! grep -q '# No robots' "$httpdir/robots.txt" 2>/dev/null; then
                echo "  robots.txt: Found (check $httpdir/robots.txt)"
            fi
            echo ""
        done

        # --- SMB Findings ---
        if [[ -d "$target_dir/tcp/smb" ]]; then
            echo "═══ SMB FINDINGS ═════════════════════════════════════════"
            echo ""
            if [[ -f "$target_dir/tcp/smb/smb_quick_findings.txt" ]]; then
                while IFS= read -r line; do echo "  $line"; done < "$target_dir/tcp/smb/smb_quick_findings.txt"
            fi
            # NFS next steps
            if grep -qP '^\s*/' "$target_dir/tcp/rpc/nfs_exports.txt" 2>/dev/null; then
                echo "  NFS NEXT STEPS:"
                while IFS= read -r export_line; do
                    local export_path
                    export_path=$(echo "${export_line}" | awk '{print $1}')
                    [[ -z "${export_path}" ]] && continue
                    echo "    showmount -e $ip"
                    echo "    mkdir /mnt/nfs_${ip//\./_} && mount -t nfs $ip:${export_path} /mnt/nfs_${ip//\./_}"
                    echo "    # If no_root_squash: cp /bin/bash /mnt/nfs_${ip//\./_}/bash && chmod +s /mnt/nfs_${ip//\./_}/bash"
                done < <(grep -P '^\s*/' "$target_dir/tcp/rpc/nfs_exports.txt" 2>/dev/null | head -3)
            fi
            echo ""
        fi

        # --- SNMP Findings ---
        if [[ -d "$target_dir/udp/snmp" ]]; then
            echo "═══ SNMP FINDINGS ════════════════════════════════════════"
            echo ""
            if [[ -f "$target_dir/udp/snmp/valid_community_strings.txt" ]]; then
                local snmp_strings
                snmp_strings=$(tr '\n' ',' < "$target_dir/udp/snmp/valid_community_strings.txt" | sed 's/,$//')
                echo "  Community strings: ${snmp_strings}"
                echo ""
                echo "  NEXT STEPS:"
                while IFS= read -r community; do
                    [[ -z "${community}" ]] && continue
                    echo "    snmpwalk -v2c -c '${community}' $ip                      # full walk"
                    echo "    snmpwalk -v2c -c '${community}' $ip 1.3.6.1.2.1.25.4.2.1.5  # process args (creds!)"
                done < "$target_dir/udp/snmp/valid_community_strings.txt"
            fi
            if [[ -f "$target_dir/udp/snmp/running_processes.txt" && -s "$target_dir/udp/snmp/running_processes.txt" ]]; then
                echo "  Running processes: $(wc -l < "$target_dir/udp/snmp/running_processes.txt") entries — check $target_dir/udp/snmp/process_args.txt for embedded creds"
            fi
            if [[ -f "$target_dir/udp/snmp/process_args.txt" && -s "$target_dir/udp/snmp/process_args.txt" ]]; then
                echo "  ★ process_args.txt present — grep for credentials:"
                echo "    grep -iE 'pass|pwd|secret|key|token|cred|-p[[:space:]]' $target_dir/udp/snmp/process_args.txt"
            fi
            echo ""
        fi

        # --- SMTP Findings ---
        if grep -q "| DONE | smtp_" "$target_dir/progress.log" 2>/dev/null; then
            echo "═══ SMTP FINDINGS ════════════════════════════════════════"
            echo ""
            local vrfy_file="$target_dir/tcp/smtp/vrfy_users.txt"
            if [[ -f "$vrfy_file" ]]; then
                local vcount
                vcount=$(grep -c "^VALID:" "$vrfy_file" 2>/dev/null); vcount=${vcount:-0}
                if (( vcount > 0 )); then
                    echo "  ★ VRFY found $vcount valid users (see $vrfy_file)"
                    echo "  Top users:"
                    grep "^VALID:" "$vrfy_file" 2>/dev/null | head -10 | while IFS= read -r l; do echo "    $l"; done
                else
                    echo "  VRFY enumeration returned no valid users"
                fi
            fi
            # Banner info
            local smtp_banner="$target_dir/tcp/smtp/banner.txt"
            [[ -f "$smtp_banner" ]] && echo "  Banner: $(head -1 "$smtp_banner" 2>/dev/null | tr -d '\r')"
            echo ""
        fi

        # --- POP3 / IMAP Findings ---
        local mail_section=false
        for proto_name in pop3 imap; do
            if grep -q "| DONE | ${proto_name}_" "$target_dir/progress.log" 2>/dev/null; then
                if [[ "$mail_section" == "false" ]]; then
                    echo "═══ MAIL SERVICE FINDINGS ════════════════════════════════"
                    echo ""
                    mail_section=true
                fi
                echo "  ${proto_name^^} detected — check $target_dir/tcp/${proto_name}/ for capabilities/banner"
                find "$target_dir/tcp/${proto_name}" -name "banner_*.txt" 2>/dev/null | while read -r bf; do
                    local port_n
                    port_n=$(basename "$bf" | grep -oP '\d+')
                    local banner_line
                    banner_line=$(head -1 "$bf" 2>/dev/null | tr -d '\r\n')
                    [[ -n "$banner_line" ]] && echo "    Port $port_n: $banner_line"
                done
            fi
        done
        [[ "$mail_section" == "true" ]] && echo ""

        # --- Finding-driven Next-Step Commands ---
        echo "═══ ★ NEXT-STEP COMMANDS ★ ══════════════════════════════"
        echo ""
        echo "  Full library: $target_dir/loot/next_steps.txt"
        echo ""
        if is_nonempty_file "$target_dir/loot/next_steps.txt"; then
            awk '
                /^## / {shown++; if (shown > 3) exit}
                shown > 0 && !/^# Finding-Driven/ && !/^# Generated/ && !/^# Commands below/ {print "  " $0}
            ' "$target_dir/loot/next_steps.txt"
        else
            echo "  (no grounded next-step commands generated)"
        fi

        echo ""

        # --- Completion Status ---
        echo "═══ SCAN STATUS ═══════════════════════════════════════════"
        echo ""
        if [[ -f "$target_dir/progress.log" ]]; then
            echo "  Completed phases:"
            grep '| DONE |' "$target_dir/progress.log" | awk -F'|' '{print "    ✓ " $3}' | sort -u
            echo ""
            local failed=""
            failed=$(grep '| FAIL |' "$target_dir/progress.log" 2>/dev/null)
            if [[ -n "$failed" ]]; then
                echo "  Failed phases (may need manual re-run):"
                echo "$failed" | awk -F'|' '{print "    ✗ " $3 " — " $4}'
            fi
        fi
        echo ""

        # --- Output Directory ---
        echo "═══ OUTPUT FILES ════════════════════════════════════════════"
        echo ""
        echo "  Full results: $target_dir/"
        find "$target_dir" -type f \( -name "*.txt" -o -name "*.nmap" -o -name "*.xml" -o -name "*.json" \) 2>/dev/null | \
            sort | while IFS= read -r f; do
                local size=""
                size=$(du -h "$f" 2>/dev/null | awk '{print $1}')
                echo "    [$size] ${f#"$target_dir"/}"
            done

    } > "$summary"

    # Also print to terminal
    cat "$summary"
    echo ""
    success "Summary saved to: $summary"
}

#------------------------------------------------------------------------------
# MAIN TARGET HANDLER — orchestrates everything for one IP
#------------------------------------------------------------------------------
recon_target() {
    local ip="$1"

    header "OffSec RECON → $ip"
    echo "  Started: $(date)"
    echo "  Output:  ${RECON_DIR}/${ip}/"

    # --- Setup directory structure (service dirs created on-demand by each enum function) ---
    local target_dir="${RECON_DIR}/${ip}"
    mkdir -p "$target_dir"/{scans,loot}

    # Initialize progress log
    if [[ ! -f "$target_dir/progress.log" ]]; then
        echo "# OffSec Recon Progress Log for $ip" > "$target_dir/progress.log"
        echo "# Started: $(date)" >> "$target_dir/progress.log"
    fi
    progress_log "$target_dir" "START" "recon" "target=$ip"

    # --- Phase 1: Fast TCP port discovery ---
    run_rustscan "$ip" "$target_dir"

    # --- Phase 2: Nmap TCP service detection ---
    run_nmap_tcp "$ip" "$target_dir"

    # --- Phase 3: UDP scan (launch in background — it's slow) ---
    # Use register_cleanup_pid (not register_pid) so wait_for_slot never sees
    # this PID and never decrements RUNNING_JOBS when the UDP scan finishes.
    run_nmap_udp "$ip" "$target_dir" &
    local udp_pid=$!
    register_cleanup_pid "$udp_pid"  # Ctrl+C cleanup without affecting semaphore
    info "UDP scan running in background (PID: $udp_pid)"

    # --- Phase 4: Service-specific enumeration ---
    triage_and_enumerate "$ip" "$target_dir"

    # --- Wait for everything to finish ---
    wait_all_enum
    # Wait for UDP independently so summary reliably includes UDP output
    wait "$udp_pid" 2>/dev/null || true
    unregister_cleanup_pid "$udp_pid"

    # --- Phase 4b: Post-UDP SNMP check ---
    # UDP scan was backgrounded during triage, so SNMP on UDP 161 may have been
    # missed (nmap_udp.nmap didn't exist yet). Re-check now that UDP is done.
    local udp_file="$target_dir/scans/nmap_udp.nmap"
    if [[ -f "$udp_file" ]]; then
        if grep -qP '161/udp\s+open' "$udp_file" 2>/dev/null; then
            if [[ -z "${QUEUED_PHASES[snmp]+x}" ]] && ! is_phase_done "$target_dir" "snmp"; then
                success "SNMP found on UDP 161 (post-UDP check) — launching enumeration"
                enum_snmp "$ip" "161" "$target_dir" "true"
            fi
        fi
    fi

    # --- Phase 5: Generate summary ---
    generate_summary "$ip" "$target_dir"

    progress_log "$target_dir" "DONE" "recon" "target=$ip"
    success "All enumeration complete for $ip"
}

#------------------------------------------------------------------------------
# USAGE / HELP
#------------------------------------------------------------------------------
usage() {
    cat <<'EOF'
OffSec RECON WRAPPER — Automated Enumeration Orchestrator

USAGE:
  ./recon.sh [OPTIONS] <IP> [IP2] [IP3] ...
  ./recon.sh -f <file_with_ips>

OPTIONS:
  -f, --file FILE       Read targets from file (one IP per line)
  --auto                Skip confirmation prompts (auto-run everything)
  --udp-ports N         Number of top UDP ports to scan (default: 200)
  --udp-full            Also scan ALL 65535 UDP ports (slow — use when stuck)
  --batch-size N        Rustscan batch size (default: 1500)
  --rate N              Deprecated alias for --batch-size
  --outdir DIR          Output directory (default: ./recon)
  --max-parallel N      Max parallel service enumerations per target (default: 5)
  --max-parallel-targets N  Max simultaneous target scans (default: 3)
  --sequential          Process targets one at a time (default: parallel)
  --quick-wins          Run 5-min triage per target BEFORE deep recon
  --quick-wins-only     Run triage only, print priority list, then stop
  --no-color            Disable colored output
  --no-sudo             Skip automatic sudo re-exec (run without root privileges)
  -h, --help            Show this help message

EXAMPLES:
  ./recon.sh 10.10.10.1                    # Single target
  ./recon.sh 10.10.10.1 10.10.10.2         # Multiple targets (parallel)
  ./recon.sh --sequential 10.10.10.1 10.10.10.2  # One at a time
  ./recon.sh --quick-wins-only 10.10.10.1 10.10.10.2 10.10.10.3  # Triage first
  ./recon.sh -f targets.txt                 # From file
  ./recon.sh --auto 10.10.10.1              # No prompts
  ./recon.sh --batch-size 3000 --auto 10.10.10.1  # Larger rustscan batches
  ./recon.sh --udp-full --auto 10.10.10.1   # Deep UDP scan

NOTES:
  - Run as root for UDP scanning; non-root mode skips UDP scans safely
  - Re-run safely: completed phases are skipped (delete progress.log to redo)
  - Ctrl+C cleanly kills all background jobs
  - Results in ~/toolkit/recon/<IP>/summary.txt
  - Set TOOLKIT_ROOT env var to change output base (default: ~/toolkit)
EOF
}

#------------------------------------------------------------------------------
# ARGUMENT PARSING
#------------------------------------------------------------------------------
declare -a TARGETS=()
TARGET_FILE=""
# Preserve original args so sudo re-exec can pass them verbatim
ORIGINAL_ARGS=("$@")

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -f|--file)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            TARGET_FILE="$2"
            shift 2
            ;;
        --auto)
            AUTO_MODE=true
            shift
            ;;
        --udp-ports)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            UDP_TOP_PORTS="$2"
            shift 2
            ;;
        --udp-full)
            UDP_FULL=true
            shift
            ;;
        --batch-size|--rate)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            RUSTSCAN_BATCH_SIZE="$2"
            shift 2
            ;;
        --outdir)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            RECON_DIR="$2"
            shift 2
            ;;
        --max-parallel)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            MAX_PARALLEL_SERVICES="$2"
            shift 2
            ;;
        --max-parallel-targets)
            [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
            MAX_PARALLEL_TARGETS="$2"
            shift 2
            ;;
        --quick-wins)
            QUICK_WINS_MODE=true
            shift
            ;;
        --quick-wins-only)
            QUICK_WINS_MODE=true
            QUICK_WINS_ONLY=true
            shift
            ;;
        --sequential)
            SEQUENTIAL_TARGETS=true
            shift
            ;;
        --no-color)
            disable_colors
            shift
            ;;
        --no-sudo)
            NO_SUDO=true
            shift
            ;;
        -*)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            TARGETS+=("$1")
            shift
            ;;
    esac
done

if ! is_positive_integer "$UDP_TOP_PORTS" || (( UDP_TOP_PORTS > 65535 )); then
    error "--udp-ports must be an integer between 1 and 65535"
    exit 1
fi

if ! is_positive_integer "$RUSTSCAN_BATCH_SIZE"; then
    error "--batch-size/--rate must be a positive integer"
    exit 1
fi

if ! is_positive_integer "$MAX_PARALLEL_SERVICES"; then
    error "--max-parallel must be a positive integer"
    exit 1
fi

# Load targets from file if specified
if [[ -n "$TARGET_FILE" ]]; then
    if [[ ! -f "$TARGET_FILE" ]]; then
        error "Target file not found: $TARGET_FILE"
        exit 1
    fi
    while IFS= read -r line; do
        # Skip empty lines and comments
        read -r line <<< "$line"  # trim leading/trailing whitespace
        [[ -z "$line" || "$line" == \#* ]] && continue
        TARGETS+=("$line")
    done < "$TARGET_FILE"
fi

# Validate we have targets
if (( ${#TARGETS[@]} == 0 )); then
    error "No targets specified"
    usage
    exit 1
fi

# Validate all targets
for target in "${TARGETS[@]}"; do
    if ! is_valid_ip "$target"; then
        error "Invalid target: $target"
        exit 1
    fi
done

#------------------------------------------------------------------------------
# SUDO AUTO-REEXEC
# UDP scanning and OS detection (-sU, -O) require root. Re-execute with sudo
# automatically so the operator doesn't discover the limitation mid-scan.
# Pass --no-sudo to skip this (e.g. when already inside a sudo environment
# that doesn't need escalation, or when testing without privilege).
#------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]] && [[ "$NO_SUDO" != "true" ]]; then
    warn "Not running as root — re-executing with sudo for full scan capability (UDP, OS detect)..."
    warn "Pass --no-sudo to skip this. Sudo may prompt for your password."
    # Build an augmented PATH that includes user-specific bin dirs.
    # sudo's secure_path can strip PATH even when passed via 'env', so we
    # prepend known locations (cargo, local, snap) explicitly so rustscan
    # and other user-installed tools survive the re-exec.
    _inv_user="${SUDO_USER:-$(id -un)}"
    _inv_home=$(getent passwd "$_inv_user" 2>/dev/null | cut -d: -f6)
    _aug_path="${_inv_home}/.cargo/bin:${_inv_home}/.local/bin:${_inv_home}/go/bin:${_inv_home}/snap/bin:${PATH}"
    unset _inv_user _inv_home
    exec sudo env PATH="$_aug_path" TOOLKIT_ROOT="$TOOLKIT_ROOT" "$0" "${ORIGINAL_ARGS[@]}"
    unset _aug_path
    # exec replaces this process; if it fails (no sudo), fall through with a warning
    warn "sudo exec failed — continuing without root (UDP and OS detection will be skipped)"
fi

#------------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
#------------------------------------------------------------------------------
header "OffSec RECON WRAPPER — Pre-Flight Check"

# ── Workspace resolution — verify this is correct before continuing ──────────
_invoking_user="${SUDO_USER:-$(id -un)}"
_effective_user="$(id -un)"
echo -e "${BOLD}  Invoking user   :${NC} ${_invoking_user}"
echo -e "${BOLD}  Effective user  :${NC} ${_effective_user}"
echo -e "${BOLD}  Workspace root  :${NC} ${TOOLKIT_ROOT}"
echo -e "${BOLD}  Recon output    :${NC} ${RECON_DIR}"
unset _invoking_user _effective_user
echo ""
# ─────────────────────────────────────────────────────────────────────────────

# Check critical tools
CRITICAL_TOOLS=(rustscan nmap)
OPTIONAL_TOOLS=(gobuster nikto whatweb enum4linux-ng smbmap smbclient snmpwalk \
                onesixtyone curl wget feroxbuster netexec nc \
                rpcclient showmount dig ldapsearch psql mysql)

echo ""
info "Checking critical tools..."
for tool in "${CRITICAL_TOOLS[@]}"; do
    if ! check_tool "$tool"; then
        error "CRITICAL: $tool is required but not installed"
        exit 1
    else
        success "  $tool — OK"
    fi
done

echo ""
info "Checking optional tools..."
MISSING_OPTIONAL=()
for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${YELLOW}✗${NC} $tool (not found — related enumeration will be skipped)"
        MISSING_OPTIONAL+=("$tool")
    fi
done

echo ""
info "Targets: ${TARGETS[*]}"
info "Output:  ${RECON_DIR}/"
info "Mode:    $(if [[ "$AUTO_MODE" == "true" ]]; then echo "AUTO (no prompts)"; else echo "INTERACTIVE"; fi)"
info "UDP:     Top $UDP_TOP_PORTS ports"
info "Rustscan batch size: $RUSTSCAN_BATCH_SIZE"
echo ""

if (( ${#MISSING_OPTIONAL[@]} > 0 )); then
    warn "${#MISSING_OPTIONAL[@]} optional tool(s) missing — some enumeration will be skipped"
    warn "Install with: sudo apt install ${MISSING_OPTIONAL[*]}"
    echo ""
fi

# --- Connectivity pre-flight ---
info "Connectivity checks..."

# VPN check
if ip link show tun0 &>/dev/null; then
    local_ip=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    success "  VPN up (tun0: $local_ip)"
else
    local_ip=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [[ -z "$local_ip" ]]; then
        local_ip=$(ip -4 route get 1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    fi
    if [[ -z "$local_ip" ]]; then
        local_ip="unknown"
        warn "  Could not determine local IP — check network interfaces"
    fi
    warn "  No VPN detected (tun0 not found) — using $local_ip"
    warn "  If this is the engagement, check your VPN connection!"
fi

# Root check (informational only — sudo re-exec already handled above)
if [[ $EUID -eq 0 ]]; then
    success "  Running as root — full scan capability"
else
    warn "  Not running as root — UDP scanning and OS detection will be limited"
    warn "  (Pass --no-sudo was set; continuing without privilege escalation)"
fi

# Target reachability
echo ""
info "Checking target reachability..."
UNREACHABLE_TARGETS=()
# shellcheck disable=SC2016
for target in "${TARGETS[@]}"; do
    if ping -c 1 -W 2 "$target" &>/dev/null; then
        success "  $target — reachable"
    elif timeout 3 bash -c 'echo "" > "/dev/tcp/$1/80" 2>/dev/null || echo "" > "/dev/tcp/$1/443" 2>/dev/null || echo "" > "/dev/tcp/$1/22" 2>/dev/null' -- "$target" 2>/dev/null; then
        success "  $target — reachable (ICMP blocked, but TCP ports responding)"
    else
        warn "  $target — NOT responding to ping or common ports"
        warn "    Check: Is the target up? Is your VPN connected? Is the IP correct?"
        UNREACHABLE_TARGETS+=("$target")
    fi
done

if (( ${#UNREACHABLE_TARGETS[@]} > 0 )) && [[ "$AUTO_MODE" != "true" ]]; then
    echo ""
    warn "${#UNREACHABLE_TARGETS[@]} target(s) appear unreachable."
    echo -n "Continue anyway? [Y/n] "
    read -r confirm
    case "$confirm" in
        [nN]*) echo "Aborted."; exit 0 ;;
    esac
fi
echo ""

# Confirmation (unless auto mode)
if [[ "$AUTO_MODE" != "true" ]]; then
    echo -e "${BOLD}Ready to start enumeration of ${#TARGETS[@]} target(s).${NC}"
    echo -n "Proceed? [Y/n] "
    read -r confirm
    case "$confirm" in
        [nN]*) echo "Aborted."; exit 0 ;;
    esac
fi

#------------------------------------------------------------------------------
# MAIN EXECUTION
#------------------------------------------------------------------------------
mkdir -p "$RECON_DIR"

START_TIME=$(date +%s)

# Quick-wins triage pass (runs before deep recon)
if [[ "$QUICK_WINS_MODE" == true ]]; then
    header "QUICK-WINS TRIAGE — 5 minutes per target"
    for target in "${TARGETS[@]}"; do
        qw_triage_target "$target"
    done
    qw_rank_targets
    if [[ "$QUICK_WINS_ONLY" == true ]]; then
        END_TIME=$(date +%s)
        ELAPSED=$(( END_TIME - START_TIME ))
        success "Quick-wins triage complete in ${ELAPSED}s"
        success "Run without --quick-wins-only for full enumeration"
        exit 0
    fi
    echo ""
    info "Proceeding to full enumeration..."
    echo ""
fi

if [[ "$SEQUENTIAL_TARGETS" == true ]]; then
    info "Sequential mode — scanning targets one at a time"
    for target in "${TARGETS[@]}"; do
        recon_target "$target"
    done
else
    info "Parallel mode — max ${MAX_PARALLEL_TARGETS} target(s) at once"
    for target in "${TARGETS[@]}"; do
        while (( $(jobs -rp | wc -l) >= MAX_PARALLEL_TARGETS )); do
            wait -n 2>/dev/null || true
        done
        recon_target "$target" &
    done
    wait
fi

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
MINUTES=$(( ELAPSED / 60 ))
SECONDS_REM=$(( ELAPSED % 60 ))

header "ALL TARGETS COMPLETE"
echo ""
success "Total time: ${MINUTES}m ${SECONDS_REM}s"
success "Results in: ${RECON_DIR}/"
echo ""
for target in "${TARGETS[@]}"; do
    echo -e "  ${CYAN}$target${NC} → ${RECON_DIR}/${target}/summary.txt"
done
echo ""
info "Quick wins across all targets:"
sort -u "${RECON_DIR}"/*/loot/quick_wins.txt 2>/dev/null | while IFS= read -r line; do
    echo -e "  ${GREEN}★${NC} $line"
done
echo ""
echo -e "${BOLD}Good luck on the engagement! 🎯${NC}"
