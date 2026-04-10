#!/usr/bin/env bash
#==============================================================================
# LOOTR — Post-Exploitation Loot Collection Script
#==============================================================================
# Enumeration and collection ONLY — no exploitation, OffSec compliant.
#
# PHASES:
#   1. proof    — Find local.txt / proof.txt
#   2. system   — OS, kernel, users, sudo, packages, env
#   3. creds    — Passwords, keys, hashes, histories, configs
#   4. network  — Interfaces, routes, connections, firewall
#   5. files    — SUID, world-writable, cron, capabilities, backups
#   6. procs    — Processes, services (skipped in --quick mode)
#
# USAGE:
#   ./lootr.sh                    # run all phases, output to ./loot/<hostname>/
#   ./lootr.sh --outdir /tmp/loot # custom output dir
#   ./lootr.sh --quick            # skip slow phases (network monitor, processes)
#   ./lootr.sh --phase creds      # run a single phase only
#   ./lootr.sh --help             # this help
#
# OUTPUT:
#   loot/<hostname>/
#   ├── creds/
#   ├── system/
#   ├── network/
#   ├── files/
#   ├── proof/
#   ├── progress.log
#   └── summary.txt
#==============================================================================

set -o pipefail
# NOT set -e — handle errors individually; one failure must not kill the run

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
phase()   { echo -e "\n${MAGENTA}${BOLD}[$(ts)] [PHASE] $*${NC}\n"; }

#==============================================================================
# PROGRESS TRACKING
#==============================================================================
progress_log() {
    local logfile="$1/progress.log"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $2 | $3 | $4" >> "$logfile"
}

is_phase_done() {
    grep -qF "| DONE | $2 |" "$1/progress.log" 2>/dev/null
}

proof_dest_for() {
    local proof_dir="$1"
    local source_path="$2"
    local base_name=""
    local safe_source=""

    base_name="$(basename "${source_path}")"
    safe_source="$(printf '%s' "${source_path}" | sed 's#^/##; s#[/ ]#_#g')"
    echo "${proof_dir}/${base_name}_${safe_source}"
}

#==============================================================================
# CHILD PROCESS MANAGEMENT
#==============================================================================
declare -a CHILD_PIDS=()

cleanup() {
    echo ""
    warn "Caught interrupt — cleaning up..."
    local pid=""
    for pid in "${CHILD_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    exit 130
}
trap cleanup INT TERM

#==============================================================================
# USAGE
#==============================================================================
usage() {
    echo -e "${BOLD}Usage:${NC} $0 [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  --outdir <dir>    Output directory root (default: ./loot)"
    echo "  --quick           Skip slow phases (processes, service monitoring)"
    echo "  --phase <name>    Run only one phase: proof|system|creds|network|files|procs"
    echo "  --help, -h        Show this help"
    echo ""
    echo -e "${BOLD}Output:${NC}"
    echo "  loot/<hostname>/"
    echo "  ├── creds/        Credentials, keys, hashes, histories"
    echo "  ├── system/       OS info, users, sudo, packages"
    echo "  ├── network/      Interfaces, routes, connections"
    echo "  ├── files/        SUID, writable, cron, capabilities"
    echo "  ├── proof/        local.txt and proof.txt"
    echo "  ├── progress.log  Phase completion tracking"
    echo "  └── summary.txt   High-value findings at a glance"
}

#==============================================================================
# ARGUMENT PARSING
#==============================================================================
QUICK_MODE=false
SINGLE_PHASE=""
LOOT_ROOT="./loot"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --outdir)
            [[ $# -lt 2 ]] && { error "--outdir requires an argument"; exit 1; }
            LOOT_ROOT="$2"; shift 2 ;;
        --quick)
            QUICK_MODE=true; shift ;;
        --phase)
            [[ $# -lt 2 ]] && { error "--phase requires an argument"; exit 1; }
            SINGLE_PHASE="$2"; shift 2 ;;
        --no-color)
            disable_colors; shift ;;
        --help|-h)
            usage; exit 0 ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1 ;;
    esac
done

#==============================================================================
# SETUP OUTPUT DIRECTORIES
#==============================================================================
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown")"
OUTDIR="${LOOT_ROOT}/${HOSTNAME_SHORT}"

mkdir -p -- \
    "${OUTDIR}/creds" \
    "${OUTDIR}/system" \
    "${OUTDIR}/network" \
    "${OUTDIR}/files" \
    "${OUTDIR}/proof"

if [[ ! -d "${OUTDIR}/creds" || ! -d "${OUTDIR}/system" || ! -d "${OUTDIR}/network" || ! -d "${OUTDIR}/files" || ! -d "${OUTDIR}/proof" ]]; then
    error "Failed to create output directory tree: ${OUTDIR}"
    exit 1
fi

info "Output directory: ${OUTDIR}"
info "Hostname: ${HOSTNAME_SHORT}"
info "Running as: $(id 2>/dev/null || echo 'unknown')"
[[ "${QUICK_MODE}" == "true" ]] && warn "Quick mode — skipping processes phase"
[[ -n "${SINGLE_PHASE}" ]] && info "Single phase mode: ${SINGLE_PHASE}"

#==============================================================================
# PHASE 1 — PROOF FLAGS
#==============================================================================
phase_proof() {
    phase "1 — PROOF FLAGS"
    progress_log "${OUTDIR}" "START" "proof" "Searching for proof flags"

    local proof_dir="${OUTDIR}/proof"
    local found_any=false

    info "Searching for local.txt and proof.txt..."

    local f=""
    while IFS= read -r f; do
        [[ -z "${f}" ]] && continue
        [[ -r "${f}" ]] || { warn "Found ${f} but not readable"; continue; }
        local fname=""
        local proof_copy=""
        fname="$(basename "${f}")"
        proof_copy="$(proof_dest_for "${proof_dir}" "${f}")"
        success "Found: ${f}"
        echo ""
        echo -e "${GREEN}${BOLD}══════════════════════════════════════════${NC}"
        echo -e "${GREEN}${BOLD}  FLAG: ${fname}${NC}"
        echo -e "${GREEN}${BOLD}══════════════════════════════════════════${NC}"
        cat -- "${f}"
        echo -e "${GREEN}${BOLD}══════════════════════════════════════════${NC}"
        echo ""
        echo -e "\033[1;31m╔══════════════════════════════════════════════════════════════╗\033[0m"
        echo -e "\033[1;31m║  STOP — TAKE YOUR SCREENSHOTS BEFORE DOING ANYTHING ELSE    ║\033[0m"
        echo -e "\033[1;31m║                                                              ║\033[0m"
        echo -e "\033[1;31m║  Run this on target NOW:                                     ║\033[0m"
        echo -e "\033[1;31m║    cat ${fname} && hostname && whoami && id                   ║\033[0m"
        echo -e "\033[1;31m║                                                              ║\033[0m"
        echo -e "\033[1;31m║  Screenshot must show: flag + hostname + whoami + id          ║\033[0m"
        echo -e "\033[1;31m║  ALL in the SAME terminal frame                              ║\033[0m"
        echo -e "\033[1;31m╚══════════════════════════════════════════════════════════════╝\033[0m"
        echo ""
        cp -- "${f}" "${proof_copy}" 2>/dev/null || true
        echo "source: ${f}" >> "${proof_copy}.meta"
        found_any=true
    done < <(timeout 120 find / -maxdepth 10 \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \( -name "local.txt" -o -name "proof.txt" \) -type f -print 2>/dev/null)

    if [[ "${found_any}" == "false" ]]; then
        warn "No proof flags found (local.txt / proof.txt)"
    fi

    progress_log "${OUTDIR}" "DONE" "proof" "Proof flag search complete"
}

#==============================================================================
# PHASE 2 — SYSTEM INFO
#==============================================================================
phase_system() {
    phase "2 — SYSTEM INFO"
    progress_log "${OUTDIR}" "START" "system" "Collecting system information"

    local sdir="${OUTDIR}/system"

    # OS release
    info "Collecting OS information..."
    if [[ -r /etc/os-release ]]; then
        cp -- /etc/os-release "${sdir}/os-release.txt" 2>/dev/null || true
    fi
    uname -a > "${sdir}/uname.txt" 2>&1 || true
    uname -r > "${sdir}/kernel.txt" 2>&1 || true
    hostname > "${sdir}/hostname.txt" 2>&1 || true
    uptime > "${sdir}/uptime.txt" 2>&1 || true

    # Current user
    info "Collecting user context..."
    {
        echo "=== whoami ==="
        whoami 2>/dev/null || true
        echo ""
        echo "=== id ==="
        id 2>/dev/null || true
        echo ""
        echo "=== groups ==="
        groups 2>/dev/null || true
    } > "${sdir}/current_user.txt"

    # sudo -ln avoids password prompt
    info "Checking sudo rights (non-interactive)..."
    sudo -ln 2>&1 | tee "${sdir}/sudo_rights.txt" > /dev/null || true

    # Users with real shells
    info "Collecting users with login shells..."
    grep -v "nologin" /etc/passwd 2>/dev/null | grep -v "false" > "${sdir}/users_with_shells.txt" || true

    # Logged-in users
    info "Collecting logged-in user data..."
    {
        echo "=== w ==="
        w 2>/dev/null || true
        echo ""
        echo "=== who ==="
        who 2>/dev/null || true
        echo ""
        echo "=== last -20 ==="
        last -20 2>/dev/null || true
    } > "${sdir}/logged_in_users.txt"

    # Installed packages — save to file only, not printed
    info "Collecting installed packages (saved to file)..."
    if command -v dpkg &>/dev/null; then
        dpkg -l > "${sdir}/installed_packages.txt" 2>/dev/null || true
    elif command -v rpm &>/dev/null; then
        rpm -qa > "${sdir}/installed_packages.txt" 2>/dev/null || true
    else
        echo "dpkg and rpm not found" > "${sdir}/installed_packages.txt"
    fi

    # Environment variables — redact sensitive values
    info "Collecting environment variables (redacting secrets)..."
    env 2>/dev/null | grep -viE "PASSWORD|SECRET|TOKEN|API_KEY" > "${sdir}/environment.txt" || true
    local redacted_count=""
    redacted_count="$(env 2>/dev/null | grep -ciE "PASSWORD|SECRET|TOKEN|API_KEY")"; redacted_count=${redacted_count:-0}
    if [[ "${redacted_count}" -gt 0 ]]; then
        warn "Redacted ${redacted_count} sensitive env var(s) from environment.txt"
    fi

    success "System info collected → ${sdir}/"
    progress_log "${OUTDIR}" "DONE" "system" "System info collected"
}

#==============================================================================
# PHASE 3 — CREDENTIALS
#==============================================================================
phase_creds() {
    phase "3 — CREDENTIALS"
    progress_log "${OUTDIR}" "START" "creds" "Collecting credentials"

    local cdir="${OUTDIR}/creds"

    # /etc/passwd and /etc/shadow
    info "Checking /etc/passwd and /etc/shadow..."
    if [[ -r /etc/passwd ]]; then
        cp -- /etc/passwd "${cdir}/passwd.txt" 2>/dev/null || true
        success "Copied /etc/passwd"
    fi
    if [[ -r /etc/shadow ]]; then
        cp -- /etc/shadow "${cdir}/shadow.txt" 2>/dev/null || true
        awk -F: '$2 !~ /^(\*|!|!!|!\*|x|$)/ && $2 !~ /^$/' /etc/shadow 2>/dev/null > "${cdir}/shadow_hashes.txt" || true
        success "Copied /etc/shadow — hashes extracted to shadow_hashes.txt"
    else
        warn "/etc/shadow not readable"
    fi

    # SSH private keys
    info "Searching for SSH private keys..."
    local keyfile=""
    while IFS= read -r keyfile; do
        [[ -z "${keyfile}" ]] && continue
        [[ -r "${keyfile}" ]] || continue
        local safename=""
        safename="$(echo "${keyfile}" | tr '/' '_')"
        cp -- "${keyfile}" "${cdir}/key_${safename}" 2>/dev/null || true
        success "SSH key: ${keyfile}"
    done < <(find /home /root /etc -maxdepth 5 \
        \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
           -o -name "*.pem" -o -name "*.key" \) \
        -type f 2>/dev/null)

    # SSH authorized_keys
    info "Searching for authorized_keys..."
    find /home /root /etc -maxdepth 5 -name "authorized_keys" -type f 2>/dev/null \
        > "${cdir}/authorized_keys_locations.txt" || true
    if [[ -s "${cdir}/authorized_keys_locations.txt" ]]; then
        success "Found authorized_keys — see ${cdir}/authorized_keys_locations.txt"
    fi

    # Shell histories
    info "Searching for shell histories..."
    local histfile=""
    while IFS= read -r histfile; do
        [[ -z "${histfile}" ]] && continue
        [[ -r "${histfile}" ]] || continue
        local safename=""
        safename="$(echo "${histfile}" | tr '/' '_')"
        cp -- "${histfile}" "${cdir}/history_${safename}" 2>/dev/null || true
        success "History: ${histfile}"
    done < <(find /root /home -maxdepth 3 \
        \( -name ".bash_history" -o -name ".zsh_history" -o -name ".sh_history" \) \
        -type f 2>/dev/null)

    # Config files containing password keywords — save list only
    info "Searching config files for password patterns..."
    grep -rliE "password|passwd|secret|token|api_key" \
        /var/www /opt /srv /etc/nginx /etc/apache2 \
        --include="*.conf" \
        --include="*.php" \
        --include="*.env" \
        --include="*.ini" \
        --include="*.xml" \
        --include="*.json" \
        2>/dev/null | head -50 > "${cdir}/config_files_with_creds.txt" || true
    if [[ -s "${cdir}/config_files_with_creds.txt" ]]; then
        success "Config files with cred patterns → ${cdir}/config_files_with_creds.txt"
    fi

    # .env files
    info "Searching for .env files..."
    find /var/www /opt /srv /home -maxdepth 5 -name ".env" -type f 2>/dev/null \
        > "${cdir}/dotenv_locations.txt" || true
    local envfile=""
    while IFS= read -r envfile; do
        [[ -z "${envfile}" ]] && continue
        [[ -r "${envfile}" ]] || continue
        local safename=""
        safename="$(echo "${envfile}" | tr '/' '_')"
        cp -- "${envfile}" "${cdir}/dotenv_${safename}" 2>/dev/null || true
        success ".env file: ${envfile}"
    done < "${cdir}/dotenv_locations.txt"

    # wp-config.php
    info "Searching for wp-config.php..."
    find /var/www /opt -maxdepth 6 -name "wp-config.php" -type f 2>/dev/null \
        > "${cdir}/wpconfig_locations.txt" || true
    if [[ -s "${cdir}/wpconfig_locations.txt" ]]; then
        local wpconf=""
        while IFS= read -r wpconf; do
            [[ -z "${wpconf}" ]] && continue
            [[ -r "${wpconf}" ]] || continue
            local safename=""
            safename="$(echo "${wpconf}" | tr '/' '_')"
            cp -- "${wpconf}" "${cdir}/wpconfig_${safename}" 2>/dev/null || true
            success "wp-config.php: ${wpconf}"
        done < "${cdir}/wpconfig_locations.txt"
    fi

    # Home dir credential files
    info "Checking home directories for credential files..."
    local homedir=""
    while IFS= read -r homedir; do
        [[ -z "${homedir}" ]] && continue
        local credfile=""
        for credfile in ".netrc" ".pgpass" ".my.cnf" ".aws/credentials" ".docker/config.json"; do
            local full="${homedir}/${credfile}"
            if [[ -r "${full}" ]]; then
                local safename=""
                safename="$(echo "${full}" | tr '/' '_')"
                cp -- "${full}" "${cdir}/homecred_${safename}" 2>/dev/null || true
                success "Home cred file: ${full}"
            fi
        done
    done < <(
        {
            printf '%s\n' /root
            find /home /root -maxdepth 1 -mindepth 1 -type d 2>/dev/null
        } | awk '!seen[$0]++'
    )

    # NetworkManager PSK
    info "Checking NetworkManager for saved passwords..."
    grep -r "psk\|password" /etc/NetworkManager 2>/dev/null \
        > "${cdir}/networkmanager_creds.txt" || true
    if [[ -s "${cdir}/networkmanager_creds.txt" ]]; then
        success "NetworkManager creds found → ${cdir}/networkmanager_creds.txt"
    fi

    # Kerberos
    info "Checking for Kerberos tickets..."
    {
        echo "=== klist ==="
        klist 2>/dev/null || echo "klist not available or no tickets"
        echo ""
        echo "=== ccache files ==="
        find /tmp -maxdepth 2 \( -name "krb5cc_*" -o -name "*.ccache" \) 2>/dev/null || true
    } > "${cdir}/kerberos.txt"

    success "Credentials collection complete → ${cdir}/"
    progress_log "${OUTDIR}" "DONE" "creds" "Credentials collected"
}

#==============================================================================
# PHASE 4 — NETWORK
#==============================================================================
phase_network() {
    phase "4 — NETWORK"
    progress_log "${OUTDIR}" "START" "network" "Collecting network information"

    local ndir="${OUTDIR}/network"

    # Interfaces
    info "Collecting network interfaces..."
    {
        ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "ip and ifconfig not available"
    } > "${ndir}/interfaces.txt"

    # Routes
    info "Collecting routing table..."
    {
        ip route show 2>/dev/null || route -n 2>/dev/null || echo "ip route and route not available"
    } > "${ndir}/routes.txt"

    # ARP
    info "Collecting ARP table..."
    {
        ip neigh show 2>/dev/null || arp -a 2>/dev/null || echo "ip neigh and arp not available"
    } > "${ndir}/arp.txt"

    # Connections / listeners
    info "Collecting active connections and listeners..."
    {
        ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "ss and netstat not available"
    } > "${ndir}/listeners.txt"

    # Internal pivot candidates — 127.x listeners
    info "Identifying internal-only listeners (pivot candidates)..."
    grep "127\." "${ndir}/listeners.txt" 2>/dev/null > "${ndir}/internal_listeners.txt" || true
    if [[ -s "${ndir}/internal_listeners.txt" ]]; then
        success "Internal listeners found — potential pivot targets"
        cat "${ndir}/internal_listeners.txt"
    fi

    # /etc/hosts
    info "Copying /etc/hosts..."
    cp -- /etc/hosts "${ndir}/hosts.txt" 2>/dev/null || true

    # /etc/resolv.conf
    info "Copying /etc/resolv.conf..."
    cp -- /etc/resolv.conf "${ndir}/resolv.conf" 2>/dev/null || true

    # iptables
    info "Checking iptables rules..."
    timeout 5 iptables -L -n 2>/dev/null > "${ndir}/iptables.txt" || echo "iptables not accessible" > "${ndir}/iptables.txt"

    # Reachable subnets from routes
    info "Deriving reachable subnets..."
    ip route show 2>/dev/null | awk '{print $1}' | grep -E "^[0-9]" | grep -v "^0\." \
        > "${ndir}/reachable_subnets.txt" || true
    if [[ -s "${ndir}/reachable_subnets.txt" ]]; then
        success "Reachable subnets:"
        cat "${ndir}/reachable_subnets.txt"
    fi

    success "Network info collected → ${ndir}/"
    progress_log "${OUTDIR}" "DONE" "network" "Network info collected"
}

#==============================================================================
# PHASE 5 — INTERESTING FILES
#==============================================================================
phase_files() {
    phase "5 — INTERESTING FILES"
    progress_log "${OUTDIR}" "START" "files" "Searching for interesting files"

    local fdir="${OUTDIR}/files"

    # SUID binaries
    info "Searching for SUID binaries (timeout 120s)..."
    timeout 120 find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -perm -4000 -type f -print 2>/dev/null | sort > "${fdir}/suid_binaries.txt" || true
    local suid_count=""
    suid_count="$(wc -l < "${fdir}/suid_binaries.txt" 2>/dev/null || echo 0)"
    success "Found ${suid_count} SUID binaries → ${fdir}/suid_binaries.txt"

    # World-writable sensitive files
    info "Searching for world-writable files in sensitive dirs (timeout 20s)..."
    timeout 20 find /etc /var /opt /srv -perm -o+w -type f 2>/dev/null \
        > "${fdir}/world_writable.txt" || true
    if [[ -s "${fdir}/world_writable.txt" ]]; then
        local ww_count=""
        ww_count="$(wc -l < "${fdir}/world_writable.txt")"
        warn "Found ${ww_count} world-writable files in sensitive dirs"
    fi

    # Recently modified files (last 10 days)
    info "Finding recently modified files (10 days, timeout 30s)..."
    timeout 30 find /etc /var /opt /home /tmp /srv -mtime -10 -type f 2>/dev/null \
        | grep -vE "\.log$|/proc/" | head -100 \
        > "${fdir}/recently_modified.txt" || true
    success "Recently modified files → ${fdir}/recently_modified.txt"

    # Cron jobs
    info "Collecting cron information..."
    {
        echo "=== /etc/crontab ==="
        cat /etc/crontab 2>/dev/null || echo "not readable"
        echo ""
        echo "=== /etc/cron.* ==="
        ls -la /etc/cron.* 2>/dev/null || echo "no cron.* dirs"
        echo ""
        echo "=== crontab -l (current user) ==="
        crontab -l 2>/dev/null || echo "no user crontab"
        echo ""
        echo "=== /var/spool/cron ==="
        find /var/spool/cron -type f 2>/dev/null || echo "not accessible"
    } > "${fdir}/cron_jobs.txt"
    success "Cron info → ${fdir}/cron_jobs.txt"

    # File capabilities
    info "Searching for file capabilities (timeout 15s)..."
    timeout 15 getcap -r / 2>/dev/null > "${fdir}/capabilities.txt" || true
    if [[ -s "${fdir}/capabilities.txt" ]]; then
        success "Capabilities found → ${fdir}/capabilities.txt"
        cat "${fdir}/capabilities.txt"
    fi

    # Backup and database files
    info "Searching for backup files (timeout 20s)..."
    timeout 20 find / -maxdepth 8 \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        \( -name "*.bak" -o -name "*.old" -o -name "*.backup" \
           -o -name "*.sql" -o -name "*.dump" \) \
        -type f -print 2>/dev/null \
        | head -50 \
        > "${fdir}/backup_files.txt" || true
    if [[ -s "${fdir}/backup_files.txt" ]]; then
        local bak_count=""
        bak_count="$(wc -l < "${fdir}/backup_files.txt")"
        success "Found ${bak_count} backup files → ${fdir}/backup_files.txt"
    fi

    info "Searching for database files (timeout 20s)..."
    timeout 20 find / -maxdepth 8 \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) \
        -type f -print 2>/dev/null \
        | head -30 \
        > "${fdir}/database_files.txt" || true
    if [[ -s "${fdir}/database_files.txt" ]]; then
        success "Database files → ${fdir}/database_files.txt"
    fi

    # Git repositories
    info "Searching for git repos (timeout 20s)..."
    timeout 20 find / -maxdepth 6 \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -name ".git" -type d -print 2>/dev/null \
        > "${fdir}/git_repos.txt" || true
    if [[ -s "${fdir}/git_repos.txt" ]]; then
        success "Git repos found → ${fdir}/git_repos.txt"
        cat "${fdir}/git_repos.txt"
    fi

    success "File enumeration complete → ${fdir}/"
    progress_log "${OUTDIR}" "DONE" "files" "File enumeration complete"
}

#==============================================================================
# PHASE 6 — PROCESSES & SERVICES (skip in --quick mode)
#==============================================================================
phase_procs() {
    phase "6 — PROCESSES & SERVICES"
    progress_log "${OUTDIR}" "START" "procs" "Collecting process and service info"

    local pdir="${OUTDIR}/system"

    # Full process list
    info "Collecting process list..."
    ps aux > "${pdir}/processes.txt" 2>/dev/null || true

    # Root-owned processes
    info "Identifying root-owned processes..."
    ps aux 2>/dev/null | awk 'NR==1 || /^root/' > "${pdir}/root_processes.txt" || true
    local root_proc_count=""
    root_proc_count="$(wc -l < "${pdir}/root_processes.txt" 2>/dev/null || echo 0)"
    info "Found ${root_proc_count} root-owned processes"

    # Running services
    info "Collecting running services..."
    {
        echo "=== systemctl ==="
        systemctl list-units --type=service --state=running 2>/dev/null \
            || service --status-all 2>/dev/null \
            || echo "systemctl and service not available"
    } > "${pdir}/running_services.txt"

    # pspy note
    if command -v pspy64 &>/dev/null; then
        warn "pspy64 is in PATH at $(command -v pspy64) — run manually to capture cron/process events"
    elif [[ -x "./pspy64" ]]; then
        warn "pspy64 found at ./pspy64 — run manually to capture cron/process events"
    else
        info "pspy64 not found — download from github.com/DominicBreuker/pspy for process monitoring"
    fi

    # Root-owned writable files in temp dirs
    info "Checking for root-owned writable files in temp dirs..."
    find /tmp /var/tmp -user root -perm -o+w -type f 2>/dev/null \
        > "${pdir}/root_writable_tmp.txt" || true
    if [[ -s "${pdir}/root_writable_tmp.txt" ]]; then
        warn "Root-owned world-writable files in temp dirs:"
        cat "${pdir}/root_writable_tmp.txt"
    fi

    success "Process/service info → ${pdir}/"
    progress_log "${OUTDIR}" "DONE" "procs" "Process/service info collected"
}

#==============================================================================
# SUMMARY GENERATION
#==============================================================================
generate_summary() {
    info "Generating summary.txt..."
    local sfile="${OUTDIR}/summary.txt"
    local cred_count=""
    local keycount=0
    local kf=""
    local common_suid="ping|su$|sudo|passwd|newgrp|chfn|chsh|gpasswd|pkexec|mount|umount"
    local pf=""

    # Count SSH keys before the redirect block
    for kf in "${OUTDIR}/creds/key_"*; do
        [[ -f "${kf}" ]] || continue
        keycount=$((keycount + 1))
    done
    cred_count="$(find "${OUTDIR}/creds/" -maxdepth 1 -type f 2>/dev/null | wc -l)"

    {
        echo "============================================================"
        echo "  LOOTR SUMMARY — ${HOSTNAME_SHORT}"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Running as: $(id 2>/dev/null || echo 'unknown')"
        echo "============================================================"
        echo ""

        # Proof flags
        echo "[ PROOF FLAGS ]"
        echo "------------------------------------------------------------"
        if find "${OUTDIR}/proof" -maxdepth 1 -name "*.txt" -not -name "*.meta" 2>/dev/null | grep -q .; then
            while IFS= read -r pf; do
                echo "  Flag: $(basename "${pf}")"
                echo "  Content: $(tr -d '\n' < "${pf}" 2>/dev/null)"
                echo ""
            done < <(find "${OUTDIR}/proof" -maxdepth 1 -name "*.txt" -not -name "*.meta" 2>/dev/null)
        else
            echo "  No proof flags found"
        fi
        echo ""

        # Credentials found
        echo "[ CREDENTIALS ]"
        echo "------------------------------------------------------------"
        if [[ -r "${OUTDIR}/creds/shadow.txt" ]]; then
            echo "  [!] /etc/shadow was readable — hashes in creds/shadow_hashes.txt"
        fi
        if [[ -r "${OUTDIR}/creds/passwd.txt" ]]; then
            echo "  [*] /etc/passwd copied to creds/passwd.txt"
        fi
        echo "  Total credential files collected: ${cred_count}"
        echo ""

        # SSH keys
        echo "[ SSH KEYS ]"
        echo "------------------------------------------------------------"
        if [[ ${keycount} -eq 0 ]]; then
            echo "  No SSH private keys found"
        else
            for kf in "${OUTDIR}/creds/key_"*; do
                [[ -f "${kf}" ]] || continue
                echo "  ${kf}"
            done
        fi
        echo ""

        # Sudo NOPASSWD
        echo "[ SUDO NOPASSWD ]"
        echo "------------------------------------------------------------"
        if [[ -r "${OUTDIR}/system/sudo_rights.txt" ]]; then
            grep -i "NOPASSWD" "${OUTDIR}/system/sudo_rights.txt" 2>/dev/null \
                | sed 's/^/  /' || echo "  No NOPASSWD entries"
        else
            echo "  sudo output not available"
        fi
        echo ""

        # Internal listeners
        echo "[ INTERNAL LISTENERS (127.0.0.1 — pivot candidates) ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/network/internal_listeners.txt" ]]; then
            sed 's/^/  /' "${OUTDIR}/network/internal_listeners.txt" 2>/dev/null
        else
            echo "  None identified"
        fi
        echo ""

        # SUID — filter common legit ones
        echo "[ SUID BINARIES (non-standard) ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/files/suid_binaries.txt" ]]; then
            grep -vE "${common_suid}" "${OUTDIR}/files/suid_binaries.txt" 2>/dev/null \
                | sed 's/^/  /' || echo "  Only common/expected SUID binaries found"
        else
            echo "  SUID list not available"
        fi
        echo ""

        # File capabilities
        echo "[ FILE CAPABILITIES ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/files/capabilities.txt" ]]; then
            sed 's/^/  /' "${OUTDIR}/files/capabilities.txt" 2>/dev/null
        else
            echo "  No special capabilities found"
        fi
        echo ""

        # High-value cred files
        echo "[ HIGH-VALUE CREDENTIAL FILES ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/creds/config_files_with_creds.txt" ]]; then
            head -20 "${OUTDIR}/creds/config_files_with_creds.txt" 2>/dev/null | sed 's/^/  /'
        else
            echo "  None found"
        fi
        echo ""

        # Reachable subnets
        echo "[ REACHABLE SUBNETS ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/network/reachable_subnets.txt" ]]; then
            sed 's/^/  /' "${OUTDIR}/network/reachable_subnets.txt" 2>/dev/null
        else
            echo "  Route info not available"
        fi
        echo ""

        echo "============================================================"
        echo "  Full data in: ${OUTDIR}/"
        echo "============================================================"

    } > "${sfile}"

    success "Summary written → ${sfile}"
    echo ""
    cat "${sfile}"
}

#==============================================================================
# MAIN
#==============================================================================
echo -e "\n${CYAN}${BOLD}"
echo "  ██╗      ██████╗  ██████╗ ████████╗██████╗ "
echo "  ██║     ██╔═══██╗██╔═══██╗╚══██╔══╝██╔══██╗"
echo "  ██║     ██║   ██║██║   ██║   ██║   ██████╔╝"
echo "  ██║     ██║   ██║██║   ██║   ██║   ██╔══██╗"
echo "  ███████╗╚██████╔╝╚██████╔╝   ██║   ██║  ██║"
echo "  ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝"
echo -e "${NC}"
info "Post-exploitation loot collection — OffSec edition"
info "Enumeration/collection only — no exploitation"
echo ""

if [[ -n "${SINGLE_PHASE}" ]]; then
    case "${SINGLE_PHASE}" in
        proof)   phase_proof ;;
        system)  phase_system ;;
        creds)   phase_creds ;;
        network) phase_network ;;
        files)   phase_files ;;
        procs)   phase_procs ;;
        *)
            error "Unknown phase: ${SINGLE_PHASE}"
            error "Valid phases: proof system creds network files procs"
            exit 1 ;;
    esac
else
    phase_proof
    phase_system
    phase_creds
    phase_network
    phase_files
    if [[ "${QUICK_MODE}" == "true" ]]; then
        warn "Skipping processes phase (--quick mode)"
    else
        phase_procs
    fi
fi

generate_summary

echo ""
success "Loot collection complete. Output: ${OUTDIR}/"
success "Quick review: cat ${OUTDIR}/summary.txt"
