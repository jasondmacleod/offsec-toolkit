#!/usr/bin/env bash
#==============================================================================
# evidencr.sh - OffSec Evidence Capture Ledger
#==============================================================================
# Kali-side only. Documentation/evidence capture only - no target interaction.
# Single-file, resume-safe, append-only ledger for per-machine reporting notes.
#==============================================================================

set -o pipefail

# Absolute dir of this script — used to emit PWD-independent commands that
# reference sibling toolkit scripts in any generated notes.
# shellcheck disable=SC2034  # reserved for sibling-command emission
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

USE_COLOR=true
ts()      { date '+%H:%M:%S'; }
info()    { echo "[$(ts)] [*] $*"; }
success() { if [[ "$USE_COLOR" == true ]]; then echo -e "\e[32m[$(ts)] [+] $*\e[0m"; else echo "[$(ts)] [+] $*"; fi; }
warn()    { if [[ "$USE_COLOR" == true ]]; then echo -e "\e[33m[$(ts)] [!] $*\e[0m"; else echo "[$(ts)] [!] $*"; fi; }
error()   { if [[ "$USE_COLOR" == true ]]; then echo -e "\e[31m[$(ts)] [-] $*\e[0m"; else echo "[$(ts)] [-] $*"; fi; }
phase()   { if [[ "$USE_COLOR" == true ]]; then echo -e "\n\e[35m[$(ts)] [EVIDENCE] $*\e[0m\n"; else echo -e "\n[$(ts)] [EVIDENCE] $*\n"; fi; }

disable_colors() { USE_COLOR=false; }
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

if [[ -z "${TOOLKIT_ROOT:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        _inv_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        TOOLKIT_ROOT="${_inv_home:-$HOME}/offsec"
        unset _inv_home
    else
        TOOLKIT_ROOT="${HOME}/offsec"
    fi
fi
OUTDIR="${TOOLKIT_ROOT}/evidence"
TARGET_IP=""
HOSTNAME_INPUT=""
FLAG_TYPE=""
FLAG_PATH=""
NON_INTERACTIVE=false
LOCAL_FLAG_INPUT=""
PROOF_FLAG_INPUT=""
OS_INPUT=""
POINTS_INPUT=""
CATEGORY_INPUT=""
FOOTHOLD_USER_INPUT=""
ELEVATED_USER_INPUT=""
MSF_USED=false
ROLLUP_MODE=false

PROGRESS_LOG=""
IP_DIR=""
FLAGS_DIR=""
SCREENSHOT_DIR=""
CHAIN_DIR=""
LEDGER_FILE=""

VPN_IFACE=""
VPN_IP="unknown"
KALI_USER="$(whoami 2>/dev/null || echo "unknown")"
RUN_TS="$(date '+%Y-%m-%d %H:%M:%S')"
RUN_EPOCH="$(date '+%s')"

TARGET_OS=""
POINTS_VALUE=""
MACHINE_CATEGORY=""
FOOTHOLD_USER="[not provided]"
ELEVATED_USER="[not provided]"

LOCAL_FLAG_VALUE="not collected"
PROOF_FLAG_VALUE="not collected"
FLAG_COPY_NOTE="[not provided]"

write_progress() { echo "$(date '+%Y-%m-%d %H:%M:%S') | $1 | $2 | $3" >> "$PROGRESS_LOG"; }

cleanup() {
    echo ""
    [[ -n "$PROGRESS_LOG" ]] && write_progress "INTERRUPTED" "run" "Interrupted by operator"
    warn "Interrupted. Progress saved to ${PROGRESS_LOG:-[not initialized]}"
    exit 130
}
trap cleanup INT TERM

usage() {
    cat <<EOF
Usage: ./evidencr.sh -t <IP> [OPTIONS]
       ./evidencr.sh --rollup [-o <outdir>]

Required (per-machine mode):
  -t <IP>              Target IP address

Options:
  -n <hostname>        Target hostname (default: prompted interactively)
  --flags <type>       Flag type: local|proof|both (default: prompted)
  --local-flag VALUE   Provide local.txt flag value (for non-interactive use)
  --proof-flag VALUE   Provide proof.txt flag value (for non-interactive use)
  -p <flag_path>       Full path to flag file on Kali for local copy
  --no-color           Disable colored output
  --os <os>            Target OS: Linux|Windows
  --points <value>     Points value: 10|20|25
  --category <type>    Machine category: standalone|AD-client|AD-DC
  --foothold-user U    Initial low-priv user used for foothold
  --elevated-user U    Elevated user account (root/SYSTEM/Administrator)
  --msf-used           Mark this machine as MSF/Meterpreter-used
                       (OffSec limit: 1 machine only; --rollup will count)
  -o <outdir>          Output directory (default: \$TOOLKIT_ROOT/evidence)
  --non-interactive    Skip all prompts; use flags only
  -h, --help           Show this help

Rollup mode:
  --rollup             Parse evidence_ledger.txt and print engagement-wide summary:
                         total points, per-category breakdown, missing flags,
                         MSF count vs OffSec limit, pass/fail vs 70-pt threshold.
EOF
}

is_valid_ip() {
    local ip="$1"
    local octet=""
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

is_uuid_like() {
    [[ "$1" =~ ^[A-Fa-f0-9]{32}$ || "$1" =~ ^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$ ]]
}

confirm_yes() {
    local prompt="$1"
    local reply=""
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        return 0
    fi
    read -r -p "$prompt [y/N]: " reply
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

prompt_value() {
    local prompt="$1"
    local default_value="$2"
    local result=""

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        printf '%s' "$default_value"
        return 0
    fi

    if [[ -n "$default_value" ]]; then
        read -r -p "$prompt [$default_value]: " result
        printf '%s' "${result:-$default_value}"
    else
        read -r -p "$prompt: " result
        printf '%s' "$result"
    fi
}

prompt_choice() {
    local prompt="$1"
    local default_value="$2"
    shift 2
    local allowed=("$@")
    local value=""
    local candidate=""

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        printf '%s' "$default_value"
        return 0
    fi

    while true; do
        read -r -p "$prompt [$default_value]: " value
        candidate="${value:-$default_value}"
        # Fix 7: renamed loop variable from 'value' to 'opt' to avoid
        # shadowing the user-input variable above
        for opt in "${allowed[@]}"; do
            if [[ "$candidate" == "$opt" ]]; then
                printf '%s' "$candidate"
                return 0
            fi
        done
        warn "Invalid choice: $candidate"
    done
}

print_expected_locations() {
    local flag_kind="$1"

    if [[ "$TARGET_OS" == "Linux" ]]; then
        if [[ "$flag_kind" == "local" ]]; then
            info "Expected local flag paths:"
            echo "  - /home/<user>/local.txt"
            echo "  - /var/www/html/local.txt"
        else
            info "Expected proof flag path:"
            echo "  - /root/proof.txt"
        fi
    else
        if [[ "$flag_kind" == "local" ]]; then
            info "Expected local flag path:"
            echo '  - C:\Users\<user>\Desktop\local.txt'
        else
            info "Expected proof flag path:"
            echo '  - C:\Users\Administrator\Desktop\proof.txt'
        fi
    fi
}

copy_flag_file_if_requested() {
    local flag_kind="$1"
    local dest=""

    if [[ -z "$FLAG_PATH" ]]; then
        return 0
    fi

    if [[ -e "$FLAG_PATH" ]]; then
        dest="${FLAGS_DIR}/${flag_kind}_$(basename "$FLAG_PATH")_${RUN_EPOCH}"
    if cp "$FLAG_PATH" "$dest"; then
            if [[ "$FLAG_COPY_NOTE" == "[not provided]" ]]; then
                FLAG_COPY_NOTE="Copied for ${flag_kind}: $dest"
            else
                FLAG_COPY_NOTE="${FLAG_COPY_NOTE}; Copied for ${flag_kind}: $dest"
            fi
            success "Copied provided flag file to $dest"
        else
            if [[ "$FLAG_COPY_NOTE" == "[not provided]" ]]; then
                FLAG_COPY_NOTE="Copy failed for ${flag_kind}: $FLAG_PATH"
            else
                FLAG_COPY_NOTE="${FLAG_COPY_NOTE}; Copy failed for ${flag_kind}: $FLAG_PATH"
            fi
            warn "Failed to copy provided flag file: $FLAG_PATH"
        fi
    else
        if [[ "$FLAG_COPY_NOTE" == "[not provided]" ]]; then
            FLAG_COPY_NOTE="Missing local path for ${flag_kind}: $FLAG_PATH"
        else
            FLAG_COPY_NOTE="${FLAG_COPY_NOTE}; Missing local path for ${flag_kind}: $FLAG_PATH"
        fi
        warn "Provided flag path does not exist locally: $FLAG_PATH"
    fi
}

record_flag_value() {
    local flag_kind="$1"
    local flag_label=""
    local flag_value=""
    local record_file=""

    copy_flag_file_if_requested "$flag_kind"
    print_expected_locations "$flag_kind"
    flag_label="${flag_kind}.txt"

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        if [[ "$flag_kind" == "local" && -n "${LOCAL_FLAG_INPUT:-}" ]]; then
            flag_value="$LOCAL_FLAG_INPUT"
        elif [[ "$flag_kind" == "proof" && -n "${PROOF_FLAG_INPUT:-}" ]]; then
            flag_value="$PROOF_FLAG_INPUT"
        else
            flag_value="not collected"
            warn "Non-interactive mode: ${flag_label} left as not collected (use --local-flag / --proof-flag)"
        fi
        if [[ "$flag_value" != "not collected" ]] && ! is_uuid_like "$flag_value"; then
            warn "Non-interactive ${flag_label} value does not match expected UUID format: ${flag_value}"
        fi
    else
        # Fix 8: use silent read (-s) so the UUID is not visible in
        # terminal scrollback; echo "" restores the newline
        read -rsp "Enter flag value for ${flag_label} (paste the UUID): " flag_value
        echo ""
        if [[ -z "$flag_value" ]]; then
            flag_value="not collected"
        elif ! is_uuid_like "$flag_value"; then
            warn "Flag value does not match expected UUID format"
        fi
    fi

    record_file="${FLAGS_DIR}/${flag_kind}.txt"
    {
        echo "[$RUN_TS] $flag_value"
    } >> "$record_file"

    if [[ "$flag_kind" == "local" ]]; then
        LOCAL_FLAG_VALUE="$flag_value"
    else
        PROOF_FLAG_VALUE="$flag_value"
    fi
}

generate_checklist_content() {
    local checklist_path="$1"

    local pivot_note=""
    local pivot_label="(if pivoting was involved)"

    # AD machines almost always require a network_position.png showing
    # pivot/proxy topology — promote from optional to REQUIRED.
    if [[ "$MACHINE_CATEGORY" == "AD-client" || "$MACHINE_CATEGORY" == "AD-DC" ]]; then
        pivot_label="(REQUIRED for AD — show pivot/proxy topology)"
    fi

    case "$FLAG_TYPE" in
        local) pivot_note=$'[ ] 3. network_position.png  '"$pivot_label"$'\n    Must show: your pivot setup confirming reachability\n' ;;
        proof) pivot_note=$'[ ] 5. network_position.png  '"$pivot_label"$'\n    Must show: your pivot setup confirming reachability\n' ;;
        both)  pivot_note=$'[ ] 6. network_position.png  '"$pivot_label"$'\n    Must show: your pivot setup confirming reachability\n' ;;
    esac

    if [[ "$TARGET_OS" == "Linux" ]]; then
        case "$FLAG_TYPE" in
            local)
                {
                    echo "SCREENSHOT CHECKLIST — ${TARGET_IP} (${HOSTNAME_INPUT})"
                    echo "Generated: ${RUN_TS}"
                    echo ""
                    echo "[ ] 1. local_flag.png"
                    echo "    Command: cat /home/<user>/local.txt && hostname && whoami && id"
                    echo "    Must show: flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 2. low_priv_shell.png"
                    echo "    Must show: your initial shell with target hostname visible"
                    echo ""
                    printf '%s\n' "$pivot_note"
                } > "$checklist_path"
                ;;
            proof)
                {
                    echo "SCREENSHOT CHECKLIST — ${TARGET_IP} (${HOSTNAME_INPUT})"
                    echo "Generated: ${RUN_TS}"
                    echo ""
                    echo "[ ] 1. proof_flag.png"
                    echo "    Command: cat /root/proof.txt && hostname && whoami && id"
                    echo "    Must show: flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 2. low_priv_shell.png"
                    echo "    Must show: your initial shell with target hostname visible"
                    echo ""
                    echo "[ ] 3. privesc_vector.png"
                    echo "    Must show: the command/exploit that granted elevated access"
                    echo ""
                    echo "[ ] 4. root_shell.png"
                    echo "    Must show: root shell with hostname and id output"
                    echo ""
                    printf '%s\n' "$pivot_note"
                } > "$checklist_path"
                ;;
            both)
                {
                    echo "SCREENSHOT CHECKLIST — ${TARGET_IP} (${HOSTNAME_INPUT})"
                    echo "Generated: ${RUN_TS}"
                    echo ""
                    echo "[ ] 1. local_flag.png"
                    echo "    Command: cat /home/<user>/local.txt && hostname && whoami && id"
                    echo "    Must show: local flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 2. low_priv_shell.png"
                    echo "    Must show: your initial shell with target hostname visible"
                    echo ""
                    echo "[ ] 3. privesc_vector.png"
                    echo "    Must show: the command/exploit that granted elevated access"
                    echo ""
                    echo "[ ] 4. proof_flag.png"
                    echo "    Command: cat /root/proof.txt && hostname && whoami && id"
                    echo "    Must show: proof flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 5. root_shell.png"
                    echo "    Must show: root shell with hostname and id output"
                    echo ""
                    printf '%s\n' "$pivot_note"
                } > "$checklist_path"
                ;;
        esac
    else
        case "$FLAG_TYPE" in
            local)
                {
                    echo "SCREENSHOT CHECKLIST — ${TARGET_IP} (${HOSTNAME_INPUT})"
                    echo "Generated: ${RUN_TS}"
                    echo ""
                    echo "[ ] 1. local_flag.png"
                    echo '    Command: type C:\Users\<user>\Desktop\local.txt && hostname && whoami'
                    echo "    Must show: flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 2. low_priv_shell.png"
                    echo "    Must show: your initial shell with target hostname visible"
                    echo ""
                    printf '%s\n' "$pivot_note"
                } > "$checklist_path"
                ;;
            proof)
                {
                    echo "SCREENSHOT CHECKLIST — ${TARGET_IP} (${HOSTNAME_INPUT})"
                    echo "Generated: ${RUN_TS}"
                    echo ""
                    echo "[ ] 1. proof_flag.png"
                    echo '    Command: type C:\Users\Administrator\Desktop\proof.txt && hostname && whoami'
                    echo "    Must show: flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 2. low_priv_shell.png"
                    echo "    Must show: your initial shell with target hostname visible"
                    echo ""
                    echo "[ ] 3. privesc_vector.png"
                    echo "    Must show: the command/exploit that granted elevated access"
                    echo ""
                    echo "[ ] 4. system_shell.png"
                    echo "    Must show: SYSTEM/Administrator shell with hostname and whoami output"
                    echo ""
                    printf '%s\n' "$pivot_note"
                } > "$checklist_path"
                ;;
            both)
                {
                    echo "SCREENSHOT CHECKLIST — ${TARGET_IP} (${HOSTNAME_INPUT})"
                    echo "Generated: ${RUN_TS}"
                    echo ""
                    echo "[ ] 1. local_flag.png"
                    echo '    Command: type C:\Users\<user>\Desktop\local.txt && hostname && whoami'
                    echo "    Must show: local flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 2. low_priv_shell.png"
                    echo "    Must show: your initial shell with target hostname visible"
                    echo ""
                    echo "[ ] 3. privesc_vector.png"
                    echo "    Must show: the command/exploit that granted elevated access"
                    echo ""
                    echo "[ ] 4. proof_flag.png"
                    echo '    Command: type C:\Users\Administrator\Desktop\proof.txt && hostname && whoami'
                    echo "    Must show: proof flag UUID + hostname + whoami output in same terminal frame"
                    echo ""
                    echo "[ ] 5. system_shell.png"
                    echo "    Must show: SYSTEM/Administrator shell with hostname and whoami output"
                    echo ""
                    printf '%s\n' "$pivot_note"
                } > "$checklist_path"
                ;;
        esac
    fi

    printf '\n' >> "$checklist_path"
}

collect_attack_chain() {
    local chain_file="${CHAIN_DIR}/attack_chain.txt"
    local lines=()
    local line=""
    local blank_count=0

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        {
            echo "--- ${RUN_TS} ---"
            echo "[not recorded]"
            echo ""
        } >> "$chain_file"
        return 0
    fi

    echo "Enter your attack chain (press ENTER twice when done):"
    while true; do
        read -r -p "> " line
        if [[ -z "$line" ]]; then
            (( blank_count++ ))
            if (( blank_count >= 2 )); then
                break
            fi
            continue
        fi
        blank_count=0
        lines+=("$line")
    done

    {
        echo "--- ${RUN_TS} ---"
        if [[ ${#lines[@]} -eq 0 ]]; then
            echo "[not recorded]"
        else
            printf '%s\n' "${lines[@]}"
        fi
        echo ""
    } >> "$chain_file"
}

build_summary_block() {
    local checklist_path="${SCREENSHOT_DIR}/checklist.txt"
    local chain_file="${CHAIN_DIR}/attack_chain.txt"
    cat <<EOF
============================================================
  EVIDENCE SUMMARY — ${TARGET_IP} (${HOSTNAME_INPUT})
  Recorded: ${RUN_TS}
  Running as: ${KALI_USER}
  VPN IP: ${VPN_IP}
============================================================

[ TARGET ]
  IP:         ${TARGET_IP}
  Hostname:   ${HOSTNAME_INPUT}
  OS:         ${TARGET_OS}
  Category:   ${MACHINE_CATEGORY}
  Points:     ${POINTS_VALUE}

[ USERS ]
  Foothold:   ${FOOTHOLD_USER}
  Elevated:   ${ELEVATED_USER}

[ FLAGS ]
  local.txt:  ${LOCAL_FLAG_VALUE}
  proof.txt:  ${PROOF_FLAG_VALUE}
  Copy note:  ${FLAG_COPY_NOTE}

[ SCREENSHOTS REQUIRED ]
$(cat "$checklist_path" 2>/dev/null || echo "[checklist not generated]")

[ SCREENSHOTS MISSING ]
$(if [[ -s "${SCREENSHOT_DIR}/missing_screenshots.txt" ]]; then
    cat "${SCREENSHOT_DIR}/missing_screenshots.txt"
else
    echo "[all expected screenshots present]"
fi)

[ ATTACK CHAIN ]
$(cat "$chain_file" 2>/dev/null || echo "[chain not recorded]")

[ EXPLOITS / CVES REFERENCED ]
$(cat "${CHAIN_DIR}/exploits_referenced.txt" 2>/dev/null || echo "[none recorded]")

[ FILES ]
  Evidence dir: ${IP_DIR}
============================================================
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t)
                [[ $# -lt 2 ]] && { error "-t requires an argument"; exit 1; }
                TARGET_IP="$2"; shift 2 ;;
            -n)
                [[ $# -lt 2 ]] && { error "-n requires an argument"; exit 1; }
                HOSTNAME_INPUT="$2"; shift 2 ;;
            --flags)
                [[ $# -lt 2 ]] && { error "--flags requires an argument"; exit 1; }
                FLAG_TYPE="$2"; shift 2 ;;
            --local-flag)
                [[ $# -lt 2 ]] && { error "--local-flag requires an argument"; exit 1; }
                LOCAL_FLAG_INPUT="$2"; shift 2 ;;
            --proof-flag)
                [[ $# -lt 2 ]] && { error "--proof-flag requires an argument"; exit 1; }
                PROOF_FLAG_INPUT="$2"; shift 2 ;;
            --no-color)
                disable_colors; shift ;;
            -p)
                [[ $# -lt 2 ]] && { error "-p requires an argument"; exit 1; }
                FLAG_PATH="$2"; shift 2 ;;
            -o)
                [[ $# -lt 2 ]] && { error "-o requires an argument"; exit 1; }
                OUTDIR="$2"; shift 2 ;;
            --os)
                [[ $# -lt 2 ]] && { error "--os requires an argument"; exit 1; }
                OS_INPUT="$2"; shift 2 ;;
            --points)
                [[ $# -lt 2 ]] && { error "--points requires an argument"; exit 1; }
                POINTS_INPUT="$2"; shift 2 ;;
            --category)
                [[ $# -lt 2 ]] && { error "--category requires an argument"; exit 1; }
                CATEGORY_INPUT="$2"; shift 2 ;;
            --non-interactive)
                NON_INTERACTIVE=true; shift ;;
            --foothold-user)
                [[ $# -lt 2 ]] && { error "--foothold-user requires an argument"; exit 1; }
                FOOTHOLD_USER_INPUT="$2"; shift 2 ;;
            --elevated-user)
                [[ $# -lt 2 ]] && { error "--elevated-user requires an argument"; exit 1; }
                ELEVATED_USER_INPUT="$2"; shift 2 ;;
            --msf-used)
                MSF_USED=true; shift ;;
            --rollup)
                ROLLUP_MODE=true; shift ;;
            -h|--help|help)
                usage; exit 0 ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1 ;;
        esac
    done
}

preflight() {
    phase "0 - PREFLIGHT"

    [[ -n "$TARGET_IP" ]] || { error "Target IP is required"; usage; exit 1; }
    is_valid_ip "$TARGET_IP" || { error "Invalid IPv4 address: $TARGET_IP"; exit 1; }

    VPN_IFACE="tun0"
    VPN_IP="$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)"
    if [[ -z "$VPN_IP" ]]; then
        VPN_IFACE="eth0"
        VPN_IP="$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)"
    fi
    if [[ -z "$VPN_IP" ]]; then
        # Fallback: resolve egress interface via default route, then read its IPv4
        local route_iface route_ip
        route_iface="$(ip route get "$TARGET_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
        [[ -z "$route_iface" ]] && \
            route_iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
        if [[ -n "$route_iface" ]]; then
            route_ip="$(ip -4 addr show "$route_iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)"
            if [[ -n "$route_ip" ]]; then
                VPN_IFACE="$route_iface"
                VPN_IP="$route_ip"
            fi
        fi
    fi
    [[ -z "$VPN_IP" ]] && VPN_IP="unknown"

    info "Kali IP (${VPN_IFACE}): ${VPN_IP}"

    IP_DIR="${OUTDIR}/${TARGET_IP}"
    FLAGS_DIR="${IP_DIR}/flags"
    SCREENSHOT_DIR="${IP_DIR}/screenshots"
    CHAIN_DIR="${IP_DIR}/chain"
    LEDGER_FILE="${OUTDIR}/evidence_ledger.txt"
    PROGRESS_LOG="${OUTDIR}/progress.log"

    mkdir -p "$FLAGS_DIR" || { error "Failed to create ${FLAGS_DIR}"; exit 1; }
    mkdir -p "$SCREENSHOT_DIR" || { error "Failed to create ${SCREENSHOT_DIR}"; exit 1; }
    mkdir -p "$CHAIN_DIR" || { error "Failed to create ${CHAIN_DIR}"; exit 1; }
    touch "$LEDGER_FILE" || { error "Failed to create ${LEDGER_FILE}"; exit 1; }
    touch "$PROGRESS_LOG" || { error "Failed to create ${PROGRESS_LOG}"; exit 1; }
    touch "${IP_DIR}/summary.txt" || { error "Failed to create ${IP_DIR}/summary.txt"; exit 1; }

    if [[ ! -s "$LEDGER_FILE" ]]; then
        printf '%s\n' "# TIMESTAMP | IP | HOSTNAME | OS | CATEGORY | POINTS | LOCAL | PROOF | FOOTHOLD | ELEVATED | MSF | CHAIN | DIR" >> "$LEDGER_FILE"
    fi

    if [[ "$MSF_USED" == "true" ]]; then
        touch "${IP_DIR}/msf_used.flag" || warn "Failed to create msf_used.flag marker"
    fi

    if grep -qF "| DONE | ${TARGET_IP} |" "$PROGRESS_LOG" 2>/dev/null; then
        warn "Machine ${TARGET_IP} already has a DONE entry in progress.log"
        if [[ "$NON_INTERACTIVE" != "true" ]] && ! confirm_yes "Continue and append another evidence run for ${TARGET_IP}?"; then
            warn "Aborted by operator"
            exit 0
        fi
    fi

    write_progress "START" "$TARGET_IP" "Preflight complete"
}

collect_machine_context() {
    local os_choice=""
    local category_choice=""

    phase "1 - MACHINE CONTEXT"
    write_progress "START" "context" "Collecting machine context"

    HOSTNAME_INPUT="$(prompt_value "Hostname" "${HOSTNAME_INPUT:-unknown}")"

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        TARGET_OS="${OS_INPUT:-unknown}"
        FLAG_TYPE="${FLAG_TYPE:-local}"
        POINTS_VALUE="${POINTS_INPUT:-[not provided]}"
        MACHINE_CATEGORY="${CATEGORY_INPUT:-[not provided]}"
        FOOTHOLD_USER="${FOOTHOLD_USER_INPUT:-[not provided]}"
        ELEVATED_USER="${ELEVATED_USER_INPUT:-[not provided]}"
    else
        os_choice="$(prompt_choice "OS [Linux/Windows, choose Linux or Windows]" "${OS_INPUT:-Linux}" "Linux" "Windows")"
        TARGET_OS="$os_choice"
        FLAG_TYPE="$(prompt_choice "Flag type [local/proof/both]" "${FLAG_TYPE:-both}" "local" "proof" "both")"
        POINTS_VALUE="$(prompt_choice "Points value [10/20/25]" "${POINTS_INPUT:-20}" "10" "20" "25")"
        category_choice="$(prompt_choice "Machine category [standalone/AD-client/AD-DC]" "${CATEGORY_INPUT:-standalone}" "standalone" "AD-client" "AD-DC")"
        MACHINE_CATEGORY="$category_choice"
        FOOTHOLD_USER="$(prompt_value "Initial foothold user (low-priv)" "${FOOTHOLD_USER_INPUT:-[not provided]}")"
        ELEVATED_USER="$(prompt_value "Elevated user (root/SYSTEM/Administrator)" "${ELEVATED_USER_INPUT:-[not provided]}")"
    fi

    case "$TARGET_OS" in
        Linux|Windows|unknown) ;;
        *)
            warn "Invalid OS '${TARGET_OS}' provided; defaulting to unknown"
            TARGET_OS="unknown"
            ;;
    esac

    case "$FLAG_TYPE" in
        local|proof|both) ;;
        *)
            warn "Invalid flag type '${FLAG_TYPE}' provided; defaulting to local"
            FLAG_TYPE="local"
            ;;
    esac

    case "$POINTS_VALUE" in
        10|20|25|'[not provided]') ;;
        *)
            warn "Invalid points value '${POINTS_VALUE}' provided; defaulting to [not provided]"
            POINTS_VALUE="[not provided]"
            ;;
    esac

    case "$MACHINE_CATEGORY" in
        standalone|AD-client|AD-DC|'[not provided]') ;;
        *)
            warn "Invalid machine category '${MACHINE_CATEGORY}' provided; defaulting to [not provided]"
            MACHINE_CATEGORY="[not provided]"
            ;;
    esac

    cat <<EOF
Machine IP:        ${TARGET_IP}
Hostname:          ${HOSTNAME_INPUT}
OS:                ${TARGET_OS}
Flag type:         ${FLAG_TYPE}
Points value:      ${POINTS_VALUE}
Machine category:  ${MACHINE_CATEGORY}
Foothold user:     ${FOOTHOLD_USER}
Elevated user:     ${ELEVATED_USER}
EOF

    if [[ "$NON_INTERACTIVE" != "true" ]] && ! confirm_yes "Proceed with this machine context?"; then
        error "Operator declined context confirmation"
        exit 1
    fi

    write_progress "DONE" "context" "hostname=${HOSTNAME_INPUT} os=${TARGET_OS} flags=${FLAG_TYPE}"
}

collect_flags() {
    phase "2 - FLAG COLLECTION"
    write_progress "START" "flags" "Recording flags"

    case "$FLAG_TYPE" in
        local)
            record_flag_value "local"
            ;;
        proof)
            record_flag_value "proof"
            ;;
        both)
            record_flag_value "local"
            record_flag_value "proof"
            ;;
    esac

    write_progress "DONE" "flags" "local=${LOCAL_FLAG_VALUE} proof=${PROOF_FLAG_VALUE}"
}

generate_screenshot_checklist() {
    local checklist_path="${SCREENSHOT_DIR}/checklist.txt"

    phase "3 - SCREENSHOT CHECKLIST"
    write_progress "START" "screenshots" "Generating checklist"

    generate_checklist_content "$checklist_path"

    echo -e "\e[32m$(cat "$checklist_path")\e[0m"

    write_progress "DONE" "screenshots" "checklist=${checklist_path}"
}

capture_attack_chain() {
    phase "4 - ATTACK CHAIN"
    write_progress "START" "chain" "Recording attack chain"
    collect_attack_chain
    collect_exploit_references
    write_progress "DONE" "chain" "chain_file=${CHAIN_DIR}/attack_chain.txt"
}

collect_exploit_references() {
    local exploits_file="${CHAIN_DIR}/exploits_referenced.txt"
    local lines=()
    local line=""
    local blank_count=0

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        {
            echo "--- ${RUN_TS} ---"
            echo "[not recorded]"
            echo ""
        } >> "$exploits_file"
        return 0
    fi

    echo ""
    echo "Public exploit / CVE references used on this target"
    echo "  (CVE IDs, exploit-db IDs, GitHub URLs, blog URLs)"
    echo "  Press ENTER twice when done; leave blank if only used built-in tools:"
    while true; do
        read -r -p "> " line
        if [[ -z "$line" ]]; then
            (( blank_count++ ))
            if (( blank_count >= 2 )); then
                break
            fi
            continue
        fi
        blank_count=0
        lines+=("$line")
    done

    {
        echo "--- ${RUN_TS} ---"
        if [[ ${#lines[@]} -eq 0 ]]; then
            echo "[none / built-in tools only]"
        else
            printf '%s\n' "${lines[@]}"
        fi
        echo ""
    } >> "$exploits_file"
}

audit_screenshots() {
    local checklist_path="${SCREENSHOT_DIR}/checklist.txt"
    local missing_file="${SCREENSHOT_DIR}/missing_screenshots.txt"
    local expected=()
    local actual=()
    local missing=()
    local name=""

    [[ -f "$checklist_path" ]] || return 0

    # Extract expected filenames: lines like "[ ] N. foo.png"
    mapfile -t expected < <(grep -oE '[[:alnum:]_]+\.png' "$checklist_path" | sort -u)
    mapfile -t actual < <(find "$SCREENSHOT_DIR" -maxdepth 1 -type f -name '*.png' -printf '%f\n' 2>/dev/null | sort -u)

    for name in "${expected[@]}"; do
        local found=false
        local a=""
        for a in "${actual[@]}"; do
            [[ "$a" == "$name" ]] && { found=true; break; }
        done
        [[ "$found" == "false" ]] && missing+=("$name")
    done

    : > "$missing_file"
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing screenshots for ${TARGET_IP} (${#missing[@]}):"
        printf '  - %s\n' "${missing[@]}"
        printf '%s\n' "${missing[@]}" > "$missing_file"
    else
        success "All expected screenshots present in ${SCREENSHOT_DIR}"
    fi
}

write_summary() {
    local summary_path="${IP_DIR}/summary.txt"
    local summary_block=""

    phase "5 - MACHINE SUMMARY BLOCK"
    write_progress "START" "summary" "Generating summary"

    audit_screenshots

    summary_block="$(build_summary_block)"
    printf '%s\n\n' "$summary_block" | tee -a "$summary_path"

    write_progress "DONE" "summary" "summary=${summary_path}"
}

append_ledger() {
    local chain_lines=""

    phase "6 - LEDGER APPEND"
    write_progress "START" "ledger" "Appending evidence ledger"

    chain_lines="$(
        awk '
                /^--- / { block = ""; next }
                { block = block $0 ORS }
                END { printf "%s", block }
            ' "${CHAIN_DIR}/attack_chain.txt" 2>/dev/null \
            | sed '/^[[:space:]]*$/d' \
            | tr '\n' ';' \
            | sed 's/;*$//'
    )"
    [[ -z "$chain_lines" ]] && chain_lines="[not recorded]"

    local msf_field="no"
    [[ "$MSF_USED" == "true" ]] && msf_field="yes"

    printf '%s\n' "${RUN_TS} | ${TARGET_IP} | ${HOSTNAME_INPUT} | ${TARGET_OS} | ${MACHINE_CATEGORY} | points=${POINTS_VALUE} | local=${LOCAL_FLAG_VALUE:-MISSING} | proof=${PROOF_FLAG_VALUE:-MISSING} | foothold=${FOOTHOLD_USER} | elevated=${ELEVATED_USER} | msf=${msf_field} | chain=${chain_lines} | dir=${IP_DIR}" >> "$LEDGER_FILE"

    write_progress "DONE" "ledger" "ledger=${LEDGER_FILE}"
}

report_reminder() {
    phase "7 - REPORT REMINDER"
    cat <<EOF
[+] Evidence collection complete for ${TARGET_IP}

NEXT STEPS:
  1. Take all screenshots listed in:
       ${SCREENSHOT_DIR}/checklist.txt
  2. Transfer attack chain notes to your Obsidian engagement day notes
  3. Copy flag values to your Creds_Tracker.md
  4. Verify nothing was missed in the creds ledger:
       cat ${TOOLKIT_ROOT}/creds.txt
  5. Cross-machine flag audit (all captured so far):
       cat ${TOOLKIT_ROOT}/evidence/*/flags/proof.txt
       cat ${TOOLKIT_ROOT}/evidence/*/flags/local.txt
  6. When done with ALL machines, review the full ledger:
       cat ${LEDGER_FILE}

Metasploit tracker:
  OffSec limit: Metasploit / Meterpreter may be used on ONE target only.
EOF

    local msf_count msf_list
    msf_count=$(find "${TOOLKIT_ROOT}/evidence" -maxdepth 2 -name 'msf_used.flag' 2>/dev/null | wc -l)
    msf_list=$(find "${TOOLKIT_ROOT}/evidence" -maxdepth 2 -name 'msf_used.flag' -printf '%h\n' 2>/dev/null | xargs -I{} basename {} 2>/dev/null | tr '\n' ' ')
    if (( msf_count == 0 )); then
        echo "  MSF targets so far: 0 (no msf_used.flag markers found)"
    elif (( msf_count == 1 )); then
        echo "  MSF targets so far: 1 → ${msf_list}"
    else
        warn "MSF LIMIT EXCEEDED — ${msf_count} machines marked as MSF-used: ${msf_list}"
        warn "OffSec policy allows only ONE target for MSF/Meterpreter. Review and rework."
    fi

    if [[ "$MACHINE_CATEGORY" == "AD-DC" ]]; then
        cat <<'ADEOF'

AD-DC checklist — confirm before closing this machine:
  [ ] DCSync run?
        impacket-secretsdump -just-dc <domain>/<user>:<pass>@<DC_IP>
        nxc smb <DC_IP> -u <user> -p <pass> --ntds
  [ ] krbtgt hash captured? (needed for golden ticket)
  [ ] Domain SID recorded?
        impacket-getPac -targetUser administrator <domain>/<user>:<pass>
  [ ] All domain admin hashes in creds.txt?
  [ ] bloodhound collection run?
        nxc ldap <DC_IP> -u <user> -p <pass> --bloodhound --collection All
  [ ] Domain trusts enumerated (if multi-domain)?
        nxc ldap <DC_IP> -u <user> -p <pass> -M enum_trusts
ADEOF
    fi

    if [[ "$MACHINE_CATEGORY" == "AD-client" ]]; then
        cat <<'ADEOF'

AD-client checklist — confirm before closing this machine:
  [ ] Domain user credentials captured to creds.txt?
        (plaintext password AND/OR NTLM hash AND/OR Kerberos ccache)
  [ ] Domain membership evidence captured?
        Linux:   whoami; realm list; klist
        Windows: whoami /groups; whoami /user; klist
  [ ] Lateral movement vector documented in attack_chain?
        (how did you pivot from foothold user → this host?)
  [ ] Kerberos ticket cache saved (if Pass-the-Ticket was used)?
        cp "$KRB5CCNAME" ~/toolkit/evidence/<ip>/chain/ticket.ccache
  [ ] Is this machine the initial foothold or mid-chain?
        (note in attack_chain so the final report narrative is clear)
  [ ] Secrets harvested from the user profile?
        %APPDATA%, Desktop, Documents, browser creds, DPAPI blobs
ADEOF
    fi

    write_progress "DONE" "$TARGET_IP" "Evidence collection complete"
}

rollup() {
    local ledger_file="${OUTDIR}/evidence_ledger.txt"

    phase "EVIDENCE ROLLUP — engagement-wide summary"

    if [[ ! -s "$ledger_file" ]]; then
        error "No ledger at ${ledger_file} — nothing to roll up"
        exit 1
    fi

    info "Ledger: ${ledger_file}"

    # Totals and per-category breakdown via awk. Skip header line.
    awk -F' *\\| *' '
        BEGIN {
            total_points = 0
            total_machines = 0
            missing_local = 0
            missing_proof = 0
            msf_targets = 0
        }
        /^# / { next }
        NF < 12 { next }
        {
            total_machines++
            category = $5
            points_field = $6
            local_field  = $7
            proof_field  = $8
            msf_field    = $11

            sub(/^points=/, "", points_field)
            if (points_field ~ /^[0-9]+$/) {
                total_points += points_field
                by_cat_points[category] += points_field
            }
            by_cat_count[category]++

            if (local_field ~ /MISSING/ || local_field ~ /not collected/) {
                missing_local++
                missing_local_ips = missing_local_ips " " $2
            }
            if (proof_field ~ /MISSING/ || proof_field ~ /not collected/) {
                missing_proof++
                missing_proof_ips = missing_proof_ips " " $2
            }
            if (msf_field == "msf=yes") {
                msf_targets++
                msf_ips = msf_ips " " $2
            }
        }
        END {
            print ""
            printf "  Machines recorded:  %d\n", total_machines
            printf "  Total points:       %d / 100\n", total_points
            if (total_points >= 70)
                printf "  Status:             PASS (>= 70)\n"
            else
                printf "  Status:             %d more points needed to pass\n", 70 - total_points
            print ""
            print "  By category:"
            for (c in by_cat_count)
                printf "    %-12s  %d machines, %d points\n", c, by_cat_count[c], by_cat_points[c]
            print ""
            if (missing_local > 0)
                printf "  local.txt MISSING on (%d):%s\n", missing_local, missing_local_ips
            else
                print "  local.txt:  all machines captured"
            if (missing_proof > 0)
                printf "  proof.txt MISSING on (%d):%s\n", missing_proof, missing_proof_ips
            else
                print "  proof.txt:  all machines captured"
            print ""
            if (msf_targets == 0)
                print "  MSF targets:   0 (no markers)"
            else if (msf_targets == 1)
                printf "  MSF targets:   1 →%s\n", msf_ips
            else
                printf "  MSF targets:   %d →%s  ← OffSec LIMIT EXCEEDED (>1)\n", msf_targets, msf_ips
            print ""
        }
    ' "$ledger_file"
}

main() {
    parse_args "$@"
    if [[ "$ROLLUP_MODE" == "true" ]]; then
        rollup
        exit 0
    fi
    preflight
    collect_machine_context
    collect_flags
    generate_screenshot_checklist
    capture_attack_chain
    write_summary
    append_ledger
    report_reminder
}

main "$@"
