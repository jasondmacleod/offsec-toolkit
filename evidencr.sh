#!/usr/bin/env bash
#==============================================================================
# evidencr.sh - OffSec Evidence Capture Ledger
#==============================================================================
# Kali-side only. Documentation/evidence capture only - no target interaction.
# Single-file, resume-safe, append-only ledger for per-machine reporting notes.
#==============================================================================

set -o pipefail

ts()      { date '+%H:%M:%S'; }
info()    { echo "[$(ts)] [*] $*"; }
success() { echo -e "\e[32m[$(ts)] [+] $*\e[0m"; }
warn()    { echo -e "\e[33m[$(ts)] [!] $*\e[0m"; }
error()   { echo -e "\e[31m[$(ts)] [-] $*\e[0m"; }
phase()   { echo -e "\n\e[35m[$(ts)] [EVIDENCE] $*\e[0m\n"; }

OUTDIR="${HOME}/evidence"
TARGET_IP=""
HOSTNAME_INPUT=""
FLAG_TYPE=""
FLAG_PATH=""
NON_INTERACTIVE=false
PIVOT_MACHINE=false   # Fix 10: track pivot context for checklist
OS_INPUT=""
POINTS_INPUT=""
CATEGORY_INPUT=""

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

LOCAL_FLAG_VALUE="not collected"
PROOF_FLAG_VALUE="not collected"
FLAG_COPY_NOTE="[not provided]"

write_progress() { echo "$(date '+%Y-%m-%d %H:%M:%S') | $1 | $2 | $3" >> "$PROGRESS_LOG"; }
# Fix 4: phase_done() was defined but never called; resume would require
# re-parsing state from progress.log (hostname, OS, flags, etc.) which is
# not implemented. Removed to avoid misleading dead code.

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

Required:
  -t <IP>              Target IP address

Options:
  -n <hostname>        Target hostname (default: prompted interactively)
  -f <flag_type>       Flag type: local|proof|both (default: prompted)
  -p <flag_path>       Full path to flag file on Kali for local copy
  --os <os>            Target OS: Linux|Windows
  --points <value>     Points value: 10|20|25
  --category <type>    Machine category: standalone|AD-client|AD-DC
  -o <outdir>          Output directory (default: ~/evidence)
  --non-interactive    Skip all prompts; use flags only
  -h, --help           Show this help
EOF
}

is_valid_ipv4() {
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

    # Only copy once per run even if called multiple times (e.g. FLAG_TYPE=both)
    if [[ "$FLAG_COPY_NOTE" != "[not provided]" ]]; then
        return 0
    fi

    if [[ -e "$FLAG_PATH" ]]; then
        dest="${FLAGS_DIR}/${flag_kind}_$(basename "$FLAG_PATH")_${RUN_EPOCH}"
        # Fix 6: use 'if cp' directly so error output is not suppressed
        # before the exit-status check
        if cp "$FLAG_PATH" "$dest"; then
            FLAG_COPY_NOTE="Copied: $dest"
            success "Copied provided flag file to $dest"
        else
            FLAG_COPY_NOTE="Copy failed: $FLAG_PATH"
            warn "Failed to copy provided flag file: $FLAG_PATH"
        fi
    else
        FLAG_COPY_NOTE="Missing local path: $FLAG_PATH"
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
        flag_value="not collected"
        warn "Non-interactive mode: ${flag_label} left as not collected"
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

    # Fix 1: explicit "both" case — previously fell into else (proof-only),
    # silently omitting the local.txt screenshot requirement
    # Fix 10: pivot note is only included when PIVOT_MACHINE=true

    local pivot_note=$'[ ] 6. network_position.png  (pivot — required)\n    Must show: your pivot setup confirming reachability\n'

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
                    [[ "$PIVOT_MACHINE" == "true" ]] && printf '%s\n' "$pivot_note"
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
                    [[ "$PIVOT_MACHINE" == "true" ]] && printf '%s\n' "$pivot_note"
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
                    [[ "$PIVOT_MACHINE" == "true" ]] && printf '%s\n' "$pivot_note"
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
                    [[ "$PIVOT_MACHINE" == "true" ]] && printf '%s\n' "$pivot_note"
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
                    [[ "$PIVOT_MACHINE" == "true" ]] && printf '%s\n' "$pivot_note"
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
                    [[ "$PIVOT_MACHINE" == "true" ]] && printf '%s\n' "$pivot_note"
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

    # Fix 3: use >> (append) with a run separator so re-runs accumulate
    # rather than silently overwriting previous chain notes
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
    # Fix 9: guard cat calls so missing files produce a clear marker
    # rather than a silently empty section
    cat <<EOF
============================================================
  EVIDENCE SUMMARY — ${TARGET_IP} (${HOSTNAME_INPUT})
  Recorded: ${RUN_TS}
  Running as: ${KALI_USER}
  VPN IP: ${VPN_IP}
============================================================

[ TARGET ]
  IP:        ${TARGET_IP}
  Hostname:  ${HOSTNAME_INPUT}
  OS:        ${TARGET_OS}
  Category:  ${MACHINE_CATEGORY}
  Points:    ${POINTS_VALUE}
  Pivot:     ${PIVOT_MACHINE}

[ FLAGS ]
  local.txt:  ${LOCAL_FLAG_VALUE}
  proof.txt:  ${PROOF_FLAG_VALUE}
  Copy note:  ${FLAG_COPY_NOTE}

[ SCREENSHOTS REQUIRED ]
$(cat "$checklist_path" 2>/dev/null || echo "[checklist not generated]")

[ ATTACK CHAIN ]
$(cat "$chain_file" 2>/dev/null || echo "[chain not recorded]")

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
            -f)
                [[ $# -lt 2 ]] && { error "-f requires an argument"; exit 1; }
                FLAG_TYPE="$2"; shift 2 ;;
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
            -h|--help)
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
    is_valid_ipv4 "$TARGET_IP" || { error "Invalid IPv4 address: $TARGET_IP"; exit 1; }

    # Fix 5: try tun0 then tun1; warn loudly rather than silently falling
    # back to eth0 (which would record the LAN IP instead of the VPN IP)
    VPN_IP=""
    for VPN_IFACE in tun0 tun1; do
        VPN_IP="$(ip -4 addr show "$VPN_IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)"
        [[ -n "$VPN_IP" ]] && break
    done
    if [[ -z "$VPN_IP" ]]; then
        VPN_IFACE="none"
        VPN_IP="unknown"
        warn "No VPN interface (tun0/tun1) found — are you connected to the OffSec VPN?"
    fi

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

    # Fix 2: use grep -F so dots in TARGET_IP are treated as literals,
    # not regex metacharacters (192.168.1.1 would otherwise match 192X168Y1Z1)
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
        TARGET_OS="${OS_INPUT:-Linux}"
        FLAG_TYPE="${FLAG_TYPE:-local}"
        POINTS_VALUE="${POINTS_INPUT:-[not provided]}"
        MACHINE_CATEGORY="${CATEGORY_INPUT:-[not provided]}"
    else
        os_choice="$(prompt_choice "OS [Linux/Windows, choose Linux or Windows]" "${OS_INPUT:-Linux}" "Linux" "Windows")"
        TARGET_OS="$os_choice"
        FLAG_TYPE="$(prompt_choice "Flag type [local/proof/both]" "${FLAG_TYPE:-both}" "local" "proof" "both")"
        POINTS_VALUE="$(prompt_choice "Points value [10/20/25]" "${POINTS_INPUT:-20}" "10" "20" "25")"
        category_choice="$(prompt_choice "Machine category [standalone/AD-client/AD-DC]" "${CATEGORY_INPUT:-standalone}" "standalone" "AD-client" "AD-DC")"
        MACHINE_CATEGORY="$category_choice"
        # Fix 10: prompt for pivot context so checklist only includes the
        # network_position screenshot requirement when actually relevant
        if confirm_yes "Is this machine accessed via a pivot/tunnel?"; then
            PIVOT_MACHINE=true
        fi
    fi

    case "$TARGET_OS" in
        Linux|Windows) ;;
        *)
            warn "Invalid OS '${TARGET_OS}' provided; defaulting to Linux"
            TARGET_OS="Linux"
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
Pivot machine:     ${PIVOT_MACHINE}
EOF

    if [[ "$NON_INTERACTIVE" != "true" ]] && ! confirm_yes "Proceed with this machine context?"; then
        error "Operator declined context confirmation"
        exit 1
    fi

    write_progress "DONE" "context" "hostname=${HOSTNAME_INPUT} os=${TARGET_OS} flags=${FLAG_TYPE} pivot=${PIVOT_MACHINE}"
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
    write_progress "DONE" "chain" "chain_file=${CHAIN_DIR}/attack_chain.txt"
}

write_summary() {
    local summary_path="${IP_DIR}/summary.txt"
    local summary_block=""

    phase "5 - MACHINE SUMMARY BLOCK"
    write_progress "START" "summary" "Generating summary"

    summary_block="$(build_summary_block)"
    printf '%s\n\n' "$summary_block" | tee -a "$summary_path"

    write_progress "DONE" "summary" "summary=${summary_path}"
}

append_ledger() {
    local chain_lines=""

    phase "6 - LEDGER APPEND"
    write_progress "START" "ledger" "Appending evidence ledger"

    # Fix 3 (continued): filter out the "--- timestamp ---" separator lines
    # and blank lines added by the append-mode chain format
    chain_lines="$(grep -vE '^(---|[[:space:]]*$)' "${CHAIN_DIR}/attack_chain.txt" 2>/dev/null | tr '\n' ';' | sed 's/;*$//')"
    [[ -z "$chain_lines" ]] && chain_lines="[not recorded]"

    printf '%s\n' "${RUN_TS} | ${TARGET_IP} | ${HOSTNAME_INPUT} | ${TARGET_OS} | local=${LOCAL_FLAG_VALUE:-MISSING} | proof=${PROOF_FLAG_VALUE:-MISSING} | chain=${chain_lines} | dir=${IP_DIR}" >> "$LEDGER_FILE"

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
  4. When done with ALL machines, run:
       cat ${LEDGER_FILE}
     to get the full cross-machine summary for your report

Metasploit tracker reminder:
  Have you used Meterpreter on more than ONE machine? (limit: 1 target)
EOF

    write_progress "DONE" "$TARGET_IP" "Evidence collection complete"
}

main() {
    parse_args "$@"
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
