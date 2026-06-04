#!/usr/bin/env bash
#==============================================================================
# proofr.sh — proof-of-compromise completeness auditor for OffSec+ targets
#==============================================================================
# PURPOSE
#   Reconcile two independent sources of truth and report where they diverge:
#     decision-layer state  — what the toolkit recorded HAPPENED on a box
#                             (foothold.log, captured creds, recon context)
#     evidence-layer capture — what the operator DOCUMENTED for the grader
#                             (evidencr ledger, flag files, screenshot audit)
#   Answers, per target + engagement-wide: "did I compromise something I haven't
#   fully documented?" Emits documented / missing / inconsistent — never a
#   report. No execution, no target interaction, no state mutation, no prompts.
#
# WORKFLOW
#   1. Resolve target IP(s) (cwd → .evidencr/last_target → --on; or --all sweep)
#   2. Per IP: read state (state_read_target / state_read_footholds) +
#      evidencr surface (ledger row, flags/*.txt, missing_screenshots.txt, msf)
#   3. Classify engagement (recon-only / engaged / documented) and run the
#      completeness + consistency checks (§3 of docs/proofr_spec.md)
#   4. Render a single-screen gap audit per target + an engagement-wide footer
#   5. Signal the result via EXIT CODE (§ exit codes below)
#
# USAGE
#   proofr                    # audit the inferred target (cwd or last_target)
#   proofr --on <ip>          # audit one explicit target
#   proofr --all              # audit every engaged target + engagement-wide footer
#   proofr --no-color         # disable ANSI (also: NO_COLOR=1)
#   proofr -h | --help        # this help
#
# OUTPUT STRUCTURE
#   - Per-target block: header (ip / hostname / os / category / points),
#     engagement line, documented line (ledger/local/proof/screenshots marks),
#     and a GAPS list — each gap tagged [ledger]/[local]/[proof]/[shots] with
#     the concrete next action. Inferred proof gaps carry a NOTE caveat.
#   - engagement-wide footer: engaged/documented/gaps tally (--all), cred inventory
#     (users only), MSF one-machine-limit gate, and a pointer to evidencr --rollup.
#
# EXIT CODES (machine-readable signal; proofr writes NO state)
#   0  every engaged target fully documented + self-consistent (report-ready)
#   1  documentation gaps / inconsistencies exist (normal "work remains")
#   2  CRITICAL: MSF limit exceeded (>1 marker), OR an engaged target has no
#      ledger entry at all (undocumented compromise) — points-losing cases
#   3  usage error / no target could be inferred
#
# DESIGN DECISIONS
#   - Pure reader. Reads lib/state.sh's API + evidencr's on-disk surface; writes
#     nothing (stdout only). One-directional, like orient.sh.
#   - Compromise signal is foothold.log (state_read_footholds) + the evidencr
#     ledger — NOT state_read_target's foothold/privesc keys, which have no
#     producer on disk (no tool writes targets/<ip>/evidence/; verified Phase 0).
#   - Flag capture rule: a flag counts as captured if ANY recorded line holds a
#     real (UUID/32-hex) value — a later "not collected" re-run never un-captures
#     a real flag. The newest real value wins.
#   - No point scoring (evidencr --rollup owns that). No report generation. No
#     screenshot capture. No --json (so warn()->stdout never corrupts output);
#     warn/error go to stderr from the start.
#   - No python, no new dependencies — bash + awk only.
#==============================================================================

set -o pipefail
# NOT set -e — checks handle their own missing-file cases; one absent source
# must never abort the audit.

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_STATE="${SCRIPT_DIR}/lib/state.sh"
TOOLKIT_ROOT="${TOOLKIT_ROOT:-$HOME/toolkit}"
DIVIDER='────────────────────────────────────────────────────────────'

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS
#------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

disable_colors() { RED='' GREEN='' YELLOW='' BOLD='' DIM='' NC=''; }
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

ts()    { date '+%H:%M:%S'; }
# error -> stderr so it never corrupts the audit stream on stdout.
error() { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }

#------------------------------------------------------------------------------
# CLI
#------------------------------------------------------------------------------
TARGET_IP=""
MODE_ALL=false

usage() {
    cat <<EOF
proofr.sh — audit proof-of-compromise completeness for OffSec+ targets

Usage:
  proofr                    target inferred from cwd or last_target
  proofr --on <ip>          explicit target
  proofr --all              audit every engaged target + engagement-wide footer
  proofr --no-color         disable ANSI color (also: NO_COLOR=1)
  proofr -h | --help        this help

Reconciles decision-layer state (foothold.log, creds) against evidencr's
captures (ledger, flags, screenshots) and reports documented / missing /
inconsistent. Never executes anything, never mutates state, never prompts.

Exit: 0 report-ready · 1 gaps · 2 critical (MSF>1 or undocumented compromise)
      · 3 usage / no target.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --on)         TARGET_IP="$2"; shift 2 ;;
        --all)        MODE_ALL=true; shift ;;
        --no-color)   disable_colors; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            error "unknown argument: $1"; usage >&2; exit 3 ;;
    esac
done

#------------------------------------------------------------------------------
# PRECHECKS
#------------------------------------------------------------------------------
if [[ ! -r "$LIB_STATE" ]]; then
    error "missing state library: $LIB_STATE"; exit 3
fi
# shellcheck disable=SC1090
source "$LIB_STATE"

EVID_DIR="${TOOLKIT_ROOT}/evidence"
LEDGER="${EVID_DIR}/evidence_ledger.txt"

#------------------------------------------------------------------------------
# EXIT-CODE ACCUMULATOR + TALLY
#------------------------------------------------------------------------------
RC=0
bump_rc() { (( $1 > RC )) && RC="$1"; return 0; }

ENGAGED_N=0        # boxes with a foothold and/or a ledger row
DOC_OK_N=0         # engaged boxes with zero gaps
GAPS_N=0           # engaged boxes with >=1 gap

#------------------------------------------------------------------------------
# SMALL HELPERS
#------------------------------------------------------------------------------
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }
strip_key() { printf '%s' "${1#"$2"=}"; }   # strip_key "local=abc" local -> abc

# flag_is_real <value> : true iff value is a recorded OffSec flag (UUID / 32-hex)
# and not a placeholder. Mirrors evidencr.sh::is_uuid_like plus the placeholders
# evidencr can write into the ledger / flag files.
flag_is_real() {
    local v="$1"
    [[ -n "$v" ]] || return 1
    case "$v" in
        "not collected"|MISSING|"[not provided]"|"[not recorded]") return 1 ;;
    esac
    [[ "$v" =~ ^[A-Fa-f0-9]{32}$ ]] && return 0
    [[ "$v" =~ ^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$ ]] && return 0
    return 1
}

# flag_file_value <flags/*.txt> : echo the NEWEST real flag value recorded in the
# file (lines are "[ts] VALUE"; evidencr.sh:295). A later "not collected" line
# never overrides an earlier real capture. Empty if no real value was ever logged.
flag_file_value() {
    local f="$1" line v real=""
    [[ -r "$f" ]] || { printf ''; return; }
    while IFS= read -r line; do
        [[ -z "${line//[[:space:]]/}" ]] && continue
        v="${line#*] }"          # drop the "[ts] " prefix; no-op if absent
        flag_is_real "$v" && real="$v"
    done < "$f"
    printf '%s' "$real"
}

# ledger_row_for <ip> : echo the LAST (newest) ledger row whose field 2 == ip.
# Append-only ledger; a re-run supersedes earlier rows.
ledger_row_for() {
    local ip="$1"
    [[ -r "$LEDGER" ]] || { printf ''; return; }
    awk -F' *\\| *' -v ip="$ip" '/^#/ {next} NF>=12 && $2==ip {row=$0} END {print row}' "$LEDGER"
}

# check_flag <ledger_val> <file_real_val> : -> ok | ledger-only | missing
#   ok          a real flag exists (in the flag file and/or the ledger)
#   ledger-only ledger cites a flag but the flag file has no real value
#   missing     no real flag anywhere
check_flag() {
    local ledger_val="$1" file_val="$2" ledger_real=0
    flag_is_real "$ledger_val" && ledger_real=1
    if [[ $ledger_real -eq 1 && -z "$file_val" ]]; then echo "ledger-only"; return; fi
    if [[ $ledger_real -eq 1 || -n "$file_val" ]]; then echo "ok"; return; fi
    echo "missing"
}

#------------------------------------------------------------------------------
# TARGET INFERENCE (mirrors stuckr.sh:133-149)
#------------------------------------------------------------------------------
infer_target() {
    local pwd_abs root_abs lt v rest
    pwd_abs=$(realpath "$PWD" 2>/dev/null || echo "$PWD")
    root_abs=$(realpath "$TOOLKIT_ROOT" 2>/dev/null || echo "$TOOLKIT_ROOT")
    if [[ "$pwd_abs" == "$root_abs/targets/"* ]]; then
        rest="${pwd_abs#"$root_abs"/targets/}"
        echo "${rest%%/*}"; return 0
    fi
    lt="$TOOLKIT_ROOT/.evidencr/last_target"
    if [[ -r "$lt" ]]; then
        v=$(head -1 "$lt" | tr -d '[:space:]')
        [[ -n "$v" ]] && { echo "$v"; return 0; }
    fi
    return 1
}

# audit_universe : sorted-unique IP set for --all (targets/ ∪ ledger ∪ evidence/)
audit_universe() {
    {
        state_list_targets
        [[ -r "$LEDGER" ]] && awk -F' *\\| *' '/^#/{next} NF>=2 {print $2}' "$LEDGER"
        [[ -d "$EVID_DIR" ]] && find "$EVID_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null
    } | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u
}

#------------------------------------------------------------------------------
# PER-TARGET AUDIT
#------------------------------------------------------------------------------
audit_target() {
    local ip="$1"

    # --- decision layer: recon context + foothold signal ---
    local state_text os foot_text has_foothold=0 f_user="" f_method="" f_ts=""
    state_text=$(state_read_target "$ip" 2>/dev/null)
    os=$(grep -m1 '^os_guess=' <<<"$state_text" | cut -d= -f2-)
    [[ -n "$os" ]] || os="unknown"
    foot_text=$(state_read_footholds "$ip" 2>/dev/null)
    if [[ -n "$foot_text" ]]; then
        has_foothold=1
        IFS=$'\t' read -r _ f_ts f_user f_method _ < <(tail -1 <<<"$foot_text")
    fi

    # --- evidence layer: ledger row + flag files + screenshots ---
    local row has_ledger=0
    local L_host="" L_os="" L_cat="" L_points="" L_local="" L_proof="" L_elev=""
    row=$(ledger_row_for "$ip")
    if [[ -n "$row" ]]; then
        has_ledger=1
        local _ts _ip _c _h _p _l _pr _f _e _m
        IFS='|' read -r _ts _ip _h _c _p _l _pr _f _e _m _ _ <<<"$row"
        L_host=$(trim "$_h"); L_os=$(trim "$_c"); L_cat=$(trim "$_p")
        L_points=$(strip_key "$(trim "$_l")" points)
        L_local=$(strip_key "$(trim "$_pr")" local)
        L_proof=$(strip_key "$(trim "$_f")" proof)
        L_elev=$(strip_key "$(trim "$_m")" elevated)
    fi
    # NB: ledger field order is ts|ip|host|os|cat|points=|local=|proof=|foothold=|
    #     elevated=|msf=|chain=|dir= (evidencr.sh:896). The read above lands
    #     host=$_h, os=$_c, cat=$_p, points=$_l, local=$_pr, proof=$_f, elev=$_m.

    local file_local file_proof
    file_local=$(flag_file_value "$EVID_DIR/$ip/flags/local.txt")
    file_proof=$(flag_file_value "$EVID_DIR/$ip/flags/proof.txt")

    local -a missing_shots=()
    local mf="$EVID_DIR/$ip/screenshots/missing_screenshots.txt"
    if [[ -s "$mf" ]]; then
        while IFS= read -r line; do
            [[ -z "${line//[[:space:]]/}" ]] && continue
            missing_shots+=("$(trim "$line")")
        done < "$mf"
    fi

    # --- recon-only: not owned, no proof expected (one line, no gap) ---
    if [[ $has_ledger -eq 0 && $has_foothold -eq 0 ]]; then
        printf '%s%-15s%s  recon-only, not owned — no proof expected (%s)\n' \
            "$DIM" "$ip" "$NC" "$os"
        return
    fi

    ENGAGED_N=$((ENGAGED_N + 1))

    # --- header ---
    local hdr_host="${L_host:-?}" hdr_cat="${L_cat:-?}" hdr_pts="${L_points:-?}"
    [[ -n "$L_os" ]] && os="$L_os"
    printf '%s═══ %s%s  (hostname: %s · %s · %s · %s pts)%s\n' \
        "$BOLD" "$ip" "$NC$BOLD" "$hdr_host" "$os" "$hdr_cat" "$hdr_pts" "$NC"

    # --- engagement line ---
    if [[ $has_foothold -eq 1 ]]; then
        printf '  engagement : foothold.log → %s via %s (%s)\n' "$f_user" "$f_method" "$f_ts"
    else
        printf '  engagement : ledger only — no foothold.log entry recorded\n'
    fi

    # --- gather gaps ---
    local -a gaps=()           # entries: "SEV|tag|message"   SEV ∈ crit|gap
    local inferred=0
    local mark_ledger mark_local mark_proof mark_shots

    if [[ $has_ledger -eq 0 ]]; then
        # engaged (foothold) but never run through evidencr — the headline gap.
        gaps+=("crit|ledger|compromised (foothold.log: ${f_user} via ${f_method}) but NO evidence ledger entry — run: evidencr ${ip}")
        bump_rc 2
        mark_ledger="✗"; mark_local="–"; mark_proof="–"; mark_shots="–"
    else
        mark_ledger="✓"

        # local flag
        case "$(check_flag "$L_local" "$file_local")" in
            ok)          mark_local="✓" ;;
            missing)     mark_local="✗"
                         gaps+=("gap|local|local.txt flag not recorded (ledger local=${L_local:-MISSING})")
                         bump_rc 1 ;;
            ledger-only) mark_local="!"
                         gaps+=("gap|local|ledger cites a local flag but flags/local.txt holds no valid value — inconsistency")
                         bump_rc 1 ;;
        esac

        # proof flag (inferred when raised from the elevated/category heuristic)
        local elev_real=0
        [[ -n "$L_elev" && "$L_elev" != "[not provided]" ]] && elev_real=1
        case "$(check_flag "$L_proof" "$file_proof")" in
            ok)          mark_proof="✓"
                         gaps+=("note|proof|verify proof was captured from an INTERACTIVE shell — web shells are not valid proof") ;;
            ledger-only) mark_proof="!"
                         gaps+=("gap|proof|ledger cites a proof flag but flags/proof.txt holds no valid value — inconsistency")
                         bump_rc 1 ;;
            missing)     mark_proof="✗"
                         if [[ $elev_real -eq 1 || "$L_cat" == "AD-DC" ]]; then
                             gaps+=("gap|proof|evidence shows elevation (elevated=${L_elev:-?}, category=${L_cat:-?}) but proof.txt flag NOT recorded")
                         else
                             gaps+=("gap|proof|proof.txt flag not recorded (ledger proof=${L_proof:-MISSING})")
                         fi
                         inferred=1
                         bump_rc 1 ;;
        esac

        # screenshots — AD network_position.png promoted to a dedicated strong gap
        if [[ ${#missing_shots[@]} -gt 0 ]]; then
            mark_shots="${#missing_shots[@]} missing"
            local -a other_shots=()
            local s ad_netpos=0
            for s in "${missing_shots[@]}"; do
                if [[ "$s" == "network_position.png" && ( "$L_cat" == "AD-client" || "$L_cat" == "AD-DC" ) ]]; then
                    ad_netpos=1
                else
                    other_shots+=("$s")
                fi
            done
            [[ $ad_netpos -eq 1 ]] && {
                gaps+=("gap|shots|network_position.png MISSING (REQUIRED for AD — pivot/proxy topology)")
                bump_rc 1
            }
            [[ ${#other_shots[@]} -gt 0 ]] && {
                gaps+=("gap|shots|missing screenshots: $(IFS=', '; echo "${other_shots[*]}")")
                bump_rc 1
            }
        else
            mark_shots="ok"
        fi
    fi

    # --- documented line ---
    printf '  documented : ledger %s   local %s   proof %s   screenshots %s\n' \
        "$mark_ledger" "$mark_local" "$mark_proof" "$mark_shots"

    # --- gaps block / clean line ---
    # count only real gaps (crit|gap), not the interactive-shell note
    local real_gaps=0 g sev tag msg
    for g in "${gaps[@]}"; do
        sev="${g%%|*}"
        [[ "$sev" == "crit" || "$sev" == "gap" ]] && real_gaps=$((real_gaps + 1))
    done

    if [[ $real_gaps -eq 0 && $has_ledger -eq 1 ]]; then
        DOC_OK_N=$((DOC_OK_N + 1))
        printf '  %sstatus     : fully documented ✓%s\n' "$GREEN" "$NC"
        # still surface the interactive-shell note if proof was captured
        for g in "${gaps[@]}"; do
            IFS='|' read -r sev tag msg <<<"$g"
            [[ "$sev" == "note" ]] && printf '    %s[%s]%s  %s\n' "$DIM" "$tag" "$NC" "$msg"
        done
    else
        GAPS_N=$((GAPS_N + 1))
        printf '  %sGAPS (%d):%s\n' "$BOLD" "$real_gaps" "$NC"
        for g in "${gaps[@]}"; do
            IFS='|' read -r sev tag msg <<<"$g"
            case "$sev" in
                crit) printf '    %s[%s]%s  %s\n' "$RED" "$tag" "$NC" "$msg" ;;
                gap)  printf '    %s[%s]%s  %s\n' "$YELLOW" "$tag" "$NC" "$msg" ;;
                note) printf '    %s[%s]%s  %s\n' "$DIM" "$tag" "$NC" "$msg" ;;
            esac
        done
    fi

    # --- inferred-gap caveat (per operator addition): inferred gaps must read
    #     differently from certain ones. The proof check is the only heuristic. ---
    if [[ $inferred -eq 1 ]]; then
        printf '  %sNOTE: %s proof gap inferred from heuristic — verify manually%s\n' \
            "$DIM" "$ip" "$NC"
    fi
}

#------------------------------------------------------------------------------
# engagement-wide FOOTER
#------------------------------------------------------------------------------
print_footer() {
    local all_mode="$1"
    printf '%s─── engagement-wide ───%s\n' "$DIM" "$NC"

    if [[ "$all_mode" == "all" ]]; then
        printf '  engaged: %d   fully documented: %d   with gaps: %d\n' \
            "$ENGAGED_N" "$DOC_OK_N" "$GAPS_N"
    fi

    # cred inventory (users only, never secrets) via the fixed state_read_global
    local global_text line cv
    local -a cred_users=()
    global_text=$(state_read_global 2>/dev/null)
    while IFS= read -r line; do
        [[ "$line" == cred=* ]] || continue
        cv="${line#cred=}"; cred_users+=("${cv%%:*}")
    done <<<"$global_text"
    if [[ ${#cred_users[@]} -gt 0 ]]; then
        local users; users=$(printf '%s\n' "${cred_users[@]}" | sort -u | paste -sd, -)
        printf '  creds captured: %d  (%s)  → cross-check Creds_Tracker\n' \
            "${#cred_users[@]}" "$users"
    else
        printf '  creds captured: 0\n'
    fi

    # MSF one-machine-limit gate
    local -a msf_ips=()
    if [[ -d "$EVID_DIR" ]]; then
        local d
        while IFS= read -r d; do
            [[ -f "$d/msf_used.flag" ]] && msf_ips+=("$(basename "$d")")
        done < <(find "$EVID_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    fi
    case ${#msf_ips[@]} in
        0) printf '  MSF markers: 0\n' ;;
        1) printf '  MSF markers: 1  (%s)  [within OffSec limit]\n' "${msf_ips[0]}" ;;
        *) printf '  %sMSF markers: %d  (%s)  ← OffSec LIMIT EXCEEDED (>1)%s\n' \
               "$RED" "${#msf_ips[@]}" "$(IFS=,; echo "${msf_ips[*]}")" "$NC"
           bump_rc 2 ;;
    esac

    printf '  weight total → run: evidencr --rollup\n'
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
# Resolve a single target (cwd -> --on -> last_target) unless --all was asked.
# If none can be inferred, fall back to a full sweep — the safe, useful default
# for a bare invocation (the audit is read-only; nothing is mutated). Replaces
# the old usage-error path that depended on .evidencr/last_target, which
# evidencr never writes.
if ! $MODE_ALL && [[ -z "$TARGET_IP" ]]; then
    TARGET_IP=$(infer_target) || true
    if [[ -z "$TARGET_IP" ]]; then
        printf '%b\n' "${DIM}[*] no target inferred — auditing all engaged targets (--all)${NC}" >&2
        MODE_ALL=true
    fi
fi

if $MODE_ALL; then
    universe=$(audit_universe)
    if [[ -z "$universe" ]]; then
        error "no engaged targets found under $TOOLKIT_ROOT (targets/, ledger, evidence/)"
        exit 3
    fi
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && { audit_target "$ip"; printf '%s\n' "$DIVIDER"; }
    done <<<"$universe"
    print_footer all
    exit "$RC"
fi

audit_target "$TARGET_IP"
print_footer single
exit "$RC"
