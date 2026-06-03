#!/usr/bin/env bash
#==============================================================================
# stuckr.sh — "I'm stuck" decision helper for OffSec+ targets
#==============================================================================
# PURPOSE
#   Operator hit a dead end on a target. stuckr reads the target's state,
#   matches against the symptom map, and prints 3-5 ranked next moves with
#   paste-and-run commands. No execution, no state mutation, no prompts.
#
# WORKFLOW
#   1. Resolve target IP (cwd → last_target → --on <ip>)
#   2. Read per-target state vector via lib/state.sh
#   3. Read global state (creds, domain, dc_ip) via lib/state.sh
#   4. Hand state + symptom_map.yaml + exploitdb corpus to the ranker
#   5. Render single-screen output (§8) — or §9 fallback if no confident hits
#
# USAGE
#   stuckr                    # target inferred from cwd or last_target
#   stuckr --on <ip>          # explicit target
#   stuckr --all              # scan every target under $TOOLKIT_ROOT
#   stuckr --no-color         # disable ANSI (also: NO_COLOR=1)
#
# OUTPUT STRUCTURE
#   - Target summary line (ip / os / foothold / privesc)
#   - Services line (truncated at 6, +N more)
#   - "what's been tried (last 5)"     — newest first
#   - "empty-result findings"          — deduped sentinels with context
#   - "untried next moves"             — top 5 from the §6 ranker, full command
#
# DESIGN DECISIONS
#   - State files are plain text. lib/state.sh parses with grep/awk.
#   - YAML and exploitdb corpus parsing is done in a single Python heredoc
#     (python3 + PyYAML are present on Kali by default — same dependency
#     surface as ~/offsec-toolkit/exploitdb/).
#   - Ranking is deterministic per spec §6 — no heuristics.
#   - Substitutions for corpus gaps are invisible at output layer — the
#     gap log lives at exploitdb/data/seed/symptom_map_gaps.md.
#   - Commands have IP / creds substituted before render. Unknown
#     placeholders (e.g. service-specific ports) stay as <port> with a note.
#==============================================================================

set -o pipefail
# NOT set -e — phases handle their own errors

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_STATE="${SCRIPT_DIR}/lib/state.sh"
LIB_RANKER="${SCRIPT_DIR}/lib/stuckr_rank.py"
SYMPTOM_MAP="${SCRIPT_DIR}/lib/symptom_map.yaml"
EXPLOITDB_SEED_DIR="${SCRIPT_DIR}/exploitdb/data/seed"
TOP_N=5

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
DIM='\033[2m'
NC='\033[0m'

disable_colors() { RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' DIM='' NC=''; }
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

ts() { date '+%H:%M:%S'; }
info()    { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }

#------------------------------------------------------------------------------
# CLI
#------------------------------------------------------------------------------
TARGET_IP=""
MODE_ALL=false

usage() {
    cat <<EOF
stuckr.sh — surface the top 3-5 untried next moves for a target

Usage:
  stuckr                    target inferred from cwd or last_target
  stuckr --on <ip>          explicit target
  stuckr --all              one report per target under \$TOOLKIT_ROOT/targets/
  stuckr --no-color         disable ANSI color (also: NO_COLOR=1)
  stuckr -h | --help        this help

Output: a single screen of ranked actions with paste-and-run commands.
Never executes anything, never mutates state, never prompts.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --on)         TARGET_IP="$2"; shift 2 ;;
        --all)        MODE_ALL=true; shift ;;
        --no-color)   disable_colors; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            error "unknown argument: $1"; usage >&2; exit 2 ;;
    esac
done

#------------------------------------------------------------------------------
# PRECHECKS
#------------------------------------------------------------------------------
if [[ ! -r "$LIB_STATE" ]]; then
    error "missing state library: $LIB_STATE"; exit 1
fi
if [[ ! -r "$SYMPTOM_MAP" ]]; then
    error "missing symptom map: $SYMPTOM_MAP"; exit 1
fi
if [[ ! -d "$EXPLOITDB_SEED_DIR" ]]; then
    error "missing exploitdb seed dir: $EXPLOITDB_SEED_DIR"; exit 1
fi
if [[ ! -r "$LIB_RANKER" ]]; then
    error "missing ranker: $LIB_RANKER"; exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    error "python3 required (for yaml + corpus parsing)"; exit 1
fi

# shellcheck disable=SC1090
source "$LIB_STATE"

#------------------------------------------------------------------------------
# TARGET INFERENCE
#------------------------------------------------------------------------------
infer_target() {
    # 1. cwd matches $TOOLKIT_ROOT/targets/<ip>/
    local pwd_abs; pwd_abs=$(realpath "$PWD" 2>/dev/null || echo "$PWD")
    local root_abs; root_abs=$(realpath "$TOOLKIT_ROOT" 2>/dev/null || echo "$TOOLKIT_ROOT")
    if [[ "$pwd_abs" == "$root_abs/targets/"* ]]; then
        local rest="${pwd_abs#"$root_abs"/targets/}"
        echo "${rest%%/*}"
        return 0
    fi
    # 2. $TOOLKIT_ROOT/.evidencr/last_target
    local lt="$TOOLKIT_ROOT/.evidencr/last_target"
    if [[ -r "$lt" ]]; then
        local v; v=$(head -1 "$lt" | tr -d '[:space:]')
        [[ -n "$v" ]] && { echo "$v"; return 0; }
    fi
    return 1
}

#------------------------------------------------------------------------------
# RANKER  (delegates to lib/stuckr_rank.py — yaml + corpus parsing + §6 sort)
#------------------------------------------------------------------------------
# Reads state on stdin (key=value lines from lib/state.sh + target_count=N).
# Emits pipe-delimited lines: sentinel|… ranked|… fallback|… nofallback|… raw|…
run_ranker() {
    local ip="$1"
    python3 "$LIB_RANKER" "$SYMPTOM_MAP" "$EXPLOITDB_SEED_DIR" "$ip" "$TOP_N"
}

#------------------------------------------------------------------------------
# RENDERER  (§8 / §9)
#------------------------------------------------------------------------------
report_target() {
    local ip="$1"

    # gather state into bash arrays for header rendering
    local _services="" _os="unknown" _foothold="no" _privesc="no"
    local -a _service_list=() _tried=() _sentinels=()
    local _state_text _global_text
    _state_text=$(state_read_target "$ip")
    _global_text=$(state_read_global)

    while IFS='=' read -r k v; do
        case "$k" in
            services)     _services="$v" ;;
            service)      _service_list+=("$v") ;;
            os_guess)     _os="$v" ;;
            foothold)     _foothold="$v" ;;
            privesc)      _privesc="$v" ;;
            sentinel)     _sentinels+=("$v") ;;
            tried_slug)   _tried+=("$v") ;;
        esac
    done <<< "$_state_text"

    # §9 case A — no enumeration data at all
    if [[ -z "$_services" && ${#_sentinels[@]} -eq 0 && "$_foothold" == "no" && "$_privesc" == "no" ]]; then
        local td="$TOOLKIT_ROOT/targets/$ip"
        if [[ ! -d "$td" ]] || [[ -z "$(ls -A "$td" 2>/dev/null)" ]]; then
            printf '%starget%s  %s     no enumeration data found\n\n' "$BOLD" "$NC" "$ip"
            printf '%srun this first%s\n' "$BOLD" "$NC"
            printf '  ~/offsec-toolkit/recon.sh %s\n\n' "$ip"
            return
        fi
    fi

    # header line: target ip os foothold privesc
    printf '%starget%s   %-15s %s    foothold:%s   privesc:%s\n' \
        "$BOLD" "$NC" "$ip" "$_os" "$_foothold" "$_privesc"

    # services line (truncate at 6, +N more)
    if [[ -n "$_services" ]]; then
        local count=${#_service_list[@]}
        local shown=("${_service_list[@]:0:6}")
        local suffix=""
        [[ $count -gt 6 ]] && suffix="  +$((count - 6)) more"
        printf '%sservices%s %s%s\n' "$BOLD" "$NC" "${shown[*]}" "$suffix"
    else
        printf '%sservices%s (none)\n' "$BOLD" "$NC"
    fi
    echo

    # what's been tried (last 5, newest first)
    if [[ ${#_tried[@]} -gt 0 ]]; then
        printf '%swhat'\''s been tried (last 5)%s\n' "$DIM" "$NC"
        local n=${#_tried[@]} start=0
        [[ $n -gt 5 ]] && start=$((n - 5))
        local i
        for (( i=n-1; i>=start; i-- )); do
            printf '  %s\n' "${_tried[i]}"
        done
        echo
    fi

    # Hand off to ranker
    local target_count
    target_count=$(state_list_targets | wc -l)
    local ranker_out
    ranker_out=$( { echo "$_state_text"; echo "$_global_text"; echo "target_count=$target_count"; } | run_ranker "$ip" )

    # parse ranker output
    local -a sentinel_lines=() ranked_lines=() raw_lines=()
    local nofallback_msg="" fallback_marker=""
    while IFS= read -r line; do
        case "$line" in
            sentinel\|*)    sentinel_lines+=("$line") ;;
            ranked\|*)      ranked_lines+=("$line") ;;
            raw\|*)         raw_lines+=("$line") ;;
            nofallback\|*)  nofallback_msg="${line#nofallback|}" ;;
            fallback\|*)    fallback_marker="${line#fallback|}" ;;
        esac
    done <<< "$ranker_out"

    # empty-result findings block (§8) — skipped if empty
    if [[ ${#sentinel_lines[@]} -gt 0 ]]; then
        printf '%sempty-result findings%s\n' "$BOLD" "$NC"
        local line key ctx
        for line in "${sentinel_lines[@]}"; do
            IFS='|' read -r _ key ctx <<< "$line"
            printf '  %s%-22s%s %s\n' "$YELLOW" "$key" "$NC" "$ctx"
        done
        echo
    fi

    # untried next moves block (§8)
    if [[ ${#ranked_lines[@]} -gt 0 ]]; then
        if [[ "$fallback_marker" == "broad-category" ]]; then
            printf '%suntried next moves%s  %s(service-only fallback — no sentinels yet)%s\n' \
                "$BOLD" "$NC" "$DIM" "$NC"
        else
            printf '%suntried next moves%s\n' "$BOLD" "$NC"
        fi
        local line rank slug trig cmd
        for line in "${ranked_lines[@]}"; do
            IFS='|' read -r _ rank slug trig cmd <<< "$line"
            printf '  %s%s.%s %s%s%s\n' "$BOLD" "$rank" "$NC" "$CYAN" "$slug" "$NC"
            printf '     %strigger%s    %s\n' "$DIM" "$NC" "$trig"
            printf '     %scommand%s    %s\n\n' "$DIM" "$NC" "$cmd"
        done
    elif [[ -n "$nofallback_msg" ]]; then
        # §9 case B
        printf '%sno confident suggestions from the symptom map.%s\n' "$YELLOW" "$NC"
        echo
        printf 'raw alternates from exploitdb (top 5 by engagement_relevance):\n'
        local line slug title
        for line in "${raw_lines[@]}"; do
            IFS='|' read -r _ slug title <<< "$line"
            printf '  - %s%s%s — %s\n' "$CYAN" "$slug" "$NC" "$title"
        done
        echo
        printf 'if these don'\''t fit, browse the full corpus:\n'
        printf '  ls %s/*.json | xargs -n1 jq -r %s.entries[].slug %s 2>/dev/null\n' \
            "$EXPLOITDB_SEED_DIR" "'" "'"
        echo
    else
        printf '%sno actions surfaced — state may be incomplete%s\n\n' "$YELLOW" "$NC"
    fi
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
if $MODE_ALL; then
    targets=$(state_list_targets)
    if [[ -z "$targets" ]]; then
        error "no targets under $TOOLKIT_ROOT/targets/"
        exit 1
    fi
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && { report_target "$ip"; echo '────────────────────────────────────────────────────────────'; }
    done <<< "$targets"
    exit 0
fi

if [[ -z "$TARGET_IP" ]]; then
    TARGET_IP=$(infer_target) || true
fi

if [[ -z "$TARGET_IP" ]]; then
    error "no target — run from a target dir or pass --on <ip>"
    exit 1
fi

report_target "$TARGET_IP"
