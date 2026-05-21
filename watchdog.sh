#!/usr/bin/env bash
#==============================================================================
# watchdog.sh — what's still alive? (shells / tunnels / listeners)
#==============================================================================
# PURPOSE
#   One-screen, sub-second liveness check of Kali-side shells, tunnels, and
#   listeners. Reads OS surface (ps / ss / tmux / ip-route) plus the state
#   vector (foothold.log via state_read_footholds, pivots/state.tsv via
#   state_read_pivots) and classifies each resource ALIVE/STALE/DEAD/UNKNOWN.
#   Never probes a target, never drives a tool's REPL, never remediates.
#
# WORKFLOW
#   1. Parse CLI
#   2. Collect surfaces → temp files  (or read --surfaces-dir for tests)
#   3. Classify via lib/watchdog_classify.py → JSON
#   4. Transition writes (shells only, v1) via lib/state.sh — unless --dry-run
#   5. Render the JSON (Python heredoc) — or print JSON with --json
#
# USAGE
#   watchdog                              one-shot, all targets + types
#   watchdog --target 10.10.11.42         filter to one target
#   watchdog --type shell|tunnel|listener filter to one resource type
#   watchdog --since shells=2h            STALE threshold override (repeatable)
#   watchdog --since tunnels=10m
#   watchdog --json                       machine-readable (livefetch consumes)
#   watchdog --dry-run                    classify + render, no state writes
#   watchdog --verbose                    show PIDs / argv detail
#   watchdog --no-color                   disable ANSI (also: NO_COLOR=1)
#
# DESIGN
#   - Sibling to targetcheckr.sh: lib/state.sh consumer, classifier in Python,
#     render in a Python heredoc, fail-loud (no set -e).
#   - All detection lives in lib/watchdog_classify.py (pure transform).
#   - STALE = idle (min lastsnd/lastrcv from ss -i) >= threshold; shells 4h,
#     tunnels 30m; listeners never STALE. Tunnels also STALE on zero ESTABLISHED.
#   - Tunnel TUN-iface/route presence checks deferred to v2 (pivotr.sh status).
#   - Tunnel transition events deferred to v2; v1 writes shell transitions only.
#==============================================================================

set -o pipefail
# NOT set -e — surface a phase failure with a clear message, never abort silently.

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_STATE="${SCRIPT_DIR}/lib/state.sh"
LIB_CLASSIFY="${SCRIPT_DIR}/lib/watchdog_classify.py"
TOOLKIT_ROOT="${TOOLKIT_ROOT:-$HOME/toolkit}"

CMD_TIMEOUT=5                     # seconds — bound every external surface call
IDLE_SHELLS_MS=14400000           # 4h
IDLE_TUNNELS_MS=1800000           # 30m

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS
#------------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
disable_colors() { RED='' GREEN='' YELLOW='' CYAN='' MAGENTA='' BOLD='' DIM='' NC=''; }
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

ts() { date '+%H:%M:%S'; }
error() { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }

#------------------------------------------------------------------------------
# CLI PARSING
#------------------------------------------------------------------------------
TARGET=""; TYPE="all"; OUT_JSON=false; DRY_RUN=false; VERBOSE=false
SURFACES_DIR=""

dur_to_ms() {
    # 4h | 30m | 90s | 120(=seconds) → milliseconds
    local v="$1" n unit
    n="${v%[hms]}"; unit="${v: -1}"
    [[ "$n" =~ ^[0-9]+$ ]] || { echo ""; return 1; }
    case "$unit" in
        h) echo $(( n * 3600 * 1000 )) ;;
        m) echo $(( n * 60 * 1000 )) ;;
        s) echo $(( n * 1000 )) ;;
        *) echo $(( v * 1000 )) ;;   # bare number = seconds
    esac
}

usage() {
    cat <<EOF
watchdog.sh — liveness of Kali-side shells / tunnels / listeners

Usage:
  watchdog                              one-shot, all targets + types
  watchdog --target <ip>                filter to one target
  watchdog --type shell|tunnel|listener filter to one resource type
  watchdog --since shells=<Xh|Xm>       STALE threshold override (repeatable)
  watchdog --since tunnels=<Xh|Xm>
  watchdog --json                       machine-readable output
  watchdog --dry-run                    classify + render, no state writes
  watchdog --verbose                    show PIDs / extra detail
  watchdog --no-color                   disable ANSI (also: NO_COLOR=1)
  watchdog -h | --help                  this help

Never probes a target, never drives a REPL, never remediates.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)       TARGET="$2"; shift 2 ;;
        --type)         TYPE="$2"; shift 2 ;;
        --since)
            case "$2" in
                shells=*)  IDLE_SHELLS_MS=$(dur_to_ms "${2#shells=}") ;;
                tunnels=*) IDLE_TUNNELS_MS=$(dur_to_ms "${2#tunnels=}") ;;
                *) error "unknown --since key: $2 (use shells=Xh or tunnels=Ym)"; exit 2 ;;
            esac
            shift 2 ;;
        --json)         OUT_JSON=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --verbose)      VERBOSE=true; shift ;;
        --no-color)     disable_colors; shift ;;
        --surfaces-dir) SURFACES_DIR="$2"; shift 2 ;;   # hidden test hook
        -h|--help)      usage; exit 0 ;;
        -*)             error "unknown option: $1"; usage >&2; exit 2 ;;
        *)              error "unexpected argument: $1"; usage >&2; exit 2 ;;
    esac
done

case "$TYPE" in shell|tunnel|listener|all) ;; *)
    error "--type must be shell|tunnel|listener|all (got: $TYPE)"; exit 2 ;;
esac

#------------------------------------------------------------------------------
# PRECHECKS
#------------------------------------------------------------------------------
for f in "$LIB_STATE" "$LIB_CLASSIFY"; do
    [[ -r "$f" ]] || { error "missing: $f"; exit 1; }
done
command -v python3 >/dev/null 2>&1 || { error "python3 required"; exit 1; }
# shellcheck disable=SC1090
source "$LIB_STATE"

#------------------------------------------------------------------------------
# SURFACE COLLECTION
#------------------------------------------------------------------------------
WORK=$(mktemp -d -t watchdog.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

PS_F="$WORK/ps"; SSE_F="$WORK/ss-est"; SSL_F="$WORK/ss-listen"
TMUX_F="$WORK/tmux"; ROUTES_F="$WORK/routes"; FOOT_F="$WORK/footholds"; PIV_F="$WORK/pivots"

collect_live() {
    timeout "$CMD_TIMEOUT" ps -eo pid,ppid,etime,comm,args --no-headers > "$PS_F" 2>/dev/null
    timeout "$CMD_TIMEOUT" ss -tinp state established      > "$SSE_F" 2>/dev/null
    timeout "$CMD_TIMEOUT" ss -tlnp                        > "$SSL_F" 2>/dev/null
    if command -v tmux >/dev/null 2>&1; then
        timeout "$CMD_TIMEOUT" tmux list-panes -aF \
            '#{session_name}:#{window_index}.#{pane_index} #{pane_pid} #{pane_dead} #{pane_current_command}' \
            > "$TMUX_F" 2>/dev/null || : > "$TMUX_F"
    else
        : > "$TMUX_F"
    fi
    # foothold baseline across all targets
    : > "$FOOT_F"
    local ip
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        state_read_footholds "$ip" >> "$FOOT_F"
    done < <(state_list_targets)
    # pivot baseline
    state_read_pivots > "$PIV_F" 2>/dev/null || : > "$PIV_F"
    # routes: one ip route get per unique foothold IP
    : > "$ROUTES_F"
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        local line
        line=$(timeout "$CMD_TIMEOUT" ip route get "$f" 2>/dev/null | head -1)
        if [[ -n "$line" ]]; then printf '%s %s\n' "$f" "$line" >> "$ROUTES_F"
        else printf '%s FAILED\n' "$f" >> "$ROUTES_F"; fi
    done < <(cut -f1 "$FOOT_F" | sort -u)
}

use_surfaces_dir() {
    PS_F="$SURFACES_DIR/ps"; SSE_F="$SURFACES_DIR/ss-est"; SSL_F="$SURFACES_DIR/ss-listen"
    TMUX_F="$SURFACES_DIR/tmux"; ROUTES_F="$SURFACES_DIR/routes"
    FOOT_F="$SURFACES_DIR/footholds"; PIV_F="$SURFACES_DIR/pivots"
}

if [[ -n "$SURFACES_DIR" ]]; then
    [[ -d "$SURFACES_DIR" ]] || { error "--surfaces-dir not a directory: $SURFACES_DIR"; exit 1; }
    use_surfaces_dir
else
    collect_live
fi

#------------------------------------------------------------------------------
# CLASSIFY
#------------------------------------------------------------------------------
CLASSIFY_ARGS=(
    --ps "$PS_F" --ss-est "$SSE_F" --ss-listen "$SSL_F" --tmux "$TMUX_F"
    --routes "$ROUTES_F" --footholds "$FOOT_F" --pivots "$PIV_F"
    --idle-shells-ms "$IDLE_SHELLS_MS" --idle-tunnels-ms "$IDLE_TUNNELS_MS"
    --uid "$(id -u)" --type "$TYPE"
)
[[ -n "$TARGET" ]] && CLASSIFY_ARGS+=(--target "$TARGET")

JSON=$(python3 "$LIB_CLASSIFY" "${CLASSIFY_ARGS[@]}")
RC=$?
if [[ $RC -ne 0 || -z "$JSON" ]]; then
    error "classifier failed (rc=$RC)"; exit 1
fi

#------------------------------------------------------------------------------
# TRANSITION WRITES  (shells only in v1; tunnels deferred to v2)
#------------------------------------------------------------------------------
prior_liveness_class() {
    local ip="$1" sf last
    sf="$TOOLKIT_ROOT/targets/$ip/state/sentinels.log"
    [[ -r "$sf" ]] || { echo NONE; return; }
    # exact-prefix filter so future sentinel families never collide
    last=$(awk '$2 ~ /^success-liveness-/ { print $2 }' "$sf" | tail -1)
    case "$last" in
        success-liveness-*-died)    echo DEAD;  return ;;
        success-liveness-*-stale)   echo STALE; return ;;
        success-liveness-recovered) echo ALIVE; return ;;
    esac
    # cold-start (spec §6): implicit prior ALIVE iff targetcheckr logged a shell
    if awk '$2 == "success-shell-spawned" { f=1 } END { exit !f }' "$sf" 2>/dev/null; then
        echo ALIVE; return
    fi
    echo NONE
}

if ! $DRY_RUN; then
    while IFS=$'\t' read -r ip cls; do
        [[ -n "$ip" && "$ip" != "null" ]] || continue
        prior=$(prior_liveness_class "$ip")
        case "$cls/$prior" in
            DEAD/ALIVE)             state_write_event "$ip" success-liveness-shell-died >/dev/null ;;
            STALE/ALIVE)            state_write_event "$ip" success-liveness-shell-stale >/dev/null ;;
            ALIVE/DEAD|ALIVE/STALE) state_write_event "$ip" success-liveness-shell-recovered >/dev/null ;;
            *) : ;;
        esac
    done < <(python3 -c '
import json, sys
d = json.loads(sys.argv[1])
for r in d["resources"]:
    if r["type"] == "shell" and r["ip"]:
        print("{}\t{}".format(r["ip"], r["class"]))
' "$JSON")
fi

#------------------------------------------------------------------------------
# OUTPUT
#------------------------------------------------------------------------------
if $OUT_JSON; then
    printf '%s\n' "$JSON"
    exit 0
fi

WATCHDOG_JSON="$JSON" VERBOSE="$VERBOSE" \
BOLD="$BOLD" DIM="$DIM" RED="$RED" GREEN="$GREEN" YELLOW="$YELLOW" \
CYAN="$CYAN" MAGENTA="$MAGENTA" NC="$NC" \
python3 - <<'PYRENDER'
import json, os

j = json.loads(os.environ['WATCHDOG_JSON'])
VERBOSE = os.environ.get('VERBOSE') == 'true'
C = {k: os.environ.get(k, '') for k in
     ('BOLD', 'DIM', 'RED', 'GREEN', 'YELLOW', 'CYAN', 'MAGENTA', 'NC')}
def col(c, s): return "%s%s%s" % (C[c], s, C['NC'])
def bar(): print('─' * 69)

CLASS_GLYPH = {'ALIVE': ('GREEN', '✓'), 'STALE': ('YELLOW', '⚠'),
               'DEAD': ('RED', '✗'), 'UNKNOWN': ('DIM', '?')}

def idle_str(ms):
    if ms is None:
        return ''
    s = ms // 1000
    if s < 90:    return 'active %ds' % s
    if s < 5400:  return 'idle %dm' % (s // 60)
    return 'idle %dh%02dm' % (s // 3600, (s % 3600) // 60)

def render_row(r):
    cc, glyph = CLASS_GLYPH.get(r['class'], ('BOLD', '?'))
    holder = r['holder']
    if r.get('port'):
        holder = '%s :%s' % (holder, r['port'])
    bits = []
    if r['type'] == 'shell':
        if r['established']:
            bits.append('%d ESTABLISHED' % r['established'])
        if r.get('route') and r['route'] != 'direct':
            bits.append('via %s' % r['route'] if r['route'].startswith('ligolo:')
                        else r['route'])
        i = idle_str(r.get('idle_ms'))
        if i: bits.append(i)
        if r.get('foothold_lines', 0) > 1:
            bits.append('%d foothold lines' % r['foothold_lines'])
    elif r['type'] == 'tunnel':
        if r['established']:
            bits.append('%d ESTABLISHED' % r['established'])
        i = idle_str(r.get('idle_ms'))
        if i: bits.append(i)
    if 'file-server' in r.get('flags', []):
        holder = holder + ' (file-server)'
    if 'nc-warn' in r.get('flags', []):
        bits.append(col('YELLOW', 'nc detected — prefer penelope'))
    if 'msf-allowance' in r.get('flags', []):
        bits.append(col('YELLOW', 'MSF — counts against your one allowance'))
    if 'relay-blindspot' in r.get('flags', []):
        bits.append(col('DIM', 'relay blindspot'))
    if VERBOSE and r.get('pid'):
        bits.append('pid %s' % r['pid'])
    label = '%-5s %-8s %-26s %s' % (r['class'], r['type'], holder, '  '.join(bits))
    print('  %s %s' % (col(cc, glyph), label.rstrip()))
    if r.get('note'):
        print('      %s' % col('DIM', r['note']))

bar()
s = j['summary']
print(' %s   uid %s' % (col('BOLD', 'watchdog ' + j['timestamp']), j['uid']))
print(' %s alive   %s stale   %s dead   %s unknown' % (
    col('GREEN', s['alive']), col('YELLOW', s['stale']),
    col('RED', s['dead']), col('DIM', s['unknown'])))
bar()

shells = [r for r in j['resources'] if r['type'] == 'shell']
tunnels = [r for r in j['resources'] if r['type'] == 'tunnel']
listeners = [r for r in j['resources'] if r['type'] == 'listener']

if shells:
    print()
    cur = None
    for r in sorted(shells, key=lambda x: x['ip'] or ''):
        if r['ip'] != cur:
            cur = r['ip']
            print(' %s' % col('BOLD', cur))
        render_row(r)
if tunnels:
    print()
    print(' %s' % col('DIM', '(tunnels — baselined from pivots/state.tsv)'))
    for r in tunnels:
        render_row(r)
if listeners:
    print()
    print(' %s' % col('DIM', '(listeners — observation-only)'))
    for r in listeners:
        render_row(r)
if not (shells or tunnels or listeners):
    print()
    print(' %s' % col('DIM', 'no shells, tunnels, or listeners observed'))

for note in j.get('footer_notes', []):
    print()
    print(' %s' % col('YELLOW', note))
print()
bar()
PYRENDER

exit 0
