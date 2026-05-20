#!/usr/bin/env bash
#==============================================================================
# targetcheckr.sh — did the exploit actually work?
#==============================================================================
# PURPOSE
#   Reads captured exploit output (stdout+stderr) and the bound target's
#   state vector, classifies the outcome into a pinned vocabulary (spec §3),
#   and — only when authorized via --expect — writes the success-side state
#   updates the rest of the toolkit depends on (foothold log, creds.txt
#   append, sentinel event). Inverse of exploitfixr. Never executes, never
#   opens sockets, never re-runs the exploit.
#
# WORKFLOW
#   1. Parse CLI (--against, --expect, --dry-run, --tmux-pane, --, -)
#   2. Resolve input — file | tmux capture | stdin (precedence per §2)
#   3. Bind target via lib/state.sh inference (matching stuckr/exploitfixr)
#   4. Content-hash the input → check targetcheckr_runs.log for replay (§8)
#   5. Hand input + state to lib/targetcheckr_classify.py
#   6. Render banner per §6 (success / partial / failure / unclear / replay / dry-run)
#   7. Dispatch state writes (foothold / cred / event) only when:
#         outcome ∈ {success-confirmed, success-likely}
#         AND --expect set
#         AND --dry-run not set
#         AND not a hash replay
#
# USAGE
#   targetcheckr <output-file>                       classify a captured run
#   targetcheckr --tmux-pane <pane-id>               capture from a tmux pane
#   exploit.py | targetcheckr                        classify stdin
#   targetcheckr <file> --against <ip>               bind to target state
#   targetcheckr <file> --expect <class>             authorize state writes
#   targetcheckr <file> --expect shell --dry-run     classify+preview, no writes
#   targetcheckr --no-color                          disable ANSI (also: NO_COLOR=1)
#
# --expect values: shell | cred-dump | file-read | file-write | auth-bypass
#                  | sqli-data | rce
#
# DESIGN
#   - Sibling to stuckr.sh / exploitfixr.sh: same lib/state.sh consumer,
#     same banner style, same fail-loud discipline.
#   - All detection / regex logic lives in lib/targetcheckr_classify.py.
#   - 10.10.14.x is NEVER substituted anywhere — Kali VPN side, per
#     lib/substitutions.md.
#   - State writes only land via the three lib/state.sh functions:
#     state_write_foothold, state_append_cred, state_write_event.
#==============================================================================

set -o pipefail
# NOT set -e — surface errors with clear messages, don't abort silently.

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_STATE="${SCRIPT_DIR}/lib/state.sh"
LIB_CLASSIFY="${SCRIPT_DIR}/lib/targetcheckr_classify.py"
FAILURE_MAP="${SCRIPT_DIR}/lib/failure_map.yaml"
SUBSTITUTIONS="${SCRIPT_DIR}/lib/substitutions.md"
TOOLKIT_ROOT="${TOOLKIT_ROOT:-$HOME/toolkit}"

# tmux capture window — 3000 lines is enough to cover most engagement-grade
# captures but bounded so the file never explodes.
TMUX_CAPTURE_LINES=3000

# --expect → sub-class set (kept in sync with classifier EXPECT_TO_SUBCLASS)
declare -A EXPECT_MAP=(
    ["shell"]=1
    ["cred-dump"]=1
    ["file-read"]=1
    ["file-write"]=1
    ["auth-bypass"]=1
    ["sqli-data"]=1
    ["rce"]=1
)

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
# shellcheck disable=SC2329  # house style — info/warn kept for future use
info()  { echo -e "${BLUE}[$(ts)] [*]${NC} $*"; }
# shellcheck disable=SC2329
warn()  { echo -e "${YELLOW}[$(ts)] [!]${NC} $*"; }
error() { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }

#------------------------------------------------------------------------------
# CLI PARSING
#------------------------------------------------------------------------------
INPUT_FILE=""
TMUX_PANE=""
TARGET_IP=""
EXPECT=""
DRY_RUN=false

usage() {
    cat <<EOF
targetcheckr.sh — classify exploit outcome and update success-side state

Usage:
  targetcheckr <output-file>              classify a captured run from a file
  targetcheckr --tmux-pane <pane-id>      capture+classify from a tmux pane
  exploit.py | targetcheckr               classify stdin
  targetcheckr <file> --against <ip>      bind to a specific target
  targetcheckr <file> --expect <class>    authorize state writes (see below)
  targetcheckr <file> --expect <class> --dry-run
                                          classify and preview, no writes
  targetcheckr -h | --help                this help
  targetcheckr --no-color                 disable ANSI (also: NO_COLOR=1)

--expect values (any other value fails loud at startup):
  shell        success-confirmed when shell-spawned fires
  cred-dump    cred-dumped OR hash-dumped
  file-read    file-read
  file-write   file-written
  auth-bypass  auth-bypassed
  sqli-data    sql-rows-returned
  rce          rce-stdout

Target binding: --against wins, else cwd under \$TOOLKIT_ROOT/targets/<ip>/.
With no target bound, targetcheckr runs in target-less mode: classify and
print, no state writes.

Never executes, never opens sockets, never re-runs the exploit.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --against)      TARGET_IP="$2"; shift 2 ;;
        --expect)       EXPECT="$2"; shift 2 ;;
        --tmux-pane)    TMUX_PANE="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=true; shift ;;
        --no-color)     disable_colors; shift ;;
        -h|--help)      usage; exit 0 ;;
        --) shift; break ;;
        -)
            if [[ -n "$INPUT_FILE" ]]; then
                error "stdin marker '-' conflicts with positional input"
                usage >&2; exit 2
            fi
            INPUT_FILE="-"; shift ;;
        -*) error "unknown option: $1"; usage >&2; exit 2 ;;
        *)
            if [[ -z "$INPUT_FILE" ]]; then
                INPUT_FILE="$1"
            else
                error "unexpected positional argument: $1"; usage >&2; exit 2
            fi
            shift ;;
    esac
done

# Validate --expect against fixed table (spec §2 — fail loud on bad value).
if [[ -n "$EXPECT" ]] && [[ -z "${EXPECT_MAP[$EXPECT]:-}" ]]; then
    error "--expect: invalid value '$EXPECT'"
    error "valid values: ${!EXPECT_MAP[*]}"
    exit 2
fi

# Mutually-exclusive input modes
if [[ -n "$INPUT_FILE" && -n "$TMUX_PANE" ]]; then
    error "input file and --tmux-pane are mutually exclusive"
    exit 2
fi

#------------------------------------------------------------------------------
# PRECHECKS
#------------------------------------------------------------------------------
for f in "$LIB_STATE" "$LIB_CLASSIFY" "$FAILURE_MAP"; do
    if [[ ! -r "$f" ]]; then error "missing: $f"; exit 1; fi
done
if ! command -v python3 >/dev/null 2>&1; then
    error "python3 required (classifier engine)"; exit 1
fi
if ! python3 -c "import yaml" 2>/dev/null; then
    error "python3 PyYAML required (apt install -y python3-yaml)"; exit 1
fi

# shellcheck disable=SC1090
source "$LIB_STATE"

#------------------------------------------------------------------------------
# INPUT RESOLUTION  (spec §2 precedence: file > tmux > stdin)
#------------------------------------------------------------------------------
TMP_INPUT=""
# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    [[ -n "$TMP_INPUT" && -f "$TMP_INPUT" ]] && rm -f "$TMP_INPUT"
    [[ -n "${TMP_CERR:-}" && -f "${TMP_CERR}" ]] && rm -f "${TMP_CERR}"
}
trap cleanup EXIT

resolve_input() {
    if [[ -n "$INPUT_FILE" && "$INPUT_FILE" != "-" ]]; then
        if [[ ! -r "$INPUT_FILE" ]]; then
            error "cannot read input file: $INPUT_FILE"; exit 1
        fi
        ACTIVE_INPUT="$INPUT_FILE"
        INPUT_SOURCE="file:$INPUT_FILE"
        return 0
    fi
    if [[ -n "$TMUX_PANE" ]]; then
        if ! command -v tmux >/dev/null 2>&1; then
            error "tmux not installed — cannot use --tmux-pane"; exit 1
        fi
        TMP_INPUT=$(mktemp -t targetcheckr.tmux.XXXXXX)
        # Spec §2: tmux failure is fatal, no fallback to stdin, no retry.
        if ! tmux capture-pane -p -t "$TMUX_PANE" -S "-${TMUX_CAPTURE_LINES}" \
                > "$TMP_INPUT" 2>&1; then
            error "tmux capture-pane failed for pane '$TMUX_PANE':"
            cat "$TMP_INPUT" >&2
            exit 1
        fi
        ACTIVE_INPUT="$TMP_INPUT"
        INPUT_SOURCE="tmux:$TMUX_PANE"
        return 0
    fi
    # stdin (either explicit `-` or piped without args)
    if [[ "$INPUT_FILE" == "-" ]] || [[ ! -t 0 ]]; then
        TMP_INPUT=$(mktemp -t targetcheckr.stdin.XXXXXX)
        cat > "$TMP_INPUT"
        ACTIVE_INPUT="$TMP_INPUT"
        INPUT_SOURCE="stdin"
        return 0
    fi
    error "no input — pass a file, --tmux-pane, or pipe via stdin"
    usage >&2
    exit 2
}

resolve_input

#------------------------------------------------------------------------------
# TARGET INFERENCE (mirrors stuckr/exploitfixr)
#------------------------------------------------------------------------------
infer_target() {
    local pwd_abs root_abs
    pwd_abs=$(realpath "$PWD" 2>/dev/null || echo "$PWD")
    root_abs=$(realpath "$TOOLKIT_ROOT" 2>/dev/null || echo "$TOOLKIT_ROOT")
    if [[ "$pwd_abs" == "$root_abs/targets/"* ]]; then
        local rest="${pwd_abs#"$root_abs"/targets/}"
        echo "${rest%%/*}"
        return 0
    fi
    return 1
}

INFER_HOW=""
if [[ -n "$TARGET_IP" ]]; then
    INFER_HOW="--against"
elif TARGET_IP=$(infer_target); then
    INFER_HOW="inferred (cwd under \$TOOLKIT_ROOT/targets/)"
else
    TARGET_IP=""
    INFER_HOW="target-less"
fi

#------------------------------------------------------------------------------
# CONTENT-HASH REPLAY CHECK  (spec §8)
#------------------------------------------------------------------------------
INPUT_HASH=$(sha256sum "$ACTIVE_INPUT" 2>/dev/null | awk '{print $1}')
REPLAY_HIT=""
PRIOR_RUN=""
if [[ -n "$TARGET_IP" && -n "$INPUT_HASH" ]]; then
    RUNS_LOG="$TOOLKIT_ROOT/targets/$TARGET_IP/state/targetcheckr_runs.log"
    if [[ -r "$RUNS_LOG" ]]; then
        # Match on hash field (field 2). Format: <iso> <hash> <outcome> <sub> <conf>
        PRIOR_RUN=$(awk -v h="$INPUT_HASH" '$2 == h { print; exit }' "$RUNS_LOG")
        [[ -n "$PRIOR_RUN" ]] && REPLAY_HIT="yes"
    fi
fi

#------------------------------------------------------------------------------
# STATE STREAM (consumed via stdin by the classifier)
#------------------------------------------------------------------------------
build_state_stream() {
    [[ -z "$TARGET_IP" ]] && return 0
    state_read_target "$TARGET_IP"
    state_read_global
}

#------------------------------------------------------------------------------
# CLASSIFIER INVOCATION
#------------------------------------------------------------------------------
TMP_CERR=$(mktemp -t targetcheckr.cerr.XXXXXX)
JSON=$(build_state_stream | python3 "$LIB_CLASSIFY" \
    "$FAILURE_MAP" "$ACTIVE_INPUT" "$SUBSTITUTIONS" \
    "$EXPECT" "$TARGET_IP" 2>"$TMP_CERR")
RC=$?
if [[ $RC -ne 0 || -z "$JSON" ]]; then
    error "classifier failed (rc=$RC)"
    [[ -s "$TMP_CERR" ]] && cat "$TMP_CERR" >&2
    exit 1
fi

#------------------------------------------------------------------------------
# WRITE-DISPATCH GATE (spec §5 / §8)
#------------------------------------------------------------------------------
# Decide whether to write BEFORE rendering, so the banner reflects reality.
SHOULD_WRITE=false
WRITE_BLOCKED_REASON=""
OUTCOME=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(d.get('outcome',''))" "$JSON")

if [[ "$REPLAY_HIT" == "yes" ]]; then
    WRITE_BLOCKED_REASON="replay — hash matches prior run"
elif $DRY_RUN; then
    WRITE_BLOCKED_REASON="dry-run"
elif [[ -z "$EXPECT" ]]; then
    WRITE_BLOCKED_REASON="no --expect"
elif [[ -z "$TARGET_IP" ]]; then
    WRITE_BLOCKED_REASON="target-less mode"
elif [[ "$OUTCOME" != "success-confirmed" && "$OUTCOME" != "success-likely" ]]; then
    WRITE_BLOCKED_REASON="outcome is $OUTCOME (writes only on success-{confirmed,likely})"
else
    SHOULD_WRITE=true
fi

#------------------------------------------------------------------------------
# RENDER  (spec §6 banner — calls into python for formatting)
#------------------------------------------------------------------------------
mode_arg="render"
if [[ "$REPLAY_HIT" == "yes" ]]; then mode_arg="render-replay"
elif $DRY_RUN; then mode_arg="render-dry-run"
fi

RENDER_OUT=$(
    JSON_PAYLOAD="$JSON" \
    INPUT_SOURCE="$INPUT_SOURCE" \
    INPUT_HASH="$INPUT_HASH" \
    TARGET_IP="$TARGET_IP" \
    INFER_HOW="$INFER_HOW" \
    MODE="$mode_arg" \
    PRIOR_RUN="$PRIOR_RUN" \
    WRITE_BLOCKED_REASON="$WRITE_BLOCKED_REASON" \
    SHOULD_WRITE="$SHOULD_WRITE" \
    BOLD="$BOLD" DIM="$DIM" RED="$RED" GREEN="$GREEN" YELLOW="$YELLOW" \
    CYAN="$CYAN" MAGENTA="$MAGENTA" NC="$NC" \
    python3 - <<'PYRENDER'
import json, os, sys

j = json.loads(os.environ['JSON_PAYLOAD'])
SRC      = os.environ['INPUT_SOURCE']
HASH     = os.environ['INPUT_HASH']
TIP      = os.environ['TARGET_IP']
HOW      = os.environ['INFER_HOW']
MODE     = os.environ['MODE']
PRIOR    = os.environ['PRIOR_RUN']
BLOCKED  = os.environ['WRITE_BLOCKED_REASON']
WRITES_OK = os.environ['SHOULD_WRITE'] == 'true'

C = {k: os.environ.get(k, '') for k in
     ('BOLD','DIM','RED','GREEN','YELLOW','CYAN','MAGENTA','NC')}

def bar():   print('═' * 65)
def hr():    print('─' * 65)
def col(c, s): return f"{C[c]}{s}{C['NC']}"

outcome = j['outcome']
sub = j.get('subclass') or ''
conf = j.get('confidence', '?')
expect = j.get('expect', '')
expect_agrees = j.get('expect_agrees')
expect_disagrees = j.get('expect_disagrees', False)

# Colorize outcome name
OUTCOME_COLOR = {
    'success-confirmed':    'GREEN',
    'success-likely':       'GREEN',
    'partial-success':      'YELLOW',
    'no-effect':            'DIM',
    'failure-with-symptom': 'RED',
    'unclear':              'YELLOW',
}.get(outcome, 'BOLD')

# ── BANNER ───────────────────────────────────────────────────────────────────
bar()
banner_title = f"  OUTCOME: {col(OUTCOME_COLOR, outcome)}"
if sub:
    banner_title += f"  ({col('BOLD', sub)})"
if MODE == 'render-replay':
    banner_title += f"  {col('DIM', '[REPLAY — no writes]')}"
elif MODE == 'render-dry-run':
    banner_title = f"  [DRY RUN] {banner_title.lstrip()}"
print(banner_title)

bits = []
if TIP:
    bits.append(f"target: {TIP}")
elif outcome != 'unclear':
    bits.append("(target-less)")
if expect:
    bits.append(f"expect: {expect}")
else:
    bits.append("expect: (none)")
bits.append(f"confidence: {conf}")
print('  ' + '   '.join(bits))

if MODE == 'render-replay' and PRIOR:
    # Prior log line: <iso> <hash> <outcome> <sub> <conf>
    fields = PRIOR.split(None, 4)
    when = fields[0] if fields else '?'
    print(col('DIM', f"  prior run: {when}"))

bar()
print()

# ── EXPECT DISAGREEMENT NOTICE ───────────────────────────────────────────────
if expect and expect_disagrees:
    print(col('YELLOW',
              "NOTE: --expect disagrees with the strongest detected sub-class."))
    print(col('DIM',
              "      Classifier prefers detected evidence over stated intent."))
    print()

# ── POSITIVE MARKERS ─────────────────────────────────────────────────────────
positives = j.get('positive_markers', [])
if positives:
    total = sum(len(p['snippets']) for p in positives)
    print(col('BOLD', f"POSITIVE MARKERS ({total}):"))
    for p in positives:
        print(f"  {col('CYAN', p['subclass'])}:")
        for s in p['snippets']:
            line = s['line'].replace('\n', ' ')
            print(f"    [+] {s['label']:34s}  {line[:90]}")
    print()

# ── NEGATIVE / PARTIAL MARKERS ───────────────────────────────────────────────
partials = j.get('partial_markers', [])
if partials:
    print(col('BOLD', f"PARTIAL-SUCCESS MARKERS ({len(partials)}):"))
    for p in partials:
        for s in p['snippets']:
            print(f"  [~] {col('YELLOW', p['subclass']):28s}  {s['line'][:90]}")
    print()

failures = j.get('failure_markers', [])
if failures:
    label = 'NEGATIVE MARKERS' if outcome == 'failure-with-symptom' \
            else 'NEGATIVE MARKERS (background)'
    print(col('BOLD', f"{label} ({len(failures)}):"))
    for f in failures:
        line = (f['hits'][0]['matched'] if f['hits'] else '')[:90]
        print(f"  [-] {col('RED', f['key']):34s}  {line}")
    print()

# ── STATE CROSS-CHECK ────────────────────────────────────────────────────────
checks = j.get('state_cross_checks', [])
if checks:
    print(col('BOLD', "STATE CROSS-CHECK:"))
    for c in checks:
        ag = c.get('agrees')
        if ag is True:    mark = col('GREEN', 'agrees')
        elif ag is False: mark = col('RED', 'contradicts')
        else:             mark = col('DIM', 'no-data')
        print(f"  {c['check']:34s}  {c['result']:28s}  {mark}")
    print()

# ── STATE WRITES ─────────────────────────────────────────────────────────────
writes = j.get('state_writes', [])
if MODE == 'render-dry-run':
    label = 'WOULD-WRITE'
elif MODE == 'render-replay':
    label = 'STATE WRITES'
else:
    label = 'STATE WRITES'

if not writes:
    print(f"{col('BOLD', label + ':')} none")
else:
    if MODE == 'render-replay':
        print(f"{col('BOLD', label + ':')} skipped (input hash matches prior run)")
    elif not WRITES_OK and MODE != 'render-dry-run':
        print(f"{col('BOLD', label + ':')} skipped ({BLOCKED})")
    else:
        # List each write the same way for live and dry-run
        print(col('BOLD', label + ':'))
        for w in writes:
            kind = w['kind']
            if kind == 'foothold':
                print(f"  foothold:  {w['ip']}  {w['user']}  {w['method']}")
            elif kind == 'cred':
                print(f"  cred:      {w['value']}")
            elif kind == 'event':
                print(f"  event:     {w['ip']}  {w['key']}")
print()

# ── INPUT METADATA + HASH ────────────────────────────────────────────────────
print(col('DIM', f"input:  {SRC}"))
print(col('DIM', f"sha256: {HASH[:32]}…"))
print()

# ── NEXT TOOL HINT ───────────────────────────────────────────────────────────
nt = j.get('next_tool')
nh = j.get('next_hint')
if nt and nh:
    print(f"{col('BOLD', 'NEXT:')}  {nh}")
elif outcome == 'unclear':
    print(col('BOLD', "NEXT:"))
    print("  - re-read the exploit output yourself")
    if TIP:
        print(f"  - stuckr --against {TIP}  (if you are out of moves)")
        print(f"  - exploitfixr <path> --against {TIP}  (if it might be broken)")
    else:
        print("  - stuckr  (if you are out of moves)")
        print("  - exploitfixr <path>  (if it might be broken)")
print()
bar()
PYRENDER
)
RENDER_RC=$?
if [[ $RENDER_RC -ne 0 || -z "$RENDER_OUT" ]]; then
    error "renderer failed (rc=$RENDER_RC)"
    exit 1
fi
printf '%s\n' "$RENDER_OUT"

#------------------------------------------------------------------------------
# STATE WRITES (only when SHOULD_WRITE=true)
#------------------------------------------------------------------------------
if $SHOULD_WRITE; then
    # Pull state_writes out of the JSON via python (no jq dep)
    while IFS=$'\t' read -r kind a b c; do
        case "$kind" in
            foothold)
                state_write_foothold "$a" "$b" "$c" >/dev/null
                ;;
            cred)
                state_append_cred "$a" >/dev/null
                ;;
            event)
                state_write_event "$a" "$b" >/dev/null
                ;;
        esac
    done < <(python3 -c '
import json, sys
d = json.loads(sys.argv[1])
for w in d.get("state_writes", []):
    k = w["kind"]
    if k == "foothold":
        print("foothold\t{}\t{}\t{}".format(w["ip"], w["user"], w["method"]))
    elif k == "cred":
        print("cred\t{}\t\t".format(w["value"]))
    elif k == "event":
        print("event\t{}\t{}\t".format(w["ip"], w["key"]))
' "$JSON")

    # Append to targetcheckr_runs.log so a later identical-hash run is a replay.
    if [[ -n "$TARGET_IP" && -n "$INPUT_HASH" ]]; then
        SUB=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(d.get('subclass') or '-')" "$JSON")
        CONF=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(d.get('confidence','?'))" "$JSON")
        runs_dir="$TOOLKIT_ROOT/targets/$TARGET_IP/state"
        mkdir -p "$runs_dir" 2>/dev/null
        printf '%s %s %s %s %s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%S)" "$INPUT_HASH" "$OUTCOME" "$SUB" "$CONF" \
            >> "$runs_dir/targetcheckr_runs.log"
    fi
fi

exit 0
