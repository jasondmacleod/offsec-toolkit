#!/usr/bin/env bash
#==============================================================================
# livefetch.sh — pull current intel for the targets you're working
#==============================================================================
# PURPOSE
#   Selectively RE-RUN the right recon stage(s), DIFF the new output against
#   what's already on disk, and surface what changed — without re-running the
#   full recon.sh. A wrapper, not a recon tool: it drives recon.sh /
#   webenum.sh / adr.sh, never invents scans. Build 6 of 7.
#
# WORKFLOW (per stage)
#   1. Discover DONE markers from the collection script's progress.log.
#   2. Decide stale (artifact mtime > --since) or cascade-forced.
#   3. Snapshot artifacts aside, strip the | DONE | <marker> | line, re-run the
#      wrapped script (it overwrites in place), diff vs the snapshot.
#   4. Classify the delta via lib/livefetch_diff.py → emit success-livefetch-*
#      sentinels via state_write_event (unless --diff-only).
#
# USAGE
#   livefetch --target <ip>                  all stages, default --since 30m
#   livefetch --target <ip> --stage recon|web|ad|from-foothold
#   livefetch --diff-only --target <ip>      run into temp, diff, discard (read-only)
#   livefetch --all [--since 1h]             every target with artifacts older
#   livefetch --json                         machine-readable (proofr)
#   livefetch --no-cascade                   suppress downstream cascade
#   livefetch --verbose                      full unified diff per stage
#   livefetch --target <ip> from-foothold <file>|-|--tmux-pane <id> [--label N]
#
# DESIGN
#   - Collection-layer tool (Option 1): reads/re-runs recon/<ip>, web/<svc>,
#     ad/<domain>; never normalizes into targets/<ip>/ (that's orient.sh).
#   - Markers are DISCOVERED from progress.log and mapped marker→stage by
#     string (bare-vs-suffixed is a recognition reference, not a construction
#     rule — dns/ldap/rpc/snmp are bare too).
#   - Sentinels via state_write_event only; NO new lib/state.sh writers.
#   - Sibling of watchdog.sh: lib/state.sh consumer, classifier in Python,
#     fail-loud (no set -e).
#==============================================================================

set -o pipefail

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_STATE="${SCRIPT_DIR}/lib/state.sh"
LIB_DIFF="${SCRIPT_DIR}/lib/livefetch_diff.py"
TOOLKIT_ROOT="${TOOLKIT_ROOT:-$HOME/toolkit}"

RECON_SH="${SCRIPT_DIR}/recon.sh"
WEBENUM_SH="${SCRIPT_DIR}/webenum.sh"
ADR_SH="${SCRIPT_DIR}/adr.sh"

DEFAULT_SINCE=1800   # 30m

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS
#------------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
disable_colors() { RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''; }
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

ts()    { date '+%H:%M:%S'; }
warn()  { echo -e "${YELLOW}[$(ts)] [!]${NC} $*" >&2; }
error() { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }

#------------------------------------------------------------------------------
# CLI PARSING
#------------------------------------------------------------------------------
TARGET=""; ALL=false; STAGE="all"; SINCE="$DEFAULT_SINCE"
DIFF_ONLY=false; OUT_JSON=false; CASCADE=true; VERBOSE=false
SUBCMD=""; FF_INPUT=""; FF_TMUX=""; FF_LABEL="capture"
TMUX_CAPTURE_LINES=3000

dur_to_seconds() {
    local v="$1" n unit
    n="${v%[hms]}"; unit="${v: -1}"
    [[ "$n" =~ ^[0-9]+$ ]] || { echo ""; return 1; }
    case "$unit" in
        h) echo $(( n * 3600 )) ;;
        m) echo $(( n * 60 )) ;;
        s) echo "$n" ;;
        *) echo "$v" ;;
    esac
}

usage() {
    cat <<EOF
livefetch.sh — selective recon re-fetch + delta detection

Usage:
  livefetch --target <ip>                  re-fetch stale stages, diff, surface deltas
  livefetch --target <ip> --stage recon|web|ad|from-foothold
  livefetch --all [--since 1h]             all targets with artifacts older than --since
  livefetch --diff-only --target <ip>      run into temp, diff, discard (read-only)
  livefetch --json                         machine-readable output (for proofr)
  livefetch --no-cascade                   re-run only stale stages, no cascade
  livefetch --verbose                      include full unified diff per stage
  livefetch --target <ip> from-foothold <file>|-|--tmux-pane <id> [--label <name>]
  livefetch -h | --help                    this help

Wraps recon.sh / webenum.sh / adr.sh. Never reinvents recon, never
escalates --deep/--vhost, never normalizes into targets/<ip>/, never touches
findings.sqlite. --diff-only is fully read-only (no state writes).
EOF
}

declare -a ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        from-foothold) SUBCMD="from-foothold"; shift ;;
        --target)      TARGET="$2"; shift 2 ;;
        --all)         ALL=true; shift ;;
        --stage)       STAGE="$2"; shift 2 ;;
        --since)       SINCE=$(dur_to_seconds "$2") || { error "bad --since: $2"; exit 2; }; shift 2 ;;
        --diff-only)   DIFF_ONLY=true; shift ;;
        --json)        OUT_JSON=true; shift ;;
        --no-cascade)  CASCADE=false; shift ;;
        --verbose)     VERBOSE=true; shift ;;
        --label)       FF_LABEL="$2"; shift 2 ;;
        --tmux-pane)   FF_TMUX="$2"; shift 2 ;;
        --no-color)    disable_colors; shift ;;
        -h|--help)     usage; exit 0 ;;
        -)             FF_INPUT="-"; shift ;;
        --)            shift; break ;;
        -*)            error "unknown option: $1"; usage >&2; exit 2 ;;
        *)             ARGS+=("$1"); shift ;;
    esac
done
[[ ${#ARGS[@]} -gt 0 ]] && FF_INPUT="${ARGS[0]}"

case "$STAGE" in recon|web|ad|from-foothold|all) ;; *)
    error "--stage must be recon|web|ad|from-foothold|all (got: $STAGE)"; exit 2 ;;
esac
if ! $ALL && [[ -z "$TARGET" ]]; then
    error "specify --target <ip> or --all"; usage >&2; exit 2
fi

#------------------------------------------------------------------------------
# PRECHECKS
#------------------------------------------------------------------------------
for f in "$LIB_STATE" "$LIB_DIFF"; do
    [[ -r "$f" ]] || { error "missing: $f"; exit 1; }
done
command -v python3 >/dev/null 2>&1 || { error "python3 required"; exit 1; }
# shellcheck disable=SC1090
source "$LIB_STATE"

WORK=$(mktemp -d -t livefetch.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

RESULTS_F="$WORK/results.ndjson"; : > "$RESULTS_F"
PROPOSALS_F="$WORK/proposals.txt"; : > "$PROPOSALS_F"
EMITTED_STALE=" "
RIDDEN=" "                 # ip:stage set already recorded as a rider this run
declare -a RIDER_STAGES=() # markerless stages that regenerate with the primary

# Re-run hook: tests set LIVEFETCH_RERUN_CMD to simulate a wrapped-script run.
# It sees LF_STAGE / LF_IP / LF_WORKROOT / LF_INSTANCE / LF_OUTBASE and is
# expected to (re)write the stage's artifact under LF_WORKROOT.
run_wrapped() {
    if [[ -n "${LIVEFETCH_RERUN_CMD:-}" ]]; then
        bash -c "$LIVEFETCH_RERUN_CMD" >/dev/null 2>&1
        return $?
    fi
    "$@" >/dev/null 2>&1
}

#------------------------------------------------------------------------------
# HELPERS
#------------------------------------------------------------------------------
emit_sentinels() {   # $1=ip  $2=keys-json
    $DIFF_ONLY && return 0
    local ip="$1" k
    while IFS= read -r k; do
        [[ -n "$k" ]] && state_write_event "$ip" "$k" >/dev/null 2>&1
    done < <(printf '%s' "$2" | python3 -c 'import json,sys
try:
    [print(k) for k in json.load(sys.stdin)]
except Exception: pass')
}

mark_stale_run() {   # run-level stale-detected, once per ip per persisted run
    $DIFF_ONLY && return 0
    local ip="$1"
    [[ "$EMITTED_STALE" == *" $ip "* ]] && return 0
    state_write_event "$ip" success-livefetch-stale-detected >/dev/null 2>&1
    EMITTED_STALE="$EMITTED_STALE$ip "
}

is_stale() {         # $1=primary artifact → true if present AND older than SINCE
    local f="$1" now mt
    [[ -e "$f" ]] || return 1
    now=$(date +%s)
    mt=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo "$now")
    (( now - mt > SINCE ))
}

strip_marker() {     # $1=progress.log  $2=marker
    local plog="$1" marker="$2" tmp
    [[ -f "$plog" ]] || return 0
    tmp="${plog}.lf.$$"
    if grep -vF "| DONE | $marker |" "$plog" > "$tmp" 2>/dev/null; then mv "$tmp" "$plog"
    else rm -f "$tmp"; fi
}

record_result() {    # stdin=classifier-json  $1=ip  $2=tier
    python3 -c '
import json,sys
r=json.load(sys.stdin)
r["target"]=sys.argv[1]; r["tier"]=sys.argv[2]; r["ran"]=True
r["diff_only"]=(sys.argv[3]=="1")
print(json.dumps(r))' "$1" "$2" "$($DIFF_ONLY && echo 1 || echo 0)" >> "$RESULTS_F"
}

# Core per-stage refetch. Globals expected: STAGE_TIER, RERUN_BUILDER (fn name
# taking <outbase> and setting RERUN_CMD[]). Args:
#   $1 stage  $2 instance  $3 live_root  $4 rel_under_base  $5 ip  $6 plog_rel
#   $7.. markers to strip
# Returns 0 if a meaningful delta was found.
refetch_stage() {
    local stage="$1" instance="$2" live_root="$3" rel="$4" ip="$5" plog_rel="$6"; shift 6
    local markers=("$@")
    local old_root new_root outbase tmpbase=""

    if $DIFF_ONLY; then
        tmpbase=$(mktemp -d "$WORK/do.XXXXXX")
        new_root="$tmpbase/$rel"
        mkdir -p "$new_root"
        cp -a "$live_root/." "$new_root/" 2>/dev/null
        old_root="$live_root"           # untouched
        outbase="$tmpbase"
    else
        old_root=$(mktemp -d "$WORK/snap.XXXXXX")
        cp -a "$live_root/." "$old_root/" 2>/dev/null
        new_root="$live_root"           # re-run in place
        outbase="$REAL_OUTBASE"
    fi

    local m
    for m in "${markers[@]}"; do strip_marker "$new_root/$plog_rel" "$m"; done

    "$RERUN_BUILDER" "$outbase"
    LF_STAGE="$stage" LF_IP="$ip" LF_WORKROOT="$new_root" \
    LF_INSTANCE="$instance" LF_OUTBASE="$outbase" \
        run_wrapped "${RERUN_CMD[@]}"

    local vflag=(); $VERBOSE && vflag=(--verbose)
    local res
    res=$(python3 "$LIB_DIFF" --stage "$stage" --old "$old_root" --new "$new_root" \
            --instance "$instance" "${vflag[@]}" 2>/dev/null)
    [[ -n "$res" ]] || res='{"stage":"'"$stage"'","instance":"'"$instance"'","changed":false,"keys":[],"items":{},"summary":"classifier error","diff":""}'

    local changed keys
    changed=$(printf '%s' "$res" | python3 -c 'import json,sys;print("1" if json.load(sys.stdin).get("changed") else "0")' 2>/dev/null)
    keys=$(printf '%s' "$res" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin).get("keys",[])))' 2>/dev/null)
    [[ "$changed" == "1" ]] && emit_sentinels "$ip" "$keys"
    printf '%s' "$res" | record_result "$ip" "$STAGE_TIER"

    # rider stages: markerless artifacts regenerated by this same re-run
    # (tcp-vulnmatch rides tcp-services; *-summary regenerate). Deduped per run.
    local rstage rres rchanged rkeys
    for rstage in "${RIDER_STAGES[@]}"; do
        [[ -n "$rstage" ]] || continue
        [[ "$RIDDEN" == *" $ip:$rstage "* ]] && continue
        RIDDEN="$RIDDEN$ip:$rstage "
        rres=$(python3 "$LIB_DIFF" --stage "$rstage" --old "$old_root" --new "$new_root" --instance "" "${vflag[@]}" 2>/dev/null)
        [[ -n "$rres" ]] || continue
        rchanged=$(printf '%s' "$rres" | python3 -c 'import json,sys;print("1" if json.load(sys.stdin).get("changed") else "0")' 2>/dev/null)
        rkeys=$(printf '%s' "$rres" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin).get("keys",[])))' 2>/dev/null)
        [[ "$rchanged" == "1" ]] && emit_sentinels "$ip" "$rkeys"
        printf '%s' "$rres" | record_result "$ip" "$STAGE_TIER"
    done

    # cleanup temp ONLY — never the live tree
    [[ -n "$tmpbase" ]] && rm -rf "$tmpbase"
    $DIFF_ONLY || rm -rf "$old_root"
    [[ "$changed" == "1" ]]
}

#------------------------------------------------------------------------------
# RECON TIER
#------------------------------------------------------------------------------
RB_IP=""
# shellcheck disable=SC2329  # invoked indirectly via "$RERUN_BUILDER"
build_rerun_recon() { RERUN_CMD=("$RECON_SH" --auto "$RB_IP" --outdir "$1"); }

# marker → "stage|instance|primary_rel|order"
recon_map() {
    case "$1" in
        rustscan|nmap_tcp_discovery) echo "tcp-discovery||scans/tcp_ports.txt|10" ;;
        nmap_tcp)                    echo "tcp-services||scans/nmap_tcp.nmap|20" ;;
        nmap_udp|nmap_udp_full)      echo "udp-scan||scans/udp_ports.txt|25" ;;
        http_*)                      echo "http-quick|${1#http_}|tcp/http/port_${1#http_}/whatweb.txt|40" ;;
        smb)                         echo "smb||tcp/smb/netexec_shares.txt|41" ;;
        ssh)                         echo "ssh||tcp/ssh/version_info.txt|42" ;;
        ftp)                         echo "ftp||tcp/ftp/anonymous_check.txt|43" ;;
        dns|ldap|rpc|snmp)           echo "svc-generic|$1|tcp/$1|44" ;;
        mysql_*|mssql_*|postgres_*|redis_*|smtp_*|pop3_*|imap_*)
                                     echo "svc-generic|${1%%_*}|tcp/${1%%_*}|45" ;;
        *) ;;
    esac
}

markers_for() {      # inverse: (stage, instance) → marker(s) to strip
    case "$1" in
        tcp-discovery) echo "rustscan nmap_tcp_discovery" ;;
        tcp-services)  echo "nmap_tcp" ;;
        udp-scan)      echo "nmap_udp nmap_udp_full" ;;
        http-quick)    echo "http_$2" ;;
        *)             echo "$2" ;;     # smb/ssh/ftp/dns/ldap/rpc/snmp = bare ; svc dir name
    esac
}

refetch_recon() {
    local ip="$1"
    local root="$TOOLKIT_ROOT/recon/$ip"
    [[ -d "$root" ]] || return 0
    local plog="$root/progress.log"
    STAGE_TIER="recon"; RB_IP="$ip"; RERUN_BUILDER=build_rerun_recon
    REAL_OUTBASE="$TOOLKIT_ROOT/recon"

    local lines force=false
    lines=$(awk -F'|' '/\| DONE \|/{gsub(/^ +| +$/,"",$3); print $3}' "$plog" 2>/dev/null \
            | while IFS= read -r mk; do [[ -n "$mk" ]] && recon_map "$mk"; done \
            | sort -t'|' -k4 -n -u)

    local stage instance prim _o run mks
    while IFS='|' read -r stage instance prim _o; do
        [[ -n "$stage" ]] || continue
        run=false
        is_stale "$root/$prim" && run=true
        { $CASCADE && $force; } && run=true
        $run || continue
        if [[ "$stage" == "udp-scan" && $EUID -ne 0 ]]; then
            echo "udp-scan ($ip): needs sudo (root) to re-run UDP — skipped" >> "$PROPOSALS_F"
            continue
        fi
        mark_stale_run "$ip"
        if [[ "$stage" == "tcp-services" ]]; then RIDER_STAGES=(tcp-vulnmatch recon-summary)
        else RIDER_STAGES=(recon-summary); fi
        read -ra mks <<< "$(markers_for "$stage" "$instance")"
        if refetch_stage "$stage" "$instance" "$root" "$ip" "$ip" "progress.log" "${mks[@]}"; then
            { [[ "$stage" == "tcp-discovery" || "$stage" == "tcp-services" ]] && $CASCADE; } && force=true
        fi
    done <<< "$lines"
}

#------------------------------------------------------------------------------
# WEB TIER (per web service) + propose-don't-run
#------------------------------------------------------------------------------
RB_URL=""
# shellcheck disable=SC2329  # invoked indirectly via "$RERUN_BUILDER"
build_rerun_web() { RERUN_CMD=("$WEBENUM_SH" --url "$RB_URL" --root "$1"); }

refetch_web() {
    local ip="$1" d base port proto root url plog mk wstage primary rel
    STAGE_TIER="web"; RERUN_BUILDER=build_rerun_web; REAL_OUTBASE="$TOOLKIT_ROOT/web"
    for d in "$TOOLKIT_ROOT"/web/"${ip}"_*_*/; do
        [[ -d "$d" ]] || continue
        base="${d%/}"; base="${base##*/}"          # <ip>_<port>_<proto>
        port="${base#"${ip}"_}"; proto="${port#*_}"; port="${port%%_*}"
        root="$d/artifacts"; url="$proto://$ip:$port"; plog="$root/progress.log"
        rel="$base/artifacts"; RB_URL="$url"
        for mk in fingerprint content sqli_probe recursive vhosts params; do
            grep -qF "| DONE | $mk |" "$plog" 2>/dev/null || continue
            case "$mk" in
                fingerprint) wstage=web-fingerprint;  primary="fingerprint/whatweb.txt" ;;
                content)     wstage=web-content;      primary="content/dirs_medium.txt" ;;
                sqli_probe)  wstage=web-sqli_probe;   primary="sqli/suspects.txt" ;;
                recursive)   wstage=web-recursive;    primary="content/recursive" ;;
                vhosts)      wstage=web-vhosts;       primary="content/ffuf_vhosts.json" ;;
                params)      wstage=web-params;       primary="params" ;;
            esac
            is_stale "$root/$primary" || continue
            mark_stale_run "$ip"
            RIDER_STAGES=(web-summary)
            refetch_stage "$wstage" "" "$root" "$rel" "$ip" "progress.log" "$mk" || true
        done
    done
    # propose webenum for recon HTTP ports lacking a web/ dir (depth/scope discipline)
    local recon="$TOOLKIT_ROOT/recon/$ip/scans/nmap_tcp.nmap" p
    if [[ -r "$recon" ]]; then
        while IFS= read -r p; do
            [[ -n "$p" ]] || continue
            ls -d "$TOOLKIT_ROOT"/web/"${ip}"_"${p}"_* >/dev/null 2>&1 && continue
            echo "webenum (HTTP on $ip:$p, no web/ dir) → $WEBENUM_SH --from-recon $ip" >> "$PROPOSALS_F"
        done < <(grep -oP '^\d+(?=/tcp\s+open\s+\S*http)' "$recon" 2>/dev/null)
    fi
}

#------------------------------------------------------------------------------
# AD TIER (per domain) — hard cred + DC precondition
#------------------------------------------------------------------------------
RB_DOMAIN=""; RB_USER=""; RB_DC=""; declare -a RB_AUTH=()
# shellcheck disable=SC2329  # invoked indirectly via "$RERUN_BUILDER"
build_rerun_ad() { RERUN_CMD=("$ADR_SH" -d "$RB_DOMAIN" -u "$RB_USER" "${RB_AUTH[@]}" -dc "$RB_DC" -o "$1/$RB_DOMAIN"); }

ad_primary() {
    case "$1" in
        phase1_domain_context) echo "domain_context.txt" ;;
        phase2_user_enum)      echo "users/all_users.txt" ;;
        phase2b_ldap_enum)     echo "ldap/laps.txt" ;;
        phase2c_adcs)          echo "adcs/certipy_find.txt" ;;
        phase3_kerberos)       echo "users/kerberoastable.txt" ;;
        phase4_computers)      echo "computers/all_computers.txt" ;;
        phase5_smb_signing)    echo "smb_no_signing.txt" ;;
        phase6_bloodhound)     echo "bloodhound/collection_output.txt" ;;
        phase7_shares)         echo "shares/all_shares.txt" ;;
        phase8_sessions)       echo "sessions/loggedon_users.txt" ;;
        phase9_spray_cracked)  echo "hashes/cracked_passwords.txt" ;;
        *) echo "" ;;
    esac
}

refetch_ad() {
    local ip="$1" d domain root plog cred dc_ip user secret mk primary
    STAGE_TIER="ad"; RERUN_BUILDER=build_rerun_ad; REAL_OUTBASE="$TOOLKIT_ROOT/ad"
    for d in "$TOOLKIT_ROOT"/ad/*/; do
        [[ -d "$d" ]] || continue
        domain="${d%/}"; domain="${domain##*/}"; root="${d%/}"; plog="$root/progress.log"
        # cred from the authoritative creds.txt (6-field pipe; USER/CRED = fields
        # 4/5, the sprayr reader contract, state.sh:312). state_read_global reads
        # the same locked creds.txt since build 8; we read it directly here.
        cred=$(awk -F'|' 'NF>=6 {u=$4;c=$5;gsub(/^ +| +$/,"",u);gsub(/^ +| +$/,"",c);
                                 if(u!=""&&c!=""){print u":"c; exit}}' \
               "$TOOLKIT_ROOT/creds.txt" 2>/dev/null)
        dc_ip=$(grep -vE '^[[:space:]]*(#|$)' "$TOOLKIT_ROOT/ad/dc.txt" 2>/dev/null | head -1 | tr -d '[:space:]')
        if [[ -z "$cred" || -z "$dc_ip" ]]; then
            warn "AD re-fetch for $domain: needs a domain cred + DC IP; none in state — skipping"
            echo "ad-skip ($domain): needs cred + DC IP in state (state_read_global)" >> "$PROPOSALS_F"
            continue
        fi
        user="${cred%%:*}"; secret="${cred#*:}"
        if [[ "$secret" == *:* || "$secret" =~ ^[0-9a-fA-F]{32}$ ]]; then RB_AUTH=(-H "$secret"); else RB_AUTH=(-p "$secret"); fi
        RB_DOMAIN="$domain"; RB_USER="$user"; RB_DC="$dc_ip"
        while IFS= read -r mk; do
            [[ -n "$mk" ]] || continue
            primary=$(ad_primary "$mk"); [[ -n "$primary" ]] || continue
            is_stale "$root/$primary" || continue
            mark_stale_run "$ip"
            RIDER_STAGES=(ad-summary)
            refetch_stage "$mk" "" "$root" "$domain" "$ip" "progress.log" "$mk" || true
        done < <(awk -F'|' '/\| DONE \|/{gsub(/^ +| +$/,"",$3); print $3}' "$plog" 2>/dev/null)
    done
}

#------------------------------------------------------------------------------
# FROM-FOOTHOLD (ingest-only)
#------------------------------------------------------------------------------
do_from_foothold() {
    local ip="$1"
    [[ -n "$ip" ]] || { error "from-foothold needs --target <ip>"; exit 2; }
    local captured; captured=$(mktemp "$WORK/ff.XXXXXX")
    if [[ -n "$FF_TMUX" ]]; then
        command -v tmux >/dev/null 2>&1 || { error "tmux not installed — cannot use --tmux-pane"; exit 1; }
        tmux capture-pane -p -t "$FF_TMUX" -S "-${TMUX_CAPTURE_LINES}" > "$captured" 2>&1 \
            || { error "tmux capture-pane failed for pane '$FF_TMUX'"; cat "$captured" >&2; exit 1; }
    elif [[ -n "$FF_INPUT" && "$FF_INPUT" != "-" ]]; then
        [[ -r "$FF_INPUT" ]] || { error "cannot read input file: $FF_INPUT"; exit 1; }
        cp "$FF_INPUT" "$captured"
    elif [[ "$FF_INPUT" == "-" || ! -t 0 ]]; then
        cat > "$captured"
    else
        error "from-foothold: pass a file, --tmux-pane, or pipe via stdin"; exit 2
    fi

    if [[ -x "$SCRIPT_DIR/watchdog.sh" ]]; then
        local cls
        cls=$("$SCRIPT_DIR/watchdog.sh" --json --target "$ip" 2>/dev/null | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print(next((r["class"] for r in d.get("resources",[]) if r["type"]=="shell" and r["ip"]==sys.argv[1]),"NONE"))
except Exception: print("NONE")' "$ip" 2>/dev/null)
        [[ "$cls" == "DEAD" || "$cls" == "NONE" || -z "$cls" ]] && \
            warn "watchdog: no live shell on $ip — internal capture normally needs a foothold (accepting input anyway)"
    fi

    local dir="$TOOLKIT_ROOT/recon/$ip/from-foothold" old_root new_root
    old_root=$(mktemp -d "$WORK/ffo.XXXXXX"); new_root=$(mktemp -d "$WORK/ffn.XXXXXX")
    [[ -f "$dir/$FF_LABEL.txt" ]] && cp "$dir/$FF_LABEL.txt" "$old_root/$FF_LABEL.txt"
    cp "$captured" "$new_root/$FF_LABEL.txt"
    $DIFF_ONLY || { mkdir -p "$dir"; cp "$captured" "$dir/$FF_LABEL.txt"; }

    STAGE_TIER="from-foothold"
    local vflag=(); $VERBOSE && vflag=(--verbose)
    local res changed keys
    res=$(python3 "$LIB_DIFF" --stage from-foothold --old "$old_root" --new "$new_root" \
            --instance "$FF_LABEL" "${vflag[@]}" 2>/dev/null)
    [[ -n "$res" ]] || res='{"stage":"from-foothold","changed":false,"keys":[],"items":{},"summary":"classifier error","diff":""}'
    changed=$(printf '%s' "$res" | python3 -c 'import json,sys;print("1" if json.load(sys.stdin).get("changed") else "0")' 2>/dev/null)
    keys=$(printf '%s' "$res" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin).get("keys",[])))' 2>/dev/null)
    if [[ "$changed" == "1" ]]; then mark_stale_run "$ip"; emit_sentinels "$ip" "$keys"; fi
    printf '%s' "$res" | record_result "$ip" "from-foothold"
}

#------------------------------------------------------------------------------
# DRIVER
#------------------------------------------------------------------------------
process_target() {
    case "$STAGE" in
        recon)        refetch_recon "$1" ;;
        web)          refetch_web "$1" ;;
        ad)           refetch_ad "$1" ;;
        from-foothold) do_from_foothold "$1" ;;
        all)          refetch_recon "$1"; refetch_web "$1"; refetch_ad "$1" ;;
    esac
}

if [[ "$SUBCMD" == "from-foothold" ]]; then
    do_from_foothold "$TARGET"
elif $ALL; then
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        process_target "$ip"
    done < <( { state_list_targets 2>/dev/null; ls -1 "$TOOLKIT_ROOT/recon" 2>/dev/null; } | sort -u )
else
    process_target "$TARGET"
fi

#------------------------------------------------------------------------------
# OUTPUT
#------------------------------------------------------------------------------
RESULTS_JSON=$(python3 -c '
import json,sys,os,datetime
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
props=[l.rstrip("\n") for l in open(sys.argv[2])] if os.path.exists(sys.argv[2]) else []
print(json.dumps({"timestamp":datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                  "since_seconds":int(sys.argv[3]),"diff_only":sys.argv[4]=="1",
                  "results":rows,"proposals":props}))' \
    "$RESULTS_F" "$PROPOSALS_F" "$SINCE" "$($DIFF_ONLY && echo 1 || echo 0)" 2>/dev/null)
[[ -n "$RESULTS_JSON" ]] || RESULTS_JSON='{"results":[],"proposals":[]}'

if $OUT_JSON; then printf '%s\n' "$RESULTS_JSON"; exit 0; fi

LF_JSON="$RESULTS_JSON" VERBOSE="$VERBOSE" DIFF_ONLY="$($DIFF_ONLY && echo 1 || echo 0)" \
BOLD="$BOLD" DIM="$DIM" RED="$RED" GREEN="$GREEN" YELLOW="$YELLOW" CYAN="$CYAN" NC="$NC" \
python3 - <<'PYRENDER'
import json, os
j = json.loads(os.environ.get('LF_JSON', '{}'))
C = {k: os.environ.get(k, '') for k in ('BOLD','DIM','RED','GREEN','YELLOW','CYAN','NC')}
def col(c, s): return "%s%s%s" % (C[c], s, C['NC'])
def bar(): print('─' * 69)
VERBOSE = os.environ.get('VERBOSE') == 'true'
DIFF_ONLY = os.environ.get('DIFF_ONLY') == '1'

rows = j.get('results', [])
bar()
print(' %s%s' % (col('BOLD', 'livefetch ' + j.get('timestamp','')),
                 ' (diff-only, read-only)' if DIFF_ONLY else ''))
bar()
if not rows:
    print(); print(' ' + col('DIM', 'no stale stages — nothing re-fetched (all fresh within --since)'))
cur = None
for r in sorted(rows, key=lambda x: (x.get('target') or '', x.get('tier') or '', x.get('stage') or '')):
    if r.get('target') != cur:
        cur = r.get('target'); print(); print(' ' + col('BOLD', cur or '(unknown)'))
    name = r.get('stage','?')
    if r.get('instance'): name += ':' + str(r['instance'])
    if r.get('changed'):
        print('  %s %-22s %s' % (col('GREEN','▲'), name, col('GREEN', r.get('summary',''))))
    else:
        print('  %s %-22s %s' % (col('DIM','·'), name, col('DIM','ran — no changes')))
    for k in r.get('keys', []):
        for it in r.get('items', {}).get(k, []):
            print('        %s %s' % (col('CYAN', k.replace('success-livefetch-','')), it))
    if VERBOSE and r.get('diff'):
        for dl in r['diff'].splitlines():
            print('        ' + col('DIM', dl))
props = j.get('proposals', [])
if props:
    print(); print(' ' + col('YELLOW', 'proposed (not run — depth/scope discipline):'))
    for p in props:
        print('   ' + col('YELLOW', p))
print(); bar()
PYRENDER
exit 0
