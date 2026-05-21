#!/usr/bin/env bash
#==============================================================================
# orient.sh — collection-to-decision-layer bridge (build 7 of 8)
#==============================================================================
# PURPOSE
#   Translate the COLLECTION-layer tree (recon.sh / webenum.sh / adr.sh
#   under $TOOLKIT_ROOT/{recon,web,ad}) into the DECISION-layer tree
#   ($TOOLKIT_ROOT/targets/<ip>/) that lib/state.sh's state_read_target /
#   state_read_global parse — in the exact shape those readers expect. Reads
#   collection artifacts, writes the canonical files. Does NOT run recon,
#   classify outcomes, write sentinels, or touch evidence/foothold/creds.
#
# WORKFLOW
#   orient <ip>  →  recon/<ip>/scans/nmap_tcp.nmap       → targets/<ip>/recon/nmap.txt
#                   recon/<ip>/tcp/smb/*                 → targets/<ip>/recon/smb.txt
#                   web/<host>_<port>_<proto>/artifacts  → targets/<ip>/web/{feroxbuster,vhosts}.txt
#                   ad/<DOMAIN>/{users,computers}/*      → targets/<ip>/ad/{users,computers}.txt
#                                                          $TOOLKIT_ROOT/ad/{domain,dc}.txt
#
# USAGE
#   orient <ip>                          normalize one target into targets/<ip>/
#   orient --all                         normalize every IP found under recon/, web/
#   orient <ip> --web-host <hostname>    associate a hostname-keyed web/ dir (repeatable)
#   orient <ip> --domain <name>          associate AD <DOMAIN>/ as this ip's data (ip = DC)
#   orient <ip> --dry-run                print intended writes, change nothing
#   orient -h | --help
#
# OUTPUT STRUCTURE (decision layer — paths locked to state.sh readers)
#   targets/<ip>/recon/nmap.txt       os_guess + services  (state.sh:165,178,184)
#   targets/<ip>/recon/smb.txt        smb_share            (state.sh:166,203)
#   targets/<ip>/web/feroxbuster.txt  web_path             (state.sh:167,192)
#   targets/<ip>/web/vhosts.txt       web_vhost            (state.sh:169,198)
#   targets/<ip>/ad/users.txt         ad_user              (state.sh:170,208)
#   targets/<ip>/ad/computers.txt     ad_computer          (state.sh:171,211)
#   $TOOLKIT_ROOT/ad/domain.txt|dc.txt   domain | dc_ip       (state.sh:240,244)
#
# DESIGN DECISIONS
#   - One-directional: collection → decision. Never reads its own output.
#   - Full-file replacement (idempotent). No append, no sentinels, no new
#     state.sh writers. evidence/, state/, creds.txt are NOT orient's surface.
#   - Transforms verified against real artifacts (Phase 0 2026-05-21, see
#     docs/orient_spec.md §9): nmap + smbclient table + all_users copy VERBATIM;
#     netexec/smbmap shares, nxc computers, and vhosts are awk-NORMALIZED because
#     the readers would otherwise drop or mis-parse the raw tool output (e.g. the
#     nxc "Share" header would leak as a false share).
#   - Hostname→IP and DOMAIN→IP association is operator-driven (--web-host /
#     --domain), never DNS-guessed at runtime. AD rows fire only with --domain;
#     dc_ip is then the IP being oriented (it is the DC).
#==============================================================================

set -o pipefail

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
# Resolve TOOLKIT_ROOT to the invoking user's home when run through sudo.
if [[ -z "${TOOLKIT_ROOT:-}" ]]; then
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        TOOLKIT_ROOT="$(eval echo "~${SUDO_USER}")/offsec"
    else
        TOOLKIT_ROOT="$HOME/toolkit"
    fi
fi

IP_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

#------------------------------------------------------------------------------
# COLORS & OUTPUT HELPERS
#------------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
disable_colors() { RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''; }
{ [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; } && disable_colors

ts()      { date '+%H:%M:%S'; }
info()    { echo -e "${CYAN}[$(ts)] [*]${NC} $*"; }
success() { echo -e "${GREEN}[$(ts)] [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(ts)] [!]${NC} $*" >&2; }
error()   { echo -e "${RED}[$(ts)] [-]${NC} $*" >&2; }

#------------------------------------------------------------------------------
# CLI PARSING
#------------------------------------------------------------------------------
TARGET=""; ALL=false; DOMAIN=""; DRY_RUN=false
declare -a WEB_HOSTS=()

usage() {
    cat <<EOF
orient.sh — collection-to-decision-layer bridge

Usage:
  orient <ip>                          normalize one target into targets/<ip>/
  orient --all                         normalize every IP found under recon/, web/
  orient <ip> --web-host <hostname>    associate a hostname-keyed web/ dir (repeatable)
  orient <ip> --domain <name>          associate AD <DOMAIN>/ as this ip's data (ip = DC)
  orient <ip> --dry-run                print intended writes, change nothing
  orient -h | --help                   this help

Reads \$TOOLKIT_ROOT/{recon,web,ad}; writes \$TOOLKIT_ROOT/targets/<ip>/ (+ ad/domain.txt,
ad/dc.txt). Never runs recon, never writes sentinels/evidence/creds, never reads
its own output. TOOLKIT_ROOT=$TOOLKIT_ROOT
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)       ALL=true; shift ;;
        --web-host)  [[ -n "${2:-}" ]] || { error "--web-host needs a hostname"; exit 2; }; WEB_HOSTS+=("$2"); shift 2 ;;
        --domain)    [[ -n "${2:-}" ]] || { error "--domain needs a name"; exit 2; }; DOMAIN="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=true; shift ;;
        --no-color)  disable_colors; shift ;;
        -h|--help)   usage; exit 0 ;;
        -*)          error "unknown option: $1"; usage >&2; exit 2 ;;
        *)           if [[ -z "$TARGET" ]]; then TARGET="$1"; else error "unexpected argument: $1"; exit 2; fi; shift ;;
    esac
done

if ! $ALL && [[ -z "$TARGET" ]]; then
    error "specify <ip> or --all"; usage >&2; exit 2
fi
if $ALL && [[ -n "$TARGET" ]]; then
    error "--all takes no <ip> argument"; exit 2
fi
if $ALL && { [[ ${#WEB_HOSTS[@]} -gt 0 ]] || [[ -n "$DOMAIN" ]]; }; then
    warn "--web-host/--domain ignored with --all (per-IP literal matching only)"
    WEB_HOSTS=(); DOMAIN=""
fi

# Primary output root must be creatable (skip the side effect in dry-run).
if ! $DRY_RUN; then
    mkdir -p "$TOOLKIT_ROOT/targets" || { error "cannot create $TOOLKIT_ROOT/targets"; exit 1; }
fi

#------------------------------------------------------------------------------
# WRITE HELPER — full-file replacement, dry-run aware. Reads content on stdin;
# callers feed it via `< file` or `<<< "$var"` (never a pipe — keeps WROTE in
# the current shell rather than a pipeline subshell).
#------------------------------------------------------------------------------
WROTE=0
emit_to() {  # $1=dest ; content on stdin
    local dest="$1" content
    content="$(cat)"
    if $DRY_RUN; then
        info "[dry-run] ${dest#"$TOOLKIT_ROOT"/} ($(printf '%s\n' "$content" | grep -c '') lines)"
        return 0
    fi
    if ! mkdir -p "$(dirname "$dest")"; then
        error "mkdir failed for ${dest#"$TOOLKIT_ROOT"/}"; return 1
    fi
    if ! printf '%s\n' "$content" > "$dest"; then
        error "write failed: ${dest#"$TOOLKIT_ROOT"/}"; return 1
    fi
    success "wrote ${dest#"$TOOLKIT_ROOT"/}"
    WROTE=$((WROTE + 1))
}

_in_array() {  # $1=needle, rest=haystack
    local n="$1"; shift
    local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done
    return 1
}

#------------------------------------------------------------------------------
# COLLECTION-LAYER NORMALIZERS  (Phase 0-verified — orient_spec.md §2 / §2.1)
#------------------------------------------------------------------------------

# smb.txt stream: smbclient table VERBATIM (reader branch-1) + netexec(guarded
# $5) + smbmap(permission-anchored $1). Caller sort -u's and writes.
orient_smb_stream() {  # $1=smbdir
    local d="$1" f
    [[ -r "$d/smbclient_list.txt" ]] && cat "$d/smbclient_list.txt"
    [[ -r "$d/netexec_shares.txt" ]] && awk '
        /^SMB[[:space:]]/ && $5 !~ /^\[/ && $5 !~ /^(Share|Permissions|Remark)$/ && $5 !~ /^-+$/ { print $5 }
    ' "$d/netexec_shares.txt"
    for f in smbmap_null.txt smbmap_guest.txt; do
        [[ -r "$d/$f" ]] && awk '
            /^[[:space:]]+[A-Za-z0-9_.$-]+[[:space:]]+(READ|WRITE|NO ACCESS)/ { print $1 }
        ' "$d/$f"
    done
}

# Web dirs whose <host> (in <host>_<port>_<proto>) is this IP or a --web-host.
orient_match_webdirs() {  # $1=ip
    local ip="$1" dir base host
    [[ -d "$TOOLKIT_ROOT/web" ]] || return 0
    for dir in "$TOOLKIT_ROOT"/web/*/; do
        [[ -d "$dir" ]] || continue
        base="$(basename "$dir")"
        [[ "$base" =~ ^(.+)_([0-9]+)_(https?)$ ]] || continue
        host="${BASH_REMATCH[1]}"
        if [[ "$host" == "$ip" ]] || _in_array "$host" "${WEB_HOSTS[@]}"; then
            printf '%s\n' "$dir"
        fi
    done
}

# feroxbuster.txt: raw ffuf text concatenated VERBATIM (the URL carries the
# port; _state_parse_web_paths extracts the path from each URL line at read).
orient_web_paths_stream() {  # $@=webdirs
    local dir
    for dir in "$@"; do
        cat "${dir}artifacts/content/dirs_medium.txt"  2>/dev/null
        cat "${dir}artifacts/content/files_medium.txt" 2>/dev/null
    done
}

# vhosts.txt: bare hostnames (field 2 of the `  <ip>  <vhost>` /etc/hosts lines).
orient_web_vhosts_stream() {  # $@=webdirs
    local dir
    for dir in "$@"; do
        [[ -r "${dir}artifacts/vhosts/hosts_entries.txt" ]] && \
            awk 'NF>=2 {print $2}' "${dir}artifacts/vhosts/hosts_entries.txt"
    done | sort -u
}

# computers.txt: prefer nxc --computers (machine accounts = $5 ending in $);
# fall back to LDAP dNSHostName + rpcclient user:[NAME$]. Caller sort -u's.
orient_ad_computers_stream() {  # $1=addir
    local d="$1"
    if [[ -r "$d/computers/nxc_computers.txt" ]]; then
        awk '/^SMB[[:space:]]/ && $5 ~ /\$$/ { sub(/\$$/, "", $5); print $5 }' "$d/computers/nxc_computers.txt"
    fi
    if [[ -r "$d/computers/all_computers.txt" ]]; then
        awk -F': ' '/^dNSHostName:/ { print $2 }' "$d/computers/all_computers.txt"
        grep -oP 'user:\[\K[^\]]+' "$d/computers/all_computers.txt" 2>/dev/null | sed 's/\$$//'
    fi
}

#------------------------------------------------------------------------------
# PER-TARGET NORMALIZE
#------------------------------------------------------------------------------
orient_one() {  # $1=ip
    local ip="$1"
    local td="$TOOLKIT_ROOT/targets/$ip"
    info "orient ${BOLD}${ip}${NC}"

    # --- recon/nmap.txt (os_guess + services) — verbatim copy ---
    local nmap_src="$TOOLKIT_ROOT/recon/$ip/scans/nmap_tcp.nmap"
    [[ -r "$nmap_src" ]] && emit_to "$td/recon/nmap.txt" < "$nmap_src"

    # --- recon/smb.txt (smb_share) — verbatim smbclient + normalized nxc/smbmap ---
    local smbdir="$TOOLKIT_ROOT/recon/$ip/tcp/smb"
    if [[ -d "$smbdir" ]]; then
        emit_to "$td/recon/smb.txt" <<< "$(orient_smb_stream "$smbdir" | sort -u)"
    fi

    # --- web/feroxbuster.txt + web/vhosts.txt (web_path + web_vhost) ---
    local -a webdirs=()
    mapfile -t webdirs < <(orient_match_webdirs "$ip")
    if [[ ${#webdirs[@]} -gt 0 ]]; then
        emit_to "$td/web/feroxbuster.txt" <<< "$(orient_web_paths_stream "${webdirs[@]}")"
        local vh; vh="$(orient_web_vhosts_stream "${webdirs[@]}")"
        [[ -n "$vh" ]] && emit_to "$td/web/vhosts.txt" <<< "$vh"
    fi

    # --- ad/users.txt + ad/computers.txt + global ad/domain.txt, ad/dc.txt ---
    if [[ -n "$DOMAIN" ]]; then
        local addir="$TOOLKIT_ROOT/ad/$DOMAIN" comp
        if [[ -d "$addir" ]]; then
            [[ -r "$addir/users/all_users.txt" ]] && emit_to "$td/ad/users.txt" < "$addir/users/all_users.txt"
            comp="$(orient_ad_computers_stream "$addir" | sort -u)"
            [[ -n "$comp" ]] && emit_to "$td/ad/computers.txt" <<< "$comp"
            emit_to "$TOOLKIT_ROOT/ad/domain.txt" <<< "$DOMAIN"
            emit_to "$TOOLKIT_ROOT/ad/dc.txt"     <<< "$ip"
        else
            warn "$ip: --domain '$DOMAIN' but $addir not found — skipping AD rows"
        fi
    fi
}

# IP-keyed targets under recon/ (dir names) + web/ (host part), IP-shaped only.
orient_discover_ips() {
    {
        [[ -d "$TOOLKIT_ROOT/recon" ]] && find "$TOOLKIT_ROOT/recon" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null
        if [[ -d "$TOOLKIT_ROOT/web" ]]; then
            local dir base
            for dir in "$TOOLKIT_ROOT"/web/*/; do
                [[ -d "$dir" ]] || continue
                base="$(basename "$dir")"
                [[ "$base" =~ ^(.+)_([0-9]+)_(https?)$ ]] && printf '%s\n' "${BASH_REMATCH[1]}"
            done
        fi
    } | grep -E "$IP_RE" | sort -u
}

#------------------------------------------------------------------------------
# DISPATCH
#------------------------------------------------------------------------------
if $ALL; then
    declare -a IPS=()
    mapfile -t IPS < <(orient_discover_ips)
    if [[ ${#IPS[@]} -eq 0 ]]; then
        warn "no IP-keyed targets found under $TOOLKIT_ROOT/{recon,web}"; exit 0
    fi
    for ip in "${IPS[@]}"; do orient_one "$ip"; done
    info "oriented ${#IPS[@]} target(s)"
else
    orient_one "$TARGET"
fi

if $DRY_RUN; then
    info "[dry-run] complete — no files changed"
else
    info "orient complete — ${WROTE} file(s) written"
fi
exit 0
