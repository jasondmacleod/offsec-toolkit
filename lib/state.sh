#!/usr/bin/env bash
#==============================================================================
# lib/state.sh — Shared state reader for the OffSec toolkit
#==============================================================================
# Sourced, not executed. First consumer: stuckr.sh. Future consumers:
# orient.sh, timekeeper.sh, watchdog.sh.
#
# PUBLIC API
#   state_read_target <ip>            emit per-target state vector (stdout)
#   state_read_global                 emit global state vector (stdout)
#   state_emit_empty <ip> <key>       append sentinel to target log
#   state_list_targets                one ip per line, from $TOOLKIT_ROOT/targets/
#
# OUTPUT FORMAT (key=value, one per line, repeated keys = list items)
#   ip=10.10.11.42
#   os_guess=linux
#   foothold=no
#   privesc=no
#   services=22/tcp/ssh 80/tcp/http 445/tcp/microsoft-ds
#   service=22/tcp/ssh                 (singular, repeated, for easy loops)
#   service=80/tcp/http
#   web_path=/login
#   web_path=/admin
#   web_vhost=staging.corp.com
#   smb_share=ADMIN$
#   ad_user=jdoe
#   ad_computer=DC01
#   sentinel=smb-no-anon
#   tried_slug=web-feroxbuster-common
#
# Global:
#   cred=jdoe:Summer2026!
#   domain=corp.com
#   dc_ip=10.10.10.5
#
# DESIGN
#   - Plain text state files only. No JSON. Parse with grep/awk.
#   - Missing files → empty field, not error. Empty is a valid state.
#   - Reader is read-only EXCEPT state_emit_empty (append to sentinels.log).
#   - Idempotent: safe to call repeatedly. No caching, no side effects.
#==============================================================================

# Guard: only define once.
if [[ -n "${_STATE_SH_LOADED:-}" ]]; then return 0; fi
_STATE_SH_LOADED=1

TOOLKIT_ROOT="${TOOLKIT_ROOT:-$HOME/toolkit}"

#------------------------------------------------------------------------------
# Path helpers
#------------------------------------------------------------------------------
_state_target_dir() { printf '%s/targets/%s' "$TOOLKIT_ROOT" "$1"; }
_state_global_dir() { printf '%s' "$TOOLKIT_ROOT"; }

#------------------------------------------------------------------------------
# Field parsers (each takes the source file path; emits value(s) to stdout)
#------------------------------------------------------------------------------

# Parse nmap tabular output for open ports.
# Matches lines like:  22/tcp   open  ssh     OpenSSH 8.4p1
# Returns:             22/tcp/ssh
_state_parse_services() {
    local f="$1"
    [[ -r "$f" ]] || return 0
    awk '
        /^[0-9]+\/(tcp|udp)[[:space:]]+open[[:space:]]+/ {
            split($1, a, "/")
            svc = $3
            if (svc == "") svc = "unknown"
            print a[1] "/" a[2] "/" svc
        }
    ' "$f"
}

# Parse OS guess from nmap output. Look at "OS details:" and "Running:" lines.
# Returns: linux | windows | unknown
_state_parse_os() {
    local f="$1"
    [[ -r "$f" ]] || { echo unknown; return; }
    local hits
    hits=$(grep -hE '^(OS details:|Running:|OS:|Service Info:.*OS)' "$f" 2>/dev/null)
    if   echo "$hits" | grep -qiE 'windows|microsoft'; then echo windows
    elif echo "$hits" | grep -qiE 'linux|unix|bsd|debian|ubuntu'; then echo linux
    else echo unknown
    fi
}

# Parse web-content lines from feroxbuster/gobuster output.
# Feroxbuster line:  200      GET      120l   45w   1234c http://host/login
# Gobuster line:     /login                (Status: 200) [Size: 1234]
# Emits one path per line, no scheme/host. Sorted+deduped by caller.
_state_parse_web_paths() {
    local f="$1"
    [[ -r "$f" ]] || return 0
    awk '
        # feroxbuster: extract path from a full URL in the line
        match($0, /https?:\/\/[^[:space:]]+/) {
            url = substr($0, RSTART, RLENGTH)
            sub(/^https?:\/\/[^\/]+/, "", url)
            if (url == "") url = "/"
            print url
            next
        }
        # gobuster: line starts with / (path), optional whitespace then status
        /^[[:space:]]*\// {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^\//) { print $i; next }
            }
        }
    ' "$f"
}

# Emit slug-shaped tokens (kebab-case identifiers) from next_steps.txt.
# A slug = ^[a-z][a-z0-9-]*$ length >= 4 with at least one dash.
# Lines may have leading [ ]/[x]/numbering — we scan tokens.
_state_parse_tried_slugs() {
    local f="$1"
    [[ -r "$f" ]] || return 0
    grep -ohE '\b[a-z][a-z0-9]*(-[a-z0-9]+){1,}\b' "$f" 2>/dev/null
}

# Extract sentinel key from sentinels.log lines:
#   <ISO timestamp> <key>
# We take field 2. Caller does not dedupe (ranker handles it).
_state_parse_sentinels() {
    local f="$1"
    [[ -r "$f" ]] || return 0
    awk 'NF >= 2 { print $2 }' "$f"
}

# Non-empty, non-comment lines, trimmed.
_state_parse_lines() {
    local f="$1"
    [[ -r "$f" ]] || return 0
    grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

# Parse SMB share names from either a clean newline-list or raw
# smbclient/nxc output containing a `Sharename Type Comment` table.
_state_parse_smb_shares() {
    local f="$1"
    [[ -r "$f" ]] || return 0
    awk '
        # smbclient table row: <name>  Disk|IPC|Printer ...
        /^[[:space:]]*[A-Za-z0-9_.$-]+[[:space:]]+(Disk|IPC|Printer)([[:space:]]|$)/ {
            sub(/^[[:space:]]+/, ""); print $1; next
        }
        # bare share name on its own line (no whitespace, no leading symbol)
        /^[A-Za-z0-9_.$-]+$/ { print; next }
    ' "$f" \
    | grep -vE '^(Sharename|Type|Comment|---+)$' \
    | sort -u
}

#------------------------------------------------------------------------------
# Public API
#------------------------------------------------------------------------------

# state_read_target <ip>
state_read_target() {
    local ip="$1"
    [[ -n "$ip" ]] || { echo "state_read_target: missing ip" >&2; return 2; }

    local td; td=$(_state_target_dir "$ip")
    local nmap_f="$td/recon/nmap.txt"
    local smb_f="$td/recon/smb.txt"
    local fx_f="$td/web/feroxbuster.txt"
    local gb_f="$td/web/gobuster.txt"
    local vh_f="$td/web/vhosts.txt"
    local au_f="$td/ad/users.txt"
    local ac_f="$td/ad/computers.txt"
    local local_f="$td/evidence/local.txt"
    local proof_f="$td/evidence/proof.txt"
    local sent_f="$td/state/sentinels.log"
    local steps_f="$td/state/next_steps.txt"

    echo "ip=$ip"
    echo "os_guess=$(_state_parse_os "$nmap_f")"
    [[ -s "$local_f" ]] && echo "foothold=yes" || echo "foothold=no"
    [[ -s "$proof_f" ]] && echo "privesc=yes"  || echo "privesc=no"

    # services: emit both the aggregate (space-sep tuples) and per-item lines.
    local svc_list svc
    svc_list=$(_state_parse_services "$nmap_f" | tr '\n' ' ' | sed 's/[[:space:]]*$//')
    echo "services=$svc_list"
    if [[ -n "$svc_list" ]]; then
        for svc in $svc_list; do echo "service=$svc"; done
    fi

    # web_paths: dedupe + sort
    local p
    while IFS= read -r p; do [[ -n "$p" ]] && echo "web_path=$p"; done < <(
        { _state_parse_web_paths "$fx_f"; _state_parse_web_paths "$gb_f"; } \
            | sort -u
    )

    # web_vhosts: dedupe
    while IFS= read -r p; do [[ -n "$p" ]] && echo "web_vhost=$p"; done < <(
        _state_parse_lines "$vh_f" | sort -u
    )

    # smb_shares: parse smbclient/nxc table or bare-list, deduped
    while IFS= read -r p; do [[ -n "$p" ]] && echo "smb_share=$p"; done < <(
        _state_parse_smb_shares "$smb_f"
    )

    # ad_users / ad_computers
    while IFS= read -r p; do [[ -n "$p" ]] && echo "ad_user=$p"; done < <(
        _state_parse_lines "$au_f" | sort -u
    )
    while IFS= read -r p; do [[ -n "$p" ]] && echo "ad_computer=$p"; done < <(
        _state_parse_lines "$ac_f" | sort -u
    )

    # sentinels: NOT sorted/deduped at the read layer — ranker handles it.
    # Order preserved (oldest first) for any downstream "newest first" caller.
    _state_parse_sentinels "$sent_f" | while IFS= read -r p; do
        [[ -n "$p" ]] && echo "sentinel=$p"
    done

    # tried_slugs: dedupe
    _state_parse_tried_slugs "$steps_f" | sort -u | while IFS= read -r p; do
        [[ -n "$p" ]] && echo "tried_slug=$p"
    done
}

# state_read_global
state_read_global() {
    local gd; gd=$(_state_global_dir)
    local creds_f="$gd/creds/creds.txt"
    local dom_f="$gd/ad/domain.txt"
    local dc_f="$gd/ad/dc.txt"

    _state_parse_lines "$creds_f" | while IFS= read -r p; do
        [[ -n "$p" ]] && echo "cred=$p"
    done

    if [[ -r "$dom_f" ]]; then
        local d; d=$(_state_parse_lines "$dom_f" | head -1)
        [[ -n "$d" ]] && echo "domain=$d"
    fi
    if [[ -r "$dc_f" ]]; then
        local d; d=$(_state_parse_lines "$dc_f" | head -1)
        [[ -n "$d" ]] && echo "dc_ip=$d"
    fi
}

# state_emit_empty <ip> <symptom-key>
state_emit_empty() {
    local ip="$1" key="$2"
    [[ -n "$ip" && -n "$key" ]] || {
        echo "state_emit_empty: usage: state_emit_empty <ip> <symptom-key>" >&2
        return 2
    }
    local td; td=$(_state_target_dir "$ip")
    local logf="$td/state/sentinels.log"
    mkdir -p "$td/state" || return 1
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S)" "$key" >> "$logf"
}

# state_list_targets
state_list_targets() {
    local root="$TOOLKIT_ROOT/targets"
    [[ -d "$root" ]] || return 0
    find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort
}

#------------------------------------------------------------------------------
# WRITE API (targetcheckr.sh additions per its design spec §5)
#
# Three append-only writers. Each is idempotent on the dimensions named in
# the spec. Atomic on POSIX append for the line sizes we emit (well under
# PIPE_BUF, typically <200 bytes).
#
# Source-of-truth conventions (env-overridable, defaults sane for the only
# current caller, targetcheckr.sh):
#   STATE_WRITE_SOURCE   tool name embedded as the foothold log's 4th field
#                        (default: targetcheckr)
#   STATE_WRITE_PROTO    proto column for creds.txt (default: exploit)
#   STATE_WRITE_HOST     host column for creds.txt (default: -)
#   STATE_WRITE_NOTE     note column for creds.txt (default: via-targetcheckr)
#------------------------------------------------------------------------------

# state_write_foothold <ip> <user> <method>
# Append a foothold event to targets/<ip>/state/foothold.log.
# Line format: <ISO timestamp> <user> <method> <source-tool>
# Idempotent at READ time (reader collapses by (user, method)); the writer
# always appends so the file serves as an audit trail.
state_write_foothold() {
    local ip="$1" user="$2" method="$3"
    [[ -n "$ip" && -n "$user" && -n "$method" ]] || {
        echo "state_write_foothold: usage: state_write_foothold <ip> <user> <method>" >&2
        return 2
    }
    local src="${STATE_WRITE_SOURCE:-targetcheckr}"
    local td; td=$(_state_target_dir "$ip")
    local logf="$td/state/foothold.log"
    mkdir -p "$td/state" || return 1
    printf '%s %s %s %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%S)" "$user" "$method" "$src" >> "$logf"
}

# state_append_cred <user-pass-or-hash>
#
# AUTHORITATIVE CONTRACT (locked 2026-05-20, supersedes targetcheckr spec §5
# placeholder `creds/creds.txt`):
#   path     = $TOOLKIT_ROOT/creds.txt          (NOT $TOOLKIT_ROOT/creds/creds.txt)
#   schema   = TIMESTAMP | PROTO | HOST | USER | CRED | NOTE   (6 fields, pipe-separated)
#   dedupe   = (USER, CRED) tuple across the entire file (timestamps always differ)
#   readers  = sprayr.sh::parse_creds_file (awk -F'|', fields 4/5/6)
#   writers  = adr / sprayr / crackr / startr / targetcheckr
# Future tools (watchdog / livefetch / proofr) MUST use this function rather
# than rolling their own append — the schema, padding, and dedupe rule are
# co-evolved across the toolkit; bypassing the API breaks `sprayr --from-creds`.
#
# Append a credential to $TOOLKIT_ROOT/creds.txt. The single positional arg is
# `user:cred`, `domain/user:cred`, or any variant whose first `:` separates
# the user side from the cred side. Returns 0 on append, 0 (silent) on
# dedupe-skip, 2 on malformed input.
state_append_cred() {
    local raw="$1"
    [[ -n "$raw" ]] || {
        echo "state_append_cred: usage: state_append_cred <user-pass-or-hash>" >&2
        return 2
    }
    if [[ "$raw" != *:* ]] || [[ "$raw" == :* ]]; then
        echo "state_append_cred: malformed cred (expected user:cred): $raw" >&2
        return 2
    fi
    local user="${raw%%:*}"
    local cred="${raw#*:}"
    [[ -n "$user" && -n "$cred" ]] || {
        echo "state_append_cred: malformed cred (empty user or cred): $raw" >&2
        return 2
    }

    local creds_file="${TOOLKIT_ROOT}/creds.txt"
    mkdir -p "$(dirname "$creds_file")" 2>/dev/null || return 1

    # Dedupe by (user, cred) tuple — same parse used by sprayr's
    # parse_creds_file. Whitespace-trim both sides before compare.
    if [[ -f "$creds_file" ]]; then
        if awk -F'|' -v u="$user" -v c="$cred" '
            NF >= 6 {
                fu = $4; gsub(/^[[:space:]]+|[[:space:]]+$/, "", fu)
                fc = $5; gsub(/^[[:space:]]+|[[:space:]]+$/, "", fc)
                if (fu == u && fc == c) { found = 1; exit }
            }
            END { exit (found ? 0 : 1) }
        ' "$creds_file" 2>/dev/null; then
            return 0  # silent dedupe-skip
        fi
    fi

    local proto="${STATE_WRITE_PROTO:-exploit}"
    local host="${STATE_WRITE_HOST:--}"
    local note="${STATE_WRITE_NOTE:-via-targetcheckr}"
    printf '%s | %-8s | %-15s | %-20s | %s | %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$proto" "$host" "$user" "$cred" "$note" \
        >> "$creds_file"
}

# state_write_event <ip> <key>
# Append a success-side event to targets/<ip>/state/sentinels.log. Same file
# as state_emit_empty; different key namespace (positive: `success-…`).
# Dedupe: skip if the same (ip, key) appears within the last 60 seconds.
state_write_event() {
    local ip="$1" key="$2"
    [[ -n "$ip" && -n "$key" ]] || {
        echo "state_write_event: usage: state_write_event <ip> <key>" >&2
        return 2
    }
    local td; td=$(_state_target_dir "$ip")
    local logf="$td/state/sentinels.log"
    mkdir -p "$td/state" || return 1

    # 60-second (ip, key) window — secondary dedupe per targetcheckr §8.
    # date -d on an ISO-8601 'Z' (UTC) timestamp returns the correct epoch.
    if [[ -f "$logf" ]]; then
        local now_ep; now_ep=$(date -u +%s)
        local recent
        recent=$(awk -v k="$key" '$2 == k { print $1 }' "$logf" | tail -1)
        if [[ -n "$recent" ]]; then
            local then_ep
            then_ep=$(date -u -d "${recent}Z" +%s 2>/dev/null || echo 0)
            if [[ "$then_ep" -gt 0 ]] && (( now_ep - then_ep < 60 )); then
                return 0  # silent dedupe-skip
            fi
        fi
    fi

    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S)" "$key" >> "$logf"
}
