#!/usr/bin/env bash
#==============================================================================
# tests/test_stuckr_demo.sh — populated-mock demo for stuckr.sh
#==============================================================================
# Builds a populated $TOOLKIT_ROOT covering all four spec demo cases:
#   A) target with no enumeration         (§9 case A fallback)
#   B) target with services no sentinels  (§7 broad-category fallback)
#   C) target with sentinels + tried slugs (§6 main path)
#   D) target matching §9 case B           (state present but no map match)
#==============================================================================

set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STUCKR="$HERE/../stuckr.sh"

TMP=$(mktemp -d -t stuckr-demo-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export TOOLKIT_ROOT="$TMP"

#------------------------------------------------------------------------------
# A) 10.10.11.10  — no enumeration data
#------------------------------------------------------------------------------
mkdir -p "$TMP/targets/10.10.11.10"

#------------------------------------------------------------------------------
# B) 10.10.11.20  — services only, no sentinels
#------------------------------------------------------------------------------
T_B=10.10.11.20
mkdir -p "$TMP/targets/$T_B/recon"
cat > "$TMP/targets/$T_B/recon/nmap.txt" <<'EOF'
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.4p1
80/tcp   open  http          Apache httpd 2.4.51
445/tcp  open  microsoft-ds  Samba 4.10.0
OS details: Linux 5.4 - 5.10
Running: Linux 5.X
EOF

#------------------------------------------------------------------------------
# C) 10.10.11.42  — sentinels + tried slugs (main §6 path)
#------------------------------------------------------------------------------
T_C=10.10.11.42
mkdir -p "$TMP/targets/$T_C/"{recon,web,evidence,state}
cat > "$TMP/targets/$T_C/recon/nmap.txt" <<'EOF'
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.4p1
80/tcp   open  http          Apache httpd 2.4.51
139/tcp  open  netbios-ssn   Samba smbd
445/tcp  open  microsoft-ds  Samba 4.10.0
3268/tcp open  ldap
OS details: Linux 5.4 - 5.10
Running: Linux 5.X
EOF
cat > "$TMP/targets/$T_C/web/feroxbuster.txt" <<'EOF'
200 GET 120l 45w 1234c http://10.10.11.42/login
200 GET 80l  30w 900c  http://10.10.11.42/admin
EOF
# Already tried web-feroxbuster sweep + smb anon listing; pretend operator has
# foothold from web (so foothold=yes), no privesc yet.
echo "flag-xyz" > "$TMP/targets/$T_C/evidence/local.txt"
cat > "$TMP/targets/$T_C/state/sentinels.log" <<'EOF'
2026-05-20T14:33:12 smb-no-anon
2026-05-20T14:35:01 web-no-vhosts
2026-05-20T14:36:44 web-no-params
EOF
cat > "$TMP/targets/$T_C/state/next_steps.txt" <<'EOF'
[x] web-feroxbuster-common
[x] smb-anon-listing
[x] re-web-vhost-enumeration
[x] re-web-nikto-scan
[x] web-tech-fingerprint
EOF

#------------------------------------------------------------------------------
# D) 10.10.11.99  — services with no symptom-map or category match
#------------------------------------------------------------------------------
T_D=10.10.11.99
mkdir -p "$TMP/targets/$T_D/recon"
cat > "$TMP/targets/$T_D/recon/nmap.txt" <<'EOF'
PORT     STATE SERVICE         VERSION
8080/tcp open  unknown         Quirky proprietary banner
9999/tcp open  unknown
EOF

#------------------------------------------------------------------------------
# Global state — credentials, domain, dc_ip (for C's preconditions)
#------------------------------------------------------------------------------
# Authoritative creds.txt (6-field pipe schema), read back as cred=USER:CRED.
mkdir -p "$TMP/ad"
cat > "$TMP/creds.txt" <<'EOF'
2026-05-20 16:00:00 | exploit | - | jdoe | Summer2026! | via-targetcheckr
EOF
echo "corp.local" > "$TMP/ad/domain.txt"
echo "10.10.11.5" > "$TMP/ad/dc.txt"

#------------------------------------------------------------------------------
# Run all four
#------------------------------------------------------------------------------
banner() { printf '\n\n%s\n  %s\n%s\n' "════════════════════════════════════════════════════════════" "$*" "════════════════════════════════════════════════════════════"; }

banner "DEMO A: empty target (§9 case A — no enumeration)"
"$STUCKR" --on 10.10.11.10

banner "DEMO B: services but no sentinels (§7 broad-category fallback)"
"$STUCKR" --on "$T_B"

banner "DEMO C: sentinels + tried slugs (§6 main path)"
"$STUCKR" --on "$T_C"

banner "DEMO D: services with no map / category match (§9 case B)"
"$STUCKR" --on "$T_D"
