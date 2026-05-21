#!/usr/bin/env bash
#==============================================================================
# tests/test_orient_demo.sh — orient.sh behavior cases (spec §2 coverage)
#==============================================================================
# Builds synthetic collection-layer fixtures under a temp TOOLKIT_ROOT, runs
# orient.sh, then asserts through the REAL lib/state.sh reader (state_read_target
# / state_read_global) — the same contract the decision tools consume.
#
#   A os_guess + services      nmap_tcp.nmap verbatim → linux + port tuples
#   B smb_share (⚠4)           smbclient + netexec(+junk) + smbmap → real shares only
#   C web_path  (⚠2)           ffuf has_input (FUZZ+URL) rows → extracted paths
#   D web_path empty (⚠2)      wildcard header-only file → file written, 0 paths
#   E web_vhost (⚠3)           hosts_entries.txt → bare field-2 hostnames
#   F ad_user   (⚠5)           all_users.txt bare → copy verbatim (no rpcclient awk)
#   G ad_computer (⚠6)         nxc --computers ($-suffix) → bare hostnames, no banner
#   H global domain/dc_ip      --domain writes ad/{domain,dc}.txt → state_read_global
#   I --web-host               hostname-keyed web/ dir associated to the IP
#   J --dry-run                writes nothing
#   K idempotency              two runs → byte-identical reader output
#   L --all                    discovers IP-keyed targets, normalizes each
#==============================================================================
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ORIENT="$HERE/../orient.sh"
STATE="$HERE/../lib/state.sh"
TMP=$(mktemp -d -t orient-demo-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export NO_COLOR=1

PASS=0; FAIL=0
pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
eq()   { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2' want '$3')"; fi; }

run_orient() { TOOLKIT_ROOT="$1" bash "$ORIENT" "${@:2}" >/dev/null 2>&1; }
# Each reader call runs in its own subshell so TOOLKIT_ROOT stays test-local — the
# subshell-scoping shellcheck flags is the intended isolation, not a bug.
# shellcheck disable=SC1090,SC2030,SC2031
srt() { ( export TOOLKIT_ROOT="$1"; source "$STATE"; state_read_target "$2" ); }
# shellcheck disable=SC1090,SC2030,SC2031
srg() { ( export TOOLKIT_ROOT="$1"; source "$STATE"; state_read_global ); }
hasx() { grep -qxF "$2" <<<"$1" && echo 1 || echo 0; }          # exact line present
nmatch(){ grep -cE "$2" <<<"$1"; }                              # count matching lines

ffrow() { printf '%-30s %-40s | %6s | %8s | %6s | %5s\n' "$1" "$2" "$3" "$4" "$5" "$6"; }

mk_nmap() {  # $1=recon-target-dir
    mkdir -p "$1/scans"
    cat > "$1/scans/nmap_tcp.nmap" <<'EOF'
Nmap scan report for 10.10.10.10
22/tcp   open  ssh          OpenSSH 8.4p1
80/tcp   open  http         Apache httpd 2.4.41
445/tcp  open  microsoft-ds Samba smbd 4.9.5
Running: Linux 5.X
OS details: Linux 5.4
EOF
}

mk_smb() {  # $1=recon-target-dir ; netexec deliberately carries status/header junk (⚠4)
    mkdir -p "$1/tcp/smb"
    printf '\tSharename       Type      Comment\n\t---------       ----      -------\n\tprint$          Disk      Printer Drivers\n\tIPC$            IPC       IPC Service\n' \
        > "$1/tcp/smb/smbclient_list.txt"
    {
        printf 'SMB  10.10.10.10  445  HOST  [*] Windows 10\n'
        printf 'SMB  10.10.10.10  445  HOST  [+] authenticated\n'
        printf 'SMB  10.10.10.10  445  HOST  Share           Permissions     Remark\n'
        printf 'SMB  10.10.10.10  445  HOST  -----           -----------     ------\n'
        printf 'SMB  10.10.10.10  445  HOST  print$                          Printer Drivers\n'
        printf 'SMB  10.10.10.10  445  HOST  backups         READ            Backups\n'
    } > "$1/tcp/smb/netexec_shares.txt"
    printf '[+] IP: 10.10.10.10:445\tName: x\n\tDisk\tPermissions\tComment\n\t----\t-----------\t-------\n\tbackups\tREAD ONLY\tBackups\n' \
        > "$1/tcp/smb/smbmap_null.txt"
}

mk_web() {  # $1=root $2=webdir-basename (host_port_proto) ; non-empty has_input rows
    local c="$1/web/$2/artifacts/content"; mkdir -p "$c"
    { ffrow FUZZ URL Status Size Words Lines; printf -- '------------\n';
      ffrow admin   "http://10.10.10.10:80/admin"    200 100 5 2;
      ffrow uploads "http://10.10.10.10:80/uploads/" 301 0   0 0; } > "$c/dirs_medium.txt"
    : > "$c/files_medium.txt"
}

mk_vhosts() {  # $1=root $2=webdir-basename
    local v="$1/web/$2/artifacts/vhosts"; mkdir -p "$v"
    printf '  10.10.10.10  staging.corp.com\n  10.10.10.10  dev.corp.com\n' > "$v/hosts_entries.txt"
}

mk_ad() {  # $1=root $2=domain ; nxc --computers carries the [*] banner (⚠6)
    local a="$1/ad/$2"; mkdir -p "$a/users" "$a/computers"
    printf 'administrator\njdoe\nsvc_sql\n' > "$a/users/all_users.txt"
    { printf 'SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:%s)\n' "$2";
      printf 'SMB  10.10.10.5  445  DC01  DC01$\n';
      printf 'SMB  10.10.10.5  445  DC01  WS01$\n';
      printf 'SMB  10.10.10.5  445  DC01  FILE01$\n'; } > "$a/computers/nxc_computers.txt"
}

#------------------------------------------------------------------------------
echo "=== A: os_guess + services (nmap_tcp.nmap verbatim) ==="
R="$TMP/A"; mk_nmap "$R/recon/10.10.10.10"
run_orient "$R" 10.10.10.10
S=$(srt "$R" 10.10.10.10)
eq "A os_guess linux"          "$(hasx "$S" 'os_guess=linux')" 1
eq "A service 22/ssh"          "$(hasx "$S" 'service=22/tcp/ssh')" 1
eq "A service 445/microsoft-ds" "$(hasx "$S" 'service=445/tcp/microsoft-ds')" 1

echo "=== B: smb_share — real shares only, no header/status leak (⚠4) ==="
R="$TMP/B"; mk_smb "$R/recon/10.10.10.10"
run_orient "$R" 10.10.10.10
S=$(srt "$R" 10.10.10.10)
eq "B smb_share print\$"  "$(hasx "$S" 'smb_share=print$')" 1
eq "B smb_share IPC\$"    "$(hasx "$S" 'smb_share=IPC$')" 1
eq "B smb_share backups"  "$(hasx "$S" 'smb_share=backups')" 1
eq "B no 'Share' header leak"   "$(hasx "$S" 'smb_share=Share')" 0
eq "B no '[*]' status leak"     "$(nmatch "$S" 'smb_share=\[')" 0

echo "=== C: web_path — ffuf has_input (FUZZ+URL) rows extracted (⚠2) ==="
R="$TMP/C"; mk_web "$R" 10.10.10.10_80_http
run_orient "$R" 10.10.10.10
S=$(srt "$R" 10.10.10.10)
eq "C web_path /admin"    "$(hasx "$S" 'web_path=/admin')" 1
eq "C web_path /uploads/" "$(hasx "$S" 'web_path=/uploads/')" 1
eq "C no FUZZ/URL header leak" "$(nmatch "$S" 'web_path=(/FUZZ|/URL|web_path=$)')" 0

echo "=== D: web_path empty — wildcard header-only → file written, 0 paths (⚠2) ==="
R="$TMP/D"; c="$R/web/10.10.10.10_80_http/artifacts/content"; mkdir -p "$c"
{ ffrow FUZZ URL Status Size Words Lines; printf -- '------------\n'; } > "$c/dirs_medium.txt"
: > "$c/files_medium.txt"
run_orient "$R" 10.10.10.10
eq "D feroxbuster.txt written" "$([[ -f "$R/targets/10.10.10.10/web/feroxbuster.txt" ]] && echo 1 || echo 0)" 1
eq "D zero web_path"           "$(nmatch "$(srt "$R" 10.10.10.10)" '^web_path=')" 0

echo "=== E: web_vhost — bare field-2 hostnames, no IP (⚠3) ==="
R="$TMP/E"; mk_web "$R" 10.10.10.10_80_http; mk_vhosts "$R" 10.10.10.10_80_http
run_orient "$R" 10.10.10.10
S=$(srt "$R" 10.10.10.10)
eq "E web_vhost staging"  "$(hasx "$S" 'web_vhost=staging.corp.com')" 1
eq "E web_vhost dev"      "$(hasx "$S" 'web_vhost=dev.corp.com')" 1
eq "E no IP as vhost"     "$(hasx "$S" 'web_vhost=10.10.10.10')" 0

echo "=== F: ad_user — all_users.txt copy verbatim (⚠5) ==="
R="$TMP/F"; mk_ad "$R" corp.com
run_orient "$R" 10.10.10.5 --domain corp.com
S=$(srt "$R" 10.10.10.5)
eq "F ad_user administrator" "$(hasx "$S" 'ad_user=administrator')" 1
eq "F ad_user svc_sql"       "$(hasx "$S" 'ad_user=svc_sql')" 1

echo "=== G: ad_computer — nxc \$-suffix machine accounts, no banner (⚠6) ==="
R="$TMP/G"; mk_ad "$R" corp.com
run_orient "$R" 10.10.10.5 --domain corp.com
S=$(srt "$R" 10.10.10.5)
eq "G ad_computer DC01"  "$(hasx "$S" 'ad_computer=DC01')" 1
eq "G ad_computer WS01"  "$(hasx "$S" 'ad_computer=WS01')" 1
eq "G ad_computer FILE01" "$(hasx "$S" 'ad_computer=FILE01')" 1
eq "G no 'SMB' as computer"    "$(hasx "$S" 'ad_computer=SMB')" 0
eq "G no trailing-\$ leak"      "$(nmatch "$S" 'ad_computer=.*\$')" 0

echo "=== H: global domain/dc_ip from --domain ==="
R="$TMP/H"; mk_ad "$R" corp.com
run_orient "$R" 10.10.10.5 --domain corp.com
G=$(srg "$R")
eq "H domain=corp.com" "$(hasx "$G" 'domain=corp.com')" 1
eq "H dc_ip=10.10.10.5" "$(hasx "$G" 'dc_ip=10.10.10.5')" 1

echo "=== I: --web-host associates a hostname-keyed web/ dir ==="
R="$TMP/I"; mk_web "$R" shop.corp.com_80_http
run_orient "$R" 10.10.10.10 --web-host shop.corp.com
S=$(srt "$R" 10.10.10.10)
eq "I web_path via --web-host" "$(hasx "$S" 'web_path=/admin')" 1
# without --web-host the hostname dir must NOT be picked up
R2="$TMP/I2"; mk_web "$R2" shop.corp.com_80_http
run_orient "$R2" 10.10.10.10
eq "I no leak without --web-host" "$(nmatch "$(srt "$R2" 10.10.10.10)" '^web_path=')" 0

echo "=== J: --dry-run writes nothing ==="
R="$TMP/J"; mk_nmap "$R/recon/10.10.10.10"; mk_smb "$R/recon/10.10.10.10"
run_orient "$R" 10.10.10.10 --dry-run
eq "J no targets/ created" "$([[ -e "$R/targets/10.10.10.10" ]] && echo 1 || echo 0)" 0

echo "=== K: idempotency — two runs → identical reader output ==="
R="$TMP/K"; mk_nmap "$R/recon/10.10.10.10"; mk_smb "$R/recon/10.10.10.10"; mk_web "$R" 10.10.10.10_80_http
run_orient "$R" 10.10.10.10; one=$(srt "$R" 10.10.10.10)
run_orient "$R" 10.10.10.10; two=$(srt "$R" 10.10.10.10)
eq "K second run identical" "$([[ "$one" == "$two" ]] && echo 1 || echo 0)" 1

echo "=== L: --all discovers and normalizes every IP-keyed target ==="
R="$TMP/L"; mk_nmap "$R/recon/10.10.10.10"; mk_nmap "$R/recon/10.10.10.20"
run_orient "$R" --all
eq "L .10 normalized" "$(hasx "$(srt "$R" 10.10.10.10)" 'os_guess=linux')" 1
eq "L .20 normalized" "$(hasx "$(srt "$R" 10.10.10.20)" 'os_guess=linux')" 1

#------------------------------------------------------------------------------
echo
echo "==============================================================="
echo "  PASS: $PASS    FAIL: $FAIL"
echo "==============================================================="
[[ $FAIL -eq 0 ]] || exit 1
exit 0
