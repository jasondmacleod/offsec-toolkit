#!/usr/bin/env bash
#==============================================================================
# tests/test_livefetch_demo.sh — livefetch.sh behavior cases (spec coverage)
#==============================================================================
# Drives livefetch.sh against synthetic collection-layer fixtures, using the
# LIVEFETCH_RERUN_CMD hook to simulate a wrapped-script re-run (copy a prepared
# "new" artifact set into the work root) — no real nmap/webenum/adr.
#
#   A snapshot-diff → new port → new-services-found + stale-detected
#   B cascade: upstream delta force-runs fresh downstream  (+ --no-cascade)
#   C tcp-vulnmatch rider → new CVE → new-exploits-found
#   D noise-only change → empty filtered diff → NO sentinel
#   E ssh banner change → delta-detected
#   F --diff-only → live tree + progress.log untouched, no sentinel
#   G adr (cred present) phase2_user_enum → new-users-found
#   H adr (no cred) → skip-with-message, no run
#   I udp-scan non-root → needs-sudo skip
#   J web depth-discipline → propose webenum --from-recon, don't run
#   K from-foothold netstat → new internal listener → new-services-found
#   L idempotency: second run inside --since re-fetches nothing
#==============================================================================
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LF="$HERE/../livefetch.sh"
TMP=$(mktemp -d -t livefetch-demo-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export NO_COLOR=1

PASS=0; FAIL=0
pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
eq()   { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2' want '$3')"; fi; }

# re-run hook: overlay $NEWDATA/<stage>/ onto the work root
HOOK='[ -n "$NEWDATA" ] && [ -d "$NEWDATA/$LF_STAGE" ] && cp -a "$NEWDATA/$LF_STAGE/." "$LF_WORKROOT/" 2>/dev/null; true'

OLD='2026-01-01 00:00:00'      # well past any --since
mkstale() { touch -d "$OLD" "$1"; }

j_n()    { python3 -c 'import json,sys;print(len(json.loads(sys.argv[1]).get("results",[])))' "$1"; }
j_field(){ python3 -c 'import json,sys
d=json.loads(sys.argv[1])
for r in d["results"]:
    if r.get("stage")==sys.argv[2]: print(r.get(sys.argv[3],"")); break' "$1" "$2" "$3"; }
j_key()  { python3 -c 'import json,sys
d=json.loads(sys.argv[1])
for r in d["results"]:
    if r.get("stage")==sys.argv[2]:
        print("1" if sys.argv[3] in r.get("keys",[]) else "0"); break
else: print("0")' "$1" "$2" "$3"; }
j_changed(){ python3 -c 'import json,sys
d=json.loads(sys.argv[1])
for r in d["results"]:
    if r.get("stage")==sys.argv[2]: print("1" if r.get("changed") else "0"); break
else: print("0")' "$1" "$2"; }
j_prop() { python3 -c 'import json,sys
print("1" if any(sys.argv[2] in p for p in json.loads(sys.argv[1]).get("proposals",[])) else "0")' "$1" "$2"; }
sentinel_has() { grep -q "$2" "$1/targets/$3/state/sentinels.log" 2>/dev/null && echo 1 || echo 0; }

# build a recon target with given markers; caller fills artifacts after
mk_recon() {  # $1=root $2=ip ; markers via stdin (one per line)
    local d="$1/recon/$2"; mkdir -p "$d/scans" "$d/tcp" "$d/loot"
    { echo "# progress"; while IFS= read -r m; do
        [[ -n "$m" ]] && printf '2026-04-22 16:00:00 | DONE | %s | x\n' "$m"
      done; } > "$d/progress.log"
    echo "$d"
}
run_lf() { TOOLKIT_ROOT="$1" LIVEFETCH_RERUN_CMD="$HOOK" NEWDATA="$2" \
           bash "$LF" "${@:3}" --json 2>/dev/null; }

PORTROW() { printf '%s/tcp   open  %s   %s\n' "$1" "$2" "$3"; }

#------------------------------------------------------------------------------
echo "=== A: snapshot-diff → new port → new-services-found + stale-detected ==="
R="$TMP/A"; d=$(printf 'rustscan\n' | mk_recon "$R" 10.10.11.5)
printf '22,80\n' > "$d/scans/tcp_ports.txt"; mkstale "$d/scans/tcp_ports.txt"
N="$TMP/A.new"; mkdir -p "$N/tcp-discovery/scans"; printf '22,80,445\n' > "$N/tcp-discovery/scans/tcp_ports.txt"
J=$(run_lf "$R" "$N" --target 10.10.11.5 --stage recon)
eq "A tcp-discovery changed"        "$(j_changed "$J" tcp-discovery)" 1
eq "A new-services-found in result" "$(j_key "$J" tcp-discovery success-livefetch-new-services-found)" 1
eq "A new-services sentinel written" "$(sentinel_has "$R" success-livefetch-new-services-found 10.10.11.5)" 1
eq "A stale-detected sentinel written" "$(sentinel_has "$R" success-livefetch-stale-detected 10.10.11.5)" 1

echo "=== B: cascade force-runs fresh downstream (and --no-cascade does not) ==="
R="$TMP/B"; d=$(printf 'rustscan\nnmap_tcp\n' | mk_recon "$R" 10.10.11.6)
printf '22,80\n' > "$d/scans/tcp_ports.txt"; mkstale "$d/scans/tcp_ports.txt"
PORTROW 22 ssh OpenSSH > "$d/scans/nmap_tcp.nmap"   # FRESH (not stale)
N="$TMP/B.new"; mkdir -p "$N/tcp-discovery/scans" "$N/tcp-services/scans"
printf '22,80,445\n' > "$N/tcp-discovery/scans/tcp_ports.txt"
{ PORTROW 22 ssh OpenSSH; PORTROW 445 microsoft-ds Samba; } > "$N/tcp-services/scans/nmap_tcp.nmap"
J=$(run_lf "$R" "$N" --target 10.10.11.6 --stage recon)
eq "B cascade ran tcp-services"     "$(j_field "$J" tcp-services ran)" True
R2="$TMP/B2"; d=$(printf 'rustscan\nnmap_tcp\n' | mk_recon "$R2" 10.10.11.6)
printf '22,80\n' > "$d/scans/tcp_ports.txt"; mkstale "$d/scans/tcp_ports.txt"
PORTROW 22 ssh OpenSSH > "$d/scans/nmap_tcp.nmap"
J=$(run_lf "$R2" "$N" --target 10.10.11.6 --stage recon --no-cascade)
eq "B --no-cascade skips fresh tcp-services" "$(j_field "$J" tcp-services ran)" ""

echo "=== C: tcp-vulnmatch rider → new CVE → new-exploits-found ==="
R="$TMP/C"; d=$(printf 'nmap_tcp\n' | mk_recon "$R" 10.10.11.7)
PORTROW 8080 http Jetty > "$d/scans/nmap_tcp.nmap"; mkstale "$d/scans/nmap_tcp.nmap"
printf '# none\n' > "$d/loot/vulners_hits.txt"
N="$TMP/C.new"; mkdir -p "$N/tcp-services/scans" "$N/tcp-services/loot"
PORTROW 8080 http Jetty > "$N/tcp-services/scans/nmap_tcp.nmap"
printf 'CVE-2021-34429 Jetty file disclosure\n' > "$N/tcp-services/loot/vulners_hits.txt"
J=$(run_lf "$R" "$N" --target 10.10.11.7 --stage recon)
eq "C tcp-vulnmatch new-exploits-found" "$(j_key "$J" tcp-vulnmatch success-livefetch-new-exploits-found)" 1
eq "C new-exploits sentinel written" "$(sentinel_has "$R" success-livefetch-new-exploits-found 10.10.11.7)" 1

echo "=== D: noise-only change → empty filtered diff → NO sentinel ==="
R="$TMP/D"; d=$(printf 'nmap_tcp\n' | mk_recon "$R" 10.10.11.8)
{ echo "# Nmap 7.99 scan initiated Mon Jan 1 2026"; PORTROW 22 ssh OpenSSH;
  echo "Host is up (0.011s latency)."; } > "$d/scans/nmap_tcp.nmap"; mkstale "$d/scans/nmap_tcp.nmap"
N="$TMP/D.new"; mkdir -p "$N/tcp-services/scans"
{ echo "# Nmap 7.99 scan initiated Tue Feb 2 2026"; PORTROW 22 ssh OpenSSH;
  echo "Host is up (0.450s latency)."; } > "$N/tcp-services/scans/nmap_tcp.nmap"
J=$(run_lf "$R" "$N" --target 10.10.11.8 --stage recon)
eq "D tcp-services no change"     "$(j_changed "$J" tcp-services)" 0
eq "D no new-services sentinel"   "$(sentinel_has "$R" success-livefetch-new-services-found 10.10.11.8)" 0

echo "=== E: ssh banner change → delta-detected ==="
R="$TMP/E"; d=$(printf 'ssh\n' | mk_recon "$R" 10.10.11.9); mkdir -p "$d/tcp/ssh"
printf 'SSH-2.0-OpenSSH_7.9\n' > "$d/tcp/ssh/version_info.txt"; mkstale "$d/tcp/ssh/version_info.txt"
N="$TMP/E.new"; mkdir -p "$N/ssh/tcp/ssh"; printf 'SSH-2.0-OpenSSH_9.2\n' > "$N/ssh/tcp/ssh/version_info.txt"
J=$(run_lf "$R" "$N" --target 10.10.11.9 --stage recon)
eq "E ssh delta-detected" "$(j_key "$J" ssh success-livefetch-delta-detected)" 1

echo "=== F: --diff-only → live tree + marker untouched, no sentinel ==="
R="$TMP/F"; d=$(printf 'rustscan\n' | mk_recon "$R" 10.10.11.10)
printf '22,80\n' > "$d/scans/tcp_ports.txt"; mkstale "$d/scans/tcp_ports.txt"
N="$TMP/F.new"; mkdir -p "$N/tcp-discovery/scans"; printf '22,80,445\n' > "$N/tcp-discovery/scans/tcp_ports.txt"
J=$(run_lf "$R" "$N" --target 10.10.11.10 --stage recon --diff-only)
eq "F diff-only still reports delta" "$(j_changed "$J" tcp-discovery)" 1
eq "F live artifact UNCHANGED"       "$(cat "$d/scans/tcp_ports.txt")" "22,80"
eq "F marker still present"          "$(grep -c 'DONE | rustscan' "$d/progress.log")" 1
eq "F NO sentinel written (read-only)" "$(sentinel_has "$R" success-livefetch 10.10.11.10)" 0

echo "=== G: adr (cred present) phase2_user_enum → new-users-found ==="
R="$TMP/G"; mkdir -p "$R/ad/corp.local/users"
printf '2026-01-01 | exploit | - | jdoe | Summer2026! | x\n' > "$R/creds.txt"
mkdir -p "$R/ad"; printf '10.10.10.5\n' > "$R/ad/dc.txt"; printf 'corp.local\n' > "$R/ad/domain.txt"
printf '# progress\n2026-04-22 16:00:00 | DONE | phase2_user_enum | x\n' > "$R/ad/corp.local/progress.log"
printf 'administrator\njdoe\n' > "$R/ad/corp.local/users/all_users.txt"; mkstale "$R/ad/corp.local/users/all_users.txt"
N="$TMP/G.new"; mkdir -p "$N/phase2_user_enum/users"; printf 'administrator\njdoe\nsvc_sql\n' > "$N/phase2_user_enum/users/all_users.txt"
J=$(run_lf "$R" "$N" --target corp.local --stage ad)
eq "G phase2_user_enum new-users-found" "$(j_key "$J" phase2_user_enum success-livefetch-new-users-found)" 1

echo "=== H: adr (no cred) → skip-with-message, no run ==="
R="$TMP/H"; mkdir -p "$R/ad/corp.local/users"
printf '# progress\n2026-04-22 16:00:00 | DONE | phase2_user_enum | x\n' > "$R/ad/corp.local/progress.log"
printf 'administrator\n' > "$R/ad/corp.local/users/all_users.txt"; mkstale "$R/ad/corp.local/users/all_users.txt"
J=$(run_lf "$R" "$TMP/none" --target corp.local --stage ad)
eq "H ad-skip proposal present" "$(j_prop "$J" 'ad-skip')" 1
eq "H no ad result row"         "$(j_n "$J")" 0

echo "=== I: udp-scan non-root → needs-sudo skip ==="
R="$TMP/I"; d=$(printf 'nmap_udp\n' | mk_recon "$R" 10.10.11.11)
printf '161\n' > "$d/scans/udp_ports.txt"; mkstale "$d/scans/udp_ports.txt"
J=$(run_lf "$R" "$TMP/none" --target 10.10.11.11 --stage recon)
if [[ $EUID -ne 0 ]]; then
    eq "I udp needs-sudo proposal" "$(j_prop "$J" 'udp-scan')" 1
    eq "I udp did not run"          "$(j_field "$J" udp-scan ran)" ""
else
    pass "I (running as root — udp re-run allowed; skip guard N/A)"; pass "I (root)"
fi

echo "=== J: web depth-discipline → propose webenum --from-recon, don't run ==="
R="$TMP/J"; d=$(printf 'nmap_tcp\n' | mk_recon "$R" 10.10.11.12)
PORTROW 8080 http Jetty > "$d/scans/nmap_tcp.nmap"
J=$(run_lf "$R" "$TMP/none" --target 10.10.11.12 --stage web)
eq "J webenum proposal present" "$(j_prop "$J" 'from-recon')" 1
eq "J no web result row"        "$(j_n "$J")" 0

echo "=== K: from-foothold netstat → new internal listener → new-services-found ==="
R="$TMP/K"; mkdir -p "$R/recon/10.10.11.13/from-foothold"
printf 'tcp LISTEN 0.0.0.0:22\n' > "$R/recon/10.10.11.13/from-foothold/netstat.txt"
NEW=$(mktemp "$TMP/k.XXXX"); printf 'tcp LISTEN 0.0.0.0:22\ntcp LISTEN 127.0.0.1:3306\n' > "$NEW"
J=$(TOOLKIT_ROOT="$R" bash "$LF" --target 10.10.11.13 from-foothold "$NEW" --label netstat --json 2>/dev/null)
eq "K from-foothold new-services-found" "$(j_key "$J" from-foothold success-livefetch-new-services-found)" 1
eq "K sentinel written"                 "$(sentinel_has "$R" success-livefetch-new-services-found 10.10.11.13)" 1

echo "=== L: idempotency — second run inside --since re-fetches nothing ==="
R="$TMP/L"; d=$(printf 'rustscan\n' | mk_recon "$R" 10.10.11.14)
printf '22,80\n' > "$d/scans/tcp_ports.txt"; mkstale "$d/scans/tcp_ports.txt"
N="$TMP/L.new"; mkdir -p "$N/tcp-discovery/scans"; printf '22,80,445\n' > "$N/tcp-discovery/scans/tcp_ports.txt"
run_lf "$R" "$N" --target 10.10.11.14 --stage recon >/dev/null    # run 1 (re-writes fresh)
J=$(run_lf "$R" "$N" --target 10.10.11.14 --stage recon)          # run 2
eq "L second run re-fetches nothing" "$(j_n "$J")" 0

#------------------------------------------------------------------------------
echo
echo "==============================================================="
echo "  PASS: $PASS    FAIL: $FAIL"
echo "==============================================================="
[[ $FAIL -eq 0 ]] || exit 1
exit 0
