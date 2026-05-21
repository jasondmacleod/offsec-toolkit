#!/usr/bin/env bash
#==============================================================================
# tests/test_watchdog_demo.sh — watchdog.sh demo cases per spec §10 (+2 new)
#==============================================================================
# Drives watchdog.sh in --surfaces-dir mode against synthetic OS surfaces:
#   1 ALIVE shell direct        2 DEAD shell            3 STALE shell (idle≥4h)
#   4 UNKNOWN (perms, no pid)   5 ligolo-tunneled shell 6 penelope multiplex
#   7 tunnel DEAD (proc gone)   8 nc listener (warn)    9 tmux pane_dead override
#  10 empty (no baselines)     11 pivotr stale-PID     12 route-unresolved
# Plus D7 transition rule:
#  13 implicit-ALIVE → DEAD writes success-liveness-shell-died
#  14 cold-start, no prior, DEAD → no transition write
#==============================================================================

set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WD="$HERE/../watchdog.sh"

TMP=$(mktemp -d -t watchdog-demo-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export NO_COLOR=1

PASS=0; FAIL=0
pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
eq()   { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2' want '$3')"; fi; }
has()  { if grep -qF -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (missing '$3')"; fi; }

res_field() {
    python3 -c '
import json,sys
d=json.loads(sys.argv[1]); typ=sys.argv[2]; ip=sys.argv[3] or None; fld=sys.argv[4]
for r in d["resources"]:
    if r["type"]==typ and (ip is None or r["ip"]==ip):
        v=r.get(fld)
        print("" if v is None else (",".join(map(str,v)) if isinstance(v,list) else v)); break
' "$1" "$2" "$3" "$4"
}
nres() { python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])["resources"]))' "$1"; }

newdir() {
    local d; d=$(mktemp -d "$TMP/case.XXXXXX")
    : > "$d/ps"; : > "$d/ss-est"; : > "$d/ss-listen"; : > "$d/tmux"
    : > "$d/routes"; : > "$d/footholds"; : > "$d/pivots"
    echo "$d"
}
run() { TOOLKIT_ROOT="$TMP/noroot" "$WD" --surfaces-dir "$1" --json --dry-run 2>&1; }

KALI=10.10.14.5

#------------------------------------------------------------------------------
echo "=== (1) ALIVE shell, direct (ssh) ==="
d=$(newdir)
printf '%s %s %s %s %s\n' 12044 12000 01:23:45 ssh "ssh jason@10.10.11.42" > "$d/ps"
{ printf '0 0 %s:51000 10.10.11.42:22 users:(("ssh",pid=12044,fd=3))\n' "$KALI"
  printf ' cubic lastsnd:5000 lastrcv:4000 lastack:4000\n'; } > "$d/ss-est"
printf '10.10.11.42 10.10.11.42 dev tun0 src %s uid 1000\n' "$KALI" > "$d/routes"
printf '10.10.11.42\t2026-06-05T14:03:00\tjason\treverse-shell\ttargetcheckr\n' > "$d/footholds"
J=$(run "$d")
eq "(1) class ALIVE"  "$(res_field "$J" shell 10.10.11.42 class)" ALIVE
eq "(1) route direct" "$(res_field "$J" shell 10.10.11.42 route)" direct

echo "=== (2) DEAD shell (no process, no ESTABLISHED) ==="
d=$(newdir)
printf '10.10.11.42 10.10.11.42 dev tun0 src %s uid 1000\n' "$KALI" > "$d/routes"
printf '10.10.11.42\t2026-06-05T14:03:00\tjason\treverse-shell\ttargetcheckr\n' > "$d/footholds"
J=$(run "$d")
eq "(2) class DEAD" "$(res_field "$J" shell 10.10.11.42 class)" DEAD

echo "=== (3) STALE shell (idle >= 4h) ==="
d=$(newdir)
printf '%s %s %s %s %s\n' 12044 12000 06:00:00 ssh "ssh jason@10.10.11.42" > "$d/ps"
{ printf '0 0 %s:51000 10.10.11.42:22 users:(("ssh",pid=12044,fd=3))\n' "$KALI"
  printf ' cubic lastsnd:15000000 lastrcv:15000000 lastack:15000000\n'; } > "$d/ss-est"
printf '10.10.11.42 10.10.11.42 dev tun0\n' > "$d/routes"
printf '10.10.11.42\t2026-06-05T14:03:00\tjason\treverse-shell\ttargetcheckr\n' > "$d/footholds"
J=$(run "$d")
eq "(3) class STALE" "$(res_field "$J" shell 10.10.11.42 class)" STALE

echo "=== (4) UNKNOWN (ESTABLISHED but unattributable PID) ==="
d=$(newdir)
{ printf '0 0 %s:443 10.10.11.42:54321\n' "$KALI"
  printf ' cubic lastsnd:3000 lastrcv:3000 lastack:3000\n'; } > "$d/ss-est"
printf '10.10.11.42 10.10.11.42 dev tun0\n' > "$d/routes"
printf '10.10.11.42\t2026-06-05T14:03:00\troot\treverse-shell\ttargetcheckr\n' > "$d/footholds"
J=$(run "$d")
eq "(4) class UNKNOWN" "$(res_field "$J" shell 10.10.11.42 class)" UNKNOWN

echo "=== (5) ligolo-tunneled shell (peer in 240/4, route via ligolo) ==="
d=$(newdir)
{ printf '%s %s %s %s %s\n' 11400 11000 02:00:00 python3 "python3 /usr/bin/penelope -p 4444"
  printf '%s %s %s %s %s\n' 11500 11000 02:10:00 ligolo-proxy "ligolo-proxy -selfcert -laddr 0.0.0.0:11601"; } > "$d/ps"
{ printf '0 0 %s:4444 240.0.0.1:40000 users:(("penelope",pid=11400,fd=6))\n' "$KALI"
  printf ' cubic lastsnd:3000 lastrcv:3000 lastack:3000\n'
  printf '0 0 %s:11601 10.10.11.42:50000 users:(("ligolo-proxy",pid=11500,fd=8))\n' "$KALI"
  printf ' cubic lastsnd:1000 lastrcv:1000 lastack:1000\n'; } > "$d/ss-est"
printf '172.16.50.5 172.16.50.5 dev ligolo src 240.0.0.1\n' > "$d/routes"
printf '172.16.50.5\t2026-06-05T15:00:00\troot\treverse-shell\ttargetcheckr\n' > "$d/footholds"
{ printf 'tun\tligolo\t\n'
  printf 'tunnel\tligolo\tsubnet=172.16.50.0/24;port=11601;tun_name=ligolo\n'; } > "$d/pivots"
J=$(run "$d")
eq "(5) shell ALIVE"      "$(res_field "$J" shell 172.16.50.5 class)" ALIVE
eq "(5) route ligolo:tun" "$(res_field "$J" shell 172.16.50.5 route)" ligolo:ligolo
eq "(5) tunnel ALIVE"     "$(res_field "$J" tunnel "" class)" ALIVE

echo "=== (6) penelope multiplexing (2 footholds, same IP) ==="
d=$(newdir)
printf '%s %s %s %s %s\n' 11400 11000 02:00:00 python3 "python3 /usr/bin/penelope -p 443" > "$d/ps"
{ printf '0 0 %s:443 10.10.11.81:51001 users:(("penelope",pid=11400,fd=6))\n' "$KALI"
  printf ' cubic lastsnd:2000 lastrcv:2000 lastack:2000\n'
  printf '0 0 %s:443 10.10.11.81:51002 users:(("penelope",pid=11400,fd=7))\n' "$KALI"
  printf ' cubic lastsnd:9000 lastrcv:9000 lastack:9000\n'; } > "$d/ss-est"
printf '10.10.11.81 10.10.11.81 dev tun0\n' > "$d/routes"
{ printf '10.10.11.81\t2026-06-05T14:19:00\tSYSTEM\tmsfvenom-payload\ttargetcheckr\n'
  printf '10.10.11.81\t2026-06-05T14:25:00\tSYSTEM\tmsfvenom-payload\ttargetcheckr\n'; } > "$d/footholds"
J=$(run "$d")
eq "(6) class ALIVE"       "$(res_field "$J" shell 10.10.11.81 class)" ALIVE
eq "(6) established=2"      "$(res_field "$J" shell 10.10.11.81 established)" 2
eq "(6) foothold_lines=2"  "$(res_field "$J" shell 10.10.11.81 foothold_lines)" 2

echo "=== (7) tunnel DEAD (state.tsv baseline, process gone) ==="
d=$(newdir)
printf 'tunnel\tligolo\tsubnet=172.16.50.0/24;port=11601\n' > "$d/pivots"
J=$(run "$d")
eq "(7) tunnel DEAD" "$(res_field "$J" tunnel "" class)" DEAD

echo "=== (8) nc listener (warned) ==="
d=$(newdir)
printf '%s %s %s %s %s\n' 9100 9000 00:30:00 nc "nc -lvnp 9001" > "$d/ps"
printf 'LISTEN 0 1 0.0.0.0:9001 0.0.0.0:* users:(("nc",pid=9100,fd=3))\n' > "$d/ss-listen"
J=$(run "$d")
eq "(8) listener ALIVE" "$(res_field "$J" listener "" class)" ALIVE
has "(8) nc-warn flag"  "$J" '"nc-warn"'

echo "=== (9) tmux pane_dead override → DEAD ==="
d=$(newdir)
printf '%s %s %s %s %s\n' 12044 12000 00:10:00 ssh "ssh jason@10.10.11.42" > "$d/ps"
{ printf '0 0 %s:51000 10.10.11.42:22 users:(("ssh",pid=12044,fd=3))\n' "$KALI"
  printf ' cubic lastsnd:1000 lastrcv:1000 lastack:1000\n'; } > "$d/ss-est"
printf 'sa-1:1.0 12000 1 ssh\n' > "$d/tmux"
printf '10.10.11.42 10.10.11.42 dev tun0\n' > "$d/routes"
printf '10.10.11.42\t2026-06-05T14:03:00\tjason\treverse-shell\ttargetcheckr\n' > "$d/footholds"
J=$(run "$d")
eq "(9) class DEAD (pane dead)" "$(res_field "$J" shell 10.10.11.42 class)" DEAD

echo "=== (10) empty — no baselines, no resources ==="
d=$(newdir)
J=$(run "$d")
eq "(10) zero resources" "$(nres "$J")" 0

echo "=== (11) pivotr stale-PID (recorded PID is now bash) ==="
d=$(newdir)
printf '%s %s %s %s %s\n' 4444 4000 00:05:00 bash "bash" > "$d/ps"
{ printf 'process\t4444\tligolo-proxy\n'
  printf 'tunnel\tligolo\tsubnet=172.16.50.0/24;port=11601\n'; } > "$d/pivots"
J=$(run "$d")
eq "(11) tunnel DEAD (stale pid)" "$(res_field "$J" tunnel "" class)" DEAD

echo "=== (12) route-unresolved (ESTABLISHED present, ip route get fails) ==="
d=$(newdir)
printf '%s %s %s %s %s\n' 12044 12000 00:10:00 ssh "ssh jason@10.10.11.99" > "$d/ps"
{ printf '0 0 %s:51000 10.10.11.99:22 users:(("ssh",pid=12044,fd=3))\n' "$KALI"
  printf ' cubic lastsnd:2000 lastrcv:2000 lastack:2000\n'; } > "$d/ss-est"
printf '10.10.11.99 FAILED\n' > "$d/routes"
printf '10.10.11.99\t2026-06-05T16:00:00\twww-data\tweb-cmdi\ttargetcheckr\n' > "$d/footholds"
J=$(run "$d")
eq "(12) class ALIVE"            "$(res_field "$J" shell 10.10.11.99 class)" ALIVE
eq "(12) route route-unresolved" "$(res_field "$J" shell 10.10.11.99 route)" route-unresolved

#------------------------------------------------------------------------------
# Transition writes (D7) — run WITHOUT --dry-run against a mock TOOLKIT_ROOT
#------------------------------------------------------------------------------
echo "=== (13) transition: implicit-ALIVE → DEAD writes shell-died ==="
d=$(newdir)
printf '10.10.11.42 10.10.11.42 dev tun0\n' > "$d/routes"
printf '10.10.11.42\t2026-06-05T14:03:00\tjason\treverse-shell\ttargetcheckr\n' > "$d/footholds"
R13="$TMP/root13"; mkdir -p "$R13/targets/10.10.11.42/state"
printf '2026-06-05T14:03:00 success-shell-spawned\n' > "$R13/targets/10.10.11.42/state/sentinels.log"
TOOLKIT_ROOT="$R13" "$WD" --surfaces-dir "$d" >/dev/null 2>&1
if grep -q 'success-liveness-shell-died' "$R13/targets/10.10.11.42/state/sentinels.log"; then
    pass "(13) shell-died written on ALIVE→DEAD"
else
    fail "(13) shell-died NOT written"
fi

echo "=== (14) cold-start: no prior, DEAD → no transition write ==="
d=$(newdir)
printf '10.10.11.55 10.10.11.55 dev tun0\n' > "$d/routes"
printf '10.10.11.55\t2026-06-05T14:03:00\tjason\treverse-shell\ttargetcheckr\n' > "$d/footholds"
R14="$TMP/root14"; mkdir -p "$R14/targets/10.10.11.55/state"
TOOLKIT_ROOT="$R14" "$WD" --surfaces-dir "$d" >/dev/null 2>&1
SF14="$R14/targets/10.10.11.55/state/sentinels.log"
if [[ ! -s "$SF14" ]] || ! grep -q 'success-liveness-' "$SF14"; then
    pass "(14) no transition written (nothing was alive)"
else
    fail "(14) unexpected transition write"
fi

#------------------------------------------------------------------------------
echo
echo "==============================================================="
echo "  PASS: $PASS    FAIL: $FAIL"
echo "==============================================================="
[[ $FAIL -eq 0 ]] || exit 1
exit 0
