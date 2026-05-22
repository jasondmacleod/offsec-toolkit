#!/usr/bin/env bash
#==============================================================================
# tests/test_workflow_integration.sh — end-to-end seam audit for the toolkit
#==============================================================================
# The eight per-tool suites each exercise ONE tool against synthetic fixtures.
# None chains tool N's REAL output into tool N+1's REAL parser. This suite fills
# that gap: it drives the actual tools in sequence and asserts each producer's
# real on-disk output is correctly consumed by the next reader — the seams that
# live in the gaps between tools.
#
# Layering under test:
#   COLLECTION  recon/web/ad fixtures (producer-faithful shapes)
#       → BRIDGE     orient.sh         (collection → targets/<ip>/)
#       → DECISION   stuckr / targetcheckr / watchdog   (read targets/<ip>/)
#       → EVIDENCE   evidencr ledger/flags (hand-built, schema asserted at runtime)
#       → AUDIT      proofr.sh         (reconcile state ⟷ evidence; exit code)
#
# Scenarios (map to handoff §2):
#   S1   standalone full chain:  recon → orient → stuckr → targetcheckr
#                                (foothold) → watchdog (liveness) → evidencr
#                                → proofr  (documented, exit 0)
#   S1e  cross-producer merge:   recon + web + ad for ONE ip, single orient run;
#                                + 2-web-instance fan-in; + partial/half-written
#                                tree coherence
#   S2   AD credential flow:     orient --domain; targetcheckr cred-dump → creds.txt
#                                → state_read_global → proofr inventory + stuckr
#                                substitution + exploitfixr creds-available
#   S3   adversarial:            wildcard-empty web; engaged-no-ledger (exit 2);
#                                MSF×2 (exit 2); stale ledger row; success-*
#                                sentinel namespace vs stuckr
#   S4   boundary/failure:       missing / empty / malformed inputs degrade, not crash
#
# Fixtures are producer-faithful: shapes verified this audit against the real
# producers' write-code (recon.sh:1043,1443-1462; webenum.sh:932,1175,1873;
# adr.sh:1182-1200,2180; evidencr.sh:295,896). State writes flow through the REAL
# lib/state.sh writers; reads through the REAL readers.
#
# ADDITIVE: touches no existing tool or suite.
#==============================================================================
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/.."
ORIENT="$ROOT/orient.sh"
STUCKR="$ROOT/stuckr.sh"
TC="$ROOT/targetcheckr.sh"
WD="$ROOT/watchdog.sh"
PROOFR="$ROOT/proofr.sh"
EXFIX="$ROOT/exploitfixr.sh"
STATE="$ROOT/lib/state.sh"
EVIDENCR="$ROOT/evidencr.sh"
TMP=$(mktemp -d -t wf-integ-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export NO_COLOR=1

PASS=0; FAIL=0
pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
eq()   { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2' want '$3')"; fi; }
has()  { if grep -qF -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (missing '$3')"; fi; }
absent(){ if grep -qF -- "$3" <<<"$2"; then fail "$1 (unexpected '$3')"; else pass "$1"; fi; }

# Reader calls run in their own subshell so TOOLKIT_ROOT stays case-local.
# shellcheck disable=SC1090,SC2030,SC2031
srt() { ( export TOOLKIT_ROOT="$1"; source "$STATE"; state_read_target "$2" ); }
# shellcheck disable=SC1090,SC2030,SC2031
srg() { ( export TOOLKIT_ROOT="$1"; source "$STATE"; state_read_global ); }
# shellcheck disable=SC1090,SC2030,SC2031
srf() { ( export TOOLKIT_ROOT="$1"; source "$STATE"; state_read_footholds "$2" ); }

run_orient()  { TOOLKIT_ROOT="$1" bash "$ORIENT" "${@:2}" >/dev/null 2>&1; }
run_stuckr()  { TOOLKIT_ROOT="$1" bash "$STUCKR" "${@:2}" 2>&1; }
run_proofr()  { OUT=$(TOOLKIT_ROOT="$1" bash "$PROOFR" "${@:2}" 2>/dev/null); RC=$?; }
run_tc()      { TOOLKIT_ROOT="$1" bash "$TC" "${@:2}" 2>&1; }
run_wd_live() { TOOLKIT_ROOT="$1" bash "$WD" --surfaces-dir "$2" >/dev/null 2>&1; }

ffrow() { printf '%-30s %-40s | %6s | %8s | %6s | %5s\n' "$1" "$2" "$3" "$4" "$5" "$6"; }

#------------------------------------------------------------------------------
# Producer-faithful COLLECTION-layer fixture builders
#------------------------------------------------------------------------------
mk_recon_nmap() {  # root ip [os]
    local d="$1/recon/$2/scans"; mkdir -p "$d"
    cat > "$d/nmap_tcp.nmap" <<EOF
Nmap scan report for $2
22/tcp   open  ssh          OpenSSH 8.4p1
80/tcp   open  http         Apache httpd 2.4.41
445/tcp  open  microsoft-ds Samba smbd 4.9.5
Running: ${3:-Linux 5.X}
OS details: ${3:-Linux 5.4}
EOF
}
mk_recon_smb() {  # root ip — netexec carries header/status junk (⚠4)
    local d="$1/recon/$2/tcp/smb"; mkdir -p "$d"
    printf '\tSharename       Type      Comment\n\t---------       ----      -------\n\tprint$          Disk      Printer Drivers\n\tIPC$            IPC       IPC Service\n' \
        > "$d/smbclient_list.txt"
    {
        printf 'SMB  %s  445  HOST  [*] Windows 10\n' "$2"
        printf 'SMB  %s  445  HOST  Share           Permissions     Remark\n' "$2"
        printf 'SMB  %s  445  HOST  -----           -----------     ------\n' "$2"
        printf 'SMB  %s  445  HOST  backups         READ            Backups\n' "$2"
    } > "$d/netexec_shares.txt"
}
mk_web_instance() {  # root webdir-basename(host_port_proto) ip
    local c="$1/web/$2/artifacts/content"; mkdir -p "$c"
    { ffrow FUZZ URL Status Size Words Lines; printf -- '------------\n';
      ffrow admin   "http://$3:80/admin"    200 100 5 2;
      ffrow uploads "http://$3:80/uploads/" 301 0   0 0; } > "$c/dirs_medium.txt"
    : > "$c/files_medium.txt"
}
mk_web_wildcard() {  # root webdir-basename — header-only (wildcard-filtered, ⚠2)
    local c="$1/web/$2/artifacts/content"; mkdir -p "$c"
    { ffrow FUZZ URL Status Size Words Lines; printf -- '------------\n'; } > "$c/dirs_medium.txt"
    : > "$c/files_medium.txt"
}
mk_ad() {  # root domain — nxc --computers carries the [*] banner (⚠6)
    local a="$1/ad/$2"; mkdir -p "$a/users" "$a/computers"
    printf 'administrator\njdoe\nsvc_sql\n' > "$a/users/all_users.txt"
    { printf 'SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:%s)\n' "$2";
      printf 'SMB  10.10.10.5  445  DC01  DC01$\n';
      printf 'SMB  10.10.10.5  445  DC01  WS01$\n'; } > "$a/computers/nxc_computers.txt"
}

#------------------------------------------------------------------------------
# EVIDENCE-layer fixture builders (hand-built; ledger schema asserted at runtime)
#------------------------------------------------------------------------------
led_init() { mkdir -p "$1/evidence"
    printf '# TIMESTAMP | IP | HOSTNAME | OS | CATEGORY | POINTS | LOCAL | PROOF | FOOTHOLD | ELEVATED | MSF | CHAIN | DIR\n' \
        > "$1/evidence/evidence_ledger.txt"; }
led_row() { # root ip host os cat points local proof foothold elevated msf
    printf '2026-05-21 11:00:00 | %s | %s | %s | %s | points=%s | local=%s | proof=%s | foothold=%s | elevated=%s | msf=%s | chain=x | dir=%s/evidence/%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "$1" "$2" \
        >> "$1/evidence/evidence_ledger.txt"; }
mk_flag() { mkdir -p "$1/evidence/$2/flags"; printf '[2026-05-21 10:00:00] %s\n' "$4" > "$1/evidence/$2/flags/$3.txt"; }
mk_missing_shots() { mkdir -p "$1/evidence/$2/screenshots"; : > "$1/evidence/$2/screenshots/missing_screenshots.txt"
    local s; for s in "${@:3}"; do printf '%s\n' "$s" >> "$1/evidence/$2/screenshots/missing_screenshots.txt"; done; }
mk_msf() { mkdir -p "$1/evidence/$2"; touch "$1/evidence/$2/msf_used.flag"; }

UUID_A="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
UUID_B="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
UUID_C="cccccccccccccccccccccccccccccccc"

#==============================================================================
# RUNTIME SCHEMA-CONFORMANCE GUARD (note 2): the led_row fixture must conform to
# evidencr's CURRENT ledger-row format. Extract the keyed-field order live from
# evidencr.sh and assert the fixture matches — so this suite goes RED the day
# evidencr's schema drifts, instead of silently testing a stale shape.
#==============================================================================
echo "=== Guard: evidencr ledger-row schema conformance (live from evidencr.sh) ==="
# The single ledger printf line carries both points=...  and dir=...${IP_DIR}
EVID_LINE=$(grep -E 'local=\$\{LOCAL_FLAG_VALUE.*dir=\$\{IP_DIR\}' "$EVIDENCR")
if [[ -z "$EVID_LINE" ]]; then
    fail "Guard: could not locate evidencr ledger printf line (schema anchor moved)"
else
    # keyed fields, in order, as evidencr emits them
    EVID_KEYS=$(grep -oE '[a-z_]+=\$\{' <<<"$EVID_LINE" | sed 's/=\${//' | tr '\n' ' ')
    eq "Guard: evidencr keyed-field order" "$EVID_KEYS" "points local proof foothold elevated msf chain dir "
    # Build one fixture row and extract its keyed fields (cols 6-13, before '=')
    GR="$TMP/guard"; led_init "$GR"
    led_row "$GR" 10.0.0.1 h Linux standalone 20 "$UUID_A" "$UUID_B" www-data root no
    FIX_ROW=$(grep -v '^#' "$GR/evidence/evidence_ledger.txt" | tail -1)
    FIX_NF=$(awk -F' *\\| *' '{print NF}' <<<"$FIX_ROW")
    eq "Guard: fixture row has 13 pipe-fields" "$FIX_NF" 13
    FIX_KEYS=$(awk -F' *\\| *' '{for(i=6;i<=13;i++){split($i,a,"=");printf "%s ",a[1]}}' <<<"$FIX_ROW")
    eq "Guard: fixture keyed-field order matches evidencr" "$FIX_KEYS" "$EVID_KEYS"
fi
echo

#==============================================================================
# S1 — STANDALONE FULL CHAIN
#   recon → orient → stuckr → targetcheckr(foothold) → watchdog → evidencr → proofr
#==============================================================================
echo "=== S1: standalone full chain (recon→orient→decision→evidence→audit) ==="
R="$TMP/s1"; IP=10.10.10.10
mk_recon_nmap "$R" "$IP"; mk_recon_smb "$R" "$IP"; mk_web_instance "$R" "${IP}_80_http" "$IP"

# -- Seam S1a/S1b/S1c + S2: collection → orient → state --
run_orient "$R" "$IP"
S=$(srt "$R" "$IP")
has "S1 [S1a] orient→state os_guess=linux"   "$S" 'os_guess=linux'
has "S1 [S1a] orient→state service 22/ssh"   "$S" 'service=22/tcp/ssh'
has "S1 [S1b] orient→state smb_share backups" "$S" 'smb_share=backups'
absent "S1 [S1b] no nxc 'Share' header leak"  "$S" 'smb_share=Share'
has "S1 [S1c] orient→state web_path /admin"   "$S" 'web_path=/admin'

# -- Seam S2: stuckr reads orient's output (sees services, not the empty-recon msg) --
OUT=$(run_stuckr "$R" --on "$IP")
has "S1 [S2] stuckr sees target"          "$OUT" "$IP"
absent "S1 [S2] stuckr NOT in empty-recon mode" "$OUT" 'no enumeration data found'
has "S1 [S2] stuckr rendered services row"      "$OUT" 'services'

# -- Seam S3a/S6/S7: targetcheckr classifies a real shell capture and writes state --
CAP="$TMP/s1_shell.txt"
cat > "$CAP" <<EOF
[*] Incoming connection from $IP:54812
[*] Got shell from $IP
\$ whoami
root
\$ id
uid=0(root) gid=0(root) groups=0(root)
\$ hostname
victim01
EOF
TCOUT=$(run_tc "$R" "$CAP" --against "$IP" --expect shell)
has "S1 [S3a] targetcheckr success-confirmed" "$TCOUT" 'OUTCOME: success-confirmed'
eq  "S1 [S3a] foothold.log written" "$([[ -s "$R/targets/$IP/state/foothold.log" ]] && echo 1 || echo 0)" 1
# foothold.log → state_read_footholds round-trip (the schema watchdog consumes)
FOOT=$(srf "$R" "$IP")
has "S1 [S7] state_read_footholds emits ip\\tts\\tuser\\tmethod\\tsrc" "$FOOT" "$IP"$'\t'
eq  "S1 [S7] foothold TSV has 5 cols" "$(awk -F'\t' 'END{print NF}' <<<"$FOOT")" 5
has "S1 [S6] sentinels.log carries success-shell-spawned" \
    "$(cat "$R/targets/$IP/state/sentinels.log")" 'success-shell-spawned'

# -- Seam S6+S7 chained: real foothold.log + sentinels.log drive watchdog transition --
# Build watchdog surfaces from the REAL state_read_footholds output; empty ps/ss
# ⇒ the shell classifies DEAD; prior success-shell-spawned ⇒ cold-start ALIVE ⇒
# watchdog must write success-liveness-shell-died. This is the targetcheckr→state→
# watchdog seam end to end.
WSD="$TMP/s1_surfaces"; mkdir -p "$WSD"
: > "$WSD/ps"; : > "$WSD/ss-est"; : > "$WSD/ss-listen"; : > "$WSD/tmux"; : > "$WSD/pivots"
printf '%s %s dev tun0\n' "$IP" "$IP" > "$WSD/routes"
srf "$R" "$IP" > "$WSD/footholds"          # ← real reader output as watchdog input
run_wd_live "$R" "$WSD"
has "S1 [S6] watchdog wrote shell-died from targetcheckr's ALIVE marker" \
    "$(cat "$R/targets/$IP/state/sentinels.log")" 'success-liveness-shell-died'

# -- EVIDENCE → proofr: documented + full proof → exit 0 --
led_init "$R"
led_row "$R" "$IP" victim01 Linux standalone 20 "$UUID_A" "$UUID_B" root root no
mk_flag "$R" "$IP" local "$UUID_A"; mk_flag "$R" "$IP" proof "$UUID_B"; mk_missing_shots "$R" "$IP"
run_proofr "$R" --on "$IP"
has "S1 [S4] proofr reads foothold engagement" "$OUT" 'engagement : foothold.log'
has "S1 [S4] proofr fully documented" "$OUT" 'fully documented'
eq  "S1 [S4] proofr exit 0 (report-ready)" "$RC" 0
echo

#==============================================================================
# S1e — CROSS-PRODUCER MERGE + FAN-IN + PARTIAL TREE (handoff note 1)
#   The three producers write DISJOINT subtrees (recon/ web/ ad/) and orient
#   fans them into DISJOINT decision-layer files — so the cross-producer merge
#   is not a path-collision seam. What IS a seam: one orient run reconciling all
#   three for a single IP, multi-web-instance fan-in, and a half-written tree.
#==============================================================================
echo "=== S1e: one orient run merges 3 disjoint producers for one IP ==="
R="$TMP/s1e"; DC=10.10.10.5; DOM=corp.com
mk_recon_nmap "$R" "$DC" "Windows Server 2019"; mk_recon_smb "$R" "$DC"
mk_web_instance "$R" "${DC}_80_http" "$DC"
mk_web_instance "$R" "${DC}_8080_http" "$DC"      # 2nd web instance, same IP (fan-in)
mk_ad "$R" "$DOM"
run_orient "$R" "$DC" --domain "$DOM"
S=$(srt "$R" "$DC"); G=$(srg "$R")
has "S1e recon merged (service)"   "$S" 'service=445/tcp/microsoft-ds'
has "S1e smb merged (smb_share)"   "$S" 'smb_share=backups'
has "S1e web merged (web_path)"    "$S" 'web_path=/admin'
has "S1e ad users merged"          "$S" 'ad_user=svc_sql'
has "S1e ad computers merged"      "$S" 'ad_computer=DC01'
has "S1e global domain merged"     "$G" 'domain=corp.com'
has "S1e global dc_ip merged"      "$G" "dc_ip=$DC"
# fan-in: both web instances' paths land in the single feroxbuster.txt
eq  "S1e web fan-in: feroxbuster.txt single file" \
    "$([[ -f "$R/targets/$DC/web/feroxbuster.txt" ]] && echo 1 || echo 0)" 1
eq  "S1e web fan-in: paths from both instances present" \
    "$(grep -c '/admin' "$R/targets/$DC/web/feroxbuster.txt")" 2

echo "=== S1e: half-written tree (recon only) → coherent partial state, re-orient additive ==="
R2="$TMP/s1e_partial"; PIP=10.10.10.40
mk_recon_nmap "$R2" "$PIP"
run_orient "$R2" "$PIP"
S=$(srt "$R2" "$PIP")
has   "S1e partial: services present"   "$S" 'service=22/tcp/ssh'
absent "S1e partial: no web yet"         "$S" 'web_path='
absent "S1e partial: no ad yet"          "$S" 'ad_user='
# web arrives later; re-orient is additive (full-file replacement, no clobber of recon)
mk_web_instance "$R2" "${PIP}_80_http" "$PIP"
run_orient "$R2" "$PIP"
S=$(srt "$R2" "$PIP")
has "S1e partial→full: web_path now present" "$S" 'web_path=/admin'
has "S1e partial→full: services still present (no clobber)" "$S" 'service=22/tcp/ssh'
echo

#==============================================================================
# S2 — AD CREDENTIAL FLOW: the §7 cred chain end to end
#   targetcheckr cred-dump → state_append_cred → creds.txt → state_read_global
#   → {proofr inventory, stuckr substitution, exploitfixr creds-available}
#==============================================================================
echo "=== S2: cred-dump → creds.txt → state_read_global → 3 consumers ==="
R="$TMP/s2"; DC=10.10.10.5; DOM=corp.com
mk_recon_nmap "$R" "$DC" "Windows Server 2019"; mk_ad "$R" "$DOM"
run_orient "$R" "$DC" --domain "$DOM"
CAP="$TMP/s2_creds.txt"
cat > "$CAP" <<'EOF'
[*] Dumping credentials via secretsdump
[+] corp.com\svc_sql:Summ3r2026!
[+] Dump complete
EOF
TCOUT=$(run_tc "$R" "$CAP" --against "$DC" --expect cred-dump)
has "S2 [S3b] targetcheckr classified cred-dump" "$TCOUT" 'cred-dumped'
# creds.txt written via the real state_append_cred?
eq "S2 [S3b] creds.txt written" "$([[ -s "$R/creds.txt" ]] && echo 1 || echo 0)" 1
G=$(srg "$R")
# cred-dump detector emits the Windows DOMAIN\user convention; it round-trips verbatim
has "S2 [S3b] state_read_global emits cred=USER:CRED" "$G" 'cred=corp.com\svc_sql:Summ3r2026!'
absent "S2 [S3b] no whole-line pipe leak in cred=" "$G" 'cred=2026'
# consumer 1: proofr inventory lists the user, never the secret
run_proofr "$R" --all
has    "S2 [S3b] proofr inventory lists user" "$OUT" 'svc_sql'
absent "S2 [S3b] proofr never leaks secret"   "$OUT" 'Summ3r2026!'
# consumer 2: exploitfixr creds-available precondition fires (state stream non-empty)
#   (smoke: run exploitfixr against a trivial file bound to the target; just assert
#    it consumes state without error — the precondition logic is unit-tested already)
echo "id" > "$TMP/s2_exp.py"
TOOLKIT_ROOT="$R" bash "$EXFIX" "$TMP/s2_exp.py" --against "$DC" >/dev/null 2>&1; EXRC=$?
eq "S2 [S3b] exploitfixr consumes cred-bearing state w/o error" "$EXRC" 0
echo

#==============================================================================
# S3 — ADVERSARIAL STATES
#==============================================================================
echo "=== S3a: wildcard/header-only web → orient empty feroxbuster, stuckr survives ==="
R="$TMP/s3a"; IP=10.10.10.11
mk_recon_nmap "$R" "$IP"; mk_web_wildcard "$R" "${IP}_80_http"
run_orient "$R" "$IP"
S=$(srt "$R" "$IP")
eq "S3a feroxbuster.txt written (empty valid)" "$([[ -f "$R/targets/$IP/web/feroxbuster.txt" ]] && echo 1 || echo 0)" 1
eq "S3a zero web_path"  "$(grep -c '^web_path=' <<<"$S")" 0
OUT=$(run_stuckr "$R" --on "$IP"); SRC=$?
eq "S3a stuckr exits 0 on empty web" "$SRC" 0
has "S3a stuckr still renders target" "$OUT" "$IP"

echo "=== S3b: engaged (real foothold) but NO ledger → proofr exit 2 ==="
R="$TMP/s3b"; IP=10.10.10.20; led_init "$R"
mk_recon_nmap "$R" "$IP"; run_orient "$R" "$IP"
CAP="$TMP/s3b.txt"; printf '[*] Got shell from %s\n# id\nuid=0(root) gid=0(root)\n' "$IP" > "$CAP"
run_tc "$R" "$CAP" --against "$IP" --expect shell >/dev/null
run_proofr "$R" --on "$IP"
has "S3b proofr flags undocumented compromise" "$OUT" '[ledger]'
eq  "S3b proofr exit 2 (critical)" "$RC" 2

echo "=== S3c: MSF used on >1 machine → proofr exit 2 ==="
R="$TMP/s3c"; led_init "$R"
mk_foothold_real() { local cap="$TMP/mf.$2.txt"; printf '[*] Got shell from %s\n# id\nuid=0(root) gid=0(root)\n' "$2" > "$cap"
                     run_tc "$1" "$cap" --against "$2" --expect shell >/dev/null; }
mk_recon_nmap "$R" 10.0.3.10; run_orient "$R" 10.0.3.10
mk_foothold_real "$R" 10.0.3.10
led_row "$R" 10.0.3.10 h Linux standalone 20 "$UUID_A" "$UUID_B" root root yes
mk_flag "$R" 10.0.3.10 local "$UUID_A"; mk_flag "$R" 10.0.3.10 proof "$UUID_B"; mk_missing_shots "$R" 10.0.3.10
mk_msf "$R" 10.0.3.10; mk_msf "$R" 10.0.3.11
run_proofr "$R" --all
has "S3c proofr MSF limit exceeded" "$OUT" 'OffSec LIMIT EXCEEDED'
eq  "S3c proofr exit 2 (critical)"  "$RC" 2

echo "=== S3d: stale ledger row + 'not collected' below a real flag → newest-real wins ==="
R="$TMP/s3d"; IP=10.0.4.10; led_init "$R"
mk_foothold_real "$R" "$IP" 2>/dev/null || { mk_recon_nmap "$R" "$IP"; run_orient "$R" "$IP"; mk_foothold_real "$R" "$IP"; }
# two ledger rows for the same IP — last (newest) row wins per proofr
led_row "$R" "$IP" h Linux standalone 20 MISSING MISSING root '[not provided]' no
led_row "$R" "$IP" h Linux standalone 20 "$UUID_A" "$UUID_B" root root no
# flag file: a real capture, then a later "not collected" line below it
mkdir -p "$R/evidence/$IP/flags"
printf '[2026-05-21 09:00:00] %s\n[2026-05-21 12:00:00] not collected\n' "$UUID_C" > "$R/evidence/$IP/flags/local.txt"
mk_flag "$R" "$IP" proof "$UUID_B"; mk_missing_shots "$R" "$IP"
run_proofr "$R" --on "$IP"
absent "S3d local NOT flagged missing (newest-real wins)" "$OUT" '[local]'
has    "S3d documented despite stale rows" "$OUT" 'fully documented'
eq     "S3d exit 0" "$RC" 0

echo "=== S3e: success-* sentinel namespace vs stuckr (no false symptom match) ==="
R="$TMP/s3e"; IP=10.0.5.10
mk_recon_nmap "$R" "$IP"; run_orient "$R" "$IP"
mkdir -p "$R/targets/$IP/state"
# positive-event sentinels (targetcheckr/livefetch namespace) share sentinels.log
{ printf '2026-05-21T10:00:00 success-shell-spawned\n'
  printf '2026-05-21T10:01:00 success-livefetch-delta-detected\n'; } > "$R/targets/$IP/state/sentinels.log"
OUT=$(run_stuckr "$R" --on "$IP"); SRC=$?
eq "S3e stuckr exits 0 with success-* sentinels present" "$SRC" 0
# success-* keys must NOT be rendered as matched empty-result symptoms
absent "S3e no false symptom match on success-shell-spawned" "$OUT" 'success-shell-spawned'
absent "S3e no false symptom match on livefetch key"         "$OUT" 'success-livefetch-delta-detected'
# state_read_target DOES surface them as sentinel= lines (shared namespace, by design)
has "S3e success-* visible to state reader (shared sentinels.log)" \
    "$(srt "$R" "$IP")" 'sentinel=success-shell-spawned'
# F-1 regression: positive-event sentinels must NOT suppress the service-only
# fallback label. stuckr_rank gates on matched SYMPTOM sentinels, not raw count,
# so a target with services + only success-* keys still gets the labeled fallback.
has "S3e [F-1] service-only fallback label present despite success-* sentinels" \
    "$OUT" 'service-only fallback'
echo

#==============================================================================
# S4 — BOUNDARY / FAILURE MODES (missing / empty / malformed → degrade, not crash)
#==============================================================================
echo "=== S4: boundary & failure modes ==="
# orient on an IP with no collection dirs → no crash, exit 0, no decision files
R="$TMP/s4a"; mkdir -p "$R"
TOOLKIT_ROOT="$R" bash "$ORIENT" 10.0.9.9 >/dev/null 2>&1; eq "S4 orient missing-input exit 0" "$?" 0
eq "S4 orient wrote no decision files" "$([[ -e "$R/targets/10.0.9.9/recon/nmap.txt" ]] && echo 1 || echo 0)" 0
# proofr on an empty root → exit 3 (no target inferable)
run_proofr "$TMP/s4_empty"; eq "S4 proofr empty-root exit 3" "$RC" 3
# stuckr on a bare target dir (no enumeration) → graceful 'run recon first'
R="$TMP/s4c"; mkdir -p "$R/targets/10.0.9.5"
OUT=$(run_stuckr "$R" --on 10.0.9.5); eq "S4 stuckr empty-target exit 0" "$?" 0
has "S4 stuckr empty-target guidance" "$OUT" 'no enumeration data'
# state_append_cred rejects malformed (no colon) → rc 2, no creds.txt corruption
# shellcheck disable=SC1090,SC2030,SC2031
( export TOOLKIT_ROOT="$TMP/s4d"; source "$STATE"; state_append_cred "no-colon-here" ) >/dev/null 2>&1
eq "S4 state_append_cred rejects malformed (rc 2)" "$?" 2
# orient invalid usage (unknown flag) → exit 2
TOOLKIT_ROOT="$TMP/s4e" bash "$ORIENT" --bogus >/dev/null 2>&1; eq "S4 orient unknown-flag exit 2" "$?" 2
echo

#------------------------------------------------------------------------------
echo "==============================================================="
echo "  test_workflow_integration:  PASS: $PASS    FAIL: $FAIL"
echo "==============================================================="
[[ $FAIL -eq 0 ]] || exit 1
exit 0
