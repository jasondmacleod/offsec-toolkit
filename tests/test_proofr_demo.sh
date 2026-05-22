#!/usr/bin/env bash
#==============================================================================
# tests/test_proofr_demo.sh — proofr.sh behavior cases (proofr_spec §3/§5/§6)
#==============================================================================
# Builds synthetic decision-layer (foothold.log, creds.txt) + evidence-layer
# (evidencr ledger, flags/*.txt, missing_screenshots.txt, msf markers) fixtures
# under per-case temp TOOLKIT_ROOTs, runs proofr.sh, and asserts on its stdout gap
# audit + EXIT CODE. Footholds/creds are written through the REAL lib/state.sh
# writers so the fixtures match the on-disk schema proofr reads back.
#
#   A documented + full proof    → "fully documented ✓", exit 0
#   B engaged, NO ledger         → CRITICAL [ledger] gap, exit 2
#   C proof missing + elevated   → inferred [proof] gap + NOTE caveat, exit 1
#   D adversarial flag file      → good capture then "not collected" → local ✓
#   E AD network_position.png     → dedicated REQUIRED-for-AD [shots] gap
#   F recon-only target          → "recon-only, not owned", not counted engaged
#   G MSF limit exceeded (>1)     → footer "OffSec LIMIT EXCEEDED", exit 2
#   H cred inventory             → users listed, secrets NEVER leaked
#   I missing local flag         → [local] gap, exit 1
#   J ledger-only inconsistency  → [local] inconsistency gap
#   K --all tally + universe      → engaged/documented/gaps counts
#   L no target inferred          → exit 3
#==============================================================================
set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PROOFR="$HERE/../proofr.sh"
STATE="$HERE/../lib/state.sh"
TMP=$(mktemp -d -t proofr-demo-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export NO_COLOR=1

PASS=0; FAIL=0
pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
eq()   { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got '$2' want '$3')"; fi; }

# run_proofr <root> [args...] : captures stdout in OUT and exit code in RC
OUT=""; RC=0
run_proofr() { OUT=$(TOOLKIT_ROOT="$1" bash "$PROOFR" "${@:2}" 2>/dev/null); RC=$?; }
has()  { grep -qF -- "$2" <<<"$1" && echo 1 || echo 0; }   # substring present
absent() { grep -qF -- "$2" <<<"$1" && echo 0 || echo 1; } # substring absent

UUID_A="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"   # 32-hex, flag_is_real==true
UUID_B="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
UUID_C="cccccccccccccccccccccccccccccccc"

# --- fixture builders -------------------------------------------------------
# Writers run in their own subshell so TOOLKIT_ROOT stays test-local — the
# subshell-scoping shellcheck flags is the intended isolation, not a bug.
# shellcheck disable=SC1090,SC2030,SC2031
mk_foothold() { # root ip user method   (through the real writer)
    ( export TOOLKIT_ROOT="$1"; source "$STATE"; state_write_foothold "$2" "$3" "$4" ) >/dev/null 2>&1
}
# shellcheck disable=SC1090,SC2030,SC2031
mk_cred() { # root user:cred   (through the real writer → authoritative schema)
    ( export TOOLKIT_ROOT="$1"; source "$STATE"; state_append_cred "$2" ) >/dev/null 2>&1
}
mk_flag() { # root ip kind value   (evidencr flag-file line shape)
    mkdir -p "$1/evidence/$2/flags"
    printf '[2026-05-21 10:00:00] %s\n' "$4" > "$1/evidence/$2/flags/$3.txt"
}
mk_missing_shots() { # root ip line...
    mkdir -p "$1/evidence/$2/screenshots"
    : > "$1/evidence/$2/screenshots/missing_screenshots.txt"
    local s
    for s in "${@:3}"; do printf '%s\n' "$s" >> "$1/evidence/$2/screenshots/missing_screenshots.txt"; done
}
mk_msf() { mkdir -p "$1/evidence/$2"; touch "$1/evidence/$2/msf_used.flag"; }
led_init() { # root
    mkdir -p "$1/evidence"
    printf '# TIMESTAMP | IP | HOSTNAME | OS | CATEGORY | POINTS | LOCAL | PROOF | FOOTHOLD | ELEVATED | MSF | CHAIN | DIR\n' \
        > "$1/evidence/evidence_ledger.txt"
}
led_row() { # root ip host os cat points local proof foothold elevated msf
    printf '2026-05-21 11:00:00 | %s | %s | %s | %s | points=%s | local=%s | proof=%s | foothold=%s | elevated=%s | msf=%s | chain=x | dir=%s/evidence/%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "$1" "$2" \
        >> "$1/evidence/evidence_ledger.txt"
}

#------------------------------------------------------------------------------
echo "=== A: documented + full proof → fully documented, exit 0 ==="
R="$TMP/A"; led_init "$R"
mk_foothold "$R" 10.0.0.10 www-data web-rce
mk_flag "$R" 10.0.0.10 local "$UUID_A"; mk_flag "$R" 10.0.0.10 proof "$UUID_B"
mk_missing_shots "$R" 10.0.0.10        # empty = none missing
led_row "$R" 10.0.0.10 web01 Linux standalone 20 "$UUID_A" "$UUID_B" www-data root no
run_proofr "$R" --on 10.0.0.10
eq "A fully documented"  "$(has "$OUT" 'fully documented')" 1
eq "A no GAPS block"     "$(absent "$OUT" 'GAPS (')" 1
eq "A interactive note"  "$(has "$OUT" 'INTERACTIVE shell')" 1
eq "A exit 0"            "$RC" 0

echo "=== B: engaged but NO ledger → CRITICAL [ledger], exit 2 ==="
R="$TMP/B"; led_init "$R"
mk_foothold "$R" 10.0.0.20 user7 kerberoast
run_proofr "$R" --on 10.0.0.20
eq "B ledger gap"        "$(has "$OUT" '[ledger]')" 1
eq "B run evidencr hint" "$(has "$OUT" 'run: evidencr 10.0.0.20')" 1
eq "B exit 2 critical"   "$RC" 2

echo "=== C: proof missing + elevated → inferred [proof] gap + NOTE, exit 1 ==="
R="$TMP/C"; led_init "$R"
mk_foothold "$R" 10.0.0.30 svc sqli
mk_flag "$R" 10.0.0.30 local "$UUID_A"
led_row "$R" 10.0.0.30 host3 Linux standalone 20 "$UUID_A" MISSING svc admin no
run_proofr "$R" --on 10.0.0.30
eq "C proof gap"          "$(has "$OUT" '[proof]')" 1
eq "C elevation phrasing" "$(has "$OUT" 'evidence shows elevation')" 1
eq "C inferred NOTE"      "$(has "$OUT" 'inferred from heuristic')" 1
eq "C exit 1"             "$RC" 1

echo "=== D: adversarial flag file — good capture then later 'not collected' → local ✓ ==="
R="$TMP/D"; led_init "$R"
mk_foothold "$R" 10.0.0.40 www-data web-rce
mkdir -p "$R/evidence/10.0.0.40/flags"
printf '[2026-05-21 09:00:00] %s\n[2026-05-21 12:00:00] not collected\n' "$UUID_C" \
    > "$R/evidence/10.0.0.40/flags/local.txt"
mk_flag "$R" 10.0.0.40 proof "$UUID_B"
mk_missing_shots "$R" 10.0.0.40
led_row "$R" 10.0.0.40 host4 Linux standalone 20 "$UUID_C" "$UUID_B" www-data root no
run_proofr "$R" --on 10.0.0.40
eq "D local NOT flagged missing" "$(absent "$OUT" '[local]')" 1
eq "D local mark present"        "$(has "$OUT" 'local ✓')" 1
eq "D fully documented"          "$(has "$OUT" 'fully documented')" 1
eq "D exit 0"                    "$RC" 0

echo "=== E: AD network_position.png → dedicated REQUIRED-for-AD [shots] gap ==="
R="$TMP/E"; led_init "$R"
mk_foothold "$R" 10.0.0.50 svc psexec
mk_flag "$R" 10.0.0.50 local "$UUID_A"; mk_flag "$R" 10.0.0.50 proof "$UUID_B"
mk_missing_shots "$R" 10.0.0.50 network_position.png
led_row "$R" 10.0.0.50 dc01 Windows AD-DC 20 "$UUID_A" "$UUID_B" svc Administrator no
run_proofr "$R" --on 10.0.0.50
eq "E AD network_position gap" "$(has "$OUT" 'network_position.png MISSING (REQUIRED for AD')" 1
eq "E exit 1"                  "$RC" 1

echo "=== F: recon-only target → not owned, not counted engaged ==="
R="$TMP/F"; led_init "$R"; mkdir -p "$R/targets/10.0.0.60"
run_proofr "$R" --on 10.0.0.60
eq "F recon-only line" "$(has "$OUT" 'recon-only, not owned')" 1
eq "F no GAPS"         "$(absent "$OUT" 'GAPS (')" 1
eq "F exit 0"          "$RC" 0

echo "=== G: MSF limit exceeded (>1) → footer warning + exit 2 ==="
R="$TMP/G"; led_init "$R"
mk_foothold "$R" 10.0.0.70 www-data web-rce
mk_flag "$R" 10.0.0.70 local "$UUID_A"; mk_flag "$R" 10.0.0.70 proof "$UUID_B"; mk_missing_shots "$R" 10.0.0.70
led_row "$R" 10.0.0.70 h7 Linux standalone 20 "$UUID_A" "$UUID_B" www-data root yes
mk_msf "$R" 10.0.0.70; mk_msf "$R" 10.0.0.71
run_proofr "$R" --on 10.0.0.70
eq "G msf limit warning" "$(has "$OUT" 'OffSec LIMIT EXCEEDED')" 1
eq "G exit 2"            "$RC" 2

echo "=== H: cred inventory — users listed, secrets NEVER leaked ==="
R="$TMP/H"; led_init "$R"; mkdir -p "$R/targets/10.0.0.80"
mk_cred "$R" "jdoe:SuperSecret123"
mk_cred "$R" "svc:NTLM:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
run_proofr "$R" --all
eq "H cred count 2"       "$(has "$OUT" 'creds captured: 2')" 1
eq "H user jdoe listed"   "$(has "$OUT" 'jdoe')" 1
eq "H secret NOT leaked"  "$(absent "$OUT" 'SuperSecret123')" 1
eq "H hash NOT leaked"    "$(absent "$OUT" 'aad3b435')" 1

echo "=== I: missing local flag → [local] gap, exit 1 ==="
R="$TMP/I"; led_init "$R"
mk_foothold "$R" 10.0.0.90 www-data web-rce
led_row "$R" 10.0.0.90 h9 Linux standalone 20 MISSING "$UUID_B" www-data root no
run_proofr "$R" --on 10.0.0.90
eq "I local gap"  "$(has "$OUT" '[local]')" 1
eq "I exit 1"     "$RC" 1

echo "=== J: ledger cites flag but flag file empty → inconsistency [local] ==="
R="$TMP/J"; led_init "$R"
mk_foothold "$R" 10.0.0.91 www-data web-rce
# ledger claims a local flag, but NO flags/local.txt on disk
led_row "$R" 10.0.0.91 h91 Linux standalone 20 "$UUID_A" "$UUID_B" www-data root no
mk_flag "$R" 10.0.0.91 proof "$UUID_B"; mk_missing_shots "$R" 10.0.0.91
run_proofr "$R" --on 10.0.0.91
eq "J inconsistency flagged" "$(has "$OUT" 'inconsistency')" 1
eq "J exit 1"                "$RC" 1

echo "=== K: --all tally + universe (engaged/documented/gaps) ==="
R="$TMP/K"; led_init "$R"
# documented-clean
mk_foothold "$R" 10.0.1.10 www-data web-rce
mk_flag "$R" 10.0.1.10 local "$UUID_A"; mk_flag "$R" 10.0.1.10 proof "$UUID_B"; mk_missing_shots "$R" 10.0.1.10
led_row "$R" 10.0.1.10 a Linux standalone 20 "$UUID_A" "$UUID_B" www-data root no
# engaged-no-ledger
mk_foothold "$R" 10.0.1.20 user kerb
# recon-only (must NOT count as engaged)
mkdir -p "$R/targets/10.0.1.30"
run_proofr "$R" --all
eq "K engaged count 2"       "$(has "$OUT" 'engaged: 2')" 1
eq "K documented count 1"    "$(has "$OUT" 'fully documented: 1')" 1
eq "K gaps count 1"          "$(has "$OUT" 'with gaps: 1')" 1
eq "K recon-only present"    "$(has "$OUT" 'recon-only')" 1
eq "K exit 2 (no-ledger)"    "$RC" 2

echo "=== L: no target inferred → exit 3 ==="
R="$TMP/L"; mkdir -p "$R"
run_proofr "$R"
eq "L exit 3 usage" "$RC" 3

#------------------------------------------------------------------------------
echo
echo "==============================================================="
echo "  PASS: $PASS    FAIL: $FAIL"
echo "==============================================================="
[[ $FAIL -eq 0 ]] || exit 1
exit 0
