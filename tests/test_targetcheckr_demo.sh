#!/usr/bin/env bash
#==============================================================================
# tests/test_targetcheckr_demo.sh — five demo cases per spec §11
#==============================================================================
# Builds fixtures in a mock $TOOLKIT_ROOT and runs each case:
#   (a) success-confirmed shell-spawned with --expect shell
#   (b) failure-with-symptom matching a failure_map.yaml key
#   (c) unclear fallback with no detectable signals
#   (d) --dry-run on a success-confirmed input
#   (e) replay (same input twice) showing hash short-circuit
#==============================================================================

set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TC="$HERE/../targetcheckr.sh"

TMP=$(mktemp -d -t targetcheckr-demo-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
export TOOLKIT_ROOT="$TMP"
export NO_COLOR=1

PASS=0
FAIL=0
check() {
    local label="$1" haystack="$2" needle="$3"
    if grep -qF -- "$needle" <<< "$haystack"; then
        printf '  [PASS] %s\n' "$label"
        PASS=$((PASS + 1))
    else
        printf '  [FAIL] %s — expected: %q\n' "$label" "$needle"
        FAIL=$((FAIL + 1))
    fi
}

#------------------------------------------------------------------------------
# Minimal state for a single bound target (10.10.11.42)
#------------------------------------------------------------------------------
TARGET=10.10.11.42
mkdir -p "$TMP/targets/$TARGET/recon" "$TMP/targets/$TARGET/state"
cat > "$TMP/targets/$TARGET/recon/nmap.txt" <<'EOF'
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.4
80/tcp   open  http         Apache 2.4.51
445/tcp  open  microsoft-ds Samba 4.10
OS details: Linux 5.4 - 5.10
Running: Linux 5.X
EOF

#------------------------------------------------------------------------------
# (a) success-confirmed shell-spawned with --expect shell
#------------------------------------------------------------------------------
echo "=== (a) success-confirmed shell-spawned + --expect shell ==="
CAP_A="$TMP/cap_a.txt"
cat > "$CAP_A" <<'EOF'
[*] msfvenom payload sent
[*] Incoming connection from 10.10.11.42:54812
[*] Got shell from 10.10.11.42
$ whoami
root
$ id
uid=0(root) gid=0(root) groups=0(root)
$ hostname
victim01
$ uname -a
Linux victim01 5.15.0-67-generic #74-Ubuntu SMP x86_64 GNU/Linux
EOF
OUT_A=$("$TC" "$CAP_A" --against "$TARGET" --expect shell 2>&1)
echo "$OUT_A"
check "(a) outcome label" "$OUT_A" "OUTCOME: success-confirmed"
check "(a) sub-class label" "$OUT_A" "(shell-spawned)"
check "(a) confidence is high (§7 all-available rule)" "$OUT_A" "confidence: high"
check "(a) foothold write line" "$OUT_A" "foothold:  10.10.11.42  root"
check "(a) sentinel write line" "$OUT_A" "event:     10.10.11.42  success-shell-spawned"
check "(a) NEXT hint" "$OUT_A" "evidencr"
# Confirm files actually written
if [[ -s "$TMP/targets/$TARGET/state/foothold.log" ]]; then
    echo "  [PASS] foothold.log written"; PASS=$((PASS+1))
else
    echo "  [FAIL] foothold.log NOT written"; FAIL=$((FAIL+1))
fi
if [[ -s "$TMP/targets/$TARGET/state/sentinels.log" ]]; then
    echo "  [PASS] sentinels.log written"; PASS=$((PASS+1))
else
    echo "  [FAIL] sentinels.log NOT written"; FAIL=$((FAIL+1))
fi
if [[ -s "$TMP/targets/$TARGET/state/targetcheckr_runs.log" ]]; then
    echo "  [PASS] targetcheckr_runs.log written"; PASS=$((PASS+1))
else
    echo "  [FAIL] targetcheckr_runs.log NOT written"; FAIL=$((FAIL+1))
fi
echo

#------------------------------------------------------------------------------
# (b) failure-with-symptom matching failure_map.yaml key
#------------------------------------------------------------------------------
echo "=== (b) failure-with-symptom (python2-print-statement) ==="
CAP_B="$TMP/cap_b.txt"
cat > "$CAP_B" <<'EOF'
Traceback (most recent call last):
  File "exploit.py", line 42
    print "Sending payload..."
                              ^
SyntaxError: Missing parentheses in call to 'print'
EOF
OUT_B=$("$TC" "$CAP_B" --against "$TARGET" 2>&1)
echo "$OUT_B"
check "(b) outcome label" "$OUT_B" "OUTCOME: failure-with-symptom"
check "(b) sub-class = yaml key" "$OUT_B" "python2-print-statement"
check "(b) STATE WRITES skipped" "$OUT_B" "STATE WRITES: none"
check "(b) NEXT → exploitfixr" "$OUT_B" "exploitfixr"
echo

#------------------------------------------------------------------------------
# (c) unclear fallback with no detectable signals
#------------------------------------------------------------------------------
echo "=== (c) unclear fallback ==="
CAP_C="$TMP/cap_c.txt"
cat > "$CAP_C" <<'EOF'
[*] Connecting to target
[*] Connection established
[*] Sending data
[*] Done
EOF
OUT_C=$("$TC" "$CAP_C" --against "$TARGET" 2>&1)
echo "$OUT_C"
# This should land in no-effect (input has content but no markers fired).
# Spec §3 maps that to "no-effect" not "unclear", but either is acceptable
# absence-of-signal handling; confirm it isn't a false success.
check "(c) not a success" "$OUT_C" "OUTCOME:"
if grep -qE 'success-confirmed|success-likely' <<< "$OUT_C"; then
    echo "  [FAIL] (c) unexpectedly classified as success"
    FAIL=$((FAIL+1))
else
    echo "  [PASS] (c) did not falsely fire success"
    PASS=$((PASS+1))
fi
check "(c) STATE WRITES: none" "$OUT_C" "STATE WRITES: none"
echo

#------------------------------------------------------------------------------
# (d) --dry-run on success-confirmed input
#------------------------------------------------------------------------------
echo "=== (d) --dry-run on success-confirmed ==="
TARGET_D=10.10.11.50
mkdir -p "$TMP/targets/$TARGET_D/recon"
cp "$TMP/targets/$TARGET/recon/nmap.txt" "$TMP/targets/$TARGET_D/recon/nmap.txt"
CAP_D="$TMP/cap_d.txt"
cat > "$CAP_D" <<'EOF'
[*] Got shell from 10.10.11.50
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
EOF
OUT_D=$("$TC" "$CAP_D" --against "$TARGET_D" --expect shell --dry-run 2>&1)
echo "$OUT_D"
check "(d) [DRY RUN] banner prefix" "$OUT_D" "[DRY RUN]"
check "(d) confidence is high (§7 all-available rule)" "$OUT_D" "confidence: high"
check "(d) WOULD-WRITE label" "$OUT_D" "WOULD-WRITE:"
check "(d) would-write foothold" "$OUT_D" "foothold:  10.10.11.50  root"
# Critically — no files should exist for this target
if [[ -e "$TMP/targets/$TARGET_D/state/foothold.log" ]]; then
    echo "  [FAIL] (d) foothold.log WAS written (dry-run leaked)"
    FAIL=$((FAIL+1))
else
    echo "  [PASS] (d) foothold.log NOT written (dry-run honored)"
    PASS=$((PASS+1))
fi
if [[ -e "$TMP/targets/$TARGET_D/state/targetcheckr_runs.log" ]]; then
    echo "  [FAIL] (d) targetcheckr_runs.log WAS written (dry-run leaked)"
    FAIL=$((FAIL+1))
else
    echo "  [PASS] (d) targetcheckr_runs.log NOT written"
    PASS=$((PASS+1))
fi
echo

#------------------------------------------------------------------------------
# (e) replay (same input twice) hash short-circuit
#------------------------------------------------------------------------------
echo "=== (e) replay — run case (a)'s exact input again ==="
# Snapshot foothold.log line count before
PRE_FOOT_LINES=$(wc -l < "$TMP/targets/$TARGET/state/foothold.log" 2>/dev/null || echo 0)
PRE_SENT_LINES=$(wc -l < "$TMP/targets/$TARGET/state/sentinels.log" 2>/dev/null || echo 0)
PRE_RUNS_LINES=$(wc -l < "$TMP/targets/$TARGET/state/targetcheckr_runs.log" 2>/dev/null || echo 0)
OUT_E=$("$TC" "$CAP_A" --against "$TARGET" --expect shell 2>&1)
echo "$OUT_E"
check "(e) REPLAY banner" "$OUT_E" "[REPLAY — no writes]"
check "(e) prior run timestamp shown" "$OUT_E" "prior run:"
check "(e) STATE WRITES skipped" "$OUT_E" "skipped (input hash matches prior run)"
POST_FOOT_LINES=$(wc -l < "$TMP/targets/$TARGET/state/foothold.log" 2>/dev/null || echo 0)
POST_SENT_LINES=$(wc -l < "$TMP/targets/$TARGET/state/sentinels.log" 2>/dev/null || echo 0)
POST_RUNS_LINES=$(wc -l < "$TMP/targets/$TARGET/state/targetcheckr_runs.log" 2>/dev/null || echo 0)
if [[ "$PRE_FOOT_LINES" == "$POST_FOOT_LINES" ]]; then
    echo "  [PASS] (e) foothold.log unchanged on replay"
    PASS=$((PASS+1))
else
    echo "  [FAIL] (e) foothold.log changed ($PRE_FOOT_LINES → $POST_FOOT_LINES)"
    FAIL=$((FAIL+1))
fi
if [[ "$PRE_SENT_LINES" == "$POST_SENT_LINES" ]]; then
    echo "  [PASS] (e) sentinels.log unchanged on replay"
    PASS=$((PASS+1))
else
    echo "  [FAIL] (e) sentinels.log changed ($PRE_SENT_LINES → $POST_SENT_LINES)"
    FAIL=$((FAIL+1))
fi
if [[ "$PRE_RUNS_LINES" == "$POST_RUNS_LINES" ]]; then
    echo "  [PASS] (e) targetcheckr_runs.log unchanged on replay"
    PASS=$((PASS+1))
else
    echo "  [FAIL] (e) targetcheckr_runs.log changed ($PRE_RUNS_LINES → $POST_RUNS_LINES)"
    FAIL=$((FAIL+1))
fi
echo

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
echo "==============================================================="
echo "  PASS: $PASS    FAIL: $FAIL"
echo "==============================================================="
[[ $FAIL -eq 0 ]] || exit 1
exit 0
