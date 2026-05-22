# proofr.sh — design spec (build 8 of 8)

> Status: **design draft (2026-05-21)**, written against the resolved tool
> identity (state↔evidence auditor — IDEATION B6's "screenshot compositor" was
> rejected in the design halt: it adds deps, automates a live shell, overlaps
> evidencr, and does not use the §4 creds fix). Every input below was verified on
> disk during Phase 0 (see §9). Re-verify before trusting any line ref — the tree
> drifts. Awaiting a five-part critique + "go" before code lands (§10).

---

## §1 Purpose & role

`proofr.sh` is the **proof-of-compromise auditor**. It reconciles two independent
sources of truth and reports where they diverge:

- **Decision-layer state** — what the toolkit recorded *happened* on a box:
  footholds (`state_read_footholds` ← targetcheckr's `foothold.log`), captured
  credentials (`state_read_global`, after the §7 fix), and recon context
  (`state_read_target`).
- **Evidence-layer captures** — what the operator *documented for the grader*:
  evidencr's ledger, per-IP flag files, and screenshot audit.

proofr answers one question, per target and engagement-wide: **"For every box I touched,
is the grader-required proof complete and self-consistent — or did I compromise
something I haven't fully documented?"** It emits *documented / missing /
inconsistent*, with the concrete next action for each gap.

**What proofr is NOT (binding guardrails from the design halt):**

- **Not a report generator.** "Proof" = proof-of-compromise auditing, not report
  writing. The OffSec report is operator-written from evidencr's outputs +
  screenshots + the engagement template. proofr's output ends at the gap list. **No
  markdown/PDF report emitter.** If a report-template writer appears, it has drifted.
- **Not a writer to evidencr's surface.** Reads the ledger, `flags/*.txt`, and the
  screenshot audit; never writes them. One-directional, like orient.
- **Not a state mutator.** No sentinels, no foothold writes, no `state_*` write
  calls. Pure reader + reporter, parallel in shape to `stuckr.sh`.
- **Not a point-totaler.** `evidencr --rollup` already computes points/100 + PASS
  status (`evidencr.sh:976-1057`). proofr defers totals to it and references it;
  proofr's lane is *gaps & consistency*, not scoring. No overlap.

---

## §2 The compromise universe (which IPs proofr audits)

A box matters for a proof audit only if the toolkit shows the operator **engaged**
it. proofr's target set (for `--all`) is the sorted union of:

1. `state_list_targets` — dirs under `$TOOLKIT_ROOT/targets/` (`state.sh:262-266`).
2. Evidencr-recorded IPs — field 2 of `$TOOLKIT_ROOT/evidence/evidence_ledger.txt`,
   plus any `$TOOLKIT_ROOT/evidence/<ip>/` directory.
3. IPs with a non-empty `targets/<ip>/state/foothold.log` (via
   `state_read_footholds`).

Single-target modes (`proofr`, `proofr --on <ip>`) audit just that IP.

Each IP is then classified by **engagement signal**:

| Class | Signal | Proof expectation |
|---|---|---|
| `recon-only` | in `targets/` but no foothold.log, no ledger row | none — not owned; reported as context, not a gap |
| `engaged` | foothold.log entry exists | full per-target proof (§3) |
| `documented` | evidencr ledger row exists | completeness + consistency check (§3) |

The headline gap is **`engaged` but not `documented`**: foothold recorded, no
ledger entry → *"compromised, evidence not captured."* evidencr's own `--rollup`
cannot see this — it reads only the ledger, so a box never run through evidencr is
invisible to it. That blind spot is proofr's reason to exist.

> **Why not `state_read_target`'s `foothold`/`privesc`?** Phase 0 (§9, ⚠P3)
> confirmed **no tool writes `targets/<ip>/evidence/{local,proof}.txt`** — orient
> explicitly doesn't (`orient_spec.md` §7), and no other script does. So
> `state_read_target` (`state.sh:179-180`) reports `foothold=no`/`privesc=no`
> universally. proofr reads `state_read_target` for **os/services/web context
> only**, and takes the compromise signal from `foothold.log` + the ledger, never
> from the latent (unproduced) `foothold`/`privesc` keys.

---

## §3 Audit model — what is checked, against what

All sources verified in §9. Per-IP, proofr collects then reconciles:

**Sources (read-only):**

| Datum | Source (verified) | Reader |
|---|---|---|
| os / services / web | `targets/<ip>/recon/*`, `web/*` | `state_read_target <ip>` |
| foothold(s) | `targets/<ip>/state/foothold.log` | `state_read_footholds <ip>` (`state.sh:410-417`) — TSV `ip\tts\tuser\tmethod\tsrc` |
| ledger row | `$TOOLKIT_ROOT/evidence/evidence_ledger.txt` | direct `awk -F' *\\| *'`; **last row wins per IP** (append-only; newer run supersedes) |
| local flag | `$TOOLKIT_ROOT/evidence/<ip>/flags/local.txt` | direct read; line shape `[ts] VALUE`, VALUE may be `not collected` (`evidencr.sh:293-296`) |
| proof flag | `$TOOLKIT_ROOT/evidence/<ip>/flags/proof.txt` | same |
| missing shots | `$TOOLKIT_ROOT/evidence/<ip>/screenshots/missing_screenshots.txt` | non-empty ⇒ list (`evidencr.sh:850-854`) |
| msf marker | `$TOOLKIT_ROOT/evidence/<ip>/msf_used.flag` | existence (`evidencr.sh:650-652`) |
| creds (global) | `$TOOLKIT_ROOT/creds.txt` | `state_read_global` **after §7 fix** → `cred=USER:CRED` |
| domain / dc_ip | `$TOOLKIT_ROOT/ad/{domain,dc}.txt` | `state_read_global` (unchanged) |

**Ledger row field map (verified `evidencr.sh:896`, pipe-separated):**
`1 ts · 2 ip · 3 hostname · 4 os · 5 category · 6 points= · 7 local= · 8 proof= ·
9 foothold= · 10 elevated= · 11 msf= · 12 chain= · 13 dir=`. A flag field reads
`MISSING` (no value at append) or `not collected` (operator skipped).

**Per-target checks (only for `engaged`/`documented`):**

1. **Ledger presence** — `engaged` with no ledger row → GAP *"run `evidencr <ip>`"*.
2. **local flag** — ledger `local=` is `MISSING`/`not collected`, OR
   `flags/local.txt` absent / its newest value not UUID-shaped → GAP.
3. **proof flag** — same test on `proof=` / `flags/proof.txt`. Escalated to a
   **strong** gap when ledger `elevated=` names a real user (≠ `[not provided]`)
   or category is `AD-DC` — i.e. evidence says you went all the way but the proof
   flag is absent (the "rooted but proof unrecorded" case).
4. **Screenshots** — `missing_screenshots.txt` non-empty → GAP, list the names
   (AD boxes additionally expect `network_position.png`, `evidencr.sh:313-315`).
5. **Ledger ↔ flag-file consistency** — ledger `local=`/`proof=` shows a value but
   the corresponding `flags/*.txt` is absent/empty (or vice-versa) → INCONSISTENCY.

**engagement-wide checks (footer, `--all` or always-appended):**

6. **MSF limit** — count `evidence/*/msf_used.flag`; `>1` → **CRITICAL** (OffSec
   one-machine limit, AGENTS.md §9). Mirrors evidencr's warning but proofr treats
   it as a hard exit-code gate (§6).
7. **Cred inventory** — count of `cred=` lines from the fixed `state_read_global`;
   list users (not secrets) for the operator's Creds_Tracker cross-check. Zero
   creds is informational, not a gap.
8. **Roll-up line** — `N targets engaged · M fully documented · K with gaps`. No
   point total (deferred to `evidencr --rollup`).

**Interactive-shell caveat (non-disk):** the rubric requires proof from an
interactive shell (web shells don't count). proofr cannot verify shell type from
disk, so where a proof flag exists it prints a one-line reminder, not a gap.

---

## §4 Invocation modes / CLI (mirror stuckr.sh)

```
proofr                      # audit the inferred target (cwd → .evidencr/last_target)
proofr --on <ip>            # audit one explicit target
proofr --all                # audit every engaged target + engagement-wide footer
proofr --no-color           # disable ANSI (also: NO_COLOR=1 / non-tty)
proofr --help
```

- Target inference chain matches stuckr (`stuckr.sh:134-154`): cwd under
  `$TOOLKIT_ROOT/targets/<ip>/` → `$TOOLKIT_ROOT/.evidencr/last_target` → error if none.
- `lib/state.sh` sourced via `SCRIPT_DIR` (`stuckr.sh:49,128`).
- **No `--json`.** proofr stays plain-text, so the dormant `warn()→stdout` concern
  (`proofr_handoff.md` §6) never bites. proofr defines `warn`/`error` → **stderr**
  from the start (one line, like `livefetch.sh:65`); it does **not** touch the
  other 13 scripts.
- **No file artifact, no `-o`.** Output is stdout only (operator redirects if they
  want a file). This honors "no report generation" and "no evidencr-surface
  mutation" — proofr writes nothing to disk. *(Flagged as an open decision in §11.)*

---

## §5 Output shape (single-screen per target, like stuckr §8)

Plain text, ANSI-colored when tty. Per target:

```
═══ 192.168.233.98  (hostname: web01 · linux · standalone · 20 pts) ═══
  engagement : foothold.log → www-data via web-rce-upload (2026-05-21T14:02)
  documented : ledger ✓   local ✓   proof ✗   screenshots 2 missing
  GAPS (3):
    [proof]   proof.txt flag not recorded — elevated=root in ledger but proof MISSING
    [shots]   missing: proof_root.png, network_position.png
    [shots]   capture from an INTERACTIVE shell (web shells are not valid proof)
```

`recon-only` targets collapse to one line (`… : recon-only, not owned — no proof
expected`). A target with zero gaps prints `… : fully documented ✓`.

engagement-wide footer (after the last target / always in `--all`):

```
─── engagement-wide ──────────────────────────────────────────────
  engaged: 4   fully documented: 2   with gaps: 2
  creds captured: 3  (jdoe, corp.com/admin, svc_sql)   → cross-check Creds_Tracker
  MSF markers: 1     (192.168.233.98)  [within OffSec limit]
  point total → run `evidencr --rollup`
```

---

## §6 Exit-code conventions (the machine-readable signal — no state writes)

proofr signals results to the operator and to any future gate (controlpanelr /
startr / a timekeeper) via exit code, **not** by writing state:

- `0` — every engaged target is fully documented and self-consistent (report-ready).
- `1` — one or more documentation gaps/inconsistencies exist (the normal "work
  remains" state).
- `2` — **CRITICAL**: MSF limit exceeded (`>1` marker), or an `engaged` target has
  no ledger entry at all (undocumented compromise). These are the catastrophic,
  points-losing cases that must not be missed.
- `3` — usage / no target could be inferred.

Idempotent: re-running with unchanged inputs yields identical output and exit code.

---

## §7 The `state_read_global` creds-reader fix (bundled, in scope)

This build is the **one** place that legitimately touches shared `lib/state.sh`;
it carries regression responsibility (§10).

**Defect (verified `state.sh:228-246`, 2026-05-21):** `state_read_global` reads
`creds_f="$gd/creds/creds.txt"` (`:230`) — the wrong path — and parses with
`_state_parse_lines` (`:234`), which emits the whole line. The authoritative file
is `$TOOLKIT_ROOT/creds.txt` (`:337`) with a 6-field pipe schema (`:308`).

**Fix:** rewrite only the cred branch of `state_read_global` to mirror
`sprayr.sh::parse_creds_file` (`sprayr.sh:1040-1050`):

```sh
local creds_f="${TOOLKIT_ROOT}/creds.txt"
[[ -r "$creds_f" ]] && awk -F'|' '
    NF >= 6 {
        u = $4; gsub(/^[[:space:]]+|[[:space:]]+$/, "", u)
        c = $5; gsub(/^[[:space:]]+|[[:space:]]+$/, "", c)
        if (u != "" && c != "" && !seen[u":"c]++) print "cred=" u ":" c
    }
' "$creds_f"
```

- Take field 4 (USER) / field 5 (CRED), trim, emit `cred=USER:CRED`, skip
  malformed (`NF<6` or empty), dedupe by `USER:CRED`.
- The cred side is taken **verbatim** (field 5), so colon-bearing secrets (NTLM
  `user:HASH:HASH:HASH`) round-trip correctly as `cred=user:HASH:HASH:HASH` — the
  documented `state.sh:32` shape, and what every consumer's `split(':',1)` expects.
- **Do not touch** the writer (`state_append_cred`, `:320-361`), the schema, or the
  `domain`/`dc_ip` branches. Reader-only change.

**Contract change — state it loudly:** today the reader points at a path that does
not exist, so `state_read_global` emits **zero** `cred=` lines; after the fix it
emits `cred=USER:CRED` for the first time. This is an **un-block, not a break** —
verified Phase 0 (§9, ⚠P4): every downstream consumer already parses `user:cred`
(`exploitfixr_classify.py:294`, `stuckr_rank.py:240-245`,
`targetcheckr_classify.py:220-221`), and `exploitfixr`'s `creds-available`
precondition (`:105`) currently can never fire. `livefetch` is unaffected — it
already bypasses `state_read_global` and reads `creds.txt` directly
(`livefetch.sh:423-435`); it is **not** modified.

---

## §8 Boundaries — what proofr does NOT do

- No exploitation, no target interaction (Kali-side reader only; AGENTS.md §2).
- No screenshot capture/composition (rejected IDEATION B6 — deps + live-shell automation).
- No report/template generation (operator's job).
- No writes to evidencr's surface, to `targets/<ip>/`, to `creds.txt`, or to any
  state log. The only file proofr's build modifies is `lib/state.sh` (§7).
- No point/PASS scoring (deferred to `evidencr --rollup`).
- No `findings.sqlite` access.
- No `--json`, no daemon, no watch mode, no new dependencies (pure bash + awk;
  python3 is **not** needed — there is no YAML/corpus ranking, unlike stuckr).
- **controlpanelr is out of scope** for build 8 (design-halt decision). proofr may
  surface a "captured but not submitted" gap; acting on it is a later build's job.

---

## §9 Phase 0 verification results (done 2026-05-21, against the live tree)

- **⚠P1 — line anchors RE-VERIFIED.** `state_read_global` `:228-246`; wrong path
  `:230`; `_state_parse_lines` `:234`; authoritative `creds.txt` `:337`; 6-field
  schema `:308`; dedupe `:347`; sprayr reader `sprayr.sh:1025-1051`. No drift.
- **⚠P2 — §4 fix proven against a producer-faithful fixture.** Generated
  `creds.txt` with the real `state_append_cred` writer; current reader emits
  nothing (wrong path); the §7 awk emits exactly `cred=jdoe:Summer2026!`,
  `cred=corp.com/admin:P@ssw0rd`, `cred=svc_sql:NTLM:…` (colon-in-cred round-trips).
- **⚠P3 — no producer for `targets/<ip>/evidence/`.** Grep across all `*.sh`:
  nothing writes `evidence/{local,proof}.txt` under `targets/`. So
  `state_read_target`'s `foothold`/`privesc` are always `no`; proofr's compromise
  signal is `foothold.log` (targetcheckr) + the ledger, **not** those keys (§2).
- **⚠P4 — cred consumers tolerate the new shape.** All parse `user:cred` via
  `split(':',1)` / `':' in c`; the fix un-blocks them rather than breaking them.
  `livefetch` independently reads `creds.txt` and is untouched.
- **⚠P5 — evidencr contract mapped.** `OUTDIR=$TOOLKIT_ROOT/evidence`; ledger header
  + 13-field row (`:647,:896`); per-IP `flags/{local,proof}.txt` (`:293-296`),
  `screenshots/missing_screenshots.txt` (`:850-854`), `msf_used.flag` (`:650-652`);
  `.evidencr/last_target` inference marker. evidencr `--rollup` already owns points.
- **On-disk reality:** the sample target has only `recon/` + `web/` (header-only
  feroxbuster), **no `evidence/`, `state/`, `ad/`, and no `creds.txt` anywhere** —
  proofr must treat every missing source as a normal empty state, never an error.

---

## §10 Build protocol (mirror orient §10 / handoff §7)

1. **Phase 0** — done (§9). ✅
2. **This spec** → **five-part critique** → **halt for "go"** before any code.
3. Write `proofr.sh` (single file, house style, shellcheck-clean, no python) +
   the §7 `state_read_global` cred-reader fix in `lib/state.sh`.
4. Write `tests/test_proofr_demo.sh` — synthetic fixtures under a temp `TOOLKIT_ROOT`,
   asserting **through the real readers** (mirrors `test_orient_demo` /
   `test_livefetch_demo`): each engagement class, each §3 gap, each exit code.
   Add `state_read_global` cred coverage to `tests/test_state.sh`.
5. Run all 7 prior suites + the new one; confirm green (the §7 change carries
   regression responsibility — `test_state`, `test_exploitfixr_smoke`,
   `test_stuckr_demo`, `test_targetcheckr_demo`, `test_watchdog_demo`,
   `test_livefetch_demo`, `test_orient_demo`).
6. Commit: `proofr: build 8 of 8 — state↔evidence proof-completeness auditor`.

---

## §11 Open decisions for the critique

1. **stdout-only vs. an audit file.** §4 specs stdout-only (cleanest; honors "no
   report generation / no surface mutation"; matches stuckr). The handoff said
   "reader + reporter to stdout/**file**." If a persisted artifact is wanted, the
   safe location is a **proofr-owned** path (e.g. `$TOOLKIT_ROOT/proofr/audit.txt`),
   never inside `evidence/`. Decide before coding.
2. **Exit-code `2` scope.** Is "engaged but no ledger entry" critical (`2`) or just
   a normal gap (`1`)? Specced as `2` because it's the catastrophic
   compromised-but-undocumented case, but it's debatable.
3. **Cred→host attribution.** §3 uses creds as a global inventory (USER:CRED only).
   `creds.txt` has a HOST field (col 3) proofr could read directly for per-box cred
   attribution, but that means parsing the collection layer outside the state API.
   Specced as global-only for now; flag if per-host attribution is wanted.
4. **`recon-only` verbosity in `--all`.** One line each, or suppressed entirely to
   keep the audit focused on owned boxes? Specced as one line each.
