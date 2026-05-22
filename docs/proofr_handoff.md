# proofr — build handoff (build 8 of 8)

> For the next Code session. This is a **briefing, not a spec**. proofr's design
> is deliberately left open (see §5) — do not treat anything here as locked.
> Read §0 and §3 before you do anything else.
>
> Authored 2026-05-21, immediately after orient (build 7) shipped. Every code
> reference below is line-anchored and was verified against the live tree on that
> date. Re-verify before trusting any of it — the tree drifts.

---

## §0 How to read this handoff (path discipline)

- **Do not cite section numbers from memory.** To navigate any spec, grep its real
  headers first: `grep -nE '^#{1,3} ' docs/orient_spec.md`. The orient handoff
  pointed at a `livefetch_spec.md §0` that never existed; that cost a confused
  lookup. Reference sections by their *actual* headers, after you've grep'd them.
- **Verified `orient_spec.md` section map** (grep'd 2026-05-21, cite these, not a
  remembered numbering): §1 Purpose & role · §2 Input→output mapping (+ §2.1 SMB
  normalization) · §3 Instance fan-in (Web + AD) · §4 CLI · §5 Idempotency · §6
  The three livefetch findings · §7 Write surface · §8 Boundaries · §9 Open
  verification items (Phase 0) · §10 Build protocol · §11 Out of scope (this file).
- Line numbers in this handoff (`state.sh:NNN`) were live on 2026-05-21. If they
  point at something other than what's described, the file moved — re-grep, don't
  trust the number.

---

## §1 Toolkit snapshot — where the suite stands

- **Seven numbered builds shipped** (builds 1–7); orient is the latest (commits
  `bceffbd` + `496a767`). proofr is **build 8, the last**.
- **Three layers, now bridged:**
  - *Collection layer* — `recon.sh` / `webenum.sh` / `adr.sh` write
    `$TOOLKIT_ROOT/{recon,web,ad}/…`.
  - *Bridge* — **orient.sh** (build 7) normalizes collection → decision.
  - *Decision layer* — operator-facing tools (`stuckr`, `targetcheckr`, `watchdog`,
    `livefetch`) read `$TOOLKIT_ROOT/targets/<ip>/…` via `lib/state.sh`.
- **All 7 test suites green:** `test_state`, `test_exploitfixr_smoke`,
  `test_stuckr_demo`, `test_targetcheckr_demo` (28), `test_watchdog_demo` (21),
  `test_livefetch_demo` (25), `test_orient_demo` (31).
- **House style locked** (AGENTS.md §6, verify there): `#!/usr/bin/env bash`;
  `set -o pipefail` and **never `set -e`**; banner block (PURPOSE/WORKFLOW/USAGE/
  OUTPUT/DESIGN); `info/success/warn/error/ts` helpers; **`warn`/`error` → stderr**;
  `TOOLKIT_ROOT` resolved via `$SUDO_USER`; quote everything; config-at-top;
  shellcheck-clean.
- **proofr is a different animal.** stuckr/watchdog/livefetch are *operator-facing
  decision tools* — read state, tell the operator what to do next. proofr is the
  bridge from those to the **engagement deliverable**: different audience (the grader),
  different shape (see §5). Do not assume it inherits their CLI or output model.

---

## §2 What just shipped (build 7 — orient)

- **`orient.sh`** — collection→decision bridge. Pure bash (no Python sidecar),
  full-file-replacement idempotency, operator-driven `--web-host` / `--domain`
  association, no new `state.sh` writers, no sentinel/evidence/creds writes.
  Validated end-to-end against the real `192.168.233.98` tree, not just fixtures.
- **`tests/test_orient_demo.sh`** — 31 assertions, run *through the real
  `state_read_target` / `state_read_global`* (contract-level, not output-shape).
  Covers every `orient_spec.md` §2 row plus the Phase-0 findings (⚠2–⚠6).
- **`docs/orient_spec.md`** — redlined then Phase-0-corrected. Read the **final
  version on disk**, not any pasted draft from chat history.
- **Phase 0 earned its keep** (see §3): two transforms the draft spec asserted as
  verified turned out wrong against real artifacts.

---

## §3 The verify-before-spec gate — NON-NEGOTIABLE

**Do not write a single line of proofr spec before reading, on disk, today:**

1. **`lib/state.sh`** in full — the reader API (`state_read_target`,
   `state_read_global`, `state_read_footholds`, `state_read_pivots`) *and* the
   writer API (`state_write_foothold`, `state_append_cred`, `state_write_event`).
   proofr is the heaviest state consumer of all 8 tools.
2. **`docs/orient_spec.md`** (final) — the decision-layer paths and shapes proofr
   will read are defined by orient's output contract.
3. **A real sample of orient's output** — e.g. `ls -R ~/toolkit/targets/192.168.233.98/`
   then `cat` the files. See what the data actually looks like before you spec a
   reader for it.

**Track record (this is not hypothetical):** across the 7 builds, Phase 0 has
caught speculation-rebadged-as-verified at least twice — in orient alone:
- *⚠5* — the spec "verified" that `adr.sh` appends **raw** `user:[x] rid:[…]`
  lines to `all_users.txt`. The live `adr.sh:778` already strips them with
  `grep -oP 'user:\[\K[^\]]+'` before append. The whole rpcclient-stripping awk
  (and a gawk-only `match()` dependency) was unnecessary → reverted to copy-verbatim.
- *⚠2* — the spec "verified" ffuf text is a bare-URL format. The real
  `ffuf_json_to_text` emits a two-column **FUZZ + URL** layout, and the on-disk
  file was header-only (wildcard-filtered). The parser still worked, but for a
  different reason than the spec claimed.

Expect proofr to make a **third**. Every input source proofr names must be
verified against the actual on-disk file, never constructed from a plausible
pattern (orient §6, "marker discovery discipline"). The gate is what catches it.

---

## §4 The live deferred defect — proofr's job, NOT optional

`state_read_global`'s credential reader is broken and proofr inherits the fix. It
is the heaviest `state_read_global` consumer; **without this fix every cred line
proofr emits is garbage.**

**The defect (verified `lib/state.sh` 2026-05-21):**
- Reader `state_read_global()` (`state.sh:228-246`) reads
  `creds_f="$gd/creds/creds.txt"` (`state.sh:230`) — the **wrong path** — and
  parses it with `_state_parse_lines` (`state.sh:234`), which emits the *whole
  line*.
- The **authoritative** creds file is `$TOOLKIT_ROOT/creds.txt` (`state.sh:337`; the
  contract comment at `state.sh:307` says explicitly "NOT `$TOOLKIT_ROOT/creds/creds.txt`").
- Its schema is **6 pipe-separated fields**: `TIMESTAMP | PROTO | HOST | USER |
  CRED | NOTE` (`state.sh:308`). USER = field 4, CRED = field 5 (dedupe at
  `state.sh:347`).
- So today the reader either finds nothing (wrong path) or, if pointed right,
  emits `cred=2026-05-20 16:00:00 | exploit | - | jdoe | Summer2026! | note`
  instead of the documented `cred=jdoe:Summer2026!` (`state.sh:32`).

**The fix proofr must land:**
- Rewrite `state_read_global`'s cred branch to read `$TOOLKIT_ROOT/creds.txt` and
  parse with `awk -F'|'`: trim whitespace, take field 4 (USER) and field 5 (CRED),
  emit `cred=USER:CRED`; skip malformed lines (`NF < 6`).
- **Read `sprayr.sh::parse_creds_file` first** — `state.sh:310` names it the
  canonical reader of this schema (`awk -F'|', fields 4/5/6`). Match its field
  handling exactly; verify it on disk before writing the new reader.
- **Do NOT touch the writer or the schema.** `state_append_cred`
  (`state.sh:320-361`) and sprayr's reader are a co-evolved contract; only the
  *reader* is wrong. Changing the schema breaks `sprayr --from-creds`.
- This is the **first `state.sh` change since watchdog** (orient deliberately made
  none). Treat it as a real, tested change — add coverage to `test_state.sh` and
  re-run all 7 suites.

---

## §5 What proofr actually is — DESIGN FROM FIRST PRINCIPLES (not locked here)

The orient handoff called proofr "generates the report." **That is
underspecified — do not anchor on it.** Design proofr in its own session from the
inputs below; this handoff records the inputs, not the answer.

**Design inputs to reconcile (none is the spec):**
- **`IDEATION_REPORT_2026-05-20.md`** (grep `proofr`): *"B6 + B9 bundle —
  `proofr.sh` + `controlpanelr.sh`. Closes the two known endgame failure modes:
  incomplete proof screenshots (forgotten `ip a`) and unsubmitted flags (zero
  points despite capture). Built together, they share state with evidencr and
  reuse the same TUI pattern."* → proofr ≈ **proof-completeness auditor**;
  controlpanelr ≈ flag-submission tracker.
- **`orient_spec.md` §6 / §11** → proofr = heaviest `state_read_global` consumer,
  owner of the §4 creds fix → it reads state heavily (creds, footholds, proof).
- **AGENTS.md §9** (the engagement rubric, the real requirements doc): every compromise
  needs *screenshots + `whoami` + `hostname` + flag from the original path*, from
  an *interactive shell* (web shells don't count); *flags must be submitted to the
  control panel* before time expires.
- **`evidencr.sh`** (AGENTS.md §5: "Evidence capture — terminal logs, screenshots,
  per-target orgs") — likely proofr's primary upstream. Read it and its output
  paths before specing any reader.

**Open questions the design session must answer (do not pre-decide):**
1. **What is in the output?** Per-target proof checklist? reproducibility chain the
   grader walks? cred/service inventory? gap audit ("target X missing `ip a`")?
2. **What format?** A markdown report matching the OffSec template? a TUI checklist
   like evidencr? a machine-readable gap list? Plain `.txt`?
3. **What triggers it?** Manual per-target? `--all` sweep? an end-of-engagement pass?
4. **What reads what?** `targets/<ip>/evidence/{local,proof}.txt` (orient does NOT
   write these — see orient §2/§7), `state_read_*`, evidencr's captures,
   `findings.sqlite`? Verify each on disk (§3).
5. **Is `controlpanelr` in scope for build 8?** The IDEATION_REPORT bundles them;
   the orient spec names only proofr as build 8. Decide scope explicitly and early.
6. **Audience = the grader, not the operator.** Justify every output element
   against "does this make the graded report tighter / harder to forget a flag,"
   not against operator decision-making.

---

## §6 The dormant concern — `warn()` → stdout on 13 scripts

`warn()` writing to stdout silently corrupts any `--json` / machine-readable
output (the warning lands in the parsed stream). Verified 2026-05-21: **15 scripts
define `warn()`; 13 still write to stdout; only `livefetch.sh` and `orient.sh`
redirect to stderr.**

Stdout (the dormant bug): `adr.sh`, `escalatr.sh`, `evidencr.sh`, `startr.sh`,
`exploitfixr.sh`, `lootr.sh`, `recon.sh`, `pivotr.sh`, `servr.sh`,
`sprayr.sh`, `stuckr.sh`, `targetcheckr.sh`, `webenum.sh`.

> (The orient handoff said "14 scripts" — the verified count is **13**. Cited here
> as a live example of §3: check the number, don't carry it.)

**It only bites proofr if proofr grows a `--json` / structured mode.** If it does,
fix `warn()` → `>&2` *in proofr itself* (one line, like `livefetch.sh:65`) and do
not "while I'm here" the other 13 — that's a separate, scoped change and a
batch-edit to 13 working scripts is the kind of cleanup AGENTS.md §7 rejects on
sight. If proofr stays plain-text, no action.

---

## §7 Build protocol (mirror orient §10)

1. **Phase 0 (the §3 gate).** Read `state.sh`, `orient_spec.md` (final), and a real
   `~/toolkit/targets/<ip>/` sample. Verify the `sprayr.sh::parse_creds_file` schema
   and every input source proofr will read. **Halt** if anything doesn't match.
2. **Design session** — answer §5's open questions, decide controlpanelr scope,
   produce `docs/proofr_spec.md`. Design halt for review before code.
3. **Write `proofr.sh`** + the `state_read_global` creds-reader fix in `lib/state.sh`
   (§4). Single file, house style, shellcheck-clean.
4. **Write `tests/test_proofr_demo.sh`** — assertion model mirrors
   `test_orient_demo` / `test_livefetch_demo` (assert through the real readers).
   Add `state.sh` cred-reader coverage to `test_state.sh`.
5. **Run all 7 prior suites + the new one; confirm green.**
6. **Commit:** `proofr: build 8 of 8 — <desc>` (repo convention is
   `<tool>: build N of M — <desc>`, not `feat:`; see `git log --oneline`).

---

*Single-file entry point for the proofr chat. Start at §3, not §1.*
