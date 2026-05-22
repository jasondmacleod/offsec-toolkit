# Workflow Audit Report — end-to-end seam audit of the 8-build toolkit

> Status: **complete, findings only — no fixes applied** (2026-05-21).
> Scope: composition audit. Do the eight individually-correct tools work as one
> workflow, and does the playbook describe that workflow accurately?
> Companion suite: `tests/test_workflow_integration.sh` (63 assertions, green).
> Adjudication of bucket-1/2 items and any fixes are a **separate, commissioned pass.**

---

## 0. Method, scope, and the one honest boundary

**What this audit did.** For every seam where one tool's real on-disk output becomes
another tool's input, it (a) read the producer's *write-code* and the consumer's
*read-code* and compared them line-for-line, and (b) drove the actual tools in
sequence in `tests/test_workflow_integration.sh`, asserting tool N's real output is
correctly consumed by tool N+1's real parser — the integration layer the eight
per-tool suites never had (each of those tests one tool against synthetic fixtures
and stops).

**What it did not do (by design, per handoff).** It did not run the toolkit against
live engagement-style targets. That run — a human following the playbook with no AI — is
the operator's, and it is the thesis's first data point. This audit de-risks it.

**The one residual-risk boundary, stated plainly.** The static half verifies
*producer write-code vs consumer read-code*. It cannot catch a divergence between a
tool's **own write-code and its live runtime output** — e.g. an `nxc --computers`
build whose real banner differs from the orient ⚠6 fixture, or a `ffuf` version that
changes its JSON shape. Those are exactly what the operator's live run exercises;
Code cannot close them without running live targets. Where a seam's correctness rests
on a tool's runtime output rather than its source, it is marked **runtime-dependent**
in the table below and recorded as a Known Limitation (§7, bucket 3), not a pass.

---

## 1. Seam-by-seam verdict table

Verdict key: **HOLDS** = producer output and consumer parser agree, verified in code
and exercised end-to-end. **DRIFTS** = works today but a latent mismatch/comment is
wrong. **BROKEN** = a real defect. Line refs are `file:line`.

| # | Seam | Verdict | Evidence (producer → consumer) |
|---|------|---------|-------------------------------|
| **S1a** | recon nmap → orient → os/services | **HOLDS** | `recon.sh:1043` writes `scans/nmap_tcp.nmap` → `orient.sh:238-239` copies verbatim → `state.sh:62-86,178-188` parses. Integ S1/S1e green. |
| **S1b** | recon SMB → orient → smb_share | **HOLDS** | `recon.sh:1443-1462` writes `tcp/smb/{smbclient_list,netexec_shares,smbmap_*}.txt` → `orient.sh:169-180` (the ⚠4 netexec `$5` guard) → `state.sh:140-153`. Integ asserts no `Share`/`[*]` leak. |
| **S1c** | webenum → orient → web_path/web_vhost | **HOLDS** (runtime-dependent on ffuf) | `webenum.sh:932,1175` write `artifacts/content/{dirs,files}_medium.txt` + `vhosts/hosts_entries.txt`; `ffuf_json_to_text` `has_input` row carries full URL (`webenum.sh:1873`) → `orient.sh:199-214` → `state.sh:92-111`. Empty (wildcard-filtered) file is valid (⚠2). Integ S1/S3a green. |
| **S1d** | adr → orient → ad_user/computer/domain/dc | **HOLDS** (runtime-dependent on nxc) | `adr.sh:2180` OUTDIR=`ad/<DOMAIN>`; `:1182-1200` write `computers/{nxc_computers,all_computers}.txt`, `:327` `users/all_users.txt` → `orient.sh:218-268` (⚠6 `$`-suffix machine-acct key) → `state.sh`. Integ S1e/S2 green. |
| **S2** | orient → decision tools | **HOLDS** | every `orient.sh` output path is the exact file a `state.sh` reader opens (`orient.sh:29-35` maps each to `state.sh:165-258`); stuckr/targetcheckr/exploitfixr read through `state_read_target`/`state_read_global`. Integ S1 asserts stuckr leaves empty-recon mode only after orient. |
| **S3a** | state writers ↔ readers (schema) | **HOLDS** | `state_append_cred` 6-field pipe (`state.sh:371`) ↔ `state_read_global` fields 4/5 (`:241-249`); `state_write_foothold` 4-field (`:312`) ↔ `state_read_footholds` 5-col TSV (`:429`); `state_write_event` (`:405`) ↔ `_state_parse_sentinels` (`:128`). Integ S1/S7 round-trips. |
| **S3b** | §7 cred write → read → 3 consumers | **HOLDS** | targetcheckr `state_append_cred` → `creds.txt` → `state_read_global` `cred=USER:CRED` → proofr inventory (`proofr.sh:422-435`), stuckr subst (`stuckr_rank.py:241-245`), exploitfixr `creds-available` (`exploitfixr_classify.py:78,105`). Round-trips `DOMAIN\user` and colon-bearing NTLM. Integ S2 green. |
| **S4** | evidencr → proofr | **HOLDS** | ledger 13-field (`evidencr.sh:896`) ↔ proofr parser (`proofr.sh:254`); flags `[ts] VALUE` (`evidencr.sh:295`) ↔ `flag_file_value` (`proofr.sh:171-180`); placeholders `[not provided]`/`not collected`/`MISSING` (`evidencr.sh:68-72`) ↔ `flag_is_real`/`L_elev` (`proofr.sh:157-166,326`); `msf_used.flag` (`:651`), `missing_screenshots.txt` (`:527`). **Fixture conformance asserted at runtime** against `evidencr.sh` (integ Guard block). Integ S1/S3b–d green. |
| **S5** | sentinel/marker namespaces | **HOLDS w/ one BROKEN sub-case** | `state_emit_empty` symptoms + targetcheckr `success-*` + watchdog `success-liveness-*` + livefetch `success-livefetch-*` share `sentinels.log`; watchdog filters by exact prefix (`watchdog.sh:220`); no symptom-map key collides with a `success-*` key (positive vs negative naming). **Sub-case BROKEN:** positive-event keys leak into stuckr's symptom-emptiness gate — see Finding **F-1**. |
| **S6** | targetcheckr → watchdog (cold-start) | **HOLDS** | classifier emits `success-shell-spawned` (`targetcheckr_classify.py:769`) → watchdog cold-start ALIVE (`watchdog.sh:227`) → ALIVE→DEAD writes `success-liveness-shell-died` (`:238`). Integ S1 drives this with **real** targetcheckr output. |
| **S7** | foothold.log schema round-trip | **HOLDS** | `state_write_foothold` 4 space-fields → `state_read_footholds` 5-col TSV (`state.sh:429`) → watchdog `cut -f1` (`watchdog.sh:179`) + proofr `tail -1` 5-field read (`proofr.sh:244`). Integ S1 feeds the real reader output as watchdog's surface. |
| **S8** | watchdog → livefetch (`--json`) | **HOLDS** | `watchdog_classify.py:555` emits `resources[].{type,ip,class}` → `livefetch.sh:469-471` parses same keys. (Exercised by `test_livefetch_demo`/`test_watchdog_demo`; static contract match.) |
| **S9** | pivotr → watchdog | **HOLDS** | `pivots/state.tsv` (pivotr) → `state_read_pivots` read-only mirror (`state.sh:440-444`) → watchdog tunnel baseline. Covered by `test_watchdog_demo` cases 5/7/11. |
| **S10** | proofr exit codes as gate | **HOLDS** | 0/1/2/3 monotonic via `bump_rc` (`proofr.sh:142`), defined `:39-44`; no collision with the success-side exit conventions of the other tools. Integ S1/S3b/S3c assert 0/2. |

**Cross-producer merge (handoff note 1) — is it its own seam?** **No — and the report
states why.** The three collection producers write **disjoint subtrees**
(`recon/`, `web/`, `ad/`); orient fans them into **disjoint decision-layer files**
(`recon/nmap.txt`, `recon/smb.txt`, `web/feroxbuster.txt`, `web/vhosts.txt`,
`ad/users.txt`, `ad/computers.txt`). There is **no path two producers both write**,
and **no decision-layer file orient fills from two producers** — so there is no
collision or last-writer-wins contention at the merge. A half-written tree (a
producer that hasn't run yet) is safe by construction: orient guards each source
(`orient.sh:243,250,259`), writes only what exists, and `state_read_target` is
missing-file-safe; re-running orient after the late producer finishes is additive
(full-file replacement, no clobber of the others). The genuine fan-in that *does*
warrant coverage — **multiple `web/<host>_<port>_<proto>/` instances for one IP
merging into one `feroxbuster.txt`**, and the partial→full re-orient — is exercised
by integration scenario **S1e** (both web ports' paths land in the single file;
recon-only tree yields coherent partial state; web arriving later is additive).

---

## 2. Integration-test results — `tests/test_workflow_integration.sh`

**63/63 assertions pass.** Additive: touches no existing tool or suite. Full
regression confirmed — the new suite plus all eight prior suites are green:

| Suite | Result |
|---|---|
| test_workflow_integration (new) | **PASS 63 / FAIL 0** |
| test_state | PASS (creds 7/0) |
| test_stuckr_demo | exit 0 |
| test_exploitfixr_smoke | exit 0 |
| test_targetcheckr_demo | PASS 28 / 0 |
| test_watchdog_demo | PASS 21 / 0 |
| test_livefetch_demo | PASS 25 / 0 |
| test_orient_demo | PASS 31 / 0 |
| test_proofr_demo | PASS 36 / 0 |

Scenario coverage: **S1** standalone spine (recon→orient→stuckr→targetcheckr foothold
→watchdog liveness→evidencr→proofr, exit 0); **S1e** one-orient-run 3-producer merge +
2-instance web fan-in + half-written tree; **S2** the §7 cred chain end-to-end through
all three consumers; **S3** adversarial (wildcard-empty web; engaged-no-ledger → exit
2; MSF×2 → exit 2; stale ledger + below-real "not collected"; success-* sentinel
namespace); **S4** boundary (missing/empty/malformed → graceful, never crash).

> One assertion failed on first run and was a **test bug, not a toolkit bug**: the
> cred-dump detector emits the Windows `DOMAIN\user` convention, so the round-tripped
> value is `corp.com\svc_sql:…` (backslash); the assertion had used `/`. Corrected to
> match the real, correct output. Recorded here for transparency.

---

## 3. Playbook-fidelity findings

**Flag/path verification — all clean.** Every command in `OffSec_Toolkit_Playbook.md`
(§2 order, §3 table, §4 loops) and `OffSec_Exam_Methodology_Complete.md` toolkit
callouts was checked against the real arg parsers and write paths. **Every flag and
output path exists as written**, including `startr -f/--recon`, `recon
--auto/--quick-wins-only` + `recon/target_priority.txt`, `webenum --from-recon/--url/
--vhost/--deep`, `evidencr -t/-n/--os/--flags/--rollup`, `adr -d/-u/-p/-dc(=`-dc|--dc-ip`,
adr.sh:2124)/--quick`, `crackr -q/-f/-H/-m/-e/--cewl/--hydra`, `sprayr --from-creds`,
`pivotr ligolo/--subnet/--serve/reconnect`, and the layer ordering
(collection→bridge→decision→audit). The exit-code meanings in the §3 table match the
tools' real codes (orient/stuckr/targetcheckr/watchdog/livefetch/proofr).

**Four documentation discrepancies — reported verbatim, NOT adjudicated** (per
instruction; adjudication and any doc fix are the separate pass):

- **D-1 — tool count.** `OffSec_Toolkit_Playbook.md:12`: "The **what-do-I-run-next**
  spine for the **9-tool engagement toolkit**." vs `OffSec_Exam_Methodology_Complete.md:18`:
  "**8-build toolkit** (`orient` · `stuckr` · `targetcheckr` · `watchdog` · `livefetch`
  · `proofr`)". The two docs state different counts.
- **D-2 — orient-prerequisite claim.** `OffSec_Exam_Methodology_Complete.md:995`: "Both
  require `orient` to have run for the target." (re `targetcheckr` + `watchdog`).
  Code reality (recorded, not adjudicated): `watchdog` reads `foothold.log`
  (`state_read_footholds`) and `pivots/state.tsv` (`state_read_pivots`) — neither is
  written by `orient`; `targetcheckr`'s foothold/cred writes need only `--against <ip>`.
  The playbook §1 hard-rule ("decision and audit tools read near-empty until `orient`
  has run") is the same claim's general form.
- **D-3 — exploitfixr attribution.** `OffSec_Toolkit_Playbook.md:100`: "`exploitfixr` is
  *surfaced by* `stuckr`, not run from this spine." Code reality (recorded, not
  adjudicated): the tool that emits an `exploitfixr` next-step hint is `targetcheckr`
  (`targetcheckr_classify.py:801-804`, `next_tool_hint` on `failure-with-symptom`);
  `stuckr`/`stuckr_rank.py` produce no `exploitfixr` reference.
- **D-4 — stale livefetch comment.** `livefetch.sh:424-425`: "NB: `state_read_global`
  reads the legacy `creds/creds.txt` path — we use the locked one." Code reality
  (recorded, not adjudicated): `state_read_global` was changed in build 8 to read the
  authoritative `$TOOLKIT_ROOT/creds.txt` (`state.sh:236-249`); the comment describes the
  pre-build-8 state. livefetch's own cred read (`livefetch.sh:426-428`) is correct and
  unaffected — this is a stale **comment**, not a functional defect.

---

## 4. Boundary & failure-mode findings

All documented "missing-file-safe / degrade-don't-crash" boundaries hold (integ S4):
`orient` on a target with no collection dirs → exit 0, writes nothing; `orient --bogus`
→ exit 2; `proofr` on an empty root → exit 3; `stuckr` on a bare target dir → exit 0
with "no enumeration data" guidance; `state_append_cred` on malformed input (no colon)
→ rc 2, no `creds.txt` corruption. The documented "does NOT" boundaries (§5 of the
playbook) match behavior: orient writes no sentinels/evidence/creds; targetcheckr/
watchdog never execute or probe; proofr writes nothing. **No crash, garbage-output, or
boundary-violation found.**

House-convention spot check (no violations found in the audited new tools): all use
`set -o pipefail` not `set -e`; `nxc` not `crackmapexec`; `warn`/`error` → stderr in
proofr/orient/livefetch; impacket- prefixes and `penelope -O` in the docs' commands.

---

## 5. Findings, triaged into the three buckets

### Bucket 1 — Toolkit bug (needs a fix)

- **F-1 — stuckr's service-only-fallback label is suppressed by positive-event
  sentinels (LOW severity, cosmetic).** `success-*` keys written by targetcheckr
  (`success-shell-spawned`), watchdog (`success-liveness-*`), and livefetch
  (`success-livefetch-*`) all land in the same `targets/<ip>/state/sentinels.log` that
  `state_read_target` surfaces as `sentinel=` lines. `stuckr_rank.py:296` gates the
  `fallback|broad-category` marker on `not state['sentinels']` — i.e. it treats *any*
  sentinel as a real symptom. So once a foothold/liveness/delta event has been logged,
  a service-only target's broad-category fallback loses its
  "(service-only fallback — no sentinels yet)" annotation. **Verified empirically:**
  identical target, no sentinels → label present; add one `success-shell-spawned` →
  label gone. **Impact:** label only — the ranked moves are byte-identical; nothing is
  hidden or wrongly surfaced (confirmed: `success-*` keys never match a symptom and
  never render in the empty-result block, integ S3e). It is a genuine cross-tool
  namespace bleed, which is why it is recorded as a bug rather than a limitation.

### Bucket 2 — Playbook / doc error (needs a doc fix) — reported verbatim, not adjudicated

- **D-1** tool count: "9-tool" (`Playbook:12`) vs "8-build" (`Methodology:18`).
- **D-2** orient-prerequisite claim for watchdog/targetcheckr (`Methodology:995`).
- **D-3** exploitfixr "surfaced by stuckr" (`Playbook:100`) vs surfaced by targetcheckr.
- **D-4** stale `livefetch.sh:424-425` comment about `state_read_global`.

### Bucket 3 — Known limitation (recorded, no action)

- **L-1 — runtime-dependent seams.** S1c (ffuf JSON shape) and S1d (`nxc --computers`
  banner) are verified against the producers' write-code and the orient Phase-0
  fixtures, not against live tool output. A future tool-version change to those output
  shapes would not be caught by any suite. This is the boundary in §0 and is exactly
  what the operator's live run tests.
- **L-2 — `targets/<ip>/web/gobuster.txt` has no producer.** `state.sh:92-111` reads
  it; orient writes only `feroxbuster.txt` (orient_spec §2 note). Documented and
  intentional (reader degrades cleanly on the absent file) — not a defect.
- **L-3 — two-tree architecture is by design.** The decision/collection split and the
  "run orient after recon or the decision tools read empty" rule are intended; orient
  is the sole bridge. Recorded so it is not mistaken for a seam break.

---

## 6. Fix list (NOT fixes — a separate, reviewed pass owns these)

1. **F-1 (bucket 1):** in `stuckr_rank.py`, gate the service-only-fallback marker on
   whether a *symptom-namespace* sentinel matched (e.g. `not matched_sym` / the
   `seen_sentinels` set), not on raw `state['sentinels']` non-emptiness — so positive
   `success-*` events don't suppress the label. One-line change at/near `:296`; add a
   regression assertion (integ S3e is the natural home). Severity LOW, optional.
2. **D-1…D-4 (bucket 2):** doc owner decides which side of each discrepancy is correct
   and edits the doc; no code change implied. Adjudication deferred by instruction.

---

## 7. Conclusion

The eight individually-correct tools **compose into one correct workflow.** All twelve
seam families HOLD in code and end-to-end; the only toolkit defect found is **F-1**, a
low-severity cosmetic label bleed in stuckr — no broken contract, no crash, no silent
empty-read, no points-losing audit gap. The §7 cred-reader fix is coherent across all
consumers; the collection→bridge→decision→evidence→audit chain carries real data end to
end; proofr's exit-code gate fires correctly on the catastrophic cases. The playbook's
invocations are all valid as written; the only documentation issues are the four
verbatim discrepancies in bucket 2, left for the adjudication pass.

This is close to the strongest possible result: the integration layer the per-tool
suites never had is now permanent and green, and the one bug is cosmetic. With F-1 (if
the operator chooses to fix it) and the bucket-2 doc calls resolved in the separate
pass, the toolkit is genuinely frozen and the runway is pure practice.

---

## 8. Addendum — fixes applied (2026-05-22)

> Supersedes the §0 "findings only — no fixes applied" status. §1–§7 above are
> preserved as the point-in-time audit record; this addendum logs the commissioned
> fix pass. Every bucket-1 and bucket-2 item is now resolved; bucket-3 limitations
> are by design and unchanged. All 9 suites (integration + 8 existing) green after
> the pass.

The operator commissioned the fix pass and adjudicated the bucket-2 doc calls. Fixes
landed in **two isolated commits** (F-1 separated from the doc/comment changes per the
operator's split), each verified green:

| Finding | Resolution | Commit |
|---|---|---|
| **D-1** | Playbook header: dropped the bare "9-tool" count → "engagement toolkit". Adjudication: the playbook's operational-spine scope and the methodology's 8-build scope genuinely differ, so no unified number was invented; methodology keeps "8-build". | `7052185` |
| **D-2** | `Methodology:995`: replaced "Both require `orient`…" — now states `watchdog` reads `foothold.log` + `pivots/state.tsv` (needs neither `orient` nor a bound target) and `targetcheckr` logs the foothold with just `--against` (cross-checks richer once `orient` has run). | `7052185` |
| **D-3** | `Playbook:100`: `exploitfixr` "surfaced by `stuckr`" → "surfaced by `targetcheckr`". | `7052185` |
| **D-4** | `livefetch.sh:423-425`: stale "`state_read_global` reads the legacy `creds/creds.txt` path" comment corrected to the build-8 reality (authoritative `creds.txt`; livefetch reads it directly). | `7052185` |
| **F-1** | `lib/stuckr_rank.py`: the service-only-fallback marker now gates on the matched **symptom** set (`seen_sentinels`) instead of raw `state['sentinels']`, so `success-*` positive-event keys no longer suppress the "(service-only fallback — no sentinels yet)" label. **Display-only — ranked moves byte-identical.** Regression assertion added to `tests/test_workflow_integration.sh` S3e. | `3eefc83` |

**Verification.** F-1's "behavior-preserving" claim was gated on a full re-run: all 9
suites stayed green after the change (the agreed revert-on-red condition never fired),
and the new `S3e [F-1]` assertion confirms the label is restored under positive-event
sentinels. Bucket-3 limitations (L-1 runtime-dependent seams, L-2 `gobuster.txt` has no
producer, L-3 two-tree by design) remain recorded with no action, as before.

With this pass complete, the toolkit is genuinely frozen and the runway is pure practice.
