# Ideation Report — Tools for the No-Prep OffSec+ Thesis

**Date:** 2026-05-20
**engagement target:** OffSec+ on 2026-07-09 (50 days out)
**Scope:** Two ranked lists of proposals (upgrades to existing toolkit, new tools), a combined top 5, an anti-list, and an honest assessment of whether the thesis survives design pressure.
**This is ideation, not implementation.** No code is produced from this report. Each proposal is a design sketch.

---

## 1. Inventory summary

**What is already strong.** The 14 scripts under `~/scripts/` are tightly designed enumeration orchestrators with consistent house style: timeouts on every external call, evidence-gated `next_steps.txt` emission, resume markers, and graceful degradation when optional tools are missing. The crack→spray loop is documented as a contract. `recon.sh` and `webenum.sh` emit fingerprint-grade summaries with resolved next-step commands tied to discovered services. `adr.sh` covers the full AD kill chain to the limit of "enumeration only." `exploitdb` serves 442 curated entries with `alternates` populated on 87% of entries and `false_positives` on 97% — the data needed to recover from a wrong turn is already there. `vquery` indexes 79 vault docs with FTS5, an authored shortcut layer (62 of a planned ~160), and bidirectional cross-references into exploitdb. Reverse-shell handoff, Penelope conventions, Ligolo-ng over chisel, `nxc` over `crackmapexec` — the tool-choice decisions a trained operator would otherwise have to make are pre-made and embedded.

**Where the no-prep gaps concentrate.** The bright line in AGENTS.md ("enumeration only, no auto-exploitation") was drawn for a trained operator who will read `next_steps.txt`, decide, and execute. For a no-prep operator three failure modes recur: (1) **empty findings produce silence** — every script evidence-gates output, which is correct for a trained operator but leaves the untrained one with no command library when a phase finds nothing (the exact moment they need the most help); (2) **handoffs between scripts are manual** — crack→spray, recon→exploitdb search, pivotr→recon-through-tunnel, lootr→evidencr — every cross-tool action is "operator reads file, types next command;" (3) **content gaps inside exploitdb** — `web_exploits` and `sqli` (79 entries combined, 18% of the corpus) have **zero `next_actions` populated**, so successful LFI/RFI/SQLi strands the operator at the moment of success; the `shells` category has a single PowerShell entry; CMS coverage beyond WordPress is absent; deserialization (Java/.NET/Python) is absent. The vault layer is similar: strong on AD and privesc methodology, thin on service-specific foothold playbooks (Redis, Memcached, MongoDB, Elasticsearch, MSSQL/MySQL post-auth), kernel-exploit decision trees, BloodHound edge-to-command cookbooks, and "what to do when cracking fails" pivots. None of these gaps require the operator to study — they require the toolkit to be more opinionated at the moment of interaction.

---

## 2. List A — Upgrades to existing scripts and apps (ranked)

> **Ranking revised post-review.** Items remain in file order but the effective leverage ranking is: **A1, A11, A2, A3, A4, A5, A6, A7, A8, A9, A10, A12**. A11 (sprayr `--ad-policy`) was promoted because locking out the only working admin credential at hour 14 is a single-action engagement-killer that nothing else in the toolkit catches — it sits just below A1 (the highest-leverage content fix). The build plan in §4 selects from this list per the decided order.

### A1. `exploitdb` — populate `next_actions` on `web_exploits.json` and `sqli.json`

**Script/app:** exploitdb (data + templates)
**Current behavior:** 442 entries; 73% average `next_actions` coverage but 0% on `web_exploits` (43 entries) and 0% on `sqli` (36 entries). The other 9 categories average 100%.
**No-prep gap:** A trained operator who reads "LFI confirmed via `php://filter/convert.base64-encode/resource=...`" knows the next move is log poisoning, `/proc/self/environ`, session-file inclusion, or wrapper-based RCE. A no-prep operator sees a working LFI primitive and stares at it.
**Upgrade:** Author `next_actions` arrays for all 79 entries. Each entry gets 2–4 ordered next moves, each phrased as a single free-text instruction ending with `→ see \`<slug>\`` (matching the existing convention in 938 already-populated items across the other 9 categories).
**Operator-visible difference:** After LFI confirmed, the entry page renders a "Next actions" `<ul>` showing items like "Read `/proc/self/environ` for RCE → see `web-lfi-environ-rce`" / "Log-poison Apache access.log → see `web-lfi-log-poison`" / "Include PHP session file → see `web-lfi-session-inc`."
**Implementation effort:** ~3 days of seed authoring. **No app or template changes needed** — `entry.html` already renders `next_actions` as a plain `<ul><li>` when present (template line ~133).
**Sketch:** Edit `data/seed/web_exploits.json` and `data/seed/sqli.json` to add a `next_actions` array per entry. Schema: `next_actions: List[str]`. Each string is one instruction with an inline slug pointer (`→ see \`<slug>\``); the existing corpus averages 58 chars at p50, 92 at p90, with a hard ceiling around 140 (max observed: 142). Target ~60–90 chars per item, never exceed ~140. No structured object, no separate trigger/note fields — match the convention exactly. After authoring, `./run.sh rebuild` and `audit_app.py` to verify. Extend `audit_seed.py` to flag any entry in these two categories with an empty `next_actions` so the gap can't silently reopen.

### A2. All `.sh` scripts — emit empty-result sentinels for `stuckr` to consume

**Script/app:** recon, webenum, adr, lootr, escalatr, sprayr, crackr
**Current behavior:** Evidence-gated emission. If a phase finds nothing, `next_steps.txt` gets no entry for that phase — by design, to avoid fabricated findings.
**No-prep gap:** The most dangerous moment for a no-prep operator is "the script told me nothing was found, what now?" Silence is the worst possible response. But the *fix* shouldn't be that every script re-implements the same symptom→action map — that spreads the same logic across seven scripts, each maintaining its own vocabulary, each drifting over time.
**Upgrade:** Each script emits a small machine-readable sentinel into `summary.txt` (or a sibling file) for every phase that produced empty findings — e.g., `EMPTY:smb-no-anon`, `EMPTY:web-no-vhosts`, `EMPTY:linux-no-suid`. The actual "here's what to try" content lives in one place: `stuckr.sh` (B1), which reads the sentinels and maps to exploitdb alternates.
**Operator-visible difference:** `summary.txt` ends with "Phases with no findings: smb-no-anon, web-no-vhosts. Run `stuckr` for next moves." One tool, one symptom map, one set of decisions to keep current.
**Implementation effort:** ~1 day per script for sentinel emission (small mechanical change). The symptom→action map effort moves into B1's scope.
**Sketch:** Add a one-line `emit_empty_sentinel <symptom-key>` helper to `~/scripts/lib/state.sh` (shared by stuckr + orient). Each script's empty-result branches call it. The helper writes `EMPTY:<key>` into `summary.txt` and into a structured `$TOOLKIT_ROOT/<category>/<target>/state.json` file that stuckr reads. Evidence-gate preserved — `next_steps.txt` still requires real findings; the sentinels are explicit about "no findings here."

### A3. `recon.sh` — embed one-click exploitdb search URLs in `next_steps.txt`

**Script/app:** recon.sh
**Current behavior:** `next_steps.txt` emits resolved tool commands per discovered service. Operator must then manually search exploitdb.
**No-prep gap:** Two cognitive steps (read the port, formulate the search query) collapse to one only for someone who already knows what they would search for.
**Upgrade:** For each discovered service, embed a pre-built URL like `http://127.0.0.1:5000/search?q=kerberos+88+enumeration` and an Obsidian deep-link to the relevant vault doc. Operator clicks or middle-clicks once.
**Operator-visible difference:** `next_steps.txt` shows: "Port 88/tcp Kerberos. exploitdb: <local url>. Vault: <obsidian link>. Suggested first command: …". No typing required to traverse the knowledge surface.
**Implementation effort:** ~1 day. The mapping from port/service to exploitdb category and query string is small.
**Sketch:** Add a `PORT_TO_QUERY` table at the top of `recon.sh` (or extracted to `lib/portmap.sh`). In the next-steps emission, append the URL lines. Mirror in `webenum.sh` (per CMS) and `adr.sh` (per attack name).

### A4. `recon.sh` — add a plain-English "what you're looking at" verdict to `summary.txt`

**Script/app:** recon.sh
**Current behavior:** `summary.txt` reports the port table and per-service enum results in technical form.
**No-prep gap:** A trained operator reads "88/tcp kerberos, 389/tcp ldap, 445/tcp smb, 3268/tcp ldap-gc, 5985/tcp wsman" and instantly thinks "domain controller, standard AD path." A no-prep operator reads five port numbers.
**Upgrade:** Detect common host profiles from port + service signatures (DC, member server, web-only, Linux file server, jump box, IoT-flavored) and write a 2–3 sentence verdict at the top of `summary.txt`: "Looks like a Domain Controller (ports 88/389/445/3268/5985). Standard play: enumerate users → AS-REP roast → spray → BloodHound. Start with `next_steps.txt` line 1."
**Operator-visible difference:** The first thing the operator reads is a plain-English orientation, not a port table.
**Implementation effort:** ~1 day. Small set of profiles (5–8), pattern-matched against the port set.
**Sketch:** New `detect_host_profile()` function in `recon.sh`. Reads the rustscan/nmap output, matches against a profile table, prints the verdict and a one-line "standard play" sentence. No verdict if no profile matches (do not fabricate).

### A5. `crackr.sh` → `sprayr.sh` — auto-feed cracked credentials end-to-end

**Script/app:** crackr.sh + sprayr.sh
**Current behavior:** `crackr.sh` writes cracks to `$TOOLKIT_ROOT/creds.txt` and emits `next_steps.txt`. Operator must read it, identify user:pass, choose protocols, type the spray command.
**No-prep gap:** The crack→spray loop is documented as a contract but operationalized through manual command assembly. Domain inference, target list, hash format — all on the operator.
**Upgrade:** After every successful crack, `crackr.sh` writes a pre-assembled `sprayr` command to `next_steps.txt` with the cracked credential, the domain inferred from `adr.sh` artifacts (if present), and the target subnet inferred from the recon host list. Optionally add `crackr --auto-spray` that dispatches it.
**Operator-visible difference:** `next_steps.txt` shows the full `sprayr.sh -u alice -p Summer2026! --domain corp.com -T $TOOLKIT_ROOT/recon/hosts.txt --proto smb,winrm` line. Operator copy-pastes one line instead of building five fields.
**Implementation effort:** ~2 days. Requires a thin state-read of `$TOOLKIT_ROOT/ad/<domain>/` and `$TOOLKIT_ROOT/recon/`.
**Sketch:** Add `infer_spray_context()` to `crackr.sh` that reads adr's `domain.txt` and `users.txt` and the recon `hosts.txt` (when present), then writes the resolved spray command. Default to dry output (no auto-execution) unless `--auto-spray` is set explicitly.

### A6. `adr.sh` — auto-dispatch `crackr.sh` on collected hashes with sensible budget

**Script/app:** adr.sh
**Current behavior:** Collects SPN and AS-REP hashes; lists them in `next_steps.txt`. Operator decides whether to crack.
**No-prep gap:** A trained operator looks at a Kerberoast hash and knows "best64 + rockyou-30000 will catch the easy ones in 5 minutes — start it now, do other stuff." A no-prep operator may not know to start cracking until later.
**Upgrade:** Add `adr.sh --auto-crack` that, on hash collection, spawns `crackr.sh` in the background with a budgeted strategy (best64 then rockyou-30000, capped at e.g. 30 minutes, output streamed to a known location). Recombines results into adr's `next_steps.txt`.
**Operator-visible difference:** While the operator continues with the next target, hashes are quietly being cracked in the background. When they return to this target, cracked creds are already in `creds.txt` and pre-assembled `sprayr` lines are in `next_steps.txt`.
**Reproducibility (report-grader contract):** Background crack dispatch must emit a one-line entry into `next_steps.txt` at the moment of fork — e.g., `[BG-CRACK started 14:23] hashcat -m 13100 ${OUTDIR}/hashes/kerberoast.txt --rule best64 --wordlist rockyou-30000 (budget: 30m)`. When the reaper merges results, it appends `[BG-CRACK completed 14:48] cracked: 2/7 hashes → creds.txt`. The operator must be able to reconstruct the cred-source chain from the report; a credential that "just appeared" without a documented `hashcat` invocation is unreproducible and the grader will deduct.
**Implementation effort:** ~2 days. Background process management with PID tracking; result reincorporation.
**Sketch:** New phase in `adr.sh` that on completion of hash-collection phase forks `crackr.sh` against the actual collected files — `${OUTDIR}/hashes/kerberoast.txt` and `${OUTDIR}/hashes/asreproast.txt` (these are the real paths in adr.sh:1086,1125) — with `--rule best64 --wordlist rockyou-30000 --budget 30m` and a known logfile. A separate "reaper" routine at adr end (or at `--rollup`) reads the logfile, merges results, and writes the completion line per the reproducibility contract above.

### A7. `webenum.sh` — emit a "what kind of app is this" verdict line

**Script/app:** webenum.sh
**Current behavior:** Fingerprint section reports tech stack: server header, frameworks detected, CMS if known.
**No-prep gap:** "PHP/7.4.3, jQuery, Bootstrap" doesn't tell the no-prep operator what to do. A trained operator reads it and thinks "custom PHP, no CMS — try LFI, file upload, SSTI, default creds in known dirs."
**Upgrade:** Add a verdict line that classifies the app into one of ~6 buckets (known CMS, custom PHP, ASP.NET, Java/JSP, Node/Express, static-only, unknown) and emits a one-sentence ranked-vector recommendation.
**Operator-visible difference:** Top of summary shows "Custom PHP, no CMS. Highest-likelihood vectors (ranked): file upload bypass → LFI → SSTI → default-creds in known dirs. See next_steps.txt and stuck_actions.txt."
**Implementation effort:** ~1 day. Small classification table.
**Sketch:** Add `classify_web_app()` to `webenum.sh` that consumes the fingerprint output (whatweb/wappalyzer JSON) and matches against a small lookup table. Writes verdict line. No verdict if confidence is low.

### A8. `escalatr.sh` — emit a single-shot "transfer + run + exfil" runner script

**Script/app:** escalatr.sh
**Current behavior:** Stages tools and prints commands the operator must transfer to the target, run, and parse manually.
**No-prep gap:** The operator must execute ~6 commands across two boxes correctly in sequence — every typo restarts the loop.
**Upgrade:** Add `escalatr.sh --remote-runner <session-label>` that emits a single self-contained shell (or PowerShell) script the operator pastes once into the active session. The script runs the enum tools, exfiltrates results to a Kali HTTP server (already orchestrated by escalatr's `--serve`), and exits. Kali side auto-parses on receipt.
**Operator-visible difference:** Instead of "stage tool / transfer / chmod / run / save / transfer back / parse" (7 ops), the operator pastes one long line. Output appears under `$TOOLKIT_ROOT/privesc/<ip>/raw/` automatically.
**Implementation effort:** ~3 days. Generating the self-contained payload + a small exfil endpoint on the Kali HTTP server.
**Sketch:** New flag in escalatr. Generated payload is a heredoc bash (or compressed-base64 PowerShell) that includes linpeas/winpeas invocation, redirects output to a tmp file, curls it back to the Kali listener with a target-tagged path, deletes the local copy. The Kali listener (extension of `servr.sh http` or a new sub-mode) writes received files into the right `$TOOLKIT_ROOT` location.

### A9. `evidencr.sh` — drive the live status board (always-running, not on-demand)

**Script/app:** evidencr.sh + startr.sh
**Current behavior:** evidencr is invoked per-target with manual entry; `--rollup` produces a point-total summary when asked.
**No-prep gap:** The operator must remember to check the rollup. Points are tracked retrospectively, not in real time. The "where am I in the engagement" question requires explicit work.
**Upgrade:** Make `evidencr.sh --board` a long-running view (intended to be parked in a tmux window). Auto-refresh every 60s. Renders: machine list with status (none / foothold / root) and points, total earned vs 70-needed, time elapsed in engagement, MSF-machines used (1/1 cap), next pre-buzzer alert. startr opens this window automatically.
**Operator-visible difference:** One always-visible tmux pane shows the engagement state. The operator never has to ask "am I going to pass?" — they can see it.
**Implementation effort:** ~3 days. Watch-mode loop, terminal layout, integration with `startr.sh` window plan.
**Sketch:** New mode in `evidencr.sh`. Reads `$TOOLKIT_ROOT/evidence/*/progress.log` and aggregates. Uses `tput` for a stable rendering. startr's tmux layout adds `evidencr --board` to a permanent window.

### A10. `vquery` — add an "I see this output, what is it" route

**Script/app:** vquery
**Current behavior:** Full-text search over indexed chunks. Operator must formulate the query.
**No-prep gap:** "I don't know what to call this" is itself a no-prep failure. The operator sees `STATUS_ACCESS_DENIED` from an SMB enum and types... what?
**Upgrade:** New route `/identify` (and CLI `vquery identify -`) that accepts a paste of tool output, runs symptom/keyword extraction against a curated symptom→topic map, and returns top 3 vault chunks + top 3 exploitdb entries.
**Operator-visible difference:** Operator selects an error or partial output line, pipes it (or pastes it) — gets back "This is the SMB null-session being refused. Try: anonymous LDAP, RID cycling, asreproast against guessed users." plus document/entry links.
**Implementation effort:** ~4 days. Symptom map is the bulk of the work — needs ~50–80 hand-authored symptom rules.
**Sketch:** Extend `vquery/app.py` with `/identify` POST endpoint. Body is raw text. Extractor runs against a `symptom_map.yaml` (new file). Returns ranked chunks + exploitdb cross-refs. Add a small `vquery identify` CLI shim.

### A11. `sprayr.sh` — AD-policy-aware safe mode

**Script/app:** sprayr.sh
**Current behavior:** `--safe` adds sequential + jitter. Generic; no awareness of the target's badPwdCount threshold.
**No-prep gap:** A no-prep operator will run a spray and lock out the only valid admin credential they have, then spend hours figuring out why nothing works. There is no second chance at engagement time.
**Upgrade:** Add `--ad-policy <domain>` that reads `$TOOLKIT_ROOT/ad/<DOMAIN>/password_policy.txt` (the actual file adr.sh writes via `nxc smb --pass-pol` — see adr.sh:680–682) and respects badPwdCount with a hard ceiling (e.g., max attempts = threshold − 2). Refuses to proceed if policy is unknown unless `--force` is also passed.
**Operator-visible difference:** Spray refuses to lock anyone out. Operator sees "Domain policy: lockout at 5 attempts. I'll do at most 3 per user, then stop. Continue? [y/N]"
**Implementation effort:** ~2 days. Policy parser + per-user attempt counter.
**Sketch:** `parse_ad_policy()` reads the adr-collected policy. `sprayr` tracks attempts per user across protocols. Hard ceiling before lockout. Add an explicit warn-and-confirm if policy file is missing and `--ad-policy` was requested.

### A12. `lootr.sh` + `lootr.ps1` — auto-emit evidencr-ready stanzas

**Script/app:** lootr.sh, lootr.ps1
**Current behavior:** Hunts loot, including proof.txt/local.txt content. Operator must then manually type flag values into `evidencr.sh`.
**No-prep gap:** Tedious-to-type 32-char hex values entered correctly twice (lootr discovered them; operator re-types them into evidencr). Easy to mistype under fatigue.
**Upgrade:** When lootr captures a flag-shaped value, write a pre-baked `evidencr.sh --apply ...` invocation to a known path (`$TOOLKIT_ROOT/evidence/<ip>/staged_apply.sh`). Operator runs one shell line to commit the evidence record.
**Operator-visible difference:** lootr says "Flag captured at C:\Users\Administrator\Desktop\proof.txt. Run `bash $TOOLKIT_ROOT/evidence/<ip>/staged_apply.sh` to record it." One command vs four prompts.
**Implementation effort:** ~1.5 days.
**Sketch:** Add `emit_evidencr_stanza()` to both lootr variants. Detect proof-shaped values (32-hex or known format), write the apply script with the flag value, target IP, hostname, and OS auto-populated.

---

## 3. List B — New tools/scripts/apps (ranked)

> **Ranking revised post-review.** Items remain in file order for diff-ability but the effective leverage ranking is: **B1, B10 (`exploitfixr`, new), B11 (`targetcheckr`, new), B5, B3, B6+B9 (bundled), B2, B4, B8**. Two new entries (B10, B11) close gaps the prior §6 incorrectly conceded as uncloseable. **B7 (`replayr.sh`) was dropped from the corrected ranking** — its highest-value cases are covered by `exploitfixr` (exploit-side slips) and `shellpicker` (shell-handoff slips); it is retained below as a v2 candidate. The build plan in §4 selects from this list per the decided order.

### B1. `stuckr.sh` — the "I'm stuck" button (single source of truth for empty-finding response)

**Name:** stuckr (working title)
**Type:** script
**Problem:** The no-prep operator hits dead ends and freezes. There is no single command that, given the current state of a target, surfaces "here are the 3–5 things you haven't tried." Today they must remember to read every script's `next_steps.txt`, cross-reference exploitdb, decide. Under fatigue this fails. **A2 review note:** the symptom→action map belongs in *one* place, not duplicated across every enumeration script — stuckr is that place. Scripts emit empty-result sentinels (A2); stuckr maps them to actions.
**Solution:** One command. `stuckr --on <ip>` reads everything the toolkit knows about that target (recon, web, ad, privesc, loot, evidence dirs under `$TOOLKIT_ROOT`, plus the `EMPTY:<symptom>` sentinels emitted per A2), determines what's been tried and what's missing, queries exploitdb for relevant alternates and unexplored vectors, and returns 3–5 ranked next moves with concrete copy-paste commands. Also callable with no args (target inferred from cwd or last evidencr record) and with `--all` to scan every target's state at once.
**Operator experience:** Operator types `stuckr`. Output is a single screen: target summary (1 line), what's been tried (5–10 lines), explicit list of empty-finding symptoms hit, top 3 untried actions ranked by likelihood, each with a one-line trigger and a ready command. Operator picks one and runs it.
**Implementation effort:** ~1.5 weeks (was ~1 week before A2 scope was folded in). The symptom→action map is the bulk of the new work — author ~50–80 symptom keys, each mapping to 2–4 ranked exploitdb slugs.
**Builds on:** Reads outputs of every other script (via a new `~/scripts/lib/state.sh` shared with `orient.sh` if built). Queries `exploitdb`'s SQLite for alternates. Calls `vquery /identify` (A11 in revised ranking, formerly A10) for symptom-based fallback when the symptom map doesn't have a direct hit.
**Risk if it fails:** Fail loud is essential. If stuckr returns wrong suggestions, operator wastes 10 minutes. Acceptable. If it silently returns nothing, operator stares at a blank screen — unacceptable. Design rule: if no confident suggestions, say so explicitly and emit a "raw alternates from exploitdb for this category" fallback. Single-source-of-truth on the symptom map means the failure surface is small enough to test exhaustively.
**Sketch:** New `~/scripts/stuckr.sh` + `~/scripts/lib/symptom_map.yaml` (the keyed action map). State reader walks `$TOOLKIT_ROOT/recon/<ip>/`, `web/`, `ad/<domain>/`, `privesc/<ip>/`, `loot/`, `evidence/` and parses sentinels from `summary.txt`/`state.json`. Builds a state vector: known services, known creds, foothold status, privesc status, list of `EMPTY:<symptom>` hits. Queries exploitdb for entries whose `triggers` match the state vector AND whose `slug` does not appear in any consumed `next_steps.txt`. Ranks by `exam_relevance` + match-strength. Renders text. No execution, no auto-anything — output only.

### B2. `orient.sh` — the operator's compass

**Name:** orient
**Type:** script
**Problem:** During the engagement the operator has ~6 target dirs, 4+ tmux windows, dozens of files. Without state awareness they get buried on one target and don't notice the wider picture. A trained operator carries the model in their head. A no-prep operator can't.
**Solution:** A 25-line plain-text board printed on demand. Shows: time elapsed / remaining, total points earned vs 70-needed, projected pass/fail, per-target row (status, points, time spent on it, last activity), recommended focus.
**Operator experience:** Operator types `orient`. Sees a one-screen board. "SA1: rooted, 20pt, evidence captured. SA2: foothold, 10pt, 47min in, next: privesc. SA3: untouched. AD: 0/40pt, untouched. Total 30/70. Time left 18h22m. **Recommend: pivot to AD now — single biggest point block remaining.**"
**Implementation effort:** ~3 days.
**Builds on:** Same state reader as `stuckr.sh` (share the library). Reuses `evidencr` aggregation.
**Risk if it fails:** Low — read-only summary. If wrong about "recommend," operator can ignore. Hard requirement: never claim a point is earned without an evidencr record backing it.
**Sketch:** New `~/scripts/orient.sh`. Reads the same state files as `stuckr`. Renders a fixed-layout table. The "recommend" line is deterministic, not heuristic — derived from a small rule table ("if no AD foothold and < 12h left, recommend AD pivot"; "if foothold but no privesc after 60 min, recommend running stuckr on this target"). State-machine, not magic.

### B3. `livefetch.sh` — internet-augmented technique lookup

**Name:** livefetch
**Type:** script
**Problem:** Internet is allowed at engagement time but the operator has to context-switch to a browser, search, parse a webpage, copy back to terminal. For a no-prep operator under pressure that context switch is expensive. They also won't know which sites to consult.
**Solution:** A unified terminal command that wraps curls against the highest-value live sources (HackTricks, GTFOBins, LOLBAS, PayloadsAllTheThings, exploit-db search, NIST NVD by CVE) and formats them into one screen of plain text per query.
**Operator experience:** `livefetch sudo nano` → GTFOBins entry rendered as text. `livefetch "Apache 2.4.49"` → CVE list + ranked exploits + summary lines from each. `livefetch lfi-to-rce` → HackTricks section text. No browser, no clicks. Operator stays in tmux.
**Implementation effort:** ~5 days. Each source needs a small adapter (HTML scrape or API). HackTricks is the trickiest (large pages, need to slice).
**Builds on:** None of the existing toolkit, but cross-links into exploitdb when a fetched technique has a local entry.
**Risk if it fails:** Source goes down at engagement time = no result. Failure mode is "no answer" not "wrong answer" — acceptable if it falls back to "site unreachable, here's the raw URL to open manually." Caching: results are cached locally per query so a repeat lookup is instant and survives a network blip.
**Sketch:** New `~/scripts/livefetch.sh`. Adapters in `~/scripts/lib/livefetch/<source>.sh`. Each adapter: fetch URL, extract content section, render to width-80 text. Top-level command dispatches by query shape. Local cache under `~/.cache/livefetch/`. Pre-warmed for common queries the day before the engagement.

### B4. `timekeeper.sh` — engagement clock and decision-point alerts

**Name:** timekeeper
**Type:** script (daemon, started by startr)
**Problem:** A no-prep operator gets time-blind. They spend 90 minutes on one privesc path because they don't notice 90 minutes elapsed. The engagement clock is 23h45m; there is no slack for that.
**Solution:** A daemon started at engagement time. Tracks: total engagement elapsed, time on current focus target (inferred from recent tmux/file activity under `$TOOLKIT_ROOT/<target>/`), points captured. Triggers tmux popups at decision points: "47 minutes on SA2 with no foothold. Your alternates are: [3 lines from stuckr]. Continue? Switch?"
**Operator experience:** Mostly invisible. Quiet bell + popup at well-chosen moments. The operator doesn't have to remember to check the clock — the clock checks them.
**Implementation effort:** ~5 days. Activity inference is the hard part (which target is the operator focused on right now?).
**Builds on:** evidencr for point state; stuckr for the "your alternates are" content; tmux for the popup mechanism.
**Risk if it fails:** Popups too often = ignored = useless. Too rarely = no help. Calibration matters. Failure mode at engagement time: silent daemon. Add a watchdog signal so the orient board shows "timekeeper: alive/stalled."
**Sketch:** New `~/scripts/timekeeper.sh` started by `startr --recon` (and a manual flag). Reads `find $TOOLKIT_ROOT -mmin -10` to infer focus target. Threshold table: 45 min on a target without progress event → soft prompt; 90 min → harder prompt; 180 min → "you must move on" alarm. All prompts include a `stuckr` mini-output for that target.

### B5. `watchdog.sh` — VPN, tunnel, and shell health monitor

**Name:** watchdog
**Type:** script (daemon)
**Problem:** Shells drop at 3am. VPN drops silently. Ligolo TUN dies and proxychains-style traffic disappears into the void. A trained operator notices; a no-prep operator finds out by trying to do something and getting an unhelpful error 20 minutes later.
**Solution:** Daemon that pings the VPN gateway, checks the Ligolo TUN interface state, and probes every active reverse-shell session (via `penelope`'s session-list IPC or its log files) every 30 seconds. On drop: terminal bell, tmux popup with the exact reconnect command, and a write to `$TOOLKIT_ROOT/incidents.log`.
**Operator experience:** Mostly silent. When something drops, operator gets an immediate alert with the fix. "Ligolo TUN went down 12s ago. Recover: `~/scripts/pivotr.sh ligolo --resume <state-id>`."
**Implementation effort:** ~4 days. Penelope IPC integration is the unknown; fall back to log-file tailing if no IPC.
**Builds on:** pivotr's state.tsv; Penelope's session logs.
**Risk if it fails:** False positive = annoying. False negative = catastrophic (shell silently dead, operator finds out 30 min later). Bias detection thresholds toward false positives.
**Sketch:** New `~/scripts/watchdog.sh`. Three subroutines: `check_vpn` (ping gateway from $TOOLKIT_ROOT/engagement/vpn_gateway), `check_pivots` (read pivotr's state.tsv, test each), `check_shells` (tail Penelope log for last-seen per session). Loops every 30s. tmux popup via `tmux display-popup`.

### B6. `proofr.sh` — automated proof composition

**Name:** proofr
**Type:** script
**Problem:** OffSec requires a screenshot containing the flag, `whoami`, `hostname`, `ip a` (or equivalent), all in one frame. Easy to forget one element. Easy to take five screenshots instead of one. Easy to capture the wrong terminal.
**Solution:** Given an active shell session label and a captured flag value, compose the required terminal state and screenshot it. Operator visually confirms the result before submission (handoff hard constraint — operator must verify visually).
**Operator experience:** `proofr --session win-target-rdp --flag <value> --type proof` runs the required commands in that session and captures the screenshot to `$TOOLKIT_ROOT/evidence/<ip>/proof_admin.png`. Operator opens it, verifies, moves on.
**Implementation effort:** ~3 days. Session driving via tmux send-keys or RDP-side instrumentation is the hard part.
**Builds on:** Penelope session naming; evidencr's output paths.
**Risk if it fails:** Wrong screenshot saved. Mitigation: never delete or overwrite — always write to a new filename and let the operator pick the correct one.
**Sketch:** New `~/scripts/proofr.sh`. For tmux-bound shells: `send-keys` the required commands; `capture-pane -p` and convert to image via `aha` + `wkhtmltoimage`, or `tmux capture-pane -e` plus an HTML→PNG pass. For RDP: requires the operator to have the window foregrounded; calls `import` (ImageMagick) or `gnome-screenshot` on the active window.

### B7. `replayr.sh` — wrapper that catches operator slips on common commands

**Name:** replayr
**Type:** script (or shell-function set)
**Problem:** The operator types `nxc smb 10.10.11.0/24 -u admin -p Pass!` and hits Enter. They forgot `--continue-on-success`. They typed `Admin` instead of `admin`. They base64-encoded their PowerShell payload as ASCII instead of UTF-16LE. Errors fail silently or with cryptic output. A no-prep operator can't debug from "STATUS_ACCESS_DENIED."
**Solution:** Aliasable wrappers (`nxc`, `impacket-secretsdump`, `evil-winrm`, `hashcat`, `responder`, `psexec.py`) that intercept the invocation, run a pre-flight check against a known slip table, and either auto-correct with confirmation or block with a clear message.
**Operator experience:** Operator types a command as they would normally. Replayr prints "Caught: PowerShell payload looks ASCII, should be UTF-16LE for `powershell -enc`. Re-encode? [Y/n]". One keystroke fixes it.
**Implementation effort:** ~5 days for the highest-value 6 commands. More commands can be added incrementally.
**Builds on:** Each wrapped tool's actual CLI; vault docs for the slip rules.
**Risk if it fails:** A wrapper that breaks the underlying command is worse than no wrapper. Hard rule: any failure of replayr falls through transparently to the real binary with the original arguments. No bricking the command on a bug.
**Sketch:** New `~/scripts/replayr.sh` plus `~/scripts/lib/slips/<tool>.sh` per wrapped tool. Each slip module defines `precheck()` returning either `pass`, `correct <new-args>`, or `block <message>`. On `pass`: exec original tool with original args. On `correct`: confirm + exec with corrected args. On `block`: print message + exit non-zero.

### B8. `shellpicker.sh` — reverse shell catalog + listener handoff

**Name:** shellpicker
**Type:** script
**Problem:** `exploitdb` has one shell entry (PowerShell). A no-prep operator who needs a Bash reverse shell, a Python one, a `nc` one, an AMSI-bypassing PowerShell stager, or a UTF-16LE encoded payload, has to leave the toolkit. They might forget to start Penelope first. They might use the wrong IP (Kali tun0 vs Ligolo tun1).
**Solution:** One command. `shellpicker --os linux --constraints no-python,no-bash --to 10.10.14.5:4444` → prints the right payload AND starts the Penelope listener on the right IP/port AND remembers which session label is reserved.
**Operator experience:** Single line in, single line out. The listener is already running. Operator pastes the payload into the target.
**Implementation effort:** ~4 days. Payload catalog + listener orchestration + IP auto-detection.
**Builds on:** servr.sh's Penelope launch conventions; pivotr's state for choosing tun0 vs tun1.
**Risk if it fails:** Wrong IP picked → shell connects nowhere. Bias to "ask if ambiguous, never guess silently."
**Sketch:** New `~/scripts/shellpicker.sh`. Catalog of ~40 payloads keyed on OS + constraints + transport. IP resolver checks pivot state and asks if multiple interfaces match. Spawns Penelope with `-0` (per AGENTS.md §3). Prints both the payload and a confirmation that the listener is ready.

### B10. `exploitfixr.sh` — public-exploit modification assistant *(added post-review)*

**Name:** exploitfixr
**Type:** script
**Problem:** OffSec+ frequently requires the operator to take a public exploit (exploit-db, GitHub PoCs) and modify it to work in the lab: change LHOST/LPORT, change target URL or RHOST, swap a payload encoding, run a Python 2→3 conversion. A trained operator does this in 5 minutes. A no-prep operator with literacy can read the code but may not know which lines actually need to change vs which can be left alone, and under fatigue at hour 18 the risk of editing the wrong line is high. The prior §6 of this report wrongly conceded this gap as uncloseable.
**Solution:** `exploitfixr <path/to/exploit.py> --lhost 10.10.14.5 --lport 4444 --rhost 10.10.11.42` ingests the public exploit and emits a diff updating the obvious config-block patterns (LHOST/LPORT/RHOST/target URL string, listener IP variables, payload encoding patterns) plus a Python-2→3 `2to3` pass when applicable. Pre-flight also flags the 3–5 lines the operator most likely needs to read manually before running (shellcode blocks, offset constants, version-specific bytes).
**Operator experience:** Operator finds a candidate exploit, runs `exploitfixr exploit.py --lhost ... --lport ... --rhost ...`. Sees a unified diff with the obvious substitutions, a list of "lines you should look at" with one-line reasons, and a "ready to run" or "needs operator review" verdict. Operator reviews flagged lines (literacy is sufficient), applies the diff, runs.
**Implementation effort:** ~1.5 weeks. The 80% case (Python and Bash scripts with obvious config blocks at the top) is tractable. The 20% case (shellcode regeneration, syscall offsets, non-obvious config patterns) is explicitly out of scope and the tool must fail loud on those rather than silently producing a broken diff.
**Builds on:** None of the existing toolkit. Standalone. Optional integration with `exploitdb` entries that already have `command_notes` describing what to modify.
**Risk if it fails:** Worst case is a silently-wrong diff that the operator applies and runs against a target. Mitigation: never auto-apply — always emit as a diff for the operator to inspect; always include the "lines to look at" list; refuse to emit a "ready to run" verdict if any flagged-line heuristic triggers. Bias hard toward "operator review required."
**Sketch:** New `~/scripts/exploitfixr.py` (Python preferred for AST inspection of Python exploits). Detection rules in `~/scripts/lib/exploit_patterns.yaml` keyed by language and exploit-class.

Variable-substitution patterns based on observed exploit-db convention (verified by sampling 20 random PoCs under `/usr/share/exploitdb/exploits/`): both `LHOST`/`RHOST`/`TARGET` (uppercase, Metasploit-style) **and** lowercase `host`, `port`, `target`, `target_url` (more common in raw PoCs); both top-of-file constants and mid-function assignments; both `argparse`-driven exploits (where the right answer is "build the invocation flags," not modify source) and hardcoded-IP exploits.

Patterns to detect:
- `argparse` usage → emit a `python3 exploit.py --host <RHOST> --port <PORT> --lhost <LHOST> ...` invocation line; no source modification.
- Top-of-file constants matching `(LHOST|RHOST|TARGET|HOST|host|target|target_url|target_ip|port|PORT)\s*=` → propose substitutions in a diff.
- Inline IP regex in string literals (`\b(\d{1,3}\.){3}\d{1,3}\b`) and URL regex → propose substitutions with operator confirmation.
- msfvenom invocation lines in comments → preserve and update; treat as a one-shot payload-regeneration command for the operator to run separately.

Pre-flight flags ("operator review required"): any line containing `shellcode`, `\\x[0-9a-f]{2}` runs >32 bytes, offset arithmetic (`+ 0x[0-9a-f]+`), `struct.pack` / `p32` / `p64`, hardcoded version strings (`Windows 7 SP1`, kernel version regexes).

**Python 2→3 conversion note:** the `2to3` tool and `lib2to3` module were removed from CPython in Python 3.13 per PEP 594. Kali's current Python is 3.13.12, so `2to3` is not available on the engagement machine. Options: (1) ship `python-modernize` (third-party, installable via pip) as the conversion engine; (2) hand-roll the handful of patterns that actually appear in OffSec-era exploits (`print` statement → function, `urllib2` → `urllib.request`, `xrange` → `range`, `iteritems` → `items`, `raw_input` → `input`, `string.maketrans` → `bytes.maketrans`). Option 2 is preferable — the pattern set is small, the failure mode is explicit, and no extra dependency is needed on the engagement machine.

### B11. `targetcheckr.sh` — exploit-failure mode discriminator *(added post-review)*

**Name:** targetcheckr
**Type:** script
**Problem:** When an exploit fails, a trained operator can distinguish "I configured it wrong" from "the auth step failed" from "the box is unstable, restart it" from "this technique is wrong for this target" in seconds. A no-prep operator stares at "Connection refused" or a stack trace and cannot tell which category they're in. They may spend 90 minutes "fixing" an exploit that was always wrong for the target. The prior §6 wrongly conceded this gap as uncloseable.
**Solution:** `targetcheckr --target 10.10.11.42 --exploit-cmd '...the failing command...' --expected-port 8080` runs a structured discrimination: (1) baseline reachability (ping, TCP connect to expected port, full nmap top-100 if those fail); (2) re-runs the exploit with maximum verbosity and captures output; (3) classifies failure into one of five categories: `network` (target unreachable), `auth` (creds rejected), `path` (URL/endpoint wrong), `payload` (exploit ran but produced wrong response), `unknown` (no pattern match). Emits a verdict line plus the raw evidence and a one-line "most likely cause."
**Operator experience:** Exploit fails. Operator runs `targetcheckr` with the failing command. Gets back: "Target reachable on 8080. Exploit failed at auth step (HTTP 401 on /admin). Likely cause: wrong credentials or wrong endpoint path. Not a target problem." Operator stops fixing the exploit, starts checking credentials.
**Implementation effort:** ~5 days. Small, self-contained. The classification rules are the main work — ~30–50 patterns mapped to verdicts.
**Builds on:** None of the existing toolkit directly; reads `next_steps.txt` for context when available.
**Risk if it fails:** Mis-classifies a real network problem as an auth problem; operator wastes time chasing the wrong fix. Mitigation: always emit raw evidence alongside the verdict; never claim a verdict above a confidence threshold without the evidence to back it up; the `unknown` bucket is real and must be used liberally rather than guessing.
**Sketch:** New `~/scripts/targetcheckr.sh`. Reachability check order matters: lead with `nc -zv <target> <expected-port>` and `timeout 30 nmap -Pn -p <expected-port> <target>` (both bypass ICMP). **Do not lead with `ping`** — lab and engagement targets routinely block ICMP, and a ping-first probe produces false negatives that send the operator down the "network broken" path when the actual issue is service-level. Use `ping` only as a tertiary signal (and only to distinguish "host alive but service blocked" from "host fully unreachable"), never as the primary verdict input.

Exploit retry by re-invoking the failing command with stderr captured. Classification via regex patterns against stdout+stderr:
- HTTP status: `401`/`407` → auth; `403` → likely auth (could be path-policy, flag for operator); `404` → path; `5xx` → payload-or-target.
- Stack traces / exceptions: `socket.gaierror` or `NameResolutionError` (urllib3) → network; `ConnectionRefusedError` → service-down or wrong port; impacket `SessionError` with `STATUS_LOGON_FAILURE` → auth; impacket `SessionError` with `STATUS_ACCESS_DENIED` → auth-or-path (operator review); generic Python tracebacks without recognizable patterns → `unknown`.
- Timeout patterns (`timeout`, `timed out`, `TimeoutError`) → network-or-target-overloaded.

Bias liberally toward the `unknown` bucket rather than guessing — the prior version of this sketch named `KeyError` as a payload-class indicator, which was wrong (`KeyError` is too generic to map to any single failure mode). Always emit the raw retry output to `$TOOLKIT_ROOT/<target>/targetcheckr_<timestamp>.log` so the operator can read for themselves regardless of the classifier's verdict.

### B9. `controlpanelr.sh` — flag submission helper with pre-buzzer alarm

**Name:** controlpanelr
**Type:** script
**Problem:** OffSec+ requires flags to be submitted to the control panel before the engagement ends. Flags in the report but not the panel = zero points. A no-prep operator under fatigue at hour 22 will forget at least one flag.
**Solution:** Reads `evidencr`'s captured flags. Tracks which have been marked "submitted." Pre-buzzer alarms at T-60min and T-30min if any are unsubmitted. Optional helper: opens Chromium to the control panel URL with the flag values already in the clipboard ready to paste (operator still pastes and confirms — submission is the operator's hand).
**Operator experience:** Mostly invisible. At T-30min if any unsubmitted: a full-screen tmux popup that won't go away until the operator marks each one. "5 flags captured, 2 unsubmitted. Submit now. Press [Enter] after each submission."
**Implementation effort:** ~2 days. Clipboard integration + a small TUI confirm loop.
**Builds on:** evidencr's flag records.
**Risk if it fails:** The auto-clipboard could put the wrong flag in the operator's paste buffer. Mitigation: print the flag in big text in the tmux popup so the operator can visually verify before pasting.
**Sketch:** New `~/scripts/controlpanelr.sh`. Reads `$TOOLKIT_ROOT/evidence/*/flags.txt` for status. Pre-buzzer triggers from timekeeper. TUI confirm loop with one flag per screen. xclip / wl-copy for clipboard. Writes "submitted" status back to a known field in evidencr so orient and the board reflect it.

---

## 4. The build plan and the top-5 contraction

### The decision: build all seven, in this order

After review, the decision is to build all seven proposals listed below in the order shown. Each tool's dependencies feed the next; the order matters more than the calendar.

**Phase 1 — Content foundation (parallelizable with Phase 2):**

1. **A1 — `next_actions` on web/sqli + audit pass on the rest of the corpus.** Everything downstream queries exploitdb. If the corpus has dead-end entries when stuckr looks them up, stuckr is broken regardless of how well it's built. A1 is load-bearing for B1. (~3 days of seed authoring; no app or template changes.)

**Phase 2 — Decision layer (sequential):**

2. **B1 — `stuckr.sh`** (with A2's symptom→action map folded in). Build the state reader as `lib/state.sh` shared with future tools. Ranker can be simple: match triggers in state vector, return top 5 from exploitdb ordered by `exam_relevance`. A2's per-script sentinel emission is built alongside this, since stuckr needs the sentinels to read.

3. **B10 — `exploitfixr.sh`.** Build third because it has the most unknowns. Detecting LHOST/LPORT/RHOST/target-URL patterns reliably is the design work; the Python 2→3 pass is mostly `2to3`. Don't try to make it work on every exploit — make it work well on the 80% case (Python and Bash scripts with obvious config blocks at the top) and fail loud on the rest.

4. **B11 — `targetcheckr.sh`.** Small and self-contained — a good break from exploitfixr. Logic: baseline reachability, retry exploit with verbose flags, classify failure into network/auth/path/payload/unknown. Bias liberally toward `unknown` rather than guessing.

**Phase 3 — Operational resilience (independent, build in either order):**

5. **B5 — `watchdog.sh`.** Resolve the Penelope IPC question first (read Penelope source for whatever it exposes — session list, log path, status file). If no IPC exists, fall back to log tailing. Don't let this question block more than a day.

6. **B3 — `livefetch.sh`.** Six source adapters, priority order: **GTFOBins → LOLBAS → HackTricks → PayloadsAllTheThings → exploit-db search → NIST NVD**. GTFOBins and LOLBAS are the highest-value lookups and have clean structured data. HackTricks is the trickiest (large pages, need section extraction). If patience runs out, ship the first four and call NVD a v2.

**Phase 4 — Endgame (bundled, build last):**

7. **B6 + B9 — `proofr.sh` + `controlpanelr.sh` as one bundled build.** Last because they integrate with `evidencr` and shouldn't disturb it while other tools are still being built that read evidencr's state. They share enough state and TUI patterns that building together is cheaper than apart.

### "Done" criteria

Each tool ships when:

- All seven run end-to-end on a retired HTB box (QA, not practice — testing tools, not operator).
- `stuckr` returns non-empty results for every state vector that can be constructed.
- `exploitfixr` produces a valid diff on at least 5 of 7 randomly chosen public exploits from exploit-db.
- `targetcheckr` correctly classifies failures across all five buckets on a synthetic test suite (~15 known-failure scenarios).
- `watchdog` correctly detects an intentionally killed shell within 60 seconds.
- `livefetch` returns formatted output for at least the top four sources without network errors.
- `proofr` produces a screenshot containing all four required elements (`whoami`, `hostname`, `ip a`, flag) without operator intervention beyond providing the flag value.

Half-working decision-layer tools are worse than no tools. If any of the above fail, that tool isn't done.

### Top 5 if scope contracts to five

If the build can only ship 5 of the 7, the highest-leverage subset:

1. **A1 — `next_actions` on web/sqli.** Content fix, ~3 days, the single highest-leverage edit possible. No prerequisites.

2. **B1 — `stuckr.sh`** (with A2 folded in). The decision layer's anchor. The single most thesis-defining tool — "I don't know what to do next" is the core no-prep failure, and stuckr is the answer.

3. **B5 — `watchdog.sh`.** Fact-based detection of shell/VPN/tunnel drops. No other tool covers this. Shell drops at 3am are engagement-killers; watchdog catches them in seconds. **Promoted into the top 5** over the prior version's `timekeeper` because facts beat heuristics in a no-prep toolkit.

4. **B6 + B9 bundle — `proofr.sh` + `controlpanelr.sh`.** Closes the two known endgame failure modes: incomplete proof screenshots (forgotten `ip a`) and unsubmitted flags (zero points despite capture). Built together, they share state with evidencr and reuse the same TUI pattern. Treating them as one entry is honest scoping.

5. **B3 — `livefetch.sh`.** Turns the "internet allowed, AI not allowed" rule from a passive fact into an active terminal tool. The single biggest force multiplier external to the local toolkit.

**Drops from the prior version's top 5:** `orient.sh` (the operator can run `evidencr --rollup` manually and survive — real but lower-leverage than watchdog); `timekeeper.sh` (a phone alarm set the night before for hours 4/8/12/16 covers most of the value — not nothing, but not top-5 either). Both remain in List B as v2 candidates.

**Why `exploitfixr` and `targetcheckr` are in the seven-tool build but not the top 5:** They close specific failure modes that nothing else covers (and that §6 previously and wrongly conceded as uncloseable), but if the operator has minimal code literacy they can survive the 80% case manually. Watchdog, proofr, and controlpanelr each prevent a *catastrophic* and *unrecoverable* loss; exploitfixr and targetcheckr prevent *time loss*, which is more survivable.

---

## 5. Anti-list — proposals rejected, with reasons

These were considered and cut. Sharpening the build list by stating what is *not* worth building.

### X1. An AI-powered "explain this output" sidebar in the exploitdb app
Dead on arrival. AI is not allowed at engagement time. Even if the model ran fully local, the spirit of the rule is no-AI-assistance — using it would be cheating regardless of local execution.

### X2. Auto-exploitation on top of any script
Violates AGENTS.md §2 (the bright line) and OffSec engagement rules. Also undermines the operator's ability to demonstrate manual technique in the report, which is what OffSec grades.

### X3. A "drill mode" / practice-box simulator inside the toolkit
Violates the no-prep thesis directly. The thesis is that the operator does not practice. Building a practice mode is admitting the thesis is false. Either the thesis holds without practice, or the experiment is over — there is no middle ground where "a little practice in our own tools" is allowed.

### X4. A flashcard system for technique recall
Same as X3. Memorization-via-spaced-repetition is exactly the form of prep the thesis rejects. If recall is needed at the keyboard, the toolkit should surface it, not the operator's brain.

### X5. An adaptive-difficulty learning mode
Same family as X3, X4. "The tool helps you learn over weeks" is not the thesis. Cut.

### X6. Auto-screenshot every command and every shell action
Considered. Rejected because evidencr already covers per-target evidence capture, and indiscriminate screenshots create signal-to-noise problems the operator must then triage. A targeted `proofr.sh` (B6) that captures the specific OffSec-required composition is the right shape; an "every keystroke" recorder is wrong shape and would cost time at submission.

### X7. A chat-with-experts integration / "phone a friend"
Operator is alone at engagement time per OffSec rules. Any human-help integration violates the engagement. Building one undermines the legitimacy of the experiment even if it goes unused.

### X8. A "next button" that auto-runs the top-ranked `next_steps` command
Considered seriously. Rejected because it removes the operator's awareness of what their tools are doing. If the auto-run wrong-targets a box or burns lockout attempts, the operator can't recover from a state they didn't see being created. The handoff says "the operator brings literacy and typing" — auto-running pushes past literacy into "the tool does it for them," which the thesis explicitly forbids. The operator pastes one line that the tool composed; they do not surrender execution.

### X9. A "score this finding" rubric that predicts whether the report-graded write-up will pass
Considered. Rejected because OffSec's grading rubric is not public in actionable detail and any built rubric would be a guess that could mislead the operator about a passing report. Better to invest in templates that make the write-up easier and leave grading to the grader.

---

## 6. Honest assessment of the thesis *(revised post-review)*

The prior version of this section conceded two gaps as uncloseable by tooling: (1) modifying public exploit code, and (2) distinguishing a misconfigured exploit from a broken target. Both concessions were wrong. They are closeable — `exploitfixr.sh` (B10) handles the 80% case of exploit modification (LHOST/LPORT/RHOST swaps, target URL updates, Python 2→3, encoding adjustments) and `targetcheckr.sh` (B11) handles failure-mode discrimination (network / auth / path / payload / unknown) via baseline retry. Both are now in the build plan. The "uncloseable" framing was a flinch; this revision retracts it.

The thesis as literally stated ("only literacy and typing") is still a mild overstatement — the operator brings a small set of additional minimums no tool can fully substitute for: reading short blocks of text and accepting their guidance, making a handful of judgment calls when the tool's ranking ties or returns `unknown`, recognizing visually whether a proof screenshot is right, and the willingness to type one corrected line when a tool says what's wrong. These are minimums of *operator competence at the keyboard*, not of *prep*. They cost nothing in study time and can be assumed for any literate adult.

The thesis as charitably restated — that **tooling can stand in for muscle-memory-from-repetition** — is defensible with the full seven-tool build.

**Pass-probability estimate (standard-flavored OffSec+ boxes):**

- Toolkit as-is, no proposals built: ~30–40%.
- Toolkit + top-5 contraction (A1, B1, B5, B6+B9, B3): ~55–65%.
- Toolkit + full seven-tool build (adds exploitfixr, targetcheckr): ~60–70%.

That is not a guarantee of 70/100. It is "more likely than not." The remaining residual risk:

- **Boxes with vulnerabilities outside the curated corpus.** OffSec varies their boxes. A custom application with a novel vulnerability pattern requires reasoning from primitives. `stuckr` returns ranked next moves but cannot invent a never-seen technique. `livefetch` mitigates by pulling HackTricks/PayloadsAllTheThings/LOLBAS/GTFOBins at engagement time, but the operator still must read and apply.
- **Time pressure on AD chains.** Even with `stuckr` and the live engagement board (`evidencr --board`, A9), the no-prep operator is slower per decision than a trained one. 23h45m may not be enough if multiple targets force backtracking.
- **The `exploitfixr` 20% case.** Exploits that require shellcode regeneration, syscall-level adjustments, or non-obvious offset math fall outside what `exploitfixr` can handle — it must fail loud on those. The operator either skips them (acceptable if other points are available) or fails on them.
- **The `targetcheckr` `unknown` bucket.** Failure modes that don't match any classification rule return `unknown` and offer no useful verdict. The operator falls back to manual diagnosis.

**Bottom line:** the thesis is defensible with the full seven-tool build. It is not defensible with the toolkit as-is, and only partially defensible with the top-5 contraction. The experiment, in honest form, is: *build these seven tools, validate against retired boxes, then close the AI prep entirely and walk into July 9 with literacy, typing, and the corpus made executable.* That is a falsifiable claim with a measurable outcome — the operator either clears 70/100 or they don't, and the result is data about whether tools can substitute for repetition. The earlier "partially defensible" framing was hedging; the corrected framing is binary, testable, and worth the experiment.
