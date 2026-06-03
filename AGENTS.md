# AGENTS.md — OffSec Toolkit

Authoritative instructions for any coding agent (Claude Code, Codex, Cursor, etc.) working in this repository. Read on every session. Vault content and this file override general training knowledge.

---

## 1. Mission

**Get Jason to a passing OffSec score on June 6.**

Every change, every suggestion, every edit is evaluated against one question: *does this make engagement execution faster, more reliable, or more correct?* If it doesn't, don't make it.

Reach the objectives. engagement = the engagement window + 24h report. Targets: 3 standalones (each, local + proof) + 1 AD set (10 + 10 + 20). The scripts and cheatsheets in this repo are the primary execution surface. Treat them as such.

Bias every decision toward: **reducing cognitive load under pressure, reducing the number of things that can fail at 3am, and making the reproducibility chain that the grader will walk as tight as possible.**

---

## 2. Enumeration-only, always

This is the bright line. Do not cross it.

- Scripts in this suite are **enumeration, orchestration, and reporting only**. No auto-exploitation. Ever.
- If a change would add an exploit trigger, a payload delivery, a credential-use-to-execute-code flow, or anything that performs the "gain a shell" step automatically — **stop**. That belongs in manual playbooks, not the suite.
- Generating copy-paste commands for Jason to run manually is fine. Running them for him is not.
- Credential spraying (`sprayr.sh`), hash cracking (`crackr.sh`), BloodHound collection (`adr.sh`), privesc enumeration (`escalatr.sh`) — all fine. These are enumeration, not exploitation.
- The distinction matters for the engagement compliance **and** for Jason's muscle memory. Automating exploitation is how people fail the engagement thinking their scripts will save them.

---

## 3. Non-negotiable tool conventions

These override model defaults. Do not "correct" them.

- **`nxc` (NetExec) — never `crackmapexec` or `cme`.** CME is deprecated. Every reference, every command, every doc string: `nxc`.
- **Penelope with `-0` (zero) flag** is the standard reverse shell handler. Not `nc -lvnp`, not `rlwrap nc`, not `pwncat`. Penelope.
- **SharpHound + `impacket-smbserver`** for BloodHound collection. `bloodhound-python` / `bloodhound-ce-python` is unreliable in this environment (DNS SRV timeouts against lab DCs). Do not suggest it as the primary path.
- **`pipx`** for Python tool installs (e.g. `git-dumper`). Not `pip` into system Python.
- **Wordlists live in `/usr/share/wordlists/`** unless a specific script override exists.
- **`TOOLKIT_ROOT`** defaults to `~/toolkit`. Tools live in `~/tools/`. Scripts live in `~/scripts/`.
- **Ligolo-ng** over chisel/SSH for pivoting when possible — real TUN interface, no proxychains.
- **PrintSpoofer / GodPotato** for `SeImpersonatePrivilege` on modern Windows. JuicyPotato only for older boxes.

---

## 4. Script-first doctrine

The cheatsheets and scripts are structured around one principle: **automation runs first, manual commands are the fallback.**

- Manual commands in cheatsheets must be gated behind an explicit "script found nothing" trigger. Do not promote a manual command to equal status with script output.
- When adding a feature to a cheatsheet, check whether the corresponding script already covers it. If it does, reference the script; do not duplicate the command inline at the top level.
- Never propose replacing a script with a one-liner. The scripts exist because one-liners fail under time pressure.
- **Crack-then-spray discipline:** cracked passwords flow immediately into spraying (`crackr.sh → sprayr.sh --from-creds`). Any change touching either script must preserve this loop.

---

## 5. Script suite inventory

| Script | Purpose |
|---|---|
| `recon.sh` | Host recon orchestrator (rustscan → nmap → service enum) |
| `webenum.sh` | Deep web enumeration (post-recon, extensions + recursion + vhosts + params) |
| `escalatr.sh` | Privesc enumeration orchestrator (Linux + Windows, tool staging) — **enumeration only** |
| `lootr.sh` / `lootr.ps1` | Credential/loot hunting (Linux / Windows) |
| `crackr.sh` | Hash identification + cracking dispatcher |
| `sprayr.sh` | Credential spraying across protocols |
| `adr.sh` | AD enumeration + kill chain (`--chain` mode) |
| `pivotr.sh` | Ligolo-ng pivot automation (TUN + routes + teardown) |
| `servr.sh` | Workspace setup (HTTP server, Penelope, tmux layout) |
| `evidencr.sh` | Evidence capture (terminal logs, screenshots, per-target orgs) |
| `startr.sh` | engagement bootstrap |
| `tools_setup.sh` | Fresh Kali provisioning — authoritative for directory layout |

---

## 6. Bash script conventions (match the suite)

All scripts share a house style. New code MUST match:

- **Shebang:** `#!/usr/bin/env bash`
- **Error handling:** `set -o pipefail`. **Do NOT use `set -e`** — scripts handle errors individually; one failed phase must never kill the run.
- **Banner block:** multi-line comment header with PURPOSE, WORKFLOW, USAGE, OUTPUT STRUCTURE, DESIGN DECISIONS. Match the visual style of `recon.sh` / `webenum.sh` / `escalatr.sh` (double-equals separator bars).
- **Colors + logging:** `info()`, `success()`, `warn()`, `error()`, `phase()`, `cmd_log()` helpers. Timestamps via `ts()`. Auto-disable colors when `NO_COLOR=1` or stdout is not a tty.
- **Timeouts on everything.** `timeout N <cmd>` for any external tool call. Nothing hangs the engagement. Named timeout constants at the top of the file.
- **Graceful degradation.** If an optional tool is missing, warn and skip the phase. Only exit on truly critical missing tools (e.g. `nxc` for `adr.sh`).
- **Resume support.** Phases check a `progress.log` / `phase_done` marker and skip if complete. `--force` re-runs.
- **Output layout:** `$TOOLKIT_ROOT/<category>/<target>/...`. Never scatter files into cwd.
- **Quoting:** always quote variable expansions. Prefer `"${VAR}"` over `$VAR`. Pass arrays for nxc auth (`"${NXC_AUTH[@]}"`) — never flatten.
- **Config at top:** All tunables (timeouts, URLs, threads, ports) in a clearly-labeled CONFIGURATION section at the top.

---

## 7. Editing discipline

This is how edits are expected to land. Deviating wastes a review cycle.

- **Surgical edits only.** Tighten and insert. **Do not flatten, do not rewrite, do not restructure** unless explicitly asked.
- **Preserve existing improvements.** If something looks odd, assume it's intentional until verified. Ask before removing.
- **No "helpful" expansion.** Do not add examples, explanatory comments, or defensive checks that weren't requested. The docs are already tuned for execution speed; verbosity is a regression.
- **Verify before writing.** Script-specific details (filenames, flag names, output paths, function names) are verified against actual script content before being referenced. No hallucinated flags.
- **Don't introduce dependencies.** If a change requires a new tool, call it out and wait for approval. Do not silently add `jq`, `yq`, `python3-<whatever>`, etc.
- **Rewrites disguised as cleanups are rejected on sight.** Symptoms: adds headers and visual polish while removing content; flattens tiered callouts into flat bullets; replaces specific commands with generic prose; "cleans up" working code into broken code.

---

## 8. Review format

When reviewing a script or doc (before any edit), output in this exact five-part structure:

1. **Verdict** — one line: ready / needs revision / broken.
2. **What is working** — short; only note things that should be preserved.
3. **What still slows execution** — friction points under time pressure.
4. **What is missing** — coverage gaps vs. PEN-200 2025 or vs. the rest of the suite.
5. **Done or needs revision** — explicit next step.

**Do not make changes during review.** Review is read-only. The next message ("do it" / "make the change" / "go") is when edits happen. If review and edits are collapsed into one response, that's a protocol violation.

---

## 9. engagement compliance (hard rules)

Every change is evaluated against these:

- **Metasploit is restricted to ONE machine** on the engagement. The restriction is per-*machine*, not per-module. Post-exploitation modules on an already-compromised machine do not count as additional uses. Do not add Metasploit calls to scripts that run on arbitrary targets.
- **`sqlmap` is banned** in an engagement boxes. Do not reference it in an engagement-path tooling.
- **Automated exploitation tools are banned.** See §2 — this is the bright line.
- **Commercial tools are restricted.** Burp Community is fine; Burp Pro features are not.
- **Screenshots + `whoami` + `hostname` + flag from original path** are required on every compromise. Interactive shell — web shells do not count for proof. Any evidence-tooling edit must preserve this.
- **Flags must be submitted to the engagement tracker before an engagement time expires.** Flags in the report but not in the engagement tracker = an unrecorded finding. Evidence tooling should make this hard to forget.

---

## 10. Response style

- Concise and technically precise. No over-explaining basics.
- Direct answers. No "Great question!" preamble. No hedging wrap-up.
- Code fences use language tags (`bash`, `powershell`, `python`). Bash scripts get `bash`, not `sh`.
- Warnings use Obsidian callout syntax: `> [!warning]`, `> [!important]`, `> [!tip]`, `> [!note]`.
- When uncertain, say so and stop. Do not fabricate flags, paths, or function names.
- Lab domain in docs/examples: `corp.com`. Lab Windows host: `CLIENT75`.

---

## 11. What NOT to do

- Do not replace `nxc` with `crackmapexec`.
- Do not replace Penelope with `nc`/`rlwrap`/`pwncat`.
- Do not add `bloodhound-python` as the BloodHound collection path.
- Do not add `set -e` to any script.
- Do not flatten tiered callouts in cheatsheets into flat bullet lists.
- Do not restructure a doc or script as part of a "while I'm here" cleanup.
- Do not add auto-exploitation to any script.
- Do not generate multi-file rewrites in response to a single-file review.
- Do not skip the review step and jump straight to edits.

---

## 12. exploitdb subproject

`~/scripts/exploitdb/` is a local Flask app: read-only OffSec technique reference (442 entries served, FTS5-indexed) + per-engagement findings intake. Companion to the `.sh` scripts, not a replacement. Vault doc: [[exploitdb]] at `vault/_SCRIPTS/exploitdb.md`.

**Architecture you must respect:**

- **Drop-and-rebuild loader, not migrations.** `load_seed.py` deletes `data/exploitdb.sqlite` and recreates it from `data/seed/*.json` in ~30ms. Schema change = edit `SCHEMA` + `INSERT_COLS` + `normalize_entry()` + the FTS `INSERT` statement, then `./run.sh rebuild`. No `ALTER TABLE` logic exists or is needed.
- **Two SQLite files, different lifecycles.** `data/exploitdb.sqlite` (curated reference, gitignored, regenerated from seed). `$TOOLKIT_ROOT/findings/findings.sqlite` (per-engagement user data, gitignored, lives under the engagement directory like every other toolkit artifact; survives rebuild). Don't merge them.
- **Banned-entry filter at load time.** Entries with `compliance: offsec_banned` are excluded by `load_seed.py`. Source has 443+ entries; app serves 442 (and rising as new entries are curated). Filter is intentional — banned techniques have no operator use.

**Testing model:** `audit_app.py` is the test framework. End-to-end against a running server; ~574 requests in ~3s; reports failures + warnings + p50/p95/max timings. Extend by adding `# ---- 7x. <feature> ----` blocks following the existing pattern; clean up any test rows you create. **Do not introduce pytest.**

**UI conventions:**

- Server-rendered Jinja + htmx partials. Templates with leading `_` are partials. `HX-Request` header switches a route to its partial response (see `/search`, `/category/<name>`, `/intake/slug-complete`).
- All static assets vendored — htmx, Pico.classless CSS, custom `app.css`. **No CDNs.** Verify with `audit_app.py` if you change static deps.
- No JS framework. Vanilla JS for keyboard handlers and copy buttons; htmx for everything else.

**Toolkit-integration contracts (don't break these):**

- `produced_by_script` field on an entry → app renders canonical `$TOOLKIT_ROOT/...` output paths from the `SCRIPT_OUTPUTS` mapping in `app.py`. If you change a `.sh` script's output paths, update `SCRIPT_OUTPUTS` to match.
- Obsidian deep-links use `obsidian://open?vault={EXPLOITDB_VAULT_NAME}&file=_SCRIPTS/<script>` to surface the script's vault doc from inside the app. The vault must have those docs.
- Commands are rendered verbatim from seed JSON. **No paraphrasing, no "modernization", no silent corrections.** If a command needs fixing, fix the seed JSON.

**Gate discipline for structured handoffs:**

Kickoff prompts under `exploitdb/` (see `APP_BUILD_BRIEF.md`, prior handoff messages) include explicit gates: "Step 0: read first, report, wait for confirmation" and intermediate "show me the rendered example before continuing past step N". Respect them. The operator has been consistent about these; skipping them wastes review cycles.

**What NOT to do in exploitdb:**

- Don't merge findings into the entries DB
- Don't add pytest, a JS framework, or a build step
- Don't auto-launch exploits or auto-import terminal scrollback
- Don't paraphrase commands in templates — render `e.commands` as-is
- Don't write to `$TOOLKIT_ROOT` from the app (read-only contract — only `.sh` scripts write there; the findings DB is the one exception, and the path is parameterised by TOOLKIT_ROOT explicitly)
- Don't bypass the "Step 0" gate on a fresh handoff prompt

---

## Workspace And Output Rules

- Default OffSec output belongs under `$TOOLKIT_ROOT`, with `$HOME/toolkit` as the
  normal fallback.
- For Kali-side scripts that may run through `sudo`, resolve `$TOOLKIT_ROOT` to the
  invoking user's home via `$SUDO_USER` instead of silently writing to
  `/root/toolkit`.
- Help text, docs, final status output, and actual output paths must agree.
- Validate arguments before creating output directories when practical,
  especially phase/mode selectors.
- Check `mkdir -p` failures for primary output roots and exit with a clear
  error. Do not continue after failing to create the workspace.
- Keep per-tool artifacts in their existing script-specific structure:
  `recon/<ip>/`, `web/<target>/artifacts/web/`, `ad/<domain>/`,
  `spray/<run>/`, `crackr/`, `privesc/`, `evidence/`, and lootr target loot.

---

## Evidence-Gated Next Steps

- Every generated command should have a concrete trigger: non-empty output file,
  parsed positive result, nmap service line, progress marker, or validated
  credential/admin marker.
- Prefer `next_steps.txt` as the primary action file. Keep legacy aliases only
  where scripts already use them.
- Summaries may preview next actions, but they must not invent findings. Prefer
  pointing to `next_steps.txt` for full command blocks.
- Anonymous SMB/FTP/LDAP/NFS follow-ups require proven anonymous access or a
  positive readable/export artifact, not merely an open port.
- Web commands should distinguish real web apps from management HTTP endpoints.
  WinRM/HTTPAPI ports `5985`, `5986`, and `47001` are not brute-force web
  targets without stronger evidence.
- AD lateral movement, relay, DCSync, BloodHound review, and on-host PowerView
  steps must be tied to artifacts such as validated domain context, user lists,
  roast hashes, computer lists, SMB signing findings, BloodHound zips,
  privileged sessions, or admin-on-DC markers.
- Windows privesc next steps must reflect exploit preconditions. For example,
  AlwaysInstallElevated requires both HKLM and HKCU enabled, and scheduled-task
  payload advice requires a proven writable high-privilege task binary.
- Avoid generic canned commands at the top of summaries. If a command includes
  placeholders, the surrounding evidence should explain what still needs human
  replacement.
- Exploit payloads over ~200 chars must be staged to files in
  `$work_dir/loot/` and referenced by path in emitted commands. Never embed
  long exploit strings inline in `append_next_finding` or bash heredocs.
- Emitted commands inside `append_next_finding` should also stay under ~200
  chars per line — long lines are fragile against Edit truncation, classifier
  blocks, and tmux paste mangling (split with line-continuations or stage
  the payload).
- Files staged to `$work_dir/loot/` persist across runs intentionally (they
  serve as evidence); `prune_recon_artifacts()` does not touch them.

---

## Command And Runtime Reliability

- Prefer arrays for commands with optional flags. Do not rely on unsafe word
  splitting for multi-argument options such as `-M lsassy`.
- Quote paths and variables unless a command intentionally needs separate array
  elements.
- Be careful with `echo` and Windows paths; use `printf` when backslashes or
  escape sequences could be mangled.
- Timeouts should use the configured runtime variables where present, and logs
  should show enough budget/progress information for the engagement use.
- Tool detection should degrade gracefully for optional tooling and fail early
  for truly required tooling.
- If a faster helper is optional, preserve coverage through a slower fallback
  where practical, such as nmap full-TCP discovery when rustscan is missing.
- When running as root through `sudo`, include invoking-user tool paths where
  the script already supports user-installed tooling.
- Keep long-running phases interrupt-safe and preserve partial results.

---

## Tool Setup Rules

- `tools_setup.sh` should install/check OffSec-safe recon and enum helpers by
  default. Include tools that Kali images often lack when they directly support
  recon evidence, such as `httpx-toolkit`, `gowitness`, `eyewitness`,
  `sslscan`, `wafw00f`, `dnsrecon`, `snmpcheck`, `nbtscan`, `davtest`,
  `cadaver`, `nuclei`, `wpscan`, and `jq`.
- Keep restricted automatic exploitation tools out of `tools_setup.sh` and
  generated next-step commands. Exception: `nuclei` and `wpscan` may appear in
  generated next-step commands when tied to concrete findings (e.g. Grafana,
  WordPress evidence).
- Check-mode package validation should map package names to real binaries when
  they differ, for example `httpx-toolkit` to `httpx` and `samba-common-bin` to
  `nmblookup`.

---

## PowerShell / Windows Script Rules

- `lootr.ps1 -Help` should work from Kali/PowerShell Core even though normal
  collection is Windows-only.
- Validate `-Phase` before creating output directories.
- Parse Windows service/task executable paths carefully; unquoted paths with
  spaces are common.
- Writable checks should consider the current user and group memberships, not
  only exact user ACEs.
- Keep collection passive. Generate next steps, but do not run privesc payloads.

---

## Testing

Run these before committing script changes:

```bash
bash -n recon.sh webenum.sh crackr.sh sprayr.sh adr.sh escalatr.sh lootr.sh pivotr.sh servr.sh startr.sh workflow.sh tools_setup.sh evidencr.sh stuckr.sh exploitfixr.sh targetcheckr.sh
shellcheck recon.sh webenum.sh crackr.sh sprayr.sh adr.sh escalatr.sh lootr.sh pivotr.sh servr.sh startr.sh workflow.sh tools_setup.sh evidencr.sh stuckr.sh exploitfixr.sh targetcheckr.sh
pwsh -NoProfile -Command '$errs=$null; $null=[System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw ./lootr.ps1), [ref]$errs); if ($errs) { $errs | Format-List; exit 1 }'
tests/test_state.sh
tests/test_exploitfixr_smoke.sh
tests/test_targetcheckr_demo.sh
```

Also validate relevant help/argument behavior when touching parsers:

```bash
./recon.sh --help
./webenum.sh --help
./adr.sh --help
./sprayr.sh --help
./lootr.sh --help
pwsh -NoProfile -File ./lootr.ps1 -Help
```

For workspace changes, run a sudo-environment simulation in library mode, for
example:

```bash
bash -c 'SUDO_USER=jdoe HOME=/root OffSec_LIB_ONLY=true source ./webenum.sh; printf "%s\n" "$TOOLKIT_ROOT"'
```

For invalid phase/mode changes, verify the script exits non-zero before creating
new output directories.

---

## Git Hygiene

- Do not commit `.claude/settings.local.json`.
- Do not commit `.DS_Store`.
- Check `git status --short` before staging.
- Stage only files relevant to the task.

---

## Documentation

When behavior changes, update the related file under `docs/`. Keep docs aligned
with actual output filenames and avoid claiming a command is generated unless a
real trigger exists in the script.
