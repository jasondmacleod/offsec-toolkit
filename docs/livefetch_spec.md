# livefetch.sh — design spec (build 6 of 7)

> Status: **design locked**, ready for a fresh Code build session.
> Authored against real ground truth in `~/scripts/` (paths/markers/flags
> verified with line refs throughout). The build session re-runs its own
> Phase 0 FS-verify per protocol — see §11. Every `⚠` is an open verification
> item the build session must resolve before coding the affected stage.

---

## §1 Purpose & role

livefetch is the **"pull current intel for the targets I'm working" tool**. The
operator has been on a target for a while, has recon artifacts on disk, and
wants to **selectively re-run the right recon stage(s), diff the new output
against what's there, and surface what changed** — without re-running the full
`recon.sh` from scratch.

livefetch is a **wrapper, not a recon tool**. It does not invent scans. It
drives the existing collection scripts (`recon.sh`, `webenum.sh`,
`adr.sh`) with the discipline of "only re-run what's stale or input-changed,
diff the output, surface the delta." Build order: stuckr → exploitfixr →
targetcheckr → watchdog → **livefetch** → proofr+controlpanelr.

It is the **first downstream consumer of watchdog's `success-liveness-*`
events** and feeds proofr the "what's new since last fetch" signal.

---

## §2 The two-tree architecture (the central finding)

The toolkit has **two disjoint filesystem trees, and nothing bridges them**:

| Layer | Owner | Tree | Populated in real engagements? |
|---|---|---|---|
| **Decision** | `state.sh`, stuckr, exploitfixr, targetcheckr, watchdog | `$TOOLKIT_ROOT/targets/<ip>/{recon,web,ad,evidence,state}/` | **Only `state/`** (sentinels.log, foothold.log, *_runs.log). `recon/`/`web/`/`ad/`/`evidence/` subdirs have **no producer** — `state_read_target` reads them but in a real engagement they're empty (validated against synthetic test fixtures only, e.g. `tests/test_watchdog_demo.sh:177`). |
| **Collection** | `recon.sh`, `webenum.sh`, `adr.sh` | `$TOOLKIT_ROOT/recon/<ip>/`, `$TOOLKIT_ROOT/web/<host>_<port>_<proto>/`, `$TOOLKIT_ROOT/ad/<domain>/` | **Yes** — this is where artifacts actually land. |

`TOOLKIT_ROOT` defaults to `$HOME/toolkit` (`state.sh:47`, `recon.sh:67-76`),
**not** the `~/scripts/` repo.

**Decision (locked): livefetch lives in the collection layer (Option 1).** It
reads/diffs the real `recon/<ip>/`, `web/<host>/`, `ad/<domain>/` trees, re-runs
the wrapped scripts in place, and emits deltas as `state_write_event` sentinels
into the decision layer's `state/` tree (the one cross-tree write the existing
API supports — `state.sh:367` — and the one watchdog already uses). It does
**not** normalize collection→decision trees; that's the planned `orient.sh`'s
job (`state.sh:6` names it). AGENTS.md:209 ("keep per-tool artifacts in their
existing script-specific structure") supports this. See §9.

---

## §3 Input sources (all read-only)

- **State vector:** `state_read_target <ip>`, `state_read_global` (creds/domain/
  dc_ip), `state_read_footholds <ip>` — all from `lib/state.sh`, missing-file-safe.
- **Liveness:** `watchdog --json` (`watchdog.sh:25` — "livefetch consumes") for
  ALIVE/STALE/DEAD/UNKNOWN per resource; and the `success-liveness-{shell-died,
  shell-stale,recovered}` sentinels watchdog writes (`watchdog.sh:224,238-239`).
- **Collection artifacts:** the `recon/<ip>/`, `web/<host>_<port>_<proto>/`,
  `ad/<domain>/` trees and their per-script `progress.log` (the DONE-marker
  state that drives re-run; see §5).

---

## §4 Invocation modes / CLI

```
livefetch --target <ip>                       all stages, default --since 30m
livefetch --target <ip> --stage recon|web|ad|from-foothold
livefetch --diff-only --target <ip>           run→diff→discard (read-only, no persist, no sentinels)
livefetch --all [--since 1h]                  every target with artifacts older than --since
livefetch --json                              machine-readable (for proofr)
livefetch --no-cascade                        suppress downstream cascade (see §6)
livefetch --target <ip> from-foothold <file>|-|--tmux-pane <id> [--label <name>]
livefetch --verbose                           full unified diff in addition to the structured summary
```

Input-ingestion for `from-foothold` mirrors **targetcheckr's contract**
(`targetcheckr.sh:14,29-30,142-160`): positional `<file>` | `-` (stdin) | bare
pipe | `--tmux-pane <id>`. There is **no `--from-stdin` flag** (the original
handoff named a phantom flag; corrected here for toolkit consistency).

---

## §5 Stage taxonomy (30 stages)

**Re-run mechanism (uniform).** No collection script has a per-stage flag. Each
gates phases on a `progress.log` DONE marker (`recon.sh:213`,
`webenum.sh:231`, `adr.sh:89`). So livefetch's per-stage re-run is:

> **snapshot the stage's artifacts aside → strip the `| DONE | <marker> |` line
> from the live `progress.log` → invoke the wrapped script → diff regenerated
> output against the snapshot.**

Scripts **overwrite fixed filenames in place** (no timestamping), so the
snapshot-then-rerun-then-diff order is mandatory. Crash mid-stage is safe: the
script re-runs that phase next time (idempotent).

**The marker table below is a RECOGNITION reference, not a CONSTRUCTION rule.**
The build Phase 0 found the original bare-vs-suffixed pattern-match wrong for 4
of 15 services, so livefetch **discovers** the `| DONE | <marker> |` lines from
the live `progress.log` and maps marker→stage by string — it never constructs a
marker from a rule. Verified marker shapes (`recon.sh`): **bare** =
`smb`, `ssh`, `ftp`, `dns`, `ldap`, `rpc`, `snmp`; **`<svc>_<port>`** = `http`,
`mysql`, `mssql`, `postgres`, `redis`, `smtp`, `pop3`, `imap`. Discovery also
catches the no-rustscan fallback marker `nmap_tcp_discovery` and the
`nmap_udp_full` variant without special-casing.

Sentinel keys (§8): **DELTA**=`success-livefetch-delta-detected`,
**SVC**=`…-new-services-found`, **USR**=`…-new-users-found`,
**EXP**=`…-new-exploits-found`.

### 5.1 Recon scan tier — `recon/<ip>/`, re-run via `recon.sh --auto <ip> [--outdir DIR]`

| # | Stage (marker) | Artifact → diff target | Noise filters | Meaningful delta → key |
|---|---|---|---|---|
| 1 | tcp-discovery (`rustscan` ⚠fallback) | `scans/tcp_ports.txt` (CSV) | none (sort CSV); port-flap absorbed by 60s dedupe | new port→**SVC**; dropped port→**DELTA** |
| 2 | tcp-services (`nmap_tcp`) | `scans/nmap_tcp.nmap`(`.xml`) | strip `# Nmap …initiated/done`, latency value, `\|_clock-skew:` | new/changed svc·version, new NSE finding, state change→**SVC**/**DELTA** |
| 3 | tcp-vulnmatch (*rides nmap_tcp*) | `loot/{searchsploit_hits,vulners_hits}.txt` | strip searchsploit local Path col | new CVE/EDB→**EXP** |
| 4 | udp-scan (`nmap_udp`) | `scans/udp_ports.txt`, `nmap_udp.nmap` | nmap comment/latency; suppress `open\|filtered` churn | new definitive UDP open→**SVC** |
| 5 | recon-summary (*regenerated*) | `summary.txt`, `loot/{quick_wins,next_steps}.txt` | strip `# Started`/`[ts]` prefixes; line-set diff | new quick-win·next-step→**DELTA** |

- Stage 4 needs root (`recon.sh` NOTES); non-root → report "skipped, needs sudo", no empty diff.
- Stage 3/5 have no own marker — regenerated when stage 2 (resp. any stage) re-runs.

### 5.2 Recon per-service tier — `recon/<ip>/tcp/`, re-run via `recon.sh --auto <ip>`

| # | Stage (marker) | Artifact → diff target | Noise filters | Meaningful delta → key |
|---|---|---|---|---|
| 6 | http-quick (`http_<port>`) | `tcp/http/port_<port>/{whatweb,gobuster_dir,feroxbuster,nikto,http_methods,tls_names}.txt` | strip curl_headers `Date:`/`Set-Cookie:`; nikto banner+`Start/End Time`+`N requests/errors`; feroxbuster `Configuration{}` block; gobuster `Progress:` | **new write-capable HTTP method (PUT/PROPFIND/WebDAV)→SVC**; new path·title·tech·nikto·method·TLS-name→**DELTA** |
| 7 | smb (`smb` bare) | `tcp/smb/{netexec_shares,smbmap_*,enum4linux.json,nmap_smb_vuln}.txt` | diff `enum4linux.json` not `_console.txt`; strip nmap comments | new share·null/guest·SMB-vuln→**SVC**; new user/RID→**USR** |
| 8 | ssh (`ssh` bare) | `tcp/ssh/{version_info,nmap_ssh_scripts}.txt` | strip nmap comments | banner·version·auth-method·NSE→**DELTA** |
| 9 | ftp (`ftp` bare) | `tcp/ftp/{anonymous_check,banner,version_info,nmap_ftp_scripts}.txt`, `mirror/` | strip banner date; nmap comments | anon access→**SVC**; new mirror file·banner·NSE→**DELTA** |
| 10 | svc-generic (`<svc>_<port>`) | `tcp/<svc>/{banner_<port>,nmap_<svc>_<port>}.txt` for mysql·mssql·postgres·redis·smtp·pop3·imap·ldap·dns·rpc | strip nmap comments + banner timestamps | unauth access (redis/mysql/anon-LDAP-bind)→**SVC**; banner·version·NSE→**DELTA**; `ldap_<port>` anon-bind users→**USR** (deep enum→adr, §6) |

### 5.3 webenum tier — `web/<host>_<port>_<proto>/artifacts/`, re-run via `webenum.sh --url <proto>://<ip>:<port> [--deep|--vhost <domain>]`

Keyed **per web service**, not per IP. Depth-discipline (§6): `recursive`/`params`
re-run only if their dirs already exist (→ `--deep`); `vhosts` only if vhost
artifacts exist + domain known (→ `--vhost <domain>`). A recon HTTP port with no
`web/` dir is a **proposal** (`webenum.sh --from-recon <ip>`), not a re-run.

| # | Stage (marker) | Artifact → diff target | Noise filters | Meaningful delta → key |
|---|---|---|---|---|
| 11 | web-fingerprint (`fingerprint`) | `fingerprint/{httpx.json,http_methods,whatweb}.txt` | strip httpx `timestamp`·`response-time`·`body-sha256`·`header-sha256`; `headers.txt` `Date:`/`Set-Cookie:` | **new write-capable HTTP method→SVC**; new tech·CMS·title·status→**DELTA** |
| 12 | web-content (`content`) | `content/{dirs,files}_medium.txt` | diff `.txt` not `.json` (`FFUFHASH`·`duration`·`time`·`commandline`); strip header/separator rows | new dir·file·sensitive path→**DELTA** |
| 13 | web-recursive (`recursive`, `--deep`) | `content/recursive/` | ffuf `.txt`-over-`.json` | new nested path→**DELTA** |
| 14 | web-vhosts (`vhosts`, `--vhost`) | `content/ffuf_vhosts.json` → vhost list | ffuf json noise | new vhost→**SVC** |
| 15 | web-params (`params`, `--deep`) | `params/` | ffuf | new parameter·endpoint→**DELTA** |
| 16 | web-sqli_probe (`sqli_probe`) ⚠path | flagged-suspect list (`DONE` detail `probed=N suspects=M`) | ⚠ (per resolved path) | new injection-suspect→**DELTA** (heuristic, not catalog → not EXP) |
| 17 | web-summary (*regenerated*) | `loot/next_steps.txt`, `summary/quick_wins.txt` | strip `# Quick Wins — <ts>`, `# Generated:` | new next-step·quick-win→**DELTA** |

### 5.4 adr tier — `ad/<DOMAIN>/` (`adr.sh:2180`), re-run via `adr.sh -d <domain> -u <user> {-p <pass>|-H <hash>} -dc <dc_ip> [--outdir DIR]`

Keyed **per domain** (from the OUTDIR dir name). **Hard precondition:** needs a
domain cred + DC IP. livefetch sources domain from the dir name, `dc_ip` from
`state_read_global` (`dc_ip=`), cred from `state_read_global` (`cred=`, first
valid `user:pass`). **No usable cred + DC IP → report "AD re-fetch needs a
domain cred + DC IP; none in state" and skip the tier** (never silent). adr's
`--quick`/`--skip-bloodhound`/`--skip-shares` honored only if the original run
used them (depth-discipline). adr does its **own** `state_append_cred` writes on
crack/spray — livefetch surfaces the count, performs no cred-write (§9).

| # | Stage (marker `<phase_key>`) | Artifact → diff target | Noise filters | Meaningful delta → key |
|---|---|---|---|---|
| 18 | phase1_domain_context | `domain_context.txt`, `password_policy.txt` | strip console run-ts | new domain·trust·policy fact→**DELTA** |
| 19 | phase2_user_enum | `users/all_users.txt` (sorted) | none | new user→**USR** |
| 20 | phase2b_ldap_enum | `ldap/laps.txt`, `users/suspicious_descriptions.txt` | strip ldap query ts | new LDAP user→**USR**; LAPS·GPP·desc-pass·delegation→**DELTA** |
| 21 | phase2c_adcs | `adcs/certipy_find.txt` | strip certipy ts | ESC1–8 vuln template→**EXP** (named·tool-backed) |
| 22 | phase3_kerberos | `users/{kerberoastable,asrep_candidates}.txt` | ⚠ **never diff `hashes/*.txt`** (Kerberos blobs re-encrypt every roast); diff candidate lists only | new roastable acct→**DELTA** (+**USR** if previously unknown) |
| 23 | phase4_computers | `computers/{all_computers,old_os}.txt` | none | new computer·EOL host→**DELTA** |
| 24 | phase5_smb_signing | `smb_no_signing.txt` | none | new relay target→**SVC** |
| 25 | phase6_bloodhound | `bloodhound/collection_output.txt` | **never byte-diff the `.zip`**; diff summary counts; strip ts | collection grew→**DELTA** |
| 26 | phase7_shares | `shares/{all_shares,sysvol_interesting}.txt` | none | new readable/writable share→**SVC**; SYSVOL interesting file→**DELTA** |
| 27 | phase8_sessions | `sessions/{loggedon_users,smb_sessions}.txt` | sessions volatile → 60s dedupe absorbs flaps | new (priv) logged-on user→**DELTA** |
| 28 | phase9_spray_cracked | `hashes/cracked_passwords.txt`, valid-auth results | none | new cracked pass·valid user→host→**DELTA** (adr appends cred; livefetch surfaces count) |
| 29 | ad-summary (*regenerated*) | `attack_commands.txt`/`next_steps.txt`, `summary_notes.txt` | strip `CLOCK_SKEW=`; `attack_commands` already dedup'd (`adr.sh:299`) | new attack cmd·`ADMIN_ON_DC=YES`→**DELTA** |

### 5.5 from-foothold tier — `recon/<ip>/from-foothold/` (new dir, additive)

| # | Stage | Artifact → diff target | Noise filters (per-label, conservative) | Meaningful delta → key |
|---|---|---|---|---|
| 30 | from-foothold (no marker, no re-run — operator re-pipes) | `from-foothold/<label>.txt` | `netstat`/`ss`→strip ephemeral ports/timers, diff listening set; `ip a`→strip RX/TX; `ps`→strip PID·CPU·TIME; `whoami`/`id` stable | new internal listening svc→**SVC**; new subnet/route→**DELTA**; new local user→**USR** |

v1 is **ingest-only** — livefetch does not drive the shell (v2). `watchdog --json`
ALIVE → suggest the internal-enum commands to pipe back; DEAD/none → note "needs
a foothold" but still accept piped input if offered (advisory, not a hard
block — operator pasting output inherently has access).

### 5.6 Tier-wide noise rules (shared)
- **Binary/timestamped artifacts diff by summary, never bytes** (BloodHound `.zip`, Kerberos hash blobs).
- **nmap comment/latency filter** — reused across all recon nmap artifacts.
- **ffuf `.txt`-over-`.json`** — reused across content/recursive/vhosts/params.
- **HTTP `Date:`/`Set-Cookie:` filter** — reused across curl_headers, headers.txt, httpx.
- **Volatility-absorption** — churny artifacts surfaced once; 60s `(ip,key)` dedupe absorbs repeats.
- **Lean conservative** — show a benign delta rather than swallow a real one.

---

## §6 Stage-selection logic & cross-cutting behavior

**Run flow:** bind target(s) → read state + `watchdog --json` → select STALE
(mtime > `--since`) or MISSING-but-expected stages for the `--stage` filter →
order by the DAG, apply cascade → per stage snapshot→strip→rerun→diff→classify→
emit/skip sentinel→report → emit human table or `--json`.

**Cascade (+ `--no-cascade`).** DAG: `tcp-discovery → tcp-services → {per-service,
tcp-vulnmatch}`; `udp-scan` parallel; summaries downstream. Cross-tier: new HTTP
port→`http-quick`→(routing) webenum; new 445→`smb`; DC signal+domain→adr.
**Cascade fires only when an upstream delta changes a downstream stage's input
(new/changed open port, new service identification).** Terminal deltas (new
title/share/user) surface but don't propagate. **Bound: each stage re-runs at
most once per invocation** (no loops/storms). `--no-cascade` re-runs only
explicitly-stale stages and reports "downstream may be stale." Default: cascade.

**Routing rules (pinned).**
- `http-quick → webenum-deep`: content-depth routes to webenum; `http-quick`
  answers only "still serving / tech changed."
- `ldap_<port> → adr`: domain enum routes to adr (cred precondition);
  `ldap_<port>` answers only "anon bind / base DN."
- **Propose-don't-run:** a missing tier (HTTP port w/o `web/` dir; LDAP+domain
  w/o `ad/<domain>/` dir) is **printed as a suggested command**, never auto-run.

**Depth-discipline (§9).** livefetch re-runs each stage at the depth the operator
originally chose; never adds `--deep`/`--vhost`/`--udp-full` or escalates
`--quick` on its own.

**Liveness-priority (advisory, never a gate).** ALIVE→offer `from-foothold`;
`shell-died`/DEAD→prefer external re-fetch, flag "lost foothold"; `recovered`→
re-offer internal capture; STALE/UNKNOWN→external default. Targets with recent
liveness transitions float to the top of `--all`. Sets order/perspective, not
which stages run (operator may have manual access watchdog can't see).

---

## §7 Diff & delta reporting

- **Mechanism:** snapshot-aside → re-run → diff (§5). `--diff-only` runs into a
  temp dir, diffs, discards (read-only — no artifact writes, no sentinels).
- **Output:** structured summary by default ("3 new ports: 8080, 8443, 9001; 2
  new HTTP titles: …"); full unified diff additionally under `--verbose`.
- **`--json`** for proofr: per-target, per-stage `{stage, marker, ran, stale,
  delta:{key,items[]}, sentinels[]}`.

---

## §8 State writes

Five positive-namespace event keys, all via `state_write_event <ip> <key>`
(`state.sh:367`) — **no new `lib/state.sh` writers**:

| Key | Meaning | Emitted |
|---|---|---|
| `success-livefetch-stale-detected` | run-level: ≥1 stage was stale and re-fetched ("operator refreshed intel at T") | once per target per **persisted** run; **not** in `--diff-only` |
| `success-livefetch-delta-detected` | a stage re-run produced a meaningful non-surface delta | per delta; **never on empty filtered diff** (pin #2) |
| `success-livefetch-new-services-found` | new attack surface / access vector (new port·share·anon-FTP·unauth-DB·relay-target·vhost·write-capable-HTTP-method·internal-listening-svc) | per delta |
| `success-livefetch-new-users-found` | new principal (domain user·RID·LDAP user·local user) | per delta |
| `success-livefetch-new-exploits-found` | **named, catalog-identified** exploit candidate (searchsploit/vulners CVE·EDB, ADCS ESC1–8) — *not* heuristic suspects | per delta |

Vocabulary line (locked): **EXP = "candidate with a known/named exploit";
DELTA = "candidate to investigate"** (sqli_probe suspect, EOL host stay DELTA).
livefetch performs **no cred-append** — wrapped tools (adr) do their own
`state_append_cred`; livefetch surfaces the count, neither suppresses nor claims
it. Per pin #2, an empty filtered diff writes no sentinel but the run still
reports "ran stage X — no changes"; nothing-stale runs report "all stages fresh."

---

## §9 Boundaries — what livefetch does NOT do

1. **Normalize collection→decision trees** — orient.sh's job (`state.sh:6`).
2. **Reinvent recon** — wraps existing scripts only; if a stage doesn't exist as
   a script, livefetch doesn't run it (pre-livefetch amendments are surfaced and
   shipped first).
3. **Auto-escalate depth** — never adds `--deep`/`--vhost`/`--udp-full`/full-`--quick`; missing tiers are proposed, not run.
4. **Touch `findings.sqlite`** — that's the exploitdb Flask app's store
   (`exploitdb/app.py`), decoupled from the recon pipeline; proofr reads
   evidencr's flat-file `evidence_ledger.txt` (`evidencr.sh`) for evidence.
5. **Auto-append creds** — wrapped tools do their own writes; livefetch surfaces counts.
6. **Classify** — outcomes (targetcheckr), liveness (watchdog), interpretation (stuckr) are out; livefetch outputs facts.
7. **Remediate** (stuckr/exploitfixr) or **drive shells** (v2; v1 from-foothold is ingest-only).
8. **Probe beyond** what the wrapped scripts already do.

*Cross-cutting patterns also pinned as boundaries:* volatility-absorption (churn
surfaced once, 60s dedupe absorbs repeats), binary-diff-by-summary, and the
wrapper-not-rewriter rule ("wrapped tools' writes are not livefetch's writes").

---

## §10 Idempotency & "nothing changed"

- **Double-run inside `--since`:** artifacts fresh → re-runs nothing → "all stages fresh." 60s sentinel dedupe → no duplicate events.
- **Crash mid-stage:** stripped marker → wrapped script re-runs that phase next time (safe). Snapshots kept until diff completes.
- **`--diff-only`** never persists → always safe to repeat (the default exploration mode under engagement pressure).
- **Never silently nothing** (pin #2).

---

## §11 Build protocol (for the fresh Code session)

Phased, halt-gated — same as the prior five builds.

- **Phase 0 — FS verify (Step 0: read first, report, wait for confirmation).**
  Re-read the ground-truth sources and **resolve every `⚠`** in §12 before any
  code. Per AGENTS.md:100, no flag/path/marker is referenced without
  verification against actual script content. Report findings + any conflicts
  with this spec; halt for confirmation.
- **Implement** `livefetch.sh` (orchestrator) + `lib/livefetch_diff.py` if a pure
  diff/noise-filter classifier is cleaner than bash (mirrors watchdog_classify.py).
  Reuse the shared regex constants verbatim only if a real corpus-command-render
  need appears (none expected — §3 reads real recon output, not corpus templates).
- **Validate:** `shellcheck` clean; `tests/test_livefetch_demo.sh` covering
  snapshot-then-diff, cascade (one-rerun bound), each noise-filter family,
  empty-diff→no-sentinel, `--diff-only` no-persist/no-sentinel, cred-precondition
  skip-with-message, UDP-needs-sudo skip, depth-discipline propose-don't-run, and
  each of the 5 sentinel keys. Run the AGENTS.md pre-commit checklist
  (`AGENTS.md:303`). Confirm prior suites still pass (state, targetcheckr, watchdog).
- **Commit:** `feat: livefetch.sh — selective recon re-fetch + delta detection (build 6 of 7)`.

---

## §12 Open build-time verification items (`⚠`)

1. **Stage 1 fallback marker.** When rustscan is absent, `recon.sh` writes
   `nmap_full_tcp_discovery` artifacts (`:912`) — confirm the `progress.log`
   marker name for that path; strip-logic must handle both `rustscan` and the
   fallback.
2. **Stage 16 sqli_probe artifact path.** `webenum.sh:1415/1666/1852` write it,
   but the dir wasn't triggered on the live target — confirm exact path
   (`loot/` vs a `sqli_*` file) and its noise profile.
3. **Stage 30 `--tmux-pane` capture.** Confirm targetcheckr's exact tmux-capture
   mechanism (`--tmux-pane`) and replicate it verbatim.
4. **Web-service enumeration + propose-don't-run.** Verify the web-service
   enumeration glob (`web/<host>_<port>_<proto>/`) and the propose-don't-run
   mechanism for recon-HTTP-port → `webenum.sh --from-recon <ip>`: livefetch
   **proposes** the command, does **not** auto-run it (depth-discipline
   boundary, §9).
5. **adr cred sourcing.** Confirm `state_read_global` `cred=` format and the
   first-valid-`user:pass` pick; confirm the `-H <hash>` re-run path
   (`AUTH_TYPE=hash`, `adr.sh:2123`).
6. **from-foothold dir.** Confirm `recon/<ip>/from-foothold/` doesn't collide
   with any existing `recon.sh` output path.

---

*Verified ground-truth anchors (for fast re-verification): `lib/state.sh:47,166-174,
303,367,403-431`; `recon.sh:67-76,213,1233,1408,1511,1604`; `webenum.sh:231,
558,934,1066,1182,1283,1415`; `adr.sh:89,580-1520(phase_key),2180,2123`;
`watchdog.sh:25,224,238-239`; `targetcheckr.sh:14,29-30,142-160`;
`lib/substitutions.md`.*
