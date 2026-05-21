# orient.sh — design spec (build 7 of 8)

> Status: **design locked (redlined 2026-05-21)**, ready for a fresh Code build session.
> Authored against real ground truth in `~/scripts/` (paths / markers / flags
> verified with line refs throughout). The build session re-runs its own
> Phase 0 FS-verify per protocol — see §10. Every `⚠` is an open verification
> item the build session must resolve before coding the affected stage.

---

## §1 Purpose & role

`orient.sh` is the **translator** that bridges the **collection-layer** filesystem
tree (written by `recon.sh`, `webenum.sh`, `adr.sh`) and the
**decision-layer** filesystem tree (read by `stuckr`, `targetcheckr`, `watchdog`,
`livefetch`, and `proofr`). It does **not** invent data, run recon, classify
outcomes, or write state sentinels. It reads collection-layer artifacts and
writes the canonical files that `state_read_target` and `state_read_global`
parse, in the exact shape those readers expect.

Order of operations on a real engagement:

```
recon.sh <ip>   →  populates ~/toolkit/recon/<ip>/
webenum.sh   --url   →  populates ~/toolkit/web/<host>_<port>_<proto>/
adr.sh       -d ...  →  populates ~/toolkit/ad/<DOMAIN>/   (or adr's --outdir)
orient.sh    <ip>    →  populates ~/toolkit/targets/<ip>/
                        decision tools now see real data
```

Without orient, `state_read_target` returns near-empty on every real target.

---

## §2 Input → output mapping (locked)

This is the contract. Every `state_read_target` key that orient owns gets one
row; rows that orient does **not** own are listed for completeness. Every row is
verified against `lib/state.sh`'s actual reader logic and the collection layer's
actual on-disk output.

### Per-target (`state_read_target <ip>`)

| Output key | Decision-layer file | Collection-layer source | Transform |
|---|---|---|---|
| `os_guess` | `targets/<ip>/recon/nmap.txt` | `recon/<ip>/scans/nmap_tcp.nmap` | copy verbatim (`run_nmap_tcp` uses `-O -oA`, so this one file carries both OS-detail lines and the port table) |
| `services` | *(same `nmap.txt`)* | *(same)* | same copy serves both keys — `_state_parse_os` and `_state_parse_services` both read `nmap.txt` |
| `web_path` × N | `targets/<ip>/web/feroxbuster.txt` | merged `web/<host>_<port>_<proto>/artifacts/content/dirs_medium.txt` + `files_medium.txt` across all web instances for this IP | concatenate; `_state_parse_web_paths` parses `ffuf_json_to_text`'s text format. **Phase 0 (⚠2):** rows are two-column `FUZZ  http://host:port/path \| status \| …` (the `has_input` branch, `webenum.sh:1875-1880`) — the parser scans for `http://` anywhere on the line, so the path is extracted from column 2 regardless. An **empty file (header+separator only) is a valid outcome** — wildcard / catch-all servers get every row filtered by `_drop_wildcard_ffuf_rows`; orient writes an empty/absent `feroxbuster.txt`, not an error |
| `web_vhost` × N | `targets/<ip>/web/vhosts.txt` | `web/<host>_<port>_<proto>/artifacts/vhosts/hosts_entries.txt` (if present) | extract field 2 (hostname) from `/etc/hosts`-format lines, dedupe |
| `smb_share` × N | `targets/<ip>/recon/smb.txt` | `recon/<ip>/tcp/smb/{smbclient_list,netexec_shares,smbmap_null,smbmap_guest}.txt` | smbclient → copy verbatim (reader branch-1 parses its tab table); netexec + smbmap → normalize to bare tokens — **see §2.1.** Verbatim concat of nxc/smbmap does NOT work: `_state_parse_smb_shares` (`state.sh:143-153`) matches only smbclient-table rows and bare tokens, so raw netexec/smbmap rows are silently dropped by the reader |
| `ad_user` × N | `targets/<ip>/ad/users.txt` | `ad/<DOMAIN>/users/all_users.txt` | **copy verbatim.** Phase 0 (⚠5) falsified the earlier "raw rpcclient append" assumption: `adr.sh:778` already parses rpcclient output to bare names (`grep -oP 'user:\[\K[^\]]+'`) before appending, and `adr.sh:785` does `sort -u`, so `all_users.txt` is bare-usernames-only. No rpcclient-stripping awk needed (also avoids a gawk-only 3-arg `match()` dependency) |
| `ad_computer` × N | `targets/<ip>/ad/computers.txt` | `ad/<DOMAIN>/computers/nxc_computers.txt` (preferred) or `all_computers.txt` | prefer nxc — raw `nxc smb --computers` (`adr.sh:1182`, no `--computers-export` exists; same `SMB ip port HOST <msg>` prefix as shares). Machine accounts are `$5` ending in `$`: `awk '/^SMB[[:space:]]/ && $5 ~ /\$$/ { sub(/\$$/,"",$5); print $5 }'` → bare hostnames (Phase 0 ⚠6-verified: DC01/WS01/FILE01, no `SMB`/`[*]` leak). Fallback `all_computers.txt`: LDAP `dNSHostName:` values + rpcclient `user:[NAME$]` tokens, strip trailing `$`. dedupe |
| `foothold` | `targets/<ip>/evidence/local.txt` | — | **orient does not write.** Populated by post-foothold tools |
| `privesc` | `targets/<ip>/evidence/proof.txt` | — | **orient does not write.** Populated by post-privesc tools |
| `sentinel` | `targets/<ip>/state/sentinels.log` | — | **orient does not write.** Decision-tool surface |

> **`web_path` reader note.** `state.sh:167-168` reads *two* files —
> `web/feroxbuster.txt` **and** `web/gobuster.txt`. orient writes only the
> former; `gobuster.txt` stays absent on disk, which the reader handles cleanly
> (`[[ -r "$f" ]] || return 0` at `state.sh:94`). It is not dead code in the
> reader — it preserves the option for a future tool that runs gobuster — but
> orient has no source for it today.

> **`tried_slug` is intentionally absent.** `tried_slug` is a *suppression set*
> in `stuckr_rank.py:196-198` (it filters candidates *out* of the "untried next
> moves" list). The collection-layer `next_steps.txt` files are TODO / suggestion
> libraries (`recon.sh:2844`, `adr.sh:307`, `escalatr.sh:1280`). Feeding a
> TODO library into a suppression set inverts the semantics and would hide
> exactly the candidates the operator should see. orient does **not** write
> `targets/<ip>/state/next_steps.txt` — it joins `evidence/`, `sentinels.log`,
> and `foothold.log` as non-orient surface.

### §2.1 SMB normalization (pre-write)

`_state_parse_smb_shares` (`state.sh:143-153`) recognises only two on-disk
formats: smbclient table rows (`<name>  Disk|IPC|Printer …`) and bare single-token
lines. netexec (`SMB ip 445 HOST share perms`) and smbmap
(`share PERMISSION comment`) rows match neither branch and are dropped if passed
verbatim. orient therefore pre-extracts each source to bare share-name tokens
before writing `recon/smb.txt`:

- `smbclient_list.txt` → **copy verbatim.** Phase 0-verified: it is a tab-indented
  `<name>  Disk|IPC  Comment` table; the reader's branch-1 (`state.sh:145`) parses
  it directly to bare names.
- `netexec_shares.txt` → `awk '/^SMB[[:space:]]/ && $5 !~ /^\[/ && $5 !~ /^(Share|Permissions|Remark)$/ && $5 !~ /^-+$/ { print $5 }'`
  Column 5 is the share name, **but the guard is required**: the unguarded
  `{ print $5 }` also emits nxc status markers (`[*]`/`[+]`), the
  `Share`/`Permissions`/`Remark` header, and the `-----` separator — and `Share`
  survives the reader as a false share (Phase 0 ⚠4, verified against real
  `netexec_shares.txt`).
- `smbmap_null.txt`, `smbmap_guest.txt` → `awk '/^[[:space:]]+[A-Za-z0-9_.$-]+[[:space:]]+(READ|WRITE|NO ACCESS)/ { print $1 }'`
  Phase 0-verified clean against the real (tab-delimited) smbmap table.

Concatenate the normalized streams + the verbatim smbclient table, `sort -u`,
write to `targets/<ip>/recon/smb.txt`. The reader then resolves smbclient rows
via branch-1 and the bare nxc/smbmap tokens via branch-2.

> On real `192.168.233.98` data all three sources yield the **same** shares
> (`print$`, `IPC$`). netexec is kept for the asymmetric-auth case (nxc authenticates
> where smbclient/smbmap don't), but it is the only noisy source — hence the guard.

### Global (`state_read_global`)

| Output key | Decision-layer file | Collection-layer source | Transform |
|---|---|---|---|
| `domain` | `$TOOLKIT_ROOT/ad/domain.txt` | operator-supplied via `--domain <name>` flag (mirrors `--web-host`) | one line |
| `dc_ip` | `$TOOLKIT_ROOT/ad/dc.txt` | the IP being oriented — the AD rows only fire when this IP is the DC | one line |
| `cred` × N | `$TOOLKIT_ROOT/creds/creds.txt` *(read path)* | — | **orient does not write.** `state_read_global`'s reader is broken (see §6); not orient's job to fix |

**Locked design choice:** output schema is exactly what `state_read_target`
parses. No extensions. `proofr`, if it needs more, reads the collection layer
directly.

---

## §3 Instance fan-in (the non-obvious part)

### Web-instance fan-in

One IP can have multiple `web/<host>_<port>_<proto>/` directories. The collection
layer keys them by `<host>_<port>_<proto>`; the decision layer keys by `<ip>`
only. orient must:

1. Enumerate `~/toolkit/web/*/` directories whose `<host>` resolves to `<ip>` or
   whose `<host>` literally equals `<ip>`. The host portion may be a hostname
   (vhost discovery) or the IP itself.
2. For each match, merge the three artifact files
   (`content/dirs_medium.txt`, `content/files_medium.txt`,
   `vhosts/hosts_entries.txt`) into the single decision-layer file for that key.
3. Tag merged `web_path` lines with their port so the operator can disambiguate.
   (Format preserved as URLs — the reader strips host/scheme but keeps the path;
   ports are encoded in the URL.)

**Resolution rule for hostname-keyed web dirs:** default is **literal IP match
only**. Hostname-keyed web dirs require explicit operator association via
`--web-host <hostname>`. This avoids guessing DNS resolution at orient-time
(an engagement-time DNS misconfig producing a silent miss is the worse failure mode).

### AD-instance association

AD collection is keyed by `<DOMAIN>` at `~/toolkit/ad/<DOMAIN>/`, not by IP. orient
cannot infer the domain↔IP association from disk. When orienting a DC, the
operator passes `--domain <name>`; orient reads from
`~/toolkit/ad/<name>/users/all_users.txt` and
`…/computers/{nxc_computers.txt,all_computers.txt}`, and writes
`$TOOLKIT_ROOT/ad/domain.txt` (the flag value) and `$TOOLKIT_ROOT/ad/dc.txt` (the IP
being oriented). Without `--domain`, the AD rows produce no output — equivalent
to the IP not being a DC. Same manual-association discipline as `--web-host`.
`adr.sh` stays untouched.

---

## §4 Invocation modes / CLI

```
orient <ip>                                  # normalize one target
orient --all                                 # normalize every IP found in recon/, web/, ad/
orient <ip> --web-host <hostname>            # associate a hostname-keyed web/ dir with this IP
orient <ip> --domain <name>                  # associate AD <DOMAIN>/ dir (this ip = DC)
orient <ip> --dry-run                        # print what would be written, write nothing
orient --help
```

`--web-host` and `--domain` are independently optional and stackable.

- No `--json`. orient's output is files on disk; there's no scalar to emit as JSON.
- No `--auto`. orient is operator-driven (per handoff §3, manual trigger).
- No `--watch`. That's livefetch's job.

---

## §5 Idempotency & re-runs

Every write is **full-file replacement**, not append. Running orient twice
produces identical output (given identical inputs). If `recon.sh` re-ran and
updated `nmap_tcp.nmap`, the next `orient <ip>` rewrites
`targets/<ip>/recon/nmap.txt` from the new content.

orient never reads its own output. One-directional flow: collection → decision.

orient writes no sentinels and no state-tool surface. It does not coordinate with
`watchdog` or `livefetch`'s markers. It's stateless beyond what's on disk.

---

## §6 The three livefetch findings, addressed

**Finding 1 — creds-path inconsistency.** Out of scope for orient. The bug is in
`state_read_global`'s reader (`state.sh:230` reads `creds/creds.txt` with
`_state_parse_lines`, but the authoritative file is `$TOOLKIT_ROOT/creds.txt` with a
6-field pipe schema — `state.sh:307,337`). Fixing it requires rewriting the reader
to parse the pipe schema, which is `proofr`'s natural inheritance (`proofr` is the
heaviest `state_read_global` consumer). Recommend deferring to `proofr`'s build.

**Finding 2 — `warn()` → stderr.** Already fixed at `livefetch.sh:65`. No other
script needs the fix unless it grows `--json`. orient does not have `--json`. No
action.

**Finding 3 — marker discovery discipline.** Applied throughout this spec. Every
input source above was verified against the actual on-disk tree
(`recon/<ip>/scans/nmap_tcp.nmap`, `web/<…>/artifacts/content/dirs_medium.txt`,
`ad/<DOMAIN>/users/all_users.txt`), not constructed from spec'd patterns. The
mapping table in §2 is recognition-reference.

---

## §7 Write surface

All writes are direct file writes (`mkdir -p`; `cp` or `cat > …`). No new
`state.sh` functions. Rationale: `state.sh`'s existing writers
(`state_write_foothold`, `state_append_cred`, `state_write_event`) write
event-log schemas. orient writes snapshot files that are wholesale replacements —
adding `state_write_recon_nmap()` etc. would be a one-caller wrapper. Direct
writes are clearer.

**Files orient creates if missing (then writes):**

- `targets/<ip>/recon/nmap.txt` · `…/recon/smb.txt`
- `targets/<ip>/web/feroxbuster.txt` · `…/web/vhosts.txt`
- `targets/<ip>/ad/users.txt` · `…/ad/computers.txt`
- `$TOOLKIT_ROOT/ad/domain.txt` · `…/ad/dc.txt` (global, only when `--domain` is supplied)

**Files orient never touches:**

- `targets/<ip>/evidence/` (post-foothold tools' surface)
- `targets/<ip>/state/sentinels.log` (decision tools' append-only log)
- `targets/<ip>/state/foothold.log` (`state_write_foothold`'s exclusive surface)
- `targets/<ip>/state/next_steps.txt` (not orient's surface — see the `tried_slug` note in §2)
- `$TOOLKIT_ROOT/creds.txt` / `$TOOLKIT_ROOT/creds/creds.txt` (`state_append_cred`'s surface)

---

## §8 Boundaries — what orient does NOT do

- **No recon execution.** Never invokes `recon`, `webenum`, `adr`.
- **No outcome classification.** Doesn't decide whether a service is exploitable.
- **No liveness checks.** Doesn't ping targets.
- **No state sentinels.** Writes nothing to `sentinels.log`.
- **No `findings.sqlite` mutation.** Out of scope.
- **No reverse flow.** Never reads the decision layer to mutate the collection layer.
- **No coupling with livefetch's markers.** orient runs when the operator runs
  it; livefetch runs when the operator runs livefetch.
- **No JSON, no daemon, no watch mode.**

---

## §9 Open verification items (⚠) — Phase 0 deliverables for the build session

All resolved in the Phase-0 session 2026-05-21 against real artifacts under
`~/toolkit` (target `192.168.233.98`). Harness: `_state_parse_*` sourced from the
live `lib/state.sh`; results below.

- **⚠1 — dropped.** adr persistence is resolved by the `--domain` flag (see §2
  global table, §3 AD-instance association, §4 CLI). `adr.sh` does not persist
  `domain.txt`/`dc.txt`; orient takes the domain from the flag and the DC IP from
  the IP being oriented.
- **⚠2 — RESOLVED.** `_state_parse_web_paths` extracts paths from the real ffuf
  `has_input` format (FUZZ + URL columns). The on-disk `dirs_medium.txt` /
  `files_medium.txt` here are header-only (wildcard-filtered) — a **valid empty
  outcome**, not a parser failure; orient must treat empty web output as normal.
  Positive case proven with a producer-faithful fixture (3 paths extracted, no
  header/scheme leak).
- **⚠3 — RESOLVED.** Field-2 extraction (`awk '{print $2}'`) on the `  <ip>  <vhost>`
  producer format (`webenum.sh:1253`) yields bare hostnames. Fixture-verified — no
  real `hosts_entries.txt` on the test box (no vhosts discovered).
- **⚠4 — RESOLVED; netexec extractor hardened.** Verified against real
  `netexec_shares.txt` / `smbmap_null.txt` / `smbclient_list.txt`. smbclient
  (verbatim) and smbmap extractors are clean; the unguarded netexec awk leaked the
  `Share` header as a false share — fixed by the guard now in §2.1. All three
  sources yield `print$`, `IPC$` on this box.
- **⚠5 — RESOLVED; premise falsified.** The spec assumed adr appends raw rpcclient
  lines; the live `adr.sh:778` already strips them (`grep -oP 'user:\[\K[^\]]+'`)
  before append + `sort -u`. `all_users.txt` is bare-usernames-only → ad_user is
  copy-verbatim, no awk (see §2 ad_user row).
- **⚠6 — RESOLVED (Phase 0 follow-up).** `nxc_computers.txt` is raw
  `nxc smb --computers` (no `--computers-export`; `adr.sh:1182-1183`) — the same
  prefix as the shares output, so naive first-token / unguarded `$5` extraction
  would emit `SMB` or the header rows. Extractor keys on the machine-account `$`
  suffix (`$5 ~ /\$$/`, strip `$`) → verified DC01/WS01/FILE01 from real-format
  input, no `[*]` banner leak. Fallback `all_computers.txt` (LDAP `dNSHostName:`
  + rpcclient `user:[NAME$]`, `adr.sh:1190-1224`) handled by a secondary extractor.

---

## §10 Build protocol

Same pattern as builds 1–6:

1. **Phase 0:** resolve ⚠2–⚠5 above by running the extractors against actual
   collection-layer files. Re-verify the line refs cited in this spec
   (`state.sh`, `stuckr_rank.py`, `recon.sh`, `adr.sh`, `webenum.sh`) against
   the live files — do not trust them if the tree has drifted. Halt if any input
   doesn't match what this spec assumed.
2. Write `orient.sh` (single file, no `lib/orient_normalize.py`). Transforms are
   awk-scale: SMB column extraction (netexec guarded + smbmap), vhost field-2
   extraction, AD computer extraction (nxc `$`-suffix keyed, LDAP/rpcclient
   fallback). `ad_user` and the smbclient table are copy-verbatim. No classifier
   logic; no Python sidecar warranted.
3. Write `tests/test_orient_demo.sh` with synthetic fixtures under a temp
   `TOOLKIT_ROOT`, exercising each row of §2's mapping table (including ⚠4 and ⚠5).
   Assertion model mirrors `test_targetcheckr` / `test_watchdog` / `test_livefetch`.
4. Run all six prior test suites; confirm green. No `state.sh` changes in this
   build (per §6 and §7).
5. Update this doc with any Phase-0 resolutions that changed the mapping.
6. Commit: `feat: orient.sh — collection-to-decision-layer bridge (build 7 of 8)`.

---

## §11 Out of scope, recorded for proofr's handoff

- `state_read_global` creds-path reader fix (§6 Finding 1). Schema mismatch
  between reader (`_state_parse_lines`) and writer (6-field pipe). `proofr`
  consumes `state_read_global` heavily; natural owner.
- `warn()` → stderr propagation to any future `--json`-capable tool. Not orient's
  concern.
- Hostname → IP resolution for `web/` dir auto-association, and DOMAIN → DC-IP
  auto-association. If `proofr` or a later tool wants either, it can be added;
  orient defers to the operator via `--web-host` / `--domain`.
