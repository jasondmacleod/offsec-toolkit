---
tags:
  - phase/enumeration
  - tool/orient
  - type/tool-docs
---

# orient.sh

## What It Is
The **collection→decision bridge** (build 7 of 8). Normalizes the collection layer (`recon/`, `web/`, `ad/`, written by `recon`/`webenum`/`adr`) into the decision layer (`targets/<ip>/`) that `stuckr`, `targetcheckr`, `watchdog`, `livefetch`, and `proofr` read via `lib/state.sh`. One direction only: collection → decision.

> [!warning] Run after recon, before any decision tool
> The decision tools read `targets/<ip>/`, which only exists once `orient` has run. Empty decision-tool output almost always means `orient` hasn't run yet — not that the box is empty.

## Usage
```bash
./orient.sh --all                          # normalize every IP found under recon/, web/
./orient.sh 10.10.10.5                      # one target
./orient.sh 10.10.10.5 --web-host app.htb   # associate a hostname-keyed web/ dir (repeatable)
./orient.sh 10.10.10.5 --domain corp.com    # associate AD <DOMAIN>/ as this ip's data (ip = DC)
./orient.sh 10.10.10.5 --dry-run            # print intended writes, change nothing
```
Exit: `0` ok · `1` cannot create output dir · `2` usage. Output is files under `targets/<ip>/` (and `ad/{domain,dc}.txt` with `--domain`).

## Boundaries
Never runs recon, classifies an outcome, pings a host, or writes evidence / creds / sentinels. Full-file replacement (idempotent); never reads its own output.

## Read more
- Workflow: [[OffSec_Exam_Methodology_Complete]] Phase 2 (Bridge the Recon Output)
- Sequence + three-layer data-flow diagram: [[OffSec_Toolkit_Playbook]] §1, §4
- Design spec: `docs/orient_spec.md` (scripts repo) · ground truth: `./orient.sh --help`
