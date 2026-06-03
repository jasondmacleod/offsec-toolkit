---
tags:
  - phase/enumeration
  - tool/livefetch
  - type/tool-docs
---

# livefetch.sh

## What It Is
The **selective re-fetch + delta detector** (decision layer). When you've been on a target a while and want fresh intel, livefetch re-runs only the *stale* recon stage(s), diffs the new output against what's on disk, and surfaces what changed — without re-running the whole `recon` from scratch. A wrapper around `recon`/`webenum`/`adr`, not a new recon tool.

## Usage
```bash
./livefetch.sh --target 10.10.10.5                 # all stale stages, default --since 30m
./livefetch.sh --target 10.10.10.5 --stage web     # scope to recon | web | ad | from-foothold
./livefetch.sh --diff-only --target 10.10.10.5     # run into temp, diff, discard (read-only)
./livefetch.sh --all --since 1h                     # every target with artifacts older than 1h
./livefetch.sh --target 10.10.10.5 from-foothold - --label net   # ingest pasted internal recon
```
Exit: `0` ok · `1` fatal · `2` usage. Emits `success-livefetch-*` sentinels — except under `--diff-only`, which is fully read-only.

## Boundaries
Never reinvents recon, never escalates depth (`--deep`/`--vhost`/`--udp-full`) on its own, never normalizes into `targets/` (that's `orient`), never touches `findings.sqlite`. AD re-fetch needs a domain cred + DC IP in state.

## Read more
- Workflow: Phase 5 (web), Phase 9 (AD), Phase 10 (pivot), Phase 12 (stuck)
- Sequence: [[Toolkit_Strategy]] §4 (livefetch change-check)
- Design spec: `docs/livefetch_spec.md` (scripts repo) · ground truth: `./livefetch.sh --help`
