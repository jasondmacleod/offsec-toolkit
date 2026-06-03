---
tags:
  - phase/all
  - tool/stuckr
  - type/tool-docs
---

# stuckr.sh

## What It Is
The **stuck advisor** (decision layer). Surfaces the top 3–5 *untried* next moves for a target, ranked, with paste-and-run commands. Reads the target's recon artifacts, the empty-result sentinels other tools logged, and the exploitdb corpus — and filters out moves already tried. Read-only.

> [!warning] Requires `orient` first
> `stuckr` reads `targets/<ip>/`. Run `./orient.sh --all` after recon or it has nothing to rank.

## Usage
```bash
./stuckr.sh --on 10.10.10.5     # explicit target
./stuckr.sh                      # target inferred from cwd or last_target
./stuckr.sh --all                # one ranked report per target under targets/
```
Exit: `0` ok · `1` no target inferable / missing library · `2` usage. Output = a single screen of ranked actions on stdout.

## Boundaries
Never executes anything, never mutates state, never prompts. It only ranks and prints; `exploitfixr` and the manual [[Triage_Decision_Tree]] are where you act when it runs out of moves.

## Read more
- Workflow: [[Engagement_Methodology]] Phase 3 (Triage) and Phase 12 (When You're Stuck)
- Sequence: [[Toolkit_Strategy]] §4 (stuck path; recon→orient→decision cycle)
- Ground truth: `./stuckr.sh --help`
