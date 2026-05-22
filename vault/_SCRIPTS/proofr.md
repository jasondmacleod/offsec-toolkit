---
tags:
  - phase/reporting
  - tool/proofr
  - type/tool-docs
---

# proofr.sh

## What It Is
The **proof-of-compromise auditor** and **submission gate** (build 8 of 8, audit layer). Reconciles what the toolkit recorded *happened* (`foothold.log`, `creds.txt`) against what you *documented for the grader* (evidencr's ledger, flag files, screenshot audit) and reports documented / missing / inconsistent — with the concrete next action for each gap. Its **exit code is the verdict.**

> [!important] The last mandatory step before time expires
> `evidencr --rollup` is blind to a box you owned but never ran through evidencr; `proofr` takes the compromise signal from `foothold.log` instead, so an undocumented compromise surfaces as **exit 2**. That blind spot is the reason proofr exists.

## Usage
```bash
./proofr.sh --all          # audit every engaged target + engagement-wide footer
./proofr.sh --on 10.10.10.5 # one explicit target
./proofr.sh                 # target inferred from cwd / last_target
```
Exit: `0` report-ready · `1` gaps · `2` **CRITICAL** (Metasploit on >1 machine, or an engaged box with no evidence entry) · `3` usage / no target. Resolve every exit-2 before you stop attacking.

## Boundaries
Does **not** write your report, capture or compose screenshots, total points (that's `evidencr --rollup`), or mutate any state. Pure reader + reporter.

## Read more
- Workflow + exit-code meaning: [[OffSec_Exam_Methodology_Complete]] Phase 13 (Submission Gate)
- Sequence: [[OffSec_Toolkit_Playbook]] §6
- Design spec: `docs/proofr_spec.md` (scripts repo) · ground truth: `./proofr.sh --help`
