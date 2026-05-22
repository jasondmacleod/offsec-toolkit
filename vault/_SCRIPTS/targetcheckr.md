---
tags:
  - phase/exploitation
  - phase/post-exploitation
  - tool/targetcheckr
  - type/tool-docs
---

# targetcheckr.sh

## What It Is
The **outcome classifier** (decision layer). Reads captured exploit/post-ex output, classifies it into a pinned vocabulary, and — only when authorized via `--expect` — writes the success-side state the rest of the toolkit depends on (foothold log, `creds.txt` append, sentinel event). The inverse of `exploitfixr`.

> [!important] `--expect` gates the writes
> Without `--expect`, targetcheckr classifies and prints but writes **nothing** (safe dry classify). With `--expect <class>` it writes only when the classification confirms.

## Usage
```bash
<exploit-output> | ./targetcheckr.sh --expect shell --against 10.10.10.5   # pipe stdin
./targetcheckr.sh out.txt --expect cred-dump --against 10.10.10.5          # from a file
./targetcheckr.sh --tmux-pane %3 --expect rce                              # from a tmux pane
./targetcheckr.sh out.txt --expect shell --dry-run                         # classify + preview
```
`--expect` classes: `shell · cred-dump · file-read · file-write · auth-bypass · sqli-data · rce`. Target binding: `--against` wins, else cwd under `targets/<ip>/`; unbound = classify+print only. Exit: `0` ok · `1` classifier/IO fail · `2` usage. **Signal is the printed verdict** (outcome + subclass + confidence), not the exit code.

## Boundaries
Never executes, never opens sockets, never re-runs the exploit. Requires `orient` to have run for the target before state writes are meaningful.

## Read more
- Workflow: [[OffSec_Exam_Methodology_Complete]] Phase 6 (foothold), Phases 7–8 (privesc loot), Phase 9 (AD)
- Sequence: [[OffSec_Toolkit_Playbook]] §2 (invocation order), §4 (AD credential loop)
- Ground truth: `./targetcheckr.sh --help`
