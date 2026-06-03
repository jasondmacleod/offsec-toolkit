---
tags:
  - phase/post-exploitation
  - phase/lateral-movement
  - tool/watchdog
  - type/tool-docs
---

# watchdog.sh

## What It Is
The **liveness monitor** (decision layer). One-screen, sub-second check of your Kali-side shells, tunnels, and listeners. Classifies each resource `ALIVE` / `STALE` / `DEAD` / `UNKNOWN` from the state vector (`foothold.log`, pivots) and writes shell transition sentinels (`success-liveness-shell-{died,stale,recovered}`) that `livefetch` later consumes.

## Usage
```bash
./watchdog.sh                            # one-shot, all targets + resource types
./watchdog.sh --type shell               # filter to shells (or tunnel | listener)
./watchdog.sh --target 10.10.10.5        # filter to one target
./watchdog.sh --since shells=2h          # STALE threshold override (repeatable)
./watchdog.sh --json                     # machine-readable (for livefetch)
./watchdog.sh --dry-run                  # classify + render, no state writes
```
Exit: `0` ok · `1` fatal · `2` usage. **Signal is the per-resource class** in the output, not the exit code.

## Boundaries
Never probes a target, never drives a REPL, never remediates. A dead tunnel is re-established with `./pivotr.sh reconnect`, not by watchdog.

## Read more
- Workflow: [[Engagement_Methodology]] Phase 6 (shell liveness), Phase 10 (tunnel liveness)
- Sequence: [[Toolkit_Strategy]] §2, §3
- Ground truth: `./watchdog.sh --help`
