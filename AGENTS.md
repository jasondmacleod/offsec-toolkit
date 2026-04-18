# AGENTS.md

## Project

This repository contains OffSec-focused helper scripts. Prefer pragmatic, reliable,
single-file Bash/PowerShell changes over elaborate abstractions. The scripts are
used under engagement pressure, so outputs should be concise, grounded, and easy to
copy-paste after human review.

## Core Rules

- Generated follow-up commands must be evidence-gated.
- Do not emit commands for services or findings that are absent.
- Do not emit anonymous access commands unless anonymous access/readability was
  actually proven by script output.
- Do not treat WinRM/HTTPAPI ports such as `5985`, `5986`, or `47001` as real
  web app targets unless there is positive web-app evidence.
- Keep command libraries concise and OffSec-practical, not exhaustive.
- Prefer `next_steps.txt` as the primary action file. Keep legacy aliases only
  where scripts already use them.
- Do not add exploit automation that runs automatically. Suggestions are fine;
  execution should remain user-controlled.
- Do not include restricted automatic exploitation tools in scripts, setup,
  generated commands, or docs. `nuclei` and `wpscan` may appear in default OffSec
  follow-up output when they are tied to concrete findings, such as Grafana or
  WordPress evidence.
- Do not rewrite scripts from scratch. Preserve useful techniques and build on
  existing phases, output paths, and helper functions.
- Keep coverage OffSec-practical. Add small missing checks when they unlock real
  engagement value; avoid large generic command dumps.

## Workspace And Output Rules

- Default OffSec output belongs under `$TOOLKIT_ROOT`, with `$HOME/toolkit` as the
  normal fallback.
- For Kali-side scripts that may run through `sudo`, resolve `$TOOLKIT_ROOT` to the
  invoking user's home via `$SUDO_USER` instead of silently writing to
  `/root/offsec`.
- Help text, docs, final status output, and actual output paths must agree.
- Validate arguments before creating output directories when practical,
  especially phase/mode selectors.
- Check `mkdir -p` failures for primary output roots and exit with a clear
  error. Do not continue after failing to create the workspace.
- Keep per-tool artifacts in their existing script-specific structure:
  `recon/<ip>/`, `web/<target>/artifacts/web/`, `ad/<domain>/`,
  `spray/<run>/`, `crackr/`, `privesc/`, `evidence/`, and lootr target loot.

## Evidence-Gated Next Steps

- Every generated command should have a concrete trigger: non-empty output file,
  parsed positive result, nmap service line, progress marker, or validated
  credential/admin marker.
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

## Command And Runtime Reliability

- Prefer arrays for commands with optional flags. Do not rely on unsafe word
  splitting for multi-argument options such as `-M lsassy`.
- Quote paths and variables unless a command intentionally needs separate array
  elements.
- Be careful with `echo` and Windows paths; use `printf` when backslashes or
  escape sequences could be mangled.
- Timeouts should use the configured runtime variables where present, and logs
  should show enough budget/progress information for engagement use.
- Tool detection should degrade gracefully for optional tooling and fail early
  for truly required tooling.
- If a faster helper is optional, preserve coverage through a slower fallback
  where practical, such as nmap full-TCP discovery when rustscan is missing.
- When running as root through `sudo`, include invoking-user tool paths where
  the script already supports user-installed tooling.
- Keep long-running phases interrupt-safe and preserve partial results.

## Tool Setup Rules

- `tools_setup.sh` should install/check OffSec-safe recon and enum helpers by
  default. Include tools that Kali images often lack when they directly support
  recon evidence, such as `httpx-toolkit`, `gowitness`, `eyewitness`,
  `sslscan`, `wafw00f`, `dnsrecon`, `snmpcheck`, `nbtscan`, `davtest`,
  `cadaver`, `nuclei`, `wpscan`, and `jq`.
- Keep restricted automatic exploitation tools out of `tools_setup.sh` and
  generated next-step commands.
- Check-mode package validation should map package names to real binaries when
  they differ, for example `httpx-toolkit` to `httpx` and `samba-common-bin` to
  `nmblookup`.

## PowerShell / Windows Script Rules

- `lootr.ps1 -Help` should work from Kali/PowerShell Core even though normal
  collection is Windows-only.
- Validate `-Phase` before creating output directories.
- Parse Windows service/task executable paths carefully; unquoted paths with
  spaces are common.
- Writable checks should consider the current user and group memberships, not
  only exact user ACEs.
- Keep collection passive. Generate next steps, but do not run privesc payloads.

## Testing

Run these before committing script changes:

```bash
bash -n recon.sh webenum.sh crackr.sh sprayr.sh adr.sh escalatr.sh lootr.sh pivotr.sh servr.sh startr.sh workflow.sh tools_setup.sh evidencr.sh tests/test_next_steps.sh
shellcheck recon.sh webenum.sh crackr.sh sprayr.sh adr.sh escalatr.sh lootr.sh pivotr.sh servr.sh startr.sh workflow.sh tools_setup.sh evidencr.sh tests/test_next_steps.sh
pwsh -NoProfile -Command '$errs=$null; $null=[System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw ./lootr.ps1), [ref]$errs); if ($errs) { $errs | Format-List; exit 1 }'
./tests/test_next_steps.sh
```

For focused next-step matrix work, `./tests/test_next_steps.sh` is the minimum
regression check. It is offline and should not require network access.

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

## Git Hygiene

- Do not commit `.claude/settings.local.json`.
- Do not commit `.DS_Store`.
- Check `git status --short` before staging.
- Stage only files relevant to the task.

## Documentation

When behavior changes, update the related file under `docs/`. Keep docs aligned
with actual output filenames and avoid claiming a command is generated unless a
real trigger exists in the script.
