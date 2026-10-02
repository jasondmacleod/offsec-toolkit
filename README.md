# offsec-toolkit

A layered offensive-security automation toolkit: recon and collection, decision support, and evidence/reporting.

Author: **[Jason D. MacLeod](https://www.jasondmacleod.com/)** (lawyer and cybersecurity compliance professional, Seattle). More at [jasondmacleod.com/code](https://www.jasondmacleod.com/code/).

> Developed with Claude Code (Anthropic).

---

## Overview

`offsec-toolkit` is a set of shell tools, two small Flask reference apps, and a
structured note vault that together cover a network engagement end to end. It is
organized as three layers:

1. **Collection layer** — recon and enumeration that fan out across targets and
   write structured output under `$TOOLKIT_ROOT` (defaults to `~/toolkit`).
2. **Decision layer** — tools that read the collection output, rank what to do
   next, classify exploit outcomes, and keep state about live access.
3. **Evidence / reporting layer** — capture of flags and loot, proof auditing,
   and an evidence ledger that rolls up into report-ready material.

All Kali-side scripts honor a single environment variable, `$TOOLKIT_ROOT`, for
their working tree, so every tool reads and writes a consistent layout.

## Components

### Automation scripts (Bash / PowerShell)

| Area | Scripts |
|------|---------|
| Setup & workspace | `tools_setup.sh`, `startr.sh`, `workflow.sh` |
| Recon & collection | `recon.sh`, `webenum.sh`, `servr.sh`, `adr.sh`, `sprayr.sh`, `crackr.sh` |
| Access & movement | `pivotr.sh`, `lootr.sh` / `lootr.ps1`, `escalatr.sh` |
| Decision support | `orient.sh`, `stuckr.sh`, `targetcheckr.sh`, `watchdog.sh`, `livefetch.sh`, `exploitfixr.sh` |
| Evidence & reporting | `evidencr.sh`, `proofr.sh` |

Shared classifiers and state helpers live under `lib/`.

### Reference apps

- **`exploitdb/`** — a Flask app over a curated, cross-referenced catalog of
  techniques and findings (SQLite + FTS5), with a findings-intake and
  report-assembly workflow.
- **`vquery/`** — a fast Flask "vault query" engine that indexes the note vault
  and a set of command shortcuts for sub-second lookup during an engagement.

Each app has its own `run.sh`; both build their database from the seed data in
the repo and start a local Flask server.

### Note vault

`vault/` is an Obsidian vault of methodology checklists, technique cheatsheets,
tool references, and report templates that the tools and apps cross-reference.

## Quick start

```bash
# install recon/enum helper tools (no sudo needed for --check)
./tools_setup.sh --check

# set the working tree (defaults to ~/toolkit)
export TOOLKIT_ROOT="$HOME/toolkit"

# run the reference apps
cd exploitdb && ./run.sh      # http://127.0.0.1:5000
cd vquery   && ./run.sh
```

## License

Released under the [MIT License](./LICENSE). Copyright (c) 2026 Jason MacLeod.
