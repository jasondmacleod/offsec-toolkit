---
tags:
  - type/engagement
  - type/tool-docs
  - tool/startr
---

# startr.sh — engagement Day Launch Automation

Automates the first 10–15 minutes of engagement setup: workspace creation, tmux session with named windows, environment variables, file server staging, connectivity checks, and auto-recon launch.

> [!important] Run this the moment you have your target IPs. It replaces the manual setup in [[Exam_Quickstart]].

---

## Quick Start

```bash
# Full launch with all targets + auto-recon
./startr.sh \
  --sa1 192.168.X.1 --sa2 192.168.X.2 --sa3 192.168.X.3 \
  --ad1 192.168.X.10 --ad2 192.168.X.11 --dc 192.168.X.20 \
  --domain corp.com --aduser stephanie --adpass 'Password123!' \
  --recon

# Or load targets from a file (recommended — pre-create template before engagement day)
./startr.sh -f targets.txt --recon

# Re-attach after VPN drop or terminal crash
./startr.sh --attach
```

---

## Targets File Format

Create `targets.txt` with one key=value per line:

```
SA1=192.168.X.1
SA2=192.168.X.2
SA3=192.168.X.3
AD1=192.168.X.10
AD2=192.168.X.11
DC=192.168.X.20
DOMAIN=corp.com
ADUSER=stephanie
ADPASS=Password123!
```

> [!tip] Pre-create this file template before engagement day. On engagement start, just fill in the IPs and run `./startr.sh -f targets.txt --recon`.

---

## What It Does

1. **Pre-flight checks** — verifies tmux installed, VPN connected (tun0), pings all targets
2. **Creates workspace** — `~/toolkit/exam_YYYY-MM-DD/` with per-target subdirectories
3. **Initializes tracking** — `creds.txt` (scratchpad, pre-populated with AD assumed-breach creds) and `hosts.txt` (all target IPs). Structured credential tracking stays in [[Creds_Tracker]]
4. **Writes env.sh** — exports target IPs, AD creds, Kali IP, workspace path — sourced in every tmux pane
5. **Builds tmux session** — 6 named windows with splits, env sourced in all panes
6. **Starts file server** — HTTP server on port 80 from `~/tools/` in the staging window
7. **Launches recon** (if `--recon`) — runs `recon.sh --auto` on all targets simultaneously
8. **Prints summary** — target map, tmux navigation, quick reference commands, engagement end time

> [!warning] Toolkit Directory
> The file server serves from `~/tools/` — the same path `tools_setup.sh` populates. Make sure this directory exists and is populated with your transfer tools (linpeas, winpeas, nc, chisel, etc.) **before engagement day**.

---

## tmux Layout Created

```
Window 1: SA-1     ← Standalone 1 (70/30 vertical split)
Window 2: SA-2     ← Standalone 2 (70/30 vertical split)
Window 3: SA-3     ← Standalone 3 (70/30 vertical split)
Window 4: AD       ← All AD targets (70/30 vertical split)
Window 5: staging  ← HTTP server (left) + listener notes (right)
Window 6: notes    ← creds.txt, scratch space
```

Navigate: `Ctrl+b 1` through `Ctrl+b 6` (or use `Ctrl+b w` for window picker). Window numbers follow your tmux `base-index` — startr.sh adapts automatically. If your `base-index` is `0`, windows are `0–5` instead.

---

## Environment Variables Available

After launch, every tmux pane has these exported:

| Variable | Value |
|----------|-------|
| `$KALI` | Your tun0 IP |
| `$SA1`, `$SA2`, `$SA3` | Standalone target IPs |
| `$AD1`, `$AD2` | AD member server IPs |
| `$DC` | Domain controller IP |
| `$DOMAIN` | AD domain name |
| `$ADUSER` / `$ADPASS` | Assumed-breach credentials |
| `$engagement` | Workspace path (`~/toolkit/exam_YYYY-MM-DD`) |

New terminal outside tmux: `source ~/toolkit/exam_YYYY-MM-DD/env.sh`

---

## Workspace Structure Created

```
~/toolkit/exam_YYYY-MM-DD/
├── env.sh              ← source this for env vars
├── creds.txt           ← quick scratchpad (AD creds pre-filled)
├── hosts.txt           ← target IP reference
├── target1/            ← SA-1
│   ├── scans/
│   ├── loot/
│   ├── screenshots/
│   └── exploits/
├── target2/            ← SA-2
├── target3/            ← SA-3
└── ad/                 ← AD set
    ├── scans/
    ├── loot/
    ├── screenshots/
    └── exploits/
```

---

## First 15 Minutes After Launch

startr finishes, summary prints, recon is running. This is what you do next.

```
startr complete → recon running on all 6 targets
│
├── 1. Validate AD assumed-breach creds immediately
│      nxc smb $DC -u $ADUSER -p $ADPASS
│      nxc smb $AD1 -u $ADUSER -p $ADPASS
│      nxc smb $AD2 -u $ADUSER -p $ADPASS
│      → If creds work: run full AD enum now
│      ./adr.sh -d $DOMAIN -u $ADUSER -p $ADPASS -dc $DC
│      → If not: flag it, don't assume — spray with crackr/sprayr once you find hashes
│
├── 2. Monitor recon results — read these first as each scan lands
│      cat $TOOLKIT_ROOT/recon/$SA1/summary.txt          # summary + short next-step preview
│      cat $TOOLKIT_ROOT/recon/$SA1/loot/next_steps.txt  # evidence-backed commands
│      cat $TOOLKIT_ROOT/recon/$SA1/loot/quick_wins.txt  # anonymous access, default creds, risky findings
│      cat $TOOLKIT_ROOT/recon/*/loot/quick_wins.txt     # all targets at once
│      → run only commands grounded in the scan output
│      → don't wait for all scans to finish; act on the first result that lands
│
├── 3. Pick first standalone target
│      Triage by open ports: HTTP (80/443/8080) → web enum first
│      SMB (445) → check anonymous/guest access
│      Unusual ports → service version scan
│      Go to Ctrl+b <window> for that target and start working
│
├── 4. Let AD recon finish in background
│      AD set runs in Window 4 (AD) — don't touch it yet unless creds
│      gave you an obvious win (e.g. admin on a member server)
│
└── 5. Start your attack on SA-1 while scans complete on SA-2/SA-3
       One target active, rest finishing recon
       Switch targets when you get stuck (not before 30 min on a target)
```

> [!tip] Target Selection
> Attack the easiest standalone first. More open ports = more attack surface = faster foothold. Save the hardest standalone and the AD set for when you have momentum and harvested credentials.

After first foothold → [[lootr]] for collection → [[evidencr]] for evidence capture → continue.

---

## Prerequisites

- `tmux` installed
- VPN connected (tun0 up)
- `~/tools/` directory populated with transfer tools for HTTP server (see warning above)
- `recon.sh` for `--recon` flag — searched script-adjacent first, then `~/scripts/recon.sh`, then `~/scripts/bin/recon.sh`

---

## Recovering from Problems

```bash
# VPN dropped — tmux session survives, just reattach
./startr.sh --attach

# Need env vars in a new terminal
source ~/toolkit/exam_YYYY-MM-DD/env.sh

# tmux session was killed — re-run (idempotent — skips existing dirs)
./startr.sh -f targets.txt

# File server died — restart manually
cd ~/tools && python3 -m http.server 80
```

---

## All Options

| Flag | Description |
|------|-------------|
| `--sa1`, `--sa2`, `--sa3` | Standalone target IPs (required) |
| `--ad1`, `--ad2` | AD member server IPs (required) |
| `--dc` | Domain controller IP (required) |
| `--domain` | AD domain name (required) |
| `--aduser` | Assumed-breach username (required) |
| `--adpass` | Assumed-breach password (required) |
| `-f`, `--file` | Load targets from KEY=VALUE file |
| `--recon` | Auto-launch recon.sh on all targets |
| `--attach` | Re-attach to existing engagement tmux session |
| `--no-color` | Disable ANSI colors (also: `export NO_COLOR=1`) |
| `-h`, `--help` | Show usage |

---

## Related

- [[Exam_Quickstart]] — manual fallback if startr fails
- [[tmux]] — tmux commands and navigation
- [[recon]] — recon script launched by `--recon`
- [[Creds_Tracker]] — structured credential tracking (separate from the `creds.txt` scratchpad)
- [[lootr]] — post-exploitation loot collection after first shell
- [[evidencr]] — evidence capture at every flag
- [[OffSec_Exam_Methodology_Complete]] — full engagement playbook
