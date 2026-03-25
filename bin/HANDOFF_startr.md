# Claude Code Handoff: startr.sh

## Context

You are building `startr.sh` for Jason, who is preparing for the OffSec+ engagement on June 5, 2026. This script automates the first 10-15 minutes of engagement setup so he can start hacking faster. It lives in `~/scripts/` alongside his other toolkit scripts.

Jason runs Kali Linux in a Parallels VM on macOS. He uses tmux daily but struggles to remember commands under pressure. He uses Penelope (with `-0` zero flag, NOT `-O` capital O) as his default shell handler. He uses `nxc` (netexec) exclusively — never `crackmapexec`/`cme`.

## What This Script Does

When Jason runs `startr.sh`, it should:

1. **Accept target IPs as arguments** (positional or via flags — his other scripts use flags)
   - 3 standalone IPs + 3 AD IPs (6 total), or a file with IPs
   - Also accept AD domain name and provided creds (username/password) since the AD set uses assumed-breach

2. **Create the engagement workspace directory structure:**
   ```
   ~/toolkit/exam_YYYY-MM-DD/
   ├── target1/  (standalone 1)
   │   ├── scans/
   │   ├── loot/
   │   ├── screenshots/
   │   └── exploits/
   ├── target2/  (standalone 2)
   ├── target3/  (standalone 3)
   ├── ad/
   │   ├── scans/
   │   ├── loot/
   │   ├── screenshots/
   │   └── exploits/
   ├── creds.txt      (initialized with header)
   └── hosts.txt      (initialized with header)
   ```

3. **Set environment variables and export them:**
   ```bash
   export KALI=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+[^\s/]+')
   export engagement=~/toolkit/exam_$(date +%F)
   export SA1=<standalone1_ip>
   export SA2=<standalone2_ip>
   export SA3=<standalone3_ip>
   export AD1=<ad_ip1>
   export AD2=<ad_ip2>
   export DC=<ad_ip3>  # or AD3
   export DOMAIN=<domain_name>
   export ADUSER=<provided_username>
   export ADPASS=<provided_password>
   ```
   These should also be written to a sourceable file like `$engagement/env.sh` so any new shell can `source` it.

4. **Build the tmux engagement session with named windows:**
   - Window 0: `SA-1` (standalone 1)
   - Window 1: `SA-2` (standalone 2)
   - Window 2: `SA-3` (standalone 3)
   - Window 3: `AD` (AD set work)
   - Window 4: `staging` (file server + listeners)
   - Window 5: `notes` (for creds.txt and scratch)

   Each target window should be split: main pane on top (70%), smaller pane on bottom for secondary work.

   The `staging` window should be split into:
   - Left pane: `python3 -m http.server 80` running from `~/toolkit/` (or wherever his tools live)
   - Right pane: ready for Penelope (`penelope -0` printed as a reminder but NOT auto-launched — he may want to choose port/interface first)

   The `notes` window should open `$engagement/creds.txt` in the default editor or just cat the header.

5. **Pre-flight connectivity checks:**
   - Verify tun0 exists (VPN connected)
   - Ping or TCP-check each target IP (with timeout, don't hang)
   - Report which targets are reachable and which aren't
   - Non-blocking: warn but continue if some targets don't respond (ICMP may be blocked)

6. **Print a startup summary** showing:
   - Kali IP
   - All target IPs with labels
   - engagement workspace path
   - tmux navigation reminder (Ctrl+b 0-5 to switch windows)
   - Quick reference commands (spray, serve files, catch shell)
   - Current time and engagement end time (start + 23h45m)

7. **Optionally fire recon.sh** on all targets (with `--auto` flag) if the user passes a `--recon` flag. Do NOT auto-launch recon by default — let him decide.

## Design Constraints

- **Single file, no external dependencies** beyond standard Kali tools + tmux
- **Idempotent**: safe to re-run (check if tmux session exists, don't duplicate)
- **No auto-exploitation** — this is setup only, OffSec engagement compliant
- **Color output** using the same color scheme as his other scripts (RED, GREEN, YELLOW, CYAN, BOLD, NC)
- **Error handling**: check for tmux, check for tun0, handle missing arguments gracefully
- **Must work when sourced OR executed** — the env vars need to persist in the calling shell. Consider writing env to file + printing `source` instruction.

## Usage Examples

```bash
# Full engagement launch
./startr.sh --sa1 192.168.1.100 --sa2 192.168.1.101 --sa3 192.168.1.102 \
                --ad1 10.10.10.50 --ad2 10.10.10.51 --dc 10.10.10.52 \
                --domain corp.local --aduser jsmith --adpass 'Password123!'

# Launch with auto-recon
./startr.sh --sa1 ... --recon

# Launch from a file (one IP per line, labeled)
./startr.sh -f targets.txt

# Re-attach to existing engagement session
./startr.sh --attach
```

## targets.txt Format (if using -f)

```
SA1=192.168.1.100
SA2=192.168.1.101
SA3=192.168.1.102
AD1=10.10.10.50
AD2=10.10.10.51
DC=10.10.10.52
DOMAIN=corp.local
ADUSER=jsmith
ADPASS=Password123!
```

## Script Header Template

Follow the same conventions as his other scripts:

```bash
#!/usr/bin/env bash
#==============================================================================
# STARTR.SH — OffSec engagement Day Launch Automation
#==============================================================================
# Automates the first 10-15 minutes of engagement setup:
#   - Workspace directory creation
#   - tmux session with named windows and splits
#   - Environment variables for all targets
#   - File server and listener staging
#   - Connectivity pre-flight checks
#   - Startup summary with quick reference
#
# USAGE:
#   ./startr.sh --sa1 IP --sa2 IP --sa3 IP --ad1 IP --ad2 IP --dc IP \
#                   --domain NAME --aduser USER --adpass PASS [--recon]
#   ./startr.sh -f targets.txt [--recon]
#   ./startr.sh --attach
#
# DESIGN: Enumeration/setup only — no exploitation. OffSec engagement compliant.
#==============================================================================

set -euo pipefail
```

## Testing

After building, test these scenarios:
1. Run with all flags → verify tmux session, directories, env file
2. Run with -f targets.txt → same result
3. Run twice → should detect existing session and offer attach
4. Run without tun0 → should warn clearly
5. Run with unreachable IP → should warn but continue
6. Run with --recon → should fire recon.sh in background in each target window
7. Run with --attach → should reattach to existing engagement session

## File Location

Save to: `~/scripts/startr.sh`
Make executable: `chmod +x ~/scripts/startr.sh`

## References

Jason's existing scripts are in `~/scripts/` and follow consistent patterns:
- Color variables: RED, GREEN, YELLOW, CYAN, BOLD, NC
- Logging functions: log_info, log_success, log_warn, log_error
- Flag parsing with getopts or manual while-shift
- Pre-flight checks at the top (root check, tool check, VPN check)

Look at `recon.sh` or `crackr.sh` in the repo for style reference.
