---
tags:
  - phase/post-exploitation
  - phase/reporting
  - topic/evidence
  - tool/evidencr
  - type/tool-docs
---

# evidencr

## What It Is
A Kali-side evidence capture script for OffSec engagement reporting. Records flag values, generates a per-machine screenshot checklist, logs your attack chain, and appends everything to a cross-machine ledger. Fills the gap between `lootr.sh` (raw loot) and the Word report template.

## When To Use
**At every flag.** Run it immediately after capturing `local.txt` or `proof.txt`, before moving to the next machine. Do not wait until the end of the engagement — you will forget details.

> [!warning] Do Not Leave The Host Until This Is Done
> Evidence capture is part of the exploitation, not a separate phase you come back to. Before you move on: evidencr has run, screenshots are taken, attack chain is entered. Skipping this under time pressure is how people lose points on reporting with a passing technical score.

> [!important] Kali-Side Only
> evidencr never touches the target. It records what **you** tell it. All flag values, hostnames, and attack chains are operator-entered.

---

## Quick Start

```bash
# Interactive — prompts for everything
./evidencr.sh -t 10.10.10.5

# Fully flags-driven (fastest on engagement day)
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags both \
  --points 20 --category standalone

# Pre-fill flag values (fully non-interactive)
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags both \
  --local-flag <UUID> --proof-flag <UUID> \
  --points 20 --category standalone --non-interactive

# With a local copy of the flag file
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags proof \
  --points 20 --category standalone \
  -p /tmp/loot/10.10.10.5/proof/proof.txt_1234567890
```

---

## engagement Day Workflow

### 1. Get a flag → run evidencr immediately

```bash
# You just caught root on 10.10.10.5
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags both \
  --points 20 --category standalone
```

Flag values are entered silently (no terminal echo). Paste the UUID — the script accepts both `a1b2c3d4e5f6...` (32 hex) and `a1b2c3d4-e5f6-...` (dashed UUID) formats.

### 2. Script prints the screenshot checklist in green — take those screenshots now

Example output (Linux, both flags):
```
[ ] 1. local_flag.png
    Command: cat /home/<user>/local.txt && hostname && whoami && id
    Must show: local flag UUID + hostname + whoami in same frame

[ ] 2. low_priv_shell.png
    Must show: your initial shell with target hostname visible

[ ] 3. privesc_vector.png
    Must show: the command/exploit that granted elevated access

[ ] 4. proof_flag.png
    Command: cat /root/proof.txt && hostname && whoami && id
    Must show: proof flag UUID + hostname + whoami in same frame

[ ] 5. root_shell.png
    Must show: root shell with hostname and id output

[ ] 6. network_position.png  (if pivoting was involved)
    Must show: your pivot setup confirming reachability
```

### 3. Enter your attack chain when prompted

```
Enter your attack chain (press ENTER twice when done):
> Initial foothold: SQLi → file write → webshell at /upload/shell.php
> Privesc: cron job running /tmp/backup.sh as root, world-writable
> (blank line)
> (blank line)
```

### 4. Update Creds Tracker

Copy the flag UUIDs into `Creds_Tracker.md` now while they're fresh. Do not defer this.

### 5. Confirm and move on

All three must be true before switching to the next target:
- `summary.txt` exists for this IP
- All checklist screenshots are saved
- Attack chain is recorded

### 6. At end of engagement — final audit before report writing

```bash
# Verify creds ledger — anything missed?
cat $TOOLKIT_ROOT/creds.txt

# Cross-machine flag audit — confirm every flag was captured
cat $TOOLKIT_ROOT/evidence/*/flags/proof.txt
cat $TOOLKIT_ROOT/evidence/*/flags/local.txt

# Full cross-machine evidence ledger
cat $TOOLKIT_ROOT/evidence/evidence_ledger.txt
```

---

## AD Machine Notes

Use `--category AD-client` or `--category AD-DC` to tag machines correctly. The AD set is graded as a chain — your attack chain entries must show how each machine's access enabled the next.

```bash
# Client machine — first in the AD chain
./evidencr.sh -t 10.10.10.8 -n MS01 --os Windows --flags both \
  --points 10 --category AD-client

# DC — reference how you got here from the client
./evidencr.sh -t 10.10.10.10 -n DC01 --os Windows --flags proof \
  --points 40 --category AD-DC
```

> [!important] **Before running evidencr on an AD-DC — confirm these are done:**
> - DCSync: `impacket-secretsdump -just-dc <domain>/<user>:<pass>@<DC_IP>`
> - NTDS dump: `nxc smb <DC_IP> -u <user> -p <pass> --ntds`
> - krbtgt hash captured (needed for golden ticket)
> - All domain admin hashes added to `$TOOLKIT_ROOT/creds.txt`
>
> When `--category AD-DC` is passed, the script prints this checklist again at the end of the evidence collection run.

**AD chain entries must link machines.** Standalone chains describe one host. AD chains describe movement:

```
# Standalone chain example (one host, self-contained)
> Initial foothold: anonymous FTP → writable webroot → PHP shell
> Privesc: SeImpersonatePrivilege → PrintSpoofer → SYSTEM

# AD chain example for MS01 (AD-client)
> Initial foothold: assumed-breach creds (joe:Password1) → RDP to MS01
> Local privesc: SeImpersonatePrivilege → GodPotato → SYSTEM
> Credential harvest: Mimikatz → domain admin hash (svc_admin)

# AD chain example for DC01 (AD-DC) — references MS01
> Lateral movement: used svc_admin NTLM hash from MS01 → psexec to DC01
> Domain escalation: DCSync → Administrator NTLM hash
```

---

## Output Structure

```
$TOOLKIT_ROOT/evidence/
  evidence_ledger.txt        # One-line-per-machine cross-machine summary
  progress.log               # Resume tracking (append-only)
  10.10.10.5/
    summary.txt              # Full machine evidence block for your report
    flags/
      local.txt              # Recorded local flag value (timestamped)
      proof.txt              # Recorded proof flag value (timestamped)
    screenshots/
      checklist.txt          # What to screenshot and how
    chain/
      attack_chain.txt       # Your entered attack chain (timestamped)
```

---

## Re-Running for the Same IP

Safe. The script warns you, asks for confirmation (skipped with `--non-interactive`), then appends a new evidence block. The ledger and summary both accumulate entries by timestamp.

```bash
# Ran it early with just local, now have proof too
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags proof \
  --points 20 --category standalone
```

---

## All Options

```bash
./evidencr.sh -t <IP> [OPTIONS]

Required:
  -t <IP>              Target IP address

Options:
  -n <hostname>        Hostname (prompted if omitted)
  --flags <type>       Flag type: local | proof | both (prompted if omitted)
  --local-flag VALUE   Pre-fill local.txt flag value (skips silent prompt)
  --proof-flag VALUE   Pre-fill proof.txt flag value (skips silent prompt)
  -p <path>            Local path to flag file — copies it into evidence dir
  --os <os>            Target OS: Linux | Windows
  --points <value>     Points value: 10 | 20 | 25
  --category <type>    standalone | AD-client | AD-DC
  -o <outdir>          Output dir (default: $TOOLKIT_ROOT/evidence)
  --non-interactive    Skip all prompts; use flags only
  --no-color           Disable colored output
  -h, --help           Show help
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Script hangs waiting for input | You're in interactive mode — either answer prompts or add `--non-interactive` |
| "Provided flag path does not exist locally" | The `-p` path must be on Kali, not on the target. Transfer the file first |
| Ledger chain field shows repeated entries on re-run | Known behavior — chain field in ledger accumulates all prior chains for that IP; read `attack_chain.txt` directly for the per-run view |
| VPN IP shows "unknown" | tun0 and eth0 both had no IP. Check `ip a` — informational only, doesn't affect output |

---

## Related Tools

- `lootr.sh` / `lootr.ps1` — Run on the target to collect raw loot **before** running evidencr. Flag files will be in `loot/<hostname>/proof/`
- `Creds_Tracker.md` — Update with flag UUIDs as part of step 4 above
- `OffSec_Exam_Methodology_Complete.md` — Phase 18 covers the full flag → evidence → report workflow
