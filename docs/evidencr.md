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

## engagement Day Workflow

### 1. Get a flag → run evidencr immediately

```bash
# You just caught root on 10.10.10.5
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags both \
  --points 20 --category standalone
```

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

### 4. At end of engagement, review the cross-machine ledger

```bash
cat $TOOLKIT_ROOT/evidence/evidence_ledger.txt
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

## Flag Value Entry

Flag values are entered **silently** (no terminal echo) to keep UUIDs out of scrollback. The script validates UUID format and warns — but does not block — if the value doesn't match.

```
Enter flag value for proof.txt (paste the UUID): [silent input]
```

Valid formats accepted:
- `a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4` (32 hex chars)
- `a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4` (UUID with dashes)

---

## Re-Running for the Same IP

Safe. The script warns you, asks for confirmation (skipped with `--non-interactive`), then appends a new evidence block. The ledger and summary both accumulate entries by timestamp.

```bash
# Ran it early with just local, now have proof too
./evidencr.sh -t 10.10.10.5 -n victim01 --os Linux --flags proof \
  --points 20 --category standalone
```

---

## AD Machine Notes

Use `--category AD-client` or `--category AD-DC` to tag machines correctly. The AD set is graded as a chain — make sure your attack chain entries reflect lateral movement and how each machine connects to the next.

```bash
# DC with assumed-breach credentials
./evidencr.sh -t 10.10.10.10 -n DC01 --os Windows --flags proof \
  --points 40 --category AD-DC
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

- `lootr.sh` — Run on the Linux target to collect raw loot **before** running evidencr
- `lootr.ps1` — Run on the Windows target. Flag files will be in `loot/<hostname>/proof/`
- `Creds_Tracker.md` — Copy flag UUIDs here manually after evidencr completes
- `OffSec_Exam_Methodology_Complete.md` — Phase 18 covers the full flag → evidence → report workflow
