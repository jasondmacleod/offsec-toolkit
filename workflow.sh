#!/usr/bin/env bash
#==============================================================================
# workflow.sh — OffSec engagement Workflow Quick Reference
# Prints the recommended attack flow with exact commands using the toolkit.
#
# Usage: ./workflow.sh [phase]
#   phase: recon, web, ad, spray, crack, privesc, pivot, loot, evidence, all
#==============================================================================

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'

if [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; then
    BOLD='' CYAN='' GREEN='' YELLOW='' MAGENTA='' NC=''
fi
for arg in "$@"; do [[ "$arg" == "--no-color" ]] && { BOLD='' CYAN='' GREEN='' YELLOW='' MAGENTA='' NC=''; }; done

header() { echo -e "\n${BOLD}${MAGENTA}═══ $1 ═══${NC}"; }
cmd()    { echo -e "  ${GREEN}\$${NC} $1"; }
note()   { echo -e "  ${YELLOW}→${NC} $1"; }

show_recon() {
    header "1. RECON — First 10 minutes per target"
    cmd "./recon.sh --auto 10.10.10.1 10.10.10.2 10.10.10.3"
    note "Runs rustscan → nmap TCP/UDP → service enum in parallel"
    note "Output: \$TOOLKIT_ROOT/recon/<ip>/"
    echo ""
    note "★ Read these first (generated per target):"
    cmd "cat \$TOOLKIT_ROOT/recon/10.10.10.1/summary.txt"
    note "  └─ summary includes a short next-step preview"
    cmd "cat \$TOOLKIT_ROOT/recon/10.10.10.1/loot/next_steps.txt"
    note "  └─ evidence-backed follow-on commands"
    cmd "cat \$TOOLKIT_ROOT/recon/10.10.10.1/loot/quick_wins.txt"
    note "  └─ anonymous access, default creds, zone transfers, risky findings"
    echo ""
    note "Across all targets at once:"
    cmd "cat \$TOOLKIT_ROOT/recon/*/loot/quick_wins.txt"
}

show_web() {
    header "2. WEB ENUM — When HTTP/HTTPS found"
    cmd "./webenum.sh --from-recon 10.10.10.1"
    note "Auto-detects URLs from recon nmap output"
    note "Or specify directly:"
    cmd "./webenum.sh --url http://10.10.10.1:8080"
    note "Runs: gobuster, feroxbuster, nikto, whatweb, tech fingerprint"
    note "Output: \$TOOLKIT_ROOT/web/<host>/"
}

show_ad() {
    header "3. AD ENUM — When domain controller found"
    cmd "./adr.sh -d corp.local -u user -p 'Pass123' -dc 10.10.10.1"
    note "Runs: enum4linux-ng, RPC, LDAP, SMB, BloodHound, AS-REP, Kerberoast"
    note "Creds logged to \$TOOLKIT_ROOT/creds.txt automatically"
    note "Output: \$TOOLKIT_ROOT/ad/corp.local/"
}

show_spray() {
    header "4. CREDENTIAL SPRAY — Test found creds across protocols"
    cmd "./sprayr.sh -U users.txt -p 'Summer2024!' -T targets.txt --proto smb,winrm,rdp,ssh"
    note "Use --safe for lockout-conscious sequential spraying with jitter"
    note "Hits logged to \$TOOLKIT_ROOT/creds.txt"
    note "Output: \$TOOLKIT_ROOT/spray/<timestamp>/"
}

show_crack() {
    header "5. CRACK — Offline hash cracking"
    cmd "./crackr.sh -f ntlm_hashes.txt"
    cmd "./crackr.sh -f shadow.txt                        # auto-detect"
    cmd "./crackr.sh --hydra ssh --target 10.10.10.1 -u admin"
    note "Cracked creds logged to \$TOOLKIT_ROOT/creds.txt"
    note "Output: \$TOOLKIT_ROOT/crackr/"
}

show_privesc() {
    header "6. PRIVESC ENUM — On target or remote"
    note "Linux target:"
    cmd "./escalatr.sh 10.10.10.1 --os linux"
    note "Windows target (run on target):"
    cmd "powershell -ep bypass .\\lootr.ps1"
    note "Output: \$TOOLKIT_ROOT/privesc/ (Linux) | .\\loot\\ (Windows)"
    echo ""
    note "★ Read next_steps.txt first — contains resolved exploit commands per finding:"
    cmd "cat \$TOOLKIT_ROOT/privesc/10.10.10.1/next_steps.txt  # Linux"
    cmd "type C:\\loot\\next_steps.txt                       # Windows (on target)"
}

show_pivot() {
    header "7. PIVOT — Reach internal networks"
    cmd "./pivotr.sh ligolo --pivot-ip 10.10.10.5 --subnet 172.16.1.0/24"
    note "Alternatives: ssh, chisel, listener modes"
    note "State tracked in \$TOOLKIT_ROOT/pivots/"
    echo ""
    note "Through pivot, use proxychains:"
    cmd "proxychains nmap -sT -Pn 172.16.1.10"
}

show_loot() {
    header "8. LOOT — Post-exploitation collection"
    note "Linux target (run ON target):"
    cmd "bash lootr.sh"
    note "Windows target (run ON target):"
    cmd "powershell -ep bypass .\\lootr.ps1"
    note "Finds proof.txt/local.txt, creds, network info, privesc vectors"
    echo ""
    note "★ Read next_steps.txt — generated per finding, no placeholders:"
    cmd "cat loot/next_steps.txt   # Linux output dir"
    cmd "type loot\\next_steps.txt  # Windows output dir"
    note "  └─ SeImpersonate → Potato command, SUID → exploit, creds → spray, etc."
}

show_evidence() {
    header "9. EVIDENCE — Screenshot + flag capture"
    cmd "./evidencr.sh -t 10.10.10.1 --local-flag <flag> --proof-flag <flag>"
    note "Records: IP, hostname, flags, whoami, ifconfig, screenshots"
    note "Output: \$TOOLKIT_ROOT/evidence/"
    echo ""
    note "Before submitting, verify all flags:"
    cmd "cat \$TOOLKIT_ROOT/evidence/*/flags.txt"
    cmd "cat \$TOOLKIT_ROOT/creds.txt"
}

show_env() {
    header "ENVIRONMENT"
    note "All output goes under: \${TOOLKIT_ROOT:-\$HOME/toolkit}"
    cmd "export TOOLKIT_ROOT=\$HOME/toolkit"
    note "Unified creds log: \$TOOLKIT_ROOT/creds.txt"
    echo ""
    note "Preflight tool check (no sudo needed):"
    cmd "./tools_setup.sh --check"
    note "Serve tools to targets:"
    cmd "cd ~/tools/windows && python3 -m http.server 80"
    cmd "./servr.sh http --dir ~/tools/windows --port 80"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
phase="${1:-all}"
# Strip --no-color from phase if it was first arg
[[ "$phase" == "--no-color" ]] && phase="all"

case "$phase" in
    recon)    show_recon ;;
    web)      show_web ;;
    ad)       show_ad ;;
    spray)    show_spray ;;
    crack)    show_crack ;;
    privesc)  show_privesc ;;
    pivot)    show_pivot ;;
    loot)     show_loot ;;
    evidence) show_evidence ;;
    env)      show_env ;;
    all)
        show_env
        show_recon
        show_web
        show_ad
        show_spray
        show_crack
        show_privesc
        show_pivot
        show_loot
        show_evidence
        echo -e "\n${BOLD}${CYAN}Tip:${NC} ./workflow.sh <phase> for just one section"
        echo ""
        ;;
    -h|--help|help)
        echo "Usage: ./workflow.sh [phase] [--no-color]"
        echo "Phases: recon, web, ad, spray, crack, privesc, pivot, loot, evidence, env, all"
        ;;
    *)
        echo "Unknown phase: $phase"
        echo "Phases: recon, web, ad, spray, crack, privesc, pivot, loot, evidence, env, all"
        exit 1
        ;;
esac
