#!/bin/bash
#=============================================================================
# crackr.sh v3 - OffSec Password Cracking Suite
# Usage: ./crackr.sh [OPTIONS]
#
# Automates hash identification, tool selection, and cracking with sensible
# OffSec defaults. Supports hashcat, john, *2john extraction, CeWL wordlist
# generation, Hydra online brute forcing, mask/hybrid attacks, and unshadow.
#
# v3 changes:
#   - Added hash sigs: KeePass, DCC2/MSCash2, NTLMv1, mssql, mysql
#   - MD5/NTLM 32-char hex ambiguity warning + context-aware detection
#   - Quick mode escalation matches methodology: best64 → rockyou-30000 → dive
#   - Hashcat early-exit in quick mode (not just JTR)
#   - Mask attack (-a 3), hybrid attack (-a 6), unshadow shortcut
#   - Hydra -C combo file support
#   - Replaced eval with arrays for safe command execution
#   - Removed --force flag (hashcat upstream discourages it)
#   - Dynamic CeWL mutation years (auto-generates from current year)
#   - Session logging for OffSec report reproducibility
#   - Added rockyou-30000 rule shortcut
#=============================================================================

set -o pipefail
# NOT set -e: one tool failure must not abort the whole run
# NOT set -u: optional variables must be safe to reference unset

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

disable_colors() { RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''; }
[[ "${NO_COLOR:-0}" == "1" ]] || [[ ! -t 1 ]] && disable_colors

# ── Defaults ────────────────────────────────────────────────────────────────
TOOLKIT_ROOT="${TOOLKIT_ROOT:-${HOME}/offsec}"
WORDLIST="/usr/share/wordlists/rockyou.txt"
RULE=""
TOOL="auto"
OUTPUT_DIR="${TOOLKIT_ROOT}/crackr"
EXTRACT_MODE=""
INPUT_FILE=""
SINGLE_HASH=""
FORCE_HASHCAT_MODE=""
FORCE_JTR_FORMAT=""
QUICK_MODE=0
LOG_FILE=""

# ── Mask/hybrid mode defaults ──────────────────────────────────────────────
MASK_PATTERN=""
HYBRID_APPEND=""
HYBRID_PREPEND=""
UNSHADOW_PASSWD=""
UNSHADOW_SHADOW=""

# ── Hydra defaults ──────────────────────────────────────────────────────────
HYDRA_MODE=""
HYDRA_TARGET=""
HYDRA_PORT=""
HYDRA_USER=""
HYDRA_USERLIST=""
HYDRA_PASS=""
HYDRA_PASSLIST=""
HYDRA_COMBOLIST=""
HYDRA_HTTP_PATH=""
HYDRA_HTTP_FORM=""
HYDRA_THREADS=16
HYDRA_EXTRA=""
HYDRA_STOP_ON_SUCCESS=1

# ── CeWL defaults ──────────────────────────────────────────────────────────
CEWL_URL=""
CEWL_DEPTH=2
CEWL_MIN_LEN=5
CEWL_WITH_NUMBERS=1
CEWL_MUTATE=0
CEWL_OUTPUT=""

# ── Wordlist shortcuts ──────────────────────────────────────────────────────
declare -A WORDLISTS=(
    [rockyou]="/usr/share/wordlists/rockyou.txt"
    [fasttrack]="/usr/share/wordlists/fasttrack.txt"
    [top1m]="/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    [xato1m]="/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt"
    [darkweb]="/usr/share/seclists/Passwords/darkweb2017-top10000.txt"
    [top10k]="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
)

# ── Rule shortcuts ──────────────────────────────────────────────────────────
declare -A RULES_HASHCAT=(
    [best64]="/usr/share/hashcat/rules/best64.rule"
    [best66]="/usr/share/hashcat/rules/best64.rule"
    [onerule]="/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule"
    [rockyou-30000]="/usr/share/hashcat/rules/rockyou-30000.rule"
    [d3ad0ne]="/usr/share/hashcat/rules/d3ad0ne.rule"
    [dive]="/usr/share/hashcat/rules/dive.rule"
    [toggles]="/usr/share/hashcat/rules/toggles1.rule"
)

declare -A RULES_JTR=(
    [best64]="best64"
    [wordlist]="wordlist"
    [single]="single"
    [korelogic]="KoreLogic"
)

# ── Hash patterns → hashcat mode + JTR format ──────────────────────────────
# Format: "regex|hashcat_mode|jtr_format|description"
# Order matters — more specific patterns must come before generic ones.
# The MD5 vs NTLM ambiguity for bare 32-char hex is handled separately
# in identify_hash() with a warning.
# shellcheck disable=SC2016  # \$ in single-quoted regex patterns is intentional
HASH_SIGNATURES=(
    # SAM dump and structured formats first (most specific)
    '^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$|1000|nt|NTLM (with LM pair)'
    # NTLMv1 — MUST come before NTLMv2 broad pattern (hex-length anchors prevent NTLMv2 false match)
    '.*::.*:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]+$|5500|netntlm|NTLMv1 (Net-NTLMv1)'
    # Net-NTLMv2 (Responder captures) — broad pattern after NTLMv1
    '.*::.*:.*:.*:[a-fA-F0-9]+$|5600|netntlmv2|NTLMv2 (Net-NTLMv2)'
    # Kerberos
    '^\$krb5tgs\$17\$|19600|krb5tgs-aes128|Kerberos TGS-REP AES-128 (Kerberoast)'
    '^\$krb5tgs\$18\$|19700|krb5tgs-aes256|Kerberos TGS-REP AES-256 (Kerberoast)'
    '^\$krb5tgs\$23\$|13100|krb5tgs|Kerberos TGS-REP RC4 (Kerberoast)'
    '^\$krb5asrep\$|18200|krb5asrep|Kerberos AS-REP (AS-REP Roast)'
    '^\$krb5pa\$23\$|7500|krb5pa-md5|Kerberos Pre-Auth'
    # Linux crypt formats
    '^\$1\$|500|md5crypt|MD5 Crypt (Linux)'
    '^\$5\$|7400|sha256crypt|SHA-256 Crypt (Linux)'
    '^\$6\$|1800|sha512crypt|SHA-512 Crypt (Linux)'
    '^\$y\$|NA|yescrypt|yescrypt (modern Linux)'
    # bcrypt
    '^\$2[aby]\$|3200|bcrypt|bcrypt'
    # Apache
    '^\$apr1\$|1600|md5crypt-apache|Apache MD5'
    # CMS hashes
    '^\$P\$|400|phpass|phpass (WordPress/phpBB)'
    '^\$H\$|400|phpass|phpass (WordPress/phpBB)'
    # KeePass
    '^\$keepass\$|13400|KeePass|KeePass'
    # DCC2 / MSCash2
    '^\$DCC2\$|2100|mscash2|Domain Cached Credentials 2 (DCC2)'
    # LDAP
    '^\{SSHA\}|111|salted-sha1|SSHA (LDAP)'
    '^\{SHA\}|101|raw-sha1|SHA (LDAP)'
    # Django
    '^sha1\$|124|django-sha1|Django SHA-1'
    '^pbkdf2_sha256\$|10000|django-pbkdf2-sha256|Django PBKDF2-SHA256'
    # MSSQL
    '^0x0100[a-fA-F0-9]{88}$|131|mssql05|MSSQL (2005)'
    '^0x0200[a-fA-F0-9]{136}$|1731|mssql12|MSSQL (2012+)'
    # MySQL
    '^\*[a-fA-F0-9]{40}$|300|mysql-sha1|MySQL 4.1+ (SHA1)'
    # macOS
    '^\$ml\$|7100|macos-v2|macOS v10.8+ (PBKDF2-SHA512)'
    # Generic hex hashes — LAST (least specific)
    '^[a-fA-F0-9]{128}$|1700|raw-sha512|SHA-512'
    '^[a-fA-F0-9]{64}$|1400|raw-sha256|SHA256'
    '^[a-fA-F0-9]{40}$|100|raw-sha1|SHA1'
    # 32-char hex: ambiguous MD5/NTLM — handled in identify_hash()
)

# ── *2john extraction tools ────────────────────────────────────────────────
declare -A EXTRACT_TOOLS=(
    [ssh]="ssh2john"
    [zip]="zip2john"
    [rar]="rar2john"
    [7z]="7z2john"
    [pdf]="pdf2john"
    [office]="office2john"
    [keepass]="keepass2john"
    [gpg]="gpg2john"
    [bitlocker]="bitlocker2john"
    [truecrypt]="truecrypt2john"
    [luks]="luks2john"
    [pgp]="pgp2john"
    [putty]="putty2john"
    [pfx]="pfx2john"
    [pkcs12]="pfx2john"
    [mscash]="mscash2john"
    [wpa]="wpapcap2john"
    [vnc]="vnc2john"
    [krb]="kirbi2john"
    [enc]="ansible2john"
)

# ── Hydra service ports ────────────────────────────────────────────────────
declare -A HYDRA_DEFAULT_PORTS=(
    [ssh]=22
    [ftp]=21
    [rdp]=3389
    [smb]=445
    [telnet]=23
    [mysql]=3306
    [mssql]=1433
    [postgres]=5432
    [vnc]=5900
    [pop3]=110
    [imap]=143
    [smtp]=25
    [snmp]=161
    [ldap]=389
    [http-get]=80
    [http-post-form]=80
    [https-get]=443
    [https-post-form]=443
)

# ── Functions ───────────────────────────────────────────────────────────────

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║      crackr v3 - OffSec Cracking Suite     ║"
    echo "║   Crack · Brute · Mask · Wordlist Gen    ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    banner
    cat <<EOF
${BOLD}USAGE:${NC}
  ${BOLD}Offline Cracking:${NC}
    crackr -f <hashfile>                     Auto-detect and crack hashes
    crackr -H <hash>                         Crack a single hash
    crackr -e <type> -f <file>               Extract hash & crack (ssh, zip, etc.)
    crackr -q -f <hashfile>                  Quick mode: escalating attacks

  ${BOLD}Mask & Hybrid Attacks:${NC}
    crackr --mask '?u?l?l?l?d?d?d?d' -m 1000 -f hashes.txt
    crackr --hybrid-append '?d?d?d?d' -f hashes.txt
    crackr --hybrid-prepend '?d?d?d?d' -f hashes.txt

  ${BOLD}Unshadow:${NC}
    crackr --unshadow <passwd> <shadow>      Combine & crack Linux creds

  ${BOLD}Online Brute Force (Hydra):${NC}
    crackr --hydra <service> --target <ip>   Brute force a service
    crackr --hydra ssh --target <ip> -u <user>
    crackr --hydra ssh --target <ip> -C <combo_file>
    crackr --hydra http-post-form --target <ip> --http-form <form_spec>

  ${BOLD}Wordlist Generation (CeWL):${NC}
    crackr --cewl <url>                      Generate wordlist from website
    crackr --cewl <url> -f <hashfile>        Generate wordlist then crack
    crackr --cewl <url> --cewl-mutate        Add common mutations

  ${BOLD}Utilities:${NC}
    crackr --show -f <hashfile>              Show cracked results
    crackr --list                            List available resources

${BOLD}OFFLINE CRACKING OPTIONS:${NC}
  -f, --file <path>          File containing hashes (or file to extract from)
  -H, --hash <hash>          Single hash string to crack
  -e, --extract <type>       Extract hash first (ssh,zip,rar,pdf,office,keepass,...)
  -w, --wordlist <name|path> Wordlist: rockyou,fasttrack,top1m,darkweb,top10k or path
  -r, --rule <name|path>     Rule: best64,rockyou-30000,onerule,d3ad0ne,dive or path
  -t, --tool <jtr|hashcat>   Force tool (default: auto-select)
  -m, --mode <number>        Force hashcat mode
  -j, --jtr-format <fmt>     Force JTR format
  -q, --quick                Quick mode: fasttrack -> rockyou -> +best64 -> +rockyou-30000

${BOLD}MASK / HYBRID OPTIONS:${NC}
  --mask <pattern>           Hashcat mask attack (-a 3). ?l ?u ?d ?s ?a
  --hybrid-append <mask>     Wordlist + mask appended (-a 6)
  --hybrid-prepend <mask>    Mask + wordlist prepended (-a 7)

${BOLD}UNSHADOW:${NC}
  --unshadow <passwd> <shadow>  Combine passwd+shadow then crack

${BOLD}HYDRA OPTIONS:${NC}
  --hydra <service>            Service: ssh,ftp,rdp,smb,http-post-form,...
  --target <ip>                Target host
  --port <num>                 Override default port
  -u, --user <name>            Single username
  -U, --userlist <file>        File with usernames
  -p, --pass <password>        Single password
  -P, --passlist <file>        File with passwords
  -C, --combo <file>           Combo file (user:pass per line) — replaces -u/-p/-w
  --http-path <path>           Path for http-get/https-get (default: /)
  --http-form <spec>           Form spec: "/path:params:fail_string"
  --hydra-threads <num>        Threads (default: 16)
  --hydra-extra <args>         Extra hydra arguments
  --no-stop                    Don't stop on first valid cred (per user)

${BOLD}CEWL OPTIONS:${NC}
  --cewl <url>               Target URL to scrape for words
  --cewl-depth <num>         Spider depth (default: 2)
  --cewl-min <num>           Minimum word length (default: 5)
  --cewl-mutate              Add OffSec mutations (Year, 123, !, capitalize, leet, etc.)
  --cewl-output <file>       Custom output path for generated wordlist

${BOLD}GENERAL OPTIONS:${NC}
  -o, --output <dir>         Output directory (default: \$TOOLKIT_ROOT/crackr)
  -s, --show                 Show cracked results for a hash file
  -l, --list                 List available wordlists, rules, and tools
  --no-color                 Disable colored output (also honors NO_COLOR=1 env var)
  -h, --help                 Show this help

${BOLD}EXAMPLES:${NC}
  ${CYAN}# -- Offline Cracking --${NC}
  crackr -q -f ntlm_hashes.txt                    # Quick-crack NTLM
  crackr -e ssh -f id_rsa -q                       # Extract SSH key + crack
  crackr -H '\$krb5tgs\$23\$*user...' -q             # Crack Kerberoast hash
  crackr -f shadow.txt -t hashcat -m 1800 -r best64

  ${CYAN}# -- Mask / Hybrid Attacks --${NC}
  crackr --mask 'Company?d?d?d?d' -m 1000 -f hashes.txt
  crackr --hybrid-append '?d?d?d?d' -f hashes.txt -m 1000
  crackr --unshadow /tmp/passwd.bak /tmp/shadow.bak

  ${CYAN}# -- Online Brute Force --${NC}
  crackr --hydra ssh --target 10.10.10.5 -u admin
  crackr --hydra ssh --target 10.10.10.5 -U users.txt -w fasttrack
  crackr --hydra ssh --target 10.10.10.5 -C user_pass.txt
  crackr --hydra ftp --target 10.10.10.5 -u anonymous -p anonymous
  crackr --hydra rdp --target 10.10.10.5 -u admin -w rockyou
  crackr --hydra http-post-form --target 10.10.10.5 \\
    --http-form "/login.php:user=^USER^&password=^PASS^:F=Invalid"
  crackr --hydra http-get --target 10.10.10.5 --http-path /admin

  ${CYAN}# -- CeWL Wordlist Generation --${NC}
  crackr --cewl http://target.com                  # Generate wordlist
  crackr --cewl http://target.com --cewl-mutate    # With mutations
  crackr --cewl http://target.com -f hashes.txt    # Generate + crack
  crackr --cewl http://target.com --cewl-mutate -q -f hashes.txt  # Full chain

  ${CYAN}# -- Combo Workflows --${NC}
  # Scrape target site, mutate words, crack hashes with them
  crackr --cewl http://megacorp.com --cewl-mutate -f kerberoast.txt -q

${BOLD}EXTRACT TYPES:${NC}
  ssh, zip, rar, 7z, pdf, office, keepass, gpg, bitlocker, putty, pfx, wpa, vnc, krb
EOF
}

log_info()    { echo -e "${CYAN}[*]${NC} $1" | tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1" | tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1" | tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1" | tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || echo -e "${RED}[-]${NC} $1"; }

# Log a command before running it (for OffSec report reproducibility)
log_cmd() {
    local cmd_str="$*"
    echo -e "${YELLOW}CMD: ${cmd_str}${NC}"
    echo "[$(date '+%H:%M:%S')] CMD: ${cmd_str}" >> "${LOG_FILE:-/dev/null}" 2>/dev/null || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] CMD: ${cmd_str}" >> "${OUTPUT_DIR}/cmd_log.txt" 2>/dev/null || true
}

creds_log() {
    local creds_file="${TOOLKIT_ROOT}/creds.txt"
    mkdir -p "$(dirname "$creds_file")" 2>/dev/null || true
    if ! printf '%s | %-8s | %-15s | %-20s | %s | %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" "$3" "$4" "$5" >> "$creds_file" 2>/dev/null; then
        warn "CRED NOT LOGGED — cannot write to ${creds_file}"
        warn "Credential: $3@$2 : $4 ($5)"
    fi
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

is_port_number() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1 && "$1" <= 65535 ))
}

is_valid_hydra_target() {
    local target="$1"
    [[ -n "$target" ]] || return 1
    [[ "$target" != *[[:space:]]* ]] || return 1
    [[ "$target" != */* ]] || return 1
}

# ── List resources ──────────────────────────────────────────────────────────
list_resources() {
    echo -e "\n${BOLD}Available Wordlists:${NC}"
    for key in "${!WORDLISTS[@]}"; do
        local path="${WORDLISTS[$key]}"
        if [[ -f "$path" ]]; then
            local size=""
            size=$(wc -l < "$path" 2>/dev/null || echo "?")
            echo -e "  ${GREEN}✓${NC} ${BOLD}$key${NC} → $path ($size lines)"
        else
            echo -e "  ${RED}✗${NC} ${BOLD}$key${NC} → $path (not found)"
        fi
    done

    echo -e "\n${BOLD}Hashcat Rules:${NC}"
    for key in "${!RULES_HASHCAT[@]}"; do
        local path="${RULES_HASHCAT[$key]}"
        if [[ -f "$path" ]]; then
            echo -e "  ${GREEN}✓${NC} ${BOLD}$key${NC} → $path"
        else
            echo -e "  ${RED}✗${NC} ${BOLD}$key${NC} → $path (not found)"
        fi
    done

    echo -e "\n${BOLD}JTR Rules:${NC}"
    for key in "${!RULES_JTR[@]}"; do
        echo -e "  ${CYAN}▸${NC} ${BOLD}$key${NC} → ${RULES_JTR[$key]}"
    done

    echo -e "\n${BOLD}Extract Types (*2john):${NC}"
    for key in "${!EXTRACT_TOOLS[@]}"; do
        local tool="${EXTRACT_TOOLS[$key]}"
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} ${BOLD}$key${NC} → $tool"
        else
            echo -e "  ${RED}✗${NC} ${BOLD}$key${NC} → $tool (not installed)"
        fi
    done

    echo -e "\n${BOLD}Online Attack Tools:${NC}"
    for tool_name in hydra cewl; do
        if command -v "$tool_name" &>/dev/null; then
            local ver
            case "$tool_name" in
                hydra) ver=$(hydra -h 2>&1 | head -1 | grep -oP 'v[\d.]+' || echo "") ;;
                cewl) ver=$(cewl --version 2>&1 || echo "") ;;
            esac
            echo -e "  ${GREEN}✓${NC} ${BOLD}$tool_name${NC} $ver"
        else
            echo -e "  ${RED}✗${NC} ${BOLD}$tool_name${NC} (not installed)"
        fi
    done

    echo -e "\n${BOLD}Hydra Supported Services:${NC}"
    echo -e "  ${CYAN}▸${NC} ssh, ftp, rdp, smb, telnet, mysql, mssql, postgres"
    echo -e "  ${CYAN}▸${NC} vnc, pop3, imap, smtp, snmp, ldap"
    echo -e "  ${CYAN}▸${NC} http-get, http-post-form, https-get, https-post-form"

    echo -e "\n${BOLD}Hashcat Mask Charsets:${NC}"
    echo -e "  ${CYAN}▸${NC} ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all ?b=0x00-0xff"
}

# ── Resolve helpers ─────────────────────────────────────────────────────────
resolve_wordlist() {
    local input="$1"
    local resolved=""

    if [[ -n "${WORDLISTS[$input]+_}" ]]; then
        resolved="${WORDLISTS[$input]}"
    elif [[ -f "$input" ]]; then
        resolved="$input"
    fi

    if [[ -n "$resolved" && -f "$resolved" ]]; then
        echo "$resolved"
        return 0
    fi

    # Check if the wordlist exists but is gzipped (common on fresh Kali)
    if [[ -n "$resolved" && -f "${resolved}.gz" ]]; then
        log_warn "Wordlist is compressed: ${resolved}.gz"
        log_error "Decompress it before running: sudo gunzip ${resolved}.gz"
        exit 1
    elif [[ -f "${input}.gz" ]]; then
        log_warn "Wordlist is compressed: ${input}.gz"
        log_error "Decompress it before running: sudo gunzip ${input}.gz"
        exit 1
    fi

    log_error "Wordlist not found: $input"
    exit 1
}

resolve_rule() {
    local input="$1"
    local tool="$2"
    if [[ "$tool" == "hashcat" ]]; then
        if [[ -n "${RULES_HASHCAT[$input]+_}" ]]; then
            echo "${RULES_HASHCAT[$input]}"
        elif [[ -f "$input" ]]; then
            echo "$input"
        else
            log_error "Hashcat rule not found: $input"
            exit 1
        fi
    else
        if [[ -n "${RULES_JTR[$input]+_}" ]]; then
            echo "${RULES_JTR[$input]}"
        elif [[ -f "$input" ]]; then
            echo "$input"
        else
            log_error "JTR rule not found: $input"
            exit 1
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Hash Identification ─────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

identify_hash() {
    local hash="$1"

    # Check for SAM dump format: user:rid:lm:ntlm:::
    if echo "$hash" | grep -qP '^[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::$'; then
        echo "1000|nt|NTLM (SAM dump)"
        return
    fi

    # Check for /etc/shadow format: user:$X$...
    if echo "$hash" | grep -qP '^[^:]+:\$'; then
        hash=$(echo "$hash" | cut -d: -f2)
    fi

    for sig in "${HASH_SIGNATURES[@]}"; do
        local regex hc_mode jtr_fmt desc
        IFS='|' read -r regex hc_mode jtr_fmt desc <<< "$sig"
        if echo "$hash" | grep -qP "$regex"; then
            echo "${hc_mode}|${jtr_fmt}|${desc}"
            return
        fi
    done

    # ── Handle 32-char hex ambiguity: MD5 vs NTLM ──
    if echo "$hash" | grep -qP '^[a-fA-F0-9]{32}$'; then
        log_warn "32-char hex detected: could be MD5 (mode 0) or NTLM (mode 1000)"
        log_warn "Defaulting to NTLM — use -m 0 to force MD5 if needed"
        echo "1000|nt|NTLM (32-char hex — could also be MD5, use -m 0 to override)"
        return
    fi

    echo "unknown|unknown|Unknown hash type"
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Hash Extraction (*2john) ────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

extract_hash() {
    local extract_type="$1"
    local source_file="$2"

    if [[ -z "${EXTRACT_TOOLS[$extract_type]+_}" ]]; then
        log_error "Unknown extract type: $extract_type"
        log_info "Available: ${!EXTRACT_TOOLS[*]}"
        exit 1
    fi

    local tool="${EXTRACT_TOOLS[$extract_type]}"

    local -a tool_cmd=()
    if command -v "$tool" &>/dev/null; then
        tool_cmd=("$tool")
    elif [[ -f "/usr/share/john/$tool.py" ]]; then
        tool_cmd=(python3 "/usr/share/john/$tool.py")
    elif [[ -f "/opt/john/run/$tool" ]]; then
        tool_cmd=("/opt/john/run/$tool")
    else
        log_error "Tool not found: $tool"
        log_info "Install john or check your PATH"
        exit 1
    fi

    local extracted_file
    extracted_file="${OUTPUT_DIR}/extracted_${extract_type}_$(basename "$source_file").hash"

    log_info "Extracting hash from: $source_file"
    log_info "Using: ${tool_cmd[*]}"

    local extract_err="${extracted_file}.err"
    if "${tool_cmd[@]}" "$source_file" > "$extracted_file" 2>"$extract_err"; then
        if [[ -s "$extracted_file" ]]; then
            # KeePass: strip "Database:" prefix from keepass2john output
            if [[ "$extract_type" == "keepass" ]]; then
                sed -i 's/^[^:]*://' "$extracted_file"
                log_info "Stripped KeePass filename prefix from hash"
            fi
            log_success "Hash extracted → $extracted_file"
            cat "$extracted_file"
            echo ""
            INPUT_FILE="$extracted_file"
        else
            log_error "Extraction produced empty output"
            [[ -s "$extract_err" ]] && log_error "Tool stderr:" && cat "$extract_err" >&2
            exit 1
        fi
    else
        log_error "Extraction failed"
        [[ -s "$extract_err" ]] && log_error "Tool stderr:" && cat "$extract_err" >&2
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Single Hash Setup ───────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

setup_single_hash() {
    local hash="$1"
    local hash_file
    hash_file="${OUTPUT_DIR}/single_hash_$(date +%s).hash"
    # printf avoids subshell expansion issues with special characters in hashes
    printf '%s\n' "$hash" > "$hash_file" || { log_error "Cannot write hash file: $hash_file"; exit 1; }
    INPUT_FILE="$hash_file"
    log_info "Single hash saved → $hash_file"
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Unshadow ────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

run_unshadow() {
    local passwd_file="$1"
    local shadow_file="$2"

    if [[ ! -f "$passwd_file" ]]; then
        log_error "Passwd file not found: $passwd_file"
        exit 1
    fi
    if [[ ! -f "$shadow_file" ]]; then
        log_error "Shadow file not found: $shadow_file"
        exit 1
    fi

    local unshadowed
    unshadowed="${OUTPUT_DIR}/unshadowed_$(date +%s).hash"

    if command -v unshadow &>/dev/null; then
        unshadow "$passwd_file" "$shadow_file" > "$unshadowed"
    else
        log_warn "unshadow not found, attempting manual combine"
        paste -d: <(cut -d: -f1 "$passwd_file") <(cut -d: -f2 "$shadow_file") > "$unshadowed"
    fi

    if [[ -s "$unshadowed" ]]; then
        log_success "Unshadowed → $unshadowed"
        INPUT_FILE="$unshadowed"
        # Auto-detect: likely sha512crypt
        # shellcheck disable=SC2016  # \$ in single-quoted regex is intentional
        if grep -q '^\$6\$' "$unshadowed"; then
            FORCE_HASHCAT_MODE="${FORCE_HASHCAT_MODE:-1800}"
            log_info "Detected SHA-512 crypt hashes"
        fi
    else
        log_error "Unshadow produced empty output"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Hashcat ─────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

run_hashcat() {
    if ! command -v hashcat &>/dev/null; then
        log_error "hashcat not found — install: sudo apt install hashcat"
        return 1
    fi
    local hash_file="$1"
    local wordlist="$2"
    local mode="$3"
    local rule="${4:-}"
    local potfile="${OUTPUT_DIR}/hashcat.potfile"
    local outfile
    outfile="${OUTPUT_DIR}/hashcat_cracked_$(date +%s).txt"

    local -a cmd=(hashcat -m "$mode" "$hash_file" "$wordlist")
    cmd+=(--potfile-path "$potfile")
    cmd+=(-o "$outfile")
    cmd+=(--status --status-timer=15)

    if [[ -n "$rule" ]]; then
        cmd+=(-r "$rule")
    fi

    log_info "Running hashcat..."
    log_cmd "${cmd[*]}"
    echo ""

    local rc=0
    "${cmd[@]}" || rc=$?
    if (( rc > 1 )); then
        log_warn "Hashcat exited with code $rc (check GPU/OpenCL backend)"
    fi

    echo ""
    if [[ -f "$outfile" && -s "$outfile" ]]; then
        log_success "Cracked passwords:"
        cat "$outfile"
        # Log cracked results to central creds log
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            creds_log "crackr" "offline" "${line%%:*}" "${line#*:}" "cracked"
        done < "$outfile"
        echo ""
        log_success "Results saved → $outfile"
    else
        log_warn "No new cracks. Checking potfile..."
        local show_output
        show_output=$(hashcat -m "$mode" "$hash_file" --potfile-path "$potfile" --show 2>/dev/null) || true
        if [[ -n "${show_output:-}" ]]; then
            echo "$show_output"
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                creds_log "crackr" "offline" "${line%%:*}" "${line#*:}" "cracked"
            done <<< "$show_output"
        fi
    fi
}

# ── Hashcat mask attack ────────────────────────────────────────────────────

run_hashcat_mask() {
    if ! command -v hashcat &>/dev/null; then
        log_error "hashcat not found — install: sudo apt install hashcat"
        return 1
    fi
    local hash_file="$1"
    local mode="$2"
    local mask="$3"
    local potfile="${OUTPUT_DIR}/hashcat.potfile"
    local outfile
    outfile="${OUTPUT_DIR}/hashcat_mask_cracked_$(date +%s).txt"

    local -a cmd=(hashcat -m "$mode" -a 3 "$hash_file" "$mask")
    cmd+=(--potfile-path "$potfile")
    cmd+=(-o "$outfile")
    cmd+=(--status --status-timer=15)

    log_info "Running hashcat mask attack..."
    log_info "Mask: $mask"
    log_cmd "${cmd[*]}"
    echo ""

    local rc=0
    "${cmd[@]}" || rc=$?
    if (( rc > 1 )); then
        log_warn "Hashcat exited with code $rc (check GPU/OpenCL backend)"
    fi

    echo ""
    if [[ -f "$outfile" && -s "$outfile" ]]; then
        log_success "Cracked passwords:"
        cat "$outfile"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            creds_log "crackr" "offline" "${line%%:*}" "${line#*:}" "cracked"
        done < "$outfile"
        echo ""
        log_success "Results saved → $outfile"
    else
        log_warn "No cracks from mask attack."
    fi
}

# ── Hashcat hybrid attack ──────────────────────────────────────────────────

run_hashcat_hybrid() {
    if ! command -v hashcat &>/dev/null; then
        log_error "hashcat not found — install: sudo apt install hashcat"
        return 1
    fi
    local hash_file="$1"
    local mode="$2"
    local wordlist="$3"
    local mask="$4"
    local attack_mode="$5"  # 6=append, 7=prepend
    local potfile="${OUTPUT_DIR}/hashcat.potfile"
    local outfile
    outfile="${OUTPUT_DIR}/hashcat_hybrid_cracked_$(date +%s).txt"

    local -a cmd=(hashcat -m "$mode" -a "$attack_mode" "$hash_file")
    if [[ "$attack_mode" == "6" ]]; then
        cmd+=("$wordlist" "$mask")
    else
        cmd+=("$mask" "$wordlist")
    fi
    cmd+=(--potfile-path "$potfile")
    cmd+=(-o "$outfile")
    cmd+=(--status --status-timer=15)

    log_info "Running hashcat hybrid attack (mode $attack_mode)..."
    log_cmd "${cmd[*]}"
    echo ""

    local rc=0
    "${cmd[@]}" || rc=$?
    if (( rc > 1 )); then
        log_warn "Hashcat exited with code $rc (check GPU/OpenCL backend)"
    fi

    echo ""
    if [[ -f "$outfile" && -s "$outfile" ]]; then
        log_success "Cracked passwords:"
        cat "$outfile"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            creds_log "crackr" "offline" "${line%%:*}" "${line#*:}" "cracked"
        done < "$outfile"
        echo ""
        log_success "Results saved → $outfile"
    else
        log_warn "No cracks from hybrid attack."
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ── John the Ripper ─────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

run_jtr() {
    if ! command -v john &>/dev/null; then
        log_error "john not found — install: sudo apt install john"
        return 1
    fi
    local hash_file="$1"
    local wordlist="$2"
    local format="${3:-}"
    local rule="${4:-}"

    local -a cmd=(john "$hash_file" --wordlist="$wordlist")

    if [[ "$format" != "unknown" && -n "$format" ]]; then
        cmd+=(--format="$format")
    fi

    if [[ -n "$rule" ]]; then
        cmd+=(--rules="$rule")
    fi

    log_info "Running John the Ripper..."
    log_cmd "${cmd[*]}"
    echo ""

    "${cmd[@]}" || true

    echo ""
    log_info "Cracked passwords:"
    local show_output
    if [[ "$format" != "unknown" && -n "$format" ]]; then
        show_output=$(john --show --format="$format" "$hash_file" 2>/dev/null) || true
    else
        show_output=$(john --show "$hash_file" 2>/dev/null) || true
    fi
    if [[ -n "${show_output:-}" ]]; then
        echo "$show_output"
        # Log cracked lines (john --show format is user:password or hash:password)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            # Skip the summary line ("N password hashes cracked, ...")
            [[ "$line" == *" password hash"* ]] && continue
            local jtr_user="${line%%:*}"
            local jtr_pass="${line#*:}"
            # Strip trailing fields after password (john --show can include extra : fields)
            jtr_pass="${jtr_pass%%:*}"
            [[ -n "$jtr_pass" ]] && creds_log "crackr" "offline" "$jtr_user" "$jtr_pass" "cracked"
        done <<< "$show_output"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Show Cracked ────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

show_cracked() {
    local hash_file="$1"

    log_info "Checking JTR pot..."
    john --show "$hash_file" 2>/dev/null || true

    echo ""
    log_info "Checking hashcat pot..."
    local potfile="${OUTPUT_DIR}/hashcat.potfile"
    if [[ -f "$potfile" ]]; then
        for mode in 0 100 300 400 500 1000 1400 1600 1700 1800 2100 3200 5500 5600 7400 7500 13100 13400 18200 19600 19700; do
            local result=""
            result=$(hashcat -m "$mode" "$hash_file" --potfile-path "$potfile" --show 2>/dev/null) || true
            if [[ -n "$result" ]]; then
                echo "$result"
            fi
        done
    else
        log_warn "No hashcat potfile found at $potfile"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Quick Mode — Escalating attacks matching OffSec methodology ──────────
# ═══════════════════════════════════════════════════════════════════════════

check_all_cracked_hashcat() {
    local hash_file="$1"
    local mode="$2"
    local potfile="${OUTPUT_DIR}/hashcat.potfile"

    if [[ ! -f "$potfile" ]]; then
        return 1
    fi

    local total
    total=$(grep -vE '^\s*#' "$hash_file" | grep -cv '^\s*$' 2>/dev/null); total=${total:-0}
    local cracked
    cracked=$(hashcat -m "$mode" "$hash_file" --potfile-path "$potfile" --show 2>/dev/null | grep -c ':'); cracked=${cracked:-0}

    if [[ "$cracked" -ge "$total" && "$total" -gt 0 ]]; then
        return 0
    fi
    return 1
}

run_quick_mode() {
    local hash_file="$1"
    local hc_mode="$2"
    local jtr_fmt="$3"
    local tool="$4"

    # Escalation: fasttrack → rockyou → rockyou+best64 → rockyou+rockyou-30000
    # Matches methodology: best64 → rockyou-30000 → dive (dive skipped for time)
    local stages=(
        "fasttrack|"
        "rockyou|"
        "rockyou|best64"
        "rockyou|rockyou-30000"
    )

    for stage in "${stages[@]}"; do
        local wl_name rule_name
        IFS='|' read -r wl_name rule_name <<< "$stage"

        local wl_path
        wl_path=$(resolve_wordlist "$wl_name" 2>/dev/null) || true
        if [[ ! -f "${wl_path:-}" ]]; then
            log_warn "Skipping $wl_name (not found)"
            continue
        fi

        local rule_path=""
        local label
        if [[ -n "$rule_name" ]]; then
            label="$wl_name + $rule_name rule"
        else
            label="$wl_name"
        fi

        echo ""
        echo -e "${BOLD}═══════════════════════════════════════${NC}"
        log_info "Stage: ${label}"
        echo -e "${BOLD}═══════════════════════════════════════${NC}"

        if [[ "$tool" == "hashcat" && "$hc_mode" != "NA" && "$hc_mode" != "unknown" ]]; then
            if [[ -n "$rule_name" ]]; then
                rule_path=$(resolve_rule "$rule_name" "hashcat" 2>/dev/null) || rule_path=""
                if [[ -n "$rule_path" && ! -f "$rule_path" ]]; then
                    log_warn "Rule file not found: $rule_path — skipping stage"
                    continue
                fi
            fi
            run_hashcat "$hash_file" "$wl_path" "$hc_mode" "${rule_path:-}"

            # Early exit: check if all cracked
            if check_all_cracked_hashcat "$hash_file" "$hc_mode"; then
                log_success "All hashes cracked!"
                return
            fi
        else
            if [[ -n "$rule_name" ]]; then
                rule_path=$(resolve_rule "$rule_name" "jtr" 2>/dev/null) || rule_path=""
            fi
            run_jtr "$hash_file" "$wl_path" "$jtr_fmt" "${rule_path:-}"

            # Early exit: JTR
            local remaining
            remaining=$(john --show "$hash_file" 2>/dev/null | tail -1 | grep -oP '\d+ password hash.* left' || true)
            if [[ "$remaining" == *"0 password hash"* ]]; then
                log_success "All hashes cracked!"
                return
            fi
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════
# ── CeWL: Custom Wordlist Generation ───────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

run_cewl() {
    local url="$1"

    if ! command -v cewl &>/dev/null; then
        log_error "CeWL not installed. Install with: sudo apt install cewl -y"
        exit 1
    fi

    local output="${CEWL_OUTPUT:-${OUTPUT_DIR}/cewl_$(echo "$url" | sed 's|https\?://||;s|/|_|g;s|[^a-zA-Z0-9_.-]||g').txt}"

    log_info "Generating wordlist from: $url"
    log_info "Depth: $CEWL_DEPTH | Min length: $CEWL_MIN_LEN"

    local -a cmd=(cewl "$url" -d "$CEWL_DEPTH" -m "$CEWL_MIN_LEN" -w "$output")

    if [[ "$CEWL_WITH_NUMBERS" -eq 1 ]]; then
        cmd+=(--with-numbers)
    fi

    log_cmd "${cmd[*]}"
    local cewl_err="${output}.err"
    "${cmd[@]}" 2>"$cewl_err" || true

    if [[ ! -s "$output" ]]; then
        log_error "CeWL produced no output"
        [[ -s "$cewl_err" ]] && log_error "CeWL stderr:" && cat "$cewl_err" >&2
        return 1
    fi

    local word_count
    word_count=$(wc -l < "$output")
    log_success "CeWL generated $word_count words → $output"

    # Apply OffSec mutations if requested
    if [[ "$CEWL_MUTATE" -eq 1 ]]; then
        local mutated="${output%.txt}_mutated.txt"
        log_info "Applying OffSec mutations..."

        cp "$output" "$mutated"

        # Dynamic year range: 5 years back, 1 year forward
        local current_year
        current_year=$(date +%Y)
        local year_start=$((current_year - 5))
        local year_end=$((current_year + 1))

        while IFS= read -r word; do
            [[ -z "$word" ]] && continue

            local lower="" upper="" capitalized=""
            lower=$(echo "$word" | tr '[:upper:]' '[:lower:]')
            upper=$(echo "$word" | tr '[:lower:]' '[:upper:]')
            capitalized="${word^}"

            # Case variants
            echo "$lower"
            echo "$upper"
            echo "$capitalized"

            # Common suffixes
            for suffix in "" "1" "12" "123" "1234" "!" "!!" "@" "#" "1!" "123!"; do
                echo "${capitalized}${suffix}"
                echo "${lower}${suffix}"
            done

            # Year suffixes (dynamic)
            for (( yr=year_start; yr<=year_end; yr++ )); do
                echo "${capitalized}${yr}"
                echo "${lower}${yr}"
                echo "${capitalized}${yr}!"
                echo "${lower}${yr}!"
            done

            # Leet speak basics
            local leet=""
            leet=$(echo "$lower" | sed 'y/aeiost/431057/')
            echo "$leet"
            echo "${leet}123"
            echo "${leet}!"

        done < "$output" >> "$mutated"

        # Deduplicate
        sort -u "$mutated" -o "$mutated"
        local mutated_count
        mutated_count=$(wc -l < "$mutated")
        log_success "Mutated wordlist: $mutated_count words → $mutated"

        WORDLIST="$mutated"
        output="$mutated"
    else
        WORDLIST="$output"
    fi

    log_info "Wordlist set to: $output"
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Hydra: Online Brute Force ──────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

run_hydra() {
    if ! command -v hydra &>/dev/null; then
        log_error "Hydra not installed. Install with: sudo apt install hydra -y"
        exit 1
    fi

    local service="$HYDRA_MODE"
    local target="$HYDRA_TARGET"

    if [[ -z "$target" ]]; then
        log_error "No target specified. Use --target <ip>"
        exit 1
    fi

    # Connectivity check
    if ! ping -c 1 -W 2 "$target" &>/dev/null; then
        # shellcheck disable=SC2016
        if ! timeout 3 bash -c 'echo "" > "/dev/tcp/$1/$2"' bash \
            "$target" "${HYDRA_PORT:-${HYDRA_DEFAULT_PORTS[$service]:-80}}" \
            >/dev/null 2>&1; then
            log_warn "Target $target does not appear reachable (ping failed, port probe failed)"
            log_warn "Check: Is the target up? Is your VPN connected?"
        fi
    fi

    # Resolve port
    local port="${HYDRA_PORT}"
    if [[ -z "$port" && -n "${HYDRA_DEFAULT_PORTS[$service]+_}" ]]; then
        port="${HYDRA_DEFAULT_PORTS[$service]}"
    fi

    local -a cmd=(hydra)
    local outfile
    outfile="${OUTPUT_DIR}/hydra_${service}_${target}_$(date +%s).txt"

    # ── Combo file mode (-C) ──
    if [[ -n "$HYDRA_COMBOLIST" ]]; then
        if [[ ! -f "$HYDRA_COMBOLIST" ]]; then
            log_error "Combo file not found: $HYDRA_COMBOLIST"
            exit 1
        fi
        cmd+=(-C "$HYDRA_COMBOLIST")
    else
        # Username(s)
        if [[ -n "$HYDRA_USER" ]]; then
            cmd+=(-l "$HYDRA_USER")
        elif [[ -n "$HYDRA_USERLIST" ]]; then
            if [[ ! -f "$HYDRA_USERLIST" ]]; then
                log_error "User list not found: $HYDRA_USERLIST"
                exit 1
            fi
            cmd+=(-L "$HYDRA_USERLIST")
        else
            log_warn "No username specified, using common defaults"
            local default_users="${OUTPUT_DIR}/hydra_default_users.txt"
            printf '%s\n' admin administrator root user test guest sa postgres mysql \
                ftp anonymous operator service backup > "$default_users"
            cmd+=(-L "$default_users")
        fi

        # Password(s)
        if [[ -n "$HYDRA_PASS" ]]; then
            cmd+=(-p "$HYDRA_PASS")
        elif [[ -n "$HYDRA_PASSLIST" ]]; then
            if [[ ! -f "$HYDRA_PASSLIST" ]]; then
                log_error "Password list not found: $HYDRA_PASSLIST"
                exit 1
            fi
            cmd+=(-P "$HYDRA_PASSLIST")
        else
            local wl_path
            wl_path=$(resolve_wordlist "$WORDLIST" 2>/dev/null || echo "$WORDLIST")
            if [[ -f "$wl_path" ]]; then
                cmd+=(-P "$wl_path")
                log_info "Using wordlist: $wl_path"
            else
                log_error "No password source specified and default wordlist not found"
                exit 1
            fi
        fi
    fi

    # Threading
    cmd+=(-t "$HYDRA_THREADS")

    # Stop on success
    if [[ "$HYDRA_STOP_ON_SUCCESS" -eq 1 ]]; then
        cmd+=(-f)
    fi

    # Output
    cmd+=(-o "$outfile")

    # Verbose
    cmd+=(-V)

    # Port
    if [[ -n "$port" ]]; then
        cmd+=(-s "$port")
    fi

    # Extra args (these are intentionally unquoted to allow splitting)
    if [[ -n "${HYDRA_EXTRA:-}" ]]; then
        # shellcheck disable=SC2206
        cmd+=($HYDRA_EXTRA)
    fi

    # Service-specific handling
    case "$service" in
        http-get|https-get)
            local path="${HYDRA_HTTP_PATH:-/}"
            cmd+=("$target" "$service" "$path")
            ;;
        http-post-form|https-post-form)
            if [[ -z "$HYDRA_HTTP_FORM" ]]; then
                log_error "HTTP form spec required. Use --http-form \"/path:params:fail_string\""
                log_info "Example: --http-form \"/login:user=^USER^&pass=^PASS^:F=Invalid\""
                exit 1
            fi
            cmd+=("$target" "$service" "$HYDRA_HTTP_FORM")
            ;;
        *)
            cmd+=("$target" "$service")
            ;;
    esac

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════${NC}"
    log_info "Hydra Online Brute Force"
    echo -e "${BOLD}═══════════════════════════════════════${NC}"
    log_info "Target: ${target}:${port:-default}"
    log_info "Service: ${service}"
    log_info "Threads: ${HYDRA_THREADS}"
    echo ""

    log_cmd "${cmd[*]}"
    echo ""

    local hydra_rc=0
    "${cmd[@]}" || hydra_rc=$?

    echo ""
    # Only claim success if the outfile contains at least one parseable cred line.
    # Hydra writes a header comment to -o even on failure, so `-s` alone is not proof.
    local hydra_hits=0
    if [[ -f "$outfile" && -s "$outfile" ]]; then
        hydra_hits=$(grep -cE 'login:\s*\S+\s+password:\s*\S+' "$outfile" 2>/dev/null || true)
        hydra_hits=${hydra_hits:-0}
    fi
    if (( hydra_hits > 0 )); then
        log_success "Valid credentials found:"
        grep -E 'login:\s*\S+\s+password:\s*\S+' "$outfile"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local hydra_user hydra_pass
            hydra_user=$(echo "$line" | grep -oP 'login:\s*\K\S+' || true)
            hydra_pass=$(echo "$line" | grep -oP 'password:\s*\K\S+' || true)
            if [[ -n "${hydra_user:-}" && -n "${hydra_pass:-}" ]]; then
                creds_log "crackr" "online" "$hydra_user" "$hydra_pass" "hydra:${service}"
            fi
        done < "$outfile"
        echo ""
        log_success "Results saved → $outfile"
        return 0
    fi

    # No creds parsed. Distinguish "ran fine, found nothing" from "hydra
    # failed to run" (unreachable target, bad service, tool error). Hydra
    # exits nonzero in the latter case, so propagate that instead of
    # masquerading as a clean "no credentials found".
    if (( hydra_rc != 0 )); then
        log_error "Hydra execution failed (rc=${hydra_rc}) — target/transport error, not a clean run"
        return "$hydra_rc"
    fi
    log_warn "No valid credentials found"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Main Cracking Logic ────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

crack() {
    local hash_file="$1"

    local sample_hash
    sample_hash=$(grep -v '^#' "$hash_file" 2>/dev/null | grep -v '^\s*$' | head -1 || true)

    if [[ -z "$sample_hash" ]]; then
        log_error "No hashes found in file"
        exit 1
    fi

    log_info "Sample hash: ${sample_hash:0:80}..."

    local hc_mode jtr_fmt desc
    if [[ -n "${FORCE_HASHCAT_MODE:-}" ]]; then
        hc_mode="$FORCE_HASHCAT_MODE"
        jtr_fmt="${FORCE_JTR_FORMAT:-unknown}"
        desc="User-specified (hashcat mode $hc_mode)"
    elif [[ -n "${FORCE_JTR_FORMAT:-}" ]]; then
        hc_mode="unknown"
        jtr_fmt="$FORCE_JTR_FORMAT"
        desc="User-specified (JTR format $jtr_fmt)"
    else
        local detected
        detected=$(identify_hash "$sample_hash")
        IFS='|' read -r hc_mode jtr_fmt desc <<< "$detected"
    fi

    # Reject fully unknown hashes rather than silently running with no format
    if [[ "$hc_mode" == "unknown" && ( "$jtr_fmt" == "unknown" || -z "$jtr_fmt" ) ]]; then
        log_error "Could not identify hash type for: ${sample_hash:0:64}"
        log_error "Specify manually: -m <hashcat_mode> (e.g. -m 1000 for NTLM)"
        log_error "                   -j <jtr_format>   (e.g. -j nt for NTLM)"
        log_error "See: hashcat --example-hashes | less   OR   john --list=formats"
        exit 1
    fi

    log_info "Hash type: ${BOLD}${desc}${NC}"
    log_info "Hashcat mode: ${hc_mode} | JTR format: ${jtr_fmt}"

    local selected_tool="$TOOL"
    if [[ "$selected_tool" == "auto" ]]; then
        if [[ -n "${EXTRACT_MODE:-}" || "$hc_mode" == "NA" ]]; then
            selected_tool="jtr"
        elif command -v hashcat &>/dev/null && [[ "$hc_mode" != "unknown" ]]; then
            # Verify hashcat can actually use a device before selecting it
            if hashcat -I &>/dev/null && ! hashcat -I 2>&1 | grep -qi "no devices\|no hardware"; then
                selected_tool="hashcat"
            else
                log_warn "Hashcat found but no usable device (no GPU/OpenCL backend)"
                if command -v john &>/dev/null; then
                    log_warn "Falling back to John the Ripper"
                    selected_tool="jtr"
                else
                    log_warn "Trying hashcat anyway (may fail — use -t jtr to force JTR)"
                    selected_tool="hashcat"
                fi
            fi
        elif command -v john &>/dev/null; then
            selected_tool="jtr"
        else
            log_error "Neither hashcat nor john found on PATH"
            exit 1
        fi
    fi

    # If user explicitly chose hashcat, warn if no device detected
    if [[ "$selected_tool" == "hashcat" ]]; then
        if ! hashcat -I &>/dev/null || hashcat -I 2>&1 | grep -qi "no devices\|no hardware"; then
            log_warn "Hashcat may not have a usable device — if it fails, re-run with -t jtr"
        fi
    fi

    log_info "Tool: ${BOLD}${selected_tool}${NC}"

    local hash_count
    hash_count=$(grep -cv '^\s*$' "$hash_file" 2>/dev/null || echo "?")
    log_info "Hashes: ${hash_count}"

    # ── Mask attack mode ──
    if [[ -n "${MASK_PATTERN:-}" ]]; then
        if [[ "$hc_mode" == "unknown" || "$hc_mode" == "NA" ]]; then
            log_error "Cannot run mask attack without hashcat mode. Use -m to specify."
            exit 1
        fi
        run_hashcat_mask "$hash_file" "$hc_mode" "$MASK_PATTERN"
        return
    fi

    # ── Hybrid attack mode ──
    if [[ -n "${HYBRID_APPEND:-}" || -n "${HYBRID_PREPEND:-}" ]]; then
        if [[ "$hc_mode" == "unknown" || "$hc_mode" == "NA" ]]; then
            log_error "Cannot run hybrid attack without hashcat mode. Use -m to specify."
            exit 1
        fi
        local wl_path
        wl_path=$(resolve_wordlist "$WORDLIST" 2>/dev/null || echo "$WORDLIST")
        if [[ -n "${HYBRID_APPEND:-}" ]]; then
            run_hashcat_hybrid "$hash_file" "$hc_mode" "$wl_path" "$HYBRID_APPEND" "6"
        else
            run_hashcat_hybrid "$hash_file" "$hc_mode" "$wl_path" "$HYBRID_PREPEND" "7"
        fi
        return
    fi

    # ── Quick mode ──
    if [[ "$QUICK_MODE" -eq 1 ]]; then
        run_quick_mode "$hash_file" "$hc_mode" "$jtr_fmt" "$selected_tool"
        return
    fi

    local wl_path
    wl_path=$(resolve_wordlist "$WORDLIST" 2>/dev/null || echo "$WORDLIST")

    local rule_path=""
    if [[ -n "${RULE:-}" ]]; then
        rule_path=$(resolve_rule "$RULE" "$selected_tool" 2>/dev/null || echo "$RULE")
    fi

    if [[ "$selected_tool" == "hashcat" ]]; then
        if [[ "$hc_mode" == "unknown" || "$hc_mode" == "NA" ]]; then
            log_error "Cannot determine hashcat mode. Use -m to specify, or use -t jtr"
            exit 1
        fi
        run_hashcat "$hash_file" "$wl_path" "$hc_mode" "${rule_path:-}"
    else
        run_jtr "$hash_file" "$wl_path" "$jtr_fmt" "${rule_path:-}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# ── Argument Parsing ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

SHOW_MODE=0
ORIGINAL_ARGS="$*"  # Save before argument parsing consumes them via shift

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        # ── Offline cracking ──
        -f|--file)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            INPUT_FILE="$2"; shift 2 ;;
        -H|--hash)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            SINGLE_HASH="$2"; shift 2 ;;
        -e|--extract)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            EXTRACT_MODE="$2"; shift 2 ;;
        -w|--wordlist)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            WORDLIST="$2"; shift 2 ;;
        -r|--rule)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            RULE="$2"; shift 2 ;;
        -t|--tool)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            TOOL="$2"; shift 2 ;;
        -m|--mode)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            FORCE_HASHCAT_MODE="$2"; shift 2 ;;
        -j|--jtr-format)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            FORCE_JTR_FORMAT="$2"; shift 2 ;;
        -q|--quick)
            QUICK_MODE=1; shift ;;

        # ── Mask / hybrid ──
        --mask)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            MASK_PATTERN="$2"; shift 2 ;;
        --hybrid-append)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYBRID_APPEND="$2"; shift 2 ;;
        --hybrid-prepend)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYBRID_PREPEND="$2"; shift 2 ;;

        # ── Unshadow ──
        --unshadow)
            if [[ $# -lt 3 ]]; then
                log_error "--unshadow requires two arguments: <passwd_file> <shadow_file>"
                exit 1
            fi
            UNSHADOW_PASSWD="$2"
            UNSHADOW_SHADOW="$3"
            shift 3 ;;

        # ── Hydra ──
        --hydra)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_MODE="$2"; shift 2 ;;
        --target)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_TARGET="$2"; shift 2 ;;
        --port)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_PORT="$2"; shift 2 ;;
        -u|--user)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_USER="$2"; shift 2 ;;
        -U|--userlist)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_USERLIST="$2"; shift 2 ;;
        -p|--pass)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_PASS="$2"; shift 2 ;;
        -P|--passlist)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_PASSLIST="$2"; shift 2 ;;
        -C|--combo)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_COMBOLIST="$2"; shift 2 ;;
        --http-path)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_HTTP_PATH="$2"; shift 2 ;;
        --http-form)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_HTTP_FORM="$2"; shift 2 ;;
        --hydra-threads)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_THREADS="$2"; shift 2 ;;
        --hydra-extra)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            HYDRA_EXTRA="$2"; shift 2 ;;
        --no-stop)
            HYDRA_STOP_ON_SUCCESS=0; shift ;;

        # ── CeWL ──
        --cewl)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            CEWL_URL="$2"; shift 2 ;;
        --cewl-depth)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            CEWL_DEPTH="$2"; shift 2 ;;
        --cewl-min)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            CEWL_MIN_LEN="$2"; shift 2 ;;
        --cewl-mutate)
            CEWL_MUTATE=1; shift ;;
        --cewl-output)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            CEWL_OUTPUT="$2"; shift 2 ;;

        # ── General ──
        -o|--output)
            [[ $# -lt 2 ]] && log_error "$1 requires an argument" && exit 1
            OUTPUT_DIR="$2"; shift 2 ;;
        -s|--show)
            SHOW_MODE=1; shift ;;
        -l|--list)
            list_resources; exit 0 ;;
        --no-color)
            disable_colors; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            log_error "Unknown option: $1"
            echo "Use -h for help"
            exit 1 ;;
    esac
done

if [[ "$TOOL" != "auto" && "$TOOL" != "hashcat" && "$TOOL" != "jtr" ]]; then
    log_error "Invalid tool: $TOOL (expected: auto, hashcat, or jtr)"
    exit 1
fi

if [[ -n "${FORCE_HASHCAT_MODE:-}" ]] && ! is_positive_integer "$FORCE_HASHCAT_MODE"; then
    log_error "Invalid hashcat mode: $FORCE_HASHCAT_MODE"
    exit 1
fi

if [[ -n "${HYDRA_MODE:-}" && -z "${HYDRA_DEFAULT_PORTS[$HYDRA_MODE]+_}" ]]; then
    log_error "Unsupported hydra service: $HYDRA_MODE"
    exit 1
fi

if [[ -n "${HYDRA_TARGET:-}" ]] && ! is_valid_hydra_target "$HYDRA_TARGET"; then
    log_error "Invalid Hydra target: $HYDRA_TARGET"
    exit 1
fi

if [[ -n "${HYDRA_PORT:-}" ]] && ! is_port_number "$HYDRA_PORT"; then
    log_error "Invalid port: $HYDRA_PORT"
    exit 1
fi

if ! is_positive_integer "$HYDRA_THREADS"; then
    log_error "Invalid hydra thread count: $HYDRA_THREADS"
    exit 1
fi

if ! is_positive_integer "$CEWL_DEPTH"; then
    log_error "Invalid CeWL depth: $CEWL_DEPTH"
    exit 1
fi

if ! is_positive_integer "$CEWL_MIN_LEN"; then
    log_error "Invalid CeWL minimum word length: $CEWL_MIN_LEN"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════
# ── Main Execution ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

banner

# Create output directory
mkdir -p "$OUTPUT_DIR" || { log_error "Cannot create output directory: $OUTPUT_DIR"; exit 1; }

# Initialize session log for OffSec reporting
LOG_FILE="${OUTPUT_DIR}/crackr_session_$(date +%Y%m%d_%H%M%S).log"
echo "# crackr v3 session log — $(date)" > "$LOG_FILE" || { log_error "Cannot write session log: $LOG_FILE"; exit 1; }
echo "# Command: $0 ${ORIGINAL_ARGS}" >> "$LOG_FILE" 2>/dev/null || true
echo "" >> "$LOG_FILE"

log_info "Output directory: $OUTPUT_DIR"
log_info "Session log: $LOG_FILE"

# ── Unshadow mode ──
if [[ -n "${UNSHADOW_PASSWD:-}" ]]; then
    run_unshadow "$UNSHADOW_PASSWD" "$UNSHADOW_SHADOW"
    # Fall through to crack the unshadowed file
fi

# ── CeWL wordlist generation (runs first so wordlist is available) ──
if [[ -n "${CEWL_URL:-}" ]]; then
    run_cewl "$CEWL_URL"

    # If no hash file or hydra mode, we're done
    if [[ -z "${INPUT_FILE:-}" && -z "${SINGLE_HASH:-}" && -z "${HYDRA_MODE:-}" ]]; then
        echo ""
        log_info "Done. Wordlist ready for use."
        log_info "Use it: crackr -f <hashfile> -w '${WORDLIST}'"
        exit 0
    fi
fi

# ── Hydra online brute force ──
if [[ -n "${HYDRA_MODE:-}" ]]; then
    run_hydra
    exit $?
fi

# ── Offline cracking ──

# Handle single hash
if [[ -n "${SINGLE_HASH:-}" ]]; then
    setup_single_hash "$SINGLE_HASH"
fi

# Validate input
if [[ -z "${INPUT_FILE:-}" ]]; then
    log_error "No input specified. Use -f <file>, -H <hash>, --hydra, --unshadow, or --cewl"
    exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    log_error "File not found: $INPUT_FILE"
    exit 1
fi

# Show mode
if [[ "$SHOW_MODE" -eq 1 ]]; then
    show_cracked "$INPUT_FILE"
    exit 0
fi

# Extract mode
if [[ -n "${EXTRACT_MODE:-}" ]]; then
    extract_hash "$EXTRACT_MODE" "$INPUT_FILE"
fi

# Crack
crack "$INPUT_FILE"

echo ""
log_info "Done. Results in: $OUTPUT_DIR"
log_info "Session log: $LOG_FILE"
echo -e "${CYAN}Tip: Use 'crackr --show -f <hashfile>' to view cracked passwords${NC}"
