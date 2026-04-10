#!/usr/bin/env bash
# =============================================================================
# tools_setup.sh — OffSec Tool Staging Installer
# Installs Kali-side tools (apt/pip/gem) and downloads precompiled Windows/
# Linux binaries into ~/tools/ for engagement-day serving via python3 -m http.server
#
# Usage: sudo ./tools_setup.sh
#        sudo ./tools_setup.sh --check     # verify without installing
# Re-runnable: skips anything already present, retries failures.
# =============================================================================

set -uo pipefail
# NOTE: -e intentionally omitted — we handle per-command errors manually
# so one failed download doesn't abort the whole run.

# ── Mode flags ────────────────────────────────────────────────────────────────
CHECK_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --check)    CHECK_ONLY=true ;;
        --no-color) NO_COLOR=1 ;;
        -h|--help)
            echo "Usage: sudo $0 [--check] [--no-color]"
            echo "  --check     Verify installed tools without downloading"
            echo "  --no-color  Disable colored output"
            exit 0
            ;;
    esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

USE_COLOR=true
if [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; then
    USE_COLOR=false
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

log_info()    { echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }
log_header()  {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"
}

# ── Root check (skip for --check) ────────────────────────────────────────────
if [[ "$CHECK_ONLY" == false ]] && [[ $EUID -ne 0 ]]; then
    log_error "Run with sudo: sudo $0"
    exit 1
fi
if [[ "$CHECK_ONLY" == true ]] && [[ $EUID -ne 0 ]]; then
    # For check mode, resolve real user without sudo
    REAL_USER="$USER"
    REAL_HOME="$HOME"
else
    REAL_USER="${SUDO_USER:-$USER}"
    REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
fi

TOOLS_DIR="${REAL_HOME}/tools"
WIN_DIR="${TOOLS_DIR}/windows"
LIN_DIR="${TOOLS_DIR}/linux"
LIGOLO_DIR="${TOOLS_DIR}/ligolo"

FAILED=()
SKIPPED=()
INSTALLED=()

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

# Resolve download URL from GitHub latest release.
# Uses || true so a grep no-match doesn't exit under pipefail.
gh_latest_url() {
    local repo="$1" pattern="$2"
    local result="" attempts=0
    while [[ -z "$result" && $attempts -lt 3 ]]; do
        result=$({ curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
            | grep -oP '"browser_download_url":\s*"\K[^"]+' \
            | grep -P "${pattern}" \
            | head -1; } || true)
        (( attempts++ ))
        [[ -z "$result" && $attempts -lt 3 ]] && sleep 2
    done
    echo "$result"
}

# Cleanup temp files on interrupt
trap 'rm -f /tmp/offsec_*.tar.gz /tmp/offsec_*.zip /tmp/offsec_*.gz 2>/dev/null; rm -rf /tmp/tmp.* 2>/dev/null' EXIT INT TERM

# Simple direct download — skip if dest already exists
download() {
    local url="$1"
    local dest="$2"
    local label="${3:-$(basename "$dest")}"

    if [[ -f "$dest" ]]; then
        log_warn "  SKIP (exists): ${label}"
        SKIPPED+=("$label")
        return 0
    fi
    if [[ -z "$url" ]]; then
        log_error "  FAIL (URL not resolved): ${label}"
        FAILED+=("$label")
        return 0
    fi
    log_info "  Downloading: ${label}"
    if curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url" 2>/dev/null; then
        log_success "  OK: ${label}"
        INSTALLED+=("$label")
    else
        log_error "  FAIL: ${label}"
        FAILED+=("$label")
        rm -f "$dest"
    fi
}

# Download a .tar.gz, extract named binary, place at dest
dl_targz() {
    local url="$1" dest="$2" binname="$3"
    local label="${4:-$(basename "$dest")}"
    if [[ -f "$dest" ]]; then
        log_warn "  SKIP (exists): ${label}"; SKIPPED+=("$label"); return 0
    fi
    if [[ -z "$url" ]]; then
        log_error "  FAIL (URL not resolved): ${label}"; FAILED+=("$label"); return 0
    fi
    log_info "  Downloading: ${label}"
    local tmp tmpdir
    tmp=$(mktemp /tmp/offsec_XXXXXX.tar.gz)
    tmpdir=$(mktemp -d)
    if curl -fsSL --retry 3 --retry-delay 2 -o "$tmp" "$url" 2>/dev/null; then
        tar -xzf "$tmp" -C "$tmpdir" 2>/dev/null || true
        local extracted
        extracted=$(find "$tmpdir" -name "$binname" -type f | head -1)
        if [[ -n "$extracted" ]]; then
            cp "$extracted" "$dest" && chmod +x "$dest"
            log_success "  OK: ${label}"
            INSTALLED+=("$label")
        else
            log_error "  FAIL: ${label} ('${binname}' not found in archive)"
            FAILED+=("$label")
        fi
    else
        log_error "  FAIL: ${label} (download error)"
        FAILED+=("$label")
    fi
    rm -rf "$tmp" "$tmpdir"
}

# Download a .zip, extract named binary, place at dest
dl_zip() {
    local url="$1" dest="$2" binname="$3"
    local label="${4:-$(basename "$dest")}"
    if [[ -f "$dest" ]]; then
        log_warn "  SKIP (exists): ${label}"; SKIPPED+=("$label"); return 0
    fi
    if [[ -z "$url" ]]; then
        log_error "  FAIL (URL not resolved): ${label}"; FAILED+=("$label"); return 0
    fi
    log_info "  Downloading: ${label}"
    local tmp tmpdir
    tmp=$(mktemp /tmp/offsec_XXXXXX.zip)
    tmpdir=$(mktemp -d)
    if curl -fsSL --retry 3 --retry-delay 2 -o "$tmp" "$url" 2>/dev/null; then
        unzip -q "$tmp" -d "$tmpdir" 2>/dev/null || true
        local extracted
        extracted=$(find "$tmpdir" -name "$binname" -type f | head -1)
        if [[ -n "$extracted" ]]; then
            cp "$extracted" "$dest"
            log_success "  OK: ${label}"
            INSTALLED+=("$label")
        else
            log_error "  FAIL: ${label} ('${binname}' not found in archive)"
            FAILED+=("$label")
        fi
    else
        log_error "  FAIL: ${label} (download error)"
        FAILED+=("$label")
    fi
    rm -rf "$tmp" "$tmpdir"
}

# Download a gzip-compressed single binary, decompress to dest
dl_gz() {
    local url="$1" dest="$2"
    local label="${3:-$(basename "$dest")}"
    if [[ -f "$dest" ]]; then
        log_warn "  SKIP (exists): ${label}"; SKIPPED+=("$label"); return 0
    fi
    if [[ -z "$url" ]]; then
        log_error "  FAIL (URL not resolved): ${label}"; FAILED+=("$label"); return 0
    fi
    log_info "  Downloading: ${label}"
    local tmp
    tmp=$(mktemp /tmp/offsec_XXXXXX.gz)
    if curl -fsSL --retry 3 --retry-delay 2 -o "$tmp" "$url" 2>/dev/null; then
        if gunzip -c "$tmp" > "$dest" 2>/dev/null; then
            chmod +x "$dest"
            rm -f "$tmp"
            log_success "  OK: ${label}"
            INSTALLED+=("$label")
        else
            log_error "  FAIL: ${label} (decompress failed)"
            FAILED+=("$label")
            rm -f "$tmp" "$dest"
        fi
    else
        log_error "  FAIL: ${label} (download error)"
        FAILED+=("$label")
        rm -f "$tmp"
    fi
}

apt_install() {
    local pkg="$1"
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        log_warn "  SKIP (installed): ${pkg}"; SKIPPED+=("apt:${pkg}"); return 0
    fi
    log_info "  apt install: ${pkg}"
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" &>/dev/null 2>&1; then
        log_success "  OK: ${pkg}"; INSTALLED+=("apt:${pkg}")
    else
        log_error "  FAIL: ${pkg}"; FAILED+=("apt:${pkg}")
    fi
}

pip_install() {
    local pkg="$1"
    local import_name="${2:-}"
    if [[ -z "$import_name" ]]; then
        import_name="${pkg//-/_}"; import_name="${import_name%%[>=<]*}"
    fi
    if python3 -c "import ${import_name}" &>/dev/null 2>&1; then
        log_warn "  SKIP (installed): ${pkg}"; SKIPPED+=("pip:${pkg}"); return 0
    fi
    log_info "  pip install: ${pkg}"
    if pip3 install -q "$pkg" --break-system-packages &>/dev/null 2>&1; then
        log_success "  OK: ${pkg}"; INSTALLED+=("pip:${pkg}")
    else
        log_error "  FAIL: ${pkg}"; FAILED+=("pip:${pkg}")
    fi
}

gem_install() {
    local pkg="$1"
    if gem list -i "^${pkg}$" &>/dev/null 2>&1; then
        log_warn "  SKIP (installed): ${pkg}"; SKIPPED+=("gem:${pkg}"); return 0
    fi
    log_info "  gem install: ${pkg}"
    if gem install -q "$pkg" &>/dev/null 2>&1; then
        log_success "  OK: ${pkg}"; INSTALLED+=("gem:${pkg}")
    else
        log_error "  FAIL: ${pkg}"; FAILED+=("gem:${pkg}")
    fi
}

# ── Check-mode helpers ───────────────────────────────────────────────────────
CHECK_PRESENT=()
CHECK_MISSING=()

# Map an apt package name to the primary binary it provides, so we can
# check usability via `command -v` rather than `dpkg -s`. This matters
# when a tool was installed from source / pip / cargo rather than apt.
_apt_pkg_binary() {
    case "$1" in
        snmp)                echo snmpwalk ;;
        ldap-utils)          echo ldapsearch ;;
        dnsutils)            echo dig ;;
        nfs-common)          echo showmount ;;
        netexec)             echo nxc ;;
        impacket-scripts)    echo impacket-GetNPUsers ;;
        netcat-traditional)  echo nc.traditional ;;
        python3-pip)         echo pip3 ;;
        ruby-full)           echo ruby ;;
        proxychains4)        echo proxychains4 ;;
        wordlists|seclists)  echo "" ;;   # data-only packages, no binary
        *)                   echo "$1" ;;
    esac
}

check_apt() {
    local pkg="$1"
    local bin
    bin="$(_apt_pkg_binary "$pkg")"
    if [[ -n "$bin" ]] && command -v "$bin" &>/dev/null; then
        log_success "  ✓ apt: ${pkg}"; CHECK_PRESENT+=("apt:${pkg}")
        return
    fi
    # Fall back to dpkg for data-only packages (wordlists, seclists)
    # or for tools whose binary name we don't know.
    if dpkg -s "$pkg" &>/dev/null; then
        log_success "  ✓ apt: ${pkg}"; CHECK_PRESENT+=("apt:${pkg}")
    else
        log_error "  ✗ apt: ${pkg}"; CHECK_MISSING+=("apt:${pkg}")
    fi
}
check_pip() {
    local pkg="$1" import_name="${2:-}"
    [[ -z "$import_name" ]] && { import_name="${pkg//-/_}"; import_name="${import_name%%[>=<]*}"; }
    if python3 -c "import ${import_name}" &>/dev/null 2>&1; then
        log_success "  ✓ pip: ${pkg}"; CHECK_PRESENT+=("pip:${pkg}")
    else
        log_error "  ✗ pip: ${pkg}"; CHECK_MISSING+=("pip:${pkg}")
    fi
}
check_gem() {
    local pkg="$1"
    if gem list -i "^${pkg}$" &>/dev/null 2>&1; then
        log_success "  ✓ gem: ${pkg}"; CHECK_PRESENT+=("gem:${pkg}")
    else
        log_error "  ✗ gem: ${pkg}"; CHECK_MISSING+=("gem:${pkg}")
    fi
}
check_file() {
    local path="$1" label="${2:-$(basename "$1")}"
    if [[ -f "$path" ]]; then
        log_success "  ✓ ${label}"; CHECK_PRESENT+=("$label")
    else
        log_error "  ✗ ${label}"; CHECK_MISSING+=("$label")
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$CHECK_ONLY" == true ]]; then
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  OffSec Tool Preflight Check${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"

    log_header "apt Packages"
    for pkg in \
        rustscan nmap gobuster feroxbuster ffuf nikto whatweb \
        smbclient smbmap onesixtyone snmp enum4linux \
        ldap-utils dnsutils rpcbind nfs-common \
        netexec responder impacket-scripts bloodhound \
        john hashcat wordlists seclists cewl hydra \
        rlwrap socat netcat-traditional curl wget python3-pip ruby-full unzip \
        sqlmap proxychains4 ncat chisel; do
        check_apt "$pkg"
    done

    log_header "pip Packages"
    check_pip "certipy-ad"    "certipy"
    check_pip "bloodhound"    "bloodhound"
    check_pip "impacket"      "impacket"
    check_pip "enum4linux-ng" "enum4linux_ng"

    log_header "gem Packages"
    check_gem "evil-winrm"

    log_header "Downloaded Binaries"
    check_file "${WIN_DIR}/SigmaPotato.exe"
    check_file "${WIN_DIR}/GodPotato-NET4.exe"
    check_file "${WIN_DIR}/PrintSpoofer64.exe"
    check_file "${WIN_DIR}/JuicyPotato.exe"
    check_file "${WIN_DIR}/winPEASx64.exe"
    check_file "${WIN_DIR}/PowerUp.ps1"
    check_file "${WIN_DIR}/PowerView.ps1"
    check_file "${WIN_DIR}/Rubeus.exe"
    check_file "${WIN_DIR}/SharpHound.exe"
    check_file "${WIN_DIR}/mimikatz.exe"
    check_file "${LIN_DIR}/linpeas.sh"
    check_file "${LIN_DIR}/pspy64"
    check_file "${LIGOLO_DIR}/proxy"      "ligolo proxy"
    check_file "${LIGOLO_DIR}/agent"      "ligolo agent (linux)"
    check_file "${LIGOLO_DIR}/agent.exe"  "ligolo agent (windows)"
    check_file "${TOOLS_DIR}/chisel"      "chisel (linux)"
    check_file "${WIN_DIR}/chisel.exe"    "chisel (windows)"
    check_file "${TOOLS_DIR}/penelope.py"

    # ── Summary ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}  PREFLIGHT SUMMARY${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"
    echo -e "\n${GREEN}✓ Present: ${#CHECK_PRESENT[@]}${NC}"
    if (( ${#CHECK_MISSING[@]} > 0 )); then
        echo -e "${RED}✗ Missing: ${#CHECK_MISSING[@]}${NC}"
        for item in "${CHECK_MISSING[@]}"; do printf "    %s\n" "$item"; done
        echo -e "\n${YELLOW}Run without --check to install missing tools.${NC}"
        exit 1
    else
        echo -e "\n${GREEN}${BOLD}All tools present. Ready for engagement day.${NC}"
    fi
    exit 0
fi

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
╔══════════════════════════════════════════╗
║     OffSec Tool Staging Installer          ║
║     ~/tools/ · apt · pip · gem           ║
╚══════════════════════════════════════════╝
BANNER
echo -e "${NC}"

log_info "Real user: ${REAL_USER}  |  Home: ${REAL_HOME}"

# ── Directories ───────────────────────────────────────────────────────────────
log_info "Creating directory structure..."
mkdir -p "$WIN_DIR" "$LIN_DIR" "$LIGOLO_DIR"
log_success "Directories ready under: ${TOOLS_DIR}/"

# ── 1. apt ────────────────────────────────────────────────────────────────────
log_header "1 · apt Packages"
apt-get update -qq &>/dev/null

APT_PACKAGES=(
    rustscan nmap gobuster feroxbuster ffuf nikto whatweb
    smbclient smbmap onesixtyone snmp enum4linux
    ldap-utils dnsutils rpcbind nfs-common
    netexec responder impacket-scripts bloodhound
    john hashcat wordlists seclists cewl hydra
    rlwrap socat netcat-traditional curl wget python3-pip ruby-full unzip
    sqlmap proxychains4 ncat chisel
)

for pkg in "${APT_PACKAGES[@]}"; do
    apt_install "$pkg"
done

# ── 2. pip ────────────────────────────────────────────────────────────────────
log_header "2 · pip Packages"
pip_install "certipy-ad"    "certipy"
pip_install "bloodhound"    "bloodhound"
pip_install "impacket"      "impacket"
pip_install "enum4linux-ng" "enum4linux_ng"

# ── 3. gem ────────────────────────────────────────────────────────────────────
log_header "3 · gem Packages"
gem_install "evil-winrm"

# ── 4. Potato variants ────────────────────────────────────────────────────────
log_header "4 · Windows — Potato Variants (SeImpersonate → SYSTEM)"

# SigmaPotato — Win8-11, Server 2012-2022, .NET reflection support
SP_BASE="https://github.com/tylerdotrar/SigmaPotato/releases/latest/download"
download "${SP_BASE}/SigmaPotato.exe"     "${WIN_DIR}/SigmaPotato.exe"
download "${SP_BASE}/SigmaPotatoCore.exe" "${WIN_DIR}/SigmaPotatoCore.exe" "SigmaPotatoCore.exe (NET2/PS Core)"

# GodPotato — check .NET version on target: reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP"
GP_BASE="https://github.com/BeichenDream/GodPotato/releases/download/V1.20"
download "${GP_BASE}/GodPotato-NET2.exe"  "${WIN_DIR}/GodPotato-NET2.exe"
download "${GP_BASE}/GodPotato-NET35.exe" "${WIN_DIR}/GodPotato-NET35.exe"
download "${GP_BASE}/GodPotato-NET4.exe"  "${WIN_DIR}/GodPotato-NET4.exe"

# PrintSpoofer — both architectures
PS_BASE="https://github.com/itm4n/PrintSpoofer/releases/latest/download"
download "${PS_BASE}/PrintSpoofer32.exe" "${WIN_DIR}/PrintSpoofer32.exe"
download "${PS_BASE}/PrintSpoofer64.exe" "${WIN_DIR}/PrintSpoofer64.exe"

# JuicyPotato — legacy (Server 2008/2012/2016, Win7/8/10 pre-1809)
JP_URL=$(gh_latest_url "ohpe/juicy-potato" "JuicyPotato\.exe$")
download "$JP_URL" "${WIN_DIR}/JuicyPotato.exe"

# ── 5. Windows enumeration ────────────────────────────────────────────────────
log_header "5 · Windows — Enumeration"

# winPEAS — repo moved to peass-ng/PEASS-ng
WPEAS_X64=$(gh_latest_url "peass-ng/PEASS-ng" "winPEASx64\.exe$")
WPEAS_ANY=$(gh_latest_url "peass-ng/PEASS-ng" "winPEASany\.exe$")
WPEAS_BAT=$(gh_latest_url "peass-ng/PEASS-ng" "winPEAS\.bat$")
download "$WPEAS_X64" "${WIN_DIR}/winPEASx64.exe"
download "$WPEAS_ANY" "${WIN_DIR}/winPEASany.exe" "winPEASany.exe (no .NET fallback)"
download "$WPEAS_BAT" "${WIN_DIR}/winPEAS.bat"    "winPEAS.bat (no .NET at all)"

download \
    "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" \
    "${WIN_DIR}/PowerUp.ps1"

download \
    "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" \
    "${WIN_DIR}/PowerView.ps1"

# ── 6. AD tooling ─────────────────────────────────────────────────────────────
log_header "6 · Windows — AD Tooling"

# GhostPack tools (Rubeus, Seatbelt, Certify) — GhostPack publishes NO precompiled
# releases. Using r3motecontrol/Ghostpack-CompiledBinaries (community maintained).
GHOSTPACK="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master"
download "${GHOSTPACK}/Rubeus.exe"  "${WIN_DIR}/Rubeus.exe"
download "${GHOSTPACK}/Seatbelt.exe" "${WIN_DIR}/Seatbelt.exe"
download "${GHOSTPACK}/Certify.exe" "${WIN_DIR}/Certify.exe" "Certify.exe (AD CS attacks)"

# SharpHound — ships as zip (no standalone .exe asset); extract exe from inside
# Non-debug zip excludes "%2Bdebug" in name; use grep -v debug to filter
SH_ZIP_URL=$({ curl -fsSL "https://api.github.com/repos/BloodHoundAD/SharpHound/releases/latest" 2>/dev/null \
    | grep -oP '"browser_download_url":\s*"\K[^"]+' \
    | grep -i "SharpHound" | grep "\.zip" | grep -v "debug" \
    | head -1; } || true)
dl_zip "$SH_ZIP_URL" "${WIN_DIR}/SharpHound.exe" "SharpHound.exe" "SharpHound.exe"
# ps1 lives in the BloodHound main repo collectors directory
download \
    "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1" \
    "${WIN_DIR}/SharpHound.ps1" "SharpHound.ps1"

# Mimikatz — ships as a zip with x64/x86 subdirectories
MK_ZIP_URL=$(gh_latest_url "gentilkiwi/mimikatz" "mimikatz_trunk\.zip$")
if [[ -f "${WIN_DIR}/mimikatz.exe" ]]; then
    log_warn "  SKIP (exists): mimikatz.exe"; SKIPPED+=("mimikatz.exe")
elif [[ -n "$MK_ZIP_URL" ]]; then
    log_info "  Downloading: mimikatz (zip)"
    tmp_zip=$(mktemp /tmp/offsec_mk_XXXXXX.zip)
    tmp_dir=$(mktemp -d)
    if curl -fsSL --retry 3 -o "$tmp_zip" "$MK_ZIP_URL" 2>/dev/null; then
        unzip -q "$tmp_zip" -d "$tmp_dir" 2>/dev/null || true
        mk_bin=$(find "$tmp_dir" -name "mimikatz.exe" -path "*/x64/*" | head -1)
        mk_lib=$(find "$tmp_dir" -name "mimilib.dll"  -path "*/x64/*" | head -1)
        if [[ -n "$mk_bin" ]]; then
            cp "$mk_bin" "${WIN_DIR}/mimikatz.exe"
            [[ -n "$mk_lib" ]] && cp "$mk_lib" "${WIN_DIR}/mimilib.dll"
            log_success "  OK: mimikatz.exe + mimilib.dll (x64)"
            INSTALLED+=("mimikatz.exe")
        else
            log_error "  FAIL: mimikatz.exe not found in zip"; FAILED+=("mimikatz.exe")
        fi
    else
        log_error "  FAIL: mimikatz download"; FAILED+=("mimikatz.exe")
    fi
    rm -rf "$tmp_zip" "$tmp_dir"
else
    log_error "  FAIL: could not resolve mimikatz URL"; FAILED+=("mimikatz.exe")
fi

# ── 7. Linux binaries ─────────────────────────────────────────────────────────
log_header "7 · Linux Binaries — Target Enumeration"

LP_URL=$(gh_latest_url "peass-ng/PEASS-ng" "linpeas\.sh$")
download "$LP_URL" "${LIN_DIR}/linpeas.sh"
[[ -f "${LIN_DIR}/linpeas.sh" ]] && chmod +x "${LIN_DIR}/linpeas.sh"

PSPY_URL=$(gh_latest_url "DominicBreuker/pspy" "pspy64$")
download "$PSPY_URL" "${LIN_DIR}/pspy64"
[[ -f "${LIN_DIR}/pspy64" ]] && chmod +x "${LIN_DIR}/pspy64"

# ── 8. Ligolo-ng ──────────────────────────────────────────────────────────────
log_header "8 · Ligolo-ng (Tunneling)"

# v0.8+ releases use versioned tar.gz/zip archives — no bare binary assets
LIGOLO_PROXY_URL=$(gh_latest_url "nicocha30/ligolo-ng" "ligolo-ng_proxy_.*_linux_amd64\.tar\.gz$")
dl_targz "$LIGOLO_PROXY_URL" "${LIGOLO_DIR}/proxy" "proxy" "ligolo-ng proxy (linux)"

LIGOLO_AGENT_LIN_URL=$(gh_latest_url "nicocha30/ligolo-ng" "ligolo-ng_agent_.*_linux_amd64\.tar\.gz$")
dl_targz "$LIGOLO_AGENT_LIN_URL" "${LIGOLO_DIR}/agent" "agent" "ligolo-ng agent (linux)"

LIGOLO_AGENT_WIN_URL=$(gh_latest_url "nicocha30/ligolo-ng" "ligolo-ng_agent_.*_windows_amd64\.zip$")
dl_zip "$LIGOLO_AGENT_WIN_URL" "${LIGOLO_DIR}/agent.exe" "agent.exe" "ligolo-ng agent (windows)"

# ── 9. Chisel ─────────────────────────────────────────────────────────────────
log_header "9 · Chisel (HTTP Tunneling — Fallback)"

CHISEL_LIN_URL=$(gh_latest_url "jpillora/chisel" "chisel_.*_linux_amd64\.gz$")
dl_gz "$CHISEL_LIN_URL" "${TOOLS_DIR}/chisel" "chisel (linux)"

CHISEL_WIN_URL=$(gh_latest_url "jpillora/chisel" "chisel_.*_windows_amd64\.zip$")
dl_zip "$CHISEL_WIN_URL" "${WIN_DIR}/chisel.exe" "chisel.exe" "chisel.exe (windows)"

# ── 10. Penelope ──────────────────────────────────────────────────────────────
log_header "10 · Penelope (Reverse Shell Handler)"

if [[ -f "${TOOLS_DIR}/penelope.py" ]]; then
    log_warn "  SKIP (exists): penelope.py"; SKIPPED+=("penelope.py")
else
    download \
        "https://raw.githubusercontent.com/brightio/penelope/main/penelope.py" \
        "${TOOLS_DIR}/penelope.py" \
        "penelope.py"
    [[ -f "${TOOLS_DIR}/penelope.py" ]] && chmod +x "${TOOLS_DIR}/penelope.py"
fi

if [[ -f "${TOOLS_DIR}/penelope.py" ]] && [[ ! -e /usr/local/bin/penelope ]]; then
    ln -sf "${TOOLS_DIR}/penelope.py" /usr/local/bin/penelope
    log_success "  Symlinked: penelope → /usr/local/bin/penelope"
fi

# ── Fix ownership ─────────────────────────────────────────────────────────────
chown -R "${REAL_USER}:${REAL_USER}" "$TOOLS_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  INSTALL SUMMARY${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"

echo -e "\n${GREEN}✓ Installed (${#INSTALLED[@]}):${NC}"
for item in "${INSTALLED[@]}"; do printf "    %s\n" "$item"; done

if (( ${#SKIPPED[@]} > 0 )); then
    echo -e "\n${YELLOW}⊘ Already present — skipped (${#SKIPPED[@]}):${NC}"
    for item in "${SKIPPED[@]}"; do printf "    %s\n" "$item"; done
fi

if (( ${#FAILED[@]} > 0 )); then
    echo -e "\n${RED}✗ Failed (${#FAILED[@]}) — re-run to retry:${NC}"
    for item in "${FAILED[@]}"; do printf "    %s\n" "$item"; done
fi

echo -e "\n${BOLD}Directory layout:${NC}"
echo -e "  Windows  → ${WIN_DIR}/"
echo -e "  Linux    → ${LIN_DIR}/"
echo -e "  Ligolo   → ${LIGOLO_DIR}/"
echo -e "  chisel   → ${TOOLS_DIR}/chisel"
echo -e "  penelope → ${TOOLS_DIR}/penelope.py"

echo -e "\n${BOLD}engagement-day file server:${NC}"
echo -e "  cd ${WIN_DIR} && python3 -m http.server 80"
echo ""

if (( ${#FAILED[@]} == 0 )); then
    echo -e "${GREEN}${BOLD}All done. No failures.${NC}"
else
    echo -e "${YELLOW}${BOLD}Done with ${#FAILED[@]} failure(s). Re-run to retry.${NC}"
fi
echo ""
