#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2028,SC2030,SC2031,SC2034
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT

PASS=0
FAIL=0
PASS_FILE="$TEST_TMP/pass.count"
FAIL_FILE="$TEST_TMP/fail.count"
printf '0' > "$PASS_FILE"
printf '0' > "$FAIL_FILE"

ok() {
    printf '[PASS] %s\n' "$1"
    local n
    n=$(cat "$PASS_FILE")
    printf '%s' "$((n + 1))" > "$PASS_FILE"
}

fail() {
    printf '[FAIL] %s\n' "$1" >&2
    local n
    n=$(cat "$FAIL_FILE")
    printf '%s' "$((n + 1))" > "$FAIL_FILE"
}

source_script() {
    local script="$1"
    local rc
    set +e
    # shellcheck source=/dev/null
    source "$script"
    rc=$?
    if (( rc != 0 )); then
        fail "source $(basename "$script") in OffSec_LIB_ONLY mode"
        exit 1
    fi
}

assert_contains() {
    local file="$1" pattern="$2" name="$3"
    if grep -Eq "$pattern" "$file" 2>/dev/null; then
        ok "$name"
    else
        fail "$name"
        printf '  missing pattern: %s\n  file: %s\n' "$pattern" "$file" >&2
    fi
}

assert_not_contains() {
    local file="$1" pattern="$2" name="$3"
    if grep -Eq "$pattern" "$file" 2>/dev/null; then
        fail "$name"
        printf '  unexpected pattern: %s\n  file: %s\n' "$pattern" "$file" >&2
    else
        ok "$name"
    fi
}

test_recon_rules() (
    export OffSec_LIB_ONLY=true
    export KALI_IP=10.10.14.2
    source_script "$ROOT_DIR/recon.sh"

    local ip="10.10.10.5"
    local td="$TEST_TMP/recon/$ip"
    mkdir -p "$td/scans" "$td/loot" \
        "$td/tcp/smtp" "$td/tcp/smb" "$td/tcp/http/port_80" "$td/tcp/http/port_5985" \
        "$td/tcp/ftp" "$td/tcp/pop3" "$td/tcp/imap" "$td/tcp/rpc" "$td/tcp/dns" \
        "$td/tcp/mysql" "$td/tcp/postgres" "$td/tcp/redis" "$td/tcp/ldap" "$td/tcp/ssh" \
        "$td/udp/snmp"

    cat > "$td/scans/nmap_tcp.nmap" <<'EOF'
80/tcp open http Apache httpd
445/tcp open microsoft-ds
5985/tcp open http Microsoft HTTPAPI httpd 2.0
110/tcp open pop3 Dovecot pop3d
143/tcp open imap Dovecot imapd
873/tcp open rsync
2375/tcp open docker
5900/tcp open vnc
3128/tcp open squid-http
69/tcp open tftp
513/tcp open login
3306/tcp open mysql
5432/tcp open postgresql
88/tcp open kerberos-sec
389/tcp open ldap
3389/tcp open ms-wbt-server
1433/tcp open ms-sql-s
EOF
    cat > "$td/scans/nmap_udp.nmap" <<'EOF'
69/udp open tftp
161/udp open snmp
EOF
    cat > "$td/progress.log" <<'EOF'
2026-01-01 00:00:00 | DONE | http_80 | proto=http
2026-01-01 00:00:00 | DONE | pop3_110 |
2026-01-01 00:00:00 | DONE | imap_143 |
2026-01-01 00:00:00 | DONE | smb |
EOF

    cat > "$td/tcp/smtp/vrfy_users.txt" <<'EOF'
VALID: alice — 250 Alice
VALID: bob — 250 Bob
EOF
    cat > "$td/tcp/smb/smbmap_null.txt" <<'EOF'
IPC$ NO ACCESS
EOF
    : > "$td/tcp/smb/smbmap_guest.txt"
    echo "Microsoft-IIS/10.0" > "$td/tcp/http/port_80/whatweb.txt"
    echo "Allow: GET, POST, OPTIONS, TRACE, PUT, PROPFIND" > "$td/tcp/http/port_80/http_methods.txt"
    echo "Allow: GET, POST" > "$td/tcp/http/port_5985/http_methods.txt"
    echo "anonymous ok" > "$td/tcp/ftp/ANONYMOUS_ACCESS.txt"
    echo "public" > "$td/udp/snmp/valid_community_strings.txt"
    echo "mysql -uroot -pSecret123" > "$td/udp/snmp/process_args.txt"
    echo 'STRING: "charlie"' > "$td/udp/snmp/windows_users.txt"
    echo "/home *(rw,sync)" > "$td/tcp/rpc/nfs_exports.txt"
    echo "redis_version:6.0.0" > "$td/tcp/redis/info_noauth.txt"
    printf 'namingContexts: DC=corp,DC=local\n' > "$td/tcp/ldap/naming_contexts.txt"
    printf 'dn: DC=corp,DC=local\n' > "$td/tcp/ldap/ldap_full_dump.txt"
    echo "Version" > "$td/tcp/mysql/root_nopass.txt"
    echo "SELECT 1" > "$td/tcp/postgres/login_postgres_empty.txt"
    cat > "$td/tcp/dns/zone_transfer_corp.local.txt" <<'EOF'
corp.local. 3600 IN A 10.10.10.5
XFR size: 1 records
EOF
    echo "SSH Version: OpenSSH_6.6" > "$td/tcp/ssh/version_info.txt"

    generate_quick_wins "$ip" "$td"
    generate_next_steps "$ip" "$td"

    local qw="$td/loot/quick_wins.txt"
    local ns="$td/loot/next_steps.txt"

    assert_contains "$qw" "SMTP VRFY valid usernames" "recon quick_wins includes SMTP users"
    assert_not_contains "$qw" "POP3 detected|IMAP detected|SMB detected" "recon quick_wins excludes plain service detections"
    assert_contains "$ns" "SMTP valid users found" "recon next_steps includes SMTP user rule"
    assert_contains "$ns" "POP3 detected" "recon next_steps includes POP3 rule"
    assert_contains "$ns" "IMAP detected" "recon next_steps includes IMAP rule"
    assert_contains "$ns" "Real web target identified" "recon next_steps includes real web rule"
    assert_not_contains "$ns" "webenum\.sh --url http://$ip:5985" "recon does not treat WinRM HTTPAPI as web app"
    assert_not_contains "$ns" "smbclient -L //$ip -N" "recon does not emit anonymous SMB commands without READ/WRITE"
    assert_contains "$ns" "rsync detected" "recon next_steps includes rsync rule"
    assert_contains "$ns" "Docker API detected" "recon next_steps includes Docker API rule"
    assert_contains "$ns" "VNC detected" "recon next_steps includes VNC rule"
    assert_contains "$ns" "TFTP detected" "recon next_steps includes TFTP rule"
    assert_contains "$ns" "Legacy r-service detected" "recon next_steps includes r-service rule"

    echo "READ ONLY" > "$td/tcp/smb/smbmap_null.txt"
    generate_quick_wins "$ip" "$td"
    generate_next_steps "$ip" "$td"
    assert_contains "$td/loot/next_steps.txt" "Readable SMB share found" "recon emits anonymous SMB only when READ/WRITE appears"
)

test_webenum_rules() (
    export OffSec_LIB_ONLY=true
    source_script "$ROOT_DIR/webenum.sh"

    local wd="$TEST_TMP/web"
    local url="http://10.10.10.5"
    mkdir -p "$wd/fingerprint/js" "$wd/content" "$wd/content/recursive" "$wd/vhosts" "$wd/params" "$wd/loot"
    echo "Allow: GET, POST, OPTIONS, PUT, PROPFIND" > "$wd/fingerprint/http_methods.txt"
    cat > "$wd/fingerprint/sensitive_paths.txt" <<'EOF'
http://10.10.10.5/.env | 200 |
http://10.10.10.5/upload | 200 |
EOF
    cat > "$wd/fingerprint/homepage_source.html" <<'EOF'
Index of /
APP_KEY=base64:abc
DB_PASSWORD=secret
Werkzeug debugger
<form method="post"><input type="password" name="password"></form>
EOF
    echo "Apache WordPress Grafana" > "$wd/fingerprint/whatweb.txt"
    : > "$wd/fingerprint/headers.txt"
    echo "http://10.10.10.5/static/app.js" > "$wd/fingerprint/js_urls.txt"
    echo "/api/users" > "$wd/fingerprint/js_endpoints.txt"
    echo "app.js:1: api_key='abc123'" > "$wd/fingerprint/js_secret_hints.txt"
    echo "http://10.10.10.5/login | 200 |" > "$wd/content/dirs_medium.txt"
    cat > "$wd/content/files_medium.txt" <<'EOF'
http://10.10.10.5/config.bak | 200 |
http://10.10.10.5/api/users | 200 |
EOF
    cat > "$wd/params/params.txt" <<'EOF'
http://10.10.10.5/view?file=testvalue
http://10.10.10.5/ping?host=testvalue
http://10.10.10.5/item?id=testvalue
EOF

    generate_next_steps "$url" "$wd"
    local ns="$wd/loot/next_steps.txt"
    assert_contains "$ns" "WebDAV or upload-capable methods found" "webenum detects WebDAV/PUT methods"
    assert_contains "$ns" "Laravel/.env indicators found" "webenum detects Laravel/env indicators"
    assert_contains "$ns" "Debug framework indicators found" "webenum detects debug framework indicators"
    assert_contains "$ns" "Directory listing found" "webenum detects directory listing"
    assert_contains "$ns" "Login page discovered" "webenum detects login page"
    assert_contains "$ns" "HTTP POST login form evidence found" "webenum detects POST login form evidence"
    assert_contains "$ns" "Sensitive file discovered" "webenum detects sensitive file"
    assert_contains "$ns" "API endpoint discovered" "webenum detects API endpoint evidence"
    assert_contains "$ns" "JavaScript endpoints found" "webenum detects JS endpoint evidence"
    assert_contains "$ns" "JavaScript secret-looking strings found" "webenum detects JS secret hints"
    assert_contains "$ns" "wpscan --url" "webenum default next steps include WPScan for WordPress evidence"
    assert_contains "$ns" "nuclei -u" "webenum default next steps include nuclei for Grafana evidence"
    assert_contains "$ns" "Traversal/LFI-style parameter found" "webenum detects LFI-style parameter"
    assert_contains "$ns" "Command-injection-style parameter found" "webenum detects command injection-style parameter"
    assert_contains "$ns" "SQLi-style parameter found" "webenum detects SQLi-style parameter"
    assert_not_contains "$ns" "s""qlmap" "webenum next steps avoid restricted SQL automation"
)

test_pivotr_rules() (
    export OffSec_LIB_ONLY=true
    export TOOLKIT_ROOT="$TEST_TMP/pivot_offsec"
    source_script "$ROOT_DIR/pivotr.sh"

    mode_ssh --type dynamic --pivot-ip 10.10.10.5 --pivot-user alice --pivot-port 22 --kali-ip 10.10.14.2 --socks-port 9999 --subnet 172.16.1.0/24 >/dev/null
    local ns="$TOOLKIT_ROOT/pivots/next_steps.txt"
    assert_contains "$ns" "SSH dynamic SOCKS requested" "pivotr emits SSH dynamic next steps"
    assert_contains "$ns" "sshuttle -r alice@10.10.10.5:22 172.16.1.0/24" "pivotr emits sshuttle follow-up when subnet exists"

    mode_chisel --type forward --kali-ip 10.10.14.2 --port 8080 --target-ip 172.16.1.10 --target-port 445 --local-port 1445 >/dev/null
    assert_contains "$ns" "Chisel reverse port forward requested" "pivotr emits chisel forward next steps"
    assert_contains "$ns" "chisel client 10.10.14.2:8080 R:1445:172.16.1.10:445" "pivotr emits chisel client command"
)

test_adr_rules() (
    export OffSec_LIB_ONLY=true
    source_script "$ROOT_DIR/adr.sh"

    OUTDIR="$TEST_TMP/adr"
    DOMAIN="corp.local"
    AD_USER="alice"
    PASS="Password1"
    AUTH_TYPE="password"
    DC_IP="10.10.10.10"
    LM_NT_HASH="aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
    NXC_AUTH=(-u "$AD_USER" -p "$PASS" -d "$DOMAIN")
    mkdir -p "$OUTDIR/users" "$OUTDIR/hashes" "$OUTDIR/computers" "$OUTDIR/sessions" "$OUTDIR/bloodhound" "$OUTDIR/shares"
    {
        echo "# AD Attack Commands — ${DOMAIN}"
        echo ""
    } > "$OUTDIR/attack_commands.txt"
    echo "[+] corp.local\\alice:Password1" > "$OUTDIR/domain_context.txt"
    echo "ADMIN_ON_DC=YES" > "$OUTDIR/summary_notes.txt"
    echo "SMB_SIGNING_DISABLED=YES" >> "$OUTDIR/summary_notes.txt"
    echo "PRIV_SESSIONS=YES" >> "$OUTDIR/summary_notes.txt"
    echo "alice" > "$OUTDIR/users/all_users.txt"
    echo '$krb5asrep$23$alice@CORP.LOCAL:test' > "$OUTDIR/hashes/asreproast.txt"
    echo '$krb5tgs$23$*svc$CORP.LOCAL$corp.local/svc*:test' > "$OUTDIR/hashes/kerberoast.txt"
    echo "DC01 corp.local Windows Server" > "$OUTDIR/computers/nxc_computers.txt"
    echo "signing:False" > "$OUTDIR/smb_no_signing.txt"
    echo "Administrator" > "$OUTDIR/sessions/smb_sessions.txt"
    echo "Groups.xml" > "$OUTDIR/shares/sysvol_interesting.txt"
    printf 'zip' > "$OUTDIR/bloodhound/bh.zip"

    generate_ad_2025_next_steps
    local ns="$OUTDIR/next_steps.txt"
    assert_contains "$ns" "ON-HOST AD ENUMERATION" "adr emits PowerView/SharpHound next steps"
    assert_contains "$ns" "AS-REP ROAST FOLLOW-UP" "adr emits AS-REP follow-up"
    assert_contains "$ns" "KERBEROAST FOLLOW-UP" "adr emits Kerberoast follow-up"
    assert_contains "$ns" "LATERAL MOVEMENT AUTH CHECKS" "adr emits lateral movement auth checks"
    assert_contains "$ns" "NTLM RELAY FOLLOW-UP" "adr emits NTLM relay follow-up"
    assert_contains "$ns" "DOMAIN ADMIN PATH" "adr emits DA path next steps"
    assert_contains "$ns" "BLOODHOUND 2025-2026 REVIEW QUEUE" "adr emits BloodHound review queue"
)

test_crackr_rules() (
    export OffSec_LIB_ONLY=true
    source_script "$ROOT_DIR/crackr.sh"

    OUTPUT_DIR="$TEST_TMP/crackr_ssh"
    mkdir -p "$OUTPUT_DIR"
    echo "jane:KeyPass123" > "$OUTPUT_DIR/hashcat_cracked_1.txt"
    CRACKED_HC_MODE=""
    CRACKED_HASH_TYPE="SSH private key"
    EXTRACT_CONTEXT="ssh"
    write_crack_next_steps 1 "$TEST_TMP/creds.txt"
    assert_contains "$OUTPUT_DIR/next_steps.txt" "SSH PRIVATE KEY PASSPHRASE CRACKED" "crackr emits SSH key next steps"
    assert_contains "$OUTPUT_DIR/next_steps.txt" "ssh -i <id_rsa>" "crackr SSH key output includes ssh -i"

    OUTPUT_DIR="$TEST_TMP/crackr_asrep"
    mkdir -p "$OUTPUT_DIR"
    echo "alice:Password1" > "$OUTPUT_DIR/hashcat_cracked_1.txt"
    CRACKED_HC_MODE="18200"
    CRACKED_HASH_TYPE="AS-REP"
    EXTRACT_CONTEXT=""
    write_crack_next_steps 1 "$TEST_TMP/creds.txt"
    assert_contains "$OUTPUT_DIR/next_steps.txt" "AS-REP ROAST CRACKED" "crackr emits AS-REP next steps"
    assert_contains "$OUTPUT_DIR/next_steps.txt" "./adr.sh" "crackr AS-REP output includes adr"
)

test_sprayr_rules() (
    export OffSec_LIB_ONLY=true
    source_script "$ROOT_DIR/sprayr.sh"

    OUTDIR="$TEST_TMP/sprayr"
    mkdir -p "$OUTDIR"
    AUTH_TYPE="password"
    AUTH_PASS="Password1"
    DOMAIN="corp.local"
    NT_HASH=""
    LM_NT_HASH=""
    cat > "$OUTDIR/hits.txt" <<'EOF'
smb|10.10.10.5|alice:Password1|HIT
winrm|10.10.10.6|alice:Password1|HIT
ftp|10.10.10.7|alice:Password1|HIT
mssql|10.10.10.8|alice:Password1|HIT
EOF
    generate_next_steps
    local ns="$OUTDIR/next_steps.txt"
    assert_contains "$ns" "Valid SMB credentials" "sprayr emits SMB non-admin follow-up"
    assert_contains "$ns" "Valid WinRM credentials" "sprayr emits WinRM hit follow-up"
    assert_contains "$ns" "FTP access" "sprayr emits FTP hit follow-up"
    assert_contains "$ns" "xp_cmdshell" "sprayr MSSQL output includes xp_cmdshell reminder"
)

echo "Running next-step regression tests..."
test_recon_rules
test_webenum_rules
test_pivotr_rules
test_adr_rules
test_crackr_rules
test_sprayr_rules

echo
PASS=$(cat "$PASS_FILE")
FAIL=$(cat "$FAIL_FILE")
echo "Passed: $PASS"
echo "Failed: $FAIL"

if (( FAIL > 0 )); then
    exit 1
fi
