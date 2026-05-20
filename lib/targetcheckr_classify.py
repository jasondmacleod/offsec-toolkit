#!/usr/bin/env python3
"""
targetcheckr_classify.py — outcome classifier for targetcheckr.sh.

Reads:
  argv[1]   path to failure_map.yaml         (failure-with-symptom catalog)
  argv[2]   path to input capture file       (exploit stdout+stderr)
  argv[3]   path to substitutions.md         (informational — engine has table inline)
  argv[4]   --expect value, '' if none
  argv[5]   target IP, '' if target-less

stdin      state vector lines (key=value) from lib/state.sh — may be empty

Emits a single JSON object on stdout per targetcheckr design spec §4/§5/§6/§7.
Never executes, never opens sockets, never mutates state. Pure transform.

Sub-class taxonomy (pinned per §3, post-checkpoint signoff 2026-05-20):
  success-confirmed / success-likely sub-classes (8):
    shell-spawned, cred-dumped, hash-dumped, file-read, file-written,
    sql-rows-returned, auth-bypassed, rce-stdout
  partial-success sub-classes (4):
    shell-died, dump-truncated, auth-bypass-no-data, command-ran-no-output
  failure-with-symptom sub-class = matched failure_map.yaml key
  no-effect / unclear — no sub-classes

Multi-membership: a single capture can fire >=1 success sub-class; all
fired sub-classes' state writes are emitted. Top-level outcome is the
strongest single classification across the fired set.
"""
import json
import os
import re
import sys

import yaml


# ── shared substitution constants — imported verbatim from substitutions.md ──
# Any change here must also change lib/substitutions.md. Do NOT fork.
TARGET_IP_RE = re.compile(
    r'\b(?:10\.10\.(?:10|11|12|13)\.\d+'
    r'|192\.168\.\d+\.\d+'
    r'|172\.16\.\d+\.\d+'
    r'|<TARGET(?:_IP)?>|<IP>|<RHOST>|<HOST>)\b'
)
TARGET_TOKEN_RE = re.compile(r'\bTARGET(?:_IP)?\b')
KALI_IP_RE = re.compile(r'\b10\.10\.14\.\d+\b')
DOMAIN_LITERAL_RE = re.compile(r'\bcorp\.local\b|<DOMAIN>')
USER_LITERAL_RE = re.compile(r'\bjdoe\b|<USER(?:NAME)?>')
PASS_LITERAL_RE = re.compile(r"'Password1'|<PASS(?:WORD)?>")


# ── --expect → sub-class mapping (spec §2) ───────────────────────────────────
EXPECT_TO_SUBCLASS = {
    'shell':       {'shell-spawned'},
    'cred-dump':   {'cred-dumped', 'hash-dumped'},
    'file-read':   {'file-read'},
    'file-write':  {'file-written'},
    'auth-bypass': {'auth-bypassed'},
    'sqli-data':   {'sql-rows-returned'},
    'rce':         {'rce-stdout'},
}


# ── positive-marker regex library ────────────────────────────────────────────
# Markers selected from corpus evidence_signals + evidencr.md gold-standard
# frame + standard public-exploit conventions. See spec §3 for provenance.

# --- shell-spawned ---
# uid=N(name) — Linux id/whoami output. Capture name.
RE_UID_LINE       = re.compile(r'(?m)^\s*uid=\d+\(([A-Za-z0-9_.$-]+)\)')
# NT AUTHORITY\SYSTEM (case-insensitive). Canonical Windows SYSTEM marker.
RE_NT_SYSTEM      = re.compile(r'(?i)\bnt\s+authority\\system\b')
# Windows cmd prompt at end of a line: C:\path>
RE_WIN_CMD_PROMPT = re.compile(r'(?m)^[A-Z]:\\[^\r\n]*>\s*$')
# PowerShell prompt: PS C:\path>
RE_PS_PROMPT      = re.compile(r'(?m)^PS\s+[A-Z]:\\[^\r\n]*>\s*$')
# Linux shell prompt: user@host:path$ or :path#
RE_LINUX_PROMPT   = re.compile(r'(?m)^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[^\r\n]*[#$]\s*$')
# Standalone interactive prompt char on its own line (terminal-emulated capture)
RE_BARE_PROMPT    = re.compile(r'(?m)^[#$>]\s*$')
# Penelope / standard handler banners
RE_GOT_SHELL      = re.compile(r'(?im)\[\*\]\s+Got\s+shell')
RE_INCOMING_CONN  = re.compile(r'(?im)\[\*\]\s+Incoming\s+connection')
# (Pwn3d!) tag (NXC) — local admin access marker
RE_PWN3D          = re.compile(r'\(Pwn3d!\)')
# "Logged in as <name>" — many web-shell PoCs print this
RE_LOGGED_IN_AS   = re.compile(r'(?i)\bLogged\s+in\s+as\s+(\S+)')
# USER= env line — last-resort user capture
RE_USER_ENV       = re.compile(r'(?m)^USER=(\S+)')
# whoami output (single token, alone on a line)
RE_WHOAMI_LINE    = re.compile(r'(?m)^([A-Za-z0-9_.$-]+(?:\\[A-Za-z0-9_.$-]+)?)\s*$')

# --- cred-dumped (plaintext) ---
# NXC-style: [+] DOMAIN\user:password  (or just user:password)
RE_NXC_CRED       = re.compile(
    r'(?m)^\[(?:\+|\*)\]\s+'
    r'(?:([A-Za-z0-9_.-]+)\\)?'           # optional DOMAIN\
    r'([A-Za-z0-9_.$@-]+):'               # user
    r'([^\s][^\r\n]{0,80}?)\s*$'          # password
)
# "Username: foo / Password: bar" (verbose PoC dump)
RE_USER_PASS_PAIR = re.compile(
    r'(?im)Username:\s*(\S+)\s+Password:\s*(\S+)'
)
# Generic user:pass line (bounded — exclude NTLM-shaped hashes, timestamps)
RE_GENERIC_USERPASS = re.compile(
    r'(?m)^([A-Za-z][A-Za-z0-9_.$@-]{1,40}):'
    r'([!-~]{4,40})\s*$'
)
# Hash prefix tokens — used to EXCLUDE plain-cred matches that are actually hashes
RE_HASH_PREFIX = re.compile(
    r'^\$(?:6|5|2[aby]?|1|krb5tgs|krb5asrep|argon2)\$'
)
# NTLM-shape: 32 hex : 32 hex
RE_NTLM_PAIR = re.compile(
    r'^(?:aad3b435b51404eeaad3b435b51404ee|[a-f0-9]{32}):[a-f0-9]{32}$',
    re.IGNORECASE,
)

# --- hash-dumped ---
# Linux shadow / unix-crypt
RE_HASH_UNIX      = re.compile(r'\$(?:6|5|2[aby]?|1)\$[A-Za-z0-9./+]+\$[A-Za-z0-9./+]{16,}')
# Kerberos
RE_HASH_KRB5TGS   = re.compile(r'\$krb5tgs\$23\$\*[^*\s]+\*\$[A-Fa-f0-9]+\$[A-Fa-f0-9]+')
RE_HASH_KRB5ASREP = re.compile(r'\$krb5asrep\$23\$[^\s:]+:[A-Fa-f0-9]+\$[A-Fa-f0-9]+')
# NTLM in secretsdump line: user:RID:LMhash:NThash:::
RE_HASH_SECRETSDUMP = re.compile(
    r'(?m)^([A-Za-z0-9_.$@\\-]+):(\d+):'
    r'([a-f0-9]{32}):([a-f0-9]{32}):::'
)
# Bare NTLM pair on its own line
RE_HASH_NTLM_BARE = re.compile(
    r'(?m)^([a-f0-9]{32}):([a-f0-9]{32})\s*$'
)

# --- file-read ---
RE_PASSWD_CONTENT = re.compile(r'(?m)^root:x:0:0:[^\r\n]*:/root:')
RE_SHADOW_CONTENT = re.compile(r'(?m)^root:\$(?:6|5|2[aby]?|1)\$[^:\r\n]+')
# Flag UUID — both 32-hex and dashed UUID
RE_FLAG_UUID      = re.compile(
    r'\b(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',
    re.IGNORECASE,
)
# "Reading file ..." / "Read N bytes" markers
RE_READ_BYTES     = re.compile(r'(?i)(?:read|retrieved|fetched|downloaded)\s+(?:\d+\s+bytes|file:?)\s*[^\r\n]{0,80}')
# web.config / unattend.xml content marker
RE_WEB_CONFIG     = re.compile(r'<\?xml\s+version|<configuration>|<unattend\s+xmlns')

# --- file-written ---
RE_HTTP_2XX_PUT   = re.compile(r'(?im)^HTTP/\d\.\d\s+20[0-4]\s')
RE_UPLOAD_OK      = re.compile(r'(?i)(?:upload|put|wrote|written|saved)(?:ed)?\s+[^\r\n]{0,100}?(?:successful|to\s+\S+|complete|\b\d+\s+bytes)')
RE_FILE_WRITTEN   = re.compile(r'(?i)\bfile\s+(?:written|created|saved)\b')

# --- sql-rows-returned ---
RE_SQL_ROWS_PHRASE = re.compile(r'(?i)\b\d+\s+rows?\s+(?:in\s+set|returned|affected)\b')
RE_SQLMAP_DATABASE = re.compile(r'(?i)^\s*Database:\s+\S+', re.MULTILINE)
RE_SQLMAP_TABLE    = re.compile(r'(?i)^\s*Table:\s+\S+', re.MULTILINE)
RE_SQLMAP_RETRIEVED = re.compile(r'\[INFO\]\s+retrieved:')
RE_SQL_PROMPT      = re.compile(r'(?m)^(?:mysql>|MariaDB\s+\[\S+\]>|postgres=#|sqlite>)\s')
RE_SQL_BORDER      = re.compile(r'(?m)^\+(?:-+\+){2,}\s*$')  # mysql table border

# --- auth-bypassed ---
RE_SET_COOKIE_SESSION = re.compile(
    r'(?im)^Set-Cookie:\s*(?:PHPSESSID|JSESSIONID|session(?:id)?|auth(?:_token)?|token|sid)=\S+'
)
RE_JWT_BEARER     = re.compile(r'(?i)\bBearer\s+(?:[A-Za-z0-9_-]+\.){2}[A-Za-z0-9_-]+')
RE_REDIRECT_ADMIN = re.compile(
    r'(?i)^HTTP/\d\.\d\s+30[12]\b[^\n]*\n(?:[^\n]+\n){0,8}?'
    r'Location:\s*[^\r\n]*?(?:/admin|/dashboard|/home\b|/user/)',
    re.MULTILINE,
)
RE_AUTH_OK        = re.compile(r'(?i)\bauthentication\s+(?:successful|bypassed)\b')

# --- rce-stdout (residual — only fires if no shell prompt anywhere) ---
RE_RCE_WHOAMI     = re.compile(r'(?im)^([A-Za-z][A-Za-z0-9_.$\\-]{0,40})\s*$')
RE_RCE_HOSTNAME   = re.compile(r'(?im)hostname\s*[:=]?\s*\S+|^[A-Za-z][A-Za-z0-9-]{1,30}$')
RE_RCE_UNAME      = re.compile(r'(?i)\bLinux\s+\S+\s+\d+\.\d+\.\d+[^\r\n]+GNU/Linux')
RE_RCE_MARKER     = re.compile(r'(?i)\b(?:command\s+executed|stdout\s+captured|exec\s+returned|response\s+contains)\b')

# --- shell-died (partial-success) ---
RE_CONN_CLOSED    = re.compile(
    r'(?i)\b(?:Connection\s+(?:closed|reset|to\s+\S+\s+closed)'
    r'|Broken\s+pipe'
    r'|bash:\s*exit'
    r'|shell\s+(?:died|exited|disconnected)\s+immediately)\b'
)

# --- dump-truncated (partial-success) ---
# Mid-pattern trailing line (e.g. cred dump cut at "user1:pa")
RE_TRUNC_HINT     = re.compile(r'\.\.\.$|\[truncated\]|\[\.\.\.\]')

# --- command-ran-no-output (partial-success) ---
RE_RCE_SENT       = re.compile(r'(?i)(?:POST|GET)\s+\S+\s+HTTP|payload\s+sent|exploit\s+sent')

# Prompt detection (used to GATE rce-stdout off — if any prompt visible,
# rce-stdout never fires; shell-spawned wins).
PROMPT_RE_LIST = [
    RE_WIN_CMD_PROMPT, RE_PS_PROMPT, RE_LINUX_PROMPT,
    RE_BARE_PROMPT, RE_GOT_SHELL, RE_PWN3D,
]


# ── state-vector parser ──────────────────────────────────────────────────────
def parse_state(stream):
    state = {
        'ip': '', 'os_guess': 'unknown',
        'foothold': 'no', 'privesc': 'no',
        'services': [], 'creds': [], 'domain': '', 'dc_ip': '',
    }
    for line in stream:
        line = line.rstrip('\n')
        if not line or '=' not in line:
            continue
        k, v = line.split('=', 1)
        if k == 'services':
            continue
        if k == 'service':
            state['services'].append(v)
        elif k == 'cred':
            state['creds'].append(v)
        elif k in state and not isinstance(state[k], list):
            state[k] = v
    return state


# ── shell-spawned: user capture per spec §5 priority order ───────────────────
def extract_shell_user(text):
    """Return (user, source) where source is one of:
       'uid', 'whoami', 'env', 'logged-in-as', 'nt-system', or None.
       Most-recent occurrence wins on conflict (later in capture)."""
    candidates = []  # list of (offset, source, name)
    for m in RE_UID_LINE.finditer(text):
        candidates.append((m.start(), 'uid', m.group(1)))
    for m in RE_NT_SYSTEM.finditer(text):
        candidates.append((m.start(), 'nt-system', 'nt authority\\system'))
    for m in RE_LOGGED_IN_AS.finditer(text):
        candidates.append((m.start(), 'logged-in-as', m.group(1).rstrip(',.;:')))
    for m in RE_USER_ENV.finditer(text):
        candidates.append((m.start(), 'env', m.group(1)))
    # whoami: only count tokens that look like usernames (not random words)
    # and are immediately adjacent to a prompt or shell marker
    # — handled conservatively: only credit `whoami` capture if line follows
    # `$ whoami` or `# whoami` or `> whoami` pattern.
    for m in re.finditer(
        r'(?m)^\s*(?:[#$>]|whoami|PS\s+[A-Z]:[^\r\n]*>)\s+whoami\s*$\s*\n([A-Za-z0-9_.$-]+(?:\\[A-Za-z0-9_.$-]+)?)\s*$',
        text,
    ):
        candidates.append((m.start(1), 'whoami', m.group(1)))
    if not candidates:
        return ('', None)
    # Most-recent (highest offset) wins
    candidates.sort(key=lambda c: c[0])
    _, source, name = candidates[-1]
    return (name, source)


# ── method inference for foothold log ────────────────────────────────────────
def infer_method(text):
    """Best-effort categorization of HOW the shell came in."""
    t = text.lower()
    if 'msfvenom' in t or 'meterpreter' in t:
        return 'msfvenom-payload'
    if 'psexec' in t or 'impacket-psexec' in t:
        return 'psexec'
    if 'evil-winrm' in t or 'winrm' in t:
        return 'winrm'
    if 'xp_cmdshell' in t or 'mssqlclient' in t:
        return 'mssql-xpcmdshell'
    if 'wmiexec' in t or 'smbexec' in t or 'atexec' in t:
        return 'impacket-exec'
    if 'webshell' in t or '.php' in t or 'shell.aspx' in t or 'cmd.jsp' in t:
        return 'webshell'
    if 'reverse' in t and ('shell' in t or 'tcp' in t):
        return 'reverse-shell'
    return 'exploit-rce'


# ── positive-marker detection ────────────────────────────────────────────────
def detect_shell_spawned(text):
    """Fires iff any strong shell marker is present. Returns dict or None."""
    snippets = []
    for rx, label in [
        (RE_UID_LINE, 'uid line'),
        (RE_NT_SYSTEM, 'NT AUTHORITY\\SYSTEM'),
        (RE_WIN_CMD_PROMPT, 'Windows cmd prompt'),
        (RE_PS_PROMPT, 'PowerShell prompt'),
        (RE_LINUX_PROMPT, 'Linux shell prompt'),
        (RE_GOT_SHELL, 'Got shell banner'),
        (RE_INCOMING_CONN, 'Incoming connection'),
        (RE_PWN3D, 'Pwn3d! tag'),
    ]:
        for m in rx.finditer(text):
            snippets.append((m.start(), label, _line_at(text, m.start())))
    if not snippets:
        return None
    user, user_source = extract_shell_user(text)
    method = infer_method(text)
    snippets.sort(key=lambda s: s[0])
    return {
        'subclass': 'shell-spawned',
        'snippets': [{'label': s[1], 'line': s[2]} for s in snippets[:5]],
        'captures': {
            'user': user or '',
            'user_source': user_source or '',
            'method': method,
        },
    }


def detect_cred_dumped(text):
    creds = []
    snippets = []
    seen = set()

    for m in RE_NXC_CRED.finditer(text):
        dom, user, pw = m.group(1), m.group(2), m.group(3)
        # Skip if password looks like a hash
        if RE_HASH_PREFIX.match(pw) or RE_NTLM_PAIR.match(f'{user}:{pw}'):
            continue
        if len(pw) < 3 or len(pw) > 80:
            continue
        full_user = f'{dom}\\{user}' if dom else user
        key = (full_user, pw)
        if key not in seen:
            seen.add(key)
            creds.append((full_user, pw))
            snippets.append({'label': 'NXC cred line', 'line': _line_at(text, m.start())})

    for m in RE_USER_PASS_PAIR.finditer(text):
        u, p = m.group(1), m.group(2)
        if RE_HASH_PREFIX.match(p):
            continue
        key = (u, p)
        if key not in seen:
            seen.add(key)
            creds.append((u, p))
            snippets.append({'label': 'Username/Password pair', 'line': _line_at(text, m.start())})

    for m in RE_GENERIC_USERPASS.finditer(text):
        u, p = m.group(1), m.group(2)
        # Exclusions to avoid hash-shaped or timestamp-shaped lines
        if RE_HASH_PREFIX.match(p):
            continue
        if RE_NTLM_PAIR.match(f'{u}:{p}'):
            continue
        # Skip if matches an HTTP header line, log timestamp, etc.
        if u.lower() in ('http', 'https', 'tcp', 'udp', 'set-cookie',
                          'authorization', 'content-type', 'host', 'date'):
            continue
        # Skip ratio-shaped (numbers : numbers — likely scores/ratios)
        if u.isdigit() and p.isdigit():
            continue
        key = (u, p)
        if key not in seen:
            seen.add(key)
            creds.append((u, p))
            snippets.append({'label': 'user:pass line', 'line': _line_at(text, m.start())})

    if not creds:
        return None
    return {
        'subclass': 'cred-dumped',
        'snippets': snippets[:6],
        'captures': {'creds': creds},
    }


def detect_hash_dumped(text):
    hashes = []
    user_hashes = []
    snippets = []
    seen_hash = set()
    seen_uh = set()

    for m in RE_HASH_SECRETSDUMP.finditer(text):
        user, _rid, _lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
        full = f'{user}:{nt}'
        if full not in seen_uh:
            seen_uh.add(full)
            user_hashes.append((user, nt))
            snippets.append({'label': 'secretsdump line', 'line': _line_at(text, m.start())})

    for m in RE_HASH_NTLM_BARE.finditer(text):
        h = m.group(0).strip()
        if h not in seen_hash:
            seen_hash.add(h)
            hashes.append(h)
            snippets.append({'label': 'NTLM pair', 'line': h})

    for rx, label in [
        (RE_HASH_KRB5TGS, 'krb5tgs hash'),
        (RE_HASH_KRB5ASREP, 'krb5asrep hash'),
        (RE_HASH_UNIX, 'unix-crypt hash'),
    ]:
        for m in rx.finditer(text):
            h = m.group(0)
            if h not in seen_hash:
                seen_hash.add(h)
                hashes.append(h)
                snippets.append({'label': label, 'line': h[:80] + ('…' if len(h) > 80 else '')})

    if not hashes and not user_hashes:
        return None
    return {
        'subclass': 'hash-dumped',
        'snippets': snippets[:6],
        'captures': {'hashes': hashes, 'user_hashes': user_hashes},
    }


def detect_file_read(text):
    snippets = []
    for rx, label in [
        (RE_PASSWD_CONTENT, '/etc/passwd content'),
        (RE_SHADOW_CONTENT, '/etc/shadow content'),
        (RE_WEB_CONFIG, 'XML config content (web.config / unattend.xml)'),
    ]:
        for m in rx.finditer(text):
            snippets.append({'label': label, 'line': _line_at(text, m.start())})
    # Flag UUID: only count if accompanied by a `cat`/`type` cue OR a flag-file
    # path in the same window — too noisy to fire on a bare hex string alone.
    for m in RE_FLAG_UUID.finditer(text):
        window = text[max(0, m.start() - 120):m.end() + 40]
        if re.search(r'(?i)(?:cat|type|local\.txt|proof\.txt|flag\.txt)', window):
            snippets.append({'label': 'flag UUID near flag-file cue', 'line': m.group(0)})
    for m in RE_READ_BYTES.finditer(text):
        snippets.append({'label': 'file-read marker', 'line': _line_at(text, m.start())})
    if not snippets:
        return None
    # Dedupe by line value
    uniq = {}
    for s in snippets:
        uniq.setdefault(s['line'], s)
    return {
        'subclass': 'file-read',
        'snippets': list(uniq.values())[:5],
        'captures': {},
    }


def detect_file_written(text):
    snippets = []
    # PUT/POST followed by 2xx — anchor on HTTP request lines first to avoid
    # firing on incidental 200s.
    if re.search(r'(?im)^(?:PUT|POST)\s+\S+\s+HTTP', text):
        for m in RE_HTTP_2XX_PUT.finditer(text):
            snippets.append({'label': '2xx after PUT/POST', 'line': _line_at(text, m.start())})
    for rx, label in [
        (RE_UPLOAD_OK, 'upload-OK marker'),
        (RE_FILE_WRITTEN, 'file written/created/saved'),
    ]:
        for m in rx.finditer(text):
            snippets.append({'label': label, 'line': _line_at(text, m.start())})
    if not snippets:
        return None
    return {
        'subclass': 'file-written',
        'snippets': snippets[:5],
        'captures': {},
    }


def detect_sql_rows_returned(text):
    snippets = []
    for rx, label in [
        (RE_SQL_ROWS_PHRASE, 'rows-returned phrase'),
        (RE_SQLMAP_DATABASE, 'sqlmap Database:'),
        (RE_SQLMAP_TABLE, 'sqlmap Table:'),
        (RE_SQLMAP_RETRIEVED, 'sqlmap retrieved'),
        (RE_SQL_PROMPT, 'SQL client prompt + data'),
        (RE_SQL_BORDER, 'MySQL table border'),
    ]:
        for m in rx.finditer(text):
            snippets.append({'label': label, 'line': _line_at(text, m.start())})
    if not snippets:
        return None
    return {
        'subclass': 'sql-rows-returned',
        'snippets': snippets[:5],
        'captures': {},
    }


def detect_auth_bypassed(text):
    snippets = []
    for rx, label in [
        (RE_SET_COOKIE_SESSION, 'Set-Cookie session token'),
        (RE_JWT_BEARER, 'JWT Bearer'),
        (RE_REDIRECT_ADMIN, '3xx redirect to admin/dashboard'),
        (RE_AUTH_OK, 'auth-success/bypass phrase'),
    ]:
        for m in rx.finditer(text):
            snippets.append({'label': label, 'line': _line_at(text, m.start())[:120]})
    if not snippets:
        return None
    return {
        'subclass': 'auth-bypassed',
        'snippets': snippets[:5],
        'captures': {},
    }


def has_any_prompt(text):
    """Used to gate rce-stdout off when ANY interactive-prompt marker exists."""
    for rx in PROMPT_RE_LIST:
        if rx.search(text):
            return True
    return False


def detect_rce_stdout(text, other_fired):
    """Residual single-shot class — fires only when:
       - a command-output marker is present
       - no interactive-prompt marker anywhere in capture
       - shell-spawned did NOT fire (covered by the prompt gate, but explicit)"""
    if 'shell-spawned' in other_fired:
        return None
    if has_any_prompt(text):
        return None
    snippets = []
    for m in RE_UID_LINE.finditer(text):
        snippets.append({'label': 'uid output', 'line': _line_at(text, m.start())})
    for m in RE_RCE_UNAME.finditer(text):
        snippets.append({'label': 'uname output', 'line': m.group(0)[:120]})
    for m in RE_RCE_MARKER.finditer(text):
        snippets.append({'label': 'RCE phrase', 'line': _line_at(text, m.start())})
    # whoami-style single-token line — only counts if the capture is small
    # (single-shot RCE captures are typically tiny; large captures with a
    # single matching line are probably noise).
    if len(text) < 4000:
        for m in RE_RCE_WHOAMI.finditer(text):
            tok = m.group(1)
            # Heuristic: must look like a username (not a banner word).
            if tok.lower() in ('error', 'warning', 'info', 'debug', 'true',
                               'false', 'null', 'none', 'usage'):
                continue
            if 2 <= len(tok) <= 32 and not tok.isdigit():
                snippets.append({'label': 'single-token whoami-style line', 'line': tok})
                break
    if not snippets:
        return None
    return {
        'subclass': 'rce-stdout',
        'snippets': snippets[:4],
        'captures': {},
    }


# ── partial-success detectors ────────────────────────────────────────────────
def detect_shell_died(text, fired):
    if 'shell-spawned' not in fired:
        return None
    m = RE_CONN_CLOSED.search(text)
    if not m:
        return None
    return {
        'subclass': 'shell-died',
        'snippets': [{'label': 'connection-closed marker', 'line': _line_at(text, m.start())}],
        'captures': {},
    }


def detect_dump_truncated(text, fired):
    if not ({'cred-dumped', 'hash-dumped'} & set(fired)):
        return None
    # Mid-pattern trailing — last line lacks closing newline and doesn't end
    # with a complete-shape marker, OR explicit truncation marker visible.
    if RE_TRUNC_HINT.search(text):
        return {
            'subclass': 'dump-truncated',
            'snippets': [{'label': 'explicit truncation marker', 'line': '[truncated/…]'}],
            'captures': {},
        }
    # Heuristic: last non-empty line is mid-cred-shape but bounded by EOF
    lines = text.rstrip('\n').splitlines()
    if not lines:
        return None
    last = lines[-1]
    if ':' in last and not last.endswith((':', '!', '.', ']', ')')) and len(last) < 16:
        return {
            'subclass': 'dump-truncated',
            'snippets': [{'label': 'mid-pattern tail', 'line': last}],
            'captures': {},
        }
    return None


def detect_auth_bypass_no_data(text, fired):
    if 'auth-bypassed' not in fired:
        return None
    # If we have any of: substantial HTML body, table data, dashboard markers,
    # then there IS payoff. Otherwise → no-data partial.
    if re.search(r'(?is)<(?:table|h1|h2|main|body)\b[^>]*>.*?</', text):
        return None
    if re.search(r'(?i)\b(?:dashboard|welcome|profile|settings)\b', text):
        return None
    if 'sql-rows-returned' in fired or 'file-read' in fired or 'cred-dumped' in fired:
        return None
    return {
        'subclass': 'auth-bypass-no-data',
        'snippets': [{'label': 'session token without observed payoff', 'line': '(no follow-up resource content visible)'}],
        'captures': {},
    }


def detect_command_ran_no_output(text, fired):
    # RCE invocation visible but no command stdout — only fires if no success
    # sub-class fired AND we see a clear RCE-send marker.
    if fired:
        return None
    if not RE_RCE_SENT.search(text):
        return None
    return {
        'subclass': 'command-ran-no-output',
        'snippets': [{'label': 'exploit-send marker, no command output observed',
                      'line': _line_at(text, RE_RCE_SENT.search(text).start())[:120]}],
        'captures': {},
    }


# ── failure-with-symptom detection (read failure_map.yaml) ───────────────────
def detect_failures(text, catalog):
    matches = []
    for entry in catalog:
        det = entry.get('detect') or {}
        err_pats = det.get('error_patterns') or []
        hits = []
        for pat in err_pats:
            try:
                m = re.search(pat, text)
            except re.error:
                continue
            if m:
                hits.append({'pattern': pat, 'matched': m.group(0)[:120]})
        if hits:
            matches.append({
                'key': entry['key'],
                'category': entry['category'],
                'confidence': entry['confidence'],
                'impact': entry['impact'],
                'precedence': int(det.get('precedence', 0)),
                'hits': hits,
            })
    # Highest precedence first, then by confidence
    rank = {'definite': 0, 'likely': 1, 'speculative': 2}
    matches.sort(key=lambda m: (rank.get(m['confidence'], 3), -m['precedence']))
    return matches


# ── helpers ──────────────────────────────────────────────────────────────────
def _line_at(text, offset):
    """Return the full line containing `offset`, trimmed."""
    start = text.rfind('\n', 0, offset) + 1
    end = text.find('\n', offset)
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:200]


# ── state-cross-check ────────────────────────────────────────────────────────
def state_cross_check(positives, state):
    """Return list of {check, result, agrees} dicts. `agrees`:
        True  — state evidence supports the positive
        False — state evidence contradicts
        None  — no evidence available (neither support nor refute)"""
    checks = []
    # Spec §4: listener-side log not actually accessible to targetcheckr today.
    # Absence is not a refutation, only a downgrade. Encoded as None.
    if 'shell-spawned' in positives:
        checks.append({
            'check': 'listener-connection-logged',
            'result': 'no-data',
            'agrees': None,
        })
    if 'cred-dumped' in positives:
        creds = positives['cred-dumped']['captures'].get('creds', [])
        existing = {c.split(':', 1)[0] if ':' in c else c for c in state.get('creds', [])}
        already = sum(1 for u, _ in creds if u in existing)
        checks.append({
            'check': 'creds-already-known',
            'result': f'{already}/{len(creds)} users already in creds.txt',
            'agrees': True if already > 0 else None,
        })
    if 'file-read' in positives or 'file-written' in positives:
        # Path-cite anchor — already enforced in detector (we required a
        # surrounding cat/type cue for flag UUIDs). Mark as agrees.
        checks.append({
            'check': 'path-cite-present',
            'result': 'detector required surrounding file cue',
            'agrees': True,
        })
    return checks


# ── --expect agreement ───────────────────────────────────────────────────────
def expect_agreement(expect, fired_subclasses):
    if not expect:
        return None
    mapped = EXPECT_TO_SUBCLASS.get(expect, set())
    if not mapped:
        return None
    return bool(mapped & set(fired_subclasses))


# ── confidence tiering (spec §7, amended 2026-05-20) ─────────────────────────
# "All-available-of-three": no-data signals (absence) are removed from the
# denominator. So positives + --expect agreement + cross-check no-data is
# 2-available / 2-agreeing → HIGH, not medium. Contradictions still downgrade.
def compute_confidence(outcome, fired, expect_agree, state_checks, shell_user_unknown):
    """Confidence tiers (success/partial outcomes only):
         high    — >=2 signals available AND all available agree (no contradictions)
         medium  — exactly 1 signal available AND it agrees;
                   OR >=2 available with >=2 agreeing but at least one contradicts;
                   OR shell-spawned with user=unknown (forced override per §5)
         low     — otherwise

       Signal sources (3):
         positives  — always available; AGREES iff any sub-class fired
                      (always true on the success/partial branch)
         state      — AGREES if any cross-check is True, CONTRADICTS if any is False,
                      else NO-DATA (e.g., listener-side log not accessible to targetcheckr)
         expect     — NO-DATA if --expect was not given; AGREES if it maps to a fired
                      sub-class; CONTRADICTS otherwise."""
    if outcome not in ('success-confirmed', 'success-likely', 'partial-success'):
        return 'low'

    # Positives: AGREES whenever any sub-class fired (true on this branch).
    pos_agree = bool(fired)

    # State cross-check
    state_agree_any = any(c.get('agrees') is True for c in state_checks)
    state_contradicts = any(c.get('agrees') is False for c in state_checks)
    state_available = state_agree_any or state_contradicts

    # --expect
    expect_available = expect_agree is not None
    expect_agrees = expect_agree is True
    expect_contradicts = expect_agree is False

    available = int(pos_agree) + int(state_available) + int(expect_available)
    agreeing = int(pos_agree) + int(state_agree_any) + int(expect_agrees)
    contradicts = state_contradicts or expect_contradicts

    # §5 override: shell-spawned with user=unknown is forced to medium.
    if shell_user_unknown:
        return 'medium'

    if contradicts:
        return 'medium' if agreeing >= 2 else 'low'

    # No contradictions: all-available-of-three rule.
    if available >= 2 and agreeing == available:
        return 'high'
    if available == 1 and agreeing == 1:
        return 'medium'
    return 'low'


# ── state-write directive emission per spec §5 ───────────────────────────────
def emit_state_writes(target_ip, fired, positives):
    writes = []
    if not target_ip:
        return writes
    if 'shell-spawned' in fired:
        user = positives['shell-spawned']['captures'].get('user') or 'unknown'
        method = positives['shell-spawned']['captures'].get('method') or 'exploit-rce'
        writes.append({'kind': 'foothold', 'ip': target_ip, 'user': user, 'method': method})
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-shell-spawned'})
    if 'cred-dumped' in fired:
        for user, pw in positives['cred-dumped']['captures'].get('creds', []):
            writes.append({'kind': 'cred', 'value': f'{user}:{pw}'})
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-creds-dumped'})
    if 'hash-dumped' in fired:
        for user, h in positives['hash-dumped']['captures'].get('user_hashes', []):
            writes.append({'kind': 'cred', 'value': f'{user}:{h}'})
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-hashes-dumped'})
    if 'auth-bypassed' in fired:
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-auth-bypassed'})
    if 'file-read' in fired:
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-file-read'})
    if 'file-written' in fired:
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-file-written'})
    if 'sql-rows-returned' in fired:
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-sql-rows-returned'})
    if 'rce-stdout' in fired:
        writes.append({'kind': 'event', 'ip': target_ip, 'key': 'success-rce-stdout'})
    return writes


# ── next-tool routing for §6 banner footer ───────────────────────────────────
def next_tool_hint(outcome, fired, target_ip):
    if outcome == 'success-confirmed' or outcome == 'success-likely':
        if 'shell-spawned' in fired:
            return ('evidencr', 'run evidencr to capture flag artifact for report')
        if 'cred-dumped' in fired or 'hash-dumped' in fired:
            return ('crackr/sprayr', 'crackr to crack hashes, then sprayr --from-creds')
        return ('evidencr', 'document the outcome for the report')
    if outcome == 'partial-success':
        return ('re-run', 'gather stronger evidence and re-run targetcheckr')
    if outcome == 'failure-with-symptom':
        if target_ip:
            return ('exploitfixr', f'exploitfixr <path-to-exploit> --against {target_ip}')
        return ('exploitfixr', 'exploitfixr <path-to-exploit>')
    if outcome == 'unclear':
        if target_ip:
            return ('stuckr', f'stuckr --against {target_ip}  (if you are out of moves)')
        return ('stuckr', 'stuckr  (if you are out of moves)')
    return (None, None)


# ── main classifier ──────────────────────────────────────────────────────────
def classify(text, state, expect, target_ip, failure_catalog):
    fired = {}
    for det in (
        detect_shell_spawned(text),
        detect_cred_dumped(text),
        detect_hash_dumped(text),
        detect_file_read(text),
        detect_file_written(text),
        detect_sql_rows_returned(text),
        detect_auth_bypassed(text),
    ):
        if det:
            fired[det['subclass']] = det
    # rce-stdout is residual — depends on what already fired
    rce = detect_rce_stdout(text, set(fired.keys()))
    if rce:
        fired['rce-stdout'] = rce

    # Partial-success markers (don't add to fired set — separate dimension)
    partials = []
    for det in (
        detect_shell_died(text, set(fired.keys())),
        detect_dump_truncated(text, set(fired.keys())),
        detect_auth_bypass_no_data(text, set(fired.keys())),
        detect_command_ran_no_output(text, set(fired.keys())),
    ):
        if det:
            partials.append(det)

    # Failure markers
    failures = detect_failures(text, failure_catalog)

    # Precedence (spec §4)
    definite_failures = [f for f in failures if f['confidence'] == 'definite']

    expect_agree = expect_agreement(expect, set(fired.keys()))
    expect_disagrees = (expect_agree is False)
    cross_checks = state_cross_check(fired, state)

    # Decide outcome
    if definite_failures and not fired:
        outcome = 'failure-with-symptom'
        sub = definite_failures[0]['key']
    elif definite_failures and fired:
        # Definite failure + positives → partial-success (spec §4 #1)
        outcome = 'partial-success'
        sub = ' + '.join(sorted(fired.keys()))
    elif partials and fired:
        outcome = 'partial-success'
        partial_keys = [p['subclass'] for p in partials]
        sub = ' + '.join(sorted(set(fired.keys()) | set(partial_keys)))
    elif fired:
        # Success: confirmed if expect agrees AND no contradicting state,
        # likely otherwise.
        if expect_agree is True:
            outcome = 'success-confirmed'
        else:
            outcome = 'success-likely'
        sub = ' + '.join(sorted(fired.keys()))
    elif failures:
        # likely-or-below failures with no positives → still failure-with-symptom
        outcome = 'failure-with-symptom'
        sub = failures[0]['key']
    elif partials:
        outcome = 'partial-success'
        sub = ' + '.join(sorted(p['subclass'] for p in partials))
    elif text.strip():
        outcome = 'no-effect'
        sub = None
    else:
        outcome = 'unclear'
        sub = None

    # Confidence
    shell_user_unknown = (
        'shell-spawned' in fired
        and not fired['shell-spawned']['captures'].get('user')
    )
    confidence = compute_confidence(
        outcome, fired, expect_agree, cross_checks, shell_user_unknown,
    )

    # State writes — only for success outcomes (per §5)
    writes = []
    if outcome in ('success-confirmed', 'success-likely'):
        writes = emit_state_writes(target_ip, set(fired.keys()), fired)

    next_tool, next_hint = next_tool_hint(outcome, set(fired.keys()), target_ip)

    return {
        'outcome': outcome,
        'subclass': sub,
        'subclasses_fired': sorted(fired.keys()),
        'confidence': confidence,
        'expect': expect,
        'expect_agrees': expect_agree,
        'expect_disagrees': expect_disagrees,
        'target_ip': target_ip,
        'shell_user_unknown': shell_user_unknown,
        'positive_markers': [
            {
                'subclass': k,
                'snippets': v['snippets'],
                'captures': v['captures'],
            }
            for k, v in sorted(fired.items())
        ],
        'partial_markers': partials,
        'failure_markers': failures[:4],
        'state_cross_checks': cross_checks,
        'state_writes': writes,
        'next_tool': next_tool,
        'next_hint': next_hint,
    }


def main():
    if len(sys.argv) != 6:
        sys.stderr.write(
            "usage: targetcheckr_classify.py <failure_map.yaml> <input> "
            "<substitutions.md> <expect> <target_ip>\n"
        )
        sys.exit(2)
    map_path, input_path, _subs_path, expect, target_ip = sys.argv[1:6]

    with open(map_path) as f:
        catalog = yaml.safe_load(f) or []

    with open(input_path, 'r', errors='replace') as f:
        text = f.read()

    state = parse_state(sys.stdin)
    result = classify(text, state, expect, target_ip, catalog)
    json.dump(result, sys.stdout, indent=2)


if __name__ == '__main__':
    main()
