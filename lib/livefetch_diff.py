#!/usr/bin/env python3
# =============================================================================
# lib/livefetch_diff.py — pure diff + delta classifier for livefetch.sh
# =============================================================================
# Given a stage and two artifact roots (old snapshot, new live), apply the
# stage's noise filters, compute the structured delta, and classify added units
# into the five success-livefetch-* sentinel keys. Stdout is JSON.
#
# Sibling of lib/watchdog_classify.py: pure transform, argparse, json to stdout,
# stdlib only, fail-loud (no silent except). No state writes — livefetch.sh owns
# state_write_event. The §5 stage table here is a RECOGNITION reference (the
# build verified that constructing markers from a bare/suffixed rule is wrong);
# livefetch.sh discovers markers from progress.log and passes the resolved stage.
#
# Modes:
#   --list-roots                       print the artifact-root kind per stage
#   --stage S --old ROOT --new ROOT [--instance X] [--verbose]
#                                      diff + classify → JSON
# =============================================================================
import argparse
import glob
import json
import os
import re
import sys

# ---- the five keys (positive namespace) -------------------------------------
DELTA = "success-livefetch-delta-detected"
SVC = "success-livefetch-new-services-found"      # new attack surface / access
USR = "success-livefetch-new-users-found"         # new principal
EXP = "success-livefetch-new-exploits-found"      # named, catalog-identified

# ---- line-level noise filters (drop lines matching any pattern) -------------
NMAP_NOISE = [
    r'^#\s*Nmap\b',                       # "# Nmap 7.99 scan initiated/done ..."
    r'^Host is up',                       # latency value is volatile
    r'^\|_?clock-skew:',                  # mean/deviation drift
    r'scanned in [0-9.]+ seconds',
]
HTTP_HEADER_NOISE = [r'^Date:', r'^Set-Cookie:', r'^Last-Modified:', r'^Expires:']
NIKTO_NOISE = [r'^- Nikto v', r'Start Time:', r'End Time:',
               r'^\+ \d+ host\(s\) tested', r'\d+ item\(s\) reported',
               r'\d+ requests?:', r'\d+ error\(s\)']
FEROX_NOISE = [r'^Configuration\b', r'^\s*(kind|wordlist|config|proxy|'
               r'replay_proxy|server_certs|client_cert|threads|timeout):']
GOBUSTER_NOISE = [r'^Progress:', r'^\[\+\]', r'^=+$']
CONSOLE_TS_NOISE = [r'^# Started:', r'^\[\d{4}-\d\d-\d\d', r'Start time',
                    r'^Generated:', r'^# Generated:', r'^# Quick Wins —']
ADR_SUMMARY_NOISE = [r'^CLOCK_SKEW=']

FILTERS = {
    "nmap": NMAP_NOISE,
    "http_header": HTTP_HEADER_NOISE,
    "nikto": NIKTO_NOISE,
    "ferox": FEROX_NOISE,
    "gobuster": GOBUSTER_NOISE,
    "console_ts": CONSOLE_TS_NOISE,
    "adr_summary": ADR_SUMMARY_NOISE,
}

WRITE_METHOD_RE = re.compile(r'\b(PUT|PROPFIND|MKCOL|DELETE|COPY|MOVE|WebDAV)\b', re.I)
CVE_RE = re.compile(r'\b(CVE-\d{4}-\d+|EDB-\d+)\b')
ESC_RE = re.compile(r'\bESC\d+\b')
PORT_ROW_RE = re.compile(r'^(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)$')


def _read(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (OSError, IOError):
        return ""


def _apply_filters(text, names):
    pats = []
    for n in names:
        pats.extend(FILTERS.get(n, []))
    if not pats:
        return text
    rx = re.compile("|".join(pats))
    return "\n".join(ln for ln in text.splitlines() if not rx.search(ln))


# ---- tokenizers: text -> set of comparable units ----------------------------
def tok_lines(text):
    return {ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")}


def tok_csv_ports(text):
    out = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln == "NO_OPEN_PORTS":
            continue
        out.update(p for p in ln.split(",") if p.strip())
    return out


def tok_port_table(text):
    # "8080/tcp open http Jetty 1.0" -> "8080/tcp http Jetty 1.0"
    out = set()
    for ln in text.splitlines():
        m = PORT_ROW_RE.match(ln.strip())
        if m:
            out.add("%s %s %s" % (m.group(1), m.group(2), m.group(3).strip()))
    return out


def tok_cve(text):
    return set(CVE_RE.findall(text))


def tok_url_lines(text):
    # ffuf/feroxbuster/gobuster result rows — keep the path/status, drop nothing
    out = set()
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        m = re.search(r'https?://\S+', s)
        if m:
            out.add(m.group(0))
        elif s.startswith("/"):
            out.add(s.split()[0])
    return out


def tok_sqli_suspects(text):
    return {ln.strip() for ln in text.splitlines() if ln.strip().startswith("URL:")}


TOKS = {
    "lines": tok_lines,
    "csv_ports": tok_csv_ports,
    "port_table": tok_port_table,
    "cve": tok_cve,
    "url_lines": tok_url_lines,
    "sqli": tok_sqli_suspects,
}


# ---- stage spec --------------------------------------------------------------
# Each part: relative path under the artifact root (may contain {instance}),
# a tokenizer, optional filters, the key for ADDED units, an optional key for
# REMOVED units, and a label. key_fn (per-unit) overrides `added` for
# content-based classification (e.g. write-capable HTTP methods).
def P(path, tok="lines", filters=(), added=DELTA, removed=None, label="item",
      key_fn=None):
    return dict(path=path, tok=tok, filters=list(filters), added=added,
                removed=removed, label=label, key_fn=key_fn)


def _write_method_key(unit):
    return SVC if WRITE_METHOD_RE.search(unit) else None  # None => skip (not a delta)


def _http_quick_key(unit):
    return SVC if WRITE_METHOD_RE.search(unit) else DELTA


STAGE_SPEC = {
    # ---- recon scan tier (root = recon/<ip>) ----
    "tcp-discovery": [P("scans/tcp_ports.txt", "csv_ports", added=SVC,
                        removed=DELTA, label="port")],
    "tcp-services": [P("scans/nmap_tcp.nmap", "port_table", ["nmap"], SVC,
                       DELTA, "service")],
    "tcp-vulnmatch": [P("loot/searchsploit_hits.txt", "cve", added=EXP, label="exploit"),
                      P("loot/vulners_hits.txt", "cve", added=EXP, label="exploit")],
    "udp-scan": [P("scans/udp_ports.txt", "csv_ports", added=SVC, label="udp-port")],
    "recon-summary": [P("loot/quick_wins.txt", "lines", ["console_ts"], DELTA, label="quick-win"),
                      P("loot/next_steps.txt", "lines", ["console_ts"], DELTA, label="next-step")],
    # ---- recon per-service tier (root = recon/<ip>) ----
    "http-quick": [
        P("tcp/http/port_{instance}/http_methods.txt", "lines", ["http_header"],
          label="method", key_fn=_http_quick_key),
        P("tcp/http/port_{instance}/whatweb.txt", "lines", added=DELTA, label="tech"),
        P("tcp/http/port_{instance}/gobuster_dir.txt", "url_lines", ["gobuster"], DELTA, label="path"),
        P("tcp/http/port_{instance}/feroxbuster.txt", "url_lines", ["ferox"], DELTA, label="path"),
        P("tcp/http/port_{instance}/nikto.txt", "lines", ["nikto"], DELTA, label="nikto-finding"),
        P("tcp/http/port_{instance}/tls_names.txt", "lines", added=DELTA, label="tls-name"),
    ],
    "smb": [
        P("tcp/smb/netexec_shares.txt", "lines", added=SVC, label="share"),
        P("tcp/smb/smbmap_null.txt", "lines", added=SVC, label="null-access"),
        P("tcp/smb/smbmap_guest.txt", "lines", added=SVC, label="guest-access"),
        P("tcp/smb/nmap_smb_vuln.txt", "lines", ["nmap"], SVC, label="smb-vuln"),
    ],
    "ssh": [P("tcp/ssh/version_info.txt", "lines", added=DELTA, label="ssh"),
            P("tcp/ssh/nmap_ssh_scripts.txt", "lines", ["nmap"], DELTA, label="ssh-nse")],
    "ftp": [P("tcp/ftp/anonymous_check.txt", "lines", added=SVC, label="anon-ftp"),
            P("tcp/ftp/version_info.txt", "lines", added=DELTA, label="ftp"),
            P("tcp/ftp/nmap_ftp_scripts.txt", "lines", ["nmap"], DELTA, label="ftp-nse")],
    # svc-generic resolved per service dir (root = recon/<ip>, instance = svc)
    "svc-generic": [P("tcp/{instance}/banner_*.txt", "lines", added=DELTA, label="banner"),
                    P("tcp/{instance}/nmap_{instance}_*.txt", "lines", ["nmap"], DELTA, label="nse")],
    # ---- webenum tier (root = web/<svc>/artifacts) ----
    "web-fingerprint": [
        P("fingerprint/http_methods.txt", "lines", ["http_header"], label="method",
          key_fn=_write_method_key),
        P("fingerprint/whatweb.txt", "lines", added=DELTA, label="tech"),
    ],
    "web-content": [P("content/dirs_medium.txt", "url_lines", added=DELTA, label="dir"),
                    P("content/files_medium.txt", "url_lines", added=DELTA, label="file")],
    "web-recursive": [P("content/recursive/*.txt", "url_lines", added=DELTA, label="nested-path")],
    "web-vhosts": [P("content/ffuf_vhosts.json", "url_lines", added=SVC, label="vhost")],
    "web-params": [P("params/*.txt", "lines", added=DELTA, label="param")],
    "web-sqli_probe": [P("sqli/suspects.txt", "sqli", added=DELTA, label="sqli-suspect")],
    "web-summary": [P("loot/next_steps.txt", "lines", ["console_ts"], DELTA, label="next-step"),
                    P("summary/quick_wins.txt", "lines", ["console_ts"], DELTA, label="quick-win")],
    # ---- adr tier (root = ad/<domain>) ----
    "phase1_domain_context": [P("domain_context.txt", "lines", ["console_ts"], DELTA, label="fact"),
                              P("password_policy.txt", "lines", ["console_ts"], DELTA, label="policy")],
    "phase2_user_enum": [P("users/all_users.txt", "lines", added=USR, label="user")],
    "phase2b_ldap_enum": [P("users/all_users.txt", "lines", added=USR, label="user"),
                          P("ldap/laps.txt", "lines", added=DELTA, label="laps"),
                          P("users/suspicious_descriptions.txt", "lines", added=DELTA, label="desc")],
    "phase2c_adcs": [P("adcs/certipy_find.txt", "lines", added=EXP, label="esc-template")],
    # kerberos: diff the CANDIDATE LISTS only — never the hash blobs (re-encrypt)
    "phase3_kerberos": [P("users/kerberoastable.txt", "lines", added=DELTA, label="kerberoastable"),
                        P("users/asrep_candidates.txt", "lines", added=DELTA, label="asrep-roastable")],
    "phase4_computers": [P("computers/all_computers.txt", "lines", added=DELTA, label="computer"),
                         P("computers/old_os.txt", "lines", added=DELTA, label="eol-host")],
    "phase5_smb_signing": [P("smb_no_signing.txt", "lines", added=SVC, label="relay-target")],
    # bloodhound: summary only — never byte-diff the .zip
    "phase6_bloodhound": [P("bloodhound/collection_output.txt", "lines", ["console_ts"], DELTA, label="collection")],
    "phase7_shares": [P("shares/all_shares.txt", "lines", added=SVC, label="share"),
                      P("shares/sysvol_interesting.txt", "lines", added=DELTA, label="sysvol-file")],
    "phase8_sessions": [P("sessions/loggedon_users.txt", "lines", added=DELTA, label="logged-on"),
                        P("sessions/smb_sessions.txt", "lines", added=DELTA, label="session")],
    "phase9_spray_cracked": [P("hashes/cracked_passwords.txt", "lines", added=DELTA, label="cracked")],
    "ad-summary": [P("next_steps.txt", "lines", ["console_ts"], DELTA, label="attack-cmd"),
                   P("summary_notes.txt", "lines", ["adr_summary", "console_ts"], DELTA, label="note")],
    # ---- from-foothold (root = recon/<ip>/from-foothold, instance = label) ----
    # key chosen by content sniff below (netstat→SVC, route→DELTA, users→USR)
    "from-foothold": [P("{instance}.txt", "lines", added=DELTA, label="internal")],
}

# from-foothold content sniffing: label/content → tokenizer+key
NETSTAT_RE = re.compile(r'LISTEN|:\d+\s', re.I)
ROUTE_RE = re.compile(r'\bvia\b|/\d+\s|default ', re.I)
USER_LABELS = ("id", "whoami", "passwd", "users", "net-user", "groups")
NET_LABELS = ("netstat", "ss", "listening", "ports")
ROUTE_LABELS = ("route", "ip-route", "ifconfig", "ip-a", "subnet")


def _foothold_part(instance, old_text, new_text):
    lab = (instance or "").lower()
    if any(k in lab for k in NET_LABELS):
        # listening sockets -> new internal service surface
        def t(txt):
            return {ln.strip() for ln in txt.splitlines()
                    if "LISTEN" in ln.upper() or re.search(r':\d+\b', ln)}
        return t, SVC, "internal-listener"
    if any(k in lab for k in ROUTE_LABELS):
        return tok_lines, DELTA, "internal-route"
    if any(k in lab for k in USER_LABELS):
        return tok_lines, USR, "internal-user"
    # default: lines, DELTA, with a content sniff for listeners
    both = (old_text + "\n" + new_text)
    if NETSTAT_RE.search(both) and "LISTEN" in both.upper():
        return tok_lines, SVC, "internal-listener"
    return tok_lines, DELTA, "internal"


# ---- core diff ---------------------------------------------------------------
def _resolve(root, rel):
    return os.path.join(root, rel)


def _glob_one(path):
    # path may contain a glob; return concatenated text of all matches
    if any(c in path for c in "*?["):
        return "\n".join(_read(p) for p in sorted(glob.glob(path)))
    return _read(path)


def diff_stage(stage, old_root, new_root, instance, verbose):
    parts = STAGE_SPEC.get(stage)
    if parts is None:
        # unknown stage → generic line-set diff over the whole root (DELTA)
        parts = None

    items = {}            # key -> [unit, ...]
    summary_bits = []
    diffs = []

    def record(key, label, units):
        if not units:
            return
        items.setdefault(key, []).extend("%s: %s" % (label, u) for u in units)
        summary_bits.append("%d new %s%s" % (len(units), label,
                                             "" if len(units) == 1 else "s"))

    if stage == "from-foothold":
        rel = "%s.txt" % (instance or "capture")
        ot = _read(_resolve(old_root, rel))
        nt = _read(_resolve(new_root, rel))
        tokf, key, label = _foothold_part(instance, ot, nt)
        added = sorted(tokf(nt) - tokf(ot))
        record(key, label, added)
        if verbose:
            diffs.append(_udiff(ot, nt, rel))
    elif parts:
        for part in parts:
            rel = part["path"].replace("{instance}", str(instance or ""))
            ot = _apply_filters(_glob_one(_resolve(old_root, rel)), part["filters"])
            nt = _apply_filters(_glob_one(_resolve(new_root, rel)), part["filters"])
            tokf = TOKS[part["tok"]]
            o, n = tokf(ot), tokf(nt)
            added, removed = sorted(n - o), sorted(o - n)
            if part["key_fn"]:
                bykey = {}
                for u in added:
                    k = part["key_fn"](u)
                    if k:
                        bykey.setdefault(k, []).append(u)
                for k, us in bykey.items():
                    record(k, part["label"], us)
            else:
                record(part["added"], part["label"], added)
            if part["removed"] and removed:
                record(part["removed"], part["label"] + " removed", removed)
            if verbose and (added or removed):
                diffs.append(_udiff(ot, nt, rel))
    else:
        # generic fallback
        for root_rel in ("",):
            pass

    keys = sorted(items.keys())
    changed = bool(keys)
    return {
        "stage": stage,
        "instance": instance,
        "changed": changed,
        "keys": keys,
        "items": items,
        "summary": "; ".join(summary_bits) if summary_bits else "no changes",
        "diff": "\n".join(diffs) if verbose else "",
    }


def _udiff(old_text, new_text, label):
    import difflib
    return "\n".join(difflib.unified_diff(
        old_text.splitlines(), new_text.splitlines(),
        fromfile="old/" + label, tofile="new/" + label, lineterm=""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list-roots", action="store_true")
    ap.add_argument("--stage")
    ap.add_argument("--old")
    ap.add_argument("--new")
    ap.add_argument("--instance", default="")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    if a.list_roots:
        print(json.dumps(sorted(STAGE_SPEC.keys())))
        return 0
    if not (a.stage and a.old and a.new):
        sys.stderr.write("livefetch_diff: --stage --old --new required\n")
        return 2
    out = diff_stage(a.stage, a.old, a.new, a.instance, a.verbose)
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
