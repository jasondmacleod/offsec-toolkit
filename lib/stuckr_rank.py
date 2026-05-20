#!/usr/bin/env python3
"""
stuckr_rank.py — symptom-map matcher + §6 ranker for stuckr.sh.

Reads the per-target state vector (key=value lines from lib/state.sh, plus a
target_count= line) on stdin. Loads lib/symptom_map.yaml and the exploitdb
corpus (data/seed/*.json). Emits pipe-delimited lines for stuckr.sh to render:

    sentinel|<key>|<context>
    fallback|broad-category
    ranked|<rank>|<slug>|<trigger>|<command>
    nofallback|<message>
    raw|<slug>|<title>

Usage:
    python3 stuckr_rank.py <symptom_map.yaml> <seed_dir> <ip> <top_n>
"""
import json
import os
import re
import sys
from collections import OrderedDict

import yaml


def main():
    if len(sys.argv) != 5:
        sys.stderr.write(
            "usage: stuckr_rank.py <symptom_map.yaml> <seed_dir> <ip> <top_n>\n")
        sys.exit(2)
    map_path, seed_dir, target_ip, top_n_s = sys.argv[1:5]
    top_n = int(top_n_s)

    state = {
        'ip': target_ip, 'os_guess': 'unknown',
        'foothold': 'no', 'privesc': 'no',
        'services': [], 'web_paths': [], 'web_vhosts': [],
        'smb_shares': [], 'ad_users': [], 'ad_computers': [],
        'sentinels': [], 'tried_slugs': set(),
        'creds': [], 'domain': '', 'dc_ip': '', 'target_count': 1,
    }
    keymap = {
        'ip': 'scalar', 'os_guess': 'scalar',
        'foothold': 'scalar', 'privesc': 'scalar',
        'services': 'ignore',   # aggregate line; we read repeated `service=`
        'service': ('list', 'services'),
        'web_path': ('list', 'web_paths'),
        'web_vhost': ('list', 'web_vhosts'),
        'smb_share': ('list', 'smb_shares'),
        'ad_user': ('list', 'ad_users'),
        'ad_computer': ('list', 'ad_computers'),
        'sentinel': ('list', 'sentinels'),
        'tried_slug': ('set', 'tried_slugs'),
        'cred': ('list', 'creds'),
        'domain': 'scalar', 'dc_ip': 'scalar',
        'target_count': 'scalar_int',
    }
    for line in sys.stdin:
        line = line.rstrip('\n')
        if not line or '=' not in line:
            continue
        k, v = line.split('=', 1)
        mapping = keymap.get(k)
        if mapping is None or mapping == 'ignore':
            continue
        if mapping == 'scalar':
            state[k] = v
        elif mapping == 'scalar_int':
            try:
                state[k] = int(v)
            except ValueError:
                state[k] = 1
        else:  # tuple
            kind, dest = mapping
            if kind == 'list':
                state[dest].append(v)
            elif kind == 'set':
                state[dest].add(v)

    # ---- corpus ----
    relevance_rank = {'critical': 4, 'high': 3, 'medium': 2,
                      'low': 1, 'unknown': 0, '': 0}
    corpus = {}
    for fn in os.listdir(seed_dir):
        if not fn.endswith('.json'):
            continue
        try:
            d = json.load(open(os.path.join(seed_dir, fn)))
        except Exception:
            continue
        for e in d.get('entries', []):
            slug = e.get('slug') or e.get('id')
            if not slug:
                continue
            corpus[slug] = {
                'category': d.get('category', ''),
                'exam_relevance': e.get('exam_relevance', 'unknown'),
                'title': e.get('title', slug),
                'commands': e.get('commands', []),
                'tech': e.get('tech', []) if isinstance(e.get('tech'), list) else [],
                'os': e.get('os', []) if isinstance(e.get('os'), list) else [],
            }

    # ---- symptom map ----
    with open(map_path) as f:
        sym_map = yaml.safe_load(f) or []
    sym_by_key = {e['symptom']: e for e in sym_map if 'symptom' in e}

    # ---- preconditions ----
    def svc_match(*needles):
        for svc in state['services']:
            sl = svc.lower()
            for n in needles:
                if n in sl:
                    return True
        return False

    def precond_ok(req):
        if req == 'creds':           return len(state['creds']) > 0
        if req == 'foothold':        return state['foothold'] == 'yes'
        if req == 'domain-context':  return bool(state['domain'])
        if req == 'adjacent-host':   return state['target_count'] > 1
        if req == 'web-app':         return svc_match('http')
        if req == 'windows-host':    return state['os_guess'] == 'windows'
        if req == 'linux-host':      return state['os_guess'] == 'linux'
        if req == 'ad-context':      return bool(state['domain']) or bool(state['dc_ip'])
        if req == 'smb-port':        return any(s.startswith(('445/', '139/')) for s in state['services'])
        if req == 'db-port':         return svc_match('mysql', 'mssql', 'postgres', 'ms-sql')
        return False  # unknown precondition fails closed

    category_prio = {'foothold': 0, 'privesc': 1, 'lateral': 2, 'recon-extension': 3}

    # ---- §6 step 1: trigger match ----
    seen_sentinels = OrderedDict()
    matched_sym = []
    for s in state['sentinels']:
        if s in sym_by_key:
            if s not in seen_sentinels:
                seen_sentinels[s] = sym_by_key[s]['context']
                matched_sym.append(s)

    candidates = []
    for sk in matched_sym:
        entry = sym_by_key[sk]
        for action in entry.get('actions', []):
            candidates.append({
                'slug': action['slug'],
                'match_strength': action.get('match_strength', 'moderate'),
                'category': entry.get('category', 'recon-extension'),
                'requires': action.get('requires', []) or [],
                'symptom': sk,
                'context': entry.get('context', ''),
            })

    fallback_used = None
    # §7 broad-category fallback (services present, no sentinel match).
    # Lifecycle-filter the corpus by foothold state: pre-foothold pulls
    # foothold-producing categories only (recon_enum, active_directory,
    # web_exploits, sqli). Post-foothold pulls privesc/loot.
    if not candidates and state['services']:
        fallback_used = 'broad-category'
        svc_tokens = set()
        for svc in state['services']:
            parts = svc.split('/')
            if len(parts) >= 3:
                sname = parts[2].lower()
                svc_tokens.add(sname)
                for t in re.split(r'[-_]', sname):
                    if t:
                        svc_tokens.add(t)
        if state['foothold'] == 'yes':
            allowed_cats = {'linux_privesc', 'privesc',
                            'post_exploitation_loot', 'passwords_hashes'}
        else:
            allowed_cats = {'recon_enum', 'active_directory',
                            'web_exploits', 'sqli'}
        for slug, e in corpus.items():
            if e['category'] not in allowed_cats:
                continue
            for t in e['tech']:
                tl = t.lower()
                if tl in svc_tokens:
                    candidates.append({
                        'slug': slug, 'match_strength': 'moderate',
                        'category': 'recon-extension',
                        'requires': [],
                        'symptom': '(service-only fallback)',
                        'context': f"service {tl} present — no sentinels yet, broad enumeration",
                    })
                    break

    # §6 step 2: precondition filter
    candidates = [c for c in candidates
                  if all(precond_ok(r) for r in c['requires'])]
    # §6 step 3: exclude tried
    candidates = [c for c in candidates
                  if c['slug'] not in state['tried_slugs']]

    # §6 step 4: sort
    strength_rank = {'strong': 0, 'moderate': 1, 'weak': 2}

    def sort_key(c):
        e = corpus.get(c['slug'])
        rel = e['exam_relevance'] if e else 'unknown'
        return (
            -relevance_rank.get(rel, 0),
            strength_rank.get(c['match_strength'], 2),
            category_prio.get(c['category'], 3),
            c['slug'],
        )
    candidates.sort(key=sort_key)

    # dedupe by slug
    seen = set()
    uniq = []
    for c in candidates:
        if c['slug'] in seen:
            continue
        seen.add(c['slug'])
        uniq.append(c)
    candidates = uniq[:top_n]

    # ---- IP / creds / domain substitution ----
    # Corpus conventions (from audit of all 444 commands):
    #   TARGET          → target IP        (214 uses)
    #   corp.local      → domain           (108 uses)
    #   KALI_IP         → attacker IP      (95 uses, left alone — operator-side)
    #   jdoe            → username         (50 uses)
    #   'Password1'     → password         (49 uses)
    #   10.10.10.5      → target IP (older corpus convention, ~17 uses)
    # Substitute lab example IPs in a corpus command with the actual target
    # IP. Per spec §8 "Commands are ready as-shown." Lab subnets are
    # 10.10.10/24, 10.10.11/24, RFC1918 — EXCEPT 10.10.14/24 which is the
    # Kali/attacker side of the OffSec+ VPN and must stay literal.
    ip_re = re.compile(
        r'\b(?:10\.10\.(?:10|11|12|13)\.\d+|192\.168\.\d+\.\d+|'
        r'172\.16\.\d+\.\d+|<TARGET(?:_IP)?>|<IP>|<RHOST>|<HOST>)\b')

    user, password = '', ''
    for c in state['creds']:
        if ':' in c and not c.startswith(':'):
            parts = c.split(':', 1)
            user, password = parts[0], parts[1]
            break

    def substitute(cmd):
        out = cmd
        out = ip_re.sub(target_ip, out)
        out = re.sub(r'\bTARGET\b', target_ip, out)
        if user:
            out = re.sub(r'<USER(?:NAME)?>', user, out)
            out = re.sub(r'\bjdoe\b', user, out)
        if password:
            out = re.sub(r'<PASS(?:WORD)?>', password, out)
            out = out.replace("'Password1'", f"'{password}'")
        if state['domain']:
            out = re.sub(r'<DOMAIN>', state['domain'], out)
            out = re.sub(r'\bcorp\.local\b', state['domain'], out)
        return out

    # Command picker: prefer a command that actually targets the host
    # (contains a literal IP placeholder, the bare TARGET token, or one of
    # the angle-bracket placeholders) over install/setup/check commands
    # like `pipx install …` or `cat $TOOLKIT_ROOT/…` that appear first in
    # many corpus entries.
    # Deliberately NOT including `corp.local` or `jdoe` — they appear in
    # file paths and prose contexts where the command isn't actually
    # talking to a target.
    TARGET_HINT_RE = re.compile(
        r'\b(?:10\.10\.\d+\.\d+|192\.168\.\d+\.\d+|172\.16\.\d+\.\d+|'
        r'TARGET|<TARGET(?:_IP)?>|<IP>|<RHOST>|<HOST>)\b')

    def first_command(slug):
        e = corpus.get(slug)
        if not e or not e['commands']:
            return ''
        cmds = []
        for c in e['commands']:
            if isinstance(c, dict):
                cmds.append(c.get('cmd', ''))
            elif isinstance(c, str):
                cmds.append(c)
        cmds = [c for c in cmds if c]
        if not cmds:
            return ''
        for c in cmds:
            if TARGET_HINT_RE.search(c):
                return c
        return cmds[0]

    # ---- emit ----
    out = []
    for s, ctx in seen_sentinels.items():
        out.append(f"sentinel|{s}|{ctx}")
    if fallback_used and not state['sentinels']:
        out.append(f"fallback|{fallback_used}")

    if candidates:
        for i, c in enumerate(candidates, 1):
            cmd = substitute(first_command(c['slug']))
            if '<' in cmd:
                cmd += "    # replace remaining <…> placeholders with discovered values"
            out.append(f"ranked|{i}|{c['slug']}|{c['context']}|{cmd}")
    else:
        if state['services']:
            out.append("nofallback|state present but no symptom or category match")
            # §9 case B: raw alternates from broad-enum category — the operator
            # is staring at a quirky banner with no symptom-map hook, so the
            # right surface is general recon, not whatever happens to have
            # `critical` exam_relevance globally.
            raw_pool = [(s, e) for s, e in corpus.items()
                        if e['category'] == 'recon_enum']
            ranked_raw = sorted(
                raw_pool,
                key=lambda kv: -relevance_rank.get(kv[1]['exam_relevance'], 0)
            )[:5]
            for slug, e in ranked_raw:
                out.append(f"raw|{slug}|{e['title']}")

    sys.stdout.write('\n'.join(out) + ('\n' if out else ''))


if __name__ == '__main__':
    main()
