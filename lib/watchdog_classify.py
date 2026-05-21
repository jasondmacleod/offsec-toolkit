#!/usr/bin/env python3
"""
watchdog_classify.py — liveness classifier for watchdog.sh.

Reads Kali-side surface snapshots (captured by watchdog.sh) from file paths
given as argv, classifies every shell / tunnel / listener into a pinned
liveness vocabulary, and emits a single JSON object on stdout.

Pure transform: no subprocess, no socket, no state mutation. Every input is a
file the orchestrator captured (ps, ss, tmux, ip-route, foothold + pivot state)
so the demo can feed synthetic surfaces.

argv (all optional; a missing path is treated as empty):
  --ps PATH            ps -eo pid,ppid,etime,comm,args --no-headers
  --ss-est PATH        ss -tinp state established
  --ss-listen PATH     ss -tlnp
  --tmux PATH          tmux list-panes -aF '<sess>:<w>.<p> <pid> <dead> <cmd>'
  --routes PATH        per foothold IP: "<ip> <ip route get output | FAILED>"
  --footholds PATH     state_read_footholds rows: ip\\tts\\tuser\\tmethod\\tsrc
  --pivots PATH        state_read_pivots rows:    kind\\tvalue\\textra
  --idle-shells-ms N   STALE threshold for shells   (default 14400000 = 4h)
  --idle-tunnels-ms N  STALE threshold for tunnels  (default 1800000 = 30m)
  --uid N              invoking uid (informational, echoed in JSON)
  --type T             filter output to one of: shell|tunnel|listener|all
  --target IP          filter shells/footholds to one target IP
  --timestamp ISO      override output timestamp (tests); default = now (UTC)

Liveness vocabulary (frozen):
  class       ALIVE | STALE | DEAD | UNKNOWN
  type        shell | tunnel | listener      (file-servers = listener + flag)
  STALE       idle = min(lastsnd,lastrcv) >= threshold; shells 4h, tunnels 30m;
              tunnels also STALE on process-up + zero ESTABLISHED. Listeners
              never STALE (a quiet listener is healthy).
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone


# ── holder vocabulary (17 tokens, frozen Chunk 1+2) ──────────────────────────
# Identification = rightmost recognized token in the wrapper chain (rule R1):
# argv is scanned token-wise, wrappers never match a holder rule, the rightmost
# matching token wins. Wrappers listed for documentation; they simply fail every
# holder rule below.
WRAPPERS = {'rlwrap', 'proxychains', 'proxychains4', 'sudo', 'nohup',
            'timeout', 'stdbuf', 'env'}

IMPACKET_PERSISTENT = {'wmiexec', 'smbexec'}


def _basename(tok):
    # strip a leading path and a trailing .py so /usr/share/.../psexec.py → psexec
    b = tok.rsplit('/', 1)[-1]
    if b.endswith('.py'):
        b = b[:-3]
    if b.startswith('impacket-'):
        b = b[len('impacket-'):]
    return b


def identify_holder(args):
    """Return (token, types) for the rightmost recognized holder, or (None,None).

    types is a tuple drawn from {'shell','tunnel','listener'} describing what
    resource roles this holder can occupy; classification decides the actual
    state per resource.
    """
    toks = args.split()
    best = None  # (index, token, types)
    for i, raw in enumerate(toks):
        b = _basename(raw)
        hit = None
        if b == 'penelope':
            hit = ('penelope', ('shell', 'listener'))
        elif b in ('nc', 'ncat') and any(t.startswith('-') and 'l' in t for t in toks[i + 1:]):
            hit = ('nc-listen', ('listener',))
        elif b == 'msfconsole':
            hit = ('msf-handler', ('listener',))
        elif b == 'ligolo-proxy':
            hit = ('ligolo-proxy', ('tunnel', 'listener'))
        elif b == 'chisel':
            rest = toks[i + 1:]
            if 'server' in rest:
                hit = ('chisel-server', ('tunnel', 'listener'))
            elif 'client' in rest:
                hit = ('chisel-client', ('tunnel',))
        elif b == 'sshuttle':
            hit = ('sshuttle', ('tunnel',))
        elif b == 'ssh':
            flags = ''.join(t for t in toks[i + 1:] if t.startswith('-'))
            if any(f in flags for f in ('L', 'D', 'R', 'N')):
                hit = ('ssh-tunnel', ('tunnel',))
            else:
                hit = ('ssh-interactive', ('shell',))
        elif b == 'evil-winrm':
            hit = ('evil-winrm', ('shell',))
        elif b == 'psexec':
            hit = ('impacket-psexec', ('shell',))
        elif b in IMPACKET_PERSISTENT:
            hit = ('impacket-exec-persistent', ('shell',))
        elif b == 'atexec':
            hit = ('impacket-atexec', ())  # non-persistent; observe-only
        elif b == 'mssqlclient':
            hit = ('impacket-mssqlclient', ('shell',))
        elif b == 'smbserver':
            hit = ('file-server-smb', ('listener',))
        elif b == 'pyftpdlib':
            hit = ('file-server-ftp', ('listener',))
        elif raw == 'http.server' or b == 'http.server':
            hit = ('file-server-http', ('listener',))
        if hit:
            best = (i, hit[0], hit[1])
    if best:
        return best[1], best[2]
    return None, None


FILE_SERVERS = {'file-server-http', 'file-server-smb', 'file-server-ftp'}
TUNNEL_HOLDERS = {'ligolo-proxy', 'chisel-server', 'chisel-client',
                  'sshuttle', 'ssh-tunnel'}


# ── surface parsers ──────────────────────────────────────────────────────────
def _read(path):
    if not path or not os.path.isfile(path):
        return ''
    with open(path, 'r', errors='replace') as f:
        return f.read()


def parse_ps(path):
    procs = {}
    for line in _read(path).splitlines():
        line = line.rstrip('\n')
        if not line.strip():
            continue
        parts = line.split(None, 4)
        if len(parts) < 5:
            # process with no args column — pad
            parts += [''] * (5 - len(parts))
        try:
            pid = int(parts[0]); ppid = int(parts[1])
        except ValueError:
            continue
        holder, types = identify_holder(parts[4])
        procs[pid] = {
            'pid': pid, 'ppid': ppid, 'etime': parts[2],
            'comm': parts[3], 'args': parts[4],
            'holder': holder, 'types': types,
        }
    return procs


_USERS_PID_RE = re.compile(r'pid=(\d+)')
_ADDR_RE = re.compile(r'^(.*):(\d+)$')


def _split_addr(token):
    m = _ADDR_RE.match(token)
    if not m:
        return token, None
    ip = m.group(1)
    if ip.startswith('[') and ip.endswith(']'):
        ip = ip[1:-1]
    try:
        return ip, int(m.group(2))
    except ValueError:
        return ip, None


def parse_ss_est(path):
    """Pair each socket header line with its following indented info line."""
    conns = []
    cur = None
    for line in _read(path).splitlines():
        if not line.strip():
            continue
        if re.match(r'^\s', line):  # indented → info for the current socket
            if cur is not None:
                snd = re.search(r'lastsnd:(\d+)', line)
                rcv = re.search(r'lastrcv:(\d+)', line)
                cur['lastsnd'] = int(snd.group(1)) if snd else None
                cur['lastrcv'] = int(rcv.group(1)) if rcv else None
            continue
        parts = line.split()
        if not parts or parts[0] in ('Recv-Q', 'State'):
            continue  # header
        # ss -tn established: Recv-Q Send-Q Local Peer [users:(...)]
        if len(parts) < 4:
            continue
        local_ip, local_port = _split_addr(parts[2])
        peer_ip, peer_port = _split_addr(parts[3])
        pid = None
        m = _USERS_PID_RE.search(line)
        if m:
            pid = int(m.group(1))
        cur = {'local_ip': local_ip, 'local_port': local_port,
               'peer_ip': peer_ip, 'peer_port': peer_port,
               'pid': pid, 'lastsnd': None, 'lastrcv': None}
        conns.append(cur)
    return conns


def parse_ss_listen(path):
    lis = []
    for line in _read(path).splitlines():
        parts = line.split()
        if not parts or parts[0] in ('State', 'Recv-Q'):
            continue
        # ss -tlnp: State Recv-Q Send-Q Local Peer [users:(...)]
        if len(parts) < 4:
            continue
        local_ip, local_port = _split_addr(parts[3])
        pid = None
        m = _USERS_PID_RE.search(line)
        if m:
            pid = int(m.group(1))
        lis.append({'local_ip': local_ip, 'local_port': local_port, 'pid': pid})
    return lis


def parse_tmux(path):
    dead = {}
    for line in _read(path).splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            pane_pid = int(parts[1])
        except ValueError:
            continue
        dead[pane_pid] = (parts[2] == '1')
    return dead


_DEV_RE = re.compile(r'\bdev\s+(\S+)')


def parse_routes(path):
    routes = {}
    for line in _read(path).splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        ip = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
        if rest.strip() == 'FAILED' or not rest.strip():
            routes[ip] = None  # unresolved
            continue
        m = _DEV_RE.search(rest)
        routes[ip] = m.group(1) if m else None
    return routes


def parse_footholds(path):
    rows = []
    for line in _read(path).splitlines():
        f = line.split('\t')
        if len(f) < 5:
            continue
        rows.append({'ip': f[0], 'ts': f[1], 'user': f[2],
                     'method': f[3], 'src': f[4]})
    return rows


def parse_pivots(path):
    tunnels = []   # (mode, config) in file order; last per mode is canonical
    tuns = set()
    processes = []
    for line in _read(path).splitlines():
        f = line.split('\t')
        if len(f) < 2:
            continue
        kind = f[0]
        val = f[1]
        extra = f[2] if len(f) > 2 else ''
        if kind == 'tunnel':
            tunnels.append((val, extra))
        elif kind == 'tun':
            tuns.add(val)
        elif kind == 'process':
            try:
                processes.append({'pid': int(val), 'label': extra})
            except ValueError:
                pass
    # canonical = last entry per mode
    canon = {}
    for mode, cfg in tunnels:
        canon[mode] = cfg
    return {'tunnels': canon, 'tuns': tuns, 'processes': processes}


# ── helpers ──────────────────────────────────────────────────────────────────
def _conn_idle(conn):
    vals = [v for v in (conn.get('lastsnd'), conn.get('lastrcv')) if v is not None]
    return min(vals) if vals else None


def _is_ligolo_magic(ip):
    try:
        return 240 <= int(ip.split('.')[0]) <= 255
    except (ValueError, IndexError):
        return False


def _pane_dead_for(pid, procs, tmux_dead):
    """Walk the ppid chain from pid; True if an ancestor owns a dead pane."""
    seen = set()
    cur = pid
    while cur and cur not in seen:
        seen.add(cur)
        if tmux_dead.get(cur):
            return True
        p = procs.get(cur)
        if not p:
            break
        cur = p['ppid']
    return False


def _route_flag(ip, routes, tuns):
    dev = routes.get(ip, '__missing__')
    if dev == '__missing__' or dev is None:
        return 'route-unresolved'
    if dev in tuns:
        return 'ligolo:' + dev
    return 'direct'


# ── classification ───────────────────────────────────────────────────────────
def classify_shells(footholds, procs, est, routes, tuns, tmux_dead, idle_ms):
    """One resource per foothold IP (penelope multiplexes — per-line attribution
    is unavailable, so footholds for the same IP collapse into one row)."""
    by_ip = {}
    for fh in footholds:
        by_ip.setdefault(fh['ip'], []).append(fh)

    # index established by peer ip
    est_by_peer = {}
    for c in est:
        est_by_peer.setdefault(c['peer_ip'], []).append(c)
    # penelope relay conns: peer in 240/4, owned by a penelope holder
    relay_conns = [c for c in est
                   if _is_ligolo_magic(c['peer_ip'])
                   and procs.get(c['pid'], {}).get('holder') == 'penelope']

    resources = []
    for ip, lines in sorted(by_ip.items()):
        direct = est_by_peer.get(ip, [])
        route = _route_flag(ip, routes, tuns)
        flags = []
        note = ''
        holder = None
        established = 0
        idle = None
        cls = 'DEAD'

        if direct:
            established = len(direct)
            pids = [c['pid'] for c in direct if c['pid']]
            if not pids:
                cls = 'UNKNOWN'
                note = ('connection(s) to %s ESTABLISHED but holder PID '
                        'unattributable — run watchdog as root (sudo)' % ip)
            else:
                holder = procs.get(pids[0], {}).get('holder')
                idles = [v for v in (_conn_idle(c) for c in direct) if v is not None]
                idle = min(idles) if idles else None
                if any(_pane_dead_for(p, procs, tmux_dead) for p in pids):
                    cls = 'DEAD'
                    note = 'owning tmux pane is dead (orphaned holder)'
                elif idle is not None and idle >= idle_ms:
                    cls = 'STALE'
                else:
                    cls = 'ALIVE'
        elif route.startswith('ligolo:') and relay_conns:
            # Option α relay case: F is behind a ligolo tun, and penelope holds
            # ESTABLISHED in the 240/4 magic range. Attribute heuristically.
            established = len(relay_conns)
            idles = [v for v in (_conn_idle(c) for c in relay_conns) if v is not None]
            idle = min(idles) if idles else None
            holder = 'penelope'
            pids = [c['pid'] for c in relay_conns if c['pid']]
            if any(_pane_dead_for(p, procs, tmux_dead) for p in pids):
                cls = 'DEAD'
                note = 'owning tmux pane is dead (orphaned holder)'
            elif idle is not None and idle >= idle_ms:
                cls = 'STALE'
            else:
                cls = 'ALIVE'
            if len(by_ip) > 1:
                note = ('relay attribution via %s magic-range ESTABLISHED — '
                        'shared if multiple footholds route through this tun'
                        % route)
        else:
            cls = 'DEAD'
            if route.startswith('ligolo:'):
                flags.append('relay-blindspot')
                note = ('%s is behind ligolo tun — listener_add-relayed shells '
                        'are not peer-attributable; verify in penelope' % ip)
            elif not est:
                note = 'no holder process / no ESTABLISHED to %s' % ip

        resources.append({
            'type': 'shell', 'class': cls,
            'holder': holder or '(none)', 'ip': ip,
            'port': (direct[0]['local_port'] if direct else None),
            'established': established,
            'idle_ms': idle, 'route': route,
            'foothold_lines': len(lines), 'flags': flags,
            'pid': (next((c['pid'] for c in direct if c['pid']), None)
                    if direct else None),
            'note': note,
        })
    return resources


def classify_tunnels(pivots, procs, est, idle_ms):
    """v1: liveness = backing process present + ESTABLISHED. TUN-iface/route
    presence checks deferred to v2 (pivotr.sh status covers full infra)."""
    resources = []
    holders_by_token = {}
    for p in procs.values():
        if p['holder']:
            holders_by_token.setdefault(p['holder'], []).append(p)
    est_by_pid = {}
    for c in est:
        if c['pid']:
            est_by_pid.setdefault(c['pid'], []).append(c)

    mode_to_holder = {'ligolo': 'ligolo-proxy', 'chisel': 'chisel-server'}
    for mode, cfg in sorted(pivots['tunnels'].items()):
        token = mode_to_holder.get(mode)
        # chisel may be server or client; accept either
        candidates = list(holders_by_token.get(token, []))
        if mode == 'chisel':
            candidates += holders_by_token.get('chisel-client', [])
        flags = []
        note = ''
        if not candidates:
            cls, established, idle, pid, holder = 'DEAD', 0, None, None, token
            note = 'no live %s process (state.tsv baseline, recorded PID stale/gone)' % token
        else:
            proc = candidates[0]
            holder = proc['holder']
            pid = proc['pid']
            conns = est_by_pid.get(pid, [])
            established = len(conns)
            idles = [v for v in (_conn_idle(c) for c in conns) if v is not None]
            idle = min(idles) if idles else None
            if established == 0:
                cls = 'STALE'
                note = 'process up, zero ESTABLISHED (agent disconnected)'
            elif idle is not None and idle >= idle_ms:
                cls = 'STALE'
            else:
                cls = 'ALIVE'
        resources.append({
            'type': 'tunnel', 'class': cls, 'holder': holder, 'ip': None,
            'port': None, 'established': established, 'idle_ms': idle,
            'route': None, 'foothold_lines': 0, 'flags': flags,
            'pid': pid, 'note': '%s | %s' % (cfg, note) if note else cfg,
        })
    return resources


def classify_listeners(procs, listen, est):
    """Observation-only. A bound listener is ALIVE (quiet is healthy)."""
    resources = []
    est_by_pid = {}
    for c in est:
        if c['pid']:
            est_by_pid.setdefault(c['pid'], []).append(c)
    listen_by_pid = {}
    for ls in listen:
        if ls['pid']:
            listen_by_pid.setdefault(ls['pid'], []).append(ls)

    for pid, lss in sorted(listen_by_pid.items()):
        proc = procs.get(pid)
        if not proc or not proc['holder']:
            continue
        holder = proc['holder']
        if 'listener' not in (proc['types'] or ()):
            continue
        ports = sorted({ls['local_port'] for ls in lss if ls['local_port']})
        flags = []
        if holder == 'nc-listen':
            flags.append('nc-warn')
        if holder == 'msf-handler':
            flags.append('msf-allowance')
        if holder in FILE_SERVERS:
            flags.append('file-server')
        established = len(est_by_pid.get(pid, []))
        resources.append({
            'type': 'listener', 'class': 'ALIVE', 'holder': holder, 'ip': None,
            'port': (ports[0] if ports else None),
            'established': established, 'idle_ms': None, 'route': None,
            'foothold_lines': 0, 'flags': flags, 'pid': pid,
            'note': ('ports ' + ','.join(str(p) for p in ports)) if len(ports) > 1 else '',
        })
    return resources


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--ps'); ap.add_argument('--ss-est')
    ap.add_argument('--ss-listen'); ap.add_argument('--tmux')
    ap.add_argument('--routes'); ap.add_argument('--footholds')
    ap.add_argument('--pivots')
    ap.add_argument('--idle-shells-ms', type=int, default=14400000)
    ap.add_argument('--idle-tunnels-ms', type=int, default=1800000)
    ap.add_argument('--uid', type=int, default=-1)
    ap.add_argument('--type', default='all')
    ap.add_argument('--target', default='')
    ap.add_argument('--timestamp', default='')
    a = ap.parse_args()

    procs = parse_ps(a.ps)
    est = parse_ss_est(a.ss_est)
    listen = parse_ss_listen(a.ss_listen)
    tmux_dead = parse_tmux(a.tmux)
    routes = parse_routes(a.routes)
    footholds = parse_footholds(a.footholds)
    pivots = parse_pivots(a.pivots)

    if a.target:
        footholds = [f for f in footholds if f['ip'] == a.target]

    resources = []
    if a.type in ('all', 'shell'):
        resources += classify_shells(footholds, procs, est, routes,
                                      pivots['tuns'], tmux_dead, a.idle_shells_ms)
    if a.type in ('all', 'tunnel'):
        resources += classify_tunnels(pivots, procs, est, a.idle_tunnels_ms)
    if a.type in ('all', 'listener'):
        resources += classify_listeners(procs, listen, est)

    summary = {'alive': 0, 'stale': 0, 'dead': 0, 'unknown': 0}
    for r in resources:
        summary[r['class'].lower()] = summary.get(r['class'].lower(), 0) + 1

    footer = []
    if any('proxychains' in (p['args']) for p in procs.values()):
        footer.append('proxychains client(s) detected — verify underlying '
                      'SOCKS separately')

    ts = a.timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    out = {'timestamp': ts, 'uid': a.uid, 'summary': summary,
           'resources': resources, 'footer_notes': footer}
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
