# TPC — Terminal Port Crawler Wiki

**Version:** 1.3.0
**Author:** Andrew Cappelli
**Repository:** [Andrew-most-likely/Terminal-Port-Crawler](https://github.com/Andrew-most-likely/Terminal-Port-Crawler)

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Modes of Operation](#modes-of-operation)
4. [CLI Mode](#cli-mode)
5. [TUI Mode](#tui-mode)
6. [Target Formats](#target-formats)
7. [Scan Modes](#scan-modes)
8. [UDP Scanning](#udp-scanning)
9. [Banner Grabbing](#banner-grabbing)
10. [OS Fingerprinting](#os-fingerprinting)
11. [Threat Analysis & CVEs](#threat-analysis--cves)
12. [Exporting Results](#exporting-results)
13. [Scan History](#scan-history)
14. [Service Categories](#service-categories)
15. [Keybindings (TUI)](#keybindings-tui)
16. [Legal Disclaimer](#legal-disclaimer)

---

## Overview

TPC is a Python-based network reconnaissance tool for TCP/UDP port scanning. It performs:

- TCP and UDP port scanning
- Service identification and categorization
- Banner grabbing
- OS fingerprinting
- Threat analysis with CVE references
- Multi-format export (TXT, CSV, JSON, HTML)
- Persistent scan history

It runs in two modes: a full-screen **TUI** (Terminal User Interface) for interactive use, and a **CLI** (Command Line Interface) for scripting and automation.

---

## Installation

### Option 1 — Pre-built executable (Windows, no Python required)

Download `tpc.exe` from the [Releases](https://github.com/Andrew-most-likely/Terminal-Port-Crawler/releases) page and run it directly from any terminal.

### Option 2 — From source

```bash
git clone https://github.com/Andrew-most-likely/Terminal-Port-Crawler
cd Terminal-Port-Crawler
pip install -e .
```

**Requirements:**
- Python >= 3.9
- pip >= 21.3
- `textual >= 0.50.0`

After install, the `tpc` command is available globally.

---

## Modes of Operation

| Mode | How to invoke | Best for |
|------|---------------|----------|
| **TUI** | `tpc` (no arguments) | Interactive use, visual results |
| **CLI** | `tpc -t <target> [options]` | Scripting, automation, quick scans |

---

## CLI Mode

### Usage

```
tpc -t <target> [options]
```

### Flags

| Flag | Long form | Description | Default |
|------|-----------|-------------|---------|
| `-t` | `--target` | Target to scan (IP, hostname, CIDR, or range) | **Required** |
| `-p` | `--ports` | Port range as `START-END` | `1-1024` |
| `-m` | `--mode` | Scan mode: `fast`, `random`, `slow` | `fast` |
| `--delay` | | Delay in seconds between ports (slow mode only) | `0.5` |
| `--udp` | | Also scan known UDP ports in the range | off |
| `-b` | `--banners` | Grab service banners from open ports | off |
| `-e` | `--export` | Export format: `txt`, `csv`, `json`, `html` | none |

### Examples

```bash
# Scan common ports on a single IP
tpc -t 192.168.1.1

# Full port range scan
tpc -t 192.168.1.1 -p 1-65535

# Scan a subnet
tpc -t 192.168.1.0/24

# Scan a dash range
tpc -t 192.168.1.1-50

# Random order scan
tpc -t 192.168.1.1 -m random

# Slow scan with 2-second delay
tpc -t 192.168.1.1 -m slow --delay 2.0

# Include UDP ports
tpc -t 192.168.1.1 --udp

# Grab banners and export as JSON
tpc -t 192.168.1.1 -b -e json

# Full featured scan
tpc -t 192.168.0.0/24 -p 1-10000 -m random --udp -b -e html
```

### CLI Output

```
OPEN  22    SSH      TCP/UDP/SCTP
OPEN  80    HTTP     TCP/UDP/SCTP
OPEN  443   HTTPS    TCP/UDP/SCTP

Done | 3 open | 4.21s | OS: Linux / Unix | Risk: LOW
```

---

## TUI Mode

### Launching

```bash
tpc
```

On startup, a **Legal Disclaimer** modal appears. You must click **"I Agree"** to proceed.

### Layout

```
┌─ Sidebar ──────────┬─ Main Panel ──────────────────────────────┐
│ Target input       │ [Results] [Analysis] [History] [Credits]  │
│ Port range         │                                            │
│ Scan mode          │  Results table / Analysis logs /          │
│ Options            │  History log / Credits                     │
│ Buttons            │                                            │
│ Live stats         │                                            │
└────────────────────┴────────────────────────────────────────────┘
│ Status message                          [====== 64% ========]  │
└────────────────────────────────────────────────────────────────┘
```

### Sidebar Controls

**Target Input**
Text field — accepts any supported target format (see [Target Formats](#target-formats)).

**Port Range**
Radio buttons:
- Well-known `1–1024` (default)
- Common `1–5000`
- Full `1–65535`
- Custom — reveals start/end input fields when selected

**Scan Mode**
Radio buttons:
- Fast (default)
- Random Order
- Slow — reveals a delay input field (default: `0.5` seconds)

**Options**
- `Scan UDP ports` checkbox
- `Threads:` input field (default: `100`)

**Buttons**

| Button | Enabled when | Action |
|--------|--------------|--------|
| Scan | Always | Starts the scan |
| Stop | Scan running | Cancels the scan |
| Banners | Scan complete with results | Grabs banners from open ports |
| Export | Scan complete with results | Opens export format dialog |
| New Scan | Always | Clears results and resets the UI |

**Live Stats Box**
Shows a live count of open ports grouped by category (Web, Email, File, Network, Windows, Security, Database, Remote, VMware) as scanning progresses.

### Tabs

**Results**
DataTable with columns: IP, Hostname, Port, Category, Service, Protocols, Banner.

**Analysis**
Log showing OS fingerprint, risk level, elapsed time, high/medium risk findings, and CVE references.

**History**
Displays all past scans loaded from `~/.tpc/scan_history.log`.

**Credits**
Author information.

### Modals

**Disclaimer (on startup)**
Legal warning with "I Agree" and "Exit" buttons.

**Export Dialog (`Ctrl+E`)**
Buttons: Plain Text, CSV, JSON, HTML Report, Cancel.

**About Screen (`F1`)**
Keybindings reference and target format examples. Dismiss with `Esc`, `Q`, or the Close button.

---

## Target Formats

| Format | Example | Behavior |
|--------|---------|----------|
| Single IP | `192.168.1.1` | Scans one host |
| Hostname | `router.local` | Resolved via DNS, then scanned |
| CIDR subnet | `192.168.1.0/24` | Expands to all host IPs (excludes network/broadcast) |
| Dash range | `192.168.1.1-50` | Expands to `.1` through `.50` |

Hostnames are resolved with `socket.gethostbyname()`. Reverse DNS is also attempted for display in results and exports.

---

## Scan Modes

| Mode | How it works | Use case |
|------|-------------|----------|
| `fast` | Threaded (100 workers by default), ports in order | Default — fastest scan |
| `random` | Threaded, ports in shuffled order | Evades simple sequential detection |
| `slow` | Sequential, one port at a time with a configurable delay | Low-and-slow, stealthy scanning |

**Thread count** is configurable in TUI via the Threads input (default: 100). CLI always uses 100 workers.

**Delay** (slow mode only) is set via `--delay` in CLI or the delay input field in TUI. Applies a `sleep()` between each port check.

---

## UDP Scanning

Enable with `--udp` (CLI) or the "Scan UDP ports" checkbox (TUI).

TPC scans only **known UDP ports** that fall within your selected port range.

**Detection method:**
- Sends 8 null bytes to each UDP port
- If a response is received → port is **open**
- If timeout occurs → port is treated as **open/filtered** (following nmap convention)
- If `ConnectionRefusedError` → port is **closed**

UDP results appear in the results table after all TCP scanning completes.

---

## Banner Grabbing

Enable with `-b` / `--banners` (CLI) or the **Banners** button (TUI).

For each open TCP port:

1. If the port is in the SSL list (`443, 465, 636, 993, 995, 990, 989, 8443`) → returns `SSL/TLS encrypted`
2. Connects with a 2-second timeout and attempts `recv(1024)`
3. If no response, sends an HTTP HEAD request and retries
4. Returns the first 80 characters of the first response line
5. Returns `no banner` if nothing is received

---

## OS Fingerprinting

TPC infers the operating system from open port patterns:

| Condition | OS Guess |
|-----------|----------|
| Ports 135 and 445 open | Windows |
| Ports 135, 445, and 902/912 open | Windows + VMware |
| Ports 902 or 912 open (no 445) | VMware Host / Linux |
| Port 548 open (no 445) | macOS (AFP detected) |
| Port 22 open (no 135/445/139) | Linux / Unix |
| Any ports open, no pattern matched | Unknown |
| No open ports | No open ports |

---

## Threat Analysis & CVEs

After scanning, TPC classifies open ports into risk levels and surfaces relevant CVEs.

### Risk Levels

| Level | Color | Trigger |
|-------|-------|---------|
| HIGH | Red | One or more high-risk ports open |
| MEDIUM | Yellow | One or more medium-risk ports open, no high |
| LOW | Green | No risky ports found |

### High Risk Ports

| Port | Service | Reason |
|------|---------|--------|
| 21 | FTP | Credentials sent in plaintext |
| 23 | Telnet | Credentials sent in plaintext |
| 512 | rexec | Unauthenticated remote execution |
| 513 | rlogin | Unencrypted remote login |
| 514 | rsh | Remote shell, no authentication |
| 3389 | RDP | Brute-force and BlueKeep exposure |
| 5900 | VNC | Often misconfigured, no auth |

### Medium Risk Ports

| Port | Service | Reason |
|------|---------|--------|
| 135 | RPC | Windows privilege escalation path |
| 139 | NetBIOS | Information disclosure risk |
| 161 | SNMP | Exposes device config via default community string |
| 445 | SMB | EternalBlue / WannaCry vector |
| 3306 | MySQL | Database exposed to network |
| 5432 | PostgreSQL | Database exposed to network |
| 6379 | Redis | Often runs without authentication |
| 27017 | MongoDB | Often runs without authentication |

### Notable CVEs

| Port | CVE | Description |
|------|-----|-------------|
| 21 | CVE-2011-2523 | vsftpd 2.3.4 backdoor |
| 21 | CVE-2010-4221 | ProFTPD RCE |
| 22 | CVE-2018-10933 | libssh authentication bypass |
| 22 | CVE-2023-38408 | OpenSSH agent hijack |
| 445 | CVE-2017-0144 | EternalBlue / WannaCry |
| 445 | CVE-2020-0796 | SMBGhost |
| 3389 | CVE-2019-0708 | BlueKeep RCE |
| 3389 | CVE-2019-1182 | DejaBlue RCE |
| 5900 | CVE-2015-5239 | VNC integer overflow |
| 5900 | CVE-2019-15678 | TigerVNC heap overflow |
| 6379 | CVE-2022-0543 | Redis Lua sandbox escape |
| 27017 | CVE-2015-7882 | MongoDB auth bypass |
| 27017 | CVE-2013-2132 | MongoDB NULL pointer deref |

---

## Exporting Results

Export is available via `-e <format>` (CLI) or the **Export** button / `Ctrl+E` (TUI).

### Formats

| Format | Flag | Contents |
|--------|------|----------|
| Plain Text | `txt` | Header metadata + one line per open port |
| CSV | `csv` | Headers: IP, Hostname, Port, Service, Protocols, Banner |
| JSON | `json` | Structured object with metadata and open ports array |
| HTML | `html` | Styled report with GitHub Dark theme |

### Output Location

Files are saved to the `exports/` directory (created automatically in your working directory).

**Filename format:** `scan_<IP>_<YYYYMMDD_HHMMSS>.<format>`
**Example:** `exports/scan_192_168_1_1_20260326_145230.json`

### JSON Structure

```json
{
  "version": "1.3.0",
  "target": "192.168.1.1",
  "hostname": "router.local",
  "timestamp": "2026-03-26 14:52:30",
  "port_range": { "start": 1, "end": 1024 },
  "os_guess": "Linux / Unix",
  "elapsed": 4.21,
  "open_ports": [
    {
      "port": 22,
      "service": "SSH/SCP/SFTP",
      "protocols": "TCP/UDP/SCTP",
      "banner": "SSH-2.0-OpenSSH_8.9"
    }
  ]
}
```

---

## Scan History

TPC automatically logs every completed scan to:

```
~/.tpc/scan_history.log
```

**Entry format:**

```
============================================================
[2026-03-26 14:52:30]  192.168.1.1  |  ports 1-1024  |  3 open  |  OS: Linux / Unix  |  4.21s
  PORT 22    SSH/SCP/SFTP            (TCP/UDP/SCTP)  [-> SSH-2.0-OpenSSH_8.9]
  PORT 80    HTTP                    (TCP/UDP/SCTP)
  PORT 443   HTTPS                   (TCP/UDP/SCTP)  [-> SSL/TLS encrypted]
```

View history in the TUI by clicking the **History** tab.

---

## Service Categories

Ports are grouped into categories displayed in the live stats box and results table.

| Category | Color | Example Ports |
|----------|-------|---------------|
| Web | Green | 80, 443, 8080 |
| Email | Magenta | 25, 110, 143, 993 |
| File | Yellow | 20, 21, 22, 873 |
| Network | Cyan | 53, 67, 123, 161, 179 |
| Windows | Blue | 135, 139, 445 |
| Security | Red | 22, 88, 389, 636 |
| Database | Yellow | 3306, 5432, 6379, 27017 |
| Remote | Red | 23, 3389, 5900 |
| VMware | White | 902, 912 |

---

## Keybindings (TUI)

| Key | Action |
|-----|--------|
| `Ctrl+S` | Start scan |
| `Ctrl+B` | Grab banners |
| `Ctrl+E` | Open export dialog |
| `Ctrl+N` | New scan (clear results) |
| `F1` | Show About / help screen |
| `Ctrl+Q` | Quit |
| `Esc` / `Q` | Dismiss modal dialogs |

---

## Legal Disclaimer

TPC is intended for **authorized security testing, education, and research only**.

Only use this tool on systems you own or have **explicit written permission** to test. Unauthorized port scanning may be illegal under the CFAA, Computer Misuse Act, or equivalent laws in your jurisdiction. The author assumes no responsibility for misuse.
