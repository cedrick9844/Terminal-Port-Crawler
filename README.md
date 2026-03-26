# TPC — Terminal Port Crawler

A terminal-based port crawler with threat analysis, banner grabbing, OS fingerprinting, and CVE references. Runs as a full TUI or entirely from the command line with flags.

<img width="2879" height="1799" alt="Screenshot 2026-03-26 014148" src="https://github.com/user-attachments/assets/b29e2b5c-58af-49b0-a57a-7f35921910c0" />

## Install

From source (recommended):

```bash
git clone https://github.com/Andrew-most-likely/Terminal-Port-Crawler
cd Terminal-Port-Crawler
pip install -e .
```

## Usage

### TUI (interactive)

```bash
tpc
```

Launches the full terminal UI. Enter a target and press `Ctrl+S` to start crawling.

### CLI (flags only, no UI)

```bash
tpc -t <target> [options]
```

| Flag | Description |
|------|-------------|
| `-t`, `--target` | Target IP, hostname, CIDR subnet, or dash range |
| `-p`, `--ports` | Port range, e.g. `1-1024` (default: `1-1024`) |
| `-m`, `--mode` | Scan mode: `fast`, `random`, `slow` (default: `fast`) |
| `--delay` | Delay in seconds between ports for slow mode (default: `0.5`) |
| `--udp` | Also crawl known UDP ports |
| `-b`, `--banners` | Grab service banners after crawling |
| `-e`, `--export` | Export results: `txt`, `csv`, `json`, `html` |

**Examples:**

```bash
tpc -t 192.168.1.1                        # crawl common ports
tpc -t 192.168.1.1 -p 1-65535            # full port range
tpc -t 192.168.1.0/24 -m random          # subnet, random order
tpc -t 192.168.1.1 -m slow --delay 1.0   # slow crawl
tpc -t 192.168.1.1 --udp                 # include UDP
tpc -t 192.168.1.1 -b -e json            # banners + JSON export
tpc --help                                # show all flags
```

## Features

- TCP port crawling across 70+ known service definitions
- UDP crawling across all known UDP ports in the selected range
- Fast, random order, and slow crawl modes
- Subnet crawling (CIDR notation: `192.168.1.0/24`)
- IP range crawling (`192.168.1.1-50`)
- Hostname resolution (forward and reverse DNS)
- Full port range option (1–65535)
- Banner grabbing for service enumeration
- OS fingerprinting from open port patterns
- Threat assessment — HIGH / MEDIUM / LOW risk ratings
- CVE references for notable open ports
- Export to TXT, CSV, JSON, or HTML
- HTML export renders as a styled report
- Exports saved to `exports/` folder
- Persistent crawl history log
- Full CLI mode — no UI required

## TUI Keybindings

| Action         | Key    |
|----------------|--------|
| Start crawl    | Ctrl+S |
| Grab banners   | Ctrl+B |
| Export results | Ctrl+E |
| New crawl      | Ctrl+N |
| About          | F1     |
| Quit           | Ctrl+Q |

## Target Formats

| Format      | Example           |
|-------------|-------------------|
| Single IP   | `192.168.1.1`     |
| Hostname    | `router.local`    |
| CIDR subnet | `192.168.1.0/24`  |
| Dash range  | `192.168.1.1-50`  |

## Legal

Only use this tool on systems you own or have **explicit written permission** to test.
Unauthorized port crawling may be illegal under the CFAA, Computer Misuse Act, or equivalent laws in your jurisdiction.

## Requirements

- Python 3.9+
- Linux / macOS / Windows
