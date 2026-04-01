"""
TPC Terminal Port Crawler — pure utility functions (no UI dependencies).
"""

import socket
import json
import csv
import os
import html
import ipaddress
from pathlib import Path
from datetime import datetime

from .data import known_ports, SERVICE_META, SSL_PORTS, VERSION, HISTORY_FILE


def get_service_meta(service: str) -> dict:
    for meta in SERVICE_META.values():
        if any(service.startswith(s) for s in meta["services"]):
            return meta
    return {"color": "white", "label": "Other", "services": []}


def resolve_hostname(ip: str) -> str:
    """Reverse-resolve an IP to a hostname. Returns empty string on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""



def grab_banner(ip: str, port: int) -> str:
    if port in SSL_PORTS:
        return "SSL/TLS encrypted"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        raw = b""
        try:
            raw = sock.recv(1024)
        except Exception:
            pass
        if not raw:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                raw = sock.recv(1024)
            except Exception:
                pass
        sock.close()
        text = raw.decode("utf-8", errors="ignore").strip()
        if not text:
            return "no banner"
        if text.startswith("HTTP/"):
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    return line[7:].strip()[:80]
            return text.splitlines()[0].strip()[:80]
        return text.splitlines()[0].strip()[:80] or "no banner"
    except Exception:
        return "no banner"


def fingerprint_os(results: list) -> tuple:
    ports = {int(p) for p, _, _, _ in results}
    if {135, 445} & ports:
        if {902, 912} & ports:
            return "Windows + VMware", "blue"
        return "Windows", "blue"
    if {902, 912} & ports and 445 not in ports:
        return "VMware Host / Linux", "white"
    if 548 in ports and 445 not in ports:
        return "macOS (AFP detected)", "white"
    if 22 in ports and not {135, 445, 139} & ports:
        return "Linux / Unix", "yellow"
    if ports:
        return "Unknown", "white"
    return "No open ports", "white"


def get_threat_findings(results: list) -> tuple:
    HIGH = {
        21:    "FTP — credentials sent in plaintext",
        23:    "Telnet — credentials sent in plaintext",
        512:   "rexec — unauthenticated remote execution",
        513:   "rlogin — unencrypted remote login",
        514:   "rsh (TCP) — remote shell with no authentication",
        2375:  "Docker API — unauthenticated access gives full container control",
        3389:  "RDP — brute-force and BlueKeep risk",
        5900:  "VNC — often misconfigured, no auth",
        8888:  "Jupyter Notebook — remote code execution, often no auth required",
    }
    MEDIUM = {
        135:   "RPC — Windows privilege escalation path",
        139:   "NetBIOS — information disclosure risk",
        161:   "SNMP — exposes device config if default community string",
        445:   "SMB — EternalBlue / WannaCry vector",
        3000:  "Grafana — dashboard, often default admin/admin credentials",
        3306:  "MySQL — database exposed to network",
        5432:  "PostgreSQL — database exposed to network",
        5601:  "Kibana — may expose Elasticsearch data and admin interface",
        6443:  "Kubernetes API — cluster control plane, check for anonymous access",
        9090:  "Prometheus — metrics endpoint may expose internal infrastructure data",
        9200:  "Elasticsearch — often no authentication, full data exposure",
        27017: "MongoDB — often runs without auth by default",
        6379:  "Redis — often runs without auth by default",
    }
    high, medium = [], []
    for port_str, _, _, _ in results:
        port = int(port_str)
        if port in HIGH:
            high.append((port, HIGH[port]))
        elif port in MEDIUM:
            medium.append((port, MEDIUM[port]))

    if high:
        return "HIGH", "red", high, medium
    if medium:
        return "MEDIUM", "yellow", high, medium
    return "LOW", "green", high, medium


def parse_targets(raw: str) -> tuple:
    """Returns (list_of_ips, description_string)."""
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            targets = [str(ip) for ip in net.hosts()]
            return targets, f"Subnet {raw} — {len(targets)} hosts"
        if raw.count(".") == 3 and "-" in raw.split(".")[-1]:
            parts = raw.split(".")
            base  = ".".join(parts[:3])
            s, e  = parts[3].split("-")
            targets = [f"{base}.{i}" for i in range(int(s), int(e) + 1)]
            return targets, f"Range {raw} — {len(targets)} hosts"
    except Exception:
        pass
    return [raw], raw


def log_scan(ip, results, banners, os_label, elapsed, start_port, end_port):
    with open(HISTORY_FILE, "a") as f:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{'=' * 60}\n")
        f.write(
            f"[{ts}]  {ip}  |  ports {start_port}-{end_port}  |  "
            f"{len(results)} open  |  OS: {os_label}  |  {elapsed:.2f}s\n"
        )
        for port_str, service, protocols, _ in sorted(results, key=lambda x: int(x[0])):
            b = banners.get((ip, port_str), "")
            b_str = f"  ->  {b}" if b and b not in ("no banner", "SSL/TLS encrypted") else ""
            f.write(f"  PORT {port_str:<6} {service:<30} ({protocols}){b_str}\n")
        f.write("\n")


def do_export(ip, results, banners, os_label, hostname, elapsed, start_port, end_port, fmt) -> str:
    exports_dir = Path("exports")
    exports_dir.mkdir(exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ip  = ip.replace(".", "_")
    filename = str(exports_dir / f"scan_{safe_ip}_{ts}.{fmt}")
    sorted_r = sorted(results, key=lambda x: int(x[0]))
    host_str = f" ({hostname})" if hostname else ""

    if fmt == "txt":
        with open(filename, "w") as f:
            f.write(f"TPC Terminal Port Crawler v{VERSION} — Scan Report\n{'=' * 60}\n")
            f.write(
                f"Target:    {ip}{host_str}\n"
                f"Ports:     {start_port}-{end_port}\n"
                f"Open:      {len(results)}\n"
                f"OS Guess:  {os_label}\n"
                f"Duration:  {elapsed:.2f}s\n"
                f"Timestamp: {datetime.now()}\n{'=' * 60}\n\n"
            )
            for port_str, service, protocols, _ in sorted_r:
                b = banners.get((ip, port_str), "")
                f.write(f"  PORT {port_str:<6} {service:<30} {protocols}\n")
                if b and b not in ("no banner", "SSL/TLS encrypted"):
                    f.write(f"           Banner: {b}\n")

    elif fmt == "csv":
        with open(filename, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Hostname", "Port", "Service", "Protocols", "Banner"])
            for port_str, service, protocols, _ in sorted_r:
                w.writerow([ip, hostname, port_str, service, protocols,
                            banners.get((ip, port_str), "")])

    elif fmt == "json":
        data = {
            "version":    VERSION,
            "target":     ip,
            "hostname":   hostname,
            "timestamp":  str(datetime.now()),
            "port_range": {"start": start_port, "end": end_port},
            "os_guess":   os_label,
            "elapsed":    round(elapsed, 2),
            "open_ports": [
                {
                    "port":      int(p),
                    "service":   s,
                    "protocols": pr,
                    "banner":    banners.get((ip, p), ""),
                }
                for p, s, pr, _ in sorted_r
            ],
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

    elif fmt == "html":
        _export_html(filename, ip, hostname, os_label, elapsed,
                     start_port, end_port, sorted_r, banners)

    return os.path.abspath(filename)


def _export_html(filename, ip, hostname, os_label, elapsed,
                 start_port, end_port, sorted_r, banners):
    host_str = f" <span class='hostname'>({html.escape(hostname)})</span>" if hostname else ""
    rows = ""
    for port_str, service, protocols, _ in sorted_r:
        banner = banners.get((ip, port_str), "")
        if banner and banner not in ("no banner", "SSL/TLS encrypted"):
            banner_cell = f"<code>{html.escape(banner)}</code>"
        else:
            banner_cell = f"<span class='dim'>{html.escape(banner) if banner else '—'}</span>"
        rows += (
            f"<tr>"
            f"<td class='port'>{port_str}</td>"
            f"<td>{html.escape(service)}</td>"
            f"<td class='dim'>{html.escape(protocols)}</td>"
            f"<td>{banner_cell}</td>"
            f"</tr>\n"
        )
    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TPC — {html.escape(ip)}</title>
<style>
  body      {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; margin: 40px; }}
  h1        {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2        {{ color: #8b949e; font-size: 0.9em; font-weight: normal; margin-top: 0; }}
  .meta     {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px 20px; margin-bottom: 24px; }}
  .meta span{{ color: #58a6ff; }}
  .hostname {{ color: #8b949e; }}
  table     {{ width: 100%; border-collapse: collapse; }}
  th        {{ background: #161b22; color: #58a6ff; text-align: left; padding: 10px 14px; border-bottom: 1px solid #30363d; }}
  td        {{ padding: 8px 14px; border-bottom: 1px solid #21262d; }}
  tr:hover  {{ background: #161b22; }}
  .port     {{ color: #3fb950; font-weight: bold; }}
  .dim      {{ color: #8b949e; }}
  code      {{ background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; color: #d2a679; }}
  footer    {{ margin-top: 40px; color: #8b949e; font-size: 0.8em; border-top: 1px solid #21262d; padding-top: 12px; }}
</style>
</head>
<body>
<h1>TPC Terminal Port Crawler <small style="color:#8b949e;font-size:0.5em">v{VERSION}</small></h1>
<h2>Scan Report — {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</h2>
<div class="meta">
  <b>Target:</b> <span>{html.escape(ip)}</span>{host_str} &nbsp;|&nbsp;
  <b>Ports:</b> <span>{start_port}–{end_port}</span> &nbsp;|&nbsp;
  <b>Open:</b> <span>{len(sorted_r)}</span> &nbsp;|&nbsp;
  <b>OS Guess:</b> <span>{html.escape(os_label)}</span> &nbsp;|&nbsp;
  <b>Duration:</b> <span>{elapsed:.2f}s</span>
</div>
<table>
  <thead><tr><th>Port</th><th>Service</th><th>Protocols</th><th>Banner</th></tr></thead>
  <tbody>
{rows}  </tbody>
</table>
<footer>Generated by TPC Terminal Port Crawler v{VERSION} &mdash; for authorized use only.</footer>
</body>
</html>"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
