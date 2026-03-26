"""
TPC Terminal Port Crawler v1.3.0 — entry point (TUI + CLI).
"""

import argparse
import socket
import threading
import time
import random
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from textual.app import App, ComposeResult
from textual.widgets import (
    Footer, Input, Button, DataTable,
    Static, Label, TabbedContent, TabPane,
    ProgressBar, RichLog, RadioSet, RadioButton, Checkbox,
)
from textual.containers import Horizontal, Vertical
from textual.binding import Binding
from textual import work, on
from rich.text import Text

from .data import VERSION, HISTORY_FILE, known_ports, SERVICE_META, PORT_CVES
from .utils import (
    get_service_meta, grab_banner, fingerprint_os,
    get_threat_findings, parse_targets, log_scan, do_export,
    resolve_hostname,
)
from .screens import DisclaimerScreen, ExportScreen, AboutScreen



class PortScannerApp(App):
    TITLE                   = f"TPC Terminal Port Crawler  v{VERSION}"
    COMMANDS                = set()
    ENABLE_COMMAND_PALETTE  = False
    BINDINGS = [
        Binding("ctrl+s", "start_scan",   "Scan",    priority=True),
        Binding("ctrl+b", "grab_banners", "Banners", priority=True),
        Binding("ctrl+e", "export",       "Export",  priority=True),
        Binding("ctrl+n", "new_scan",     "New",     priority=True),
        Binding("f1",     "about",        "About",   priority=True),
        Binding("ctrl+q", "quit",         "Quit",    priority=True),
    ]

    CSS = """
    Screen {
        background: #0d1117;
        layers: base overlay;
    }
    Footer {
        background: #161b22;
        color: #8b949e;
    }

    #app-body {
        height: 1fr;
    }

    /* ── Sidebar ── */
    #sidebar {
        width: 40;
        background: #0d1117;
        border-right: solid #30363d;
        padding: 0 1;
        overflow-y: auto;
    }
    .section-title {
        color: #58a6ff;
        text-style: bold;
        margin: 1 0 1 0;
        height: 1;
    }
    Input {
        background: #161b22;
        border: solid #30363d;
        color: #c9d1d9;
        height: 3;
        margin: 0;
    }
    Input:focus { border: solid #58a6ff; }

    RadioSet {
        background: transparent;
        border: none;
        padding: 0;
        margin: 0;
        height: auto;
    }
    RadioButton     { color: #8b949e; height: 1; }
    RadioButton.-on { color: #58a6ff; text-style: bold; }
    Checkbox        { color: #8b949e; height: 1; background: transparent; border: none; padding: 0; margin: 0; }
    Checkbox:focus  { border: none; }
    Checkbox.-on    { color: #58a6ff; }

#custom-range        { display: none; height: 3; margin: 0; }
    #custom-range Input  { width: 1fr; }
    #slow-delay-row      { display: none; height: 3; margin: 0; }
    #slow-delay-row Label { height: 3; content-align: left middle; width: 10; color: #8b949e; }
    #slow-delay-row Input { width: 1fr; }

    .btn-row { height: 3; margin: 0; }
    #scan-btn-row { margin-top: 1; }
    .btn-row Button {
        width: 1fr;
        height: 3;
        border: solid #30363d;
        margin: 0;
        min-width: 0;
    }

    #scan-btn            { background: #1a4a2e; color: #3fb950; border: solid #2ea043; }
    #scan-btn:hover      { background: #2ea043; color: #ffffff; }
    #scan-btn:disabled   { background: #0d1117; color: #3d5a44; border: solid #21262d; }

    #stop-btn            { background: #3d1a1a; color: #f85149; border: solid #6e2a2a; display: none; }
    #stop-btn:hover      { background: #6e2a2a; }

    #banner-btn          { background: #1a2a3d; color: #58a6ff; border: solid #1f4d8a; }
    #banner-btn:disabled { background: #0d1117; color: #2d4a6d; border: solid #21262d; }

    #export-btn          { background: #2d2200; color: #d29922; border: solid #4a3a00; }
    #export-btn:disabled { background: #0d1117; color: #4a3a1a; border: solid #21262d; }

    #new-btn {
        background: #161b22;
        color: #8b949e;
        border: solid #30363d;
        width: 100%;
        height: 3;
        margin: 0;
    }
    #new-btn:hover { color: #c9d1d9; }

    #stats-box {
        border: solid #21262d;
        padding: 0 1;
        margin-top: 0;
        color: #8b949e;
        height: auto;
    }

    /* ── Main Panel ── */
    #main-panel { background: #0d1117; padding: 0 1; }
    TabbedContent { height: 1fr; background: #0d1117; }
    TabPane { background: #0d1117; padding: 1; }
    Tab         { background: #161b22; color: #8b949e; }
    Tab.-active { background: #0d1117; color: #58a6ff; text-style: bold; }

    DataTable { background: #0d1117; color: #c9d1d9; height: 1fr; }
    DataTable > .datatable--header   { background: #161b22; color: #58a6ff; text-style: bold; }
    DataTable > .datatable--cursor   { background: #1a2332; }
    DataTable > .datatable--even-row { background: #0d1117; }
    DataTable > .datatable--odd-row  { background: #111820; }

    #results-placeholder {
        color: #8b949e;
        padding: 2 4;
        width: 100%;
    }

    RichLog {
        background: #0d1117;
        color: #8b949e;
        padding: 1 2;
        height: 1fr;
        border: none;
    }

    /* ── Status Bar ── */
    #status-bar {
        height: 3;
        background: #161b22;
        border-top: solid #30363d;
        padding: 0 2;
        align: left middle;
    }
    #status-label { width: 1fr; color: #8b949e; }
    #progress { width: 40; }
    ProgressBar > .bar--bar      { color: #3fb950; }
    ProgressBar > .bar--complete { color: #3fb950; }
    """

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Horizontal(id="app-body"):

            with Vertical(id="sidebar"):
                yield Label("TARGET", classes="section-title")
                yield Input(
                    placeholder="IP, hostname, 192.168.1.0/24, 192.168.1.1-50",
                    id="target-input",
                )
                yield Label("PORT RANGE", classes="section-title")
                with RadioSet(id="port-range"):
                    yield RadioButton("Well-known  1 – 1024", value=True)
                    yield RadioButton("Common      1 – 5000")
                    yield RadioButton("Full        1 – 65535")
                    yield RadioButton("Custom range")
                with Horizontal(id="custom-range"):
                    yield Input("1",    placeholder="start", id="custom-start")
                    yield Input("1024", placeholder="end",   id="custom-end")

                yield Label("SCAN MODE", classes="section-title")
                with RadioSet(id="scan-mode"):
                    yield RadioButton("Fast",         value=True)
                    yield RadioButton("Random Order")
                    yield RadioButton("Slow")
                with Horizontal(id="slow-delay-row"):
                    yield Label("Delay (s):")
                    yield Input("0.5", placeholder="seconds", id="slow-delay")

                yield Label("OPTIONS", classes="section-title")
                yield Checkbox("Scan UDP ports", id="udp-check")

                with Horizontal(classes="btn-row", id="scan-btn-row"):
                    yield Button("Scan", id="scan-btn")
                    yield Button("Stop", id="stop-btn")
                with Horizontal(classes="btn-row"):
                    yield Button("Banners", id="banner-btn", disabled=True)
                    yield Button("Export",  id="export-btn", disabled=True)
                yield Button("New Scan", id="new-btn")

                yield Label("LIVE STATS", classes="section-title")
                yield Static("", id="stats-box")

            with Vertical(id="main-panel"):
                with TabbedContent(id="tabs"):
                    with TabPane("Results",  id="tab-results"):
                        yield DataTable(id="results-table", cursor_type="row")
                        yield Static(
                            "Enter a target and press Ctrl+S to start scanning.",
                            id="results-placeholder",
                        )
                    with TabPane("Analysis", id="tab-analysis"):
                        yield RichLog(id="analysis-log", highlight=True, markup=True)
                    with TabPane("History",  id="tab-history"):
                        yield RichLog(id="history-log",  highlight=True, markup=True)
                    with TabPane("Credits :)", id="tab-credits"):
                        yield RichLog(id="credits-log", highlight=False, markup=True)

                with Horizontal(id="status-bar"):
                    yield Static(
                        "Ready — enter a target and press Ctrl+S to scan.",
                        id="status-label",
                    )
                    yield ProgressBar(id="progress", total=100, show_eta=False)

        yield Footer()

    # ── Mount ─────────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        self._results:    list  = []
        self._banners:    dict  = {}
        self._hostnames:  dict  = {}
        self._row_keys:   dict  = {}
        self._col_keys:   dict  = {}
        self._scan_start: float = 0.0
        self._start_port: int   = 1
        self._end_port:   int   = 1024
        self._targets:    list  = []
        self._stop_flag:  bool  = False

        table = self.query_one("#results-table", DataTable)
        self._col_keys["ip"]        = table.add_column("IP",        width=16)
        self._col_keys["hostname"]  = table.add_column("Hostname",  width=20)
        self._col_keys["port"]      = table.add_column("Port",      width=6)
        self._col_keys["category"]  = table.add_column("Category",  width=10)
        self._col_keys["service"]   = table.add_column("Service",   width=24)
        self._col_keys["protocols"] = table.add_column("Protocols", width=14)
        self._col_keys["banner"]    = table.add_column("Banner",    width=36)

        self._refresh_stats()
        self.push_screen(DisclaimerScreen(), self._handle_disclaimer)

    def _handle_disclaimer(self, agreed: bool) -> None:
        if not agreed:
            self.exit()

    # ── Radio / option handlers ───────────────────────────────────────────────

    @on(RadioSet.Changed, "#port-range")
    def _port_range_changed(self, event: RadioSet.Changed) -> None:
        self.query_one("#custom-range").display = (event.index == 3)

    @on(RadioSet.Changed, "#scan-mode")
    def _scan_mode_changed(self, event: RadioSet.Changed) -> None:
        self.query_one("#slow-delay-row").display = (event.index == 2)

    # ── Button handlers ───────────────────────────────────────────────────────

    @on(Button.Pressed, "#scan-btn")
    def _on_scan_btn(self)   -> None: self.action_start_scan()

    @on(Button.Pressed, "#stop-btn")
    def _on_stop_btn(self)   -> None:
        self._stop_flag = True
        self.workers.cancel_all()
        self._set_status("[yellow]Scan stopped.[/yellow]")
        self._finish_scan_ui()

    @on(Button.Pressed, "#banner-btn")
    def _on_banner_btn(self) -> None: self.action_grab_banners()

    @on(Button.Pressed, "#export-btn")
    def _on_export_btn(self) -> None: self.action_export()

    @on(Button.Pressed, "#new-btn")
    def _on_new_btn(self)    -> None: self.action_new_scan()

    @on(TabbedContent.TabActivated)
    def _on_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        if not event.pane:
            return
        if event.pane.id == "tab-history":
            self._load_history()
        elif event.pane.id == "tab-credits":
            self._load_credits()

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_about(self) -> None:
        self.push_screen(AboutScreen())

    def action_start_scan(self) -> None:
        raw = self.query_one("#target-input", Input).value.strip()
        if not raw:
            self._set_status("[red]Enter a target first.[/red]")
            return

        targets, desc = parse_targets(raw)
        self._targets  = targets
        self._stop_flag = False

        range_idx = self.query_one("#port-range", RadioSet).pressed_index or 0
        if range_idx == 1:
            self._start_port, self._end_port = 1, 5000
        elif range_idx == 2:
            self._start_port, self._end_port = 1, 65535
        elif range_idx == 3:
            try:
                self._start_port = int(self.query_one("#custom-start", Input).value)
                self._end_port   = int(self.query_one("#custom-end",   Input).value)
                if not (1 <= self._start_port <= self._end_port <= 65535):
                    raise ValueError
            except ValueError:
                self._set_status("[red]Invalid custom port range (1–65535).[/red]")
                return
        else:
            self._start_port, self._end_port = 1, 1024

        mode_idx = self.query_one("#scan-mode", RadioSet).pressed_index or 0
        if mode_idx == 1:
            mode = "random"
        elif mode_idx == 2:
            try:
                delay = float(self.query_one("#slow-delay", Input).value)
            except ValueError:
                delay = 0.5
            mode = ("slow", delay)
        else:
            mode = "fast"

        scan_udp  = self.query_one("#udp-check", Checkbox).value

        udp_port_count = len([
            p for p in range(self._start_port, self._end_port + 1)
            if p in known_ports and "UDP" in known_ports[p]["protocols"]
        ]) if scan_udp else 0

        total = (self._end_port - self._start_port + 1) * len(targets) + udp_port_count * len(targets)
        self.query_one("#progress", ProgressBar).update(total=total, progress=0)
        self.query_one("#scan-btn").disabled   = True
        self.query_one("#stop-btn").display    = True
        self.query_one("#banner-btn").disabled = True
        self.query_one("#export-btn").disabled = True
        self._scan_start = time.time()
        self._set_status(f"[cyan]Scanning {desc}...[/cyan]")
        self._run_scan(targets, self._start_port, self._end_port, mode, scan_udp)

    def action_grab_banners(self) -> None:
        if not self._results:
            return
        self.query_one("#banner-btn").disabled = True
        self._set_status("[cyan]Grabbing banners...[/cyan]")
        self._run_banner_grab(list(self._results))

    def action_export(self) -> None:
        if not self._results:
            return
        self.push_screen(ExportScreen(), self._handle_export)

    def action_new_scan(self) -> None:
        self._results    = []
        self._banners    = {}
        self._hostnames  = {}
        self._row_keys   = {}
        self._scan_start = 0.0
        self.query_one("#results-table", DataTable).clear()
        self.query_one("#analysis-log",  RichLog).clear()
        self.query_one("#results-placeholder").display = True
        self.query_one("#banner-btn").disabled = True
        self.query_one("#export-btn").disabled = True
        self.query_one("#progress", ProgressBar).update(progress=0)
        self._set_status("Ready — enter a target and press Ctrl+S to scan.")
        self._refresh_stats()

    # ── Workers ───────────────────────────────────────────────────────────────

    @work(thread=True, exclusive=True)
    def _run_scan(self, targets: list, start_port: int, end_port: int,
                  mode, scan_udp: bool = False) -> None:
        port_list  = list(range(start_port, end_port + 1))
        is_slow    = isinstance(mode, tuple) and mode[0] == "slow"
        port_count = end_port - start_port + 1

        for idx, raw_target in enumerate(targets):
            if self._stop_flag:
                break
            if len(targets) > 1:
                self.call_from_thread(
                    self._set_status,
                    f"[cyan]Host {idx + 1}/{len(targets)}: {raw_target}...[/cyan]",
                )
            try:
                ip = socket.gethostbyname(raw_target)
            except socket.gaierror:
                self.call_from_thread(
                    self._set_status,
                    f"[red]Could not resolve {raw_target!r} — skipping.[/red]",
                )
                self.call_from_thread(self._advance_progress, port_count)
                continue

            hostname = resolve_hostname(ip)
            self._hostnames[ip] = hostname

            scan_list = list(port_list)
            if mode == "random" or is_slow:
                random.shuffle(scan_list)

            def scan_port(port, _ip=ip):
                if self._stop_flag:
                    self.call_from_thread(self._advance_progress, 1)
                    return
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    try:
                        if sock.connect_ex((_ip, port)) == 0:
                            info  = known_ports.get(port)
                            entry = (
                                str(port),
                                info["service"] if info else "Unknown service",
                                ", ".join(info["protocols"]) if info else "?",
                                _ip,
                            )
                            self.call_from_thread(self._add_result, entry)
                    finally:
                        sock.close()
                except Exception:
                    pass
                self.call_from_thread(self._advance_progress, 1)

            if is_slow:
                delay = mode[1]
                for port in scan_list:
                    if self._stop_flag:
                        break
                    scan_port(port)
                    time.sleep(delay)
            else:
                with ThreadPoolExecutor(max_workers=100) as ex:
                    ex.map(scan_port, scan_list)

        if scan_udp and not self._stop_flag:
            udp_ports = [
                p for p in range(start_port, end_port + 1)
                if p in known_ports and "UDP" in known_ports[p]["protocols"]
            ]
            self.call_from_thread(self._set_status, "[cyan]Scanning UDP ports...[/cyan]")

            for raw_target in targets:
                if self._stop_flag:
                    break
                try:
                    ip = socket.gethostbyname(raw_target)
                except socket.gaierror:
                    self.call_from_thread(self._advance_progress, len(udp_ports))
                    continue

                for port in udp_ports:
                    if self._stop_flag:
                        self.call_from_thread(self._advance_progress, 1)
                        continue
                    is_open = False
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(1.0)
                        try:
                            sock.sendto(b"\x00" * 8, (ip, port))
                            try:
                                sock.recv(1024)
                                is_open = True
                            except socket.timeout:
                                is_open = True
                            except ConnectionRefusedError:
                                is_open = False
                        finally:
                            sock.close()
                    except Exception:
                        pass

                    if is_open:
                        info  = known_ports.get(port)
                        entry = (
                            str(port),
                            (info["service"] if info else "Unknown service") + " (UDP)",
                            ", ".join(info["protocols"]) if info else "UDP",
                            ip,
                        )
                        self.call_from_thread(self._add_result, entry)
                    self.call_from_thread(self._advance_progress, 1)

        self.call_from_thread(self._on_scan_complete)

    @work(thread=True)
    def _run_banner_grab(self, results: list) -> None:
        for port_str, _, _, ip in results:
            banner = grab_banner(ip, int(port_str))
            self._banners[(ip, port_str)] = banner
            self.call_from_thread(self._update_banner_cell, ip, port_str, banner)
        self.call_from_thread(self._set_status, "[#3fb950]Banner grab complete.[/#3fb950]")
        self.call_from_thread(self._enable_banner_btn)

    # ── Thread-safe UI helpers ────────────────────────────────────────────────

    def _advance_progress(self, amount: int = 1) -> None:
        self.query_one("#progress", ProgressBar).advance(amount)

    def _enable_banner_btn(self) -> None:
        self.query_one("#banner-btn").disabled = False

    def _add_result(self, entry: tuple) -> None:
        port_str, service, protocols, ip = entry
        self._results.append(entry)
        meta     = get_service_meta(service)
        color    = meta["color"]
        hostname = self._hostnames.get(ip, "")
        table    = self.query_one("#results-table", DataTable)

        self.query_one("#results-placeholder").display = False

        row_key = table.add_row(
            Text(ip,            style="dim white"),
            Text(hostname,      style="#8b949e"),
            Text(port_str,      style="bold #3fb950"),
            Text(meta["label"], style=f"bold {color}"),
            Text(service,       style=color),
            Text(protocols,     style="#8b949e"),
            Text("",            style="dim"),
        )
        self._row_keys[(ip, port_str)] = row_key
        self._refresh_stats()

    def _update_banner_cell(self, ip: str, port_str: str, banner: str) -> None:
        row_key = self._row_keys.get((ip, port_str))
        if row_key is not None:
            self.query_one("#results-table", DataTable).update_cell(
                row_key,
                self._col_keys["banner"],
                Text(banner, style="#d2a679"),
            )

    def _on_scan_complete(self) -> None:
        elapsed = time.time() - self._scan_start
        os_label, os_color = (
            fingerprint_os(self._results) if self._results else ("N/A", "white")
        )
        level, l_color, high, medium = get_threat_findings(self._results)

        self._set_status(
            f"[#3fb950]Done[/#3fb950]  ·  "
            f"[#d29922]{len(self._results)} open[/#d29922]  ·  "
            f"[#58a6ff]{elapsed:.2f}s[/#58a6ff]  ·  "
            f"OS: [{os_color}]{os_label}[/{os_color}]  ·  "
            f"Risk: [{l_color}]{level}[/{l_color}]"
        )
        self._finish_scan_ui()
        self._write_analysis(os_label, os_color, level, l_color, high, medium, elapsed)

        if self._results and self._targets:
            for ip in {r[3] for r in self._results}:
                ip_results = [r for r in self._results if r[3] == ip]
                log_scan(ip, ip_results, self._banners, os_label,
                         elapsed, self._start_port, self._end_port)

    def _write_analysis(self, os_label, os_color, level, l_color, high, medium, elapsed) -> None:
        log = self.query_one("#analysis-log", RichLog)
        log.clear()

        log.write(f"[bold #58a6ff]OS Fingerprint[/bold #58a6ff]   [{os_color}]{os_label}[/{os_color}]")
        log.write(f"[bold #58a6ff]Risk Level    [/bold #58a6ff]   [{l_color}]{level}[/{l_color}]")
        log.write(f"[bold #58a6ff]Elapsed       [/bold #58a6ff]   [#8b949e]{elapsed:.2f}s[/#8b949e]")
        log.write("[#30363d]" + "─" * 50 + "[/#30363d]")

        if high:
            log.write("\n[bold #f85149]High Risk Findings[/bold #f85149]")
            for port, desc in high:
                log.write(f"  [#f85149]PORT {port:<6}[/#f85149]  [#c9d1d9]{desc}[/#c9d1d9]")
                for cve, cve_desc in PORT_CVES.get(port, []):
                    log.write(f"           [#8b949e]{cve}[/#8b949e]  [#d2a679]{cve_desc}[/#d2a679]")

        if medium:
            log.write("\n[bold #d29922]Medium Risk Findings[/bold #d29922]")
            for port, desc in medium:
                log.write(f"  [#d29922]PORT {port:<6}[/#d29922]  [#c9d1d9]{desc}[/#c9d1d9]")
                for cve, cve_desc in PORT_CVES.get(port, []):
                    log.write(f"           [#8b949e]{cve}[/#8b949e]  [#d2a679]{cve_desc}[/#d2a679]")

        if not high and not medium:
            log.write("\n[#3fb950]No high-risk services detected.[/#3fb950]")

        other_cves = [
            (port_str, PORT_CVES[int(port_str)])
            for port_str, _, _, _ in self._results
            if int(port_str) in PORT_CVES
            and int(port_str) not in {p for p, _ in high + medium}
        ]
        if other_cves:
            log.write("\n[bold #58a6ff]Notable CVEs (other open ports)[/bold #58a6ff]")
            for port_str, cves in other_cves:
                for cve, cve_desc in cves:
                    log.write(f"  [#8b949e]PORT {port_str:<6}  {cve}[/#8b949e]  [#d2a679]{cve_desc}[/#d2a679]")

    def _finish_scan_ui(self) -> None:
        self.query_one("#scan-btn").disabled = False
        self.query_one("#stop-btn").display  = False
        if self._results:
            self.query_one("#banner-btn").disabled = False
            self.query_one("#export-btn").disabled = False

    def _set_status(self, markup: str) -> None:
        self.query_one("#status-label", Static).update(markup)

    def _refresh_stats(self) -> None:
        self.query_one("#stats-box", Static).update(self._build_stats())

    def _load_history(self) -> None:
        log = self.query_one("#history-log", RichLog)
        log.clear()
        if not os.path.exists(HISTORY_FILE):
            log.write("[dim]No scan history yet.[/dim]")
            return
        with open(HISTORY_FILE, "r") as f:
            for line in f:
                log.write(line.rstrip())

    def _load_credits(self) -> None:
        log = self.query_one("#credits-log", RichLog)
        log.clear()
        log.write("")
        log.write("  [#30363d]┌──────────────────────────────────────────────────────────┐[/#30363d]")
        log.write("  [#30363d]│[/#30363d]                                                          [#30363d]│[/#30363d]")
        log.write("  [#30363d]│[/#30363d]   [bold #c9d1d9]Andrew Cappelli[/bold #c9d1d9]                                        [#30363d]│[/#30363d]")
        log.write("  [#30363d]│[/#30363d]   [#8b949e]Cybersecurity Student[/#8b949e]                                  [#30363d]│[/#30363d]")
        log.write("  [#30363d]│[/#30363d]                                                          [#30363d]│[/#30363d]")
        log.write("  [#30363d]│[/#30363d]   [#58a6ff]github.com/Andrew-most-likely[/#58a6ff]                          [#30363d]│[/#30363d]")
        log.write("  [#30363d]│[/#30363d]                                                          [#30363d]│[/#30363d]")
        log.write("  [#30363d]│[/#30363d]   [#8b949e]TPC Terminal Port Crawler  ·  Python & Textual     [/#8b949e]    [#30363d]│[/#30363d]")
        log.write("  [#30363d]│[/#30363d]                                                          [#30363d]│[/#30363d]")
        log.write("  [#30363d]└──────────────────────────────────────────────────────────┘[/#30363d]")
        log.write("")
        log.write("  [#3fb950]gluten free  ·  dairy free  ·  zero sugar  ·  low fat[/#3fb950]")
        log.write("  [#8b949e]best enjoyed with a matcha and a starbucks cakepop[/#8b949e]")

    def _handle_export(self, fmt: Optional[str]) -> None:
        if not fmt or not self._results:
            return
        elapsed     = time.time() - self._scan_start
        os_label, _ = fingerprint_os(self._results)
        for ip in {r[3] for r in self._results}:
            ip_results = [r for r in self._results if r[3] == ip]
            hostname   = self._hostnames.get(ip, "")
            path = do_export(ip, ip_results, self._banners, os_label, hostname,
                             elapsed, self._start_port, self._end_port, fmt)
            self._set_status(f"[#3fb950]Exported:[/#3fb950] {path}")

    def _build_stats(self) -> str:
        counts: dict = {key: 0 for key in SERVICE_META}
        counts["other"] = 0
        for _, service, _, _ in self._results:
            matched = False
            for key, meta in SERVICE_META.items():
                if any(service.startswith(s) for s in meta["services"]):
                    counts[key] += 1
                    matched = True
                    break
            if not matched:
                counts["other"] += 1

        items = list(SERVICE_META.items())
        lines = []
        for i in range(0, len(items), 2):
            row = ""
            for key, meta in items[i:i+2]:
                n     = counts[key]
                color = meta["color"] if n else "dim white"
                row  += f"[{color}]■[/{color}] {meta['label']:<8}[dim]{n}[/dim]  "
            lines.append(row.rstrip())
        lines.append(f"[#30363d]{'─' * 30}[/#30363d]")
        lines.append(f"[bold #c9d1d9]Total open: [#3fb950]{len(self._results)}[/#3fb950][/bold #c9d1d9]")
        return "\n".join(lines)


def _run_cli(args) -> None:
    targets, desc = parse_targets(args.target)

    try:
        start_str, end_str = args.ports.split("-", 1)
        start_port, end_port = int(start_str), int(end_str)
        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError
    except ValueError:
        print(f"[!] Invalid port range '{args.ports}'. Use START-END (e.g. 1-1024).")
        return

    if args.mode == "slow":
        mode = ("slow", args.delay)
    else:
        mode = args.mode

    is_slow = isinstance(mode, tuple) and mode[0] == "slow"

    print(f"\n  TPC Terminal Port Crawler  v{VERSION}")
    print(f"  Target : {desc}")
    print(f"  Ports  : {start_port}-{end_port}  |  Mode: {args.mode}"
          + (f"  |  Delay: {args.delay}s" if is_slow else "")
          + ("  |  UDP" if args.udp else ""))
    print(f"  {'─' * 56}\n")

    results: list  = []
    banners: dict  = {}
    hostnames: dict = {}
    lock = threading.Lock()
    start_time = time.time()

    port_list = list(range(start_port, end_port + 1))
    if mode == "random" or is_slow:
        random.shuffle(port_list)

    for raw_target in targets:
        try:
            ip = socket.gethostbyname(raw_target)
        except socket.gaierror:
            print(f"  [!] Could not resolve {raw_target!r} — skipping.")
            continue

        hostname = resolve_hostname(ip)
        hostnames[ip] = hostname
        host_str = f" ({hostname})" if hostname else ""

        if len(targets) > 1:
            print(f"  Host: {ip}{host_str}")

        ip_results: list = []

        def scan_port(port, _ip=ip, _ip_results=ip_results):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                try:
                    if sock.connect_ex((_ip, port)) == 0:
                        info  = known_ports.get(port)
                        entry = (
                            str(port),
                            info["service"] if info else "Unknown",
                            ", ".join(info["protocols"]) if info else "?",
                            _ip,
                        )
                        with lock:
                            _ip_results.append(entry)
                            results.append(entry)
                            print(f"  OPEN  {port:<6}  {entry[1]:<30}  {entry[2]}")
                finally:
                    sock.close()
            except Exception:
                pass

        if is_slow:
            for port in port_list:
                scan_port(port)
                time.sleep(mode[1])
        else:
            with ThreadPoolExecutor(max_workers=100) as ex:
                ex.map(scan_port, port_list)

        if args.udp:
            udp_ports = [
                p for p in range(start_port, end_port + 1)
                if p in known_ports and "UDP" in known_ports[p]["protocols"]
            ]
            for port in udp_ports:
                is_open = False
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1.0)
                    try:
                        sock.sendto(b"\x00" * 8, (ip, port))
                        try:
                            sock.recv(1024)
                            is_open = True
                        except socket.timeout:
                            is_open = True
                        except ConnectionRefusedError:
                            is_open = False
                    finally:
                        sock.close()
                except Exception:
                    pass
                if is_open:
                    info  = known_ports.get(port)
                    entry = (
                        str(port),
                        (info["service"] if info else "Unknown") + " (UDP)",
                        ", ".join(info["protocols"]) if info else "UDP",
                        ip,
                    )
                    with lock:
                        ip_results.append(entry)
                        results.append(entry)
                        print(f"  OPEN  {port:<6}  {entry[1]:<30}  {entry[2]}")

    elapsed = time.time() - start_time
    os_label, _ = fingerprint_os(results) if results else ("N/A", "white")
    level, _, high, medium = get_threat_findings(results)

    print(f"\n  {'─' * 56}")
    print(f"  Done  |  {len(results)} open  |  {elapsed:.2f}s  |  OS: {os_label}  |  Risk: {level}")

    if high:
        print(f"\n  High Risk:")
        for port, fdesc in high:
            print(f"    PORT {port:<6}  {fdesc}")
    if medium:
        print(f"\n  Medium Risk:")
        for port, fdesc in medium:
            print(f"    PORT {port:<6}  {fdesc}")

    if args.banners and results:
        print(f"\n  Grabbing banners...")
        for port_str, _, _, ip in results:
            banner = grab_banner(ip, int(port_str))
            banners[(ip, port_str)] = banner
            if banner and banner not in ("no banner", "SSL/TLS encrypted"):
                print(f"    PORT {port_str:<6}  {banner}")

    if results:
        for ip in {r[3] for r in results}:
            ip_results = [r for r in results if r[3] == ip]
            log_scan(ip, ip_results, banners, os_label, elapsed, start_port, end_port)

    if args.export and results:
        for ip in {r[3] for r in results}:
            ip_results = [r for r in results if r[3] == ip]
            path = do_export(ip, ip_results, banners, os_label, hostnames.get(ip, ""),
                             elapsed, start_port, end_port, args.export)
            print(f"\n  Exported: {path}")

    print()


def main():
    parser = argparse.ArgumentParser(
        prog="tpc",
        description="TPC Terminal Port Crawler — port scanning with threat analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  tpc                              launch the TUI\n"
            "  tpc -t 192.168.1.1               scan common ports (1-1024)\n"
            "  tpc -t 192.168.1.1 -p 1-65535   full port scan\n"
            "  tpc -t 192.168.1.0/24 -m random  subnet scan, random order\n"
            "  tpc -t 192.168.1.1 -b -e json    scan, grab banners, export JSON\n"
        ),
    )
    parser.add_argument("-t", "--target",  help="Target IP, hostname, CIDR subnet, or dash range")
    parser.add_argument("-p", "--ports",   default="1-1024", metavar="START-END",
                        help="Port range (default: 1-1024)")
    parser.add_argument("-m", "--mode",    choices=["fast", "random", "slow"], default="fast",
                        help="Scan mode (default: fast)")
    parser.add_argument("--delay",         type=float, default=0.5, metavar="SECS",
                        help="Delay between ports in slow mode (default: 0.5)")
    parser.add_argument("--udp",           action="store_true", help="Also scan known UDP ports")
    parser.add_argument("-b", "--banners", action="store_true", help="Grab service banners")
    parser.add_argument("-e", "--export",  choices=["txt", "csv", "json", "html"],
                        help="Export results to file")

    args = parser.parse_args()

    if args.target:
        _run_cli(args)
    else:
        PortScannerApp().run()


if __name__ == "__main__":
    main()
