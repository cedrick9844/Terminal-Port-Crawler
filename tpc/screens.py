"""
TPC Terminal Port Crawler — Textual modal screens (Disclaimer, Export, About).
"""

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Static, Button
from textual.containers import Vertical, Horizontal
from textual import on

from .data import VERSION

DISCLAIMER_TEXT = """\
This tool is intended for [bold]authorized security testing, education, and research only.[/bold]

Only use this tool on systems you [bold]own[/bold] or have [bold]explicit written permission[/bold] to test.
Unauthorized port crawling may be illegal under the Computer Fraud and Abuse Act (CFAA),
the Computer Misuse Act, or equivalent laws in your jurisdiction.

The author [bold]assumes no responsibility or liability[/bold] for any misuse, damage, or legal
consequences resulting from the use of this software.

By clicking [bold]I Agree[/bold] you confirm that you have authorization to crawl your targets.\
"""

ABOUT_TEXT = f"""\
[bold #58a6ff]TPC Terminal Port Crawler[/bold #58a6ff]  [#8b949e]v{VERSION}[/#8b949e]

A terminal-based port crawler with threat analysis,
banner grabbing, OS fingerprinting, and CVE references.

[bold #58a6ff]Keybindings[/bold #58a6ff]
  [#3fb950]Ctrl+S[/#3fb950]   Start crawl
  [#3fb950]Ctrl+B[/#3fb950]   Grab banners
  [#3fb950]Ctrl+E[/#3fb950]   Export results
  [#3fb950]Ctrl+N[/#3fb950]   New crawl
  [#3fb950]F1    [/#3fb950]   This screen
  [#3fb950]Ctrl+Q[/#3fb950]   Quit

[bold #58a6ff]Target Formats[/bold #58a6ff]
  192.168.1.1          Single IP
  router.local         Hostname
  192.168.1.0/24       CIDR subnet
  192.168.1.1-50       Dash range

[#8b949e]Only use on systems you own or have permission to test.[/#8b949e]\
"""


class DisclaimerScreen(ModalScreen):
    DEFAULT_CSS = """
    DisclaimerScreen { align: center middle; }
    #disclaimer-dialog {
        background: #0d1117;
        border: solid #30363d;
        padding: 2 4;
        width: 80;
        height: auto;
    }
    #disclaimer-title {
        text-align: center;
        color: #f85149;
        text-style: bold;
        margin-bottom: 1;
    }
    #disclaimer-text { margin-bottom: 2; color: #c9d1d9; }
    #disclaimer-btns { align: center middle; height: 3; }
    #agree-btn {
        width: 20; margin: 0 2;
        background: #1a4a2e; color: #3fb950; border: solid #2ea043;
    }
    #agree-btn:hover { background: #2ea043; color: #ffffff; }
    #exit-btn {
        width: 20; margin: 0 2;
        background: #3d1a1a; color: #f85149; border: solid #6e2a2a;
    }
    #exit-btn:hover { background: #6e2a2a; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="disclaimer-dialog"):
            yield Static("Legal Disclaimer", id="disclaimer-title")
            yield Static(DISCLAIMER_TEXT, id="disclaimer-text", markup=True)
            with Horizontal(id="disclaimer-btns"):
                yield Button("I Agree", id="agree-btn")
                yield Button("Exit",    id="exit-btn")

    @on(Button.Pressed, "#agree-btn")
    def agree(self) -> None: self.dismiss(True)

    @on(Button.Pressed, "#exit-btn")
    def deny(self)  -> None: self.dismiss(False)


class ExportScreen(ModalScreen):
    DEFAULT_CSS = """
    ExportScreen { align: center middle; }
    #export-dialog {
        background: #0d1117;
        border: solid #30363d;
        padding: 2 4;
        width: 50;
        height: auto;
    }
    #export-title {
        text-align: center;
        color: #d29922;
        text-style: bold;
        margin-bottom: 1;
    }
    #export-dialog Button { width: 100%; margin: 0 0 1 0; }
    #btn-txt    { background: #1a2a3d; color: #58a6ff; border: solid #1f4d8a; }
    #btn-csv    { background: #2d2200; color: #d29922; border: solid #4a3a00; }
    #btn-json   { background: #1a4a2e; color: #3fb950; border: solid #2ea043; }
    #btn-html   { background: #2d1a3d; color: #bc8cff; border: solid #5a3a8a; }
    #btn-cancel { background: #161b22; color: #8b949e; border: solid #30363d; }
    #btn-txt:hover    { background: #1f4d8a; }
    #btn-csv:hover    { background: #4a3a00; }
    #btn-json:hover   { background: #2ea043; }
    #btn-html:hover   { background: #5a3a8a; }
    #btn-cancel:hover { color: #c9d1d9; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="export-dialog"):
            yield Static("Export Results", id="export-title")
            yield Button("Plain Text  (.txt)",  id="btn-txt")
            yield Button("CSV         (.csv)",  id="btn-csv")
            yield Button("JSON        (.json)", id="btn-json")
            yield Button("HTML Report (.html)", id="btn-html")
            yield Button("Cancel",              id="btn-cancel")

    @on(Button.Pressed, "#btn-txt")
    def export_txt(self)  -> None: self.dismiss("txt")

    @on(Button.Pressed, "#btn-csv")
    def export_csv(self)  -> None: self.dismiss("csv")

    @on(Button.Pressed, "#btn-json")
    def export_json(self) -> None: self.dismiss("json")

    @on(Button.Pressed, "#btn-html")
    def export_html(self) -> None: self.dismiss("html")

    @on(Button.Pressed, "#btn-cancel")
    def cancel(self)      -> None: self.dismiss(None)


class AboutScreen(ModalScreen):
    DEFAULT_CSS = """
    AboutScreen { align: center middle; }
    #about-dialog {
        background: #0d1117;
        border: solid #30363d;
        padding: 2 4;
        width: 60;
        height: auto;
    }
    #about-text { color: #c9d1d9; margin-bottom: 2; }
    #about-close {
        width: 100%;
        background: #161b22;
        color: #8b949e;
        border: solid #30363d;
    }
    #about-close:hover { color: #c9d1d9; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="about-dialog"):
            yield Static(ABOUT_TEXT, id="about-text", markup=True)
            yield Button("Close", id="about-close")

    @on(Button.Pressed, "#about-close")
    def close(self) -> None: self.dismiss(None)

    def on_key(self, event) -> None:
        if event.key in ("escape", "q"):
            self.dismiss(None)
