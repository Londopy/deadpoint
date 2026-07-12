"""Optional Textual TUI for deadpoint.

A thin, read-only view over the library (``ingest`` + ``build_report``). Install
with ``pip install deadpoint[tui]`` and launch with ``deadpoint tui <input>``.

The formatter functions are importable without Textual so they can be unit
tested; the ``App`` subclass is only defined when Textual is available.
"""

from __future__ import annotations

from .ingest import ingest
from .report import build_report, FullReport
from .model import Verdict, Risk

_VERDICT_COLOR = {Verdict.WEAK: "red", Verdict.STRONG: "green", Verdict.UNKNOWN: "yellow"}
_RISK_COLOR = {Risk.CRITICAL: "bold red", Risk.HIGH: "red", Risk.MEDIUM: "yellow",
               Risk.LOW: "cyan", Risk.INFO: "green"}


def detect_panel(report: FullReport) -> str:
    d = report.detect
    color = _VERDICT_COLOR.get(d.verdict, "white")
    stats = d.evidence.get("stats", {})
    return (f"[b]DETECT[/b]\n\n"
            f"Verdict     : [{color} b]{d.verdict.value}[/]\n"
            f"Suspected   : {d.suspected.value}\n"
            f"Confidence  : {d.confidence:.2f}\n"
            f"Stat tests  : {stats.get('tests_passed', 'n/a')} passed\n"
            f"Samples     : {report.stream_meta.get('count')} x "
            f"{report.stream_meta.get('width')}-bit")


def exploit_panel(report: FullReport) -> str:
    e = report.exploit
    if e is None:
        return "[b]EXPLOIT[/b]\n\n[green]No weak generator to exploit.[/]"
    if not e.recovered:
        return f"[b]EXPLOIT[/b]\n\n[yellow]Not recovered[/] ({e.method})\n{e.notes}"
    vcol = "green" if e.verified else "yellow"
    return (f"[b]EXPLOIT[/b]\n\n"
            f"Recovered   : [green b]True[/]\n"
            f"Method      : {e.method}\n"
            f"Verified    : [{vcol}]{e.verified}[/] (holdout)\n"
            f"Samples req : {e.samples_required}")


def remediate_panel(report: FullReport) -> str:
    rcol = _RISK_COLOR.get(report.risk, "white")
    lines = [f"[b]REMEDIATE[/b]   risk: [{rcol}]{report.risk.value}[/]\n"]
    for f in report.remediate.findings[:6]:
        fcol = _RISK_COLOR.get(f.risk, "white")
        lines.append(f"[{fcol}]\\[{f.risk.value}][/] {f.usage}")
        lines.append(f"   fix: {f.fix}")
    return "\n".join(lines)


def prediction_rows(report: FullReport) -> list[tuple[str, str, str]]:
    e = report.exploit
    if e is None or not e.recovered:
        return []
    fwd = [str(x) for x in e.predictions_forward]
    bwd = [str(x) for x in e.predictions_backward]
    rows = []
    for i in range(max(len(fwd), len(bwd))):
        rows.append((str(i + 1), fwd[i] if i < len(fwd) else "",
                     bwd[i] if i < len(bwd) else ""))
    return rows


def build(source, fmt="int", width=32, endian="big", call="getrandbits",
          nbits=32, lo=None, hi=None, forward=8, backward=5) -> FullReport:
    """Run the full pipeline for the TUI (ingest -> detect -> exploit -> remediate)."""
    stream = ingest(source, fmt=fmt, width=width, endian=endian)
    return build_report(stream, call=call, nbits=nbits, lo=lo, hi=hi,
                        forward=forward, backward=backward)


try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Header, Footer, Static, DataTable
    from textual import work
    _HAS_TEXTUAL = True
except ImportError:  # pragma: no cover - optional dependency
    _HAS_TEXTUAL = False


if _HAS_TEXTUAL:

    class DeadpointTUI(App):
        """Interactive detect -> exploit -> remediate dashboard."""

        TITLE = "deadpoint"
        CSS = """
        Screen { layout: vertical; }
        #panels { height: 1fr; }
        #left { width: 40%; }
        #right { width: 60%; }
        Static { padding: 1 2; border: round $panel; height: auto; }
        DataTable { height: 1fr; border: round $panel; }
        """
        BINDINGS = [("q", "quit", "Quit"), ("r", "rerun", "Re-run")]

        def __init__(self, **params):
            super().__init__()
            self.params = params
            self.report: FullReport | None = None

        def compose(self) -> ComposeResult:
            yield Header()
            with Horizontal(id="panels"):
                with Vertical(id="left"):
                    yield Static("Loading...", id="detect")
                    yield Static("", id="remediate")
                with Vertical(id="right"):
                    yield Static("", id="exploit")
                    yield DataTable(id="preds")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#preds", DataTable)
            table.add_columns("#", "forward (next)", "backward (prior)")
            self.run_analysis()

        @work(thread=True, exclusive=True)
        def run_analysis(self) -> None:
            try:
                report = build(**self.params)
            except Exception as exc:  # surface errors in the UI
                self.call_from_thread(
                    self.query_one("#detect", Static).update, f"[red]Error:[/] {exc}")
                return
            self.call_from_thread(self._apply, report)

        def _apply(self, report: FullReport) -> None:
            self.report = report
            self.query_one("#detect", Static).update(detect_panel(report))
            self.query_one("#exploit", Static).update(exploit_panel(report))
            self.query_one("#remediate", Static).update(remediate_panel(report))
            table = self.query_one("#preds", DataTable)
            table.clear()
            for row in prediction_rows(report):
                table.add_row(*row)

        def action_rerun(self) -> None:
            self.run_analysis()


def run_tui(**params) -> None:
    """Launch the TUI (requires the ``[tui]`` extra)."""
    if not _HAS_TEXTUAL:
        raise RuntimeError("the TUI requires Textual: pip install 'deadpoint[tui]'")
    DeadpointTUI(**params).run()
