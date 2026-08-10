"""Terminal reporter, built on rich."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..benchmarks.aasb_v1 import benchmark_coverage
from ..core.engine import ScanReport
from ..core.models import Finding, ScanMetadata, Severity, Status

#: "ANSI Shadow" block lettering. Box-drawing glyphs need a UTF-8 capable stream,
#: so :func:`_supports_unicode` gates it and a plain fallback is always available.
BANNER_LINES = (
    r" █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗",
    r"██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝",
    r"███████║██████╔╝██║  ███╗██║   ██║███████╗",
    r"██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║",
    r"██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║",
    r"╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝",
)

BANNER_WIDTH = max(len(line) for line in BANNER_LINES)

#: Deep blue fading to cyan, top to bottom.
BANNER_GRADIENT = ("#1d4ed8", "#2563eb", "#3b82f6", "#0ea5e9", "#22d3ee", "#67e8f9")

#: Argus Panoptes, the all-seeing hundred-eyed watchman the tool is named for.
EYE = "◉"

TAGLINE = "AI Agent Security Configuration Auditor"

#: Decorative glyphs, with ASCII equivalents for streams that cannot encode them.
#: The fallback must itself be ASCII — an earlier version fell back to "◉ ARGUS",
#: which still raised UnicodeEncodeError on an ASCII stdout.
GLYPHS = {
    True: {"eye": EYE, "dot": "·", "rule": "─"},
    False: {"eye": "*", "dot": "-", "rule": "-"},
}

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

STATUS_STYLE = {
    Status.PASS: "green",
    Status.FAIL: "bold red",
    Status.WARN: "yellow",
    Status.MANUAL: "magenta",
    Status.NOT_APPLICABLE: "dim",
    Status.ERROR: "bold white on dark_red",
}

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _supports_unicode(out: Console) -> bool:
    """Whether the output stream can encode the banner's box-drawing glyphs.

    A CI log or a redirected file may be ASCII-only; printing block characters there
    produces mojibake or a UnicodeEncodeError, so the caller falls back instead.
    """
    encoding = getattr(out.file, "encoding", None) or getattr(sys.stdout, "encoding", None)
    if not encoding:
        return False
    try:
        BANNER_LINES[0].encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def banner(out: Console, metadata: ScanMetadata | None = None) -> None:
    """Print the Argus nameplate.

    Degrades in two steps: block lettering where the terminal is wide enough and can
    encode it, then a single styled line. Colour is left to rich, which strips styles
    automatically under ``--no-color``.
    """
    width = out.width or 80
    unicode_ok = _supports_unicode(out)
    glyph = GLYPHS[unicode_ok]
    out.print()

    if width >= BANNER_WIDTH + 4 and unicode_ok:
        pad = " " * max(0, (min(width, 100) - BANNER_WIDTH) // 2)
        for line, colour in zip(BANNER_LINES, BANNER_GRADIENT, strict=True):
            out.print(Text(pad + line, style=f"bold {colour}"))
        out.print(Text(pad + TAGLINE.center(BANNER_WIDTH), style="italic #67e8f9"))
    else:
        out.print(
            Text.assemble(
                (f"{glyph['eye']} ARGUS", "bold #38bdf8"),
                (f"  {TAGLINE}", "dim"),
            )
        )

    if metadata is None:
        return

    out.print()
    out.print(
        Text.assemble(
            (f"  {glyph['eye']} ", "#67e8f9"),
            (metadata.benchmark, "bold cyan"),
            (f"  {glyph['dot']}  ", "dim"),
            (metadata.hostname, "white"),
            (f"  {glyph['dot']}  ", "dim"),
            (metadata.platform, "dim"),
        )
    )
    out.print(
        Text.assemble(
            ("    scanned ", "dim"),
            (metadata.timestamp, "dim"),
            (f"  {glyph['dot']}  argus ", "dim"),
            (metadata.scanner_version, "dim"),
        )
    )
    out.print(Text("  " + glyph["rule"] * min(width - 4, 76), style="#1d4ed8"))


def render(report: ScanReport, console: Console | None = None, verbose: bool = False) -> None:
    """Print the report. Unlike other reporters this writes directly to a console."""
    out = console or Console()
    summary = report.summary
    metadata = report.result.metadata

    banner(out, metadata)

    # Score
    score_style = "green" if summary.score >= 80 else "yellow" if summary.score >= 60 else "red"
    out.print()
    out.print(
        Text.assemble(
            ("  Argus Security Score: ", "bold"),
            (f"{summary.score}/100", f"bold {score_style}"),
            (f"  (grade {summary.grade})", "dim"),
            (f"   coverage {summary.coverage}", "dim"),
        )
    )
    out.print()

    # Counts
    counts = Table(show_header=True, header_style="dim", box=None, padding=(0, 2))
    counts.add_column("Severity")
    counts.add_column("Count", justify="right")
    counts.add_column("Status")
    counts.add_column("Count", justify="right")

    status_rows = [
        ("Passed", summary.passed, Status.PASS),
        ("Failed", summary.failed, Status.FAIL),
        ("Warnings", summary.warned, Status.WARN),
        ("Manual", summary.manual, Status.MANUAL),
        ("Not applicable", summary.not_applicable, Status.NOT_APPLICABLE),
    ]
    severity_rows = [(s, getattr(summary, s.value.lower())) for s in SEVERITY_ORDER]

    for index in range(max(len(status_rows), len(severity_rows))):
        left_label = left_value = right_label = right_value = ""
        left_style = right_style = ""
        if index < len(severity_rows):
            severity, value = severity_rows[index]
            left_label, left_value = severity.value.title(), str(value)
            left_style = SEVERITY_STYLE[severity] if value else "dim"
        if index < len(status_rows):
            label, value, status = status_rows[index]
            right_label, right_value = label, str(value)
            right_style = STATUS_STYLE[status] if value else "dim"
        counts.add_row(
            Text(left_label, style=left_style),
            Text(left_value, style=left_style),
            Text(right_label, style=right_style),
            Text(right_value, style=right_style),
        )
    out.print(counts)

    if summary.errors:
        out.print(Text(f"  {summary.errors} check(s) errored — coverage is incomplete.", "bold red"))
    if summary.accepted_risk:
        out.print(Text(f"  {summary.accepted_risk} finding(s) accepted as risk.", "yellow"))
    if summary.suppressed:
        # Disclosed unconditionally. How much of a clean report rests on suppression
        # is exactly what a reader needs to know about it.
        out.print(
            Text(
                f"  {summary.suppressed} finding(s) suppressed as false positives "
                "— see 'argus triage list'.",
                "yellow",
            )
        )

    # Findings
    issues = [f for f in report.result.findings if f.status in (Status.FAIL, Status.WARN)]
    issues.sort(key=lambda f: (-f.severity.rank, f.check_id))

    if issues:
        out.print()
        out.rule("[bold]Findings", style="dim")
        for finding in issues:
            _print_finding(out, finding, verbose)
    else:
        out.print()
        out.print(Text("  No failing or warning findings.", "green"))

    manual = [f for f in report.result.findings if f.status is Status.MANUAL]
    if manual:
        out.print()
        out.rule("[bold]Requires manual review", style="dim")
        for finding in manual:
            out.print(
                Text.assemble(
                    ("  MANUAL  ", "magenta"),
                    (f"{finding.check_id}  ", "bold"),
                    (f"{finding.meta.title}\n", ""),
                    (f"          {finding.asset} — {finding.detail}", "dim"),
                )
            )

    errors = [f for f in report.result.findings if f.status is Status.ERROR]
    if errors:
        out.print()
        out.rule("[bold red]Check errors", style="red")
        for finding in errors:
            out.print(Text(f"  {finding.check_id}: {finding.detail}", "red"))

    if verbose:
        # An all-zero coverage table after a rules-only scan reads as "the benchmark
        # found nothing", when in fact no benchmark check ran at all.
        if any(not f.check_id.startswith("CUSTOM-") for f in report.result.findings):
            _print_coverage(out, report)
        _print_breakdown(out, report)

    if metadata.discovery_errors:
        out.print()
        out.rule("[bold red]Discovery errors — coverage is INCOMPLETE", style="red")
        out.print(
            Text(
                "  One or more discoverers failed. Assets in the affected domain were "
                "never examined, so the score below does not cover them.",
                "red",
            )
        )
        for entry in metadata.discovery_errors:
            out.print(Text(f"    {entry}", "red"))

    if metadata.expired_exceptions:
        out.print()
        out.rule("[bold yellow]Expired exceptions", style="yellow")
        for entry in metadata.expired_exceptions:
            out.print(Text(f"  {entry}", "yellow"))

    if metadata.unreadable_paths:
        # Deliberately prominent rather than dim: an asset that was discovered but not
        # scanned is a coverage hole, and padding a file past the read cap is a known
        # scanner-evasion technique. A quiet footnote here would let a perfect score
        # sit next to an unexamined skill.
        out.print()
        out.rule("[bold yellow]Not scanned — coverage is incomplete", style="yellow")
        out.print(
            Text(
                f"  {len(metadata.unreadable_paths)} discovered path(s) were unreadable or "
                "over the size cap and were NOT analyzed. The score does not cover them.",
                "yellow",
            )
        )
        for entry in metadata.unreadable_paths[:20]:
            out.print(Text(f"    {entry}", "yellow"))
    out.print()


def _print_finding(out: Console, finding: Finding, verbose: bool) -> None:
    meta = finding.meta
    severity_style = SEVERITY_STYLE[finding.severity]

    out.print()
    out.print(
        Text.assemble(
            (f" {finding.severity.value:<8} ", severity_style),
            (f" {finding.check_id}", "bold"),
            (f" [AASB {meta.aasb} L{meta.aasb_level}] ", "dim"),
            (meta.title, ""),
        )
    )
    out.print(
        Text.assemble(
            ("          status ", "dim"),
            (finding.display_status, STATUS_STYLE[finding.status]),
            ("  ·  confidence ", "dim"),
            (finding.confidence.value, "dim"),
            ("  ·  asset ", "dim"),
            (finding.asset or "-", "cyan"),
        )
    )
    if finding.detail:
        out.print(Text(f"          {finding.detail}", ""))

    for item in finding.evidence[: (None if verbose else 3)]:
        location = item.path or ""
        if item.line:
            location += f":{item.line}"
        bits = [b for b in (location, item.key, item.snippet) if b]
        out.print(Text(f"            • {'  '.join(bits)}", "dim"))
        if item.reason:
            out.print(Text(f"              {item.reason}", "dim italic"))

    hidden = len(finding.evidence) - 3
    if not verbose and hidden > 0:
        out.print(Text(f"            … {hidden} more evidence item(s) — use --verbose", "dim"))

    if finding.suppressed:
        out.print(Text(f"          FALSE POSITIVE: {finding.suppression_reason}", "yellow"))
    if finding.accepted_risk:
        out.print(Text(f"          ACCEPTED RISK: {finding.acceptance_reason}", "yellow"))
    out.print(Text(f"          fix: {meta.remediation}", "green"))


def _print_coverage(out: Console, report: ScanReport) -> None:
    out.print()
    out.rule("[bold]Benchmark coverage", style="dim")
    table = Table(box=None, padding=(0, 2), header_style="dim")
    table.add_column("#")
    table.add_column("Section")
    for column in ("Checks", "Pass", "Fail", "Warn", "Manual", "N/A"):
        table.add_column(column, justify="right")
    for row in benchmark_coverage(report.result.findings):
        table.add_row(
            str(row["section"]), row["title"], str(row["checks"]), str(row["passed"]),
            str(row["failed"]), str(row["warned"]), str(row["manual"]), str(row["not_applicable"]),
        )
    out.print(table)


def _print_breakdown(out: Console, report: ScanReport) -> None:
    breakdown = report.summary.breakdown
    if not breakdown:
        return
    out.print()
    out.rule("[bold]Score derivation", style="dim")
    out.print(
        Text("  score = 100 − Σ(severity weight × status multiplier × confidence multiplier)", "dim")
    )
    table = Table(box=None, padding=(0, 2), header_style="dim")
    table.add_column("Check")
    table.add_column("Asset")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Conf")
    table.add_column("Deduction", justify="right")
    for item in breakdown:
        table.add_row(
            item.check_id, item.asset, item.severity, item.status, item.confidence,
            f"−{item.deduction:.1f}",
        )
    out.print(table)
    out.print(
        Text(f"  total deduction: −{sum(b.deduction for b in breakdown):.1f}", "bold")
    )
