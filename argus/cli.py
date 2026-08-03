"""The ``argus`` command line interface.

Exit codes (spec 3.5):
    0  no FAIL findings at or above --fail-on
    1  FAIL findings at or above --fail-on
    2  scanner error
    3  usage or configuration error
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__, log
from .benchmarks import aasb_v1
from .config import ArgusConfig, find_config, load_config
from .core.engine import Exception_, ScanOptions, ScanReport, run_scan
from .core.exceptions import ArgusConfigError, ArgusScanError
from .core.models import Category, Severity, Status, Target
from .core.registry import all_checks, get_check
from .core.severity import filter_for_display, gating_findings
from .reporters import FORMATS, extension, render, terminal

EnumT = TypeVar("EnumT", Category, Target)  # value-constrained: the two filter enums

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_SCANNER_ERROR = 2
EXIT_USAGE_ERROR = 3

app = typer.Typer(
    name="argus",
    help=(
        "Argus — AI Agent Security Configuration Auditor.\n\n"
        "Read-only auditing of Claude Code, Claude Desktop, MCP servers, Skills, "
        "Plugins, hooks and instruction files against the Argus Agent Security "
        "Benchmark (AASB). Never executes scanned content."
    ),
    add_completion=False,
    no_args_is_help=True,
)

def _safe_stream() -> None:
    """Degrade unencodable characters instead of raising.

    Report text contains bullets, ellipses and box drawing. On an ASCII stdout —
    a redirected CI log, or PYTHONIOENCODING=ascii — writing those raises
    UnicodeEncodeError and kills the run. Replacement is the right trade here:
    a slightly mangled glyph beats a crashed security scan.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="replace")


_safe_stream()

console = Console()
err_console = Console(stderr=True)

# Checks self-register on import.
from . import checks as _checks  # noqa: E402,F401


def _fail(message: str, code: int = EXIT_USAGE_ERROR) -> None:
    err_console.print(Text(f"error: {message}", style="bold red"))
    raise typer.Exit(code)


def _parse_enum_list(
    values: list[str] | None,
    parser: Callable[[str], EnumT],
    label: str,
) -> set[EnumT] | None:
    if not values:
        return None
    out: set[EnumT] = set()
    for value in values:
        for part in str(value).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                out.add(parser(part))
            except ValueError as exc:
                _fail(f"invalid {label}: {exc}")
    return out or None


def _resolve_exceptions(config: ArgusConfig) -> list[Exception_]:
    out: list[Exception_] = []
    for entry in config.exceptions:
        out.append(
            Exception_(
                check_id=str(entry.get("check_id", "")),
                asset=str(entry["asset"]) if entry.get("asset") else None,
                reason=str(entry.get("reason", "")),
                expires=str(entry["expires"]) if entry.get("expires") else None,
            )
        )
    return out


@app.command()
def scan(
    all_targets: bool = typer.Option(False, "--all", help="Scan every target (default when --target is omitted)."),
    target: list[str] | None = typer.Option(None, "--target", "-t", help="Limit to a target: claude-code, claude-desktop, mcp, skills, plugins, hooks, instructions, ide, filesystem."),
    category: list[str] | None = typer.Option(None, "--category", "-c", help="Limit to a check category: claude, mcp, skills, plugins, hooks, instructions, secrets, filesystem."),
    check: list[str] | None = typer.Option(None, "--check", help="Run only these check IDs."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Skip these check IDs. Always wins over --check."),
    level: int | None = typer.Option(None, "--level", "-l", min=1, max=2, help="AASB level: 1 = basic hygiene, 2 = includes defense in depth."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Report gate: show this severity and above."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit-code gate: fail on this severity and above (default: high)."),
    fmt: list[str] | None = typer.Option(None, "--format", "-f", help=f"Output format, repeatable. One of: {', '.join(FORMATS)}."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write reports to this directory."),
    path: Path | None = typer.Option(None, "--path", "-p", help="Project root to scan (default: current directory)."),
    config_file: Path | None = typer.Option(None, "--config", help="Path to argus.yaml."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all evidence, coverage, and score derivation."),
    exit_zero: bool = typer.Option(False, "--exit-zero", help="Always exit 0 when the scan itself completes."),
    no_user_scope: bool = typer.Option(False, "--no-user-scope", help="Scan only --path; skip user-level locations (~/.claude, Claude Desktop)."),
    rules: list[Path] | None = typer.Option(None, "--rules", "-r", help="Custom .argus rule file or directory. Repeatable."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured terminal output."),
) -> None:
    """Discover and audit AI-agent configuration in this environment."""
    logger = log.configure(verbose=verbose)
    global console
    if no_color:
        console = Console(no_color=True, force_terminal=False)

    project_root = (path or Path.cwd()).expanduser()
    if not project_root.exists():
        _fail(f"path does not exist: {project_root}")

    # --- configuration, CLI takes precedence (spec 9) ------------------------
    try:
        config = load_config(find_config(project_root, config_file))
    except ArgusConfigError as exc:
        _fail(str(exc))

    if config.path and path is None:
        project_root = Path(config.path).expanduser()

    targets = _parse_enum_list(target, Target.parse, "target")
    if targets is None and config.include and not all_targets:
        targets = set(config.include)

    categories = _parse_enum_list(category, Category.parse, "category")
    if categories is None and config.categories:
        categories = set(config.categories)

    effective_level = level if level is not None else config.level

    exclude_ids = list(exclude or [])
    exclude_ids.extend(config.exclude)

    try:
        display_gate = Severity.parse(severity) if severity else None
        gate = Severity.parse(fail_on) if fail_on else config.severity_threshold
    except ValueError as exc:
        _fail(str(exc))

    formats = [f.lower() for f in (fmt or [])] or config.report.formats
    for name in formats:
        if name not in FORMATS:
            _fail(f"unknown format '{name}'. Choose from: {', '.join(FORMATS)}")

    output_dir = output or (Path(config.report.output) if config.report.output else None)
    file_formats = [f for f in formats if f != "terminal"]
    if len(file_formats) > 1 and output_dir is None:
        _fail("multiple output formats require --output DIR")

    # --- run ------------------------------------------------------------------
    options = ScanOptions(
        project_root=project_root,
        targets=targets,
        categories=categories,
        include_ids=list(check) if check else None,
        exclude_ids=exclude_ids or None,
        level=effective_level,
        exceptions=_resolve_exceptions(config),
        weights=config.weights or None,
        score_accepted_risk=config.score_accepted_risk,
        user_scope=not no_user_scope,
        rule_paths=list(rules or []) or [Path(p) for p in config.rules],
        verbose=verbose,
    )

    try:
        report = run_scan(options)
    except ArgusScanError as exc:
        _fail(str(exc), EXIT_SCANNER_ERROR)
    except Exception as exc:  # noqa: BLE001 — surface as scanner error, not a traceback
        logger.debug("scan failed", exc_info=True)
        _fail(f"scan failed: {type(exc).__name__}: {exc}", EXIT_SCANNER_ERROR)

    if not report.result.findings:
        err_console.print(
            Text("warning: no checks produced results — nothing was discovered to audit.", "yellow")
        )

    # The display gate must not alter the score, which is computed over all findings.
    display_report = ScanReport(
        result=type(report.result)(
            metadata=report.result.metadata,
            findings=filter_for_display(report.result.findings, display_gate),
            assets=report.result.assets,
        ),
        summary=report.summary,
    )

    _emit(display_report, formats, output_dir, verbose)

    # --- exit code ------------------------------------------------------------
    if exit_zero:
        raise typer.Exit(EXIT_OK)
    gating = gating_findings(report.result.findings, gate)
    if gating:
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_OK)


def _emit(report: ScanReport, formats: list[str], output_dir: Path | None, verbose: bool) -> None:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if output_dir is not None:
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _fail(f"cannot create output directory {output_dir}: {exc}", EXIT_SCANNER_ERROR)

    for name in formats:
        if name == "terminal":
            terminal.render(report, console=console, verbose=verbose)
            continue

        content = render(name, report)
        if output_dir is None:
            console.print(content, markup=False, highlight=False, soft_wrap=True)
            continue

        destination = output_dir / f"argus-report-{stamp}.{extension(name)}"
        try:
            destination.write_text(content, encoding="utf-8")
        except OSError as exc:
            _fail(f"cannot write {destination}: {exc}", EXIT_SCANNER_ERROR)
        err_console.print(Text(f"wrote {destination}", style="green"))


@app.command("list-checks")
def list_checks(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category."),
    target: str | None = typer.Option(None, "--target", "-t", help="Filter by target."),
    level: int | None = typer.Option(None, "--level", "-l", min=1, max=2, help="Filter by AASB level."),
) -> None:
    """List every registered AASB check."""
    try:
        want_category = Category.parse(category) if category else None
        want_target = Target.parse(target) if target else None
    except ValueError as exc:
        _fail(str(exc))

    table = Table(title=f"{aasb_v1.FULL_NAME} — registered checks", header_style="bold")
    table.add_column("ID", style="bold")
    table.add_column("AASB")
    table.add_column("L", justify="center")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Title")

    count = 0
    for check_cls in all_checks():
        meta = check_cls.meta
        if want_category and meta.category is not want_category:
            continue
        if want_target and want_target not in meta.applies_to:
            continue
        if level is not None and meta.aasb_level > level:
            continue
        count += 1
        table.add_row(
            meta.check_id,
            meta.aasb,
            str(meta.aasb_level),
            Text(meta.severity.value, style=terminal.SEVERITY_STYLE[meta.severity]),
            meta.category.display,
            meta.title,
        )

    console.print(table)
    console.print(Text(f"  {count} check(s).", style="dim"))


@app.command("list-benchmarks")
def list_benchmarks() -> None:
    """Describe the AASB benchmark, its sections, and its levels."""
    console.print()
    console.print(Text(aasb_v1.FULL_NAME, style="bold"))
    console.print(Text(aasb_v1.DESCRIPTION, style="dim"))
    console.print()

    table = Table(header_style="bold")
    table.add_column("Section")
    table.add_column("Title")
    table.add_column("Checks", justify="right")
    table.add_column("Level 1", justify="right")
    table.add_column("Level 2", justify="right")

    total = 0
    for section in aasb_v1.sections():
        total += section.total
        table.add_row(
            str(section.number), section.title, str(section.total),
            str(section.level1), str(section.level2),
        )
    console.print(table)
    console.print(Text(f"  {total} check(s) total.", style="dim"))

    console.print()
    for info in aasb_v1.LEVELS.values():
        console.print(Text(info["name"], style="bold"))
        console.print(Text(f"  {info['description']}", style="dim"))
    console.print()
    console.print(Text(aasb_v1.DISCLAIMER, style="yellow"))
    console.print()


@app.command()
def info(check_id: str = typer.Argument(..., help="Check ID (MCP-003) or AASB number (2.3).")) -> None:
    """Show full metadata for one check."""
    check_cls = get_check(check_id)
    if check_cls is None:
        _fail(f"unknown check: {check_id}. Try 'argus list-checks'.")
        return  # unreachable: _fail raises, but this keeps the type narrowed

    meta = check_cls.meta
    console.print()
    console.print(Text(f"{meta.check_id} — {meta.title}", style="bold"))
    console.print()

    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Field", style="dim")
    table.add_column("Value")
    table.add_row("AASB", f"{meta.aasb} (Level {meta.aasb_level})")
    table.add_row("Category", f"{meta.category.display} ({meta.category.value})")
    table.add_row("Severity", Text(meta.severity.value, style=terminal.SEVERITY_STYLE[meta.severity]))
    table.add_row("Applies to", ", ".join(sorted(t.value for t in meta.applies_to)))
    console.print(table)

    for label, value in (
        ("Description", meta.description),
        ("Rationale", meta.rationale),
        ("Security impact", meta.security_impact),
        ("Remediation", meta.remediation),
    ):
        if value:
            console.print()
            console.print(Text(label, style="bold"))
            console.print(Text(f"  {value}"))

    if meta.compliance:
        console.print()
        console.print(Text("Compliance mappings", style="bold"))
        for framework, refs in meta.compliance_dict().items():
            console.print(Text(f"  {framework}: {', '.join(refs)}", style="dim"))

    if meta.references:
        console.print()
        console.print(Text("References", style="bold"))
        for reference in meta.references:
            console.print(Text(f"  {reference}", style="dim"))
    console.print()


@app.command()
def check(
    check_id: str = typer.Argument(..., help="Check ID to run."),
    path: Path | None = typer.Option(None, "--path", "-p", help="Project root to scan."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all evidence."),
) -> None:
    """Run exactly one check. Alias for 'argus scan --check ID'."""
    if get_check(check_id) is None:
        _fail(f"unknown check: {check_id}. Try 'argus list-checks'.")

    log.configure(verbose=verbose)
    options = ScanOptions(
        project_root=(path or Path.cwd()).expanduser(),
        include_ids=[check_id],
        verbose=verbose,
    )
    try:
        report = run_scan(options)
    except Exception as exc:  # noqa: BLE001
        _fail(f"scan failed: {type(exc).__name__}: {exc}", EXIT_SCANNER_ERROR)

    terminal.render(report, console=console, verbose=verbose)
    raise typer.Exit(
        EXIT_FINDINGS
        if any(f.status is Status.FAIL and not f.accepted_risk for f in report.result.findings)
        else EXIT_OK
    )


rule_app = typer.Typer(
    name="rule",
    help="Create, validate and test custom .argus rules.",
    no_args_is_help=True,
)
app.add_typer(rule_app)


@rule_app.command("new")
def rule_new(
    prompt: str = typer.Argument(..., help="Describe what the rule should detect."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write to this path instead of stdout."),
    provider: str = typer.Option("openai", "--provider", help="openai | anthropic | moonshot | deepseek."),
    model: str | None = typer.Option(None, "--model", help="Override the provider default model."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Generate a rule from a prompt using an AI provider.

    Only your prompt and the rule schema are sent. No scanned configuration ever
    leaves the machine, and the result is validated before it is written.
    """
    from .rules.generate import GeneratedRule, LLMError, RuleError, generate_rule
    from .rules.providers import build_provider, consent_line

    try:
        preview = build_provider(provider, model=model, api_key="preview")
        err_console.print(Text(consent_line(preview), style="dim"))
    except LLMError as exc:
        _fail(str(exc))

    try:
        generated: GeneratedRule = generate_rule(prompt, provider=provider, model=model)
    except LLMError as exc:
        _fail(str(exc), EXIT_SCANNER_ERROR)
    except RuleError as exc:
        _fail(f"the model did not produce a valid rule — {exc}", EXIT_SCANNER_ERROR)

    if output is None:
        console.print(generated.yaml_text, markup=False, highlight=False)
        raise typer.Exit(EXIT_OK)

    destination = output if output.suffix == ".argus" else output.with_suffix(".argus")
    if destination.exists() and not force:
        _fail(f"{destination} already exists. Pass --force to overwrite.")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(generated.yaml_text, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write {destination}: {exc}", EXIT_SCANNER_ERROR)

    err_console.print(Text(f"wrote {destination}", style="green"))
    console.print(
        Text(f"  Review it before use, then run: argus scan --rules {destination}", style="dim")
    )
    raise typer.Exit(EXIT_OK)


@rule_app.command("validate")
def rule_validate(
    paths: list[Path] = typer.Argument(..., help="Rule files or directories."),
) -> None:
    """Check that rule files parse and conform to the schema."""
    from .rules import load_rules

    loaded, errors = load_rules(list(paths))
    for rule in loaded:
        console.print(
            Text.assemble(("  ok  ", "green"), (f"{rule.rule_id:<40} ", "bold"),
                          (f"{rule.severity.value:<8} ", "dim"),
                          (f"target={rule.target.value} ", "cyan"),
                          (f"category={rule.category.value}", "magenta"))
        )
    for message in errors:
        err_console.print(Text(f"  error {message}", style="red"))

    console.print(Text(f"\n  {len(loaded)} valid, {len(errors)} invalid.", style="dim"))
    raise typer.Exit(EXIT_USAGE_ERROR if errors else EXIT_OK)


@rule_app.command("test")
def rule_test(
    paths: list[Path] = typer.Argument(..., help="Rule files or directories."),
    path: Path | None = typer.Option(None, "--path", "-p", help="Project root to test against."),
    no_user_scope: bool = typer.Option(False, "--no-user-scope", help="Skip user-level locations."),
) -> None:
    """Run rules against this environment and show only their findings."""
    from .core.models import Category

    log.configure(verbose=False)
    try:
        report = run_scan(
            ScanOptions(
                project_root=(path or Path.cwd()).expanduser(),
                categories={Category.CUSTOM},
                user_scope=not no_user_scope,
                rule_paths=list(paths),
            )
        )
    except Exception as exc:  # noqa: BLE001
        _fail(f"scan failed: {type(exc).__name__}: {exc}", EXIT_SCANNER_ERROR)

    terminal.render(report, console=console, verbose=True)
    raise typer.Exit(
        EXIT_FINDINGS if any(f.is_open for f in report.result.findings) else EXIT_OK
    )


@app.command()
def version() -> None:
    """Print version information."""
    terminal.banner(console)
    console.print()
    console.print(Text.assemble(("  version    ", "dim"), (__version__, "bold")))
    console.print(Text.assemble(("  benchmark  ", "dim"), (aasb_v1.FULL_NAME, "cyan")))
    console.print(Text.assemble(("  checks     ", "dim"), (str(len(all_checks())), "bold")))
    console.print()
    # Short form here so it does not wrap; the full text is in list-benchmarks.
    console.print(
        Text(
            "  AASB is an original Argus benchmark. Not affiliated with or certified\n"
            "  by CIS, Anthropic, OpenAI, or any other organization.",
            style="dim italic",
        )
    )
    console.print()


def main() -> None:
    """Console-script entry point."""
    try:
        app()
    except ArgusConfigError as exc:
        err_console.print(Text(f"error: {exc}", style="bold red"))
        sys.exit(EXIT_USAGE_ERROR)
    except ArgusScanError as exc:
        err_console.print(Text(f"error: {exc}", style="bold red"))
        sys.exit(EXIT_SCANNER_ERROR)
    except KeyboardInterrupt:
        err_console.print(Text("interrupted", style="yellow"))
        sys.exit(EXIT_SCANNER_ERROR)


if __name__ == "__main__":
    main()
