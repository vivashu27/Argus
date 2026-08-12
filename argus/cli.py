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
    rules_only: bool = typer.Option(False, "--rules-only", help="Run only custom .argus rules; skip the built-in AASB checks."),
    triage: Path | None = typer.Option(None, "--triage", help="Triage file of findings judged false positives (default: .argus-triage.yaml if present)."),
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

    rule_paths = list(rules or []) or [Path(p) for p in config.rules]
    if rules_only and not rule_paths:
        _fail("--rules-only needs rules: pass --rules FILE|DIR, or set 'rules:' in argus.yaml")

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
        rule_paths=rule_paths,
        rules_only=rules_only,
        triage_path=_triage_path(triage, project_root),
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


@app.command()
def dynamo(
    path: Path | None = typer.Option(None, "--path", "-p", help="Project root to search for MCP servers."),
    server: list[str] | None = typer.Option(None, "--server", help="Probe only servers whose id contains this. Repeatable."),
    i_understand: bool = typer.Option(False, "--i-understand-this-executes-code", help="Required. Confirms you accept that dynamo runs the audited servers."),
    allow_network: bool = typer.Option(False, "--allow-network", help="Give probed servers real network access. Exfiltration will succeed, not merely be attempted."),
    include_mutating: bool = typer.Option(False, "--include-mutating", help="Also invoke tools whose name suggests they change state."),
    no_call: bool = typer.Option(False, "--no-call", help="List tools but never invoke them. Weakens DYN-001 and disables DYN-004."),
    timeout: float = typer.Option(20.0, "--timeout", help="Seconds to wait for any single server response."),
    fmt: list[str] | None = typer.Option(None, "--format", "-f", help=f"Output format, repeatable. One of: {', '.join(FORMATS)}."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write reports to this directory."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Report gate: show this severity and above."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit-code gate: fail on this severity and above (default: high)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all evidence and the full probe transcript."),
    exit_zero: bool = typer.Option(False, "--exit-zero", help="Always exit 0 when the probe itself completes."),
    no_user_scope: bool = typer.Option(False, "--no-user-scope", help="Probe only servers declared under --path."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable coloured terminal output."),
) -> None:
    """Audit MCP servers by running them in a sandbox (AASB section 10, DYN-*).

    Unlike 'scan', this executes the servers it audits. It finds what static
    reading cannot: descriptions that mutate after approval, tools that appear
    mid-session, credentials read and echoed back, instructions injected into tool
    output. Every server runs under an unprivileged namespace with no network, no
    access to your real home, and fake credentials planted as tripwires.
    """
    logger = log.configure(verbose=verbose)
    global console
    if no_color:
        console = Console(no_color=True, force_terminal=False)

    from .dynamic.sandbox import SandboxUnavailable, describe_isolation
    from .dynamo import run_probes

    if not i_understand:
        _fail(
            "dynamo executes the MCP servers it audits. That is the point of the "
            "module, and it is not safe to do casually.\n\n"
            "  Re-run with --i-understand-this-executes-code once you have read what "
            "it does:\n"
            "    - each server is launched under an unprivileged bubblewrap namespace\n"
            "    - the host filesystem is read-only and your real home is not mounted\n"
            "    - the network is disabled unless you pass --allow-network\n"
            "    - fake credentials are planted to detect reads\n\n"
            "  A kernel-level namespace escape is not defended against. Do not point "
            "this at a server you believe is actively malicious on a machine you "
            "care about."
        )

    project_root = (path or Path.cwd()).expanduser()
    if not project_root.exists():
        _fail(f"path does not exist: {project_root}")

    try:
        probes, found, reference = run_probes(
            project_root,
            user_scope=not no_user_scope,
            only=set(server) if server else None,
            network=allow_network,
            timeout=timeout,
            call_tools=not no_call,
            include_mutating=include_mutating,
        )
    except SandboxUnavailable as exc:
        _fail(f"no usable sandbox: {exc}", EXIT_SCANNER_ERROR)
    except Exception as exc:  # noqa: BLE001
        _fail(f"probe failed: {type(exc).__name__}: {exc}", EXIT_SCANNER_ERROR)

    err_console.print(Text("sandbox", style="bold"))
    for line in describe_isolation(reference):
        err_console.print(Text(f"  {line}", style="dim"))
    probed = sum(1 for p in probes if p.started)
    err_console.print(
        Text(f"  probed {probed} of {len(found)} discovered server(s)\n", style="dim")
    )
    if allow_network:
        err_console.print(
            Text("  WARNING: --allow-network is set. A malicious server can reach the "
                 "internet from inside the sandbox.\n", style="bold yellow")
        )
    logger.debug("probe candidates: %s", [c.server_id for c in found])

    options = ScanOptions(
        project_root=project_root,
        categories={Category.DYNAMIC},
        user_scope=not no_user_scope,
        probes=probes,
        verbose=verbose,
    )
    try:
        report = run_scan(options)
    except Exception as exc:  # noqa: BLE001
        _fail(f"scoring failed: {type(exc).__name__}: {exc}", EXIT_SCANNER_ERROR)

    if severity:
        report.result.findings = filter_for_display(
            report.result.findings, Severity.parse(severity)
        )
    _emit(report, fmt or ["terminal"], output, verbose)

    if exit_zero:
        raise typer.Exit(EXIT_OK)
    gate = Severity.parse(fail_on) if fail_on else Severity.HIGH
    raise typer.Exit(
        EXIT_FINDINGS if gating_findings(report.result.findings, gate) else EXIT_OK
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
    except Exception as exc:  # noqa: BLE001 — a provider fault is an error, not a traceback
        _fail(f"rule generation failed: {type(exc).__name__}: {exc}", EXIT_SCANNER_ERROR)

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
    from .rules.model import TARGET_FIELDS

    loaded, errors = load_rules(list(paths))
    dead = 0
    for rule in loaded:
        unknown = rule.unknown_fields()
        console.print(
            Text.assemble(
                ("  warn" if unknown else "  ok  ", "yellow" if unknown else "green"),
                (f"  {rule.rule_id:<40} ", "bold"),
                (f"{rule.severity.value:<8} ", "dim"),
                (f"target={rule.target.value} ", "cyan"),
                (f"category={rule.category.value}", "magenta"),
            )
        )
        if unknown:
            dead += 1
            available = ", ".join(sorted(TARGET_FIELDS.get(rule.target, frozenset())))
            console.print(
                Text(
                    f"        field(s) {', '.join(unknown)} do not exist on target "
                    f"'{rule.target.value}', so this rule can never match.\n"
                    f"        available: {available}",
                    style="yellow",
                )
            )
    for message in errors:
        err_console.print(Text(f"  error {message}", style="red"))

    summary = f"\n  {len(loaded)} valid, {len(errors)} invalid"
    summary += f", {dead} that cannot match." if dead else "."
    console.print(Text(summary, style="dim"))
    raise typer.Exit(EXIT_USAGE_ERROR if errors else EXIT_OK)


@rule_app.command("test")
def rule_test(
    paths: list[Path] = typer.Argument(..., help="Rule files or directories."),
    path: Path | None = typer.Option(None, "--path", "-p", help="Project root to test against."),
    no_user_scope: bool = typer.Option(False, "--no-user-scope", help="Skip user-level locations."),
) -> None:
    """Run rules against this environment and show only their findings."""
    log.configure(verbose=False)
    try:
        report = run_scan(
            ScanOptions(
                project_root=(path or Path.cwd()).expanduser(),
                user_scope=not no_user_scope,
                rule_paths=list(paths),
                rules_only=True,
            )
        )
    except Exception as exc:  # noqa: BLE001
        _fail(f"scan failed: {type(exc).__name__}: {exc}", EXIT_SCANNER_ERROR)

    terminal.render(report, console=console, verbose=True)
    raise typer.Exit(
        EXIT_FINDINGS if any(f.is_open for f in report.result.findings) else EXIT_OK
    )


def _triage_path(explicit: Path | None, project_root: Path) -> Path | None:
    """An explicit path is used as given; otherwise the project's file if it exists."""
    from .core.triage import DEFAULT_TRIAGE_FILE

    if explicit is not None:
        if not explicit.is_file():
            _fail(f"triage file not found: {explicit}")
        return explicit
    default = project_root / DEFAULT_TRIAGE_FILE
    return default if default.is_file() else None


triage_app = typer.Typer(
    name="triage",
    help="Record findings judged to be false positives, and list what is suppressed.",
    no_args_is_help=True,
)
app.add_typer(triage_app)


@triage_app.command("add")
def triage_add(
    check: str = typer.Argument(..., help="Check ID to suppress, e.g. MCP-013."),
    reason: str = typer.Option(..., "--reason", help="Why this finding is wrong. Required."),
    report: Path = typer.Option(..., "--report", help="A JSON report from 'argus scan -f json'."),
    asset: str | None = typer.Option(None, "--asset", help="Limit to one asset."),
    file: Path | None = typer.Option(None, "--file", help="Triage file to write (default: .argus-triage.yaml)."),
) -> None:
    """Mark findings in a report as false positives.

    Matching is on the finding's evidence, not its check ID, so suppressing one hit
    does not disable the check. Edit the evidence and it reappears under a new
    fingerprint — which is the intended behaviour, not a bug.
    """
    import json as _json

    from .core.triage import DEFAULT_TRIAGE_FILE, TriageEntry, load_triage, save_triage

    if not reason.strip():
        _fail("--reason cannot be empty. Every suppression must say why the finding is wrong.")
    try:
        payload = _json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"cannot read report {report}: {exc}")

    wanted = check.strip().upper()
    matches = [
        f for f in payload.get("findings", [])
        if str(f.get("id", "")).upper() == wanted
        and (asset is None or f.get("asset") == asset)
        and f.get("status") in ("FAIL", "WARN")
    ]
    if not matches:
        _fail(f"no open {wanted} finding in {report}" + (f" for asset {asset}" if asset else ""))

    destination = file or Path(DEFAULT_TRIAGE_FILE)
    entries = load_triage(destination) if destination.is_file() else []
    known = {e.fingerprint for e in entries}

    added = 0
    for finding in matches:
        mark = _fingerprint_from_report(finding)
        if mark in known:
            continue
        entries.append(
            TriageEntry(
                fingerprint=mark,
                reason=reason.strip(),
                check_id=str(finding.get("id", "")),
                asset=str(finding.get("asset", "")),
                added=_dt.date.today().isoformat(),
            )
        )
        known.add(mark)
        added += 1

    save_triage(destination, entries)
    console.print(
        Text(f"  {added} finding(s) suppressed · {destination} now holds {len(entries)}", "green")
    )
    err_console.print(
        Text("  Suppressed findings are still counted and listed in every report.", "dim")
    )


def _fingerprint_from_report(finding: dict) -> str:
    """Rebuild a finding's fingerprint from its serialised form.

    Kept identical to :func:`argus.core.triage.fingerprint` by reconstructing the
    finding rather than duplicating the hash, so the two can never drift.
    """
    from .core.models import Evidence, Finding, Status
    from .core.registry import get_check
    from .core.triage import fingerprint

    check = get_check(str(finding.get("id", "")))
    if check is None:
        _fail(f"unknown check in report: {finding.get('id')!r}")
        raise AssertionError  # unreachable: _fail raises
    return fingerprint(
        Finding(
            meta=check.meta,
            status=Status(finding.get("status", "FAIL")),
            asset=str(finding.get("asset", "")),
            detail=str(finding.get("detail", "")),
            evidence=[
                Evidence(
                    path=e.get("path"), line=e.get("line"), key=e.get("key"),
                    snippet=e.get("snippet"), reason=e.get("reason", ""),
                )
                for e in finding.get("evidence", [])
            ],
        )
    )


@triage_app.command("list")
def triage_list(
    file: Path | None = typer.Option(None, "--file", help="Triage file to read."),
) -> None:
    """Show every suppressed finding and the reason given."""
    from .core.triage import DEFAULT_TRIAGE_FILE, load_triage

    destination = file or Path(DEFAULT_TRIAGE_FILE)
    entries = load_triage(destination)
    if not entries:
        console.print(Text(f"  No suppressions in {destination}.", "dim"))
        raise typer.Exit(EXIT_OK)

    table = Table(box=None, padding=(0, 2), header_style="dim")
    for column in ("Fingerprint", "Check", "Asset", "Added", "Reason"):
        table.add_column(column)
    for entry in entries:
        table.add_row(entry.fingerprint, entry.check_id, entry.asset, entry.added, entry.reason)
    console.print(table)
    console.print(Text(f"\n  {len(entries)} suppressed finding(s) in {destination}", "dim"))


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
