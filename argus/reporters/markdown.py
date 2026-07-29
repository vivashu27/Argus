"""Markdown reporter."""

from __future__ import annotations

from ..benchmarks.aasb_v1 import DISCLAIMER, benchmark_coverage
from ..core.engine import ScanReport
from ..core.models import Finding, Severity, Status

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _issues(report: ScanReport) -> list[Finding]:
    issues = [f for f in report.result.findings if f.status in (Status.FAIL, Status.WARN)]
    issues.sort(key=lambda f: (-f.severity.rank, f.check_id))
    return issues


def render(report: ScanReport) -> str:
    summary = report.summary
    metadata = report.result.metadata
    out: list[str] = []

    out.append("# Argus Security Assessment\n")
    out.append(f"**Benchmark:** {metadata.benchmark}  ")
    out.append(f"**Scanned:** {metadata.timestamp}  ")
    out.append(f"**Host:** {metadata.hostname} — {metadata.platform}  ")
    out.append(f"**Scanner:** Argus {metadata.scanner_version}\n")

    # Executive summary
    out.append("## Executive Summary\n")
    out.append(
        f"The assessment identified **{summary.critical} Critical**, **{summary.high} High**, "
        f"**{summary.medium} Medium** and **{summary.low} Low** findings across "
        f"{summary.total} checks.\n"
    )
    out.append(
        f"**Security score: {summary.score}/100 (grade {summary.grade})** — "
        f"coverage {summary.coverage} checks passed of those evaluated.\n"
    )
    if summary.manual:
        out.append(
            f"{summary.manual} check(s) require manual review and are not counted as passing.\n"
        )
    if summary.accepted_risk:
        out.append(f"{summary.accepted_risk} finding(s) are recorded as accepted risk.\n")

    # Posture
    out.append("## Security Posture\n")
    out.append("| Status | Count |")
    out.append("| --- | ---: |")
    for label, value in (
        ("Passed", summary.passed),
        ("Failed", summary.failed),
        ("Warnings", summary.warned),
        ("Manual", summary.manual),
        ("Not applicable", summary.not_applicable),
        ("Errors", summary.errors),
        ("Accepted risk", summary.accepted_risk),
    ):
        out.append(f"| {label} | {value} |")
    out.append("")

    out.append("| Severity | Count |")
    out.append("| --- | ---: |")
    for severity in SEVERITY_ORDER:
        count = getattr(summary, severity.value.lower())
        out.append(f"| {severity.value} | {count} |")
    out.append("")

    # Benchmark coverage
    out.append("## Benchmark Coverage\n")
    out.append("| # | Section | Checks | Passed | Failed | Warn | Manual | N/A |")
    out.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in benchmark_coverage(report.result.findings):
        out.append(
            f"| {row['section']} | {row['title']} | {row['checks']} | {row['passed']} | "
            f"{row['failed']} | {row['warned']} | {row['manual']} | {row['not_applicable']} |"
        )
    out.append("")

    # Findings
    issues = _issues(report)
    out.append("## Findings\n")
    if not issues:
        out.append("No failing or warning findings were identified.\n")
    for finding in issues:
        meta = finding.meta
        out.append(f"### {finding.check_id} — {meta.title}\n")
        out.append(
            f"| Field | Value |\n| --- | --- |\n"
            f"| Severity | {finding.severity.value} |\n"
            f"| Status | {finding.display_status} |\n"
            f"| Confidence | {finding.confidence.value} |\n"
            f"| Category | {meta.category.display} |\n"
            f"| AASB | {meta.aasb} (Level {meta.aasb_level}) |\n"
            f"| Affected asset | `{finding.asset}` |\n"
        )
        out.append(f"**Description.** {meta.description}\n")
        if finding.detail:
            out.append(f"**Observation.** {finding.detail}\n")
        if meta.rationale:
            out.append(f"**Technical detail.** {meta.rationale}\n")
        if meta.security_impact:
            out.append(f"**Risk.** {meta.security_impact}\n")

        if finding.evidence:
            out.append("**Evidence.**\n")
            for item in finding.evidence:
                location = item.path or ""
                if item.line:
                    location += f":{item.line}"
                key = f" `{item.key}`" if item.key else ""
                snippet = f" — `{item.snippet}`" if item.snippet else ""
                out.append(f"- {location}{key}{snippet}  \n  {item.reason}")
            out.append("")

        if finding.accepted_risk:
            out.append(f"**Accepted risk.** {finding.acceptance_reason}\n")
        out.append(f"**Remediation.** {meta.remediation}\n")

        if meta.compliance:
            mappings = "; ".join(
                f"{framework}: {', '.join(refs)}" for framework, refs in meta.compliance_dict().items()
            )
            out.append(f"**Compliance mapping.** {mappings}\n")
        if meta.references:
            out.append("**References.** " + ", ".join(meta.references) + "\n")
        out.append("---\n")

    # Manual review
    manual = [f for f in report.result.findings if f.status is Status.MANUAL]
    if manual:
        out.append("## Requires Manual Review\n")
        for finding in manual:
            out.append(f"- **{finding.check_id}** (`{finding.asset}`) — {finding.detail}")
        out.append("")

    # Passed
    passed = [f for f in report.result.findings if f.status is Status.PASS]
    if passed:
        out.append("## Passed Checks\n")
        for finding in passed:
            out.append(f"- **{finding.check_id}** {finding.meta.title} — `{finding.asset}`")
        out.append("")

    # Score derivation
    if summary.breakdown:
        out.append("## Score Derivation\n")
        out.append("Score = 100 − Σ(weight × status multiplier × confidence multiplier)\n")
        out.append("| Check | Asset | Severity | Status | Confidence | Deduction |")
        out.append("| --- | --- | --- | --- | --- | ---: |")
        for deduction in summary.breakdown:
            out.append(
                f"| {deduction.check_id} | `{deduction.asset}` | {deduction.severity} | "
                f"{deduction.status} | {deduction.confidence} | −{deduction.deduction:.1f} |"
            )
        out.append(f"\n**Total deduction: −{sum(b.deduction for b in summary.breakdown):.1f}**\n")

    if metadata.discovery_errors:
        out.append("## Discovery Errors — Coverage Is Incomplete\n")
        out.append(
            "One or more discoverers failed. Assets in the affected domain were never "
            "examined, so the score does not cover them.\n"
        )
        for entry in metadata.discovery_errors:
            out.append(f"- {entry}")
        out.append("")

    if metadata.expired_exceptions:
        out.append("## Expired Exceptions\n")
        for entry in metadata.expired_exceptions:
            out.append(f"- {entry}")
        out.append("")

    if metadata.unreadable_paths:
        out.append("## Unreadable Paths\n")
        out.append("These paths were discovered but could not be read, so coverage is incomplete.\n")
        for entry in metadata.unreadable_paths:
            out.append(f"- `{entry}`")
        out.append("")

    out.append("---\n")
    out.append(f"*{DISCLAIMER}*")
    return "\n".join(out)
