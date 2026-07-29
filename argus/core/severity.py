"""Severity filtering helpers.

Two distinct gates, deliberately kept separate (spec 3.5):

* the *display* gate (``--severity``) controls what appears in reports
* the *exit-code* gate (``--fail-on``) controls the process exit status

Both mean "this level and above".
"""

from __future__ import annotations

from .models import Finding, Severity, Status


def at_or_above(severity: Severity, threshold: Severity) -> bool:
    return severity.rank >= threshold.rank


def filter_for_display(findings: list[Finding], threshold: Severity | None) -> list[Finding]:
    """Apply the display gate.

    PASS, MANUAL, NOT_APPLICABLE and ERROR results are always retained: hiding an
    unevaluated or errored control behind a severity filter would misrepresent
    coverage.
    """
    if threshold is None:
        return findings
    keep_regardless = (Status.PASS, Status.MANUAL, Status.NOT_APPLICABLE, Status.ERROR)
    return [
        f
        for f in findings
        if f.status in keep_regardless or at_or_above(f.severity, threshold)
    ]


def gating_findings(findings: list[Finding], fail_on: Severity) -> list[Finding]:
    """Findings that trip a non-zero exit code.

    Only open FAILs gate. WARN and MANUAL never do, and accepted risks are excluded
    via :attr:`Finding.is_open`.
    """
    return [f for f in findings if f.is_open and at_or_above(f.severity, fail_on)]
