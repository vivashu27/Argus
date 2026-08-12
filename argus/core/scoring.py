"""Transparent security scoring (spec 3.4).

The score is a weighted deduction from 100. Every deduction is retained in
:class:`ScoreBreakdown` so a reader can recompute the score by hand from the report —
a score that cannot be audited is not useful in a security report.

    deduction = weight[severity] * status_multiplier * confidence_multiplier
    score     = round(max(0, 100 - sum(deductions)))

MANUAL, NOT_APPLICABLE and ERROR never deduct: an unevaluated control is not a
passing control, and must not be laundered into a better score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Confidence, Finding, Severity, Status

DEFAULT_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 10.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}

STATUS_MULTIPLIER: dict[Status, float] = {
    Status.FAIL: 1.0,
    Status.WARN: 0.5,
    Status.PASS: 0.0,
    Status.MANUAL: 0.0,
    Status.NOT_APPLICABLE: 0.0,
    Status.ERROR: 0.0,
}

CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.8,
    Confidence.LOW: 0.5,
}

GRADE_BANDS: tuple[tuple[int, str], ...] = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


@dataclass
class ScoreBreakdown:
    """One deduction line, retained so the score is reproducible."""

    check_id: str
    asset: str
    severity: str
    status: str
    confidence: str
    deduction: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "asset": self.asset,
            "severity": self.severity,
            "status": self.status,
            "confidence": self.confidence,
            "deduction": round(self.deduction, 2),
        }


@dataclass
class Summary:
    score: int = 100
    grade: str = "A"
    total: int = 0
    passed: int = 0
    failed: int = 0
    warned: int = 0
    manual: int = 0
    not_applicable: int = 0
    errors: int = 0
    accepted_risk: int = 0
    suppressed: int = 0
    advisory: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    breakdown: list[ScoreBreakdown] = field(default_factory=list)

    @property
    def applicable(self) -> int:
        return self.total - self.not_applicable - self.errors

    @property
    def coverage(self) -> str:
        return f"{self.passed}/{self.applicable}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "coverage": self.coverage,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "warned": self.warned,
            "manual": self.manual,
            "not_applicable": self.not_applicable,
            "errors": self.errors,
            "accepted_risk": self.accepted_risk,
            "suppressed": self.suppressed,
            "advisory": self.advisory,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "score_breakdown": [b.to_dict() for b in self.breakdown],
        }


def grade_for(score: int) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def score_findings(
    findings: list[Finding],
    *,
    weights: dict[Severity, float] | None = None,
    score_accepted_risk: bool = False,
) -> Summary:
    """Compute the summary and score for a set of findings."""
    active_weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    summary = Summary(total=len(findings))

    severity_counters = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "info",
    }
    status_counters = {
        Status.PASS: "passed",
        Status.FAIL: "failed",
        Status.WARN: "warned",
        Status.MANUAL: "manual",
        Status.NOT_APPLICABLE: "not_applicable",
        Status.ERROR: "errors",
    }

    total_deduction = 0.0
    for finding in findings:
        setattr(summary, status_counters[finding.status], getattr(summary, status_counters[finding.status]) + 1)

        if finding.status in (Status.FAIL, Status.WARN):
            attr = severity_counters[finding.severity]
            setattr(summary, attr, getattr(summary, attr) + 1)

        if finding.advisory:
            # A model's judgement. Counted and reported in full, but never scored:
            # the same environment can be judged differently on two runs, and a
            # score that moves without the environment moving is not a measurement.
            if finding.status in (Status.FAIL, Status.WARN):
                summary.advisory += 1
            continue
        if finding.suppressed:
            # Judged wrong by a human: it cannot deduct, but it is still counted so
            # the report shows how much of the result rests on suppression.
            summary.suppressed += 1
            continue
        if finding.accepted_risk:
            summary.accepted_risk += 1
            if not score_accepted_risk:
                continue

        deduction = (
            active_weights.get(finding.severity, 0.0)
            * STATUS_MULTIPLIER[finding.status]
            * CONFIDENCE_MULTIPLIER[finding.confidence]
        )
        if deduction > 0:
            total_deduction += deduction
            summary.breakdown.append(
                ScoreBreakdown(
                    check_id=finding.check_id,
                    asset=finding.asset,
                    severity=finding.severity.value,
                    status=finding.status.value,
                    confidence=finding.confidence.value,
                    deduction=deduction,
                )
            )

    summary.score = int(round(max(0.0, 100.0 - total_deduction)))
    summary.grade = grade_for(summary.score)
    summary.breakdown.sort(key=lambda b: b.deduction, reverse=True)
    return summary
