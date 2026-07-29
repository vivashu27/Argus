"""SARIF 2.1.0 reporter (spec 7.2).

Each Argus check becomes one ``reportingDescriptor`` rule. Only FAIL, WARN and
MANUAL findings emit results: SARIF has no natural representation for a passing
check, and emitting passes would flood GitHub Security with noise.

Severity mapping: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note.
"""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..core.engine import ScanReport
from ..core.models import Finding, Severity, Status

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/schemas/sarif-schema-2.1.0.json"

LEVEL_FOR_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

REPORTED_STATUSES = (Status.FAIL, Status.WARN, Status.MANUAL)


def _rule(finding: Finding) -> dict[str, Any]:
    meta = finding.meta
    tags = [
        f"aasb-level-{meta.aasb_level}",
        f"category:{meta.category.value}",
        "security",
    ]
    for framework, refs in meta.compliance_dict().items():
        tags.extend(f"{framework}: {ref}" for ref in refs)

    return {
        "id": meta.check_id,
        "name": meta.check_id.replace("-", ""),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.description},
        "help": {
            "text": f"{meta.security_impact}\n\nRemediation: {meta.remediation}",
            "markdown": (
                f"**Impact:** {meta.security_impact}\n\n"
                f"**Rationale:** {meta.rationale}\n\n"
                f"**Remediation:** {meta.remediation}"
            ),
        },
        "defaultConfiguration": {"level": LEVEL_FOR_SEVERITY[meta.severity]},
        "properties": {
            "tags": tags,
            "security-severity": _security_severity(meta.severity),
            "aasb": meta.aasb,
            "aasbLevel": meta.aasb_level,
        },
        "helpUri": meta.references[0] if meta.references else None,
    }


def _security_severity(severity: Severity) -> str:
    """GitHub reads this numeric string to sort and badge alerts."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.5",
        Severity.INFO: "0.0",
    }[severity]


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    locations = []
    for evidence in finding.evidence[:10]:
        if not evidence.path:
            continue
        region: dict[str, Any] = {}
        if evidence.line:
            region["startLine"] = evidence.line
        if evidence.snippet:
            region["snippet"] = {"text": evidence.snippet}
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": str(evidence.path).lstrip("/")},
            }
        }
        if region:
            location["physicalLocation"]["region"] = region
        if evidence.reason:
            location["message"] = {"text": evidence.reason}
        locations.append(location)

    if not locations:
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.asset or finding.check_id}
                }
            }
        ]

    message = finding.detail or finding.meta.title
    if finding.accepted_risk:
        message = f"[ACCEPTED RISK] {message} — {finding.acceptance_reason}"

    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "ruleIndex": rule_index,
        "level": LEVEL_FOR_SEVERITY[finding.severity],
        "message": {"text": message},
        "locations": locations,
        "properties": {
            "status": finding.status.value,
            "confidence": finding.confidence.value,
            "asset": finding.asset,
            "acceptedRisk": finding.accepted_risk,
        },
    }
    if finding.status is Status.MANUAL:
        # SARIF's "review" kind is the closest match for a control needing human
        # adjudication; a MANUAL result must not read as a confirmed failure.
        result["kind"] = "review"
        result["level"] = "note"
    if finding.accepted_risk:
        result["suppressions"] = [
            {"kind": "external", "justification": finding.acceptance_reason or "accepted risk"}
        ]
    return result


def render(report: ScanReport) -> str:
    reported = [f for f in report.result.findings if f.status in REPORTED_STATUSES]

    rule_ids: list[str] = []
    rules: list[dict[str, Any]] = []
    for finding in reported:
        if finding.check_id not in rule_ids:
            rule_ids.append(finding.check_id)
            rules.append(_rule(finding))

    results = [_result(f, rule_ids.index(f.check_id)) for f in reported]

    document = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "fullName": "Argus — AI Agent Security Configuration Auditor",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/argus-security/argus",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report.summary.errors == 0,
                        "endTimeUtc": report.result.metadata.timestamp,
                    }
                ],
                "results": results,
                "properties": {
                    "benchmark": report.result.metadata.benchmark,
                    "score": report.summary.score,
                    "grade": report.summary.grade,
                },
            }
        ],
    }
    return json.dumps(document, indent=2, default=str)
