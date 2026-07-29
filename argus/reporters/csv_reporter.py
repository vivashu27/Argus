"""CSV reporter — one row per finding, for spreadsheets and ticket import."""

from __future__ import annotations

import csv
import io

from ..core.engine import ScanReport

COLUMNS = (
    "check_id", "aasb", "title", "category", "severity", "status", "confidence",
    "aasb_level", "asset", "detail", "evidence_count", "evidence", "remediation",
    "accepted_risk", "compliance",
)


def render(report: ScanReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(COLUMNS)

    for finding in report.result.findings:
        meta = finding.meta
        evidence = " | ".join(
            " ".join(
                part
                for part in (
                    e.path,
                    f"line {e.line}" if e.line else None,
                    e.key,
                    e.snippet,
                    f"({e.reason})" if e.reason else None,
                )
                if part
            )
            for e in finding.evidence
        )
        compliance = "; ".join(
            f"{framework}: {', '.join(refs)}"
            for framework, refs in meta.compliance_dict().items()
        )
        writer.writerow(
            [
                finding.check_id,
                meta.aasb,
                meta.title,
                meta.category.value,
                finding.severity.value,
                finding.status.value,
                finding.confidence.value,
                meta.aasb_level,
                finding.asset,
                finding.detail,
                len(finding.evidence),
                evidence,
                meta.remediation,
                "yes" if finding.accepted_risk else "no",
                compliance,
            ]
        )
    return buffer.getvalue()
