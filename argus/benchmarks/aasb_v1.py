"""Argus Agent Security Benchmark (AASB) v1.0.

A CIS-inspired configuration baseline. **Not** an official CIS benchmark, and not
affiliated with or certified by CIS, Anthropic, or any other organization.

Benchmark numbers are derived, not stored: ``CLAUDE-001`` renders as AASB ``1.1``
via ``CheckMeta.aasb`` (spec 3.1). This module supplies the section metadata and
level definitions that make those numbers meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.models import Category, Finding, Status
from ..core.registry import all_checks

NAME = "Argus Agent Security Benchmark"
SHORT_NAME = "AASB"
VERSION = "1.0"
FULL_NAME = f"{NAME} ({SHORT_NAME}) v{VERSION}"
DESCRIPTION = "CIS-inspired security configuration baseline for AI-agent environments"

DISCLAIMER = (
    "AASB is an original Argus benchmark inspired by CIS-style baselines. It is not a "
    "CIS Benchmark, and Argus is not affiliated with or certified by CIS, Anthropic, "
    "OpenAI, or any other organization."
)

LEVELS: dict[int, dict[str, str]] = {
    1: {
        "name": "Level 1 — Basic security hygiene",
        "description": (
            "Detects a concrete misconfiguration with a low false-positive rate, where the "
            "remediation does not materially reduce usability. Suitable as a minimum "
            "baseline for any agent environment."
        ),
    },
    2: {
        "name": "Level 2 — Defense in depth",
        "description": (
            "Requires tightening that may constrain legitimate workflows, or detects a "
            "heuristic or contextual risk. Intended for environments handling sensitive "
            "data or operating with elevated privilege."
        ),
    },
}

SECTION_TITLES: dict[int, str] = {
    1: "Claude Configuration",
    2: "MCP Security",
    3: "Skills",
    4: "Plugins",
    5: "Hooks",
    6: "Instruction Files",
    7: "Secrets",
    8: "Filesystem",
    9: "LLM-Assisted Review",
}


@dataclass
class SectionSummary:
    number: int
    title: str
    category: Category
    total: int
    level1: int
    level2: int
    check_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "title": self.title,
            "category": self.category.value,
            "total": self.total,
            "level_1": self.level1,
            "level_2": self.level2,
            "check_ids": self.check_ids,
        }


def sections() -> list[SectionSummary]:
    """Summarise the registered benchmark, grouped by section."""
    grouped: dict[int, list] = {}
    for check in all_checks():
        grouped.setdefault(check.meta.category.section, []).append(check.meta)

    out: list[SectionSummary] = []
    for number in sorted(grouped):
        metas = sorted(grouped[number], key=lambda m: int(m.check_id.rsplit("-", 1)[-1]))
        out.append(
            SectionSummary(
                number=number,
                title=SECTION_TITLES.get(number, metas[0].category.display),
                category=metas[0].category,
                total=len(metas),
                level1=sum(1 for m in metas if m.aasb_level == 1),
                level2=sum(1 for m in metas if m.aasb_level == 2),
                check_ids=[m.check_id for m in metas],
            )
        )
    return out


def benchmark_coverage(findings: list[Finding]) -> list[dict[str, Any]]:
    """Per-section pass/fail coverage, for the HTML and Markdown reports."""
    by_section: dict[int, list[Finding]] = {}
    for finding in findings:
        by_section.setdefault(finding.meta.category.section, []).append(finding)

    rows: list[dict[str, Any]] = []
    for section in sections():
        items = by_section.get(section.number, [])
        counts = dict.fromkeys(Status, 0)
        for finding in items:
            counts[finding.status] += 1
        evaluated = len(items) - counts[Status.NOT_APPLICABLE] - counts[Status.ERROR]
        rows.append(
            {
                "section": section.number,
                "title": section.title,
                "checks": section.total,
                "evaluated": evaluated,
                "passed": counts[Status.PASS],
                "failed": counts[Status.FAIL],
                "warned": counts[Status.WARN],
                "manual": counts[Status.MANUAL],
                "not_applicable": counts[Status.NOT_APPLICABLE],
                "errors": counts[Status.ERROR],
                "pass_rate": round(100 * counts[Status.PASS] / evaluated, 1) if evaluated else None,
            }
        )
    return rows


BENCHMARK: dict[str, Any] = {
    "name": NAME,
    "short_name": SHORT_NAME,
    "version": VERSION,
    "full_name": FULL_NAME,
    "description": DESCRIPTION,
    "disclaimer": DISCLAIMER,
    "levels": LEVELS,
    "sections": SECTION_TITLES,
}
