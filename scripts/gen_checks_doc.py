"""Generate docs/checks.md from the live check registry.

Keeping the reference generated means it can never drift from the implemented
checks. Run from the repository root:

    python scripts/gen_checks_doc.py > docs/checks.md
"""

from __future__ import annotations

import argus.checks  # noqa: F401  — importing registers every check
from argus.benchmarks import aasb_v1
from argus.core.registry import all_checks


def main() -> None:
    checks = all_checks()
    sections = aasb_v1.sections()

    print("# AASB v1.0 — Check Reference\n")
    print("> **Generated file.** Produced from the check registry by")
    print("> `python scripts/gen_checks_doc.py > docs/checks.md`. Do not edit by hand.\n")
    print(f"{len(checks)} checks across {len(sections)} sections.\n")

    print("## Index\n")
    print("| ID | AASB | Level | Severity | Category | Title |")
    print("| --- | --- | :-: | --- | --- | --- |")
    for check in checks:
        meta = check.meta
        print(
            f"| `{meta.check_id}` | {meta.aasb} | {meta.aasb_level} | "
            f"{meta.severity.value} | {meta.category.display} | {meta.title} |"
        )

    print("\n## Levels\n")
    for _number, info in aasb_v1.LEVELS.items():
        print(f"**{info['name']}** — {info['description']}\n")

    for section in sections:
        print(f"\n---\n\n## {section.number}. {section.title}\n")
        print(
            f"{section.total} checks — {section.level1} at Level 1, "
            f"{section.level2} at Level 2.\n"
        )
        for check in checks:
            meta = check.meta
            if meta.category is not section.category:
                continue
            print(f"### {meta.check_id} — {meta.title}\n")
            print(
                f"**AASB {meta.aasb}** · Level {meta.aasb_level} · "
                f"**{meta.severity.value}** · applies to: "
                f"{', '.join(sorted(t.value for t in meta.applies_to))}\n"
            )
            print(f"{meta.description}\n")
            if meta.rationale:
                print(f"**Detection rationale.** {meta.rationale}\n")
            if meta.security_impact:
                print(f"**Security impact.** {meta.security_impact}\n")
            if meta.remediation:
                print(f"**Remediation.** {meta.remediation}\n")
            if meta.compliance:
                rows = "; ".join(
                    f"{framework}: {', '.join(refs)}"
                    for framework, refs in meta.compliance_dict().items()
                )
                print(f"**Compliance mapping.** {rows}\n")
            if meta.references:
                print("**References.** " + ", ".join(meta.references) + "\n")

    print(f"\n---\n\n*{aasb_v1.DISCLAIMER}*")


if __name__ == "__main__":
    main()
