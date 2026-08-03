"""The scan pipeline.

    Discovery → Asset Enumeration → Configuration Collection → Static Analysis
      → Security Checks → Finding Normalization → Risk Classification
      → Security Score → Report Generation

A failing check never aborts the scan: it produces an ``ERROR`` finding so coverage
stays honest. A hostile configuration is expected, so every stage is defensive.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __benchmark__, __version__
from ..checks import base as check_base  # noqa: F401  (ensures package import)
from ..discovery import discover_all
from ..discovery.platform import hostname, platform_string
from .models import (
    Asset,
    Category,
    Finding,
    ScanMetadata,
    ScanResult,
    Severity,
    Status,
    Target,
)
from .registry import select
from .scoring import Summary, score_findings


@dataclass
class Exception_:
    """An accepted-risk entry from argus.yaml."""

    check_id: str
    asset: str | None = None
    reason: str = ""
    expires: str | None = None

    def is_expired(self, today: _dt.date | None = None) -> bool:
        if not self.expires:
            return False
        try:
            expiry = _dt.date.fromisoformat(str(self.expires))
        except ValueError:
            # An unparseable date is treated as expired: failing closed is the safe
            # reading for a control that suppresses gating.
            return True
        return expiry < (today or _dt.date.today())

    def matches(self, finding: Finding) -> bool:
        if finding.check_id.upper() != self.check_id.strip().upper():
            return False
        if not self.asset:
            return True
        return self.asset.strip() in (finding.asset, finding.asset.split(" ")[0])


@dataclass
class ScanOptions:
    """Everything the engine needs to run one scan."""

    project_root: Path = field(default_factory=Path.cwd)
    home: Path | None = None
    targets: set[Target] | None = None
    categories: set[Category] | None = None
    include_ids: list[str] | None = None
    exclude_ids: list[str] | None = None
    level: int | None = None
    exceptions: list[Exception_] = field(default_factory=list)
    weights: dict[Severity, float] | None = None
    score_accepted_risk: bool = False
    user_scope: bool = True
    rule_paths: list[Path] = field(default_factory=list)
    verbose: bool = False


@dataclass
class ScanReport:
    result: ScanResult
    summary: Summary

    def to_dict(self) -> dict[str, Any]:
        """The stable, versioned JSON representation (spec 7.1)."""
        return {
            "schema_version": "1.0",
            "scan_metadata": self.result.metadata.to_dict(),
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.result.findings],
        }


def run_scan(options: ScanOptions) -> ScanReport:
    """Execute the full pipeline and return a scored report."""
    home = options.home or Path.home()

    # 1-3. Discovery, enumeration, collection
    assets, discovery_context = discover_all(
        options.project_root, options.targets, home=home, user_scope=options.user_scope
    )

    # A requested target that yielded nothing is almost always a layout mistake —
    # the wrong --path, or Skills that are not one directory below it. Saying so
    # beats silently reporting on assets found somewhere else entirely.
    for target in options.targets or ():
        if not any(a.target is target for a in assets):
            discovery_context.record_error(
                f"no '{target.value}' assets were found under {options.project_root}"
                + ("" if options.user_scope else " (user scope disabled)")
            )

    # Same failure, without --target: an isolated scan that found nothing at all is
    # a mistake worth naming, not a clean bill of health.
    if not options.user_scope and not assets:
        discovery_context.record_error(
            f"no agent assets were found under {options.project_root} with user scope "
            "disabled. Check --path: Skills are discovered as <path>/<name>/SKILL.md, "
            "so point at the directory that contains skill folders, not at one of them."
        )

    # 4-5. Static analysis and security checks
    checks = select(
        targets=options.targets,
        categories=options.categories,
        include_ids=options.include_ids,
        exclude_ids=options.exclude_ids,
        level=options.level,
    )
    context = check_base.CheckContext(
        assets=assets,
        project_root=options.project_root,
        home=home,
        options={"verbose": options.verbose},
    )

    findings: list[Finding] = []
    for check_cls in checks:
        instance = check_cls()
        try:
            produced = instance.run(context)
        except Exception as exc:  # a hostile asset must not kill the scan
            produced = [
                Finding(
                    meta=check_cls.meta,
                    status=Status.ERROR,
                    asset="-",
                    detail=f"Check raised {type(exc).__name__}: {exc}",
                )
            ]
        findings.extend(produced or [])

    # Custom .argus rules run after the built-in checks. They are deterministic,
    # so their findings are real: they score and gate like any other check.
    if options.rule_paths:
        from ..rules import load_rules, run_rules

        rules, rule_errors = load_rules(options.rule_paths)
        for message in rule_errors:
            discovery_context.record_error(f"rule: {message}")

        # Rules are checks, so the same selection flags apply to them. Without this
        # a --category or --exclude filter silently ran every rule anyway.
        include = {i.strip().upper() for i in options.include_ids} if options.include_ids else None
        exclude = {e.strip().upper() for e in options.exclude_ids} if options.exclude_ids else set()
        selected_rules = [
            r
            for r in rules
            if (options.categories is None or r.category in options.categories)
            and (options.targets is None or r.target in options.targets)
            and (include is None or r.check_id in include)
            and r.check_id not in exclude
        ]
        findings.extend(run_rules(selected_rules, assets))

    # 6-7. Normalization and risk classification
    expired = _apply_exceptions(findings, options.exceptions)

    # 8. Scoring
    summary = score_findings(
        findings,
        weights=options.weights,
        score_accepted_risk=options.score_accepted_risk,
    )

    metadata = ScanMetadata(
        timestamp=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        hostname=hostname(),
        platform=platform_string(),
        scanner_version=__version__,
        benchmark=__benchmark__,
        scan_roots=discovery_context.scan_roots,
        expired_exceptions=expired,
        unreadable_paths=discovery_context.unreadable,
        discovery_errors=discovery_context.errors,
        used_fixtures=any(a.is_fixture for a in assets),
    )
    result = ScanResult(metadata=metadata, findings=findings, assets=assets)
    return ScanReport(result=result, summary=summary)


def _apply_exceptions(findings: list[Finding], exceptions: list[Exception_]) -> list[str]:
    """Mark accepted risks and report expired exceptions (spec 3.6).

    An expired exception is not honoured — the finding reverts to a normal FAIL and
    the expiry is surfaced in scan metadata.
    """
    expired: list[str] = []
    for exception in exceptions:
        matched = [f for f in findings if exception.matches(f)]
        if exception.is_expired():
            if matched:
                expired.append(
                    f"{exception.check_id}"
                    + (f" (asset {exception.asset})" if exception.asset else "")
                    + f" expired {exception.expires} — finding is enforced"
                )
            continue
        for finding in matched:
            if finding.status is Status.FAIL:
                finding.accepted_risk = True
                finding.acceptance_reason = exception.reason
    return expired


def collect_assets(project_root: Path, home: Path | None = None) -> list[Asset]:
    """Discovery-only helper, used by ``argus list-assets`` and by tests."""
    assets, _context = discover_all(project_root, None, home=home)
    return assets
