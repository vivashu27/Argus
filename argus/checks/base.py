"""The security check interface.

Every check subclasses :class:`Check`, declares a :class:`~argus.core.models.CheckMeta`,
and implements :meth:`Check.run`. Checks receive already-collected assets — they never
touch the filesystem for discovery, so the engine controls every read.

A check must never raise to signal a problem: it returns an ``ERROR`` finding, or a
``MANUAL`` finding when the answer cannot be determined statically (spec 5).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.models import (
    Asset,
    CheckMeta,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Status,
    Target,
)
from ..core.safe_io import locate_key


@dataclass
class CheckContext:
    """Everything a check is allowed to see."""

    assets: list[Asset]
    project_root: Path
    home: Path
    options: dict[str, Any] = field(default_factory=dict)

    def by_target(self, target: Target) -> list[Asset]:
        return [a for a in self.assets if a.target is target]

    def by_id_prefix(self, prefix: str) -> list[Asset]:
        return [a for a in self.assets if a.asset_id.startswith(prefix)]

    def first(self, target: Target) -> Asset | None:
        assets = self.by_target(target)
        return assets[0] if assets else None


class Check(ABC):
    """Base class for all AASB checks."""

    meta: CheckMeta

    @abstractmethod
    def run(self, context: CheckContext) -> list[Finding]:
        """Evaluate the check and return zero or more normalized findings."""

    # -- finding constructors -------------------------------------------------

    def _finding(
        self,
        status: Status,
        *,
        asset: str = "",
        detail: str = "",
        evidence: list[Evidence] | None = None,
        confidence: Confidence = Confidence.HIGH,
        severity: Severity | None = None,
        na_reason: str = "",
    ) -> Finding:
        return Finding(
            meta=self.meta,
            status=status,
            confidence=confidence,
            asset=asset,
            evidence=evidence or [],
            detail=detail,
            severity_override=severity,
            na_reason=na_reason,
        )

    def fail(
        self,
        asset: str,
        detail: str,
        evidence: list[Evidence] | None = None,
        confidence: Confidence = Confidence.HIGH,
        severity: Severity | None = None,
    ) -> Finding:
        """A failed control.

        Per spec 5, a LOW-confidence detection is reported as WARN rather than FAIL:
        Argus should not assert a failure it cannot substantiate.
        """
        status = Status.WARN if confidence is Confidence.LOW else Status.FAIL
        return self._finding(
            status,
            asset=asset,
            detail=detail,
            evidence=evidence,
            confidence=confidence,
            severity=severity,
        )

    def warn(
        self,
        asset: str,
        detail: str,
        evidence: list[Evidence] | None = None,
        confidence: Confidence = Confidence.MEDIUM,
        severity: Severity | None = None,
    ) -> Finding:
        return self._finding(
            Status.WARN,
            asset=asset,
            detail=detail,
            evidence=evidence,
            confidence=confidence,
            severity=severity,
        )

    def ok(self, asset: str, detail: str = "") -> Finding:
        return self._finding(Status.PASS, asset=asset, detail=detail)

    def manual(
        self,
        asset: str,
        detail: str,
        evidence: list[Evidence] | None = None,
        confidence: Confidence = Confidence.MEDIUM,
    ) -> Finding:
        """Requires human adjudication — never guess PASS or FAIL (spec 5)."""
        return self._finding(
            Status.MANUAL, asset=asset, detail=detail, evidence=evidence, confidence=confidence
        )

    def not_applicable(self, asset: str, reason: str) -> Finding:
        return self._finding(Status.NOT_APPLICABLE, asset=asset, detail=reason, na_reason=reason)

    def error(self, asset: str, detail: str) -> Finding:
        return self._finding(Status.ERROR, asset=asset, detail=detail, confidence=Confidence.LOW)

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def evidence(
        path: Any = None,
        line: int | None = None,
        key: str | None = None,
        snippet: str | None = None,
        reason: str = "",
        asset: Any = None,
    ) -> Evidence:
        """Build an evidence item. ``snippet`` must already be redacted.

        Passing ``asset`` lets a finding about a configuration key resolve to the
        line that key sits on, so "permissions.allow is too broad" opens on the rule
        rather than the top of the file. Only where the scanned text is the file byte
        for byte: a synthesised MCP config would give an offset into a reconstruction,
        which points at nothing the reader can open.
        """
        if line is None and key and asset is not None and getattr(asset, "text_is_verbatim", False):
            line = locate_key(getattr(asset, "text", None) or "", key)
        return Evidence(
            path=str(path) if path is not None else None,
            line=line if line else None,
            key=key,
            snippet=snippet,
            reason=reason,
        )

    def no_assets(self, kind: str) -> list[Finding]:
        """Uniform result when nothing of the relevant kind was discovered."""
        return [self.not_applicable("-", f"No {kind} discovered in this environment")]
