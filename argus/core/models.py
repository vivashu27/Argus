"""Normalized data model for Argus.

The finding schema defined here is the single source of truth (spec 5). Reporters
render presentation labels from these fields; they never introduce new data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Higher is more severe. Used by 'this level and above' filters."""
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Status(str, Enum):
    PASS = "PASS"  # noqa: S105 — a check outcome, not a credential
    FAIL = "FAIL"
    WARN = "WARN"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(str, Enum):
    """Check family. The slug is canonical in all machine-readable output (spec 3.3)."""

    CLAUDE = "claude"
    MCP = "mcp"
    SKILLS = "skills"
    PLUGINS = "plugins"
    HOOKS = "hooks"
    INSTRUCTIONS = "instructions"
    SECRETS = "secrets"
    FILESYSTEM = "filesystem"
    CUSTOM = "custom"

    @property
    def section(self) -> int:
        """AASB benchmark section number (spec 3.1)."""
        return _CATEGORY_SECTION[self]

    @property
    def display(self) -> str:
        return _CATEGORY_DISPLAY[self]

    @classmethod
    def parse(cls, value: str) -> Category:
        """Accept either the slug ('mcp') or the display name ('MCP Security')."""
        needle = value.strip().lower()
        for member in cls:
            if needle in (member.value, member.display.lower()):
                return member
        raise ValueError(f"unknown category: {value!r}")


_CATEGORY_SECTION: dict[Category, int] = {
    Category.CLAUDE: 1,
    Category.MCP: 2,
    Category.SKILLS: 3,
    Category.PLUGINS: 4,
    Category.HOOKS: 5,
    Category.INSTRUCTIONS: 6,
    Category.SECRETS: 7,
    Category.FILESYSTEM: 8,
    Category.CUSTOM: 9,
}

_CATEGORY_DISPLAY: dict[Category, str] = {
    Category.CLAUDE: "Claude Configuration",
    Category.MCP: "MCP Security",
    Category.SKILLS: "Skills",
    Category.PLUGINS: "Plugins",
    Category.HOOKS: "Hooks",
    Category.INSTRUCTIONS: "Instruction Files",
    Category.SECRETS: "Secrets",
    Category.FILESYSTEM: "Filesystem",
    Category.CUSTOM: "Custom Rules",
}


class Target(str, Enum):
    """Asset domain — what was discovered. Independent of Category (spec 3.2)."""

    CLAUDE_CODE = "claude-code"
    CLAUDE_DESKTOP = "claude-desktop"
    MCP = "mcp"
    SKILLS = "skills"
    PLUGINS = "plugins"
    HOOKS = "hooks"
    INSTRUCTIONS = "instructions"
    IDE = "ide"
    FILESYSTEM = "filesystem"

    @classmethod
    def parse(cls, value: str) -> Target:
        needle = value.strip().lower()
        for member in cls:
            if needle == member.value:
                return member
        raise ValueError(f"unknown target: {value!r}")


class ThreatCategory(str, Enum):
    """Classification for statically detected dangerous commands (spec 6.2)."""

    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    REMOTE_CODE_EXECUTION = "REMOTE_CODE_EXECUTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PERSISTENCE = "PERSISTENCE"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    DESTRUCTIVE_OPERATION = "DESTRUCTIVE_OPERATION"


@dataclass(frozen=True)
class Evidence:
    """A single supporting observation.

    ``snippet`` must already be redacted by the producer. Nothing downstream of this
    dataclass re-redacts, so a raw secret placed here would reach the report.
    """

    path: str | None = None
    line: int | None = None
    key: str | None = None
    snippet: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "key": self.key,
            "snippet": self.snippet,
            "reason": self.reason,
        }


@dataclass
class Asset:
    """A discovered artifact to be audited."""

    asset_id: str
    target: Target
    path: Path | None = None
    data: dict[str, Any] = field(default_factory=dict)
    text: str | None = None
    source: str = ""
    is_fixture: bool = False

    @property
    def label(self) -> str:
        return self.asset_id if self.path is None else f"{self.asset_id} ({self.path})"


@dataclass(frozen=True)
class CheckMeta:
    """Static description of a check. Registered once, reused for every finding."""

    check_id: str
    title: str
    description: str
    category: Category
    severity: Severity
    aasb_level: int
    applies_to: frozenset[Target]
    rationale: str = ""
    security_impact: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    compliance: tuple[tuple[str, str], ...] = ()

    @property
    def aasb(self) -> str:
        """CIS-style derived benchmark number, e.g. 'CLAUDE-001' -> '1.1' (spec 3.1).

        Custom rules carry slug identifiers rather than numbers and are not part of
        the benchmark, so they report their category instead of a fabricated number.
        """
        numeric = self.check_id.rsplit("-", 1)[-1]
        if not numeric.isdigit():
            return self.category.value
        return f"{self.category.section}.{int(numeric)}"

    def compliance_dict(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for framework, ref in self.compliance:
            out.setdefault(framework, []).append(ref)
        return out


@dataclass
class Finding:
    """A normalized result. One per (check, asset) outcome."""

    meta: CheckMeta
    status: Status
    confidence: Confidence = Confidence.HIGH
    asset: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    detail: str = ""
    severity_override: Severity | None = None
    accepted_risk: bool = False
    acceptance_reason: str = ""
    na_reason: str = ""

    @property
    def check_id(self) -> str:
        return self.meta.check_id

    @property
    def severity(self) -> Severity:
        """INFO for non-issues: a PASS must never carry the check's nominal severity."""
        if self.status in (Status.PASS, Status.NOT_APPLICABLE):
            return Severity.INFO
        return self.severity_override or self.meta.severity

    @property
    def is_open(self) -> bool:
        """True when this finding gates the exit code (spec 3.5): FAIL, not accepted."""
        return self.status is Status.FAIL and not self.accepted_risk

    @property
    def display_status(self) -> str:
        if self.accepted_risk and self.status is Status.FAIL:
            return "FAIL — ACCEPTED RISK"
        return self.status.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "aasb": self.meta.aasb,
            "title": self.meta.title,
            "description": self.meta.description,
            "category": self.meta.category.value,
            "category_display": self.meta.category.display,
            "severity": self.severity.value,
            "status": self.status.value,
            "display_status": self.display_status,
            "confidence": self.confidence.value,
            "aasb_level": self.meta.aasb_level,
            "asset": self.asset,
            "detail": self.detail,
            "rationale": self.meta.rationale,
            "security_impact": self.meta.security_impact,
            "remediation": self.meta.remediation,
            "references": list(self.meta.references),
            "compliance_mappings": self.meta.compliance_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "accepted_risk": self.accepted_risk,
            "acceptance_reason": self.acceptance_reason,
            "not_applicable_reason": self.na_reason,
        }


@dataclass
class ScanMetadata:
    timestamp: str
    hostname: str
    platform: str
    scanner_version: str
    benchmark: str
    scan_roots: list[str] = field(default_factory=list)
    expired_exceptions: list[str] = field(default_factory=list)
    unreadable_paths: list[str] = field(default_factory=list)
    #: Discovery-stage failures. A discoverer that aborts silently would let a report
    #: claim full coverage over assets it never examined, so these are always surfaced.
    discovery_errors: list[str] = field(default_factory=list)
    used_fixtures: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "platform": self.platform,
            "scanner_version": self.scanner_version,
            "benchmark": self.benchmark,
            "scan_roots": self.scan_roots,
            "expired_exceptions": self.expired_exceptions,
            "unreadable_paths": self.unreadable_paths,
            "discovery_errors": self.discovery_errors,
            "used_fixtures": self.used_fixtures,
        }


@dataclass
class ScanResult:
    metadata: ScanMetadata
    findings: list[Finding] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)

    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_open]
