"""argus.yaml loading and precedence resolution.

Precedence is fixed by spec 9: CLI flag > argus.yaml > built-in default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core.exceptions import ArgusConfigError
from .core.models import Category, Severity, Target
from .core.safe_io import read_yaml

DEFAULT_CONFIG_NAMES = ("argus.yaml", "argus.yml", ".argus.yaml")


@dataclass
class ReportConfig:
    formats: list[str] = field(default_factory=lambda: ["terminal"])
    output: str | None = None


@dataclass
class ArgusConfig:
    include: list[Target] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    path: str | None = None
    severity_threshold: Severity = Severity.HIGH
    categories: list[Category] = field(default_factory=list)
    level: int | None = None
    weights: dict[Severity, float] = field(default_factory=dict)
    score_accepted_risk: bool = False
    report: ReportConfig = field(default_factory=ReportConfig)
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    source: Path | None = None


def find_config(project_root: Path, explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        if not explicit.is_file():
            raise ArgusConfigError(f"config file not found: {explicit}")
        return explicit
    for name in DEFAULT_CONFIG_NAMES:
        candidate = project_root / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None) -> ArgusConfig:
    """Parse argus.yaml. Malformed configuration is a usage error (exit 3)."""
    if path is None:
        return ArgusConfig()

    data = read_yaml(path)
    if data is None:
        raise ArgusConfigError(f"{path} is not valid YAML")
    if not isinstance(data, dict):
        raise ArgusConfigError(f"{path} must contain a YAML mapping at the top level")

    config = ArgusConfig(source=path)

    scan = data.get("scan") or {}
    if not isinstance(scan, dict):
        raise ArgusConfigError(f"{path}: 'scan' must be a mapping")

    for value in scan.get("include") or []:
        try:
            config.include.append(Target.parse(str(value)))
        except ValueError as exc:
            raise ArgusConfigError(f"{path}: {exc}") from exc

    config.exclude = [str(v).upper() for v in (scan.get("exclude") or [])]
    if scan.get("path"):
        config.path = str(scan["path"])

    for value in scan.get("categories") or []:
        try:
            config.categories.append(Category.parse(str(value)))
        except ValueError as exc:
            raise ArgusConfigError(f"{path}: {exc}") from exc

    if scan.get("level") is not None:
        level = scan["level"]
        if level not in (1, 2, "1", "2"):
            raise ArgusConfigError(f"{path}: 'scan.level' must be 1 or 2")
        config.level = int(level)

    if data.get("severity_threshold"):
        try:
            config.severity_threshold = Severity.parse(str(data["severity_threshold"]))
        except ValueError as exc:
            raise ArgusConfigError(f"{path}: {exc}") from exc

    scoring = data.get("scoring") or {}
    if isinstance(scoring, dict):
        weights = scoring.get("weights") or {}
        if isinstance(weights, dict):
            for key, value in weights.items():
                try:
                    config.weights[Severity.parse(str(key))] = float(value)
                except (ValueError, TypeError) as exc:
                    raise ArgusConfigError(f"{path}: invalid scoring weight {key}={value}") from exc
        config.score_accepted_risk = bool(scoring.get("score_accepted_risk", False))

    report = data.get("report") or {}
    if isinstance(report, dict):
        formats = report.get("formats")
        if isinstance(formats, list) and formats:
            config.report.formats = [str(f).lower() for f in formats]
        elif isinstance(formats, str):
            config.report.formats = [formats.lower()]
        if report.get("output"):
            config.report.output = str(report["output"])

    exceptions = data.get("exceptions") or []
    if not isinstance(exceptions, list):
        raise ArgusConfigError(f"{path}: 'exceptions' must be a list")
    for entry in exceptions:
        if not isinstance(entry, dict) or not entry.get("check_id"):
            raise ArgusConfigError(f"{path}: each exception needs a 'check_id'")
        config.exceptions.append(entry)

    return config
