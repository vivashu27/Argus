"""YAML reporter. Mirrors the JSON schema exactly."""

from __future__ import annotations

import yaml

from ..core.engine import ScanReport


def render(report: ScanReport) -> str:
    return yaml.safe_dump(report.to_dict(), sort_keys=False, default_flow_style=False, width=100)
