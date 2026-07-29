"""JSON reporter — the stable, versioned schema (spec 7.1)."""

from __future__ import annotations

import json

from ..core.engine import ScanReport


def render(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False, default=str)
