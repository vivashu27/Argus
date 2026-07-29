"""Report generation.

Module names are suffixed (``json_reporter``) rather than bare (``json``) to avoid
shadowing stdlib modules (spec 4).
"""

from __future__ import annotations

from collections.abc import Callable

from ..core.engine import ScanReport
from . import (
    csv_reporter,
    html,
    json_reporter,
    markdown,
    sarif,
    terminal,
    yaml_reporter,
)

#: format name -> (renderer, file extension)
RENDERERS: dict[str, tuple[Callable[[ScanReport], str], str]] = {
    "json": (json_reporter.render, "json"),
    "yaml": (yaml_reporter.render, "yaml"),
    "csv": (csv_reporter.render, "csv"),
    "markdown": (markdown.render, "md"),
    "html": (html.render, "html"),
    "sarif": (sarif.render, "sarif"),
}

FORMATS = ("terminal", *RENDERERS.keys())


def render(fmt: str, report: ScanReport) -> str:
    """Render a report to a string. ``terminal`` is handled by the CLI directly."""
    if fmt not in RENDERERS:
        raise KeyError(fmt)
    return RENDERERS[fmt][0](report)


def extension(fmt: str) -> str:
    return RENDERERS[fmt][1]


__all__ = ["FORMATS", "RENDERERS", "render", "extension", "terminal"]
