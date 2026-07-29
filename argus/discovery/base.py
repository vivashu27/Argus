"""Shared discovery context."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.models import Asset


@dataclass
class DiscoveryContext:
    """State shared across discoverers and passed on to checks."""

    project_root: Path
    home: Path
    #: When False, user-level locations (~/.claude, Claude Desktop) are skipped so a
    #: scan covers only the directory given by --path. Without this, "audit this
    #: folder of skills" silently also reports the operator's own installed skills.
    user_scope: bool = True
    assets: list[Asset] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_roots: list[str] = field(default_factory=list)

    def record_unreadable(self, path: Path, reason: str = "") -> None:
        """Discovered-but-unreadable paths are reported, never silently skipped."""
        entry = str(path) + (f" ({reason})" if reason else "")
        if entry not in self.unreadable:
            self.unreadable.append(entry)

    def record_error(self, message: str) -> None:
        if message not in self.errors:
            self.errors.append(message)

    def record_root(self, path: Path) -> None:
        entry = str(path)
        if entry not in self.scan_roots:
            self.scan_roots.append(entry)
