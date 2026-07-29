"""Asset discovery.

Discovery is strictly read-only and never assumes portable paths: every location is
resolved through :mod:`argus.discovery.platform` for the detected operating system.
"""

from __future__ import annotations

from pathlib import Path

from ..core.models import Asset, Target
from . import (
    claude_code,
    claude_desktop,
    filesystem,
    hooks,
    ide,
    instructions,
    mcp,
    plugins,
    skills,
)
from .base import DiscoveryContext

_DISCOVERERS = {
    Target.CLAUDE_CODE: claude_code.discover,
    Target.CLAUDE_DESKTOP: claude_desktop.discover,
    Target.MCP: mcp.discover,
    Target.SKILLS: skills.discover,
    Target.PLUGINS: plugins.discover,
    Target.HOOKS: hooks.discover,
    Target.INSTRUCTIONS: instructions.discover,
    Target.IDE: ide.discover,
    Target.FILESYSTEM: filesystem.discover,
}


def discover_all(
    project_root: Path,
    targets: set[Target] | None = None,
    *,
    home: Path | None = None,
    user_scope: bool = True,
) -> tuple[list[Asset], DiscoveryContext]:
    """Run every requested discoverer and return the combined asset inventory."""
    context = DiscoveryContext(
        project_root=project_root, home=home or Path.home(), user_scope=user_scope
    )
    assets: list[Asset] = []
    for target, discoverer in _DISCOVERERS.items():
        if targets is not None and target not in targets:
            continue
        try:
            assets.extend(discoverer(context))
        except Exception as exc:  # a hostile config must not abort discovery
            context.record_error(f"{target.value} discovery failed: {exc}")
    context.assets = assets
    return assets, context


__all__ = ["DiscoveryContext", "discover_all"]
