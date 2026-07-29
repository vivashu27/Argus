"""Filesystem and environment collection.

Produces the assets consumed by the FS-* and SECRET-* check families: agent
configuration files with their permission bits, credential locations that actually
exist, and agent-relevant environment variables.

Credential *contents* are never read — only metadata. The one exception is agent
configuration, which must be parsed to be audited.
"""

from __future__ import annotations

from pathlib import Path

from ..analysis.paths import (
    SENSITIVE_CONFIG_FILES,
    enumerate_sensitive_paths,
    find_private_keys,
)
from ..core.models import Asset, Target
from ..core.safe_io import escapes_root, file_mode, is_readable
from . import platform as plat
from .base import DiscoveryContext


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []
    home = context.home

    # --- agent configuration files, with permission metadata ------------------
    config_paths: list[Path] = [
        *plat.claude_settings_files(home),
        plat.claude_json(home),
        plat.claude_user_dir(home) / ".credentials.json",
        plat.claude_desktop_config(home),
        plat.project_mcp_file(context.project_root),
        *plat.project_settings_files(context.project_root),
    ]
    for path in config_paths:
        if not path.is_file():
            continue
        assets.append(
            Asset(
                asset_id=f"fs:config:{path.name}",
                target=Target.FILESYSTEM,
                path=path,
                data={
                    "kind": "agent-config",
                    "mode": file_mode(path),
                    "readable": is_readable(path),
                    "is_symlink": path.is_symlink(),
                    "sensitive": any(str(path).endswith(s) for s in SENSITIVE_CONFIG_FILES),
                },
                source=str(path),
            )
        )

    # --- credential locations that exist for this user ------------------------
    for sensitive in enumerate_sensitive_paths(home):
        keys = (
            [str(p) for p in find_private_keys(sensitive.path)]
            if sensitive.kind == "ssh"
            else []
        )
        assets.append(
            Asset(
                asset_id=f"fs:sensitive:{sensitive.path.name}",
                target=Target.FILESYSTEM,
                path=sensitive.path,
                data={
                    "kind": "credential-location",
                    "category": sensitive.kind,
                    "description": sensitive.description,
                    "readable": sensitive.readable,
                    "mode": file_mode(sensitive.path),
                    "private_keys": keys,
                },
                source=str(sensitive.path),
            )
        )

    # --- symlinks inside the project that escape the workspace ----------------
    escaping: list[dict[str, str]] = []
    root = context.project_root
    if root.is_dir():
        for candidate in _iter_symlinks(root):
            if escapes_root(candidate, root):
                try:
                    destination = str(candidate.resolve())
                except OSError:
                    destination = "(unresolvable)"
                escaping.append({"link": str(candidate), "target": destination})
    if escaping:
        assets.append(
            Asset(
                asset_id="fs:symlinks",
                target=Target.FILESYSTEM,
                path=root,
                data={"kind": "symlinks", "escaping": escaping},
                source=str(root),
            )
        )

    # --- agent-relevant environment variables ---------------------------------
    env = plat.relevant_env_vars()
    if env:
        assets.append(
            Asset(
                asset_id="fs:environment",
                target=Target.FILESYSTEM,
                path=None,
                data={"kind": "environment", "variables": env},
                source="process environment",
            )
        )

    return assets


def _iter_symlinks(root: Path, max_depth: int = 4, max_entries: int = 3000) -> list[Path]:
    """Collect symlinks without ever traversing one."""
    from ..core.safe_io import SKIP_DIRS

    found: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack and len(found) < max_entries:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            if entry.is_symlink():
                found.append(entry)
                continue  # never descend through a link
            try:
                if entry.is_dir() and entry.name not in SKIP_DIRS:
                    stack.append((entry, depth + 1))
            except OSError:
                continue
    return found
