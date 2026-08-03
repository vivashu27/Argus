"""Claude Code discovery: settings files and global state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.exceptions import ArgusError
from ..core.models import Asset, Target
from ..core.safe_io import is_readable, read_json, read_text
from . import platform as plat
from .base import DiscoveryContext


def _load_settings(path: Path, scope: str, context: DiscoveryContext) -> Asset | None:
    if not path.is_file():
        return None
    if not is_readable(path):
        context.record_unreadable(path, "permission denied")
        return None
    data = read_json(path)
    if data is None:
        # Malformed JSON is itself a finding surface; keep the asset with raw text.
        try:
            raw = read_text(path)
        except OSError:
            raw = ""
        return Asset(
            asset_id=f"claude-code:{scope}-settings",
            target=Target.CLAUDE_CODE,
            path=path,
            data={"settings": {}, "scope": scope, "malformed": True},
            text=raw,
            text_is_verbatim=True,
            source=str(path),
        )
    if not isinstance(data, dict):
        data = {}
    try:
        raw = read_text(path)
    except OSError:
        raw = ""
    return Asset(
        asset_id=f"claude-code:{scope}-settings",
        target=Target.CLAUDE_CODE,
        path=path,
        data={"settings": data, "scope": scope, "malformed": False},
        text=raw,
        text_is_verbatim=True,
        source=str(path),
    )


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []
    home = context.home

    user_dir = plat.claude_user_dir(home)
    if user_dir.is_dir():
        context.record_root(user_dir)

    user_paths = plat.claude_settings_files(home) if context.user_scope else []
    for path in user_paths:
        scope = "user-local" if path.name.endswith("local.json") else "user"
        asset = _load_settings(path, scope, context)
        if asset:
            assets.append(asset)

    for path in plat.project_settings_files(context.project_root):
        scope = "project-local" if path.name.endswith("local.json") else "project"
        asset = _load_settings(path, scope, context)
        if asset:
            assets.append(asset)

    # ~/.claude.json holds per-project trust state and inline MCP definitions.
    global_state = plat.claude_json(home)
    if context.user_scope and global_state.is_file():
        if not is_readable(global_state):
            context.record_unreadable(global_state, "permission denied")
        else:
            data = read_json(global_state)
            if isinstance(data, dict):
                projects: dict[str, Any] = data.get("projects") or {}
                assets.append(
                    Asset(
                        asset_id="claude-code:global-state",
                        target=Target.CLAUDE_CODE,
                        path=global_state,
                        data={
                            "projects": projects if isinstance(projects, dict) else {},
                            "install_method": data.get("installMethod"),
                            "auto_updates": data.get("autoUpdates"),
                        },
                        source=str(global_state),
                    )
                )

    # Agent definitions are Claude Code assets that carry tool grants.
    for agents_dir in plat.agents_dirs(context.project_root, home):
        if not agents_dir.is_dir():
            continue
        context.record_root(agents_dir)
        for path in sorted(agents_dir.glob("*.md")):
            if path.is_symlink() or not path.is_file():
                continue
            if not is_readable(path):
                context.record_unreadable(path, "permission denied")
                continue
            try:
                text = read_text(path)
            except (OSError, ValueError, ArgusError) as exc:
                context.record_unreadable(path, str(exc))
                continue
            assets.append(
                Asset(
                    asset_id=f"agent:{path.stem}",
                    target=Target.CLAUDE_CODE,
                    path=path,
                    data={"kind": "agent"},
                    text=text,
                    text_is_verbatim=True,
                    source=str(path),
                )
            )

    return assets
