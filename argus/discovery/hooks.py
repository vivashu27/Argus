"""Hook discovery.

Hooks are declared in settings files under a ``hooks`` key, and plugins may ship
``hooks/hooks.json`` plus hook scripts. Each declared hook command becomes one
asset. Hook scripts are read as text; Argus never runs a hook.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.exceptions import ArgusError
from ..core.models import Asset, Target
from ..core.safe_io import is_readable, read_json, read_text
from . import platform as plat
from .base import DiscoveryContext

HOOK_EVENTS = (
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "Notification",
    "Stop",
    "SubagentStop",
    "PreCompact",
    "SessionStart",
    "SessionEnd",
)


def _script_text(command: str, base_dirs: list[Path]) -> tuple[str, str | None]:
    """Best-effort resolution of a hook command to a script on disk.

    Only the first whitespace-delimited token that looks like a path is considered,
    and the file is read as text — never executed.
    """
    if not command:
        return "", None
    for token in command.split():
        cleaned = token.strip("\"'")
        if not any(cleaned.endswith(s) for s in (".py", ".sh", ".js", ".ts", ".rb", ".ps1")):
            continue
        candidates = [Path(cleaned)] if Path(cleaned).is_absolute() else []
        candidates += [base / cleaned for base in base_dirs]
        for candidate in candidates:
            try:
                if candidate.is_file() and not candidate.is_symlink() and is_readable(candidate):
                    return read_text(candidate), str(candidate)
            except (OSError, ValueError, ArgusError):
                continue
    return "", None


def _extract(
    hooks_block: Any,
    source: Path,
    scope: str,
    base_dirs: list[Path],
) -> list[Asset]:
    """Parse a ``hooks`` mapping into individual hook assets."""
    if not isinstance(hooks_block, dict):
        return []
    assets: list[Asset] = []
    index = 0

    for event, entries in hooks_block.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            matcher = entry.get("matcher")
            matcher_str = "" if matcher is None else str(matcher)
            inner = entry.get("hooks")
            if not isinstance(inner, list):
                inner = [entry]
            for hook in inner:
                if not isinstance(hook, dict):
                    continue
                command = str(hook.get("command") or "")
                if not command:
                    continue
                index += 1
                script_text, script_path = _script_text(command, base_dirs)
                assets.append(
                    Asset(
                        asset_id=f"hook:{event}#{index}",
                        target=Target.HOOKS,
                        path=source,
                        data={
                            "event": str(event),
                            "matcher": matcher_str,
                            "command": command,
                            "type": str(hook.get("type") or "command"),
                            "timeout": hook.get("timeout"),
                            "scope": scope,
                            "script_path": script_path,
                            "script_text": script_text,
                        },
                        # Analyzers scan the declared command and any resolved script.
                        text=command + ("\n" + script_text if script_text else ""),
                        source=f"{source} [{scope}]",
                    )
                )
    return assets


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []
    home = context.home
    base_dirs = [context.project_root, plat.claude_user_dir(home), home]

    settings_paths = [
        *plat.claude_settings_files(home),
        *plat.project_settings_files(context.project_root),
    ]
    for path in settings_paths:
        if not path.is_file():
            continue
        if not is_readable(path):
            context.record_unreadable(path, "permission denied")
            continue
        data = read_json(path)
        if isinstance(data, dict):
            scope = "user" if str(path).startswith(str(plat.claude_user_dir(home))) else "project"
            assets.extend(_extract(data.get("hooks"), path, scope, base_dirs))

    # Plugin-shipped hooks
    plugins_root = plat.plugins_dir(home) / "marketplaces"
    if plugins_root.is_dir():
        for hooks_file in plugins_root.glob("*/plugins/*/hooks/hooks.json"):
            if hooks_file.is_symlink() or not is_readable(hooks_file):
                continue
            data = read_json(hooks_file)
            if not isinstance(data, dict):
                continue
            plugin_name = hooks_file.parent.parent.name
            block = data.get("hooks") if isinstance(data.get("hooks"), dict) else data
            assets.extend(
                _extract(block, hooks_file, f"plugin:{plugin_name}", [hooks_file.parent])
            )

    return assets
