"""Instruction file discovery (``CLAUDE.md`` and friends).

Instruction files are the highest-leverage injection surface in an agent
environment: their contents enter the model's context on every turn. They are read
as text and nothing inside them is ever acted on.
"""

from __future__ import annotations

from pathlib import Path

from ..core.exceptions import ArgusError
from ..core.models import Asset, Target
from ..core.safe_io import SKIP_DIRS, is_readable, read_text
from . import platform as plat
from .base import DiscoveryContext

INSTRUCTION_NAMES = frozenset({"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"})


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []
    seen: set[str] = set()

    def add(path: Path, scope: str) -> None:
        resolved = str(path)
        if resolved in seen or not path.is_file() or path.is_symlink():
            return
        if not is_readable(path):
            context.record_unreadable(path, "permission denied")
            return
        try:
            text = read_text(path)
        except (OSError, ValueError, ArgusError) as exc:
            context.record_unreadable(path, str(exc))
            return
        seen.add(resolved)
        assets.append(
            Asset(
                asset_id=f"instructions:{scope}:{path.name}",
                target=Target.INSTRUCTIONS,
                path=path,
                data={"scope": scope, "name": path.name, "lines": text.count("\n") + 1},
                text=text,
                source=str(path),
            )
        )

    user_dir = str(plat.claude_user_dir(context.home))
    for path in plat.instruction_files(context.project_root, context.home):
        is_user = str(path).startswith(user_dir)
        if is_user and not context.user_scope:
            continue
        add(path, "user" if is_user else "project")

    # Nested instruction files inside the project, depth-limited.
    root = context.project_root
    if root.is_dir():
        context.record_root(root)
        for name in INSTRUCTION_NAMES:
            for path in root.glob(f"*/{name}"):
                if not any(part in SKIP_DIRS for part in path.parts):
                    add(path, "project-nested")
            for path in root.glob(f"*/*/{name}"):
                if not any(part in SKIP_DIRS for part in path.parts):
                    add(path, "project-nested")

    return assets
