"""Skill discovery.

A Skill is a directory containing ``SKILL.md`` with YAML frontmatter. Skills are
read as text and never executed, and bundled scripts are inventoried but not run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..core.exceptions import ArgusError
from ..core.models import Asset, Target
from ..core.safe_io import is_readable, iter_files, parse_yaml_text, read_text
from . import platform as plat
from .base import DiscoveryContext

FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)

SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".ps1", ".rb", ".pl")


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str, int]:
    """Split YAML frontmatter from the body.

    Returns ``(frontmatter, body, body_line_offset)``. The offset is how many lines
    the frontmatter consumed, so findings reported against the body can be
    translated back to real file line numbers.
    """
    match = FRONTMATTER.match(text)
    if not match:
        return {}, text, 0
    offset = text[: match.end()].count("\n")
    parsed = parse_yaml_text(match.group(1))
    body = text[match.end() :]
    if not isinstance(parsed, dict):
        return {}, body, offset
    return parsed, body, offset


def _collect_scripts(skill_dir: Path) -> list[dict[str, Any]]:
    """Inventory bundled executables. Contents are read as text, never run."""
    scripts: list[dict[str, Any]] = []
    for path in iter_files(skill_dir, max_depth=3, suffixes=SCRIPT_SUFFIXES, max_files=50):
        try:
            content = read_text(path)
        except (OSError, ValueError, ArgusError):
            # Unreadable or oversized scripts are skipped here; the caller records them
            # so coverage stays honest rather than silently shrinking.
            continue
        scripts.append({"path": str(path), "name": path.name, "text": content})
    return scripts


def _discover_dir(root: Path, scope: str, context: DiscoveryContext) -> list[Asset]:
    if not root.is_dir():
        return []
    context.record_root(root)
    assets: list[Asset] = []
    try:
        entries = sorted(root.iterdir())
    except OSError as exc:
        context.record_unreadable(root, str(exc))
        return []

    for skill_dir in entries:
        if not skill_dir.is_dir() or skill_dir.is_symlink():
            continue
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file():
            continue
        if not is_readable(skill_file):
            context.record_unreadable(skill_file, "permission denied")
            continue
        try:
            text = read_text(skill_file)
        except (OSError, ValueError, ArgusError) as exc:
            context.record_unreadable(skill_file, str(exc))
            continue

        frontmatter, body, body_offset = parse_frontmatter(text)
        name = str(frontmatter.get("name") or skill_dir.name)
        scripts = _collect_scripts(skill_dir)

        assets.append(
            Asset(
                asset_id=f"skill:{name}",
                target=Target.SKILLS,
                path=skill_file,
                data={
                    "name": name,
                    "scope": scope,
                    "directory": str(skill_dir),
                    "frontmatter": frontmatter,
                    "allowed_tools": _allowed_tools(frontmatter),
                    "body": body,
                    "body_offset": body_offset,
                    "scripts": scripts,
                },
                text=text,
                text_is_verbatim=True,
                source=str(skill_file),
            )
        )
    return assets


def _allowed_tools(frontmatter: dict[str, Any]) -> list[str]:
    """Normalize ``allowed-tools`` which may be a list or a comma-separated string."""
    raw = frontmatter.get("allowed-tools") or frontmatter.get("allowed_tools") or []
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def discover(context: DiscoveryContext) -> list[Asset]:
    """Discover Skills from every plausible layout.

    Beyond the two canonical locations, the scan root itself and ``<root>/skills`` are
    treated as skill roots. That makes ``--path ./some-skills-folder`` work on a plain
    directory of skill packages, which is the natural way to audit skills you have not
    installed — previously such a directory yielded nothing at all, and the report
    quietly showed the operator's own installed skills instead.
    """
    assets: list[Asset] = []
    user_skills, project_skills = plat.skills_dirs(context.project_root, context.home)

    if context.user_scope:
        assets.extend(_discover_dir(user_skills, "user", context))
    assets.extend(_discover_dir(project_skills, "project", context))

    seen = {a.data.get("directory") for a in assets}
    for root, scope in ((context.project_root, "path"), (context.project_root / "skills", "path")):
        for asset in _discover_dir(root, scope, context):
            if asset.data.get("directory") not in seen:
                seen.add(asset.data.get("directory"))
                assets.append(asset)
    return assets
