"""Defensive file access.

Every read in Argus goes through this module. Scanned files are hostile by
assumption: they may be enormous, be symlinks pointing at ``/dev/zero`` or outside
the scan root, contain invalid encodings, or be YAML crafted to instantiate Python
objects. Nothing here executes, deserializes into custom types, or follows a link
out of bounds.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml

from .exceptions import FileTooLargeError, UnsafePathError

#: Files larger than this are never read into memory.
DEFAULT_MAX_BYTES = 5 * 1024 * 1024

#: Directory names never descended into during project discovery.
SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
        "target", "vendor", ".cache",
    }
)


def resolve_within(path: Path, root: Path) -> Path:
    """Resolve ``path`` and assert it stays inside ``root``.

    Resolution happens first so that a symlink pointing outside the root is caught
    by its target, not by its (innocent-looking) name.
    """
    resolved = path.resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise UnsafePathError(f"{path} resolves outside scan root {root}")
    return resolved


def escapes_root(path: Path, root: Path) -> bool:
    """Non-raising form of :func:`resolve_within`, for symlink reporting (FS-006)."""
    try:
        resolve_within(path, root)
    except (UnsafePathError, OSError):
        return True
    return False


def is_readable(path: Path) -> bool:
    return os.access(path, os.R_OK)


def read_text(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """Read a file as text, size-capped, never raising on bad encoding.

    Special files (FIFOs, devices) are rejected outright: ``stat`` on ``/dev/zero``
    reports size 0, so a size check alone would not protect us.
    """
    st = path.stat()
    if not path.is_file():
        raise FileTooLargeError(f"{path} is not a regular file")
    if st.st_size > max_bytes:
        raise FileTooLargeError(f"{path} is {st.st_size} bytes, over the {max_bytes} cap")
    with path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise FileTooLargeError(f"{path} exceeded the {max_bytes} cap while reading")
    return raw.decode("utf-8", errors="replace")


def read_json(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Parse JSON. Returns ``None`` for malformed input rather than raising."""
    try:
        return json.loads(read_text(path, max_bytes))
    except (json.JSONDecodeError, ValueError):
        return None


def read_yaml(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Parse YAML with ``safe_load`` only — never ``yaml.load`` (spec 2)."""
    try:
        return yaml.safe_load(read_text(path, max_bytes))
    except yaml.YAMLError:
        return None


def parse_yaml_text(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def iter_files(
    root: Path,
    *,
    max_depth: int = 6,
    suffixes: tuple[str, ...] | None = None,
    max_files: int = 5000,
) -> list[Path]:
    """Depth-limited, symlink-safe walk. Never descends outside ``root``."""
    if not root.is_dir():
        return []
    found: list[Path] = []
    root_resolved = root.resolve()
    stack: list[tuple[Path, int]] = [(root_resolved, 0)]
    while stack and len(found) < max_files:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            if entry.is_symlink():
                # Directory symlinks are never traversed: they are the classic route
                # out of the scan root and into a loop.
                continue
            try:
                if entry.is_dir() and entry.name not in SKIP_DIRS:
                    stack.append((entry, depth + 1))
                elif entry.is_file() and (
                    suffixes is None or entry.suffix.lower() in suffixes
                ):
                    found.append(entry)
            except OSError:
                continue
    return found


def file_mode(path: Path) -> int | None:
    """POSIX permission bits, or ``None`` where unavailable (e.g. Windows)."""
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return None
