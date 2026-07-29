"""OS-aware configuration path resolution (spec 4.1).

Paths differ per platform and must never be hardcoded to the developer's OS.
"""

from __future__ import annotations

import os
import platform
import socket
import sys
from pathlib import Path


def os_name() -> str:
    """Normalized platform identifier: ``linux``, ``macos``, or ``windows``."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def is_posix() -> bool:
    return os_name() != "windows"


def platform_string() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def home(explicit: Path | None = None) -> Path:
    return explicit or Path.home()


def claude_user_dir(base: Path | None = None) -> Path:
    """``~/.claude`` on every supported platform (Claude Code uses the same layout)."""
    return home(base) / ".claude"


def claude_json(base: Path | None = None) -> Path:
    """The Claude Code global state file, ``~/.claude.json``."""
    return home(base) / ".claude.json"


def claude_settings_files(base: Path | None = None) -> list[Path]:
    root = claude_user_dir(base)
    return [root / "settings.json", root / "settings.local.json"]


def claude_desktop_dir(base: Path | None = None) -> Path:
    """Claude Desktop's application-support directory, which is genuinely OS-specific."""
    system = os_name()
    if system == "macos":
        return home(base) / "Library" / "Application Support" / "Claude"
    if system == "windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Claude"
        return home(base) / "AppData" / "Roaming" / "Claude"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "Claude"
    return home(base) / ".config" / "Claude"


def claude_desktop_config(base: Path | None = None) -> Path:
    return claude_desktop_dir(base) / "claude_desktop_config.json"


def skills_dirs(project_root: Path, base: Path | None = None) -> list[Path]:
    return [claude_user_dir(base) / "skills", project_root / ".claude" / "skills"]


def plugins_dir(base: Path | None = None) -> Path:
    return claude_user_dir(base) / "plugins"


def agents_dirs(project_root: Path, base: Path | None = None) -> list[Path]:
    return [claude_user_dir(base) / "agents", project_root / ".claude" / "agents"]


def project_mcp_file(project_root: Path) -> Path:
    return project_root / ".mcp.json"


def project_settings_files(project_root: Path) -> list[Path]:
    root = project_root / ".claude"
    return [root / "settings.json", root / "settings.local.json"]


def instruction_files(project_root: Path, base: Path | None = None) -> list[Path]:
    """Instruction files in precedence order (user, then project)."""
    return [
        claude_user_dir(base) / "CLAUDE.md",
        project_root / "CLAUDE.md",
        project_root / "CLAUDE.local.md",
        project_root / ".claude" / "CLAUDE.md",
        project_root / "AGENTS.md",
    ]


def ide_config_dirs(base: Path | None = None) -> list[Path]:
    """Discoverable IDE extension roots, used for inventory only."""
    root = home(base)
    system = os_name()
    candidates = [root / ".vscode" / "extensions", root / ".cursor" / "extensions"]
    if system == "macos":
        candidates.append(root / "Library" / "Application Support" / "Code" / "User")
    elif system == "windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Code" / "User")
    else:
        candidates.append(root / ".config" / "Code" / "User")
    return candidates


def relevant_env_vars() -> dict[str, str]:
    """Agent-relevant environment variables.

    Values are returned raw; callers must redact before reporting. Anything matching
    a credential-shaped name is included precisely so SECRET checks can flag it.
    """
    prefixes = ("CLAUDE", "ANTHROPIC", "MCP", "OPENAI")
    keys = ("API_KEY", "TOKEN", "SECRET", "CREDENTIAL", "PASSWORD")
    out: dict[str, str] = {}
    for name, value in os.environ.items():
        upper = name.upper()
        if upper.startswith(prefixes) or any(k in upper for k in keys):
            out[name] = value
    return out
