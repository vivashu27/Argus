"""MCP server discovery.

MCP servers are declared in several places at once — Claude Desktop's config, the
project ``.mcp.json``, and per-project blocks inside ``~/.claude.json``. Each server
becomes its own asset so findings can name the specific server at fault.

MCP servers are never launched.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.models import Asset, Target
from ..core.safe_io import is_readable, read_json
from . import platform as plat
from .base import DiscoveryContext


def _normalize_server(name: str, spec: Any, source: Path, scope: str) -> Asset | None:
    """Turn one server definition into an asset. Tolerates malformed entries."""
    if not isinstance(spec, dict):
        return None

    command = spec.get("command")
    args = spec.get("args")
    env = spec.get("env")
    url = spec.get("url") or spec.get("endpoint") or spec.get("serverUrl")

    if not isinstance(args, list):
        args = []
    args = [str(a) for a in args if isinstance(a, (str, int, float))]
    if not isinstance(env, dict):
        env = {}

    transport = str(spec.get("type") or spec.get("transport") or ("stdio" if command else "remote"))

    return Asset(
        asset_id=f"mcp:{name}",
        target=Target.MCP,
        path=source,
        data={
            "name": name,
            "command": str(command) if command else "",
            "args": args,
            "env": {str(k): str(v) for k, v in env.items()},
            "url": str(url) if url else "",
            "transport": transport,
            "scope": scope,
            "raw": spec,
        },
        # Serialised form gives the secret and command scanners something to walk.
        text=json.dumps(spec, indent=2, default=str),
        source=f"{source} [{scope}]",
    )


def _from_mapping(
    servers: Any, source: Path, scope: str, context: DiscoveryContext
) -> list[Asset]:
    if not isinstance(servers, dict):
        return []
    out: list[Asset] = []
    for name, spec in servers.items():
        asset = _normalize_server(str(name), spec, source, scope)
        if asset is not None:
            out.append(asset)
        else:
            context.record_error(f"MCP server {name!r} in {source} has a malformed definition")
    return out


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []

    # 1. Claude Desktop configuration (user scope)
    desktop_config = plat.claude_desktop_config(context.home)
    if context.user_scope and desktop_config.is_file() and is_readable(desktop_config):
        data = read_json(desktop_config)
        if isinstance(data, dict):
            assets.extend(
                _from_mapping(data.get("mcpServers"), desktop_config, "claude-desktop", context)
            )

    # 2. Project-scoped .mcp.json
    project_mcp = plat.project_mcp_file(context.project_root)
    if project_mcp.is_file():
        if is_readable(project_mcp):
            data = read_json(project_mcp)
            if isinstance(data, dict):
                assets.extend(_from_mapping(data.get("mcpServers"), project_mcp, "project", context))
        else:
            context.record_unreadable(project_mcp, "permission denied")

    # 3. Per-project blocks in ~/.claude.json (user scope)
    global_state = plat.claude_json(context.home)
    if context.user_scope and global_state.is_file() and is_readable(global_state):
        data = read_json(global_state)
        if isinstance(data, dict):
            projects = data.get("projects")
            if isinstance(projects, dict):
                for project_path, block in projects.items():
                    if not isinstance(block, dict):
                        continue
                    assets.extend(
                        _from_mapping(
                            block.get("mcpServers"),
                            global_state,
                            f"claude-code:{project_path}",
                            context,
                        )
                    )

    # 4. Claude Code settings files may also carry MCP definitions.
    settings_sources = list(plat.project_settings_files(context.project_root))
    if context.user_scope:
        settings_sources = [*plat.claude_settings_files(context.home), *settings_sources]
    for settings_path in settings_sources:
        if settings_path.is_file() and is_readable(settings_path):
            data = read_json(settings_path)
            if isinstance(data, dict):
                assets.extend(
                    _from_mapping(data.get("mcpServers"), settings_path, "claude-code", context)
                )

    return _dedupe(assets)


def _dedupe(assets: list[Asset]) -> list[Asset]:
    """The same server declared in two scopes is one asset, keeping the first scope."""
    seen: dict[tuple[str, str, str], Asset] = {}
    for asset in assets:
        key = (
            asset.data.get("name", ""),
            asset.data.get("command", ""),
            " ".join(asset.data.get("args", [])),
        )
        if key not in seen:
            seen[key] = asset
    return list(seen.values())


def known_marketplace_paths(home: Path) -> list[Path]:
    """Plugin marketplace roots, used by MCP/plugin trust evaluation."""
    root = plat.plugins_dir(home) / "marketplaces"
    if not root.is_dir():
        return []
    return [p for p in root.iterdir() if p.is_dir() and not p.is_symlink()]
