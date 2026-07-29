"""Plugin discovery.

Plugins are installed under ``~/.claude/plugins`` — typically from a marketplace
checkout. Each plugin becomes one asset carrying its manifest, its bundled command
and agent files, and the text of any hook scripts it ships. Nothing is executed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.exceptions import ArgusError
from ..core.models import Asset, Target
from ..core.safe_io import is_readable, iter_files, read_json, read_text
from . import platform as plat
from .base import DiscoveryContext

BUNDLED_SUFFIXES = (".md", ".json", ".sh", ".py", ".js", ".ts", ".ps1", ".yaml", ".yml")

#: Marketplaces published by Anthropic. Everything else is "unverified" — which is a
#: statement about provenance, not about the plugin being malicious.
FIRST_PARTY_MARKETPLACES = frozenset({"claude-plugins-official", "anthropic-official"})


def _read_manifest(plugin_dir: Path) -> tuple[dict[str, Any], Path | None]:
    for candidate in (
        plugin_dir / ".claude-plugin" / "plugin.json",
        plugin_dir / "plugin.json",
        plugin_dir / ".claude-plugin" / "marketplace.json",
    ):
        if candidate.is_file() and is_readable(candidate):
            data = read_json(candidate)
            if isinstance(data, dict):
                return data, candidate
    return {}, None


def _bundled_files(plugin_dir: Path) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for path in iter_files(plugin_dir, max_depth=4, suffixes=BUNDLED_SUFFIXES, max_files=120):
        try:
            text = read_text(path)
        except (OSError, ValueError, ArgusError):
            continue
        try:
            relative = str(path.relative_to(plugin_dir))
        except ValueError:
            relative = path.name
        out.append({"path": str(path), "relative": relative, "text": text})
    return out


def _marketplace_trust(marketplace: str, known: dict[str, Any]) -> tuple[str, str]:
    """Classify a marketplace as first-party, known, or unverified."""
    if marketplace in FIRST_PARTY_MARKETPLACES:
        return "first-party", "Published by Anthropic"
    entry = known.get(marketplace)
    if isinstance(entry, dict):
        source = entry.get("source") or entry.get("url") or entry.get("repo") or ""
        return "known", f"Registered marketplace: {source}" if source else "Registered marketplace"
    return "unverified", "Not present in known_marketplaces.json"


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []
    if not context.user_scope:
        return assets
    root = plat.plugins_dir(context.home)
    if not root.is_dir():
        return assets
    context.record_root(root)

    known: dict[str, Any] = {}
    known_file = root / "known_marketplaces.json"
    if known_file.is_file() and is_readable(known_file):
        data = read_json(known_file)
        if isinstance(data, dict):
            registry = data.get("marketplaces")
            known = registry if isinstance(registry, dict) else data

    marketplaces_dir = root / "marketplaces"
    if not marketplaces_dir.is_dir():
        return assets

    try:
        marketplace_dirs = sorted(marketplaces_dir.iterdir())
    except OSError as exc:
        context.record_unreadable(marketplaces_dir, str(exc))
        return assets

    for marketplace_dir in marketplace_dirs:
        if not marketplace_dir.is_dir() or marketplace_dir.is_symlink():
            continue
        marketplace = marketplace_dir.name
        trust, trust_reason = _marketplace_trust(marketplace, known)

        plugin_parent = marketplace_dir / "plugins"
        candidates = (
            sorted(plugin_parent.iterdir()) if plugin_parent.is_dir() else [marketplace_dir]
        )

        for plugin_dir in candidates:
            if not plugin_dir.is_dir() or plugin_dir.is_symlink():
                continue
            manifest, manifest_path = _read_manifest(plugin_dir)
            name = str(manifest.get("name") or plugin_dir.name)
            files = _bundled_files(plugin_dir)

            mcp_config: dict[str, Any] = {}
            plugin_mcp = plugin_dir / ".mcp.json"
            if plugin_mcp.is_file() and is_readable(plugin_mcp):
                data = read_json(plugin_mcp)
                if isinstance(data, dict):
                    mcp_config = data

            assets.append(
                Asset(
                    asset_id=f"plugin:{marketplace}/{name}",
                    target=Target.PLUGINS,
                    path=manifest_path or plugin_dir,
                    data={
                        "name": name,
                        "marketplace": marketplace,
                        "trust": trust,
                        "trust_reason": trust_reason,
                        "directory": str(plugin_dir),
                        "manifest": manifest,
                        "files": files,
                        "mcp": mcp_config,
                        "has_hooks": (plugin_dir / "hooks").is_dir(),
                    },
                    text=json.dumps(manifest, indent=2, default=str) if manifest else "",
                    source=str(manifest_path or plugin_dir),
                )
            )

    return assets


def plugin_hook_files(plugin_dir: Path) -> list[Path]:
    hooks_dir = plugin_dir / "hooks"
    if not hooks_dir.is_dir():
        return []
    return iter_files(hooks_dir, max_depth=2, max_files=40)
