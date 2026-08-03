"""Claude Desktop discovery.

Claude Desktop stores its configuration in a genuinely platform-specific location,
so paths come from :mod:`argus.discovery.platform` rather than being hardcoded.
"""

from __future__ import annotations

from ..core.exceptions import ArgusError
from ..core.models import Asset, Target
from ..core.safe_io import is_readable, read_json, read_text
from . import platform as plat
from .base import DiscoveryContext


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []
    if not context.user_scope:
        return assets
    config_path = plat.claude_desktop_config(context.home)

    if not config_path.is_file():
        return assets
    context.record_root(config_path.parent)

    if not is_readable(config_path):
        context.record_unreadable(config_path, "permission denied")
        return assets

    data = read_json(config_path)
    try:
        raw = read_text(config_path)
    except (OSError, ValueError, ArgusError):
        raw = ""

    if not isinstance(data, dict):
        assets.append(
            Asset(
                asset_id="claude-desktop:config",
                target=Target.CLAUDE_DESKTOP,
                path=config_path,
                data={"config": {}, "malformed": True},
                text=raw,
                text_is_verbatim=True,
                source=str(config_path),
            )
        )
        return assets

    preferences = data.get("preferences") if isinstance(data.get("preferences"), dict) else {}
    assets.append(
        Asset(
            asset_id="claude-desktop:config",
            target=Target.CLAUDE_DESKTOP,
            path=config_path,
            data={
                "config": data,
                "preferences": preferences,
                "mcp_server_names": sorted((data.get("mcpServers") or {}).keys())
                if isinstance(data.get("mcpServers"), dict)
                else [],
                "malformed": False,
            },
            text=raw,
            text_is_verbatim=True,
            source=str(config_path),
        )
    )
    return assets
