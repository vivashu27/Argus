"""IDE integration discovery.

Inventory only. IDE extensions are enumerated so reports can describe the full
agent surface and so plugin trust evaluation has context; AASB v1.0 defines no
dedicated ``IDE-*`` checks (spec 5.9).
"""

from __future__ import annotations

from ..core.models import Asset, Target
from ..core.safe_io import is_readable, read_json
from . import platform as plat
from .base import DiscoveryContext

CLAUDE_EXTENSION_MARKERS = ("anthropic", "claude")


def discover(context: DiscoveryContext) -> list[Asset]:
    assets: list[Asset] = []

    for directory in plat.ide_config_dirs(context.home):
        if not directory.is_dir():
            continue
        context.record_root(directory)

        if directory.name == "extensions":
            try:
                entries = sorted(p for p in directory.iterdir() if p.is_dir() and not p.is_symlink())
            except OSError as exc:
                context.record_unreadable(directory, str(exc))
                continue

            names = [p.name for p in entries]
            agent_extensions = [
                n for n in names if any(m in n.lower() for m in CLAUDE_EXTENSION_MARKERS)
            ]
            assets.append(
                Asset(
                    asset_id=f"ide:{directory.parent.name}",
                    target=Target.IDE,
                    path=directory,
                    data={
                        "editor": directory.parent.name.lstrip("."),
                        "extension_count": len(names),
                        "extensions": names[:200],
                        "agent_extensions": agent_extensions,
                    },
                    source=str(directory),
                )
            )
        else:
            settings = directory / "settings.json"
            if settings.is_file() and is_readable(settings):
                data = read_json(settings)
                if isinstance(data, dict):
                    assets.append(
                        Asset(
                            asset_id=f"ide:{directory.parent.name}-settings",
                            target=Target.IDE,
                            path=settings,
                            data={"editor": directory.parent.name, "settings": data},
                            source=str(settings),
                        )
                    )

    return assets
