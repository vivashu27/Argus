"""Shared fixtures.

Every credential in these fixtures is synthetic: structurally valid so the detectors
engage, but non-functional. No real credential appears anywhere in this suite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.checks.base import CheckContext
from argus.core.models import Asset, Target

# --- synthetic credentials -----------------------------------------------------
# Structurally valid, deliberately non-functional.
#
# Note the AWS key is *not* Amazon's documented AKIAIOSFODNN7EXAMPLE: that string
# contains "EXAMPLE", which Argus's placeholder filter correctly suppresses, so it
# cannot be used to exercise positive detection.
FAKE_AWS_KEY = "AKIAQWERTYUIOPASDFGH"
FAKE_ANTHROPIC_KEY = "sk-ant-api03-" + "T3stK3yM4t3r1alN0tR34l" * 2
FAKE_GITHUB_TOKEN = "ghp_" + "0123456789abcdefghijKLMNOPQRSTUVwxyz"
FAKE_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAtestkeymaterialnotrealnotrealnotreal\n"
    "-----END RSA PRIVATE KEY-----"
)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """An isolated fake home directory."""
    root = tmp_path / "home"
    (root / ".claude").mkdir(parents=True)
    return root


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    return root


def write_settings(home: Path, settings: dict, name: str = "settings.json") -> Path:
    path = home / ".claude" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2))
    return path


def settings_asset(path: Path, settings: dict, scope: str = "user") -> Asset:
    return Asset(
        asset_id=f"claude-code:{scope}-settings",
        target=Target.CLAUDE_CODE,
        path=path,
        data={"settings": settings, "scope": scope, "malformed": False},
        text=json.dumps(settings, indent=2),
        source=str(path),
    )


def mcp_asset(name: str, spec: dict, path: Path | None = None) -> Asset:
    return Asset(
        asset_id=f"mcp:{name}",
        target=Target.MCP,
        path=path or Path("/tmp/.mcp.json"),
        data={
            "name": name,
            "command": str(spec.get("command", "")),
            "args": [str(a) for a in spec.get("args", [])],
            "env": {str(k): str(v) for k, v in (spec.get("env") or {}).items()},
            "url": str(spec.get("url", "")),
            "transport": spec.get("type", "stdio"),
            "scope": "test",
            "raw": spec,
        },
        text=json.dumps(spec, indent=2),
        source=str(path or "/tmp/.mcp.json"),
    )


def skill_asset(name: str, body: str, frontmatter: dict | None = None, scripts=None) -> Asset:
    frontmatter = frontmatter or {}
    return Asset(
        asset_id=f"skill:{name}",
        target=Target.SKILLS,
        path=Path(f"/tmp/skills/{name}/SKILL.md"),
        data={
            "name": name,
            "scope": "user",
            "directory": f"/tmp/skills/{name}",
            "frontmatter": frontmatter,
            "allowed_tools": frontmatter.get("allowed-tools", []) or [],
            "body": body,
            "body_offset": 0,
            "scripts": scripts or [],
        },
        text=body,
        source=f"/tmp/skills/{name}/SKILL.md",
    )


def hook_asset(event: str, command: str, matcher: str = "Bash", script_text: str = "") -> Asset:
    return Asset(
        asset_id=f"hook:{event}#1",
        target=Target.HOOKS,
        path=Path("/tmp/settings.json"),
        data={
            "event": event,
            "matcher": matcher,
            "command": command,
            "type": "command",
            "timeout": None,
            "scope": "user",
            "script_path": None,
            "script_text": script_text,
        },
        text=command + ("\n" + script_text if script_text else ""),
        source="/tmp/settings.json",
    )


def instruction_asset(text: str, name: str = "CLAUDE.md") -> Asset:
    return Asset(
        asset_id=f"instructions:project:{name}",
        target=Target.INSTRUCTIONS,
        path=Path(f"/tmp/{name}"),
        data={"scope": "project", "name": name, "lines": text.count("\n") + 1},
        text=text,
        source=f"/tmp/{name}",
    )


def make_context(assets: list[Asset], project: Path, home: Path) -> CheckContext:
    return CheckContext(assets=assets, project_root=project, home=home)


def run_check(check_cls, assets, project: Path, home: Path):
    return check_cls().run(make_context(assets, project, home))


def statuses(findings) -> set[str]:
    return {f.status.value for f in findings}
