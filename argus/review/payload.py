"""Build the text sent to a reviewing model, with secrets removed first.

This is the module that makes LLM review defensible at all. Argus reads
``~/.claude/.credentials.json``, ``.env`` files and MCP configs with API keys
inline. Sending those to a third-party API would mean a security tool exfiltrating
the credentials it just found — worse than not scanning, because the user believes
they ran a defensive tool.

So redaction is a precondition, not a courtesy, and it fails closed: a payload that
still trips the secret scanner after redaction is not sent. The alternative — send
it and hope — puts the burden of a leak on the person who trusted the tool.

Truncation matters for the same reason bounded reads matter elsewhere: a skill can
embed a megabyte of base64, and a reviewer that forwards it wholesale turns one
scan into an unbounded bill.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analysis import secrets
from ..core.models import Asset, Target

#: Characters of one asset's body sent for review. Generous enough for a real
#: SKILL.md or CLAUDE.md, bounded enough that a hostile file cannot run up a bill.
MAX_BODY_CHARS = 24_000

#: Per-file cap when an asset carries several files (a plugin, an MCP server).
MAX_FILE_CHARS = 6_000

#: Files from one asset included in a single payload.
MAX_FILES = 8


class UnsafePayload(RuntimeError):
    """A payload still contained a credential after redaction. Never sent."""


@dataclass
class Payload:
    """One asset, prepared for review."""

    asset_id: str
    target: Target
    kind: str
    body: str
    #: What was removed, so the operator can see the tool did not ship their secrets.
    redactions: list[str] = field(default_factory=list)

    @property
    def approx_tokens(self) -> int:
        """Rough size, for a cost estimate shown before anything is sent."""
        return len(self.body) // 4


def _redact(text: str) -> tuple[str, list[str]]:
    """Replace every credential the secret scanner can find.

    Uses the same detector as ``SECRET-*`` rather than a second, weaker one. If a
    pattern is good enough to report as a finding, it is good enough to strip before
    the text leaves the machine, and keeping one implementation means the two cannot
    drift apart.
    """
    matches = secrets.scan_text(text, max_findings=200)
    if not matches:
        return text, []

    # Whole offending lines are replaced. Surgical replacement of just the value
    # would need the raw secret, which the scanner deliberately never returns.
    lines = text.splitlines()
    for match in matches:
        index = match.line - 1
        if 0 <= index < len(lines):
            lines[index] = "[REDACTED BY ARGUS — line contained a credential]"
    return "\n".join(lines), [m.description for m in matches]


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... truncated by Argus at {limit} characters ...]"


def _describe(asset: Asset) -> tuple[str, str]:
    """The kind label and the body text for one asset."""
    data = asset.data or {}

    if asset.target is Target.SKILLS:
        frontmatter = data.get("frontmatter") or {}
        tools = data.get("allowed_tools") or []
        header = (
            f"name: {data.get('name', '')}\n"
            f"description: {frontmatter.get('description', '')}\n"
            f"allowed-tools: {', '.join(str(t) for t in tools) or '(none declared)'}\n"
        )
        scripts = data.get("scripts") or []
        if scripts:
            header += f"bundled scripts: {', '.join(str(s) for s in scripts[:12])}\n"
        return "Claude Skill", header + "\n--- SKILL.md body ---\n" + str(data.get("body") or "")

    if asset.target is Target.INSTRUCTIONS:
        return "Instruction file", asset.text or ""

    if asset.target is Target.HOOKS:
        body = (
            f"event: {data.get('event', '')}\n"
            f"matcher: {data.get('matcher', '') or '(all tools)'}\n"
            f"command: {data.get('command', '')}\n"
        )
        script = data.get("script_text")
        if script:
            body += f"\n--- hook script ({data.get('script_path')}) ---\n{script}"
        return "Hook", body

    if asset.target is Target.MCP:
        body = (
            f"name: {data.get('name', '')}\n"
            f"command: {data.get('command', '')}\n"
            f"args: {data.get('args', [])}\n"
            f"transport: {data.get('transport', '')}\n"
        )
        for path, text in (asset.code_files or [])[:MAX_FILES]:
            body += f"\n--- {path.name} ---\n{_truncate(text, MAX_FILE_CHARS)}"
        return "MCP server", body

    if asset.target is Target.PLUGINS:
        body = (
            f"name: {data.get('name', '')}\n"
            f"marketplace: {data.get('marketplace', '')} ({data.get('trust', '')})\n"
        )
        for entry in (data.get("files") or [])[:MAX_FILES]:
            body += (
                f"\n--- {entry.get('relative', '')} ---\n"
                f"{_truncate(str(entry.get('text') or ''), MAX_FILE_CHARS)}"
            )
        return "Plugin", body

    return asset.target.value, asset.text or ""


def build(asset: Asset) -> Payload:
    """Prepare one asset for review, or refuse.

    :raises UnsafePayload: if a credential survives redaction.
    """
    kind, raw = _describe(asset)
    redacted, removed = _redact(_truncate(raw, MAX_BODY_CHARS))

    # Fail closed. If the scanner still finds something after redaction, the
    # redaction did not work and the only safe move is not to send it.
    if secrets.scan_text(redacted, max_findings=1):
        raise UnsafePayload(
            f"{asset.asset_id}: a credential survived redaction, so nothing was sent"
        )

    return Payload(
        asset_id=asset.asset_id,
        target=asset.target,
        kind=kind,
        body=redacted,
        redactions=removed,
    )
