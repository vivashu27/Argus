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
from pathlib import Path

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


@dataclass(frozen=True)
class Segment:
    """A region of the payload body that came from a real file.

    Tracked in *lines* rather than byte offsets on purpose. Redaction rewrites whole
    lines, so byte offsets shift under it while line numbers do not — mapping in
    lines means the map survives the one transformation applied after it is built.
    """

    first_line: int
    last_line: int
    path: Path | None
    #: Line in the source file matching ``first_line``. ``None`` where the region is
    #: a header Argus composed, which belongs to the file but is not text from it.
    source_line: int | None


@dataclass
class Payload:
    """One asset, prepared for review."""

    asset_id: str
    target: Target
    kind: str
    body: str
    #: What was removed, so the operator can see the tool did not ship their secrets.
    redactions: list[str] = field(default_factory=list)
    #: Where each part of the body came from, so a quoted finding can name a file
    #: and a line instead of pointing vaguely at the component.
    segments: list[Segment] = field(default_factory=list)
    #: The asset's file as it is on disk, where one exists byte for byte. Used to
    #: resolve quotes that land in a header Argus composed: a skill's declared
    #: description is real text at a real line, even though the payload presents it
    #: as a summary line rather than as part of the body.
    source_text: str | None = None
    source_path: Path | None = None

    @property
    def approx_tokens(self) -> int:
        """Rough size, for a cost estimate shown before anything is sent."""
        return len(self.body) // 4

    def find(self, quote: str) -> int:
        """Offset of a quote in the body, ignoring how whitespace is broken up.

        Exact substring matching looked right and was wrong. Prose in a SKILL.md is
        hard-wrapped, so a sentence spanning two lines contains a newline that the
        model does not reproduce when it quotes the sentence back. Every finding in
        wrapped text was therefore rejected as fabricated — the first real run lost
        a true positive to it.

        Collapsing whitespace on both sides keeps the property that matters, which
        is that the words are genuinely present, while dropping the one that never
        did: that the line breaks match.
        """
        needle = " ".join(quote.split())
        if not needle:
            return -1
        haystack, offsets = _collapsed(self.body)
        position = haystack.find(needle)
        return offsets[position] if position >= 0 else -1

    def locate(self, quote: str) -> tuple[Path | None, int | None]:
        """Resolve a quote back to the file and line it came from.

        Returns ``(None, None)`` when the quote is not in the body — which the
        reviewer already treats as a fabricated citation — and ``(path, None)``
        when the text is real but sits in a header Argus composed rather than in
        the file itself.
        """
        index = self.find(quote)
        if index < 0:
            return None, None
        line_in_body = self.body.count("\n", 0, index) + 1
        for segment in self.segments:
            if segment.first_line <= line_in_body <= segment.last_line:
                if segment.source_line is None:
                    return segment.path, self._line_in_source(quote)
                return segment.path, segment.source_line + (line_in_body - segment.first_line)
        return None, None

    def _line_in_source(self, quote: str) -> int | None:
        """Find a quote directly in the asset's file.

        The fallback for text that reaches the payload through a composed header.
        A skill's ``description:`` is summarised into the header, but it is also a
        real line of the real file, and a finding about it should say which.
        """
        if not self.source_text:
            return None
        haystack, offsets = _collapsed(self.source_text)
        needle = " ".join(quote.split())
        position = haystack.find(needle)
        if position < 0:
            return None
        return self.source_text.count("\n", 0, offsets[position]) + 1


def _collapsed(text: str) -> tuple[str, list[int]]:
    """Whitespace-normalised text, plus the original offset of each character.

    The offset list is what lets a match in the normalised string be reported as a
    line in the real file, so normalising does not cost the location.
    """
    out: list[str] = []
    offsets: list[int] = []
    in_space = False
    for index, char in enumerate(text):
        if char.isspace():
            if not in_space and out:
                out.append(" ")
                offsets.append(index)
            in_space = True
            continue
        in_space = False
        out.append(char)
        offsets.append(index)
    return "".join(out), offsets


class _Body:
    """Accumulates the payload text while recording where each part came from."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self.segments: list[Segment] = []
        self._line = 1

    def add(self, text: str, *, path: Path | None = None, source_line: int | None = None) -> None:
        if not text:
            return
        if not text.endswith("\n"):
            text += "\n"
        count = text.count("\n")
        self.segments.append(
            Segment(
                first_line=self._line,
                last_line=self._line + count - 1,
                path=path,
                source_line=source_line,
            )
        )
        self._parts.append(text)
        self._line += count

    @property
    def text(self) -> str:
        return "".join(self._parts)


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


def _describe(asset: Asset) -> tuple[str, _Body]:
    """The kind label and the composed body, with its source map."""
    data = asset.data or {}
    body = _Body()

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
        body.add(header, path=asset.path)
        body.add("\n--- SKILL.md body ---")
        # body_offset counts the frontmatter lines, so the body's first line is the
        # one after it. Without this every skill finding would point at line 1.
        body.add(
            str(data.get("body") or ""),
            path=asset.path,
            source_line=int(data.get("body_offset") or 0) + 1,
        )
        return "Claude Skill", body

    if asset.target is Target.INSTRUCTIONS:
        body.add(asset.text or "", path=asset.path, source_line=1)
        return "Instruction file", body

    if asset.target is Target.HOOKS:
        # The command is declared inside a settings file, so it is attributable to
        # that file but not to a line of it — the hook asset's text is synthesised.
        body.add(
            f"event: {data.get('event', '')}\n"
            f"matcher: {data.get('matcher', '') or '(all tools)'}\n"
            f"command: {data.get('command', '')}\n",
            path=asset.path,
        )
        script = data.get("script_text")
        if script:
            script_path = data.get("script_path")
            body.add(f"\n--- hook script ({script_path}) ---")
            body.add(
                _truncate(str(script), MAX_FILE_CHARS),
                path=Path(script_path) if script_path else None,
                source_line=1,
            )
        return "Hook", body

    if asset.target is Target.MCP:
        body.add(
            f"name: {data.get('name', '')}\n"
            f"command: {data.get('command', '')}\n"
            f"args: {data.get('args', [])}\n"
            f"transport: {data.get('transport', '')}\n",
            path=asset.path,
        )
        for path, text in (asset.code_files or [])[:MAX_FILES]:
            body.add(f"\n--- {path.name} ---")
            body.add(_truncate(text, MAX_FILE_CHARS), path=path, source_line=1)
        return "MCP server", body

    if asset.target is Target.PLUGINS:
        body.add(
            f"name: {data.get('name', '')}\n"
            f"marketplace: {data.get('marketplace', '')} ({data.get('trust', '')})\n",
            path=asset.path,
        )
        for entry in (data.get("files") or [])[:MAX_FILES]:
            body.add(f"\n--- {entry.get('relative', '')} ---")
            raw = entry.get("path")
            body.add(
                _truncate(str(entry.get("text") or ""), MAX_FILE_CHARS),
                path=Path(raw) if raw else None,
                source_line=1,
            )
        return "Plugin", body

    body.add(asset.text or "", path=asset.path, source_line=1 if asset.text_is_verbatim else None)
    return asset.target.value, body


def build(asset: Asset) -> Payload:
    """Prepare one asset for review, or refuse.

    :raises UnsafePayload: if a credential survives redaction.
    """
    kind, composed = _describe(asset)
    # Truncation only removes trailing lines and redaction rewrites lines in place,
    # so neither disturbs the line numbers the segments were built from.
    redacted, removed = _redact(_truncate(composed.text, MAX_BODY_CHARS))

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
        segments=composed.segments,
        source_text=asset.text if asset.text_is_verbatim else None,
        source_path=asset.path,
    )
