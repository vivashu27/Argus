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
    #: Lazily built in _segment_texts. Each verdict resolves a quote two or three
    #: times, so recomputing the split per call meant ~10 passes over the body per
    #: asset for no gain.
    _segment_cache: list[tuple[Segment, str]] | None = field(default=None, repr=False)

    @property
    def approx_tokens(self) -> int:
        """Rough size, for a cost estimate shown before anything is sent."""
        return len(self.body) // 4

    def _segment_texts(self) -> list[tuple[Segment, str]]:
        if self._segment_cache is None:
            lines = self.body.split("\n")
            self._segment_cache = [
                (segment, "\n".join(lines[segment.first_line - 1 : segment.last_line]))
                for segment in self.segments
            ]
        return self._segment_cache

    def find(self, quote: str) -> bool:
        """Whether the quote genuinely appears inside one region of the payload.

        Matching ignores how whitespace is broken up. Exact substring matching
        looked right and was wrong: prose in a SKILL.md is hard-wrapped, so a
        sentence spanning two lines contains a newline the model does not reproduce
        when quoting it back, and every finding in wrapped text was rejected as
        fabricated. The first real run lost a true positive to it.

        Matching is confined to a single segment. Searching the concatenated body
        would let a quote straddle two different files, or a file and a separator
        Argus wrote, and still be called grounded — and the citation could then name
        only the first of them.
        """
        return self._match(quote) is not None

    def _match(self, quote: str) -> tuple[Segment, int] | None:
        """The segment containing the quote, and the 0-based line within it."""
        needle = normalise(quote)
        if not needle:
            return None
        for segment, text in self._segment_texts():
            offset = _find_normalised(text, needle)
            if offset >= 0:
                return segment, text.count("\n", 0, offset)
        return None

    def locate(self, quote: str) -> tuple[Path | None, int | None]:
        """Resolve a quote back to the file and line it came from.

        Never returns a line without a path: a bare ``:12`` in a report points the
        reader at nothing, and the reporters concatenate the two without checking.
        """
        found = self._match(quote)
        if found is None:
            return None, None
        segment, line_within = found
        if segment.path is None:
            return None, None
        if segment.source_line is None:
            return segment.path, self._line_in_source(quote, segment)
        return segment.path, segment.source_line + line_within

    def _line_in_source(self, quote: str, segment: Segment) -> int | None:
        """Find a quote directly in the asset's own file.

        The fallback for text that reaches the payload through a header Argus
        composed: a skill's ``description:`` is summarised into that header, but it
        is also a real line of a real file.

        Guarded on the segment naming the same file the verbatim text came from.
        Without that, a quote from a composed separator would be looked up in an
        unrelated file and could match coincidentally, producing a confident
        citation to a line that has nothing to do with the finding.
        """
        if not self.source_text or segment.path != self.source_path:
            return None
        offset = _find_normalised(self.source_text, normalise(quote))
        return None if offset < 0 else self.source_text.count("\n", 0, offset) + 1


def normalise(quote: str) -> str:
    """Collapse whitespace, so line wrapping cannot make a real quote look invented."""
    return " ".join(quote.split())


def _find_normalised(text: str, needle: str) -> int:
    """Offset in ``text`` of a whitespace-insensitive match, or -1.

    The offset list is what lets a match in the collapsed string be reported as a
    line in the real file, so ignoring whitespace does not cost the location.

    One implementation, used for both the payload and the asset's own file. It was
    written twice and the copies had already drifted — a later change to the
    matching rule would have been made once and silently missed the other.
    """
    if not needle:
        return -1
    collapsed: list[str] = []
    offsets: list[int] = []
    in_space = False
    for index, char in enumerate(text):
        if char.isspace():
            if not in_space and collapsed:
                collapsed.append(" ")
                offsets.append(index)
            in_space = True
            continue
        in_space = False
        collapsed.append(char)
        offsets.append(index)
    position = "".join(collapsed).find(needle)
    return offsets[position] if position >= 0 else -1


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
    #
    # Split on "\n" rather than with splitlines(): the latter also breaks on \r,
    # \x0b, \x0c, \x85, \u2028 and \u2029, so rejoining with "\n" turns each of
    # those into a real newline and shifts every line number after it. The segment
    # map is built before this runs, so the result would be a confidently wrong
    # file:line on any asset containing one — and read_text does not translate them.
    lines = text.split("\n")
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
            source_line=(int(data.get("body_offset") or 0) + 1)
            if asset.text_is_verbatim
            else None,
        )
        return "Claude Skill", body

    if asset.target is Target.INSTRUCTIONS:
        # Guarded rather than assumed: a line into text that was reconstructed
        # rather than read points at nothing the reader can open.
        body.add(
            asset.text or "",
            path=asset.path,
            source_line=1 if asset.text_is_verbatim else None,
        )
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
            # Not capped at MAX_FILE_CHARS. That cap exists to stop one file in a
            # multi-file asset crowding out the others; a hook has exactly one, so
            # applying it here just cut 4x of script out of review for no benefit.
            # The MAX_BODY_CHARS budget still bounds the whole payload.
            body.add(
                str(script),
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
        # Retained only for SKILLS, the one target whose composed header summarises
        # real lines of the file. Holding a second copy of every instruction file
        # and settings file for a fallback that never fires is pure memory.
        source_text=(
            asset.text
            if asset.target is Target.SKILLS and asset.text_is_verbatim
            else None
        ),
        source_path=asset.path,
    )
