"""Static recovery and analysis of MCP tool definitions.

A tool's description is not documentation. It is fed to the model as context, which
makes it an instruction channel that the user rarely sees rendered. That is the whole
basis of tool poisoning: text placed in a description reaches the model with the
authority of the tool list, while a human reviewing the server sees a helpful sentence
about what the tool does — or, with concealed characters, sees nothing at all.

**Argus never runs a server, so it cannot call ``tools/list``.** Definitions are
recovered from source instead, which is best-effort by construction: a server that
builds its tool list dynamically will yield fewer tools than it exposes. Checks report
what was recovered so a partial extraction is never mistaken for a clean result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .redaction import truncate

MAX_DESCRIPTION = 4000

# --- extraction -----------------------------------------------------------------

#: ``@mcp.tool()`` / ``@server.tool(...)`` followed by the function it decorates. The
#: docstring becomes the description, which is exactly how the Python SDK builds it.
#: Resources and prompts are matched too: their descriptions reach the model through
#: the same channel, so a directive in one is worth exactly as much to an attacker.
_PY_DECORATED = re.compile(
    r"@(?P<obj>\w+)\.(?P<kind>tool|resource|prompt)\s*\((?P<dargs>[^)]{0,400})\)\s*"
    r"(?:@[\w.]+\s*(?:\([^)]{0,200}\))?\s*)*"
    r"(?:async\s+)?def\s+(?P<func>\w+)\s*\([^)]{0,2000}\)[^:]{0,200}:\s*"
    r'(?:(?P<q>"""|\'\'\')(?P<doc>.{0,4000}?)(?P=q))?',
    re.S,
)

#: A ``name=``/``description=`` (Python) or ``name:``/``description:`` (JS object
#: literal) pair. One expression covers both because the shapes differ only in the
#: separator, and both SDKs put the two within a few lines of each other.
_NAME_DESC = re.compile(
    r"""["']?\bname["']?\s*[:=]\s*(?P<nq>["'`])(?P<name>[^"'`\n]{1,80})(?P=nq)"""
    r"""(?:.{0,400}?)"""
    r"""["']?\bdescription["']?\s*[:=]\s*(?P<dq>\"\"\"|'''|["'`])(?P<desc>.{0,4000}?)(?P=dq)""",
    re.S,
)

#: ``server.tool("name", "description", schema, handler)`` — the positional form used
#: by the TypeScript SDK's high-level helper.
_JS_POSITIONAL = re.compile(
    r"\.(?:tool|resource|prompt|registerTool|registerResource|registerPrompt)\s*\(\s*(?P<nq>[\"'`])(?P<name>[^\"'`\n]{1,80})(?P=nq)\s*,\s*"
    r"(?P<dq>[\"'`])(?P<desc>.{0,4000}?)(?P=dq)",
    re.S,
)


@dataclass(frozen=True)
class ToolDef:
    """One tool definition recovered from source."""

    name: str
    description: str
    path: Path
    line: int
    how: str
    #: Line where the description text itself begins, which for a decorated function
    #: is the docstring rather than the decorator. Offsets into ``description`` map
    #: onto the file from here, so a match deep in a long docstring resolves to its
    #: real line. Falls back to ``line`` when the shape does not expose one.
    description_line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            # The description is carried whole, not display-truncated. This dict is
            # what the poisoning checks and custom rules actually read, and a payload
            # placed after a realistic Args:/Returns: block sits well past any short
            # display cap — truncating here would put it outside the analysis window
            # and silently hide exactly the case worth catching. Whitespace is left
            # intact too, since a long blank run is itself a signal. Report size is
            # bounded where it matters, at the evidence snippet.
            "description": self.description,
            "path": str(self.path),
            "line": self.line,
            # ``<field>_line`` is the convention the rule engine looks for when
            # attributing a match inside this record to a line of its own file.
            "description_line": self.description_line or self.line,
            "how": self.how,
        }


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _clean_docstring(doc: str) -> str:
    return doc.strip()


def extract_tools(path: Path, text: str) -> list[ToolDef]:
    """Recover tool definitions from one source file.

    Duplicates are collapsed on ``(name, line)``: the same definition often matches
    more than one shape, and reporting it twice would overstate the tool surface.
    """
    found: dict[tuple[str, int], ToolDef] = {}

    def add(
        name: str, description: str, offset: int, how: str, desc_offset: int | None = None
    ) -> None:
        name = name.strip()
        if not name or len(name) > 80:
            return
        line = _line_of(text, offset)
        key = (name, line)
        existing = found.get(key)
        # Prefer whichever shape recovered an actual description.
        if existing is None or (not existing.description and description):
            found[key] = ToolDef(
                name=name,
                description=description[:MAX_DESCRIPTION],
                path=path,
                line=line,
                how=how,
                description_line=_line_of(text, desc_offset) if desc_offset is not None else line,
            )

    is_python = path.suffix.lower() == ".py"

    if is_python:
        for match in _PY_DECORATED.finditer(text):
            args = match.group("dargs") or ""
            named = re.search(r"""name\s*=\s*(["'])(?P<v>[^"']{1,80})\1""", args)
            described = re.search(
                r"""description\s*=\s*(?P<q>\"\"\"|'''|["'])(?P<v>.{0,4000}?)(?P=q)""", args, re.S
            )
            raw_doc = match.group("doc")
            desc_offset: int | None
            if described:
                description = described.group("v")
                desc_offset = match.start("dargs") + described.start("v")
            else:
                description = _clean_docstring(raw_doc or "")
                # strip() removes leading blank lines, so shift past them to keep an
                # offset into `description` an offset into the file.
                desc_offset = (
                    match.start("doc") + (len(raw_doc) - len(raw_doc.lstrip()))
                    if raw_doc is not None
                    else None
                )
            add(
                named.group("v") if named else match.group("func"),
                description,
                match.start(),
                "python decorator",
                desc_offset,
            )
    else:
        for match in _JS_POSITIONAL.finditer(text):
            add(
                match.group("name"), match.group("desc"), match.start(), "sdk call",
                match.start("desc"),
            )

    # Applies to both languages: ``Tool(name=..., description=...)`` in Python and a
    # ``{ name, description }`` literal in a JS tool list.
    for match in _NAME_DESC.finditer(text):
        add(
            match.group("name"), match.group("desc"), match.start(), "definition literal",
            match.start("desc"),
        )

    return sorted(found.values(), key=lambda t: (t.line, t.name))


# --- poisoning ------------------------------------------------------------------


class Tier(str, Enum):
    """How much weight one signal carries on its own."""

    #: Unambiguous on sight: an instruction to the model that no description needs.
    A = "A"
    #: Suspicious, but a legitimate description could contain it. Needs corroboration.
    B = "B"
    #: Context only. Never a finding by itself.
    C = "C"


@dataclass(frozen=True)
class PoisonMatch:
    pattern_id: str
    tier: Tier
    description: str
    excerpt: str
    offset: int


#: Tier A — text that only makes sense as an instruction aimed at the model. A tool
#: description is read by the model but written for a human; concealment directives
#: and instruction overrides have no legitimate reason to appear in one.
_TIER_A: tuple[tuple[str, str, str], ...] = (
    ("hidden-instruction-tag", r"<\s*/?\s*(IMPORTANT|SYSTEM(_INSTRUCTION)?|SECRET|HIDDEN|INTERNAL)\s*>",
     "Instruction-style tag inside a tool description"),
    ("templated-system-turn", r"\{\{\s*system\b|\{\%\s*system\b|\[\s*system\s*\]|<\|\s*system\s*\|>",
     "Description forges a system turn"),
    ("conceal-from-user", r"(do\s*not|don'?t|never|without)\s+(\w+\s+){0,3}(tell|telling|inform|informing|mention|mentioning|show|showing|reveal|revealing|disclose|disclosing)\s+(this\s+|it\s+|that\s+)?(to\s+)?(the\s+)?user",
     "Description instructs the model to hide an action from the user"),
    ("instruction-override", r"(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(previous|prior|earlier|above|the\s+system)\s+(instruction|prompt|rule|direction)",
     "Description attempts to override prior instructions"),
    ("do-not-describe", r"do\s*not\s+(describe|explain|summar[iy]|report)\s+(this|the\s+above|what)",
     "Description tells the model not to explain its own behaviour"),
    ("scare-the-user", r"(scare|alarm|worry|upset)\s+(the\s+)?(user|them)",
     "Description rationalises concealment from the user"),
)

#: Tier B — a description that names a credential path, or tells the model to route
#: data somewhere. Real descriptions occasionally mention a config file, so these
#: corroborate rather than convict on their own.
_TIER_B: tuple[tuple[str, str, str], ...] = (
    ("credential-path", r"(~|\$HOME|/home/[\w.-]+|/Users/[\w.-]+)?/?\.(ssh|aws|gnupg|config/gcloud|kube|docker)\b|\bid_rsa\b|\bcredentials\b\s*file|\.env\b|/etc/(passwd|shadow)",
     "Description references a credential or secret location"),
    ("side-channel", r"(pass|send|include|append|put|attach|copy)\s+(the\s+|its\s+|it\s+)?(content|contents|result|results|output|value|data|file)s?\s+(as|to|in|into)\s+(the\s+)?(sidenote|side_note|metadata|note|notes|extra|comment|hidden|context|debug)",
     "Description routes data into an unrelated parameter"),
    ("exfil-verb", r"(upload|exfiltrat|post|transmit|forward)\w*\s+(it|them|the\s+\w+)?\s*(to|→)\s*(https?://|\w+@|[\w.-]+\.\w{2,})",
     "Description sends data to an external destination"),
    ("read-then-call", r"(before|prior to)\s+(using|calling|invoking|running)\s+(this|the)\s+tool[^.]{0,120}\b(read|open|cat|load|fetch|retrieve)\b",
     "Description requires a read before the tool may be used"),
)

#: Tier C — imperative voice aimed at the assistant. Extremely common in legitimate
#: descriptions ("Use this when the user asks about weather"), so this only ever
#: corroborates a Tier B signal.
_TIER_C: tuple[tuple[str, str, str], ...] = (
    ("assistant-imperative", r"\byou\s+(must|should|shall|will|need\s+to|have\s+to)\b|\balways\s+(call|use|read|include|append)\b",
     "Description issues a directive to the assistant"),
    ("required-or-fails", r"(will\s+not|won'?t|cannot|can'?t|does\s*not)\s+work\s+(without|unless)|is\s+(required|mandatory)\s+for\s+(this|the)\s+tool",
     "Description claims the tool fails without an extra step"),
)

_COMPILED: tuple[tuple[str, Tier, str, re.Pattern[str]], ...] = tuple(
    (pattern_id, tier, description, re.compile(expression, re.I))
    for tier, group in ((Tier.A, _TIER_A), (Tier.B, _TIER_B), (Tier.C, _TIER_C))
    for pattern_id, expression, description in group
)


def scan_description(text: str) -> list[PoisonMatch]:
    """Every poisoning signal in one tool description."""
    if not text:
        return []
    window = text[:MAX_DESCRIPTION]
    matches: list[PoisonMatch] = []
    for pattern_id, tier, description, expression in _COMPILED:
        found = expression.search(window)
        if found:
            start = max(0, found.start() - 40)
            matches.append(
                PoisonMatch(
                    pattern_id=pattern_id,
                    tier=tier,
                    description=description,
                    excerpt=truncate(window[start : found.end() + 60], 180),
                    offset=found.start(),
                )
            )
    return matches


def is_poisoned(matches: list[PoisonMatch]) -> bool:
    """Whether the signals justify asserting a finding.

    One Tier A signal is enough. Otherwise a Tier B signal must be corroborated by a
    second signal, which keeps a description that merely names a config file from
    being reported as an attack.
    """
    tiers = [m.tier for m in matches]
    if Tier.A in tiers:
        return True
    return Tier.B in tiers and len(matches) >= 2


# --- concealed characters -------------------------------------------------------

#: Characters that carry payload without rendering. The Unicode tag block is the one
#: that matters most: U+E0000-U+E007F mirrors ASCII, so an entire instruction can be
#: written in characters that no terminal or review UI displays.
#: Written as escapes, never as literals: a pattern built from invisible characters
#: would be unreviewable in its own source, which is the exact problem it detects.
_CONCEALED: tuple[tuple[str, str, str], ...] = (
    ("zero-width", "[\u200b\u200c\u200d\u2060\ufeff]", "Zero-width character"),
    ("unicode-tags", "[\U000e0000-\U000e007f]", "Unicode tag character (invisible ASCII)"),
    ("bidi-override", "[\u202a-\u202e\u2066-\u2069]", "Bidirectional override"),
    ("ansi-escape", r"\x1b\[[0-9;]*[a-zA-Z]", "ANSI terminal escape"),
    ("private-use", "[\ue000-\uf8ff]", "Private-use character"),
)

_CONCEALED_COMPILED = tuple((k, re.compile(p), d) for k, p, d in _CONCEALED)

#: A long run of blank lines pushes text below whatever a review UI shows.
_WHITESPACE_CURTAIN = re.compile(r"\n{6,}|[ \t]{80,}")


@dataclass(frozen=True)
class ConcealedMatch:
    kind: str
    description: str
    count: int
    codepoints: str


def concealed_characters(text: str) -> list[ConcealedMatch]:
    """Non-rendering content in a description, which a human reviewer cannot see."""
    if not text:
        return []
    out: list[ConcealedMatch] = []
    for kind, expression, description in _CONCEALED_COMPILED:
        hits = expression.findall(text)
        if hits:
            points = sorted({f"U+{ord(h[0]):04X}" for h in hits if h})[:6]
            out.append(
                ConcealedMatch(
                    kind=kind,
                    description=description,
                    count=len(hits),
                    codepoints=", ".join(points),
                )
            )
    if _WHITESPACE_CURTAIN.search(text):
        out.append(
            ConcealedMatch(
                kind="whitespace-curtain",
                description="Long blank run hiding text below the visible area",
                count=1,
                codepoints="",
            )
        )
    return out
