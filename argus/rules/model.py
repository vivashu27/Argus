"""The ``.argus`` rule schema.

Kept deliberately small. Every operator here earns its place by expressing
something the existing checks actually needed; there is no speculative surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..core.models import Category, Severity, Target

#: Operators a condition may use. Exactly one per condition.
OPERATORS = ("contains", "not_contains", "equals", "regex", "not_regex", "exists", "not_exists")

#: Combinators a match block may use.
COMBINATORS = ("all", "any", "none")

#: Where a condition looks. ``field`` reads a named value from the asset's parsed
#: data; ``text`` searches the asset's raw text.
SOURCES = ("field", "text")

#: Fields each target's assets actually carry, taken from the discovery modules.
#: Used to catch the most common way a rule goes wrong: a valid schema pointed at a
#: field the target does not have, which validates cleanly and then never matches.
TARGET_FIELDS: dict[Target, frozenset[str]] = {
    Target.MCP: frozenset(
        {"name", "command", "args", "env", "url", "transport", "scope", "raw", "code", "tools"}
    ),
    Target.SKILLS: frozenset(
        {"name", "scope", "directory", "frontmatter", "allowed_tools", "body", "scripts"}
    ),
    Target.PLUGINS: frozenset(
        {"name", "marketplace", "trust", "trust_reason", "directory", "manifest", "files",
         "mcp", "has_hooks"}
    ),
    Target.HOOKS: frozenset(
        {"event", "matcher", "command", "type", "timeout", "scope", "script_path", "script_text"}
    ),
    Target.CLAUDE_CODE: frozenset(
        {"settings", "scope", "malformed", "projects", "install_method", "auto_updates", "kind"}
    ),
    Target.CLAUDE_DESKTOP: frozenset({"config", "preferences", "mcp_server_names", "malformed"}),
    Target.INSTRUCTIONS: frozenset({"scope", "name", "lines"}),
    Target.FILESYSTEM: frozenset(
        {"kind", "mode", "readable", "is_symlink", "sensitive", "category", "description",
         "private_keys", "escaping", "variables"}
    ),
    Target.IDE: frozenset({"editor", "extension_count", "extensions", "agent_extensions", "settings"}),
}

#: Rules are authored by humans and shared between machines, so a regex from a rule
#: file is only as trustworthy as its author. Bounding its length is a cheap guard
#: against a pathological pattern; input length is bounded separately at match time.
MAX_REGEX_LENGTH = 500
MAX_MATCH_INPUT = 20_000


@dataclass(frozen=True)
class Condition:
    """One test against one part of an asset."""

    source: str  # "field" | "text"
    operator: str
    value: str
    path: str | None = None  # required for source == "field"
    ignore_case: bool = True
    _compiled: re.Pattern[str] | None = field(default=None, compare=False)

    @property
    def is_negative(self) -> bool:
        return self.operator.startswith("not_")

    def describe(self) -> str:
        where = f"{self.path}" if self.source == "field" else "text"
        if self.operator in ("exists", "not_exists"):
            return f"{where} {self.operator.replace('_', ' ')}"
        return f"{where} {self.operator.replace('_', ' ')} {self.value!r}"


@dataclass(frozen=True)
class RuleMatch:
    """A match block: a combinator over conditions."""

    combinator: str  # all | any | none
    conditions: tuple[Condition, ...]


@dataclass(frozen=True)
class Rule:
    """A loaded, validated custom rule."""

    rule_id: str
    name: str
    severity: Severity
    target: Target
    category: Category
    match: RuleMatch
    description: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source_path: str = ""

    @property
    def check_id(self) -> str:
        """Findings namespace custom rules so they cannot collide with AASB IDs."""
        return f"CUSTOM-{self.rule_id.upper()}"

    def unknown_fields(self) -> list[str]:
        """Fields this rule reads that its target does not provide.

        Only the first path segment is checked, so dotted paths into a nested
        structure (``settings.permissions.allow``) validate on ``settings``.
        """
        known = TARGET_FIELDS.get(self.target, frozenset())
        if not known:
            return []
        return sorted(
            {
                c.path.split(".")[0]
                for c in self.match.conditions
                if c.source == "field" and c.path and c.path.split(".")[0] not in known
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value.lower(),
            "target": self.target.value,
            "category": self.category.value,
            "description": self.description,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "source": self.source_path,
        }
