"""Load and validate ``.argus`` rule files.

Validation is strict and every failure names the file, the field and what was
expected. A rule that silently does not do what its author meant is worse than one
that refuses to load: the first quietly reduces coverage, the second gets fixed.

Unknown keys are rejected rather than ignored. A typo like ``severty: high`` would
otherwise leave the rule at its default severity forever.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core.exceptions import ArgusError
from ..core.models import Category, Severity, Target
from ..core.safe_io import iter_files, read_yaml
from .model import (
    COMBINATORS,
    MAX_REGEX_LENGTH,
    OPERATORS,
    Condition,
    Rule,
    RuleMatch,
)

RULE_SUFFIX = ".argus"

TOP_LEVEL_KEYS = {
    "id", "name", "severity", "target", "category", "match",
    "description", "remediation", "references", "tags",
}

#: A rule filed under the category matching its target lands alongside the built-in
#: checks for that domain, so ``--category skills`` picks up your Skill rules too.
#: ``ide`` has no corresponding category, so it falls back to ``custom``.
TARGET_CATEGORY: dict[Target, Category] = {
    Target.CLAUDE_CODE: Category.CLAUDE,
    Target.CLAUDE_DESKTOP: Category.CLAUDE,
    Target.MCP: Category.MCP,
    Target.SKILLS: Category.SKILLS,
    Target.PLUGINS: Category.PLUGINS,
    Target.HOOKS: Category.HOOKS,
    Target.INSTRUCTIONS: Category.INSTRUCTIONS,
    Target.FILESYSTEM: Category.FILESYSTEM,
    Target.IDE: Category.CUSTOM,
}
REQUIRED_KEYS = {"id", "name", "severity", "target", "match"}
CONDITION_KEYS = {"field", "text", "ignore_case", *OPERATORS}

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$", re.I)


class RuleError(ArgusError):
    """A rule file is malformed. Always names the file and the problem."""


def _fail(path: Path | str, message: str) -> None:
    raise RuleError(f"{path}: {message}")


def _parse_condition(raw: object, path: Path | str) -> Condition:
    if not isinstance(raw, dict):
        _fail(path, "each match condition must be a mapping")
    assert isinstance(raw, dict)

    unknown = set(raw) - CONDITION_KEYS
    if unknown:
        _fail(path, f"unknown condition key(s): {', '.join(sorted(unknown))}")

    has_field, has_text = "field" in raw, "text" in raw
    if has_field == has_text:
        _fail(path, "each condition needs exactly one of 'field' or 'text'")

    source = "field" if has_field else "text"
    field_path = str(raw["field"]) if has_field else None

    operators = [op for op in OPERATORS if op in raw]
    if len(operators) != 1:
        _fail(
            path,
            "each condition needs exactly one operator "
            f"({', '.join(OPERATORS)}); found {len(operators)}",
        )
    operator = operators[0]
    value = "" if operator in ("exists", "not_exists") else str(raw[operator])

    compiled = None
    if operator in ("regex", "not_regex"):
        if len(value) > MAX_REGEX_LENGTH:
            _fail(path, f"regex exceeds {MAX_REGEX_LENGTH} characters")
        try:
            compiled = re.compile(value, re.IGNORECASE if raw.get("ignore_case", True) else 0)
        except re.error as exc:
            _fail(path, f"invalid regex {value!r}: {exc}")

    return Condition(
        source=source,
        operator=operator,
        value=value,
        path=field_path,
        ignore_case=bool(raw.get("ignore_case", True)),
        _compiled=compiled,
    )


def _parse_match(raw: object, path: Path | str) -> RuleMatch:
    if not isinstance(raw, dict):
        _fail(path, "'match' must be a mapping with one of: " + ", ".join(COMBINATORS))
    assert isinstance(raw, dict)

    present = [c for c in COMBINATORS if c in raw]
    unknown = set(raw) - set(COMBINATORS)
    if unknown:
        _fail(path, f"unknown key(s) in 'match': {', '.join(sorted(unknown))}")
    if len(present) != 1:
        _fail(path, f"'match' needs exactly one of: {', '.join(COMBINATORS)}")

    combinator = present[0]
    conditions = raw[combinator]
    if not isinstance(conditions, list) or not conditions:
        _fail(path, f"'match.{combinator}' must be a non-empty list")
    assert isinstance(conditions, list)

    return RuleMatch(
        combinator=combinator,
        conditions=tuple(_parse_condition(c, path) for c in conditions),
    )


def parse_rule(data: object, source_path: Path | str = "<inline>") -> Rule:
    """Validate a parsed YAML document into a :class:`Rule`."""
    if not isinstance(data, dict):
        _fail(source_path, "a rule file must contain a YAML mapping")
    assert isinstance(data, dict)

    unknown = set(data) - TOP_LEVEL_KEYS
    if unknown:
        _fail(source_path, f"unknown key(s): {', '.join(sorted(unknown))}")
    missing = REQUIRED_KEYS - set(data)
    if missing:
        _fail(source_path, f"missing required key(s): {', '.join(sorted(missing))}")

    rule_id = str(data["id"]).strip()
    if not _ID_PATTERN.match(rule_id):
        _fail(source_path, f"id {rule_id!r} must be 2-64 chars of letters, digits, . _ or -")

    try:
        severity = Severity.parse(str(data["severity"]))
    except ValueError as exc:
        _fail(source_path, str(exc))
    try:
        target = Target.parse(str(data["target"]))
    except ValueError as exc:
        _fail(source_path, str(exc))

    # Defaults to the category matching the target so a rule files itself sensibly;
    # set 'category: custom' to keep it out of the built-in domains.
    if data.get("category"):
        try:
            category = Category.parse(str(data["category"]))
        except ValueError as exc:
            _fail(source_path, str(exc))
    else:
        category = TARGET_CATEGORY.get(target, Category.CUSTOM)

    def string_list(key: str) -> tuple[str, ...]:
        raw = data.get(key) or []
        if isinstance(raw, str):
            return (raw,)
        if not isinstance(raw, list):
            _fail(source_path, f"'{key}' must be a list of strings")
        return tuple(str(v) for v in raw)

    return Rule(
        rule_id=rule_id,
        name=str(data["name"]).strip(),
        severity=severity,
        target=target,
        category=category,
        match=_parse_match(data["match"], source_path),
        description=str(data.get("description") or "").strip(),
        remediation=str(data.get("remediation") or "").strip(),
        references=string_list("references"),
        tags=string_list("tags"),
        source_path=str(source_path),
    )


def load_rule_file(path: Path) -> Rule:
    """Load a single ``.argus`` file."""
    data = read_yaml(path)
    if data is None:
        _fail(path, "not valid YAML")
    return parse_rule(data, path)


def load_rules(paths: list[Path]) -> tuple[list[Rule], list[str]]:
    """Load rules from files and directories.

    Returns the rules that loaded plus any errors. One broken rule does not stop
    the others — but it is reported, never silently dropped.
    """
    rules: list[Rule] = []
    errors: list[str] = []
    seen: dict[str, str] = {}

    candidates: list[Path] = []
    for entry in paths:
        if entry.is_dir():
            candidates.extend(sorted(iter_files(entry, suffixes=(RULE_SUFFIX,), max_depth=4)))
        elif entry.is_file():
            candidates.append(entry)
        else:
            errors.append(f"{entry}: no such file or directory")

    for path in candidates:
        try:
            rule = load_rule_file(path)
        except RuleError as exc:
            errors.append(str(exc))
            continue
        if rule.rule_id in seen:
            errors.append(f"{path}: duplicate rule id '{rule.rule_id}' (also in {seen[rule.rule_id]})")
            continue
        seen[rule.rule_id] = str(path)
        rules.append(rule)

    return rules, errors
