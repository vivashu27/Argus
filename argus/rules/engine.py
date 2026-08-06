"""Evaluate rules against discovered assets.

Rules are deterministic, so unlike an advisory reviewer their findings are real:
they count toward the score and gate the exit code exactly like a built-in check.
That is the whole point of writing one.

Field lookup understands dotted paths and walks into lists, so ``args`` matches if
any argument matches. That behaviour is what a rule author expects when they write
``field: args / contains: npx`` for a server whose args are a list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..analysis.redaction import truncate
from ..core.models import (
    Asset,
    CheckMeta,
    Confidence,
    Evidence,
    Finding,
    Status,
)
from .model import MAX_MATCH_INPUT, Condition, Rule


@dataclass(frozen=True)
class _Value:
    """One string a condition can be tested against, and where it came from.

    ``origin`` is the nested record the value was read out of, when that record
    carries its own provenance. An MCP server's ``tools`` are recovered from source
    files, so a match in ``tools.description`` belongs to a line of a ``.py`` or
    ``.js`` file — not to the ``.mcp.json`` that merely names the server.
    """

    text: str
    origin: dict[str, Any] | None = None


def _flatten(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        return [s for item in value for s in _flatten(item)]
    if isinstance(value, dict):
        return [f"{k}={v}" for k, v in value.items()]
    return [str(value)]


def _lookup(asset: Asset, path: str) -> list[_Value]:
    """Resolve a dotted field path to the string values it names, with provenance.

    Returns every value found, because a list field should match if any element
    matches. An empty list means the field is absent.
    """
    # (value, record it came from). Provenance is only taken from list elements:
    # those are the discovered sub-records, whereas the top level is the asset itself.
    entries: list[tuple[Any, dict[str, Any] | None]] = [(asset.data, None)]

    for part in path.split("."):
        following: list[tuple[Any, dict[str, Any] | None]] = []
        for value, origin in entries:
            if isinstance(value, dict):
                if part in value:
                    following.append((value[part], origin))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and part in item:
                        following.append((item[part], item if "path" in item else origin))
        if not following:
            return []
        entries = following

    return [_Value(text, origin) for value, origin in entries for text in _flatten(value)]


def _values_for(asset: Asset, condition: Condition) -> list[_Value]:
    if condition.source == "text":
        return [_Value((asset.text or "")[:MAX_MATCH_INPUT])]
    return [
        _Value(v.text[:MAX_MATCH_INPUT], v.origin)
        for v in _lookup(asset, condition.path or "")
    ]


#: Characters of context to show either side of the matched text.
SNIPPET_CONTEXT = 70


def _match_span(condition: Condition, value: str) -> tuple[int, int] | None:
    """Where inside ``value`` the condition matched, when that is a real span.

    Negative and presence operators match by the *absence* of something, so there is
    no span to point at and this returns None.
    """
    if condition.operator == "regex":
        found = condition._compiled.search(value)  # type: ignore[union-attr]
        return found.span() if found else None
    if condition.operator in ("contains", "equals"):
        haystack, needle = value, condition.value
        if condition.ignore_case:
            haystack, needle = haystack.lower(), needle.lower()
        start = haystack.find(needle)
        return (start, start + len(needle)) if start >= 0 else None
    return None


def _locate(asset: Asset, value: str, span: tuple[int, int] | None) -> int | None:
    """The 1-based line in ``asset.path`` where the match sits, if that is knowable.

    With no span — a negative operator matches by absence, so there is nothing to
    point at — this falls back to where the field itself begins, which is still a
    real position and still tells the reader what was read.

    Requires the asset's text to be the file byte for byte. Where it is synthesised
    for the analyzers — a re-serialised MCP config, a hook's command joined to its
    script — an offset into it points at nothing the reader can open, so no line is
    reported rather than a plausible wrong one.
    """
    if not asset.text_is_verbatim or not asset.text:
        return None
    base = asset.text.find(value)
    if base < 0:
        # A derived value (a dict rendered ``k=v``, a normalised list element) need
        # not appear in the file at all.
        return None
    return asset.text.count("\n", 0, base + (span[0] if span else 0)) + 1


def _locate_in_record(
    origin: dict[str, Any], condition: Condition, value: str, span: tuple[int, int] | None
) -> int | None:
    """The line of the match inside the record's own file.

    A record may publish a starting line per field as ``<field>_line`` — a tool's
    ``description_line`` is where its docstring begins, which is several lines below
    the ``line`` where the definition starts. Offsets into the value map onto the file
    from there, so a directive buried after a long ``Args:`` block resolves to its
    real line rather than to the top of the function.
    """
    field = (condition.path or "").rsplit(".", 1)[-1]
    base = origin.get(f"{field}_line") or origin.get("line")
    if not isinstance(base, int) or base <= 0:
        return None
    return base + (value[: span[0]].count("\n") if span else 0)


def _snippet(value: str, span: tuple[int, int] | None) -> str:
    """The matched text with surrounding context, rather than the head of the field.

    A rule matching at line 400 of a Skill was previously evidenced by the first 160
    characters of its body, which showed the reader nothing about why it fired.
    """
    if span is None:
        return truncate(value, 160)
    start = max(0, span[0] - SNIPPET_CONTEXT)
    end = min(len(value), span[1] + SNIPPET_CONTEXT)
    # truncate() also collapses whitespace, which keeps a snippet on one line and
    # bounds what a hostile file can push into a report.
    window = truncate(value[start:end], 160)
    return ("…" if start > 0 else "") + window + ("…" if end < len(value) else "")


def _test(condition: Condition, values: list[str]) -> bool:
    """Evaluate one condition. Negative operators are handled by the caller's
    combinator only for presence; the negation itself is applied here."""
    if condition.operator == "exists":
        return bool(values)
    if condition.operator == "not_exists":
        return not values

    if not values:
        # A field that is absent cannot contain anything, but it also does not
        # *contain* the value, so a negative operator is satisfied.
        return condition.is_negative

    needle = condition.value
    if condition.ignore_case and condition.operator in ("contains", "not_contains", "equals"):
        values = [v.lower() for v in values]
        needle = needle.lower()

    if condition.operator == "contains":
        return any(needle in v for v in values)
    if condition.operator == "not_contains":
        return all(needle not in v for v in values)
    if condition.operator == "equals":
        return any(v == needle for v in values)
    if condition.operator == "regex":
        return any(condition._compiled.search(v) for v in values)  # type: ignore[union-attr]
    if condition.operator == "not_regex":
        return all(not condition._compiled.search(v) for v in values)  # type: ignore[union-attr]
    return False


def evaluate_rule(rule: Rule, asset: Asset) -> tuple[bool, list[Evidence]]:
    """Test one rule against one asset. Returns ``(matched, evidence)``."""
    results: list[bool] = []
    evidence: list[Evidence] = []

    for condition in rule.match.conditions:
        values = _values_for(asset, condition)
        matched = _test(condition, [v.text for v in values])
        results.append(matched)
        if matched and values:
            # Point at the value that actually matched, not simply the first one:
            # a rule on a list field should evidence the element that fired.
            hit, span = next(
                (
                    (v, s)
                    for v in values
                    if (s := _match_span(condition, v.text)) is not None
                ),
                (values[0], None),
            )
            # A value read out of a record that carries its own path belongs to that
            # file, not to the config that merely referenced it: a match in an MCP
            # tool description is a line of the server's source, not of .mcp.json.
            if hit.origin and hit.origin.get("path"):
                where = str(hit.origin["path"])
                line = _locate_in_record(hit.origin, condition, hit.text, span)
            else:
                where = str(asset.path) if asset.path else asset.source
                line = _locate(asset, hit.text, span)
            evidence.append(
                Evidence(
                    path=where,
                    line=line,
                    key=condition.path if condition.source == "field" else "text",
                    snippet=_snippet(hit.text, span),
                    reason=f"matched: {condition.describe()}",
                )
            )

    if rule.match.combinator == "all":
        return all(results), evidence
    if rule.match.combinator == "any":
        return any(results), evidence
    return not any(results), []  # "none": no evidence, since nothing matched


def _meta_for(rule: Rule) -> CheckMeta:
    return CheckMeta(
        check_id=rule.check_id,
        title=rule.name,
        description=rule.description or f"Custom rule '{rule.rule_id}'.",
        category=rule.category,
        severity=rule.severity,
        aasb_level=2,
        applies_to=frozenset({rule.target}),
        rationale=f"Defined by custom rule {rule.rule_id} in {rule.source_path}.",
        security_impact=rule.description,
        remediation=rule.remediation or "Review the matched asset against your policy.",
        references=rule.references,
    )


def run_rules(rules: list[Rule], assets: list[Asset]) -> list[Finding]:
    """Evaluate every rule against every applicable asset.

    A rule that raises is reported as an ERROR finding rather than aborting the
    scan, matching how the engine treats a built-in check.
    """
    findings: list[Finding] = []

    for rule in rules:
        meta = _meta_for(rule)
        applicable = [a for a in assets if a.target is rule.target]

        if not applicable:
            findings.append(
                Finding(
                    meta=meta,
                    status=Status.NOT_APPLICABLE,
                    asset="-",
                    detail=f"No '{rule.target.value}' assets discovered",
                    na_reason=f"No '{rule.target.value}' assets discovered",
                )
            )
            continue

        matched_any = False
        for asset in applicable:
            try:
                matched, evidence = evaluate_rule(rule, asset)
            except Exception as exc:  # a bad rule must not kill the scan
                findings.append(
                    Finding(
                        meta=meta,
                        status=Status.ERROR,
                        asset=asset.asset_id,
                        detail=f"Rule '{rule.rule_id}' raised {type(exc).__name__}: {exc}",
                        confidence=Confidence.LOW,
                    )
                )
                matched_any = True
                continue
            if matched:
                matched_any = True
                findings.append(
                    Finding(
                        meta=meta,
                        status=Status.FAIL,
                        asset=asset.asset_id,
                        detail=rule.name,
                        evidence=evidence,
                        confidence=Confidence.HIGH,
                    )
                )

        if not matched_any:
            findings.append(
                Finding(
                    meta=meta,
                    status=Status.PASS,
                    asset=rule.target.value,
                    detail=f"No {rule.target.value} asset matched rule '{rule.rule_id}'.",
                )
            )

    return findings
