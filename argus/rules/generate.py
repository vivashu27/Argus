"""Generate a ``.argus`` rule from a natural-language prompt.

This is the only part of Argus that uses the network, and what it sends is worth
being precise about: **your prompt and the rule schema, and nothing else.** No
scanned configuration, no file contents, no hostname, no paths. Argus does not even
need to have run a scan.

That distinction is what makes this safe in a way that an AI *reviewer* is not. The
model produces a rule, which is data you read, edit and commit. It never produces a
verdict. If it writes a bad rule you will see it in the diff, and if it writes an
invalid one the schema validator rejects it before it is written to disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.models import Severity, Target
from .loader import RuleError, parse_rule
from .model import COMBINATORS, MAX_REGEX_LENGTH, OPERATORS, TARGET_FIELDS, Rule
from .providers import LLMError, build_provider

SYSTEM = f"""\
You write security rules for Argus, an AI-agent configuration auditor. You output a
single YAML document and nothing else: no prose, no explanation, no code fences.

Schema — these keys and no others:

  id:          lowercase slug, 2-64 chars, letters/digits/dot/underscore/hyphen
  name:        one-line description of what the rule detects
  severity:    one of {' | '.join(s.value.lower() for s in Severity)}
  target:      one of {' | '.join(t.value for t in Target)}
  match:       exactly one of: {', '.join(COMBINATORS)}
               each is a list of conditions
  description: optional, why this matters
  remediation: optional, what the operator should change
  tags:        optional list of strings
  references:  optional list of URLs

A condition has exactly one of 'field' or 'text'.

'field' reads a named value from the asset's parsed data using a dotted path, and
takes exactly one operator from: {', '.join(OPERATORS)}

    - field: command
      contains: npx

'text' searches the asset's raw text. Write it in one of exactly these two forms:

    - text: some phrase          # shorthand: raw text contains "some phrase"

    - text: true                 # explicit: any operator, on the raw text
      regex: 'some|pattern'

Never combine a quoted 'text' value with an operator — pick one form or the other.

Hard limits, enforced by the validator:
  - a regex must be at most {MAX_REGEX_LENGTH} characters. If one alternation would
    exceed that, split it across several conditions under 'any'.
  - 'id' must match ^[a-z0-9][a-z0-9._-]{{1,63}}$

Fields available per target:
{chr(10).join(f"  {t.value:14} {', '.join(sorted(f))}" for t, f in TARGET_FIELDS.items())}

Fields whose names do not say what they hold:

  mcp.tools        list of the server's recovered tool definitions. Use
                   'tools.description' to search what the model is told about each
                   tool — that is where tool poisoning lives.
  mcp.code         where the server's code was resolved to (root, resolved,
                   package_spec, unpinned). NOT the source text.
  mcp.raw          the server's entry in .mcp.json exactly as written.
  skills.body      the Skill's markdown body, after the frontmatter.
  hooks.script_text  the contents of a hook's resolved script.
  claude-code.settings  the parsed settings file; use dotted paths such as
                   'settings.permissions.allow'.

Write the narrowest rule that expresses the request. Prefer a specific field over a
text search. Do not invent fields that are not listed above.
"""

EXAMPLE = """\
id: mcp-unpinned-npx
name: MCP server launched via npx with no version pin
severity: high
target: mcp
match:
  all:
    - field: command
      contains: npx
    - field: args
      not_regex: '@\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
description: >-
  npx resolves the newest matching package at launch, so the reviewed code is not
  necessarily the code that runs.
remediation: Pin the package to an exact version.
tags: [mcp, supply-chain]
"""

_FENCE = re.compile(r"^\s*```(?:ya?ml)?\s*|\s*```\s*$", re.MULTILINE)


@dataclass
class GeneratedRule:
    yaml_text: str
    rule_id: str
    provider: str
    model: str


def _strip_fences(text: str) -> str:
    """Models add code fences despite being told not to. Tolerate it."""
    return _FENCE.sub("", text).strip()


def generate_rule(
    prompt: str,
    *,
    provider: str = "openai",
    model: str | None = None,
    timeout: int = 60,
    api_key: str | None = None,
    transport: object | None = None,
) -> GeneratedRule:
    """Ask a model for a rule, validate it, and return the YAML.

    Raises :class:`LLMError` if the provider fails, or :class:`RuleError` if the
    model produced something that is not a valid rule. Invalid output is never
    written to disk.
    """
    if not prompt.strip():
        raise RuleError("<prompt>: describe what the rule should detect")

    active = build_provider(
        provider, model=model, timeout=timeout, api_key=api_key, transport=transport
    )

    user = (
        f"Write an Argus rule for this request:\n\n{prompt.strip()}\n\n"
        f"Here is a complete example of the expected output format:\n\n{EXAMPLE}"
    )
    response = active.complete(SYSTEM, user)
    yaml_text = _strip_fences(response.text)

    try:
        rule = _validate(yaml_text)
    except RuleError as first:
        # The schema carries constraints no prompt fully conveys — a length cap, an id
        # pattern, one of several condition shapes. Handing the validator's own message
        # back is far more effective than trying to pre-empt every rule in the prompt,
        # and it costs one call only when the first attempt was already going to fail.
        repair = (
            f"{user}\n\nYou produced this document:\n\n{yaml_text}\n\n"
            f"It was rejected by the validator:\n\n  {first}\n\n"
            "Return the corrected YAML document only."
        )
        response = active.complete(SYSTEM, repair)
        yaml_text = _strip_fences(response.text)
        try:
            rule = _validate(yaml_text)
        except RuleError as second:
            raise RuleError(f"{second} — and after one repair attempt: {first}") from second

    return GeneratedRule(
        yaml_text=yaml_text.rstrip() + "\n",
        rule_id=rule.rule_id,
        provider=active.name,
        model=response.model,
    )


def _validate(yaml_text: str) -> Rule:
    """Parse and validate generated YAML. Nothing invalid is ever written to disk."""
    if not yaml_text:
        raise RuleError("<generated>: model returned an empty response")

    from ..core.safe_io import parse_yaml_text

    data = parse_yaml_text(yaml_text)
    if data is None:
        raise RuleError("<generated>: model output was not valid YAML")
    return parse_rule(data, "<generated>")


__all__ = ["GeneratedRule", "LLMError", "RuleError", "generate_rule"]
