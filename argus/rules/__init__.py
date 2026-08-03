"""Custom ``.argus`` rules.

Rules let you express a check without writing Python, in the spirit of a Nuclei
template or a YARA rule. A rule is a YAML document with a fixed, small schema:

    id: mcp-unpinned-npx
    name: MCP server launched via npx with no version pin
    severity: high
    target: mcp

    match:
      all:
        - field: command
          contains: npx
        - field: args
          not_regex: '@\\d+\\.\\d+\\.\\d+'

    remediation: Pin the package to an exact version.

YAML rather than a bespoke grammar is a deliberate choice. Rule files are input,
and a hand-written parser in a security tool is somewhere for a parser bug to be a
vulnerability. ``yaml.safe_load`` is already the only loader Argus uses, and it
cannot construct Python objects.

Rules are **data, never code**. Nothing in a rule is evaluated, executed, or
interpolated into a shell. The only dynamic element is regular expressions, which
are validated at load time and applied under input-length caps.
"""

from __future__ import annotations

from .engine import evaluate_rule, run_rules
from .loader import RuleError, load_rule_file, load_rules
from .model import Rule, RuleMatch

__all__ = [
    "Rule",
    "RuleError",
    "RuleMatch",
    "evaluate_rule",
    "load_rule_file",
    "load_rules",
    "run_rules",
]
