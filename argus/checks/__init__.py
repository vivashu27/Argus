"""AASB v1.0 security checks.

Importing this package registers every check with :mod:`argus.core.registry`.
"""

from __future__ import annotations

from . import (  # noqa: F401  (imported for registration side effects)
    claude_checks,
    dynamic_checks,
    filesystem_checks,
    hook_checks,
    instruction_checks,
    mcp_checks,
    mcp_code_checks,
    plugin_checks,
    secret_checks,
    skill_checks,
)

__all__ = [
    "claude_checks",
    "mcp_checks",
    "mcp_code_checks",
    "skill_checks",
    "plugin_checks",
    "hook_checks",
    "instruction_checks",
    "secret_checks",
    "filesystem_checks",
    "dynamic_checks",
]
