"""Argus — AI Agent Security Configuration Auditor.

Argus is a read-only, CIS-inspired security configuration auditor for AI-agent
environments. It never executes discovered content: every scanned Skill, Plugin,
hook, MCP server definition and instruction file is treated as untrusted input and
analyzed statically.

Not affiliated with or certified by CIS, Anthropic, OpenAI, or any other organization.
"""

__version__ = "1.0.0"
__benchmark__ = "AASB v1.0"
__all__ = ["__version__", "__benchmark__"]
