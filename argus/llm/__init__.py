"""Optional LLM-assisted review.

**This is the only part of Argus that makes network requests, and it is off by
default.** Nothing here runs unless the operator passes ``--llm`` (or sets
``llm.enabled: true``), because it sends excerpts of scanned configuration to a
third-party API.

Two properties are enforced structurally rather than by prompt wording:

1. **Nothing leaves the machine unsanitised.** Every payload goes through
   :mod:`argus.llm.sanitize`, which redacts secrets and strips the home path,
   username and hostname. See the tests in ``tests/unit/test_llm.py``.
2. **A model verdict can only add a finding, never remove or downgrade one.**
   LLM output becomes new ``MANUAL`` findings in section 9; it never touches a
   static finding. So a scanned file that tries to talk the reviewer into clearing
   itself — the OWASP AST08 "prompt-inject the scanner's own judge" bypass —
   cannot succeed. It can only add noise, which is a far weaker outcome.
"""

from __future__ import annotations

from .providers import LLMError, LLMResponse, Provider, build_provider
from .reviewer import LLMConfig, ReviewResult, review

__all__ = [
    "LLMConfig",
    "LLMError",
    "LLMResponse",
    "Provider",
    "ReviewResult",
    "build_provider",
    "review",
]
