"""Secret redaction.

Argus writes findings to terminals, JSON, SARIF uploaded to GitHub, and HTML reports
that get emailed around. A leaked secret in any of those is worse than the
misconfiguration being reported, so redaction happens at the point of detection and
is never reversed downstream.

Policy: keep at most a 4-character prefix and 4-character suffix, and never reveal
more than half of a short value.
"""

from __future__ import annotations

import re

KEEP = 4
ELLIPSIS = "…"

#: Values that look like secrets but are obviously not, so they need no redaction
#: and should not be reported at all.
PLACEHOLDER_PATTERN = re.compile(
    r"^(?:"
    r"x{3,}|X{3,}|\*{3,}|\.{3,}|"
    r"<[^>]{1,40}>|\{\{[^}]{1,40}\}\}|\$\{[^}]{1,40}\}|"
    r"(?:your|my|the)[-_ ]?(?:api[-_ ]?key|token|secret|password)|"
    r"(?:example|sample|dummy|placeholder|redacted|changeme|test|fake|foo|bar)"
    r"[-_ ]?(?:key|token|secret|value|password)?"
    r")$",
    re.IGNORECASE,
)


def is_placeholder(value: str) -> bool:
    """True when a matched value is a documented placeholder rather than a real secret."""
    stripped = value.strip().strip("\"'")
    if not stripped:
        return True
    if PLACEHOLDER_PATTERN.match(stripped):
        return True
    lowered = stripped.lower()
    markers = ("example", "placeholder", "changeme", "redacted", "dummy", "your-", "xxxx")
    return any(marker in lowered for marker in markers)


def redact(value: str, keep: int = KEEP) -> str:
    """Redact a secret to a prefix/suffix stub.

    Short values are redacted entirely — showing 4 of 8 characters would halve the
    search space for anyone reading the report.
    """
    if value is None:
        return ""
    text = str(value).strip().strip("\"'")
    if not text:
        return ""
    if len(text) <= keep * 2:
        return ELLIPSIS * 3
    return f"{text[:keep]}{ELLIPSIS}{text[-keep:]}"


def redact_line(line: str, secrets: list[str]) -> str:
    """Replace every occurrence of the given secrets within a line of context."""
    out = line
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret and secret in out:
            out = out.replace(secret, redact(secret))
    return out.strip()


def truncate(text: str, limit: int = 200) -> str:
    """Bound an evidence snippet so a hostile file cannot flood a report."""
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + ELLIPSIS
