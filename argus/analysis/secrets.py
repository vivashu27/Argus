"""Secret detection.

Two-stage design to keep false positives low (spec 5.7):

1. High-confidence structural patterns (``AKIA…``, ``sk-ant-…``, PEM headers). These
   have a recognisable shape, so a match is reported at HIGH confidence.
2. Generic ``key = value`` assignments, which are only reported when the value also
   clears a Shannon-entropy threshold and is not a known placeholder. These are
   reported at MEDIUM confidence.

Detected values are redacted before leaving this module.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .redaction import is_placeholder, redact, truncate

#: Values below this entropy are almost never real credentials.
ENTROPY_THRESHOLD = 3.6
MIN_GENERIC_LENGTH = 16


@dataclass(frozen=True)
class SecretMatch:
    pattern_id: str
    description: str
    kind: str  # api_key | cloud | private_key | token | plaintext
    line: int
    redacted: str
    context: str
    confidence: str  # HIGH | MEDIUM
    key: str | None = None


@dataclass(frozen=True)
class _Pattern:
    pattern_id: str
    description: str
    kind: str
    regex: re.Pattern[str]
    group: int = 0


# ---------------------------------------------------------------------------
# Stage 1 — structural, high-confidence patterns
# ---------------------------------------------------------------------------
HIGH_CONFIDENCE: tuple[_Pattern, ...] = (
    _Pattern("aws-access-key-id", "AWS access key ID", "cloud",
             re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1),
    _Pattern("anthropic-api-key", "Anthropic API key", "api_key",
             re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), 1),
    _Pattern("openai-api-key", "OpenAI API key", "api_key",
             re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{32,})"), 1),
    _Pattern("github-token", "GitHub token", "token",
             re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})"), 1),
    _Pattern("gitlab-token", "GitLab personal access token", "token",
             re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})"), 1),
    _Pattern("slack-token", "Slack token", "token",
             re.compile(r"\b(xox[abprs]-[A-Za-z0-9\-]{10,})"), 1),
    _Pattern("google-api-key", "Google API key", "api_key",
             re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    _Pattern("stripe-key", "Stripe secret key", "api_key",
             re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})"), 1),
    _Pattern("private-key-block", "Private key material", "private_key",
             re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), 0),
    _Pattern("jwt", "JSON Web Token", "token",
             re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), 1),
    _Pattern("npm-token", "npm access token", "token",
             re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), 1),
    _Pattern("hf-token", "Hugging Face token", "token",
             re.compile(r"\b(hf_[A-Za-z0-9]{34,})\b"), 1),
    _Pattern("basic-auth-url", "Credentials embedded in URL", "plaintext",
             re.compile(r"://[^/\s:@]{1,64}:([^/\s:@]{3,64})@"), 1),
)

# ---------------------------------------------------------------------------
# Stage 2 — generic assignments, entropy-corroborated
# ---------------------------------------------------------------------------
GENERIC_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z0-9_\-.]*(?:api[_\-]?key|apikey|secret|token|password|passwd|
        pwd|credential|auth|access[_\-]?key|private[_\-]?key|client[_\-]?secret)
        [A-Za-z0-9_\-.]*)
        \s*[:=]\s*
        ["']?(?P<value>[^\s"',}\]]{8,200})["']?""",
    re.IGNORECASE | re.VERBOSE,
)

#: Assignment values that are references, not literals — env indirection and command
#: substitution are the recommended remediations, so flagging them would punish
#: correct behaviour.
INDIRECTION = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|"
    r"\$\(|`|process\.env|os\.environ|os\.getenv|getenv\(|env:|"
    r"<[^>]+>|\{\{.*\}\}|\{%.*%\})",
)

#: Values that are source code rather than credential literals. Documentation and
#: sample code assign to identifiers named "token" constantly; without this filter
#: every SDK reference page reports as a credential leak.
_CODE_SHAPED = re.compile(
    r"(?:\?\.|=>|\(\)|\);|\.\w+\(|^\w+\.\w+|::|\blet\b|\bconst\b|\bvar\b|"
    r"\bawait\b|\bnew\s+\w|\bself\.|\bthis\.|\{\}|\[\]|;$)"
)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_path_or_url(value: str) -> bool:
    """Filter the most common generic-assignment false positives."""
    if value.startswith(("/", "./", "../", "~", "http://", "https://")):
        return True
    return bool(re.match(r"^[A-Za-z]:[\\/]", value)) or value.count("/") >= 2


def _looks_like_code(value: str) -> bool:
    """Whether a matched value is a code expression rather than a literal."""
    return bool(_CODE_SHAPED.search(value))


def scan_text(text: str, *, max_findings: int = 50) -> list[SecretMatch]:
    """Scan text for credentials. Returns redacted matches only."""
    matches: list[SecretMatch] = []
    seen: set[tuple[str, int]] = set()
    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1):
        if len(line) > 4000:  # a minified bundle is not worth entropy-scanning
            continue

        for pattern in HIGH_CONFIDENCE:
            for match in pattern.regex.finditer(line):
                value = match.group(pattern.group) if pattern.group else match.group(0)
                if pattern.kind != "private_key" and is_placeholder(value):
                    continue
                dedupe_key = (pattern.pattern_id, lineno)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                matches.append(
                    SecretMatch(
                        pattern_id=pattern.pattern_id,
                        description=pattern.description,
                        kind=pattern.kind,
                        line=lineno,
                        redacted=redact(value),
                        context=truncate(line.replace(value, redact(value))),
                        confidence="HIGH",
                    )
                )
                if len(matches) >= max_findings:
                    return matches

        for match in GENERIC_ASSIGNMENT.finditer(line):
            key = match.group("key")
            value = match.group("value").strip().strip("\"'")
            if len(value) < MIN_GENERIC_LENGTH:
                continue
            if INDIRECTION.match(value) or is_placeholder(value):
                continue
            if _looks_like_path_or_url(value) or _looks_like_code(value):
                continue
            if shannon_entropy(value) < ENTROPY_THRESHOLD:
                continue
            if any(m.line == lineno and m.confidence == "HIGH" for m in matches):
                continue  # already reported structurally on this line
            dedupe_key = ("generic-secret", lineno)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            matches.append(
                SecretMatch(
                    pattern_id="generic-secret",
                    description=f"High-entropy value assigned to '{key}'",
                    kind="plaintext",
                    line=lineno,
                    redacted=redact(value),
                    context=truncate(line.replace(value, redact(value))),
                    confidence="MEDIUM",
                    key=key,
                )
            )
            if len(matches) >= max_findings:
                return matches

    return matches


def scan_mapping(data: object, *, prefix: str = "") -> list[SecretMatch]:
    """Walk a parsed JSON/YAML structure looking for credential-bearing keys.

    Line numbers are unavailable here, so callers that need them should also run
    :func:`scan_text` over the raw file.
    """
    matches: list[SecretMatch] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{path}.{key}" if path else str(key)
                if isinstance(value, str):
                    _check_pair(str(key), value, child)
                else:
                    walk(value, child)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    def _check_pair(key: str, value: str, path: str) -> None:
        for pattern in HIGH_CONFIDENCE:
            match = pattern.regex.search(value)
            if match:
                found = match.group(pattern.group) if pattern.group else match.group(0)
                if pattern.kind != "private_key" and is_placeholder(found):
                    return
                matches.append(
                    SecretMatch(
                        pattern_id=pattern.pattern_id,
                        description=pattern.description,
                        kind=pattern.kind,
                        line=0,
                        redacted=redact(found),
                        context=f"{path} = {redact(found)}",
                        confidence="HIGH",
                        key=path,
                    )
                )
                return
        if not re.search(r"api[_\-]?key|secret|token|password|passwd|credential|auth", key, re.I):
            return
        if len(value) < MIN_GENERIC_LENGTH or INDIRECTION.match(value) or is_placeholder(value):
            return
        if _looks_like_path_or_url(value) or _looks_like_code(value):
            return
        if shannon_entropy(value) < ENTROPY_THRESHOLD:
            return
        matches.append(
            SecretMatch(
                pattern_id="generic-secret",
                description=f"High-entropy value assigned to '{key}'",
                kind="plaintext",
                line=0,
                redacted=redact(value),
                context=f"{path} = {redact(value)}",
                confidence="MEDIUM",
                key=path,
            )
        )

    walk(data, prefix)
    return matches
