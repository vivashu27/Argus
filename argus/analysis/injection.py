"""Prompt injection heuristics (spec 6.1).

Static analysis cannot establish intent. A pattern match here means the text
*contains language that would function as an injection if an agent read it* — not
that its author was malicious. Every caller must phrase findings as
"Potential prompt injection detected".

To keep the false-positive rate usable on security documentation (which legitimately
quotes these phrases), matches inside fenced code blocks, blockquotes and explicit
example markers are discounted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .redaction import truncate


@dataclass(frozen=True)
class InjectionMatch:
    pattern_id: str
    description: str
    family: str
    line: int
    context: str
    confidence: str  # HIGH | MEDIUM | LOW
    recommendation: str
    discounted: bool = False
    discount_reason: str = ""

    @property
    def is_actionable(self) -> bool:
        """True when the match reads as a live directive rather than documentation.

        Checks that assert a policy violation (SKILL-004, INSTR-003) must consult
        this rather than confidence alone: a phrase quoted inside a code fence in a
        security playbook is evidence of documentation, not of an attack.
        """
        return not self.discounted and self.confidence in ("HIGH", "MEDIUM")


#: Codepoints that may legitimately precede a zero-width joiner: pictographs,
#: dingbats, arrows, keycap bases, and the variation selectors that follow them.
_PICTOGRAPHIC = (
    "\U0001F000-\U0001FAFF←-⇿⌀-⏿☀-➿"
    "⬀-⯿⃣︎️"
)


#: Somewhere a credential could actually be sent. Exfiltration is a claim about a
#: destination, so requiring one is not a weakening of the rule but a statement of
#: it. A relative path or an unqualified noun is not a destination — "POST to
#: /oauth/token" is how OAuth works, not how credentials leave a machine.
_DESTINATION = (
    r"(?:https?://|ftps?://|\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|"
    r"\b(?:webhook|pastebin|paste\.ee|hastebin|ngrok|requestbin|burpcollaborator|"
    r"discord|telegram|slack\s+hook|c2|command[\s-]and[\s-]control|"
    r"(?:remote|external|attacker|our|my|third[\s-]party)[\s-]+(?:\w+[\s-]+)?"
    r"(?:server|host|endpoint|url|site|api|service|collector|bucket|inbox))\b)"
)


@dataclass(frozen=True)
class _Rule:
    pattern_id: str
    description: str
    family: str
    confidence: str
    regex: re.Pattern[str]
    recommendation: str


RULES: tuple[_Rule, ...] = (
    _Rule("ignore-previous", "Instruction to disregard prior instructions",
          "instruction_override", "HIGH",
          re.compile(r"\b(?:ignore|disregard|forget|discard)\s+(?:all\s+|any\s+)?"
                     r"(?:the\s+)?(?:previous|prior|earlier|above|preceding|foregoing)\s+"
                     r"(?:instruction|prompt|direction|rule|message|context)s?\b", re.I),
          "Remove the directive, or confirm it is quoted sample text rather than a live instruction."),
    _Rule("ignore-system", "Instruction to override the system prompt",
          "instruction_override", "HIGH",
          re.compile(r"\b(?:ignore|override|bypass|disregard|supersede)\s+(?:the\s+|your\s+|all\s+)?"
                     r"(?:system|developer|operator|base)\s+(?:prompt|instruction|message|rule)s?\b", re.I),
          "Remove the directive. Instruction files must not attempt to alter the system prompt."),
    _Rule("override-security", "Instruction to disable security controls",
          "policy_subversion", "HIGH",
          re.compile(r"\b(?:ignore|bypass|disable|turn\s+off|circumvent|skip|override)\s+"
                     r"(?:all\s+|any\s+|the\s+|your\s+)?"
                     r"(?:security|safety|guardrail|restriction|policy|policies|permission|"
                     r"approval|confirmation|sandbox)\w*\b", re.I),
          "Remove the directive and review who can modify this file."),
    _Rule("reveal-system-prompt", "Request to disclose the system prompt",
          "exfiltration", "HIGH",
          re.compile(r"\b(?:reveal|print|output|repeat|show|display|dump|echo|reproduce)\s+"
                     r"(?:me\s+)?(?:the\s+|your\s+|all\s+)?(?:full\s+|entire\s+|complete\s+|verbatim\s+)?"
                     r"(?:system\s+prompt|initial\s+instruction|hidden\s+instruction|"
                     r"prior\s+context|configuration\s+prompt)s?\b", re.I),
          "Remove the directive. Prompt disclosure requests in config files are a known exfiltration vector."),
    # The trailing lookahead separates concealment from delegation. "Don't tell the
    # user to run them" instructs the agent to act rather than hand work back; only
    # "don't tell the user <about something>" is concealment.
    _Rule("hidden-instruction", "Instruction framed as hidden from the user",
          "concealment", "HIGH",
          re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+to|reveal\s+to|"
                     r"disclose\s+to|notify|show)\s+(?:the\s+)?(?:user|human|operator|owner)\b"
                     r"(?!\s+to\s+\w)", re.I),
          "Remove the directive. Concealing agent behaviour from the operator is not legitimate configuration."),
    _Rule("silent-execution", "Instruction to act without confirmation",
          "policy_subversion", "MEDIUM",
          re.compile(r"\b(?:without|skip(?:ping)?|no\s+need\s+for|bypass(?:ing)?|"
                     r"avoid(?:ing)?|circumvent(?:ing)?)\s+"
                     r"(?:the\s+|any\s+|all\s+|explicit\s+)*"
                     r"(?:asking|prompting|confirming|approval|confirmation|permission|"
                     r"consent|knowledge|awareness|notifying|informing|"
                     r"telling\s+the\s+user|user[\s'\u2019]*s?\s+(?:consent|knowledge|"
                     r"awareness|approval|permission))\b", re.I),
          "Require explicit approval for privileged operations."),
    _Rule("fetch-instructions", "Instructions sourced from a remote URL",
          "remote_instruction", "HIGH",
          re.compile(r"\b(?:fetch|download|retrieve|load|read|get|curl|wget|pull)\b[^\n]{0,60}?"
                     r"\b(?:instruction|prompt|directive|command|rule|config)s?\b[^\n]{0,60}?"
                     r"https?://", re.I),
          "Pin instructions locally. Remote instruction sources allow silent post-approval changes."),
    # ``(?<![\w-])`` keeps the verb from matching inside an identifier. Without it,
    # a crate feature named ``ort-download-binaries`` paired with the word "run"
    # anywhere in the same sentence reads as download-and-execute.
    # The connector is required, not optional. Fetch-then-execute is always written
    # as two joined steps — "download the script and run it", "curl … | sh". Without
    # it, prose like "the active download run now owns a live handle" is two ordinary
    # words that happen to be adjacent.
    _Rule("url-then-execute", "Download-and-execute directive",
          "remote_instruction", "HIGH",
          re.compile(r"(?<![\w-])(?:download|fetch|curl|wget)(?![\w-])[^\n]{0,80}?"
                     r"(?:\band\b|\bthen\b|&&|\|\|?|;)\s*(?:\bthen\b\s*)?"
                     r"(?:\w+\s+){0,3}?(?:run|execute|eval|install|bash|sh|source)\b", re.I),
          "Remove the directive. Fetch-then-execute is the canonical agent RCE pattern."),
    # Three constraints, each earning its place against observed noise. Identifier
    # guards stop ``x-revalidate-secret`` and ``Post-Exploitation``. The destination
    # requirement is what the check's own title claims — transmitting credentials
    # *externally* — and without it every OAuth README matched, because "POST" and
    # "token" co-occur in all of them.
    _Rule("exfiltrate-secrets", "Directive to transmit credentials externally",
          "exfiltration", "HIGH",
          re.compile(r"(?<![\w-])(?:send|post|upload|transmit|exfiltrate|forward|email|leak|report)"
                     r"(?![\w-])[^\n]{0,80}?(?:(?<![\w-])(?:secret|credential|api[\s_\-]?key|"
                     r"token|password|private[\s_\-]?key|ssh\s+key)s?(?![\w-])|\.env\b)"
                     rf"[^\n]{{0,80}}?{_DESTINATION}", re.I),
          "Remove the directive and rotate any credential reachable from this environment."),
    _Rule("read-credentials", "Directive to read credential stores",
          "exfiltration", "MEDIUM",
          re.compile(r"\b(?:read|open|cat|access|load|parse)\b[^\n]{0,50}?"
                     r"(?:~/\.ssh|~/\.aws|\.env\b|id_rsa|credentials\.json|\.netrc|"
                     r"\.claude/\.credentials)", re.I),
          "Restrict filesystem access and add explicit deny rules for credential paths."),
    _Rule("upload-files", "Directive to upload local files",
          "exfiltration", "MEDIUM",
          re.compile(r"\b(?:upload|post|send)\b[^\n]{0,50}?\b(?:file|directory|folder|"
                     r"contents|repository|codebase)s?\b[^\n]{0,50}?\b(?:to|at)\b[^\n]{0,30}?https?://", re.I),
          "Remove the directive and review outbound network permissions."),
    _Rule("role-reassignment", "Attempt to reassign the agent's role or persona",
          "instruction_override", "MEDIUM",
          re.compile(r"\byou\s+are\s+(?:now|actually)\s+(?:a|an|in)\b|"
                     r"\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must)\b|"
                     r"\benter\s+(?:developer|god|admin|unrestricted|dan)\s+mode\b", re.I),
          "Review the directive. Persona reassignment is commonly used to defeat guardrails."),
    _Rule("encoded-payload", "Encoded blob adjacent to an execution directive",
          "obfuscation", "MEDIUM",
          re.compile(r"\b(?:base64|atob|fromCharCode|rot13|hex\s*decode|unescape)\b"
                     r"[^\n]{0,60}?\b(?:exec|eval|run|decode\s+and)\b", re.I),
          "Decode and review the payload manually before trusting this file."),
    # U+200D is exempt when it follows a pictograph or a variation selector: that is
    # an emoji ZWJ sequence, not concealment. "🕵️‍♀️" is one such sequence, and a
    # scanner that calls a detective emoji a hidden instruction teaches its users to
    # ignore the check. Every other zero-width and bidirectional control still counts.
    _Rule("invisible-text", "Zero-width or bidirectional control characters",
          "concealment", "HIGH",
          re.compile(
              rf"[​‌‎‏‪-‮⁠-⁤﻿]"
              rf"|(?<![{_PICTOGRAPHIC}])‍"
          ),
          "Strip the characters. Invisible text hides instructions from human review but not from the model."),
)

#: Contexts where a matched phrase is probably being described, not issued.
_FENCE = re.compile(r"^\s*(?:```|~~~)")
_DISCOUNT_MARKERS = re.compile(
    r"\b(?:example|e\.g\.|for instance|such as|detect|detection|pattern|regex|"
    r"do not write|never write|attack|malicious|test case|fixture|payload|"
    r"this is what|would look like|red flag|indicator|chain|technique|"
    r"vulnerability|exploit|adversar|threat|mitigat)\w*\b",
    re.I,
)

#: Signals that the whole document is offensive-security material. Such documents
#: quote injection strings by necessity — a pentest playbook that did not contain
#: the phrase "ignore previous instructions" would be useless. Without this,
#: security tooling and training content is the single largest false-positive source.
_SECURITY_DOC = re.compile(
    r"\b(?:penetration test|pentest|red team|security assessment|threat model|"
    r"vulnerability assessment|owasp|mitre|att&ck|atlas|exploit(?:ation)?|"
    r"attack (?:chain|vector|surface|technique)|offensive security|"
    r"security (?:review|audit|research|testing)|jailbreak|adversarial)\b",
    re.I,
)
_SECURITY_DOC_THRESHOLD = 3

_URL_TOKEN = re.compile(r"\b(?:https?|ftps?)://\S+|\b[\w.-]+\.(?:com|net|org|io|dev|sh)\b", re.I)


def _strip_urls(window: str) -> str:
    """Remove URLs before testing for documentation language.

    ``collector.example.net`` contains the word "example", and RFC 2606 placeholder
    domains appear in real payloads at least as often as in real documentation. A
    hostname is not a statement that the surrounding line is illustrative, so
    letting one discount a match suppressed genuine exfiltration directives.
    """
    return _URL_TOKEN.sub(" ", window)

#: A lead-in that turns the list beneath it into a list of prohibitions. "Claude Code
#: must never:" followed by bullets is one of the most common shapes in real
#: instruction files, and each bullet inherits the negation from the heading rather
#: than restating it. Reading those bullets as directives inverts their meaning,
#: which is the worst error available to a security scanner: it reports the presence
#: of a rule as the absence of one.
_PROHIBITION_LEAD = re.compile(
    r"\b(?:never|must\s+not|should\s+not|do\s+not|don'?t|avoid|forbidden|prohibited|"
    r"not\s+allowed|disallowed|off[\s-]?limits)\b[^\n]*:[*_\s]*$",
    re.I,
)

#: The same negation stated on the line itself rather than inherited from a heading.
#: Matched against the text *preceding* the rule's own match, not against the start
#: of the line: "don't create new folders without approval" and "### Forbidden
#: Without Permission" both negate, and neither puts the cue in column one.
_NEGATION_CUE = re.compile(
    r"\b(?:must\s+not|must\s+never|shall\s+not|should\s+not|never|not\s+ever|"
    r"do\s+not|does\s+not|did\s+not|don'?t|doesn'?t|didn'?t|cannot|can'?t|won'?t|"
    r"refrain\s+from|forbidden|prohibited|not\s+allowed|disallowed|"
    r"under\s+no\s+circumstances|no\s+longer)\b",
    re.I,
)

_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_MD_HEADING = re.compile(r"^\s*#{1,6}\s")

#: Rules whose own pattern already contains the negation. Discounting these for
#: sitting under a prohibition would suppress precisely what they exist to find.
_NEGATION_INTRINSIC = frozenset({"hidden-instruction", "invisible-text"})


def _prohibition_scope(lines: list[str]) -> set[int]:
    """1-based line numbers governed by a prohibition lead-in.

    A lead-in governs the list that follows it. Blank lines do not end the list —
    loosely formatted markdown separates bullets with them — but a heading or an
    ordinary paragraph does.
    """
    governed: set[int] = set()
    active = False
    for index, line in enumerate(lines, start=1):
        if _PROHIBITION_LEAD.search(line):
            active = True
            continue
        if not active:
            continue
        if not line.strip():
            continue
        if _MD_HEADING.match(line):
            active = False
            continue
        if _LIST_ITEM.match(line):
            governed.add(index)
            continue
        active = False
    return governed


def _downgrade(confidence: str) -> str:
    return {"HIGH": "MEDIUM", "MEDIUM": "LOW"}.get(confidence, "LOW")


def is_security_document(text: str) -> bool:
    """Whether the text as a whole reads as offensive-security documentation."""
    head = "\n".join(text.splitlines()[:80])
    return len(_SECURITY_DOC.findall(head)) >= _SECURITY_DOC_THRESHOLD or (
        len(_SECURITY_DOC.findall(text)) >= _SECURITY_DOC_THRESHOLD * 3
    )


def scan_text(
    text: str,
    *,
    max_findings: int = 40,
    line_offset: int = 0,
    trust_formatting: bool = True,
) -> list[InjectionMatch]:
    """Scan text for potential prompt-injection language.

    ``line_offset`` is added to every reported line number, so callers scanning a
    slice of a file (a Skill body after its frontmatter, say) still report line
    numbers that resolve against the original file.

    ``trust_formatting`` controls whether a code fence or blockquote is allowed to
    excuse a match. It holds for files a human wrote and reviewed, where fencing
    genuinely marks an illustration. It must be turned off for text the audited
    component *produced* — tool output, a fetched page — because there the attacker
    chooses the formatting, and wrapping a payload in a fence would otherwise be a
    one-character bypass. The semantic discounts still apply either way.
    """
    matches: list[InjectionMatch] = []
    seen: set[tuple[str, int]] = set()
    in_fence = False

    security_doc = is_security_document(text)
    lines = text.splitlines()
    prohibited = _prohibition_scope(lines)

    for index, line in enumerate(lines, start=1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if len(line) > 4000:
            continue

        lineno = index + line_offset

        # A phrase inside a code fence, a quote, or an explicitly labelled example is
        # far more likely to be documentation than a live directive.
        window = _strip_urls(" ".join(lines[max(0, index - 3) : index + 1]))
        base_reason = ""
        if in_fence and trust_formatting:
            base_reason = "inside a code fence"
        elif line.lstrip().startswith(">") and trust_formatting:
            base_reason = "inside a blockquote"
        elif _DISCOUNT_MARKERS.search(window):
            base_reason = "adjacent to example or detection-description language"
        elif security_doc:
            base_reason = "document reads as offensive-security documentation"

        for rule in RULES:
            match = rule.regex.search(line)
            if match is None:
                continue
            key = (rule.pattern_id, lineno)
            if key in seen:
                continue
            seen.add(key)

            negated = ""
            if rule.pattern_id not in _NEGATION_INTRINSIC:
                if index in prohibited:
                    negated = "listed under a prohibition heading"
                elif _NEGATION_CUE.search(line[: match.start()]):
                    negated = "the line states the behaviour as prohibited"
            reason = base_reason or negated
            matches.append(
                InjectionMatch(
                    pattern_id=rule.pattern_id,
                    description=rule.description,
                    family=rule.family,
                    line=lineno,
                    context=truncate(line),
                    confidence=_downgrade(rule.confidence) if reason else rule.confidence,
                    recommendation=rule.recommendation,
                    discounted=bool(reason),
                    discount_reason=reason,
                )
            )
            if len(matches) >= max_findings:
                return matches
    return matches


EXTERNAL_URL = re.compile(r"https?://([\w.\-]+)(?::\d+)?(?:/\S*)?", re.I)

TRUSTED_HOSTS = frozenset(
    {
        "anthropic.com", "docs.anthropic.com", "claude.ai", "modelcontextprotocol.io",
        "github.com", "raw.githubusercontent.com", "gist.github.com",
        "pypi.org", "files.pythonhosted.org", "npmjs.com", "registry.npmjs.org",
        "python.org", "docs.python.org", "owasp.org", "nist.gov", "mitre.org",
        "cwe.mitre.org", "atlas.mitre.org", "localhost", "127.0.0.1",
    }
)

#: Hosting that permits anonymous, mutable content — instructions loaded from here
#: can change after review without any signal.
#:
#: Matched against whole domain labels, never as a substring: an unanchored "t.co"
#: matches inside "raw.githubuserconten*t.co*m" and "microsof*t.co*m", which turns
#: every reference to GitHub raw content into a false positive.
UNTRUSTED_DOMAINS = frozenset(
    {
        "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "termbin.com",
        "transfer.sh", "file.io", "anonfiles.com", "bit.ly", "tinyurl.com",
        "t.co", "goo.gl", "is.gd", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
        "webhook.site", "requestbin.com", "burpcollaborator.net", "interact.sh",
        "oast.fun", "oast.live", "oast.site", "oast.online", "oast.pro",
    }
)

#: Cloud instance metadata endpoints. A reference to one inside agent configuration
#: is a credential-theft indicator, not merely an untrusted host.
METADATA_ENDPOINTS = frozenset({"169.254.169.254", "metadata.google.internal", "100.100.100.200"})

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: RFC 1918 private ranges, plus link-local and carrier-grade NAT.
_PRIVATE_IPV4 = re.compile(
    r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|100\.(?:6[4-9]|"
    r"[7-9]\d|1[01]\d|12[0-7])\.)"
)
# S104 does not apply: these are host names being *recognised*, not bound to.
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # noqa: S104


def extract_urls(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line, host, url)`` for each URL in the text."""
    out: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in EXTERNAL_URL.finditer(line):
            out.append((lineno, match.group(1).lower(), match.group(0)))
    return out


def _domain_matches(host: str, domain: str) -> bool:
    """Exact host or subdomain match — never a substring match."""
    return host == domain or host.endswith("." + domain)


def classify_host(host: str) -> tuple[bool, str]:
    """Classify a host. Returns ``(is_suspicious, reason)``."""
    host = host.lower().strip(".")
    if not host:
        return False, ""
    if host in _LOOPBACK:
        return False, ""
    if host in METADATA_ENDPOINTS:
        return True, "cloud instance metadata endpoint — a credential-theft target"
    if any(_domain_matches(host, d) for d in UNTRUSTED_DOMAINS):
        return True, "disposable, URL-shortening, or tunnelling host"
    if is_trusted_host(host):
        return False, ""
    if _IPV4.match(host):
        if _PRIVATE_IPV4.match(host):
            # An RFC 1918 or link-local address is LAN infrastructure — a Raspberry
            # Pi, a dev VM, a service on the same host. It is not an exfiltration
            # destination, and flagging it makes the check useless on home labs.
            return False, ""
        return True, "bare IP literal rather than a named host"
    return False, ""


def is_suspicious_host(host: str) -> bool:
    return classify_host(host)[0]


def is_trusted_host(host: str) -> bool:
    host = host.lower()
    return any(host == t or host.endswith("." + t) for t in TRUSTED_HOSTS)


OBFUSCATION = (
    re.compile(r"\bbase64\.b64decode\s*\(", re.I),
    re.compile(r"\batob\s*\(", re.I),
    re.compile(r"\beval\s*\(\s*(?:atob|base64|unescape|decodeURIComponent)", re.I),
    re.compile(r"\bexec\s*\(\s*(?:base64|codecs|bytes\.fromhex|__import__)", re.I),
    re.compile(r"\bString\.fromCharCode\s*\(", re.I),
    re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){8,}", re.I),
    re.compile(r"\bchr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(", re.I),
    re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"),
)


def find_obfuscation(text: str) -> list[tuple[int, str]]:
    """Locate encoded or obfuscated code constructs (HOOK-006)."""
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern in OBFUSCATION:
            if pattern.search(line):
                hits.append((lineno, truncate(line, 120)))
                break
    return hits
