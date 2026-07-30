"""Section 9 — LLM-Assisted Review (LLM-001 … LLM-004).

These checks report what an optional LLM reviewer observed. They are **advisory**:

* status is always ``MANUAL`` when review ran, so by the existing scoring rules they
  deduct nothing and never gate the exit code
* status is ``NOT_APPLICABLE`` when ``--llm`` was not passed, which is the default

``MANUAL`` is not a workaround here — it is the accurate status. A non-deterministic
reviewer produces a lead for a human to adjudicate, not a verified control outcome.
Reporting these as ``FAIL`` would make CI flaky and put a prompt-injectable component
in the gating path; reporting them as ``PASS`` would credit coverage that was never
verified.

Crucially, these checks only ever *add* findings. Nothing here can alter, downgrade
or clear a static finding, so a scanned file that tries to talk the reviewer into
clearing itself cannot succeed.
"""

from __future__ import annotations

from ..core.models import Category, CheckMeta, Confidence, Finding, Severity, Status, Target
from ..core.registry import register
from .base import Check, CheckContext

LLM_TARGETS = frozenset(
    {Target.INSTRUCTIONS, Target.SKILLS, Target.MCP, Target.HOOKS, Target.CLAUDE_CODE}
)


class _LLMPassCheck(Check):
    """Shared behaviour: surface one review pass as advisory findings."""

    STAGE = ""
    SUBJECT = "assets"

    def run(self, context: CheckContext) -> list[Finding]:
        review = context.options.get("llm_review")

        if review is None:
            return [
                self.not_applicable(
                    "-",
                    "LLM review not enabled. Pass --llm to run it (sends redacted "
                    "excerpts to a third-party provider).",
                )
            ]

        if review.errors and self.STAGE not in review.passes_run:
            return [
                self.error(
                    "-",
                    "LLM review did not complete: " + "; ".join(review.errors[:3]),
                )
            ]

        if self.STAGE not in review.passes_run:
            return [
                self.not_applicable("-", f"No {self.SUBJECT} were available for review")
            ]

        reported = [f for f in review.findings if f.pass_name == self.STAGE]
        if not reported:
            return [
                self._finding(
                    Status.MANUAL,
                    asset="-",
                    detail=(
                        f"Reviewer reported no concerns across {self.SUBJECT}. Advisory "
                        "only — this is not a verified pass."
                    ),
                    confidence=Confidence.LOW,
                    severity=Severity.INFO,
                )
            ]

        findings: list[Finding] = []
        for item in reported:
            findings.append(
                self._finding(
                    Status.MANUAL,
                    asset=item.asset_id,
                    detail=f"{item.title} — {item.rationale}",
                    evidence=[
                        self.evidence(
                            key=f"{item.provider}:{item.model}",
                            snippet=item.evidence or None,
                            reason=(
                                f"Reported by LLM review ({item.confidence.value} "
                                f"model confidence). Requires human adjudication."
                            ),
                        )
                    ],
                    # Model confidence is capped at MEDIUM: a model's own certainty is
                    # not evidence, and these never gate anything regardless.
                    confidence=Confidence.MEDIUM
                    if item.confidence is Confidence.HIGH
                    else item.confidence,
                    severity=item.severity,
                )
            )
        return findings


@register
class LLMInjectionReview(_LLMPassCheck):
    STAGE = "injection"
    SUBJECT = "instruction files and Skills"
    meta = CheckMeta(
        check_id="LLM-001",
        title="LLM review of instruction files and Skills for prompt injection",
        description=(
            "An LLM reviewed instruction files and Skill bodies for injection and "
            "security-control subversion that pattern matching does not cover."
        ),
        category=Category.LLM,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=frozenset({Target.INSTRUCTIONS, Target.SKILLS}),
        rationale=(
            "Regex detects known phrasings. A model can recognise novel wording, "
            "directives split across sentences, and indirection — the gap OWASP AST08 "
            "identifies in pattern-matching scanners. It is also itself injectable, "
            "which is why these results are advisory and additive only."
        ),
        security_impact=(
            "An injected directive that evades static detection persists across every "
            "session that loads the file."
        ),
        remediation=(
            "Adjudicate each reported item against the cited file. Confirmed injections "
            "should be removed and the file's write access reviewed."
        ),
        references=(
            "https://owasp.org/www-project-agentic-skills-top-10/",
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
        ),
    )


@register
class LLMMcpReview(_LLMPassCheck):
    STAGE = "mcp"
    SUBJECT = "MCP server configurations"
    meta = CheckMeta(
        check_id="LLM-002",
        title="LLM review of MCP server capability and destructive potential",
        description=(
            "An LLM assessed what capability each MCP server plausibly grants, covering "
            "the questions MCP-010 and MCP-011 report as MANUAL."
        ),
        category=Category.LLM,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=frozenset({Target.MCP}),
        rationale=(
            "MCP-010 and MCP-011 return MANUAL because enumerating a server's real tool "
            "surface needs a handshake Argus will not perform. A model can at least "
            "reason about the configured command and arguments."
        ),
        security_impact=(
            "An unassessed server may expose destructive tools reachable by prompt "
            "injection."
        ),
        remediation="Review the named server's tool implementations against its declared purpose.",
        references=("https://modelcontextprotocol.io/docs/concepts/tools",),
        compliance=(("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),),
    )


@register
class LLMHookReview(_LLMPassCheck):
    STAGE = "hooks"
    SUBJECT = "hook definitions"
    meta = CheckMeta(
        check_id="LLM-003",
        title="LLM review of hook intent",
        description="An LLM assessed whether each hook's behaviour matches its apparent purpose.",
        category=Category.LLM,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=frozenset({Target.HOOKS}),
        rationale=(
            "Hooks run automatically with no per-invocation approval, so intent matters "
            "more than syntax. Whether a hook does more than its name implies is a "
            "judgement call, not a pattern match."
        ),
        security_impact="A hook exceeding its stated purpose has automatic, unattended reach.",
        remediation="Read the named hook script and confirm its behaviour matches its purpose.",
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),),
    )


@register
class LLMTrifectaReview(_LLMPassCheck):
    STAGE = "trifecta"
    SUBJECT = "the combined environment"
    meta = CheckMeta(
        check_id="LLM-004",
        title="LLM correlation review for the lethal trifecta",
        description=(
            "An LLM assessed whether the environment combines private-data access, "
            "untrusted content exposure, and an outbound channel."
        ),
        category=Category.LLM,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=frozenset({Target.CLAUDE_CODE, Target.MCP, Target.SKILLS}),
        rationale=(
            "The trifecta is a property of the environment as a whole, not of any single "
            "file, so no per-asset check can detect it. This is the clearest case where "
            "cross-asset reasoning adds something regex cannot."
        ),
        security_impact=(
            "Each leg is individually routine; together they make prompt injection "
            "directly exploitable for credential exfiltration."
        ),
        remediation=(
            "Break one leg: deny credential paths, constrain network tools to an allowlist, "
            "or vet the untrusted content source."
        ),
        references=("https://owasp.org/www-project-agentic-skills-top-10/",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("MITRE ATLAS", "AML.T0057: LLM Data Leakage"),
        ),
    )
