"""Section 10 — LLM Review checks (DYN-001 … DYN-005).

These report a model's judgement, not a rule's verdict. Two consequences follow, and
both are load-bearing rather than caveats.

Every check here is ``advisory``: reported in full, never scored, never gating. The
same environment can be judged differently on two runs, and a benchmark score that
moves without the environment moving is not a measurement. Keeping these out of the
score is what lets them be speculative enough to be useful.

And a review that did not happen is not a pass. An asset the provider failed on, or
one whose payload was refused because a credential survived redaction, reports
MANUAL with the reason.
"""

from __future__ import annotations

from ..core.models import (
    Category,
    CheckMeta,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Target,
)
from ..core.registry import register
from ..review.rubric import BY_ID
from .base import Check, CheckContext

#: Where the engine hands reviews to the checks.
REVIEW_KEY = "reviews"

#: Everything an LLM reviewer can look at — the four asset types the user named,
#: plus plugins, which bundle the others.
REVIEWABLE = frozenset(
    {Target.MCP, Target.SKILLS, Target.HOOKS, Target.INSTRUCTIONS, Target.PLUGINS}
)

_CONFIDENCE = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}


def _meta(check_id: str, severity: Severity, impact: str, compliance: tuple) -> CheckMeta:
    """Build a check's metadata from its rubric criterion.

    The criterion text is the single source of truth: what the model was asked is
    exactly what the report says was checked. Restating it here in different words
    would let the two drift, and a reader comparing them could not tell which one
    the finding actually came from.
    """
    criterion = BY_ID[check_id]
    return CheckMeta(
        check_id=check_id,
        title=criterion.title,
        description=criterion.question,
        category=Category.DYNAMIC,
        severity=severity,
        aasb_level=2,
        applies_to=REVIEWABLE,
        advisory=True,
        rationale=(
            f"{criterion.excludes} Judged by a language model rather than a rule, "
            "because the question is about what the text means. Advisory: the "
            "finding never affects the score or the exit code, and a second run may "
            "reach a different answer."
        ),
        security_impact=impact,
        remediation=(
            "Read the quoted text and decide. This is a reviewer's opinion with a "
            "citation, not a detection — treat it as a prompt to look, not as proof."
        ),
        references=(
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ),
        compliance=compliance,
    )


class ReviewCheck(Check):
    """Shared plumbing: find this criterion's verdict for each reviewed asset."""

    def run(self, context: CheckContext) -> list[Finding]:
        reviews = context.options.get(REVIEW_KEY)
        if not isinstance(reviews, list) or not reviews:
            return self.no_assets("reviewed components")

        findings: list[Finding] = []
        for review in reviews:
            if not review.usable:
                findings.append(
                    self.manual(
                        review.asset_id,
                        "Component was not reviewed, so this criterion has no answer: "
                        f"{review.error or 'no reason recorded'}.",
                    )
                )
                continue

            verdict = next(
                (v for v in review.verdicts if v.check_id == self.meta.check_id), None
            )
            if verdict is None:
                findings.append(
                    self.manual(
                        review.asset_id,
                        "The reviewer did not answer this criterion. An unanswered "
                        "question is not a pass.",
                    )
                )
            elif verdict.failed:
                findings.append(
                    self.fail(
                        review.asset_id,
                        verdict.reason,
                        [
                            Evidence(
                                path=verdict.path,
                                line=verdict.line,
                                key=self.meta.check_id.lower(),
                                snippet=verdict.quote[:400],
                                # Not "verbatim": the snippet is the reviewer's
                                # rendering, whitespace-normalised, so a reader
                                # grepping the file for it may not find that exact
                                # string on that line. Saying otherwise would be the
                                # same kind of lie this module refuses elsewhere.
                                reason=(
                                    "Quoted by the reviewer and matched against the "
                                    f"source at this line — reviewed by {review.model}"
                                    if verdict.line
                                    else "Quoted by the reviewer and confirmed present "
                                    f"in the component — reviewed by {review.model}"
                                ),
                            )
                        ],
                        confidence=_CONFIDENCE.get(verdict.confidence, Confidence.LOW),
                    )
                )
            else:
                findings.append(
                    self.ok(review.asset_id, f"Reviewed by {review.model}; nothing found.")
                )
        return findings


@register
class BehaviourManipulation(ReviewCheck):
    meta = _meta(
        "DYN-001",
        Severity.HIGH,
        (
            "The agent acts on the user's behalf while serving someone else's "
            "interest, and the user has no signal that it is happening."
        ),
        (
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
        ),
    )


@register
class ContextLeakage(ReviewCheck):
    meta = _meta(
        "DYN-002",
        Severity.HIGH,
        (
            "Conversation content and file contents reach a third party, which for an "
            "agent with repository access can mean source code and credentials."
        ),
        (
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-200: Exposure of Sensitive Information"),
        ),
    )


@register
class DeceptiveCapability(ReviewCheck):
    meta = _meta(
        "DYN-003",
        Severity.HIGH,
        (
            "Approval was given against the stated purpose, so the gap between what "
            "was described and what runs is capability the user never granted."
        ),
        (
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-1104: Use of Unmaintained Third Party Components"),
        ),
    )


@register
class CovertInstruction(ReviewCheck):
    meta = _meta(
        "DYN-004",
        Severity.HIGH,
        (
            "An instruction the reviewer never saw executes with the user's full "
            "session authority, on every turn that loads the component."
        ),
        (
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("CWE", "CWE-1427: Improper Neutralization of Input Used for LLM Prompting"),
        ),
    )


@register
class ExcessiveCapability(ReviewCheck):
    meta = _meta(
        "DYN-005",
        Severity.MEDIUM,
        (
            "Breadth beyond the task is what turns a single compromise into a "
            "general-purpose foothold."
        ),
        (
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-250: Execution with Unnecessary Privileges"),
        ),
    )
