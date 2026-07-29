"""Section 6 — Instruction Files checks (INSTR-001 … INSTR-005).

Instruction files enter the model's context on every turn, which makes them the
highest-leverage injection surface in an agent environment. Findings here never
assert intent — the wording is always "potential".
"""

from __future__ import annotations

from ..analysis import injection, secrets
from ..core.models import (
    Asset,
    Category,
    CheckMeta,
    Confidence,
    Finding,
    Severity,
    Target,
)
from ..core.registry import register
from .base import Check, CheckContext

INSTRUCTIONS_ONLY = frozenset({Target.INSTRUCTIONS})


def _instruction_assets(context: CheckContext) -> list[Asset]:
    return context.by_target(Target.INSTRUCTIONS)


@register
class InstructionSecrets(Check):
    meta = CheckMeta(
        check_id="INSTR-001",
        title="Secrets in instruction files",
        description="A credential literal appears in CLAUDE.md or another instruction file.",
        category=Category.INSTRUCTIONS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=INSTRUCTIONS_ONLY,
        rationale=(
            "Instruction files are read into context on every turn and are usually "
            "committed to version control, so a credential here is both persistently "
            "exposed to the model and shared with everyone who clones the repository. "
            "Takes precedence over SECRET-* for instruction assets."
        ),
        security_impact=(
            "The credential is available to the model on every request and to anyone with "
            "repository access, and it may be reproduced in model output."
        ),
        remediation="Remove the credential, reference it from the environment, and rotate it.",
        references=("https://docs.anthropic.com/en/docs/claude-code/memory",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-798: Use of Hard-coded Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _instruction_assets(context)
        if not assets:
            return self.no_assets("instruction files")

        findings: list[Finding] = []
        for asset in assets:
            matches = secrets.scan_text(asset.text or "")
            if matches:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(matches)} credential literal(s) found in the instruction file.",
                        [
                            self.evidence(path=asset.path, line=m.line, snippet=m.redacted,
                                          reason=m.description)
                            for m in matches[:8]
                        ],
                        confidence=Confidence.HIGH
                        if any(m.confidence == "HIGH" for m in matches)
                        else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No credential literals found."))
        return findings


@register
class InstructionExternalSource(Check):
    meta = CheckMeta(
        check_id="INSTR-002",
        title="Instructions sourced from an external location",
        description="The file directs the agent to fetch instructions or content from a remote URL.",
        category=Category.INSTRUCTIONS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=INSTRUCTIONS_ONLY,
        rationale=(
            "Remote instruction sources are not covered by review of the file itself, and "
            "their contents can change silently after approval."
        ),
        security_impact=(
            "An attacker controlling the remote resource can deliver new instructions to "
            "every session that loads this file."
        ),
        remediation="Inline the required content into the instruction file and pin it in version control.",
        references=("https://docs.anthropic.com/en/docs/claude-code/memory",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("CWE", "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _instruction_assets(context)
        if not assets:
            return self.no_assets("instruction files")

        findings: list[Finding] = []
        for asset in assets:
            matches = [
                m
                for m in injection.scan_text(asset.text or "")
                if m.family == "remote_instruction" and m.is_actionable
            ]
            if matches:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Instruction file loads content from an external source.",
                        [
                            self.evidence(path=asset.path, line=m.line, snippet=m.context,
                                          reason=f"{m.description} — {m.recommendation}")
                            for m in matches[:6]
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No external instruction sources."))
        return findings


@register
class InstructionUnrestrictedExecution(Check):
    meta = CheckMeta(
        check_id="INSTR-003",
        title="Instructions granting unrestricted command execution",
        description="The file tells the agent to run commands freely or without confirmation.",
        category=Category.INSTRUCTIONS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=INSTRUCTIONS_ONLY,
        rationale=(
            "Instruction files influence model behaviour but carry no enforcement. A "
            "directive to skip confirmation encourages the model to route around the "
            "operator's approval gate."
        ),
        security_impact="Erodes the human review step that the permission system depends on.",
        remediation="Remove blanket execution directives and rely on the permission configuration.",
        references=("https://docs.anthropic.com/en/docs/claude-code/memory",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-250: Execution with Unnecessary Privileges"),
        ),
    )

    FAMILIES = ("policy_subversion",)

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _instruction_assets(context)
        if not assets:
            return self.no_assets("instruction files")

        findings: list[Finding] = []
        for asset in assets:
            matches = [
                m
                for m in injection.scan_text(asset.text or "")
                if m.family in self.FAMILIES and m.is_actionable
            ]
            if matches:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Instruction file contains directives that weaken execution controls.",
                        [
                            self.evidence(path=asset.path, line=m.line, snippet=m.context,
                                          reason=f"{m.description} — {m.recommendation}")
                            for m in matches[:6]
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No unrestricted execution directives."))
        return findings


@register
class InstructionPromptInjection(Check):
    meta = CheckMeta(
        check_id="INSTR-004",
        title="Potential prompt injection in instruction file",
        description="The file contains language that would function as an injected instruction.",
        category=Category.INSTRUCTIONS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=INSTRUCTIONS_ONLY,
        rationale=(
            "Static analysis cannot establish intent, so this reports potential injection. "
            "Matches inside code fences, blockquotes, or explicitly labelled examples are "
            "downgraded, because security documentation legitimately quotes these phrases."
        ),
        security_impact=(
            "An injected directive persists across every session that loads the file, "
            "making it far more durable than a single-turn injection."
        ),
        remediation=(
            "Review each flagged line. If it is illustrative, move it into a fenced code "
            "block; if it is a live directive, remove it and review file write access."
        ),
        references=(
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
            ("CWE", "CWE-1427: Improper Neutralization of Input Used for LLM Prompting"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _instruction_assets(context)
        if not assets:
            return self.no_assets("instruction files")

        findings: list[Finding] = []
        for asset in assets:
            matches = injection.scan_text(asset.text or "")
            high = [m for m in matches if m.is_actionable and m.confidence == "HIGH"]
            medium = [m for m in matches if m.is_actionable and m.confidence == "MEDIUM"]
            low = [m for m in matches if not m.is_actionable]

            if high or medium:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"Potential prompt injection detected — {len(high) + len(medium)} "
                        "pattern(s) matched outside documentation context.",
                        [
                            self.evidence(path=asset.path, line=m.line, snippet=m.context,
                                          reason=f"{m.description} ({m.confidence}) — {m.recommendation}")
                            for m in (high + medium)[:8]
                        ],
                        confidence=Confidence.HIGH if high else Confidence.MEDIUM,
                    )
                )
            elif low:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        f"{len(low)} injection-like phrase(s) found in documentation context.",
                        [
                            self.evidence(path=asset.path, line=m.line, snippet=m.context,
                                          reason=f"{m.description} — discounted: {m.discount_reason or 'illustrative'}")
                            for m in low[:5]
                        ],
                        confidence=Confidence.LOW,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No prompt-injection patterns detected."))
        return findings


@register
class InstructionUntrustedUrls(Check):
    meta = CheckMeta(
        check_id="INSTR-005",
        title="Instruction file references untrusted URLs",
        description="The file links to disposable hosting, tunnelling, or request-collector domains.",
        category=Category.INSTRUCTIONS,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=INSTRUCTIONS_ONLY,
        rationale=(
            "A URL in an instruction file is a candidate destination for agent fetches. "
            "Well-known documentation and package hosts are allowlisted to keep the false "
            "positive rate usable."
        ),
        security_impact=(
            "Fetching such a URL can pull attacker-controlled content into context, or "
            "signal to an external collector that the agent ran."
        ),
        remediation="Replace with a vetted domain, or remove the reference.",
        references=("https://docs.anthropic.com/en/docs/claude-code/memory",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("CWE", "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _instruction_assets(context)
        if not assets:
            return self.no_assets("instruction files")

        findings: list[Finding] = []
        for asset in assets:
            urls = injection.extract_urls(asset.text or "")
            suspicious = [(line, host, url) for line, host, url in urls if injection.is_suspicious_host(host)]
            if suspicious:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(suspicious)} untrusted URL(s) referenced.",
                        [
                            self.evidence(path=asset.path, line=line, snippet=url,
                                          reason=f"{injection.classify_host(host)[1]} ({host})")
                            for line, host, url in suspicious[:8]
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, f"{len(urls)} URL(s) referenced, none untrusted.")
                )
        return findings
