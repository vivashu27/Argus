"""Section 3 — Skills checks (SKILL-001 … SKILL-010).

Skill bodies and any bundled scripts are analyzed as text. Skills are never invoked.
"""

from __future__ import annotations

from ..analysis import commands, injection, secrets
from ..analysis.paths import touches_sensitive
from ..core.models import (
    Asset,
    Category,
    CheckMeta,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Target,
)
from ..core.registry import register
from .base import Check, CheckContext

SKILLS_ONLY = frozenset({Target.SKILLS})


def _skills(context: CheckContext) -> list[Asset]:
    return context.by_target(Target.SKILLS)


def _all_text(asset: Asset) -> list[tuple[str, str]]:
    """Every text surface of a Skill: its body plus each bundled script."""
    surfaces: list[tuple[str, str]] = [(str(asset.path), asset.text or "")]
    for script in asset.data.get("scripts") or []:
        surfaces.append((script["path"], script["text"]))
    return surfaces


@register
class SkillShellExecution(Check):
    meta = CheckMeta(
        check_id="SKILL-001",
        title="Skill declares or scripts unrestricted shell execution",
        description="The Skill grants itself the Bash tool without argument scoping, or bundles a shell script.",
        category=Category.SKILLS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=SKILLS_ONLY,
        rationale=(
            "A Skill's allowed-tools frontmatter widens the agent's permissions while the "
            "Skill is active. An unscoped Bash grant there is equivalent to a global one "
            "for the duration."
        ),
        security_impact=(
            "Any instruction that activates the Skill — including one injected into a "
            "document the agent reads — gains shell access."
        ),
        remediation="Scope the grant to specific commands, e.g. 'Bash(pytest:*)'.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-78: Improper Neutralization of Special Elements used in an OS Command"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            tools = asset.data.get("allowed_tools") or []
            unscoped = [t for t in tools if t.strip() in ("Bash", "Bash(*)", "*")]
            if unscoped:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Skill grants unscoped shell execution via allowed-tools.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key="allowed-tools",
                                snippet=", ".join(unscoped),
                                reason="Grants every shell command while the Skill is active",
                            )
                        ],
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"No unscoped shell grant ({len(tools)} tool(s) declared).",
                    )
                )
        return findings


@register
class SkillSensitiveFilesystem(Check):
    meta = CheckMeta(
        check_id="SKILL-002",
        title="Skill accesses sensitive filesystem paths",
        description="Skill text or a bundled script references a known credential location.",
        category=Category.SKILLS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=SKILLS_ONLY,
        rationale="A Skill referencing ~/.ssh or ~/.aws is directing the agent at credentials.",
        security_impact="Credentials can be read into context and then transmitted anywhere the agent can reach.",
        remediation="Remove the credential path reference from the Skill.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            evidence = []
            doc_surfaces, all_surfaces = 0, 0
            for path, text in _all_text(asset):
                hits = []
                for lineno, line in enumerate(text.splitlines(), start=1):
                    hit, description = touches_sensitive(line)
                    if hit:
                        hits.append(
                            self.evidence(
                                path=path,
                                line=lineno,
                                snippet=line.strip()[:200],
                                reason=description,
                            )
                        )
                if hits:
                    all_surfaces += 1
                    if injection.is_security_document(text):
                        doc_surfaces += 1
                    evidence.extend(hits[:8])
            if evidence:
                # A pentest playbook documents credential paths by necessity. Report it,
                # but not at the same confidence as a Skill that actually reads them.
                documentation_only = all_surfaces > 0 and doc_surfaces == all_surfaces
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Skill references credential locations"
                        + (" (within security documentation)." if documentation_only else "."),
                        evidence[:8],
                        confidence=Confidence.LOW if documentation_only else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No credential path references."))
        return findings


@register
class SkillPromptInjection(Check):
    meta = CheckMeta(
        check_id="SKILL-003",
        title="Potential prompt injection in Skill content",
        description="Skill text contains language that would function as an injected instruction.",
        category=Category.SKILLS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=SKILLS_ONLY,
        rationale=(
            "Skill bodies are loaded directly into the model's context. Static analysis "
            "cannot establish intent, so this reports potential injection only."
        ),
        security_impact="An injected directive can redirect agent behaviour whenever the Skill activates.",
        remediation="Review the flagged lines and remove any directive that overrides operator instructions.",
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
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            matches = injection.scan_text(
                asset.data.get("body") or asset.text or "",
                line_offset=int(asset.data.get("body_offset") or 0),
            )
            actionable = [m for m in matches if m.is_actionable]
            if actionable:
                confidence = (
                    Confidence.HIGH
                    if any(m.confidence == "HIGH" for m in actionable)
                    else Confidence.MEDIUM
                )
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"Potential prompt injection detected — {len(actionable)} pattern(s) matched.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                line=m.line,
                                snippet=m.context,
                                reason=f"{m.description} ({m.confidence} confidence) — {m.recommendation}",
                            )
                            for m in actionable[:8]
                        ],
                        confidence=confidence,
                    )
                )
            elif matches:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        "Low-confidence injection-like phrasing found, likely documentation.",
                        [
                            self.evidence(path=asset.path, line=m.line, snippet=m.context,
                                          reason=m.description)
                            for m in matches[:4]
                        ],
                        confidence=Confidence.LOW,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No prompt-injection patterns detected."))
        return findings


@register
class SkillSecurityOverride(Check):
    meta = CheckMeta(
        check_id="SKILL-004",
        title="Skill attempts to override security instructions",
        description="Skill text instructs the agent to bypass permissions, approvals, or safety controls.",
        category=Category.SKILLS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=SKILLS_ONLY,
        rationale=(
            "This is the policy-subversion subset of injection patterns, separated because "
            "a Skill telling the agent to skip approvals is categorically different from "
            "general injection phrasing."
        ),
        security_impact="Neutralises the operator's configured permission model.",
        remediation="Remove the directive and review the Skill's provenance.",
        references=(
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("MITRE ATLAS", "AML.T0054: LLM Jailbreak"),
        ),
    )

    FAMILIES = ("policy_subversion", "concealment")

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            matches = [
                m
                for m in injection.scan_text(
                    asset.data.get("body") or asset.text or "",
                    line_offset=int(asset.data.get("body_offset") or 0),
                )
                if m.family in self.FAMILIES and m.is_actionable
            ]
            if matches:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Skill contains directives that would bypass security controls.",
                        [
                            self.evidence(path=asset.path, line=m.line, snippet=m.context,
                                          reason=f"{m.description} — {m.recommendation}")
                            for m in matches[:6]
                        ],
                        confidence=Confidence.HIGH
                        if any(m.confidence == "HIGH" for m in matches)
                        else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No security-override directives found."))
        return findings


@register
class SkillExternalInstructions(Check):
    meta = CheckMeta(
        check_id="SKILL-005",
        title="Skill references external untrusted instructions",
        description="The Skill directs the agent to load instructions or content from a remote URL.",
        category=Category.SKILLS,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=SKILLS_ONLY,
        rationale=(
            "Instructions fetched at runtime are not covered by any review of the Skill "
            "itself, and the remote content can change after approval."
        ),
        security_impact="Provides a channel for delivering new instructions post-review.",
        remediation="Vendor required content into the Skill directory and pin it.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("CWE", "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            text = asset.data.get("body") or asset.text or ""
            remote = [
                m
                for m in injection.scan_text(
                    text, line_offset=int(asset.data.get("body_offset") or 0)
                )
                if m.family == "remote_instruction" and m.is_actionable
            ]
            suspicious = [
                (line, host, url)
                for line, host, url in injection.extract_urls(text)
                if injection.is_suspicious_host(host)
            ]
            evidence = [
                self.evidence(path=asset.path, line=m.line, snippet=m.context,
                              reason=f"{m.description} — {m.recommendation}")
                for m in remote[:5]
            ] + [
                self.evidence(path=asset.path, line=line, snippet=url,
                              reason=f"{injection.classify_host(host)[1]} ({host})")
                for line, host, url in suspicious[:5]
            ]

            if evidence:
                documentation = injection.is_security_document(text)
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Skill sources content from an external location"
                        + (" (within security documentation)." if documentation else "."),
                        evidence,
                        confidence=Confidence.LOW if documentation else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No external instruction sources."))
        return findings


@register
class SkillEmbeddedSecrets(Check):
    meta = CheckMeta(
        check_id="SKILL-006",
        title="Skill contains embedded secrets",
        description="A credential literal appears in the Skill body or a bundled script.",
        category=Category.SKILLS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=SKILLS_ONLY,
        rationale=(
            "Skills are shared and version-controlled, so an embedded credential travels "
            "with every copy. Takes precedence over SECRET-* for Skill assets."
        ),
        security_impact="The credential is exposed to everyone with access to the Skill.",
        remediation="Remove the literal, read it from the environment instead, and rotate it.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-798: Use of Hard-coded Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            evidence = []
            highest = "MEDIUM"
            for path, text in _all_text(asset):
                for match in secrets.scan_text(text)[:6]:
                    evidence.append(
                        self.evidence(path=path, line=match.line, snippet=match.redacted,
                                      reason=match.description)
                    )
                    if match.confidence == "HIGH":
                        highest = "HIGH"
            if evidence:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(evidence)} credential literal(s) embedded in the Skill.",
                        evidence,
                        confidence=Confidence.HIGH if highest == "HIGH" else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No embedded credentials."))
        return findings


@register
class SkillNetworkAccess(Check):
    meta = CheckMeta(
        check_id="SKILL-007",
        title="Skill performs undeclared network access",
        description="Skill scripts make outbound network calls not reflected in allowed-tools.",
        category=Category.SKILLS,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=SKILLS_ONLY,
        rationale=(
            "Network access inside a bundled script bypasses the tool-permission model "
            "entirely, since the script runs as a subprocess rather than as a tool call."
        ),
        security_impact="Creates an egress path invisible to the agent's permission configuration.",
        remediation="Declare network use explicitly and route it through permission-gated tools.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            scripts = asset.data.get("scripts") or []
            if not scripts:
                findings.append(
                    self.not_applicable(asset.asset_id, "Skill bundles no executable scripts")
                )
                continue

            declared_network = any(
                t.split("(")[0] in ("WebFetch", "WebSearch") for t in asset.data.get("allowed_tools") or []
            )
            evidence = []
            for script in scripts:
                for match in commands.scan_text(script["text"], include_tier_c=True):
                    if match.threat.value in ("NETWORK_ACCESS", "DATA_EXFILTRATION"):
                        evidence.append(
                            self.evidence(path=script["path"], line=match.line,
                                          snippet=match.context, reason=match.description)
                        )
            if evidence and not declared_network:
                findings.append(
                    self.warn(asset.asset_id, "Bundled scripts perform undeclared network access.",
                              evidence[:6], confidence=Confidence.MEDIUM)
                )
            elif evidence:
                findings.append(
                    self.ok(asset.asset_id, "Network access is present and declared in allowed-tools.")
                )
            else:
                findings.append(self.ok(asset.asset_id, "No network access in bundled scripts."))
        return findings


@register
class SkillDangerousCommands(Check):
    meta = CheckMeta(
        check_id="SKILL-008",
        title="Skill contains dangerous commands",
        description="Skill text or scripts contain commands classified as dangerous.",
        category=Category.SKILLS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=SKILLS_ONLY,
        rationale=(
            "Tiered detection: Tier A patterns are dangerous in any context and fail "
            "outright; Tier B patterns fail only when combined with a credential path, "
            "remote endpoint, or interpolated input."
        ),
        security_impact="Skill activation can trigger destructive or remote-code-execution behaviour.",
        remediation="Remove the command or replace it with a scoped, non-destructive equivalent.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("CWE", "CWE-78: Improper Neutralization of Special Elements used in an OS Command"),
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            failing: list[Evidence] = []
            warning: list[Evidence] = []
            for path, text in _all_text(asset):
                for match in commands.scan_text(text):
                    item = self.evidence(
                        path=path,
                        line=match.line,
                        snippet=match.context,
                        reason=(
                            f"{match.description} [Tier {match.tier.value}, {match.threat.value}]"
                            + (f" — {match.escalation_reason}" if match.escalation_reason else "")
                        ),
                    )
                    (failing if match.is_failing else warning).append(item)

            if failing:
                findings.append(
                    self.fail(asset.asset_id, f"{len(failing)} dangerous command pattern(s) found.",
                              failing[:8])
                )
            elif warning:
                findings.append(
                    self.warn(asset.asset_id,
                              f"{len(warning)} command pattern(s) require review in context.",
                              warning[:6])
                )
            else:
                findings.append(self.ok(asset.asset_id, "No dangerous command patterns."))
        return findings


@register
class SkillCredentialDirectoryAccess(Check):
    meta = CheckMeta(
        check_id="SKILL-009",
        title="Skill scripts access credential directories",
        description="A bundled script reads from a credential directory at execution time.",
        category=Category.SKILLS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=SKILLS_ONLY,
        rationale=(
            "SKILL-002 covers references anywhere in the Skill; this narrows to executable "
            "scripts, where the access is an action rather than a mention."
        ),
        security_impact="Credentials are read by a subprocess outside the tool permission model.",
        remediation="Remove credential access from bundled scripts.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            scripts = asset.data.get("scripts") or []
            if not scripts:
                findings.append(
                    self.not_applicable(asset.asset_id, "Skill bundles no executable scripts")
                )
                continue
            evidence = []
            for script in scripts:
                for lineno, line in enumerate(script["text"].splitlines(), start=1):
                    hit, description = touches_sensitive(line)
                    if hit:
                        evidence.append(
                            self.evidence(path=script["path"], line=lineno,
                                          snippet=line.strip()[:200], reason=description)
                        )
            if evidence:
                findings.append(
                    self.fail(asset.asset_id, "Bundled scripts access credential directories.",
                              evidence[:8])
                )
            else:
                findings.append(self.ok(asset.asset_id, "Scripts do not access credential directories."))
        return findings


@register
class SkillExcessivePrivileges(Check):
    meta = CheckMeta(
        check_id="SKILL-010",
        title="Skill declares excessive tool privileges",
        description="The Skill's allowed-tools list is unbounded or unusually broad.",
        category=Category.SKILLS,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=SKILLS_ONLY,
        rationale=(
            "Distinct from SKILL-001, which is specifically about shell access: this "
            "measures the overall breadth of the grant."
        ),
        security_impact="Broad grants widen what an injection activating the Skill can reach.",
        remediation="Declare only the tools the Skill actually uses.",
        references=("https://docs.anthropic.com/en/docs/claude-code/skills",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-269: Improper Privilege Management"),
        ),
    )

    TOOL_BUDGET = 8
    WRITE_TOOLS = {"Write", "Edit", "NotebookEdit", "Bash"}

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _skills(context)
        if not assets:
            return self.no_assets("Skills")

        findings: list[Finding] = []
        for asset in assets:
            tools = asset.data.get("allowed_tools") or []
            if not tools:
                findings.append(
                    self.ok(asset.asset_id, "No tool grants declared — inherits session permissions.")
                )
                continue

            evidence = []
            if any(t.strip() in ("*", "all") for t in tools):
                evidence.append(
                    self.evidence(path=asset.path, key="allowed-tools", snippet=", ".join(tools),
                                  reason="Wildcard grants every available tool")
                )
            elif len(tools) > self.TOOL_BUDGET:
                write_grants = [t for t in tools if t.split("(")[0] in self.WRITE_TOOLS]
                evidence.append(
                    self.evidence(
                        path=asset.path, key="allowed-tools",
                        snippet=f"{len(tools)} tools ({len(write_grants)} mutating)",
                        reason=f"Exceeds the budget of {self.TOOL_BUDGET} declared tools",
                    )
                )

            if evidence:
                findings.append(
                    self.warn(asset.asset_id, "Skill declares a broad tool grant.", evidence)
                )
            else:
                findings.append(self.ok(asset.asset_id, f"Declares {len(tools)} tool(s), within budget."))
        return findings
