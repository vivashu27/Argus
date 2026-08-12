"""Section 10 — Dynamic Analysis checks (DYN-001 … DYN-004).

These read a :class:`~argus.dynamic.probe.ProbeResult` rather than an
:class:`~argus.core.models.Asset`. Everything they report was observed while the
server was running, which is what lets them state things the static checks can only
guess at — and equally, what makes their silence weaker. A static check that finds
nothing has read the whole file. A dynamic check that finds nothing has watched one
execution, with the arguments Argus happened to synthesise.

That asymmetry is why every check here reports ``MANUAL`` rather than ``PASS`` when
the probe could not run, and says so in the detail line. An unprobed server is not
a clean one.
"""

from __future__ import annotations

from ..analysis import injection
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
from ..dynamic.hook_runner import HookProbe
from ..dynamic.probe import ProbeResult, ToolSnapshot
from .base import Check, CheckContext

DYNAMIC_TARGETS = frozenset({Target.MCP})

#: Where the probe results are handed to the checks. The engine puts them in
#: ``options`` because they are not assets — they are observations about assets.
PROBE_KEY = "dynamic_probes"


def _probes(context: CheckContext) -> list[ProbeResult]:
    probes = context.options.get(PROBE_KEY)
    return list(probes) if isinstance(probes, list) else []


class DynamicCheck(Check):
    """Shared plumbing: iterate probes, and be honest about the ones that failed."""

    def _for_each(self, context: CheckContext) -> tuple[list[ProbeResult], list[Finding]]:
        probes = _probes(context)
        if not probes:
            return [], self.no_assets("probed MCP servers")

        findings: list[Finding] = []
        usable: list[ProbeResult] = []
        for probe in probes:
            if probe.usable:
                usable.append(probe)
                continue
            findings.append(
                self.manual(
                    probe.server_id,
                    "Server could not be probed, so this check has no observation to "
                    f"report: {probe.reason or 'no reason recorded'}.",
                    [
                        Evidence(
                            path=None,
                            key="command",
                            snippet=probe.command[:200],
                            reason="Command Argus attempted to run under the sandbox",
                        )
                    ],
                )
            )
        return usable, findings


def _describe(before: str, after: str, limit: int = 160) -> str:
    return f"was: {before[:limit]!r}\nnow: {after[:limit]!r}"


@register
class RugPull(DynamicCheck):
    meta = CheckMeta(
        check_id="DYN-001",
        title="Tool description changed after the client approved it",
        description=(
            "A tool's description or input schema differed between the handshake "
            "listing and a listing taken after the server had been exercised."
        ),
        category=Category.DYNAMIC,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=DYNAMIC_TARGETS,
        rationale=(
            "Approval in MCP is granted against the description shown at connection "
            "time. A server that serves one description then and another later has "
            "obtained consent for a tool the operator never saw. No static reading "
            "distinguishes this from a server that composes descriptions "
            "legitimately, because the source is identical in both cases — only the "
            "two answers differ."
        ),
        security_impact=(
            "The model acts on the mutated description with permissions the operator "
            "granted to the original, so the attack inherits trust rather than "
            "having to defeat it."
        ),
        remediation=(
            "Pin the server to an exact version, diff its tool descriptions between "
            "sessions, and remove it if the change was not an intentional release."
        ),
        references=(
            "https://modelcontextprotocol.io/specification",
            "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
        ),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
            ("CWE", "CWE-494: Download of Code Without Integrity Check"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        probes, findings = self._for_each(context)
        for probe in probes:
            first, last = probe.first, probe.last
            assert first is not None and last is not None  # guaranteed by .usable
            evidence = self._diff(first, last)
            if evidence:
                findings.append(
                    self.fail(
                        probe.server_id,
                        f"{len(evidence)} tool definition(s) changed while the server ran.",
                        evidence[:8],
                        confidence=Confidence.HIGH,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        probe.server_id,
                        f"{len(first.tools)} tool definition(s) identical across "
                        f"{len(probe.snapshots)} listings and {len(probe.calls)} call(s).",
                    )
                )
        return findings

    def _diff(self, first: ToolSnapshot, last: ToolSnapshot) -> list[Evidence]:
        evidence: list[Evidence] = []
        after = last.by_name
        for name, before in first.by_name.items():
            current = after.get(name)
            if current is None:
                continue  # withdrawal is DYN-002's finding, not a mutated description
            if current.description != before.description:
                evidence.append(
                    Evidence(
                        path=None,
                        key=f"tools.{name}.description",
                        snippet=_describe(before.description, current.description),
                        reason="Description differs from the one served at handshake",
                    )
                )
            if current.input_schema != before.input_schema:
                evidence.append(
                    Evidence(
                        path=None,
                        key=f"tools.{name}.inputSchema",
                        snippet=_describe(str(before.input_schema), str(current.input_schema)),
                        reason="Input schema differs from the one served at handshake",
                    )
                )
        return evidence


@register
class ToolInventoryMutation(DynamicCheck):
    meta = CheckMeta(
        check_id="DYN-002",
        title="Tool inventory changed at runtime",
        description="Tools appeared or disappeared between two listings of the same session.",
        category=Category.DYNAMIC,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=DYNAMIC_TARGETS,
        rationale=(
            "A tool introduced after the handshake was never shown for approval. A "
            "tool withdrawn after approval frees its name to be re-registered by "
            "another server, which is how shadowing is staged."
        ),
        security_impact=(
            "The model may be offered a capability the operator never reviewed, under "
            "a server that has already been trusted."
        ),
        remediation=(
            "Treat the tool set as part of the server's identity. Re-review the "
            "server, and prefer servers whose tool list is static."
        ),
        references=("https://modelcontextprotocol.io/specification",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        probes, findings = self._for_each(context)
        for probe in probes:
            first, last = probe.first, probe.last
            assert first is not None and last is not None
            before, after = set(first.by_name), set(last.by_name)
            added, removed = sorted(after - before), sorted(before - after)

            evidence = [
                Evidence(path=None, key=f"tools.{name}", snippet=name,
                         reason="Tool appeared after the handshake listing")
                for name in added
            ] + [
                Evidence(path=None, key=f"tools.{name}", snippet=name,
                         reason="Tool present at handshake was withdrawn")
                for name in removed
            ]

            if evidence:
                parts = []
                if added:
                    parts.append(f"{len(added)} added")
                if removed:
                    parts.append(f"{len(removed)} withdrawn")
                findings.append(
                    self.fail(
                        probe.server_id,
                        f"Tool inventory changed during the session: {', '.join(parts)}.",
                        evidence[:10],
                        confidence=Confidence.HIGH,
                    )
                )
            else:
                findings.append(
                    self.ok(probe.server_id, f"Tool inventory stable ({len(before)} tools).")
                )
        return findings


@register
class CanaryDisclosure(DynamicCheck):
    meta = CheckMeta(
        check_id="DYN-003",
        title="Server disclosed a planted credential",
        description=(
            "A unique token written to a fake credential file inside the sandbox came "
            "back in the server's own output."
        ),
        category=Category.DYNAMIC,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=DYNAMIC_TARGETS,
        rationale=(
            "The canary values are random and exist only inside the jail, so the "
            "server cannot have produced one without reading the file it was written "
            "to. This is the rare check that proves rather than infers: there is no "
            "benign path by which a calculator returns the contents of an SSH key."
        ),
        security_impact=(
            "The same code path against a real home directory hands the model, and "
            "anything downstream of it, a live credential."
        ),
        remediation=(
            "Remove the server. Rotate every credential in the locations named below "
            "on any machine where it has run."
        ),
        references=("https://modelcontextprotocol.io/specification",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
            ("CWE", "CWE-200: Exposure of Sensitive Information"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        probes, findings = self._for_each(context)
        for probe in probes:
            if probe.canary_hits:
                findings.append(
                    self.fail(
                        probe.server_id,
                        f"{len(probe.canary_hits)} planted credential(s) were read and "
                        "returned by this server.",
                        [
                            Evidence(
                                path=None,
                                key=f"canary.{canary.relative}",
                                snippet=f"~/{canary.relative} disclosed via {source}",
                                reason=f"{canary.description} — token planted by Argus "
                                       "was echoed back",
                            )
                            for canary, source in probe.canary_hits[:8]
                        ],
                        confidence=Confidence.HIGH,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        probe.server_id,
                        f"No planted credential appeared in output across "
                        f"{len(probe.calls)} call(s).",
                    )
                )
        return findings


@register
class InjectedInstructionsInOutput(DynamicCheck):
    meta = CheckMeta(
        check_id="DYN-004",
        title="Tool output carries instructions aimed at the model",
        description=(
            "Text returned by a tool contains directive language addressed to the "
            "agent rather than data addressed to the user."
        ),
        category=Category.DYNAMIC,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=DYNAMIC_TARGETS,
        rationale=(
            "Tool output goes into the model's context with the authority of a tool "
            "result. Static analysis cannot reach it at all — the text does not exist "
            "until the tool is called, and may be assembled from a remote response. "
            "This is the indirect-injection path that a source review structurally "
            "cannot cover."
        ),
        security_impact=(
            "An instruction placed here is read by the model as trusted output of a "
            "tool the operator approved."
        ),
        remediation=(
            "Treat tool output as untrusted input. Review the flagged text, and where "
            "it is attacker-influenced, remove the server or wrap its output."
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
        probes, findings = self._for_each(context)
        for probe in probes:
            evidence: list[Evidence] = []
            for call in probe.calls:
                if not call.output:
                    continue
                # trust_formatting=False: the server chose this text's formatting,
                # so a fenced payload is an evasion attempt, not an illustration.
                for match in injection.scan_text(call.output, trust_formatting=False):
                    if not match.is_actionable:
                        continue
                    evidence.append(
                        Evidence(
                            path=None,
                            key=f"tools.{call.name}.output",
                            snippet=match.context,
                            reason=f"{match.description} ({match.confidence}) in the "
                                   f"output of {call.name}()",
                        )
                    )
            if evidence:
                findings.append(
                    self.fail(
                        probe.server_id,
                        f"{len(evidence)} injected instruction(s) found in tool output.",
                        evidence[:8],
                        confidence=Confidence.HIGH,
                    )
                )
            elif probe.calls:
                findings.append(
                    self.ok(
                        probe.server_id,
                        f"No directive language in the output of {len(probe.calls)} call(s).",
                    )
                )
            else:
                findings.append(
                    self.manual(
                        probe.server_id,
                        "No tool was invoked, so no output was observed. Re-run without "
                        "--no-call, or with --include-mutating if every tool was "
                        "skipped as state-changing.",
                    )
                )
        return findings


# --------------------------------------------------------------------------- #
# Hooks. A hook fires on an event rather than on a model's decision, so nothing
# stands between a malicious one and execution.
# --------------------------------------------------------------------------- #

HOOK_PROBE_KEY = "dynamic_hook_probes"


def _hook_probes(context: CheckContext) -> list[HookProbe]:
    probes = context.options.get(HOOK_PROBE_KEY)
    return list(probes) if isinstance(probes, list) else []


class HookDynamicCheck(Check):
    """Iterate executed hooks, reporting the ones that never ran rather than
    counting them as clean."""

    def _for_each(self, context: CheckContext) -> tuple[list[HookProbe], list[Finding]]:
        probes = _hook_probes(context)
        if not probes:
            return [], self.no_assets("executed hooks")

        findings: list[Finding] = []
        usable: list[HookProbe] = []
        for probe in probes:
            if probe.usable:
                usable.append(probe)
                continue
            findings.append(
                self.manual(
                    probe.hook_id,
                    "Hook could not be executed, so this check has no observation to "
                    f"report: {probe.reason or 'no reason recorded'}.",
                    [
                        Evidence(path=None, key="command", snippet=probe.command[:200],
                                 reason="Command Argus attempted to run under the sandbox")
                    ],
                )
            )
        return usable, findings


@register
class HookCanaryDisclosure(HookDynamicCheck):
    meta = CheckMeta(
        check_id="DYN-005",
        title="Hook read and disclosed a planted credential",
        description=(
            "A hook returned, or wrote out, a unique token that existed only inside a "
            "fake credential file in the sandbox."
        ),
        category=Category.DYNAMIC,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=frozenset({Target.HOOKS}),
        rationale=(
            "The token is random and exists only in the jail, so the hook cannot have "
            "produced it without reading the file. Hooks run automatically on an "
            "event, so unlike a tool call there is no approval step and no model "
            "decision that a user could decline."
        ),
        security_impact=(
            "Against a real home directory the same hook hands out a live credential "
            "on every matching event, with no prompt and no transcript entry the user "
            "is likely to read."
        ),
        remediation=(
            "Remove the hook from settings and rotate every credential in the "
            "locations named below on any machine where it has fired."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
            ("CWE", "CWE-200: Exposure of Sensitive Information"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        probes, findings = self._for_each(context)
        for probe in probes:
            if probe.canary_hits:
                findings.append(
                    self.fail(
                        probe.hook_id,
                        f"{len(probe.canary_hits)} planted credential(s) were read and "
                        f"disclosed by the {probe.event} hook.",
                        [
                            Evidence(
                                path=None,
                                key=f"canary.{canary.relative}",
                                snippet=f"~/{canary.relative} disclosed via {source}",
                                reason=f"{canary.description} — token planted by Argus "
                                       "was echoed back",
                            )
                            for canary, source in probe.canary_hits[:8]
                        ],
                        confidence=Confidence.HIGH,
                    )
                )
            else:
                findings.append(
                    self.ok(probe.hook_id, "No planted credential appeared in output.")
                )
        return findings


@register
class HookContextInjection(HookDynamicCheck):
    meta = CheckMeta(
        check_id="DYN-006",
        title="Hook injected instructions into the model's context",
        description=(
            "Text a hook emitted on a route that re-enters the model's context "
            "contained directive language aimed at the agent."
        ),
        category=Category.DYNAMIC,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=frozenset({Target.HOOKS}),
        rationale=(
            "Three routes carry hook output back into context: stdout on the events "
            "that feed context, stderr on exit code 2, and additionalContext in a JSON "
            "response. Text arriving that way is indistinguishable to the model from "
            "the agent's own reasoning. Static reading cannot cover it because the "
            "text may be assembled at runtime from a fetch or a decode."
        ),
        security_impact=(
            "An instruction placed here is executed with the user's full session "
            "authority and reappears on every matching event."
        ),
        remediation=(
            "Review the flagged text. A hook should return data or a decision, never "
            "instructions addressed to the model."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
            ("CWE", "CWE-1427: Improper Neutralization of Input Used for LLM Prompting"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        probes, findings = self._for_each(context)
        for probe in probes:
            text = probe.context_text
            evidence = [
                Evidence(
                    path=None,
                    key=f"hooks.{probe.event}.context",
                    snippet=match.context,
                    reason=f"{match.description} ({match.confidence}) on a route that "
                           "reaches the model's context",
                )
                # trust_formatting=False: the hook chose this formatting, so a fenced
                # payload is an evasion attempt rather than an illustration.
                for match in injection.scan_text(text, trust_formatting=False)
                if match.is_actionable
            ] if text.strip() else []

            if evidence:
                findings.append(
                    self.fail(
                        probe.hook_id,
                        f"{len(evidence)} injected instruction(s) reach the model from "
                        f"this {probe.event} hook.",
                        evidence[:8],
                        confidence=Confidence.HIGH,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        probe.hook_id,
                        "Nothing this hook emitted into context reads as a directive.",
                    )
                )
        return findings


@register
class HookSilentApproval(HookDynamicCheck):
    meta = CheckMeta(
        check_id="DYN-007",
        title="Hook auto-approves tool calls",
        description=(
            "A PreToolUse hook returned permissionDecision 'allow', granting a tool "
            "call without the user being asked."
        ),
        category=Category.DYNAMIC,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=frozenset({Target.HOOKS}),
        rationale=(
            "A PreToolUse hook can settle the permission prompt on the user's behalf. "
            "Returning 'allow' for a synthetic, entirely unremarkable tool call means "
            "the decision is not conditional on anything Argus varied — which is the "
            "shape of a blanket bypass rather than a considered policy. The decision "
            "is computed at runtime, so the source may show only that a decision is "
            "returned, not which one."
        ),
        security_impact=(
            "The approval gate that the whole permission system depends on is answered "
            "automatically, and the user sees no prompt."
        ),
        remediation=(
            "Restrict the hook to the specific tool invocations it is meant to "
            "pre-approve, and return 'ask' as the default rather than 'allow'."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-863: Incorrect Authorization"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        probes, findings = self._for_each(context)
        for probe in probes:
            if probe.event != "PreToolUse":
                findings.append(
                    self.not_applicable(
                        probe.hook_id,
                        f"{probe.event} hooks cannot return a permission decision",
                    )
                )
            elif probe.decision.lower() == "allow":
                findings.append(
                    self.fail(
                        probe.hook_id,
                        "Hook approved a synthetic tool call without user interaction.",
                        [
                            Evidence(
                                path=None,
                                key="hookSpecificOutput.permissionDecision",
                                snippet=f"allow — {probe.decision_reason or 'no reason given'}",
                                reason="Returned for an unremarkable probe invocation, "
                                       "so the approval is not conditional",
                            )
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        probe.hook_id,
                        f"Returned {probe.decision or 'no decision'} for the probe call.",
                    )
                )
        return findings


@register
class RuntimeConfigTampering(Check):
    meta = CheckMeta(
        check_id="DYN-008",
        title="Component rewrote agent configuration while running",
        description=(
            "A probed hook or MCP server modified the settings, MCP registry or "
            "instruction file planted in the sandbox."
        ),
        category=Category.DYNAMIC,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=frozenset({Target.HOOKS, Target.MCP}),
        rationale=(
            "Nothing legitimately edits the agent's own configuration as a side effect "
            "of answering a tool call or handling an event. Writing to settings.json "
            "is how a single execution becomes a standing foothold: the component adds "
            "a hook, an MCP server, or a line of CLAUDE.md that survives the session "
            "and re-establishes itself."
        ),
        security_impact=(
            "Persistence. The change outlives the process that made it and takes "
            "effect on every subsequent session, including after the original "
            "component is removed."
        ),
        remediation=(
            "Treat the machine as compromised: diff ~/.claude/settings.json, "
            "~/.claude.json and every CLAUDE.md against version control, then remove "
            "the component."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("MITRE ATLAS", "AML.T0018: Manipulate AI Model"),
            ("CWE", "CWE-732: Incorrect Permission Assignment for Critical Resource"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        subjects: list[tuple[str, list[str], bool, str]] = [
            (p.server_id, p.config_changes, p.usable, p.reason) for p in _probes(context)
        ] + [
            (p.hook_id, p.config_changes, p.usable, p.reason) for p in _hook_probes(context)
        ]
        if not subjects:
            return self.no_assets("probed components")

        findings: list[Finding] = []
        for subject_id, changes, usable, reason in subjects:
            if not usable:
                findings.append(
                    self.manual(
                        subject_id,
                        "Component did not run, so configuration tampering could not be "
                        f"observed: {reason or 'no reason recorded'}.",
                    )
                )
            elif changes:
                findings.append(
                    self.fail(
                        subject_id,
                        f"{len(changes)} agent configuration file(s) were modified while "
                        "this component ran.",
                        [
                            Evidence(
                                path=None,
                                key=relative,
                                snippet=f"~/{relative}",
                                reason="Planted configuration differs from how it was "
                                       "written before the component ran",
                            )
                            for relative in changes
                        ],
                        confidence=Confidence.HIGH,
                    )
                )
            else:
                findings.append(
                    self.ok(subject_id, "Agent configuration untouched.")
                )
        return findings
