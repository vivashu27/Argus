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
