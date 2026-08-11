"""Section 5 — Hooks checks (HOOK-001 … HOOK-006).

These are the redefined hooks checks (spec 5.5). The original HOOK-001/HOOK-002
("PreToolUse/PostToolUse hook executes commands") described what a hook *is*, so
they would have fired on every hook in existence. They are replaced with checks
that distinguish a risky hook from an ordinary one.
"""

from __future__ import annotations

import re

from ..analysis import commands, injection
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

HOOKS_ONLY = frozenset({Target.HOOKS})


def _hooks(context: CheckContext) -> list[Asset]:
    return context.by_target(Target.HOOKS)


def _hook_text(asset: Asset) -> str:
    return asset.text or asset.data.get("command") or ""


#: Reaching one of these while scanning backwards means the interpolation sits bare
#: on the command line rather than inside a double-quoted word.
_BARE_BOUNDARY = frozenset(" \t\n(;&|<>")

_ASSIGNED_NAME = re.compile(r"([A-Za-z_]\w*)=$")


def _quoting(command: str, start: int) -> str:
    """How the interpolation at ``start`` is embedded: quoted, assignment, or bare.

    Scanning backwards to the nearest quote or word boundary answers the question the
    finding actually depends on — is *this* value shell-split — rather than whether
    the command quotes something, anything, somewhere.
    """
    index = start - 1
    while index >= 0:
        char = command[index]
        if char == '"':
            return "quoted"
        if char == "=":
            # ``name=$(...)`` never word-splits in any POSIX shell, so the capture
            # itself is safe. Whether the value is dangerous depends on how the
            # variable is later used, which the caller follows up separately.
            return "assignment"
        if char in _BARE_BOUNDARY:
            return "bare"
        index -= 1
    return "bare"


def _bare_interpolations(command: str, agent_input: re.Pattern[str]) -> list[str]:
    """Agent-controlled values that reach the command line unquoted.

    Follows one level of indirection: a value captured into a variable is traced to
    that variable's own uses, because ``file=$(jq ...)`` followed by an unquoted
    ``$file`` is the same hazard written in two steps.
    """
    bare: list[str] = []
    assigned: set[str] = set()

    for match in agent_input.finditer(command):
        placement = _quoting(command, match.start())
        if placement == "bare":
            bare.append(match.group(0)[:60])
        elif placement == "assignment":
            name = _ASSIGNED_NAME.search(command[: match.start()])
            if name:
                assigned.add(name.group(1))

    for variable in sorted(assigned):
        for use in re.finditer(rf"\$\{{?{re.escape(variable)}\}}?(?!\w)", command):
            is_reassignment = use.start() > 0 and command[use.start() - 1] == "="
            if not is_reassignment and _quoting(command, use.start()) == "bare":
                bare.append(use.group(0))
                break

    return bare


@register
class HookUnvalidatedInterpolation(Check):
    meta = CheckMeta(
        check_id="HOOK-001",
        title="Hook interpolates unvalidated agent-controlled input into a shell command",
        description=(
            "The hook command embeds agent-supplied values — tool arguments, prompt text, "
            "or file paths — directly into a shell string."
        ),
        category=Category.HOOKS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=HOOKS_ONLY,
        rationale=(
            "Executing a command is what a hook does and is not itself a finding. The risk "
            "is interpolation: hook payloads carry model-influenced data, so embedding "
            "them in a shell string without quoting creates command injection reachable "
            "from anything that can steer the model."
        ),
        security_impact=(
            "A crafted filename or prompt fragment can break out of the intended command "
            "and execute attacker-chosen code on every matching event."
        ),
        remediation=(
            "Read the hook payload from stdin as JSON in a script, quote every "
            "interpolation, and never build a shell string from tool input."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("CWE", "CWE-78: Improper Neutralization of Special Elements used in an OS Command"),
            ("OWASP LLM Top 10 2025", "LLM05: Improper Output Handling"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
        ),
    )

    #: Variables carrying agent-controlled data.
    AGENT_INPUT = re.compile(
        r"\$\{?(?:CLAUDE_TOOL_\w+|CLAUDE_FILE_\w+|TOOL_INPUT|TOOL_ARGS|USER_PROMPT|"
        r"CLAUDE_PROMPT|FILE_PATH|CLAUDE_NOTIFICATION)\}?|"
        r"\$\(\s*jq[^)]*\)|`[^`]*jq[^`]*`",
        re.I,
    )
    def run(self, context: CheckContext) -> list[Finding]:
        assets = _hooks(context)
        if not assets:
            return self.no_assets("hooks")

        findings: list[Finding] = []
        for asset in assets:
            command = asset.data.get("command") or ""
            if not self.AGENT_INPUT.search(command):
                findings.append(
                    self.ok(asset.asset_id, "Hook command interpolates no agent-controlled input.")
                )
                continue

            bare = _bare_interpolations(command, self.AGENT_INPUT)
            evidence = [
                self.evidence(
                    path=asset.path,
                    asset=asset,
                    key=f"hooks.{asset.data.get('event')}.command",
                    snippet=command[:200],
                    reason=(
                        f"Agent-controlled value reaches the command line unquoted: {bare[0]}"
                        if bare
                        else "Agent-controlled value interpolated, but every use is quoted"
                    ),
                )
            ]
            if bare:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Hook builds a shell command from agent-controlled input without quoting.",
                        evidence,
                        confidence=Confidence.HIGH,
                    )
                )
            else:
                # A quoted interpolation does not word-split and cannot start a new
                # command, so this is not injection. Formatter hooks that quote
                # correctly are ordinary practice and must not be reported as an
                # incident — but the hook does handle model-influenced data, which is
                # worth a reviewer's attention.
                findings.append(
                    self.warn(
                        asset.asset_id,
                        "Hook passes agent-controlled input to a shell command, quoted.",
                        evidence,
                        confidence=Confidence.MEDIUM,
                    )
                )
        return findings


@register
class HookBroadMatcher(Check):
    meta = CheckMeta(
        check_id="HOOK-002",
        title="Hook registered with an overly broad matcher",
        description="A PreToolUse or PostToolUse hook matches every tool call.",
        category=Category.HOOKS,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=HOOKS_ONLY,
        rationale=(
            "A wildcard matcher runs the hook on every tool invocation, multiplying both "
            "its blast radius and the amount of agent data it observes."
        ),
        security_impact=(
            "A hook that sees every tool call sees every file path, command, and result — "
            "an ideal position for surveillance or tampering."
        ),
        remediation="Restrict the matcher to the specific tools the hook needs to observe.",
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-732: Incorrect Permission Assignment for Critical Resource"),
        ),
    )

    BROAD_MATCHERS = {"*", ".*", "", "**", "all"}
    TOOL_EVENTS = {"PreToolUse", "PostToolUse"}

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _hooks(context)
        if not assets:
            return self.no_assets("hooks")

        findings: list[Finding] = []
        for asset in assets:
            event = asset.data.get("event") or ""
            matcher = str(asset.data.get("matcher") or "").strip()
            if event not in self.TOOL_EVENTS:
                findings.append(
                    self.not_applicable(asset.asset_id, f"'{event}' hooks do not take a tool matcher")
                )
                continue
            if matcher in self.BROAD_MATCHERS:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        f"{event} hook matches every tool call.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"hooks.{event}.matcher",
                                snippet=matcher or "(empty)",
                                reason="Wildcard or empty matcher applies to all tools",
                            )
                        ],
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, f"{event} hook is scoped to matcher '{matcher}'.")
                )
        return findings


@register
class HookDangerousCommand(Check):
    meta = CheckMeta(
        check_id="HOOK-003",
        title="Hook executes a dangerous command",
        description="The hook command or its resolved script contains a dangerous command pattern.",
        category=Category.HOOKS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=HOOKS_ONLY,
        rationale=(
            "Hooks run automatically and are not surfaced for per-invocation approval, so "
            "a dangerous command in one executes without review."
        ),
        security_impact="Provides automatic, unattended execution of destructive or remote-code operations.",
        remediation="Remove the dangerous command or gate it behind an explicit confirmation.",
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("CWE", "CWE-78: Improper Neutralization of Special Elements used in an OS Command"),
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _hooks(context)
        if not assets:
            return self.no_assets("hooks")

        findings: list[Finding] = []
        for asset in assets:
            failing: list[Evidence] = []
            warning: list[Evidence] = []
            for match in commands.scan_text(_hook_text(asset)):
                item = self.evidence(
                    path=asset.data.get("script_path") or asset.path,
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
                    self.fail(asset.asset_id, "Hook executes a dangerous command.", failing[:6])
                )
            elif warning:
                findings.append(
                    self.warn(asset.asset_id, "Hook command requires review in context.", warning[:4])
                )
            else:
                findings.append(self.ok(asset.asset_id, "No dangerous command patterns in hook."))
        return findings


@register
class HookSensitiveFileAccess(Check):
    meta = CheckMeta(
        check_id="HOOK-004",
        title="Hook reads or writes sensitive files",
        description="The hook references a known credential location.",
        category=Category.HOOKS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=HOOKS_ONLY,
        rationale="A hook touching credential paths does so automatically on every matching event.",
        security_impact="Enables silent, repeated credential access with no tool call to review.",
        remediation="Remove credential path access from the hook.",
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _hooks(context)
        if not assets:
            return self.no_assets("hooks")

        findings: list[Finding] = []
        for asset in assets:
            evidence = []
            for lineno, line in enumerate(_hook_text(asset).splitlines(), start=1):
                hit, description = touches_sensitive(line)
                if hit:
                    evidence.append(
                        self.evidence(
                            path=asset.data.get("script_path") or asset.path,
                            line=lineno,
                            snippet=line.strip()[:200],
                            reason=description,
                        )
                    )
            if evidence:
                findings.append(
                    self.fail(asset.asset_id, "Hook accesses credential locations.", evidence[:6])
                )
            else:
                findings.append(self.ok(asset.asset_id, "Hook does not reference credential paths."))
        return findings


@register
class HookNetworkCommunication(Check):
    meta = CheckMeta(
        check_id="HOOK-005",
        title="Hook performs network communication",
        description="The hook makes outbound network calls.",
        category=Category.HOOKS,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=HOOKS_ONLY,
        rationale=(
            "A hook with network access sees agent activity and can transmit it. Calls to "
            "loopback are treated as local tooling rather than egress."
        ),
        security_impact="Creates an automatic exfiltration channel for tool inputs and outputs.",
        remediation="Remove network calls from hooks, or restrict them to vetted internal endpoints.",
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("MITRE ATLAS", "AML.T0057: LLM Data Leakage"),
        ),
    )

    NETWORK_MARKERS = (
        "requests.", "urllib", "httpx", "aiohttp", "fetch(", "axios", "XMLHttpRequest",
        "http.client", "socket.socket", "net.Socket", "Net.WebClient",
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _hooks(context)
        if not assets:
            return self.no_assets("hooks")

        findings: list[Finding] = []
        for asset in assets:
            text = _hook_text(asset)
            evidence = []

            for match in commands.scan_text(text, include_tier_c=True):
                if match.threat.value in ("NETWORK_ACCESS", "DATA_EXFILTRATION"):
                    evidence.append(
                        self.evidence(path=asset.data.get("script_path") or asset.path,
                                      line=match.line, snippet=match.context,
                                      reason=match.description)
                    )
            for lineno, line in enumerate(text.splitlines(), start=1):
                if any(marker in line for marker in self.NETWORK_MARKERS):
                    evidence.append(
                        self.evidence(path=asset.data.get("script_path") or asset.path,
                                      line=lineno, snippet=line.strip()[:200],
                                      reason="Network client invocation")
                    )
                    break

            external = [
                (line, host, url)
                for line, host, url in injection.extract_urls(text)
                if host not in ("localhost", "127.0.0.1", "::1")
            ]
            if evidence and not external:
                findings.append(
                    self.warn(asset.asset_id, "Hook performs network calls to a local endpoint.",
                              evidence[:4], confidence=Confidence.MEDIUM)
                )
            elif evidence:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Hook performs outbound network communication.",
                        evidence[:4]
                        + [
                            self.evidence(path=asset.path, line=line, snippet=url,
                                          reason=f"Outbound endpoint '{host}'")
                            for line, host, url in external[:3]
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No network communication in hook."))
        return findings


@register
class HookObfuscatedCode(Check):
    meta = CheckMeta(
        check_id="HOOK-006",
        title="Hook contains obfuscated or encoded code",
        description="The hook command or script contains encoded payloads or dynamic evaluation.",
        category=Category.HOOKS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=HOOKS_ONLY,
        rationale=(
            "Obfuscation in a hook has no legitimate configuration purpose and defeats "
            "review — including this scanner's own static analysis."
        ),
        security_impact="Conceals the hook's real behaviour from both operators and auditing tools.",
        remediation="Replace the encoded payload with readable source and re-review the hook.",
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("CWE", "CWE-506: Embedded Malicious Code"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _hooks(context)
        if not assets:
            return self.no_assets("hooks")

        findings: list[Finding] = []
        for asset in assets:
            hits = injection.find_obfuscation(_hook_text(asset))
            if hits:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Hook contains obfuscated or encoded code.",
                        [
                            self.evidence(
                                path=asset.data.get("script_path") or asset.path,
                                line=lineno,
                                snippet=snippet,
                                reason="Encoded payload or dynamic evaluation construct",
                            )
                            for lineno, snippet in hits[:6]
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No obfuscation detected."))
        return findings
