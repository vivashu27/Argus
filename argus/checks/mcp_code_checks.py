"""Section 2 — MCP server implementation checks (MCP-013 … MCP-019).

MCP-001 … MCP-012 audit how a server is *configured*. These audit what that
configuration actually launches: the tool definitions the model is given, and the code
behind them.

Two properties of MCP make this necessary. A tool's description is model-visible
context rather than documentation, so text placed there is an instruction channel the
user rarely sees. And every tool parameter is attacker-reachable, because the model
chooses those values and injected text can steer the model.

Argus still never starts a server, so the tool list here is whatever could be recovered
from source. Where a server could not be resolved to local code the result is MANUAL
with the reason — an unreadable server is not a clean one.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from ..analysis import code_sinks, secrets
from ..analysis.mcp_tools import (
    concealed_characters,
    is_poisoned,
    scan_description,
)
from ..analysis.redaction import truncate
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

MCP_ONLY = frozenset({Target.MCP})

def _unresolved_detail(asset: Asset) -> str:
    code = asset.data.get("code") or {}
    reason = code.get("reason") or "the server's code could not be located on this machine"
    return f"Not evaluated: {reason}."


def _tools(asset: Asset) -> list[dict[str, str]]:
    return [t for t in (asset.data.get("tools") or []) if isinstance(t, dict)]


def _description_line(tool: dict[str, str], offset: int = 0) -> int | None:
    """The line an offset inside a tool's description falls on.

    ``line`` is where the definition starts — the decorator — which for a long
    docstring can be dozens of lines above the text that actually matched.
    ``description_line`` is where the description itself begins, so an offset into
    it maps onto the file and the reader opens on the payload rather than the
    function header.
    """
    base = tool.get("description_line") or tool.get("line") or 0
    try:
        base = int(base)
    except (TypeError, ValueError):
        return None
    if base <= 0:
        return None
    return base + (tool.get("description") or "")[:offset].count("\n")


def _code_files(asset: Asset) -> list[tuple[Path, str]]:
    return asset.code_files


@register
class ToolPoisoning(Check):
    meta = CheckMeta(
        check_id="MCP-013",
        title="MCP tool description carries instructions aimed at the model",
        description=(
            "A tool description contains directives to the assistant rather than a "
            "description of the tool — concealment instructions, instruction overrides, "
            "or a required read of a credential path."
        ),
        category=Category.MCP,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "Tool descriptions are supplied to the model as context, with the standing of "
            "the tool list itself. A user approving a server sees a sentence about what the "
            "tool does; the model sees whatever else was written there. Detection is tiered: "
            "a concealment directive or instruction override is reported on sight, while a "
            "description that merely names a credential path needs corroboration."
        ),
        security_impact=(
            "The server steers the assistant into reading secrets, routing data to an "
            "attacker-controlled parameter, or hiding the action from the user — without "
            "exploiting any code, and without the user seeing the instruction."
        ),
        remediation=(
            "Remove the directive text from the description. Treat any server whose "
            "descriptions address the assistant as untrusted and disconnect it, then review "
            "what the assistant did while it was connected."
        ),
        references=(
            "https://owasp.org/www-project-agentic-skills-top-10/",
            "https://modelcontextprotocol.io/docs/concepts/tools",
        ),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("OWASP Agentic AI Threats and Mitigations v1.0", "T2: Tool Misuse"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
            ("CWE", "CWE-77: Improper Neutralization of Special Elements used in a Command"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            tools = _tools(asset)
            if not tools:
                findings.append(self._no_tools(asset))
                continue

            evidence: list[Evidence] = []
            poisoned: list[str] = []
            for tool in tools:
                matches = scan_description(tool.get("description", ""))
                if not is_poisoned(matches):
                    continue
                poisoned.append(tool.get("name", "?"))
                for match in matches[:3]:
                    evidence.append(
                        self.evidence(
                            path=tool.get("path"),
                            line=_description_line(tool, match.offset),
                            key=f"tool.{tool.get('name')}.description",
                            snippet=match.excerpt,
                            reason=f"[tier {match.tier.value}] {match.description}",
                        )
                    )

            if poisoned:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(poisoned)} tool description(s) instruct the assistant: "
                        + ", ".join(sorted(set(poisoned))[:6]),
                        evidence[:12],
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, f"{len(tools)} recovered tool description(s) are clean.")
                )
        return findings

    def _no_tools(self, asset: Asset) -> Finding:
        code = asset.data.get("code") or {}
        if not code.get("resolved"):
            return self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
        return self.manual(
            asset.asset_id,
            "The server's code was read but no tool definition could be recovered from it. "
            "Servers that build their tool list at runtime need the descriptions reviewed "
            "against the running server.",
            confidence=Confidence.LOW,
        )


@register
class ConcealedToolText(Check):
    meta = CheckMeta(
        check_id="MCP-014",
        title="MCP tool description contains non-rendering characters",
        description=(
            "A tool description contains zero-width, Unicode tag, bidirectional or ANSI "
            "escape characters, which reach the model but not a human reviewer."
        ),
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "The Unicode tag block U+E0000-U+E007F mirrors ASCII, so a complete instruction "
            "can be written in characters that no terminal or approval dialog displays. A "
            "description that reads as innocuous can therefore carry a payload the reviewer "
            "cannot see at all. There is no legitimate reason for a tool description to "
            "contain them."
        ),
        security_impact=(
            "An instruction invisible to every human review path is delivered to the model "
            "verbatim, defeating description review as a control."
        ),
        remediation=(
            "Reject the server. A description containing invisible characters is not a "
            "formatting mistake."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/tools",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("CWE", "CWE-176: Improper Handling of Unicode Encoding"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            tools = _tools(asset)
            if not tools:
                findings.append(
                    self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
                    if not (asset.data.get("code") or {}).get("resolved")
                    else self.ok(asset.asset_id, "No tool descriptions recovered to inspect.")
                )
                continue

            evidence: list[Evidence] = []
            affected: list[str] = []
            for tool in tools:
                hidden = concealed_characters(tool.get("description", ""))
                if not hidden:
                    continue
                affected.append(tool.get("name", "?"))
                for match in hidden[:3]:
                    evidence.append(
                        self.evidence(
                            path=tool.get("path"),
                            line=_description_line(tool),
                            key=f"tool.{tool.get('name')}.description",
                            snippet=f"{match.count} × {match.kind}"
                            + (f" ({match.codepoints})" if match.codepoints else ""),
                            reason=match.description,
                        )
                    )
            if affected:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Tool description(s) contain characters a reviewer cannot see: "
                        + ", ".join(sorted(set(affected))[:6]),
                        evidence[:12],
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, f"{len(tools)} description(s) render fully.")
                )
        return findings


@register
class ToolShadowing(Check):
    meta = CheckMeta(
        check_id="MCP-015",
        title="MCP tool name is claimed by more than one server, or targets another server",
        description=(
            "Two connected servers expose the same tool name, or a description refers to "
            "another server's tools and modifies how they should be called."
        ),
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "The model sees one flat tool list assembled from every connected server, and "
            "nothing in the protocol binds a name to an origin. A colliding name makes tool "
            "selection ambiguous; a description that redefines another server's tool turns "
            "one untrusted server into control over a trusted one."
        ),
        security_impact=(
            "Calls intended for a trusted server are answered by an untrusted one, or a "
            "trusted tool is invoked with attacker-chosen parameters such as an added "
            "recipient on an outbound message."
        ),
        remediation=(
            "Give colliding tools distinct names, or connect only one of the servers. "
            "Investigate any server whose descriptions mention another server's tools."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/tools",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("OWASP Agentic AI Threats and Mitigations v1.0", "T2: Tool Misuse"),
            ("CWE", "CWE-1021: Improper Restriction of Rendered UI Layers"),
        ),
    )

    #: Verbs that turn a mention of another tool into an instruction about it.
    DIRECTIVE = (
        "always", "must", "should", "instead", "when using", "when calling",
        "before calling", "also call", "in addition", "make sure",
    )

    #: Language that reaches past this server's own tools. Matching on names alone is
    #: not enough: the documented attack gives instructions about a tool of the *same*
    #: name on a different server, so the name test excludes exactly the payload that
    #: matters most.
    CROSS_SERVER = re.compile(
        r"(from|on|via|through)\s+(any\s+|the\s+|all\s+|every\s+)?"
        r"(other|another|different|trusted|external|second)\s+(mcp\s+)?(server|tool)"
        r"|(other|another|every)\s+(mcp\s+)?servers?'?s?\s+tool"
        r"|when\s+(using|calling|invoking)\s+[\w.-]{2,60}\s+from\b",
        re.I,
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        # A collision only exists across servers, so this is computed once for the set.
        owners: dict[str, set[str]] = defaultdict(set)
        for asset in assets:
            for tool in _tools(asset):
                owners[tool.get("name", "")].add(asset.asset_id)
        collisions = {name: servers for name, servers in owners.items() if name and len(servers) > 1}

        all_names = {t.get("name", "") for a in assets for t in _tools(a)}

        findings: list[Finding] = []
        for asset in assets:
            tools = _tools(asset)
            if not tools:
                findings.append(
                    self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
                )
                continue

            evidence: list[Evidence] = []
            reasons: list[str] = []

            for tool in tools:
                name = tool.get("name", "")
                if name in collisions:
                    others = sorted(collisions[name] - {asset.asset_id})
                    reasons.append(f"'{name}' also exposed by {', '.join(others)}")
                    evidence.append(
                        self.evidence(
                            path=tool.get("path"),
                            line=_description_line(tool),
                            key=f"tool.{name}",
                            snippet=f"also declared by {', '.join(others)}",
                            reason="Colliding tool name makes selection ambiguous",
                        )
                    )

                raw = tool.get("description") or ""
                description = raw.lower()
                directive = any(word in description for word in self.DIRECTIVE)

                if directive and self.CROSS_SERVER.search(raw):
                    reasons.append(f"'{name}' gives instructions about another server's tools")
                    evidence.append(
                        self.evidence(
                            path=tool.get("path"),
                            line=_description_line(tool),
                            key=f"tool.{name}.description",
                            snippet=truncate(raw, 180),
                            reason="Description reaches past this server to direct another one",
                        )
                    )
                    continue

                foreign = sorted(
                    other
                    for other in all_names
                    if other and other != name and len(other) > 3 and other.lower() in description
                )
                if foreign and directive:
                    reasons.append(f"'{name}' gives instructions about {', '.join(foreign[:3])}")
                    evidence.append(
                        self.evidence(
                            path=tool.get("path"),
                            line=_description_line(tool),
                            key=f"tool.{name}.description",
                            snippet=truncate(raw, 180),
                            reason=f"Description directs how {', '.join(foreign[:3])} should be called",
                        )
                    )

            if reasons:
                findings.append(
                    self.fail(asset.asset_id, "; ".join(reasons[:4]), evidence[:12])
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, "No colliding or cross-referencing tool names.")
                )
        return findings


@register
class ServerCommandInjection(Check):
    meta = CheckMeta(
        check_id="MCP-016",
        title="MCP server passes tool input into a shell or evaluator",
        description=(
            "Server code builds a shell command or evaluated expression from interpolated "
            "input reachable through a tool parameter."
        ),
        category=Category.MCP,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "Every tool parameter is attacker-reachable: the model chooses the value, and "
            "the model can be steered by injected text in any document it reads. A shell "
            "sink with an interpolated argument is therefore remote code execution reachable "
            "from content, not just from a malicious user. Constant arguments and the "
            "argument-vector form of subprocess are not reported."
        ),
        security_impact=(
            "Code execution as the user running the agent, from any content the model can be "
            "induced to read."
        ),
        remediation=(
            "Pass an argument vector instead of a command string — subprocess without "
            "shell=True, or execFile in place of exec — and validate parameters against an "
            "allow-list. Never evaluate a parameter as code."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://modelcontextprotocol.io/docs/concepts/tools",
        ),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM05: Improper Output Handling"),
            ("OWASP Agentic AI Threats and Mitigations v1.0", "T2: Tool Misuse"),
            ("MITRE ATLAS", "AML.T0053: LLM Plugin Compromise"),
            ("CWE", "CWE-78: OS Command Injection"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            if not (asset.data.get("code") or {}).get("resolved"):
                findings.append(
                    self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
                )
                continue

            interpolated: list[code_sinks.SinkMatch] = []
            constant: list[code_sinks.SinkMatch] = []
            evidence: list[Evidence] = []
            for path, text in _code_files(asset):
                for match in code_sinks.shell_sinks(text):
                    (interpolated if match.interpolated else constant).append(match)
                    if match.interpolated and len(evidence) < 12:
                        evidence.append(
                            self.evidence(
                                path=path,
                                line=match.line,
                                snippet=match.excerpt,
                                reason=f"{match.description}, with an interpolated argument",
                            )
                        )

            if interpolated:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(interpolated)} shell or evaluator call(s) built from interpolated input.",
                        evidence,
                    )
                )
            elif constant:
                # Informational, and scored as such. A shell call with constant
                # arguments is not command injection — plenty of servers legitimately
                # run a fixed command — so this is surfaced at INFO, which carries no
                # deduction, rather than taking points off a CRITICAL check.
                findings.append(
                    self.warn(
                        asset.asset_id,
                        f"{len(constant)} shell call(s) with constant arguments. No input reaches "
                        "them in the code Argus read, but the sink is present.",
                        [
                            self.evidence(
                                path=asset.data["code"].get("root"),
                                line=m.line,
                                snippet=m.excerpt,
                                reason=m.description,
                            )
                            for m in constant[:6]
                        ],
                        confidence=Confidence.LOW,
                        severity=Severity.INFO,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"No shell or evaluator sinks in {asset.data['code'].get('file_count')} file(s).",
                    )
                )
        return findings


@register
class ServerPathTraversal(Check):
    meta = CheckMeta(
        check_id="MCP-017",
        title="MCP server builds filesystem paths from input without confining them",
        description=(
            "Server code opens or writes a path built from interpolated input, and contains "
            "no idiom that confines the result to an intended directory."
        ),
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "A filesystem tool that joins a caller-supplied segment onto a base directory "
            "escapes that directory with '..' unless the joined result is resolved and "
            "checked. Any file containing a containment idiom — resolve, realpath, "
            "commonpath, a startswith check — is treated as having addressed this, so the "
            "check reports servers that never confine paths rather than every server that "
            "opens a file."
        ),
        security_impact=(
            "A tool scoped to a project directory reads or writes anywhere the agent's user "
            "can, including SSH keys and cloud credentials."
        ),
        remediation=(
            "Resolve the joined path and verify it is still inside the intended root before "
            "opening it. Reject the request otherwise."
        ),
        references=("https://cwe.mitre.org/data/definitions/22.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            if not (asset.data.get("code") or {}).get("resolved"):
                findings.append(
                    self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
                )
                continue

            evidence: list[Evidence] = []
            count = 0
            for path, text in _code_files(asset):
                for match in code_sinks.path_sinks(text):
                    count += 1
                    if len(evidence) < 10:
                        evidence.append(
                            self.evidence(
                                path=path,
                                line=match.line,
                                snippet=match.excerpt,
                                reason=f"{match.description}; no containment check in this file",
                            )
                        )
            if count:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{count} filesystem call(s) build a path from input with no containment check.",
                        evidence,
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "Filesystem paths are confined or constant."))
        return findings


@register
class ServerNetworkExposure(Check):
    meta = CheckMeta(
        check_id="MCP-018",
        title="MCP server binds to every network interface",
        description="Server code binds 0.0.0.0 or ::, exposing it beyond the local machine.",
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "MCP mandates no authentication. A server written for local stdio use that binds "
            "every interface is reachable by anyone who can route to the host, with the same "
            "tools the agent has. Whether the file shows any authentication at all decides "
            "the confidence of this finding."
        ),
        security_impact=(
            "Anyone able to reach the port invokes the server's tools directly, with the "
            "privileges of the account running it."
        ),
        remediation=(
            "Bind 127.0.0.1 for local use. If remote access is required, put authentication "
            "in front of it and restrict the source range."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/transports",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-306: Missing Authentication for Critical Function"),
            ("CWE", "CWE-668: Exposure of Resource to Wrong Sphere"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            if not (asset.data.get("code") or {}).get("resolved"):
                findings.append(
                    self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
                )
                continue

            unauthenticated: list[Evidence] = []
            authenticated: list[Evidence] = []
            for path, text in _code_files(asset):
                for match in code_sinks.network_binds(text):
                    item = self.evidence(
                        path=path, line=match.line, snippet=match.excerpt, reason=match.description
                    )
                    (unauthenticated if match.interpolated else authenticated).append(item)

            if unauthenticated:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Server binds every interface and shows no authentication.",
                        unauthenticated[:8],
                    )
                )
            elif authenticated:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        "Server binds every interface. Authentication code is present; confirm "
                        "it covers the tool endpoints.",
                        authenticated[:8],
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No bind to a non-local interface."))
        return findings


@register
class ToolDefinitionMutability(Check):
    meta = CheckMeta(
        check_id="MCP-019",
        title="MCP tool definitions can change after the user approves them",
        description=(
            "The server resolves to a new version at every launch, or its code is writable "
            "by the current user, so approved tool definitions can change silently."
        ),
        category=Category.MCP,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "A rug pull is a tool that behaves as described until trust is established, then "
            "changes. Approval happens once, against the definitions present that day. This "
            "reports the conditions that make such a change silent: an unpinned package "
            "fetched fresh at each launch, or server code the user's own account can rewrite. "
            "Detecting an actual change requires comparing against recorded definitions, "
            "which needs a pinned version to compare against in the first place."
        ),
        security_impact=(
            "Tool descriptions and behaviour differ from what the user reviewed, with no "
            "prompt and no visible difference in configuration."
        ),
        remediation=(
            "Pin the server to an exact version and install it rather than fetching at "
            "launch. Re-review tool descriptions whenever that pin is raised."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/tools",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
            ("OWASP Agentic AI Threats and Mitigations v1.0", "T2: Tool Misuse"),
            ("CWE", "CWE-494: Download of Code Without Integrity Check"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            code = asset.data.get("code") or {}
            reasons: list[str] = []
            evidence: list[Evidence] = []

            spec = code.get("package_spec") or ""
            if spec and code.get("unpinned"):
                reasons.append(f"'{spec}' resolves to a new version at each launch")
                evidence.append(
                    self.evidence(
                        path=asset.path,
                        asset=asset,
                        key=f"mcpServers.{asset.data.get('name')}.args",
                        snippet=spec,
                        reason="Package spec carries no exact version",
                    )
                )

            if not code.get("resolved") and spec:
                reasons.append(
                    "the package is not installed locally, so nothing can be reviewed before it runs"
                )

            if reasons:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        "Tool definitions are not fixed: " + "; ".join(reasons) + ".",
                        evidence[:10],
                        confidence=Confidence.HIGH if code.get("unpinned") else Confidence.MEDIUM,
                    )
                )
            elif code.get("resolved"):
                findings.append(
                    self.ok(asset.asset_id, "Server resolves to fixed, read-only code.")
                )
            else:
                findings.append(
                    self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
                )
        return findings


@register
class ServerEmbeddedSecrets(Check):
    meta = CheckMeta(
        check_id="MCP-020",
        title="MCP server code contains hardcoded credentials",
        description=(
            "Credential material is embedded in the server's own source rather than "
            "supplied by the environment at launch."
        ),
        category=Category.MCP,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "MCP-006 reads the server's configuration block. A credential written into "
            "the implementation never appears there, so it passed unremarked while the "
            "same value in .mcp.json would have failed. The server's source is already "
            "read for the other checks in this section; scanning it costs nothing."
        ),
        security_impact=(
            "The credential is readable by anyone with the file, travels with the "
            "package, and is exposed to every tool the agent can reach."
        ),
        remediation=(
            "Move the value to an environment variable read at startup, rotate it, and "
            "purge it from version control history."
        ),
        references=("https://cwe.mitre.org/data/definitions/798.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-798: Use of Hard-coded Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            if not (asset.data.get("code") or {}).get("resolved"):
                findings.append(
                    self.manual(asset.asset_id, _unresolved_detail(asset), confidence=Confidence.LOW)
                )
                continue

            evidence: list[Evidence] = []
            total = 0
            for path, text in _code_files(asset):
                for match in secrets.scan_text(text):
                    # Only pattern-identified credentials. The entropy heuristic that
                    # backs MEDIUM confidence is calibrated for configuration files,
                    # where `auth: <value>` names a secret; in source the same shape is
                    # ordinary code — `auth = AuthConfig(...)` — and reporting it would
                    # make this check noise on every Python server.
                    if match.confidence != "HIGH":
                        continue
                    total += 1
                    if len(evidence) < 10:
                        evidence.append(
                            self.evidence(
                                path=path,
                                line=match.line,
                                # Already redacted by the scanner; nothing downstream
                                # re-redacts, so the raw value must never land here.
                                snippet=match.redacted,
                                reason=f"{match.description} [{match.kind}]",
                            )
                        )
            if total:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{total} hardcoded credential(s) in the server's source.",
                        evidence,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"No credentials in {asset.data['code'].get('file_count')} source file(s).",
                    )
                )
        return findings
