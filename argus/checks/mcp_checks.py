"""Section 2 — MCP Security checks (MCP-001 … MCP-012).

MCP servers are analyzed purely from their configuration. Argus never starts a
server, so capability questions that can only be answered by handshaking with it
are reported as MANUAL rather than guessed.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..analysis import commands, injection, secrets
from ..analysis.paths import is_root_scope, touches_sensitive
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

MCP_ONLY = frozenset({Target.MCP})

#: Package runners whose arguments name a package fetched at launch time.
PACKAGE_RUNNERS = {"npx", "uvx", "pipx", "bunx", "pnpm", "yarn", "dlx"}

#: Registries treated as first-party or well-known for provenance purposes.
KNOWN_REGISTRY_MARKERS = ("@modelcontextprotocol/", "@anthropic-ai/", "mcp-server-")


def _mcp_assets(context: CheckContext) -> list[Asset]:
    return context.by_target(Target.MCP)


def _argv(asset: Asset) -> list[str]:
    return [asset.data.get("command") or "", *(asset.data.get("args") or [])]


@register
class UntrustedSource(Check):
    meta = CheckMeta(
        check_id="MCP-001",
        title="MCP server configured from an untrusted source",
        description=(
            "The server is launched through a package runner that fetches code at start "
            "time, or from a remote endpoint that is not a recognised registry."
        ),
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "A runner such as npx or uvx resolves and executes the newest matching package "
            "on every launch. The code reviewed at configuration time is not necessarily "
            "the code that runs later."
        ),
        security_impact=(
            "A compromised or typosquatted package executes with the user's privileges and "
            "inherits every capability the agent grants the server."
        ),
        remediation=(
            "Pin the package to an exact version and integrity hash, or vendor the server "
            "locally and launch it from a fixed path."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
            ("CWE", "CWE-494: Download of Code Without Integrity Check"),
            ("MITRE ATLAS", "AML.T0010: ML Supply Chain Compromise"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            command = asset.data.get("command") or ""
            args = asset.data.get("args") or []
            base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
            evidence = []

            if base in PACKAGE_RUNNERS:
                package = next((a for a in args if not a.startswith("-")), "")
                pinned = "@" in package.lstrip("@") and any(c.isdigit() for c in package.split("@")[-1])
                if not pinned:
                    evidence.append(
                        self.evidence(
                            path=asset.path,
                            asset=asset,
                            key=f"mcpServers.{asset.data.get('name')}.command",
                            snippet=f"{command} {' '.join(args[:3])}".strip(),
                            reason=(
                                f"'{base}' resolves and executes '{package or 'a package'}' at "
                                "launch with no version pin"
                            ),
                        )
                    )

            url = asset.data.get("url") or ""
            if url:
                host = urlparse(url).hostname or ""
                if injection.is_suspicious_host(host) or not injection.is_trusted_host(host):
                    evidence.append(
                        self.evidence(
                            path=asset.path,
                            asset=asset,
                            key=f"mcpServers.{asset.data.get('name')}.url",
                            snippet=url,
                            reason=f"Remote server hosted at unrecognised endpoint '{host}'",
                        )
                    )

            if evidence:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Server code provenance cannot be established from the configuration.",
                        evidence,
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, "Server is launched from a fixed local path or pinned package.")
                )
        return findings


@register
class ShellInterpreterCommand(Check):
    meta = CheckMeta(
        check_id="MCP-002",
        title="MCP server command invokes a shell interpreter",
        description="The configured command is itself a shell rather than a program.",
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "When the command is sh, bash, cmd or powershell, the arguments are a script "
            "rather than an argv vector, so shell parsing applies to everything after it."
        ),
        security_impact=(
            "Any value interpolated into that script — including agent-supplied data — is "
            "parsed as shell syntax, producing command injection."
        ),
        remediation=(
            "Invoke the server binary directly and pass parameters as separate argv "
            "entries instead of a shell string."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-78: Improper Neutralization of Special Elements used in an OS Command"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            command = asset.data.get("command") or ""
            if commands.is_shell_interpreter(command):
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"Server is launched through the shell interpreter '{command}'.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"mcpServers.{asset.data.get('name')}.command",
                                snippet=f"{command} {' '.join((asset.data.get('args') or [])[:3])}".strip(),
                                reason="Command is a shell, so arguments are shell-parsed",
                            )
                        ],
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, f"Launched directly via '{command or asset.data.get('transport')}'.")
                )
        return findings


@register
class UnrestrictedFilesystemScope(Check):
    meta = CheckMeta(
        check_id="MCP-003",
        title="MCP server has unrestricted filesystem access",
        description="A path argument grants the server the filesystem root or the whole home directory.",
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "Filesystem-style MCP servers take their permitted roots as arguments. A root "
            "of '/' or '~' means every file the launching user can read is exposed to the "
            "agent through the server's tools."
        ),
        security_impact=(
            "The server becomes a general-purpose file read/write primitive reachable by "
            "prompt injection, bypassing Claude's own path-scoped permission rules."
        ),
        remediation="Pass only the specific project directories the server needs.",
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-732: Incorrect Permission Assignment for Critical Resource"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            args = asset.data.get("args") or []
            offending = [a for a in args if is_root_scope(a)]
            if offending:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Server is granted a filesystem-wide root path.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"mcpServers.{asset.data.get('name')}.args",
                                snippet=value,
                                reason="Argument resolves to the filesystem or home root",
                            )
                            for value in offending
                        ],
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No filesystem-wide path arguments."))
        return findings


@register
class SensitiveDirectoryAccess(Check):
    meta = CheckMeta(
        check_id="MCP-004",
        title="MCP server granted access to sensitive directories",
        description="A path argument or environment value points at a known credential location.",
        category=Category.MCP,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "Unlike MCP-003 this is not about breadth — it is a direct grant over a "
            "location whose only contents are credentials."
        ),
        security_impact=(
            "Private keys and cloud credentials become readable through an agent tool call, "
            "enabling lateral movement well beyond the local machine."
        ),
        remediation="Remove the credential path from the server's configuration.",
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            evidence = []
            for value in asset.data.get("args") or []:
                hit, description = touches_sensitive(value)
                if hit:
                    evidence.append(
                        self.evidence(
                            path=asset.path,
                            asset=asset,
                            key=f"mcpServers.{asset.data.get('name')}.args",
                            snippet=value,
                            reason=description,
                        )
                    )
            for key, value in (asset.data.get("env") or {}).items():
                hit, description = touches_sensitive(value)
                if hit:
                    evidence.append(
                        self.evidence(
                            path=asset.path,
                            asset=asset,
                            key=f"mcpServers.{asset.data.get('name')}.env.{key}",
                            snippet=value,
                            reason=description,
                        )
                    )

            if evidence:
                findings.append(
                    self.fail(asset.asset_id, "Server configuration references a credential location.", evidence)
                )
            else:
                findings.append(self.ok(asset.asset_id, "No credential paths in server configuration."))
        return findings


@register
class ExcessivePermissions(Check):
    meta = CheckMeta(
        check_id="MCP-005",
        title="MCP server has excessive declared permissions",
        description=(
            "The server declares broad capability scopes, or is configured to run with "
            "elevated privileges."
        ),
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "Where a server declares scopes or is wrapped in sudo, the declared privilege "
            "level is visible statically and can be compared against least privilege."
        ),
        security_impact=(
            "A server running with elevated privilege converts any injection reaching it "
            "into privileged code execution."
        ),
        remediation="Run the server unprivileged and narrow declared scopes to what is used.",
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-250: Execution with Unnecessary Privileges"),
        ),
    )

    BROAD_SCOPES = {"*", "all", "admin", "root", "full", "read-write-all"}

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            raw: dict[str, Any] = asset.data.get("raw") or {}
            evidence = []

            argv = _argv(asset)
            if any(a.replace("\\", "/").rsplit("/", 1)[-1] in ("sudo", "doas", "runas") for a in argv):
                evidence.append(
                    self.evidence(
                        path=asset.path,
                        asset=asset,
                        key=f"mcpServers.{asset.data.get('name')}",
                        snippet=" ".join(argv[:4]),
                        reason="Server is launched with a privilege-escalation wrapper",
                    )
                )

            for key in ("permissions", "scopes", "capabilities", "access"):
                value = raw.get(key)
                entries: list[str] = []
                if isinstance(value, str):
                    entries = [value]
                elif isinstance(value, list):
                    entries = [str(v) for v in value]
                elif isinstance(value, dict):
                    entries = [str(k) for k, v in value.items() if v is True]
                broad = [e for e in entries if e.strip().lower() in self.BROAD_SCOPES]
                if broad:
                    evidence.append(
                        self.evidence(
                            path=asset.path,
                            asset=asset,
                            key=f"mcpServers.{asset.data.get('name')}.{key}",
                            snippet=", ".join(broad),
                            reason="Wildcard or administrative scope declared",
                        )
                    )

            if evidence:
                findings.append(self.fail(asset.asset_id, "Server declares excessive privileges.", evidence))
            else:
                findings.append(
                    self.ok(asset.asset_id, "No elevated privileges or wildcard scopes declared.")
                )
        return findings


@register
class HardcodedSecrets(Check):
    meta = CheckMeta(
        check_id="MCP-006",
        title="MCP configuration contains hardcoded secrets",
        description="A credential literal appears in the server's configuration block.",
        category=Category.MCP,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "MCP configuration files are frequently committed to repositories and synced "
            "between machines, so a literal credential there has a wide blast radius. This "
            "check takes precedence over the generic SECRET-* family for MCP assets."
        ),
        security_impact="The credential is exposed to anyone with read access to the config file.",
        remediation=(
            "Move the value to an environment variable or secret manager, reference it "
            "indirectly, and rotate the exposed credential."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-798: Use of Hard-coded Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            matches = secrets.scan_mapping(asset.data.get("raw") or {})
            if matches:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(matches)} credential literal(s) found in the server configuration.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=match.key or asset.data.get("name"),
                                snippet=match.redacted,
                                reason=match.description,
                            )
                            for match in matches[:10]
                        ],
                        confidence=Confidence.HIGH
                        if any(m.confidence == "HIGH" for m in matches)
                        else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No credential literals in configuration."))
        return findings


@register
class ShellInterpolation(Check):
    meta = CheckMeta(
        check_id="MCP-007",
        title="MCP server launched via shell string interpolation",
        description=(
            "Server arguments contain shell metacharacters, implying the command line is "
            "assembled as a string rather than an argv vector."
        ),
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "Distinct from MCP-002: there the command itself is a shell; here the command "
            "is a normal program but its arguments carry pipes, redirects, or command "
            "substitution that only a shell would interpret."
        ),
        security_impact="Introduces a command injection point at server launch.",
        remediation="Pass arguments as discrete argv entries with no shell metacharacters.",
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("CWE", "CWE-77: Improper Neutralization of Special Elements used in a Command"),
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            if commands.is_shell_interpreter(asset.data.get("command") or ""):
                findings.append(
                    self.not_applicable(asset.asset_id, "Command is a shell — reported by MCP-002")
                )
                continue
            offending = commands.has_shell_metacharacters(asset.data.get("args") or [])
            if offending:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Server arguments contain shell metacharacters.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"mcpServers.{asset.data.get('name')}.args",
                                snippet=value,
                                reason="Contains shell metacharacters (; & | > < ` $)",
                            )
                            for value in offending
                        ],
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "Arguments are plain argv entries."))
        return findings


@register
class RemoteEndpointSecurity(Check):
    meta = CheckMeta(
        check_id="MCP-008",
        title="MCP server uses an insecure or suspicious remote endpoint",
        description="A remote server URL uses plaintext HTTP or a disposable-hosting domain.",
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=MCP_ONLY,
        rationale=(
            "Traffic to a remote MCP server carries tool arguments and results, which "
            "routinely include file contents and credentials."
        ),
        security_impact=(
            "Plaintext transport exposes that traffic to interception and modification; "
            "tunnelling and paste-style hosts indicate an endpoint that can change owner "
            "without notice."
        ),
        remediation="Use HTTPS endpoints on domains your organisation controls or has vetted.",
        references=("https://modelcontextprotocol.io/docs/concepts/transports",),
        compliance=(
            ("CWE", "CWE-319: Cleartext Transmission of Sensitive Information"),
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            url = asset.data.get("url") or ""
            if not url:
                findings.append(
                    self.not_applicable(asset.asset_id, "Server uses local stdio transport")
                )
                continue

            parsed = urlparse(url)
            host = parsed.hostname or ""
            evidence = []
            if parsed.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
                evidence.append(
                    self.evidence(
                        path=asset.path,
                        asset=asset,
                        key=f"mcpServers.{asset.data.get('name')}.url",
                        snippet=url,
                        reason="Plaintext HTTP transport to a non-loopback host",
                    )
                )
            if injection.is_suspicious_host(host):
                evidence.append(
                    self.evidence(
                        path=asset.path,
                        asset=asset,
                        key=f"mcpServers.{asset.data.get('name')}.url",
                        snippet=url,
                        reason="Endpoint uses disposable or tunnelling infrastructure",
                    )
                )

            if evidence:
                findings.append(self.fail(asset.asset_id, "Remote endpoint is not adequately secured.", evidence))
            else:
                findings.append(self.ok(asset.asset_id, f"Remote endpoint '{host}' uses secure transport."))
        return findings


@register
class MissingIntegrityMetadata(Check):
    meta = CheckMeta(
        check_id="MCP-009",
        title="MCP server configuration lacks integrity metadata",
        description="No version pin, checksum, or lockfile reference constrains what the server runs.",
        category=Category.MCP,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "Without a version pin or hash, the artifact executed today may differ from "
            "the one reviewed, and nothing in the configuration would reveal the change."
        ),
        security_impact="Silent substitution of server code between launches goes undetected.",
        remediation="Pin exact versions, record integrity hashes, and commit a lockfile.",
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
            ("CWE", "CWE-494: Download of Code Without Integrity Check"),
        ),
    )

    INTEGRITY_KEYS = ("version", "integrity", "sha256", "hash", "lockfile", "digest", "revision")

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            raw: dict[str, Any] = asset.data.get("raw") or {}
            command = asset.data.get("command") or ""
            base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()

            has_metadata = any(k in raw for k in self.INTEGRITY_KEYS)
            args = asset.data.get("args") or []
            pinned_arg = any("@" in a and any(c.isdigit() for c in a.rsplit("@", 1)[-1]) for a in args)

            # A server launched from a fixed local file path is version-controlled by the
            # filesystem; the risk this check describes does not apply.
            local_path = base not in PACKAGE_RUNNERS and not asset.data.get("url")

            if has_metadata or pinned_arg:
                findings.append(self.ok(asset.asset_id, "Integrity or version metadata is present."))
            elif local_path:
                findings.append(
                    self.not_applicable(
                        asset.asset_id,
                        "Server runs from a fixed local path, not a fetched artifact",
                    )
                )
            else:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        "No version pin or integrity metadata constrains the fetched artifact.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"mcpServers.{asset.data.get('name')}",
                                snippet=f"{command} {' '.join(args[:3])}".strip(),
                                reason="No version, integrity, or digest key present",
                            )
                        ],
                    )
                )
        return findings


@register
class ExcessiveToolCapabilities(Check):
    meta = CheckMeta(
        check_id="MCP-010",
        title="MCP server exposes excessive tool capabilities",
        description="The server declares a large or unbounded set of tools.",
        category=Category.MCP,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "The tool list a server exposes is only fully known after a handshake, which "
            "Argus will not perform. Where a manifest declares tools statically it is "
            "evaluated; otherwise the result is MANUAL rather than a guess."
        ),
        security_impact=(
            "Every exposed tool is reachable by prompt injection, so unused tools are "
            "unnecessary attack surface."
        ),
        remediation="Expose only the tools in active use and disable the remainder.",
        references=("https://modelcontextprotocol.io/docs/concepts/tools",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-1059: Insufficient Technical Documentation"),
        ),
    )

    TOOL_BUDGET = 25

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            raw: dict[str, Any] = asset.data.get("raw") or {}
            declared = raw.get("tools") or raw.get("capabilities", {}).get("tools") if isinstance(
                raw.get("capabilities"), dict
            ) else raw.get("tools")

            if isinstance(declared, list):
                if len(declared) > self.TOOL_BUDGET:
                    findings.append(
                        self.fail(
                            asset.asset_id,
                            f"Server declares {len(declared)} tools, above the budget of {self.TOOL_BUDGET}.",
                            [
                                self.evidence(
                                    path=asset.path,
                                    asset=asset,
                                    key=f"mcpServers.{asset.data.get('name')}.tools",
                                    snippet=f"{len(declared)} tools declared",
                                    reason="Large tool surface increases injection reachability",
                                )
                            ],
                            confidence=Confidence.MEDIUM,
                        )
                    )
                else:
                    findings.append(
                        self.ok(asset.asset_id, f"Declares {len(declared)} tool(s), within budget.")
                    )
            else:
                findings.append(
                    self.manual(
                        asset.asset_id,
                        "Tool surface is not declared in configuration. Enumerating it requires "
                        "starting the server, which Argus does not do. Review the server's tool "
                        "list manually.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"mcpServers.{asset.data.get('name')}",
                                reason="No static tool manifest available",
                            )
                        ],
                    )
                )
        return findings


@register
class DestructiveOperations(Check):
    meta = CheckMeta(
        check_id="MCP-011",
        title="MCP tool performs destructive operations without safeguards",
        description="Configuration or manifest text indicates destructive capability with no confirmation gate.",
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "Whether a tool is destructive is a property of its implementation, not its "
            "configuration. Argus reports MANUAL unless the configuration itself carries "
            "dangerous command patterns."
        ),
        security_impact="Irreversible operations can be triggered by injected instructions.",
        remediation=(
            "Require explicit confirmation for destructive tools and run the server against "
            "a restricted scope."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/tools",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-732: Incorrect Permission Assignment for Critical Resource"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            matches = [
                m
                for m in commands.scan_text(asset.text or "")
                if m.threat.value in ("DESTRUCTIVE_OPERATION", "REMOTE_CODE_EXECUTION")
            ]
            if matches:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Server configuration contains destructive command patterns.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                line=m.line,
                                snippet=m.context,
                                reason=f"{m.description} [{m.threat.value}]",
                            )
                            for m in matches[:6]
                        ],
                    )
                )
            else:
                findings.append(
                    self.manual(
                        asset.asset_id,
                        "Destructive capability cannot be determined from configuration alone. "
                        "Review the server's tool implementations for irreversible operations.",
                        confidence=Confidence.LOW,
                    )
                )
        return findings


@register
class CredentialsInEnvironment(Check):
    meta = CheckMeta(
        check_id="MCP-012",
        title="MCP server receives credentials via environment",
        description="The server's env block passes credential-shaped values to the subprocess.",
        category=Category.MCP,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=MCP_ONLY,
        rationale=(
            "Environment variables are inherited by every child process the server spawns "
            "and are readable from process listings on some platforms. Indirect references "
            "such as ${VAR} are the recommended pattern and are not flagged."
        ),
        security_impact=(
            "A credential passed literally in the environment is exposed to the server's "
            "entire process tree and to anything that can read the config file."
        ),
        remediation=(
            "Reference secrets indirectly (${VAR}) and resolve them from a secret manager "
            "at launch, scoped to the minimum needed."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("CWE", "CWE-214: Invocation of Process Using Visible Sensitive Information"),
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
        ),
    )

    CREDENTIAL_NAME = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH")

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _mcp_assets(context)
        if not assets:
            return self.no_assets("MCP servers")

        findings: list[Finding] = []
        for asset in assets:
            env = asset.data.get("env") or {}
            if not env:
                findings.append(self.ok(asset.asset_id, "No environment variables passed to server."))
                continue

            literal = []
            for key, value in env.items():
                if not any(marker in key.upper() for marker in self.CREDENTIAL_NAME):
                    continue
                if secrets.INDIRECTION.match(str(value)):
                    continue  # indirection is the recommended pattern
                if len(str(value)) < 8:
                    continue
                literal.append((key, value))

            if literal:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(literal)} credential-shaped environment value(s) passed literally.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"mcpServers.{asset.data.get('name')}.env.{key}",
                                snippet=secrets.redact(value),
                                reason="Literal credential value inherited by the server's subprocesses",
                            )
                            for key, value in literal[:8]
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"{len(env)} environment variable(s), none passing literal credentials.",
                    )
                )
        return findings
