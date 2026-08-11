"""Section 4 — Plugins checks (PLUGIN-001 … PLUGIN-008)."""

from __future__ import annotations

from ..analysis import commands, injection, secrets
from ..analysis.paths import is_test_file, touches_sensitive
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

PLUGINS_ONLY = frozenset({Target.PLUGINS})

#: Bundled files that execute, as opposed to markdown documentation.
EXECUTABLE_SUFFIXES = (".sh", ".bash", ".py", ".js", ".ts", ".ps1", ".rb", ".pl")


def _plugins(context: CheckContext) -> list[Asset]:
    return context.by_target(Target.PLUGINS)


def _executable_files(asset: Asset) -> list[dict[str, str]]:
    return [
        f for f in (asset.data.get("files") or []) if f["relative"].endswith(EXECUTABLE_SUFFIXES)
    ]


@register
class PluginUntrustedSource(Check):
    meta = CheckMeta(
        check_id="PLUGIN-001",
        title="Plugin installed from an untrusted or unverified source",
        description="The plugin's marketplace is not first-party and is not recorded in known_marketplaces.json.",
        category=Category.PLUGINS,
        severity=Severity.MEDIUM,
        aasb_level=1,
        applies_to=PLUGINS_ONLY,
        rationale=(
            "Provenance is a statement about who can change the code, not about whether "
            "the code is malicious. An unverified marketplace can push an update at any "
            "time with no review gate."
        ),
        security_impact=(
            "Plugins contribute hooks, commands, agents, and MCP servers to the agent, so "
            "an update from an unvetted source changes agent behaviour directly."
        ),
        remediation="Install plugins from marketplaces your organisation has reviewed and pinned.",
        references=("https://docs.anthropic.com/en/docs/claude-code/plugins",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
            ("CWE", "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            trust = asset.data.get("trust")
            if trust == "unverified":
                findings.append(
                    self.warn(
                        asset.asset_id,
                        f"Plugin comes from unverified marketplace '{asset.data.get('marketplace')}'.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key="marketplace",
                                snippet=str(asset.data.get("marketplace")),
                                reason=str(asset.data.get("trust_reason")),
                            )
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"Marketplace '{asset.data.get('marketplace')}' is {trust} "
                        f"({asset.data.get('trust_reason')}).",
                    )
                )
        return findings


@register
class PluginDangerousHooks(Check):
    meta = CheckMeta(
        check_id="PLUGIN-002",
        title="Plugin registers dangerous hooks",
        description="A plugin-shipped hook runs a dangerous command or matches all tool calls.",
        category=Category.PLUGINS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=PLUGINS_ONLY,
        rationale=(
            "Plugin hooks execute automatically on agent events, without appearing as tool "
            "calls the operator can approve."
        ),
        security_impact="Gives the plugin an automatic, unattended execution path on every matching event.",
        remediation="Review the hook, narrow its matcher, and remove dangerous commands.",
        references=("https://docs.anthropic.com/en/docs/claude-code/hooks",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
            ("CWE", "CWE-506: Embedded Malicious Code"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            if not asset.data.get("has_hooks"):
                findings.append(self.not_applicable(asset.asset_id, "Plugin ships no hooks"))
                continue

            evidence = []
            for entry in asset.data.get("files") or []:
                if "/hooks/" not in f"/{entry['relative']}" and not entry["relative"].startswith("hooks/"):
                    continue
                for match in commands.scan_text(entry["text"]):
                    if match.is_failing:
                        evidence.append(
                            self.evidence(path=entry["path"], line=match.line, snippet=match.context,
                                          reason=f"{match.description} [{match.threat.value}]")
                        )
            if evidence:
                findings.append(
                    self.fail(asset.asset_id, "Plugin hooks contain dangerous commands.", evidence[:8])
                )
            else:
                findings.append(self.ok(asset.asset_id, "Plugin hooks contain no dangerous commands."))
        return findings


@register
class PluginShellExecution(Check):
    meta = CheckMeta(
        check_id="PLUGIN-003",
        title="Plugin executes shell commands",
        description="Bundled executable files invoke a shell or run commands.",
        category=Category.PLUGINS,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=PLUGINS_ONLY,
        rationale=(
            "Shell invocation in plugin code is common and often legitimate, so this is "
            "reported for review rather than as an outright failure unless the command is "
            "itself dangerous (covered by PLUGIN-002)."
        ),
        security_impact="Expands the plugin's capability beyond declared tool permissions.",
        remediation="Prefer language-native APIs to shelling out; validate any interpolated input.",
        references=("https://docs.anthropic.com/en/docs/claude-code/plugins",),
        compliance=(
            ("CWE", "CWE-78: Improper Neutralization of Special Elements used in an OS Command"),
        ),
    )

    SHELL_CALLS = (
        "subprocess.", "os.system", "os.popen", "child_process", "execSync", "spawnSync",
        "Runtime.getRuntime", "shell_exec", "Invoke-Expression",
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            files = _executable_files(asset)
            if not files:
                findings.append(self.not_applicable(asset.asset_id, "Plugin ships no executable files"))
                continue

            evidence = []
            for entry in files:
                for lineno, line in enumerate(entry["text"].splitlines(), start=1):
                    if any(marker in line for marker in self.SHELL_CALLS):
                        evidence.append(
                            self.evidence(path=entry["path"], line=lineno, snippet=line.strip()[:200],
                                          reason="Invokes a subprocess or shell")
                        )
                        break
            if evidence:
                findings.append(
                    self.warn(asset.asset_id,
                              f"{len(evidence)} bundled file(s) execute shell commands.",
                              evidence[:8], confidence=Confidence.MEDIUM)
                )
            else:
                findings.append(self.ok(asset.asset_id, "No shell execution in bundled files."))
        return findings


@register
class PluginSensitiveFilesystem(Check):
    meta = CheckMeta(
        check_id="PLUGIN-004",
        title="Plugin accesses sensitive filesystem paths",
        description="Bundled plugin code references a known credential location.",
        category=Category.PLUGINS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=PLUGINS_ONLY,
        rationale="Plugin code runs with the user's privileges and outside tool permission gating.",
        security_impact="Credentials can be read and transmitted without any agent tool call.",
        remediation="Remove credential path access from the plugin.",
        references=("https://docs.anthropic.com/en/docs/claude-code/plugins",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            evidence = []
            doc_files, hit_files = 0, 0
            for entry in _executable_files(asset):
                hits = []
                for lineno, line in enumerate(entry["text"].splitlines(), start=1):
                    hit, description = touches_sensitive(line)
                    if hit:
                        hits.append(
                            self.evidence(path=entry["path"], line=lineno,
                                          snippet=line.strip()[:200], reason=description)
                        )
                if hits:
                    hit_files += 1
                    if injection.is_security_document(entry["text"]):
                        doc_files += 1
                    evidence.extend(hits)
            if evidence:
                documentation_only = hit_files > 0 and doc_files == hit_files
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Plugin code references credential locations"
                        + (" (within security documentation)." if documentation_only else "."),
                        evidence[:8],
                        confidence=Confidence.LOW if documentation_only else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No credential path references."))
        return findings


@register
class PluginEmbeddedCredentials(Check):
    meta = CheckMeta(
        check_id="PLUGIN-005",
        title="Plugin contains embedded credentials",
        description="A credential literal appears in the plugin manifest or bundled files.",
        category=Category.PLUGINS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=PLUGINS_ONLY,
        rationale="Takes precedence over SECRET-* for plugin assets (spec 5, deduplication).",
        security_impact="The credential is distributed to every installation of the plugin.",
        remediation="Remove the literal, use environment indirection, and rotate the credential.",
        references=("https://docs.anthropic.com/en/docs/claude-code/plugins",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-798: Use of Hard-coded Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            evidence: list[Evidence] = []
            illustrative: list[Evidence] = []
            high = False
            for entry in asset.data.get("files") or []:
                # Redaction tests and integration fixtures embed sample tokens on
                # purpose — that is what they are testing. Reporting them as leaked
                # credentials at CRITICAL was the single largest source of noise on
                # a corpus of 83 public marketplace plugins.
                if is_test_file(entry["path"]):
                    continue
                # A hardening guide that shows `DB_PASSWORD = "hunter2"` under a
                # "don't do this" heading is documenting the mistake, not making it.
                # Same judgement the injection analyzer already applies to prose.
                documentation = entry["relative"].lower().endswith(
                    (".md", ".mdx", ".rst", ".txt")
                ) and injection.is_security_document(entry["text"])
                for match in secrets.scan_text(entry["text"])[:4]:
                    item = self.evidence(
                        path=entry["path"], line=match.line, snippet=match.redacted,
                        reason=match.description
                        + (" — in security documentation, likely illustrative"
                           if documentation else ""),
                    )
                    if documentation:
                        illustrative.append(item)
                        continue
                    evidence.append(item)
                    high = high or match.confidence == "HIGH"
            if evidence:
                findings.append(
                    self.fail(asset.asset_id, f"{len(evidence)} credential literal(s) in plugin files.",
                              evidence[:10],
                              confidence=Confidence.HIGH if high else Confidence.MEDIUM)
                )
            elif illustrative:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        f"{len(illustrative)} credential-shaped value(s), all in security "
                        "documentation.",
                        illustrative[:10],
                        confidence=Confidence.LOW,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No embedded credentials."))
        return findings


@register
class PluginSuspiciousUrls(Check):
    meta = CheckMeta(
        check_id="PLUGIN-006",
        title="Plugin references suspicious external URLs",
        description="Plugin files reference disposable hosting, tunnelling, or webhook-collector domains.",
        category=Category.PLUGINS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=PLUGINS_ONLY,
        rationale=(
            "Paste sites, request collectors, and tunnelling domains are the standard "
            "endpoints for exfiltration and for serving mutable payloads."
        ),
        security_impact="Provides a channel for data exfiltration or delivery of new instructions.",
        remediation="Remove the reference, or replace it with a vetted domain under your control.",
        references=("https://docs.anthropic.com/en/docs/claude-code/plugins",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("MITRE ATLAS", "AML.T0057: LLM Data Leakage"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            evidence = []
            doc_files, hit_files = 0, 0
            for entry in asset.data.get("files") or []:
                hits = []
                for line, host, url in injection.extract_urls(entry["text"]):
                    if injection.is_suspicious_host(host):
                        hits.append(
                            self.evidence(path=entry["path"], line=line, snippet=url,
                                          reason=f"{injection.classify_host(host)[1]} ({host})")
                        )
                if hits:
                    hit_files += 1
                    if injection.is_security_document(entry["text"]):
                        doc_files += 1
                    evidence.extend(hits)
            if evidence:
                documentation_only = hit_files > 0 and doc_files == hit_files
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Plugin references suspicious external endpoints"
                        + (" (within security documentation)." if documentation_only else "."),
                        evidence[:8],
                        confidence=Confidence.LOW if documentation_only else Confidence.HIGH,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No suspicious external URLs."))
        return findings


@register
class PluginUntrustedMcp(Check):
    meta = CheckMeta(
        check_id="PLUGIN-007",
        title="Plugin declares untrusted MCP dependencies",
        description="The plugin ships an .mcp.json defining servers launched from unpinned or remote sources.",
        category=Category.PLUGINS,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=PLUGINS_ONLY,
        rationale=(
            "A plugin-supplied MCP server is installed transitively — the operator approves "
            "the plugin, not each server it brings with it."
        ),
        security_impact="Extends the agent's tool surface with code the operator never directly reviewed.",
        remediation="Pin plugin-supplied MCP servers and review them as first-class dependencies.",
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
            ("CWE", "CWE-494: Download of Code Without Integrity Check"),
        ),
    )

    RUNNERS = {"npx", "uvx", "pipx", "bunx", "dlx"}

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            mcp = asset.data.get("mcp") or {}
            servers = mcp.get("mcpServers") if isinstance(mcp.get("mcpServers"), dict) else {}
            if not servers:
                findings.append(self.not_applicable(asset.asset_id, "Plugin declares no MCP servers"))
                continue

            evidence = []
            for name, spec in servers.items():
                if not isinstance(spec, dict):
                    continue
                command = str(spec.get("command") or "")
                base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
                url = spec.get("url") or ""
                if base in self.RUNNERS:
                    evidence.append(
                        self.evidence(path=asset.path, key=f"mcpServers.{name}.command",
                                      snippet=command,
                                      reason="Fetches and runs a package at launch time")
                    )
                if url:
                    evidence.append(
                        self.evidence(path=asset.path, key=f"mcpServers.{name}.url",
                                      snippet=str(url), reason="Remote MCP dependency")
                    )
            if evidence:
                findings.append(
                    self.fail(asset.asset_id, "Plugin brings unpinned or remote MCP dependencies.",
                              evidence[:8], confidence=Confidence.MEDIUM)
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, f"{len(servers)} MCP server(s), all locally pinned.")
                )
        return findings


@register
class PluginExcessivePrivileges(Check):
    meta = CheckMeta(
        check_id="PLUGIN-008",
        title="Plugin declares excessive privileges",
        description="The plugin manifest requests wildcard permissions or a very broad tool set.",
        category=Category.PLUGINS,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=PLUGINS_ONLY,
        rationale=(
            "Distinct from PLUGIN-003, which observes what the code does: this reads what "
            "the manifest asks for."
        ),
        security_impact="Broad declared privileges widen the reachable surface for injected instructions.",
        remediation="Narrow the manifest's declared permissions to what the plugin uses.",
        references=("https://docs.anthropic.com/en/docs/claude-code/plugins",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-269: Improper Privilege Management"),
        ),
    )

    BROAD = {"*", "all", "admin", "root", "full"}

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _plugins(context)
        if not assets:
            return self.no_assets("Plugins")

        findings: list[Finding] = []
        for asset in assets:
            manifest = asset.data.get("manifest") or {}
            evidence = []
            for key in ("permissions", "allowed-tools", "allowedTools", "capabilities", "scopes"):
                value = manifest.get(key)
                entries: list[str] = []
                if isinstance(value, str):
                    entries = [value]
                elif isinstance(value, list):
                    entries = [str(v) for v in value]
                elif isinstance(value, dict):
                    entries = [str(k) for k, v in value.items() if v is True]
                broad = [e for e in entries if e.strip().lower() in self.BROAD]
                if broad:
                    evidence.append(
                        self.evidence(path=asset.path, key=key, snippet=", ".join(broad),
                                      reason="Wildcard or administrative privilege requested")
                    )
            if evidence:
                findings.append(
                    self.fail(asset.asset_id, "Plugin manifest requests excessive privileges.", evidence)
                )
            else:
                findings.append(self.ok(asset.asset_id, "Manifest requests no wildcard privileges."))
        return findings
