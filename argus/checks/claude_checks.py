"""Section 1 — Claude Configuration checks (CLAUDE-001 … CLAUDE-010)."""

from __future__ import annotations

from typing import Any

from ..analysis.paths import (
    DANGEROUS_TOOLS,
    SENSITIVE_HOME_PATHS,
    PermissionRules,
    is_root_scope,
    touches_sensitive,
)
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

CLAUDE_TARGETS = frozenset({Target.CLAUDE_CODE, Target.CLAUDE_DESKTOP})


def _settings_assets(context: CheckContext) -> list[Asset]:
    return [
        a
        for a in context.by_target(Target.CLAUDE_CODE)
        if a.asset_id.endswith("settings") and not a.data.get("malformed")
    ]


def _rules(asset: Asset) -> PermissionRules:
    return PermissionRules.from_settings(asset.data.get("settings") or {})


#: Explains why a settings file without a permissions block is skipped rather than
#: failed. Measured against 150 public ``.claude/settings.json`` files, treating the
#: absent block as a finding fired on roughly three quarters of them — a rate at
#: which the check stops carrying information. A file that declares no permissions
#: grants nothing extra; the effective policy comes from user settings and the
#: product defaults, neither of which this asset can answer for.
_NO_POLICY = (
    "No permissions block in this file — it grants nothing, so the effective "
    "policy comes from user settings and defaults"
)


@register
class DangerousPermissionConfiguration(Check):
    meta = CheckMeta(
        check_id="CLAUDE-001",
        title="Dangerous permission configuration",
        description=(
            "Claude Code settings define no permission ruleset, or set a default mode "
            "that grants tool use without review."
        ),
        category=Category.CLAUDE,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "With no allow/deny/ask rules, tool authorisation falls back to interactive "
            "prompting only. A permissive defaultMode removes even that, so any prompt "
            "injection that reaches the agent inherits the operator's full tool access."
        ),
        security_impact=(
            "An attacker who can influence agent context — through a poisoned instruction "
            "file, a hostile repository, or injected tool output — can invoke tools without "
            "an approval gate."
        ),
        remediation=(
            "Define an explicit permissions block in ~/.claude/settings.json with a deny "
            "list for credential paths and destructive commands, and leave defaultMode at "
            "its interactive default."
        ),
        references=(
            "https://docs.anthropic.com/en/docs/claude-code/settings",
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-1188: Initialization of a Resource with an Insecure Default"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
        ),
    )

    PERMISSIVE_MODES = {"bypasspermissions", "acceptedits", "plan-bypass"}

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        findings: list[Finding] = []
        for asset in assets:
            rules = _rules(asset)
            evidence = []
            problems = []

            mode = (rules.default_mode or "").strip().lower()
            if rules.is_empty and mode not in self.PERMISSIVE_MODES:
                findings.append(self.not_applicable(asset.asset_id, _NO_POLICY))
                continue

            if mode in self.PERMISSIVE_MODES:
                problems.append(f"defaultMode is '{rules.default_mode}'")
                evidence.append(
                    self.evidence(
                        path=asset.path,
                        asset=asset,
                        key="permissions.defaultMode",
                        snippet=str(rules.default_mode),
                        reason="Permissive default grants tool use without per-call approval",
                    )
                )

            if problems:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"Permission configuration is unsafe: {', and '.join(problems)}.",
                        evidence,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"Permission ruleset present ({len(rules.allow)} allow, "
                        f"{len(rules.deny)} deny, {len(rules.ask)} ask).",
                    )
                )
        return findings


@register
class UnrestrictedBash(Check):
    meta = CheckMeta(
        check_id="CLAUDE-002",
        title="Unrestricted Bash execution permitted",
        description="An allow rule grants the Bash tool with no command constraint.",
        category=Category.CLAUDE,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "'Bash' or 'Bash(*)' in the allow list pre-authorises every shell command. "
            "Argument-scoped rules such as 'Bash(git status:*)' do not carry this risk."
        ),
        security_impact=(
            "Unrestricted shell access is full local code execution under the operator's "
            "account. It is the highest-value target for prompt injection against an agent."
        ),
        remediation=(
            "Replace the blanket grant with argument-scoped rules, e.g. "
            "'Bash(git status:*)', and add deny rules for destructive commands."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-78: Improper Neutralization of Special Elements used in an OS Command"),
            ("MITRE ATLAS", "AML.T0051: LLM Prompt Injection"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        findings: list[Finding] = []
        for asset in assets:
            rules = _rules(asset)
            offending = [
                rule for rule, _reason, _sev in rules.unrestricted_grants() if rule.startswith("Bash")
            ]
            if offending:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Bash is allowed without any command constraint.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key="permissions.allow",
                                snippet=rule,
                                reason="Grants every shell command, not a specific invocation",
                            )
                            for rule in offending
                        ],
                    )
                )
            else:
                scoped = rules.grants_tool("Bash")
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"No blanket Bash grant ({len(scoped)} argument-scoped rule(s) present).",
                    )
                )
        return findings


@register
class UnrestrictedFilesystemAccess(Check):
    meta = CheckMeta(
        check_id="CLAUDE-003",
        title="Unrestricted filesystem access permitted",
        description=(
            "File tools are granted without path constraints, or an additional working "
            "directory is rooted at / or the home directory."
        ),
        category=Category.CLAUDE,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "Write and Edit grants without a path scope let the agent modify any file the "
            "user can, including shell profiles and the agent's own configuration."
        ),
        security_impact=(
            "Enables persistence (writing to shell rc files), self-modification of agent "
            "permissions, and tampering with unrelated projects on the same machine."
        ),
        remediation=(
            "Scope file tool grants to the project directory, e.g. 'Edit(./src/**)', and "
            "avoid adding '/' or '~' to additionalDirectories."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-732: Incorrect Permission Assignment for Critical Resource"),
        ),
    )

    FILE_TOOLS = ("Write", "Edit", "NotebookEdit")

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        findings: list[Finding] = []
        for asset in assets:
            settings: dict[str, Any] = asset.data.get("settings") or {}
            rules = _rules(asset)
            evidence = []

            for rule, _reason, _sev in rules.unrestricted_grants():
                if rule.split("(")[0] in self.FILE_TOOLS:
                    evidence.append(
                        self.evidence(
                            path=asset.path,
                            asset=asset,
                            key="permissions.allow",
                            snippet=rule,
                            reason="File tool granted with no path scope",
                        )
                    )

            extra = settings.get("additionalDirectories") or (
                (settings.get("permissions") or {}).get("additionalDirectories")
                if isinstance(settings.get("permissions"), dict)
                else None
            )
            if isinstance(extra, list):
                for entry in extra:
                    if isinstance(entry, str) and is_root_scope(entry):
                        evidence.append(
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key="additionalDirectories",
                                snippet=entry,
                                reason="Working directory is rooted at / or the home directory",
                            )
                        )

            if evidence:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Filesystem access is granted without meaningful path restrictions.",
                        evidence,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, "No unrestricted filesystem grants found."))
        return findings


@register
class SensitiveDirectoriesReachable(Check):
    meta = CheckMeta(
        check_id="CLAUDE-004",
        title="Sensitive directories reachable by agent",
        description=(
            "Credential directories that exist on this host are not covered by any deny "
            "rule in the effective permission ruleset."
        ),
        category=Category.CLAUDE,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "Argus only reports credential locations that actually exist and are readable "
            "by the current user, so this reflects real exposure rather than a hypothetical."
        ),
        security_impact=(
            "A prompt injection that reaches a file-reading tool can retrieve SSH keys, "
            "cloud credentials, or agent OAuth tokens and exfiltrate them through any "
            "permitted network tool."
        ),
        remediation=(
            "Add deny rules covering credential paths, for example "
            "Read(~/.ssh/**), Read(~/.aws/**), Read(**/.env)."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        present = [
            (rel, desc)
            for rel, desc, _kind in SENSITIVE_HOME_PATHS
            if (context.home / rel).exists()
        ]
        if not present:
            return [
                self.not_applicable("-", "No known credential directories exist for this user")
            ]

        findings: list[Finding] = []
        for asset in assets:
            rules = _rules(asset)
            if rules.is_empty:
                findings.append(self.not_applicable(asset.asset_id, _NO_POLICY))
                continue
            exposed = [
                (rel, desc)
                for rel, desc in present
                if not rules.denies_path(str(context.home / rel))
            ]
            if exposed:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(exposed)} credential location(s) present on this host are not "
                        "covered by a deny rule.",
                        [
                            self.evidence(
                                path=context.home / rel,
                                key="permissions.deny",
                                reason=f"{desc} — no deny rule matches this path",
                            )
                            for rel, desc in exposed[:12]
                        ],
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, "All present credential locations are denied.")
                )
        return findings


@register
class NetworkAccessUnrestricted(Check):
    meta = CheckMeta(
        check_id="CLAUDE-005",
        title="Network access not sufficiently restricted",
        description="Network-capable tools are allowed without a domain allowlist.",
        category=Category.CLAUDE,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "An unconstrained WebFetch grant provides an outbound channel to any host. "
            "Exfiltration requires both read access and an egress path; this check covers "
            "the egress half."
        ),
        security_impact=(
            "Data read by the agent can be sent to an attacker-controlled endpoint, and "
            "remote content can be pulled into context to drive further injection."
        ),
        remediation=(
            "Constrain network tools to specific domains, e.g. "
            "'WebFetch(domain:docs.anthropic.com)', and deny the rest."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"),
        ),
    )

    NETWORK_TOOLS = ("WebFetch", "WebSearch")

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        findings: list[Finding] = []
        for asset in assets:
            rules = _rules(asset)
            evidence = []
            for tool in self.NETWORK_TOOLS:
                for rule in rules.grants_tool(tool):
                    stripped = rule.strip()
                    if stripped == tool or stripped == f"{tool}(*)":
                        evidence.append(
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key="permissions.allow",
                                snippet=rule,
                                reason=f"{tool} allowed with no domain restriction",
                            )
                        )
            if evidence:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Network tools are permitted without a domain allowlist.",
                        evidence,
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, "No unrestricted network tool grants found.")
                )
        return findings


@register
class PermissionPromptsBypassed(Check):
    meta = CheckMeta(
        check_id="CLAUDE-006",
        title="Permission prompts bypassed or sandbox disabled",
        description=(
            "Settings disable the interactive approval gate or opt out of sandboxing."
        ),
        category=Category.CLAUDE,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "The approval prompt is the last human control between an injected instruction "
            "and a privileged action. Disabling it removes the only interactive defence."
        ),
        security_impact=(
            "Every other permission weakness becomes directly exploitable, because no human "
            "sees the tool call before it runs."
        ),
        remediation=(
            "Remove skipDangerousModePermissionPrompt / dangerouslySkipPermissions from "
            "settings, and keep sandboxing enabled."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-250: Execution with Unnecessary Privileges"),
            ("MITRE ATLAS", "AML.T0054: LLM Jailbreak"),
        ),
    )

    BYPASS_KEYS = {
        "skipDangerousModePermissionPrompt": "Dangerous-mode approval prompt suppressed",
        "dangerouslySkipPermissions": "All permission prompts skipped",
        "bypassPermissions": "Permission enforcement bypassed",
        "disableSandbox": "Sandbox explicitly disabled",
        "disableBashSandbox": "Bash sandbox explicitly disabled",
    }

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        findings: list[Finding] = []
        for asset in assets:
            settings: dict[str, Any] = asset.data.get("settings") or {}
            evidence = []
            for key, reason in self.BYPASS_KEYS.items():
                if settings.get(key) is True:
                    evidence.append(
                        self.evidence(
                            path=asset.path, key=key, snippet="true", reason=reason
                        )
                    )
            sandbox = settings.get("sandbox")
            if sandbox is False:
                evidence.append(
                    self.evidence(
                        path=asset.path, key="sandbox", snippet="false",
                        reason="Sandboxing turned off",
                    )
                )

            if evidence:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Interactive approval or sandboxing has been disabled in settings.",
                        evidence,
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, "Approval prompts and sandboxing are not disabled.")
                )
        return findings


@register
class DangerousToolsWithoutApproval(Check):
    meta = CheckMeta(
        check_id="CLAUDE-007",
        title="Dangerous tools allowed without approval",
        description=(
            "High-impact tools are pre-authorised in the allow list with no corresponding "
            "ask rule requiring confirmation."
        ),
        category=Category.CLAUDE,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "An allow rule silences the approval prompt for that tool. Where the tool can "
            "execute code or write files, that removes the human review step entirely."
        ),
        security_impact=(
            "Injected instructions can reach destructive tooling without the operator "
            "observing the call."
        ),
        remediation=(
            "Move high-impact tools from 'allow' to 'ask' so each invocation is confirmed, "
            "or scope the allow rule to specific safe arguments."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-269: Improper Privilege Management"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        findings: list[Finding] = []
        for asset in assets:
            rules = _rules(asset)
            ask_tools = {r.split("(")[0].strip() for r in rules.ask}
            evidence = []
            for rule, reason, _severity in rules.unrestricted_grants():
                tool = rule.split("(")[0].strip()
                if tool in ask_tools:
                    continue
                evidence.append(
                    self.evidence(
                        path=asset.path,
                        asset=asset,
                        key="permissions.allow",
                        snippet=rule,
                        reason=f"Pre-authorised without an ask rule — permits {reason}",
                    )
                )
            if evidence:
                worst = max(
                    (
                        Severity.parse(sev)
                        for _r, _reason, sev in rules.unrestricted_grants()
                        if _r.split("(")[0].strip() not in ask_tools
                    ),
                    key=lambda s: s.rank,
                    default=Severity.HIGH,
                )
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(evidence)} high-impact tool grant(s) bypass the approval gate.",
                        evidence,
                        severity=worst,
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, "No unapproved high-impact tool grants found.")
                )
        return findings


@register
class MissingDenyRules(Check):
    meta = CheckMeta(
        check_id="CLAUDE-008",
        title="Missing deny rules for sensitive operations",
        description=(
            "The permission ruleset contains no deny entries covering credential paths or "
            "destructive commands."
        ),
        category=Category.CLAUDE,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "Deny rules are evaluated ahead of allow rules, so they are the only construct "
            "that holds regardless of what a future allow rule permits."
        ),
        security_impact=(
            "Without explicit denials, broadening an allow rule later silently re-exposes "
            "credential paths."
        ),
        remediation=(
            "Add deny rules for credential reads and destructive shell commands, e.g. "
            "Read(~/.ssh/**), Read(**/.env), Bash(curl:*), Bash(rm -rf:*)."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-693: Protection Mechanism Failure"),
        ),
    )

    EXPECTED = ("ssh", "aws", "env", "credential", "curl", "rm", "token", "secret")

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _settings_assets(context)
        if not assets:
            return self.no_assets("Claude Code settings files")

        findings: list[Finding] = []
        for asset in assets:
            rules = _rules(asset)
            if rules.is_empty:
                findings.append(self.not_applicable(asset.asset_id, _NO_POLICY))
                continue
            if not rules.deny:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "No deny rules are configured.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key="permissions.deny",
                                reason="Deny list is empty or absent",
                            )
                        ],
                        confidence=Confidence.HIGH,
                    )
                )
                continue

            missing = [kw for kw in self.EXPECTED if not rules.has_deny_for(kw)]
            if len(missing) >= len(self.EXPECTED) - 1:
                findings.append(
                    self.warn(
                        asset.asset_id,
                        "Deny rules exist but cover none of the common sensitive operations.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key="permissions.deny",
                                snippet=", ".join(rules.deny[:5]),
                                reason=f"No deny rule references: {', '.join(missing[:6])}",
                            )
                        ],
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"{len(rules.deny)} deny rule(s) configured covering sensitive operations.",
                    )
                )
        return findings


@register
class DesktopBypassPermissions(Check):
    meta = CheckMeta(
        check_id="CLAUDE-009",
        title="Claude Desktop permission bypass enabled",
        description=(
            "Claude Desktop preferences opt an account into bypassing permission prompts "
            "or enable developer mode."
        ),
        category=Category.CLAUDE,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=frozenset({Target.CLAUDE_DESKTOP}),
        rationale=(
            "Claude Desktop stores per-account opt-ins for permission bypass. When set, "
            "local tool and MCP invocations proceed without interactive confirmation."
        ),
        security_impact=(
            "Every MCP server configured in Claude Desktop can be driven without an "
            "approval step, including servers that execute local commands."
        ),
        remediation=(
            "Disable permission bypass in Claude Desktop settings and re-enable prompting "
            "for local tool execution."
        ),
        references=("https://modelcontextprotocol.io/docs/concepts/architecture",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM06: Excessive Agency"),
            ("CWE", "CWE-250: Execution with Unnecessary Privileges"),
        ),
    )

    BYPASS_PREFIXES = ("bypassPermissions", "developerMode", "allowUnsignedExtensions")

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.CLAUDE_DESKTOP)
        if not assets:
            return self.no_assets("Claude Desktop configuration")

        findings: list[Finding] = []
        for asset in assets:
            preferences = asset.data.get("preferences") or {}
            evidence = []
            for key, value in preferences.items():
                if not any(str(key).startswith(p) for p in self.BYPASS_PREFIXES):
                    continue
                enabled_for: list[str] = []
                if value is True:
                    enabled_for = ["(global)"]
                elif isinstance(value, dict):
                    enabled_for = [str(k) for k, v in value.items() if v is True]
                if enabled_for:
                    evidence.append(
                        self.evidence(
                            path=asset.path,
                            asset=asset,
                            key=f"preferences.{key}",
                            snippet=f"enabled for {len(enabled_for)} account(s)",
                            reason="Permission bypass or developer mode is switched on",
                        )
                    )
            if evidence:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        "Claude Desktop is configured to bypass permission prompts.",
                        evidence,
                    )
                )
            else:
                findings.append(
                    self.ok(asset.asset_id, "No permission bypass preferences enabled.")
                )
        return findings


@register
class ProjectTrustScope(Check):
    meta = CheckMeta(
        check_id="CLAUDE-010",
        title="Project trust accepted for sensitive directories",
        description=(
            "Claude Code has recorded trust for directories that sit at a filesystem root, "
            "a home directory, or a known credential location."
        ),
        category=Category.CLAUDE,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=frozenset({Target.CLAUDE_CODE}),
        rationale=(
            "Trusting a directory enables project-scoped configuration — including .mcp.json "
            "and CLAUDE.md — to take effect without further prompting. Trust granted at a "
            "home or root directory extends that to everything beneath it."
        ),
        security_impact=(
            "Any file dropped into a broadly-trusted directory can silently supply agent "
            "configuration or instructions."
        ),
        remediation=(
            "Trust individual project directories rather than home or root, and review "
            "recorded trust in ~/.claude.json."
        ),
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM01: Prompt Injection"),
            ("CWE", "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = [a for a in context.by_target(Target.CLAUDE_CODE) if "global-state" in a.asset_id]
        if not assets:
            return self.no_assets("Claude Code global state")

        findings: list[Finding] = []
        home_str = str(context.home)

        for asset in assets:
            projects = asset.data.get("projects") or {}
            trusted = [
                path
                for path, block in projects.items()
                if isinstance(block, dict) and block.get("hasTrustDialogAccepted") is True
            ]
            risky = []
            for path in trusted:
                normalized = str(path).rstrip("/") or "/"
                if normalized in ("/", home_str, "/home", "/Users"):
                    risky.append((path, "Trust granted at a home or filesystem root"))
                    continue
                sensitive, description = touches_sensitive(path)
                if sensitive:
                    risky.append((path, f"Trust granted over {description}"))

            if risky:
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(risky)} trusted director(y/ies) have an over-broad scope.",
                        [
                            self.evidence(
                                path=asset.path,
                                asset=asset,
                                key=f"projects.{path}",
                                snippet=path,
                                reason=reason,
                            )
                            for path, reason in risky[:10]
                        ],
                        confidence=Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(
                    self.ok(
                        asset.asset_id,
                        f"{len(trusted)} trusted project director(y/ies), none over-broad.",
                    )
                )
        return findings


__all__ = ["CLAUDE_TARGETS", "DANGEROUS_TOOLS"]
