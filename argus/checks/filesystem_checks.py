"""Section 8 — Filesystem checks (FS-001 … FS-007).

"Reachable" is defined by spec 5.8: the path is *not denied* by the effective Claude
permission ruleset **and** is readable by the current user. Both conditions give a
HIGH-confidence finding; either alone is reported at reduced confidence.

FS-005 and FS-007 depend on POSIX mode bits and return NOT_APPLICABLE on Windows.
"""

from __future__ import annotations

from ..analysis.paths import PermissionRules
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
from ..discovery.platform import is_posix
from .base import Check, CheckContext

FS_TARGETS = frozenset({Target.FILESYSTEM, Target.CLAUDE_CODE})


def _effective_rules(context: CheckContext) -> PermissionRules:
    """Merge every discovered settings file into one effective ruleset.

    Deny rules union across scopes — a denial anywhere counts — which is the
    conservative reading for an exposure check.
    """
    allow: list[str] = []
    deny: list[str] = []
    ask: list[str] = []
    mode: str | None = None
    for asset in context.by_target(Target.CLAUDE_CODE):
        if not asset.asset_id.endswith("settings"):
            continue
        rules = PermissionRules.from_settings(asset.data.get("settings") or {})
        allow.extend(rules.allow)
        deny.extend(rules.deny)
        ask.extend(rules.ask)
        mode = mode or rules.default_mode
    return PermissionRules(allow=allow, deny=deny, ask=ask, default_mode=mode)


def _credential_assets(context: CheckContext, category: str | None = None) -> list[Asset]:
    return [
        a
        for a in context.by_target(Target.FILESYSTEM)
        if a.data.get("kind") == "credential-location"
        and (category is None or a.data.get("category") == category)
    ]


def _reachability(asset: Asset, rules: PermissionRules) -> tuple[bool, Confidence, str]:
    """Apply the spec 5.8 reachability definition."""
    readable = bool(asset.data.get("readable"))
    denied = rules.denies_path(str(asset.path))
    if readable and not denied:
        return True, Confidence.HIGH, "readable by this user and not covered by any deny rule"
    if readable and denied:
        return False, Confidence.HIGH, "readable, but a deny rule covers this path"
    if not readable and not denied:
        return True, Confidence.LOW, "not covered by a deny rule, but not readable by this user"
    return False, Confidence.HIGH, "not readable and denied"


@register
class SensitiveFileReachable(Check):
    meta = CheckMeta(
        check_id="FS-001",
        title="Sensitive file reachable by agent",
        description="A credential-bearing location is readable and not covered by any deny rule.",
        category=Category.FILESYSTEM,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=FS_TARGETS,
        rationale=(
            "Reachability combines OS permissions with the agent's permission ruleset. "
            "Reporting on either alone would produce findings that are not actually "
            "exploitable, or miss ones that are."
        ),
        security_impact="Credential material can be read into agent context by a file-reading tool.",
        remediation="Add deny rules covering these paths in ~/.claude/settings.json.",
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-552: Files or Directories Accessible to External Parties"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _credential_assets(context)
        if not assets:
            return [self.not_applicable("-", "No credential locations exist for this user")]

        rules = _effective_rules(context)
        reachable = []
        lowest = Confidence.HIGH
        for asset in assets:
            is_reachable, confidence, reason = _reachability(asset, rules)
            if is_reachable:
                reachable.append((asset, reason))
                if confidence is Confidence.LOW:
                    lowest = Confidence.LOW

        if not reachable:
            return [self.ok("filesystem", f"All {len(assets)} credential location(s) are denied.")]

        return [
            self.fail(
                "filesystem",
                f"{len(reachable)} of {len(assets)} credential location(s) are reachable by the agent.",
                [
                    self.evidence(
                        path=asset.path,
                        snippet=str(asset.data.get("description")),
                        reason=reason,
                    )
                    for asset, reason in reachable[:12]
                ],
                confidence=lowest,
            )
        ]


@register
class CredentialDirectoriesReachable(Check):
    meta = CheckMeta(
        check_id="FS-002",
        title="Credential directories reachable by agent",
        description="Directory-level credential stores are reachable rather than individual files.",
        category=Category.FILESYSTEM,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=FS_TARGETS,
        rationale=(
            "A reachable directory exposes future contents too, so it is a durable "
            "exposure rather than a point-in-time one."
        ),
        security_impact="Every credential now or later placed in the directory is exposed.",
        remediation="Deny the directory recursively, e.g. Read(~/.aws/**).",
        references=("https://docs.anthropic.com/en/docs/claude-code/settings",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-552: Files or Directories Accessible to External Parties"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = [
            a
            for a in _credential_assets(context)
            if a.path is not None and a.path.is_dir()
        ]
        if not assets:
            return [self.not_applicable("-", "No credential directories exist for this user")]

        rules = _effective_rules(context)
        exposed = []
        for asset in assets:
            is_reachable, _confidence, reason = _reachability(asset, rules)
            if is_reachable:
                exposed.append((asset, reason))

        if not exposed:
            return [self.ok("filesystem", f"All {len(assets)} credential director(y/ies) are denied.")]
        return [
            self.fail(
                "filesystem",
                f"{len(exposed)} credential director(y/ies) reachable by the agent.",
                [
                    self.evidence(path=a.path, snippet=str(a.data.get("description")), reason=reason)
                    for a, reason in exposed[:10]
                ],
            )
        ]


@register
class SshPrivateKeysReachable(Check):
    meta = CheckMeta(
        check_id="FS-003",
        title="SSH private keys reachable by agent",
        description="Private key files in ~/.ssh are readable and not denied.",
        category=Category.FILESYSTEM,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=FS_TARGETS,
        rationale=(
            "Key files are identified by name and location only — Argus never reads key "
            "contents, so no key material passes through the scanner."
        ),
        security_impact=(
            "An exfiltrated SSH key grants access to every host trusting it, turning a "
            "local agent compromise into lateral movement."
        ),
        remediation="Add Read(~/.ssh/**) to the deny list and ensure keys are passphrase-protected.",
        references=("https://cwe.mitre.org/data/definitions/522.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _credential_assets(context, "ssh")
        keys = [k for a in assets for k in (a.data.get("private_keys") or [])]
        if not keys:
            return [self.not_applicable("-", "No SSH private keys found for this user")]

        rules = _effective_rules(context)
        exposed = [k for k in keys if not rules.denies_path(k)]
        if not exposed:
            return [self.ok("~/.ssh", f"All {len(keys)} private key(s) are covered by deny rules.")]
        return [
            self.fail(
                "~/.ssh",
                f"{len(exposed)} SSH private key(s) are reachable by the agent.",
                [
                    self.evidence(path=key, reason="Private key not covered by any deny rule")
                    for key in exposed[:10]
                ],
            )
        ]


@register
class CloudCredentialFilesReachable(Check):
    meta = CheckMeta(
        check_id="FS-004",
        title="Cloud credential files reachable by agent",
        description="AWS, GCP, Azure or Kubernetes credential stores are readable and not denied.",
        category=Category.FILESYSTEM,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=FS_TARGETS,
        rationale="Detected by location; contents are never read.",
        security_impact=(
            "Cloud credentials extend a local compromise into the organisation's "
            "infrastructure and data."
        ),
        remediation="Deny cloud credential paths and prefer short-lived, role-based credentials.",
        references=("https://cwe.mitre.org/data/definitions/522.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _credential_assets(context, "cloud")
        if not assets:
            return [self.not_applicable("-", "No cloud credential files found for this user")]

        rules = _effective_rules(context)
        exposed = []
        for asset in assets:
            is_reachable, _confidence, reason = _reachability(asset, rules)
            if is_reachable:
                exposed.append((asset, reason))

        if not exposed:
            return [self.ok("filesystem", f"All {len(assets)} cloud credential store(s) are denied.")]
        return [
            self.fail(
                "filesystem",
                f"{len(exposed)} cloud credential store(s) are reachable by the agent.",
                [
                    self.evidence(path=a.path, snippet=str(a.data.get("description")), reason=reason)
                    for a, reason in exposed[:10]
                ],
            )
        ]


@register
class UnsafeConfigPermissions(Check):
    meta = CheckMeta(
        check_id="FS-005",
        title="Unsafe permissions on agent configuration file",
        description="An agent configuration file is group- or world-readable.",
        category=Category.FILESYSTEM,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=frozenset({Target.FILESYSTEM}),
        rationale=(
            "Files such as .credentials.json hold live tokens and must be owner-only. "
            "This check relies on POSIX mode bits and is not applicable on Windows."
        ),
        security_impact="Any local account can read the agent's stored credentials and configuration.",
        remediation="Restrict permissions to 0600 (files) or 0700 (directories).",
        references=("https://cwe.mitre.org/data/definitions/732.html",),
        compliance=(
            ("CWE", "CWE-732: Incorrect Permission Assignment for Critical Resource"),
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        if not is_posix():
            return [
                self.not_applicable(
                    "filesystem",
                    "POSIX permission bits are not meaningful on Windows; review ACLs instead",
                )
            ]

        assets = [
            a
            for a in context.by_target(Target.FILESYSTEM)
            if a.data.get("kind") == "agent-config" and a.data.get("mode") is not None
        ]
        if not assets:
            return [self.not_applicable("-", "No agent configuration files discovered")]

        findings: list[Finding] = []
        unsafe = []
        for asset in assets:
            mode = int(asset.data.get("mode") or 0)
            sensitive = bool(asset.data.get("sensitive"))
            # Credential-bearing files must be owner-only; ordinary settings may be
            # group/world readable without exposing secrets, so only writability matters.
            bad = (mode & 0o077) if sensitive else (mode & 0o022)
            if bad:
                unsafe.append((asset, mode, sensitive))

        if unsafe:
            findings.append(
                self.fail(
                    "filesystem",
                    f"{len(unsafe)} agent configuration file(s) have overly permissive modes.",
                    [
                        self.evidence(
                            path=a.path,
                            snippet=f"mode {mode:04o}",
                            reason=(
                                "Credential-bearing file is accessible beyond its owner"
                                if sensitive
                                else "Configuration file is group- or world-writable"
                            ),
                        )
                        for a, mode, sensitive in unsafe[:10]
                    ],
                )
            )
        else:
            findings.append(
                self.ok("filesystem", f"All {len(assets)} configuration file(s) have safe permissions.")
            )
        return findings


@register
class SymlinkEscape(Check):
    meta = CheckMeta(
        check_id="FS-006",
        title="Symlink escapes the workspace",
        description="A symlink inside the project resolves to a location outside it.",
        category=Category.FILESYSTEM,
        severity=Severity.MEDIUM,
        aasb_level=2,
        applies_to=frozenset({Target.FILESYSTEM}),
        rationale=(
            "Path-scoped permission rules are evaluated against the link path, so a link "
            "that resolves elsewhere can defeat a scope the operator believes is enforced."
        ),
        security_impact=(
            "An agent restricted to the project directory can read or write outside it by "
            "traversing the link."
        ),
        remediation="Remove the symlink or repoint it inside the workspace.",
        references=("https://cwe.mitre.org/data/definitions/59.html",),
        compliance=(
            ("CWE", "CWE-59: Improper Link Resolution Before File Access"),
            ("CWE", "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = [a for a in context.by_target(Target.FILESYSTEM) if a.data.get("kind") == "symlinks"]
        if not assets:
            return [self.ok("workspace", "No symlinks escaping the workspace.")]

        escaping = [e for a in assets for e in (a.data.get("escaping") or [])]
        if not escaping:
            return [self.ok("workspace", "No symlinks escaping the workspace.")]
        return [
            self.fail(
                "workspace",
                f"{len(escaping)} symlink(s) resolve outside the project directory.",
                [
                    self.evidence(
                        path=entry["link"],
                        snippet=f"-> {entry['target']}",
                        reason="Link target lies outside the scan root",
                    )
                    for entry in escaping[:10]
                ],
                confidence=Confidence.MEDIUM,
            )
        ]


@register
class WorldWritableConfig(Check):
    meta = CheckMeta(
        check_id="FS-007",
        title="World-writable agent configuration",
        description="An agent configuration file or directory is writable by any local user.",
        category=Category.FILESYSTEM,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=frozenset({Target.FILESYSTEM}),
        rationale=(
            "Distinct from FS-005, which covers read exposure. Write access to agent "
            "configuration is a direct path to controlling the agent. POSIX-only."
        ),
        security_impact=(
            "Any local user can add MCP servers, hooks, or permission grants, achieving "
            "code execution as the agent's owner."
        ),
        remediation="Remove world-write permission immediately (chmod o-w).",
        references=("https://cwe.mitre.org/data/definitions/732.html",),
        compliance=(
            ("CWE", "CWE-732: Incorrect Permission Assignment for Critical Resource"),
            ("OWASP LLM Top 10 2025", "LLM03: Supply Chain"),
        ),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        if not is_posix():
            return [
                self.not_applicable(
                    "filesystem",
                    "POSIX permission bits are not meaningful on Windows; review ACLs instead",
                )
            ]

        assets = [
            a
            for a in context.by_target(Target.FILESYSTEM)
            if a.data.get("kind") == "agent-config" and a.data.get("mode") is not None
        ]
        if not assets:
            return [self.not_applicable("-", "No agent configuration files discovered")]

        writable = [(a, int(a.data.get("mode") or 0)) for a in assets if int(a.data.get("mode") or 0) & 0o002]
        if writable:
            return [
                self.fail(
                    "filesystem",
                    f"{len(writable)} agent configuration file(s) are world-writable.",
                    [
                        self.evidence(
                            path=a.path,
                            snippet=f"mode {mode:04o}",
                            reason="Writable by any local user — allows agent takeover",
                        )
                        for a, mode in writable
                    ],
                )
            ]
        return [self.ok("filesystem", f"No world-writable configuration among {len(assets)} file(s).")]
