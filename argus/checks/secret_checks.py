"""Section 7 — Secrets checks (SECRET-001 … SECRET-005).

Per the deduplication rule (spec 5), this family covers assets no other category
owns: agent configuration files, credential stores, and the process environment.
Secrets inside MCP configs, Skills, Plugins and instruction files are reported by
MCP-006, SKILL-006, PLUGIN-005 and INSTR-001 respectively, so they are excluded here.

No check in this family ever emits an unredacted value.
"""

from __future__ import annotations

from ..analysis import secrets
from ..analysis.redaction import redact
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
from ..core.safe_io import read_text
from .base import Check, CheckContext

SECRET_TARGETS = frozenset({Target.CLAUDE_CODE, Target.CLAUDE_DESKTOP, Target.FILESYSTEM})

#: Purpose-built credential stores. These files exist *to* hold a credential, so
#: reporting "a secret was found here" is noise — the real control is whether their
#: permissions are correct, which FS-005 and FS-007 evaluate. Scanning them would
#: also mean reading live tokens into the scanner for no analytic gain.
DESIGNATED_CREDENTIAL_STORES = (
    ".claude/.credentials.json",
    ".config/gh/hosts.yml",
    ".aws/credentials",
    ".netrc",
    ".npmrc",
    ".git-credentials",
)


def _is_credential_store(asset: Asset) -> bool:
    if asset.path is None:
        return False
    normalized = str(asset.path).replace("\\", "/")
    return any(normalized.endswith(name) for name in DESIGNATED_CREDENTIAL_STORES)


def _owned_assets(context: CheckContext) -> list[Asset]:
    """Assets in this family's scope — not owned by a more specific category."""
    out: list[Asset] = []
    for asset in context.assets:
        if _is_credential_store(asset):
            continue
        # Kept as separate branches: the two conditions are unrelated ownership rules,
        # and collapsing them into one `or` obscures which asset kinds are in scope.
        if asset.target in (Target.CLAUDE_CODE, Target.CLAUDE_DESKTOP):  # noqa: SIM114
            out.append(asset)
        elif asset.target is Target.FILESYSTEM and asset.data.get("kind") in (
            "agent-config",
            "environment",
        ):
            out.append(asset)
    return out


def _asset_text(asset: Asset) -> str:
    if asset.text:
        return asset.text
    if asset.data.get("kind") == "environment":
        return "\n".join(f"{k}={v}" for k, v in (asset.data.get("variables") or {}).items())
    if asset.path and asset.path.is_file():
        try:
            return read_text(asset.path)
        except (OSError, ValueError):
            return ""
    return ""


class _SecretFamilyCheck(Check):
    """Shared implementation: scan owned assets and keep matches of one kind."""

    KINDS: tuple[str, ...] = ()
    SUBJECT = "secrets"

    def run(self, context: CheckContext) -> list[Finding]:
        assets = _owned_assets(context)
        if not assets:
            return self.no_assets("agent configuration or environment sources")

        findings: list[Finding] = []
        for asset in assets:
            text = _asset_text(asset)
            if not text:
                continue
            matches = [m for m in secrets.scan_text(text) if m.kind in self.KINDS]
            if matches:
                evidence: list[Evidence] = [
                    self.evidence(
                        path=asset.path or asset.source,
                        line=m.line or None,
                        key=m.key,
                        snippet=m.redacted,
                        reason=f"{m.description} ({m.confidence} confidence)",
                    )
                    for m in matches[:10]
                ]
                findings.append(
                    self.fail(
                        asset.asset_id,
                        f"{len(matches)} {self.SUBJECT} found in {asset.source}.",
                        evidence,
                        confidence=Confidence.HIGH
                        if any(m.confidence == "HIGH" for m in matches)
                        else Confidence.MEDIUM,
                    )
                )
            else:
                findings.append(self.ok(asset.asset_id, f"No {self.SUBJECT} detected."))
        return findings


@register
class ApiKeys(_SecretFamilyCheck):
    KINDS = ("api_key",)
    SUBJECT = "API key(s)"
    meta = CheckMeta(
        check_id="SECRET-001",
        title="API keys in agent configuration",
        description="A provider API key literal appears in an agent configuration file or the environment.",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=SECRET_TARGETS,
        rationale=(
            "Provider keys have a recognisable structure, so detection is high-confidence "
            "and placeholder values are filtered out."
        ),
        security_impact=(
            "A leaked API key permits billed use of the provider account and access to any "
            "data reachable through it."
        ),
        remediation="Move the key to a secret manager, reference it indirectly, and rotate it.",
        references=("https://cwe.mitre.org/data/definitions/798.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-798: Use of Hard-coded Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )


@register
class CloudCredentials(_SecretFamilyCheck):
    KINDS = ("cloud",)
    SUBJECT = "cloud credential(s)"
    meta = CheckMeta(
        check_id="SECRET-002",
        title="Cloud provider credentials exposed",
        description="An AWS, GCP, or Azure credential literal appears in an agent-reachable location.",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=SECRET_TARGETS,
        rationale="Cloud access key identifiers have fixed prefixes and lengths, giving high-confidence detection.",
        security_impact=(
            "Cloud credentials typically grant access to infrastructure and data far beyond "
            "the local machine, making this the highest-impact class of local leak."
        ),
        remediation=(
            "Revoke and rotate the credential immediately, then use short-lived role-based "
            "credentials instead of long-lived keys."
        ),
        references=("https://cwe.mitre.org/data/definitions/522.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
            ("MITRE ATLAS", "AML.T0055: Unsecured Credentials"),
        ),
    )


@register
class PrivateKeys(_SecretFamilyCheck):
    KINDS = ("private_key",)
    SUBJECT = "private key block(s)"
    meta = CheckMeta(
        check_id="SECRET-003",
        title="Private key material in agent-reachable configuration",
        description="A PEM private key block appears inside an agent configuration file.",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        aasb_level=1,
        applies_to=SECRET_TARGETS,
        rationale=(
            "A PEM header is unambiguous. This check covers key material embedded in "
            "configuration; keys in their normal location are covered by FS-003."
        ),
        security_impact="Enables impersonation of the key holder for authentication or signing.",
        remediation="Remove the key from configuration, store it with 0600 permissions, and rotate it.",
        references=("https://cwe.mitre.org/data/definitions/522.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
        ),
    )


@register
class AuthTokens(_SecretFamilyCheck):
    KINDS = ("token",)
    SUBJECT = "authentication token(s)"
    meta = CheckMeta(
        check_id="SECRET-004",
        title="Authentication tokens exposed",
        description="A session, OAuth, or personal access token literal is present.",
        category=Category.SECRETS,
        severity=Severity.HIGH,
        aasb_level=1,
        applies_to=SECRET_TARGETS,
        rationale=(
            "Covers environment-variable exposure as well as configuration files, which is "
            "why AASB v1.0 defines no separate ENV-* family (spec 5.10)."
        ),
        security_impact="Permits authenticated access as the token's owner until it is revoked.",
        remediation="Revoke the token, reissue with minimal scope, and store it outside configuration.",
        references=("https://cwe.mitre.org/data/definitions/522.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-522: Insufficiently Protected Credentials"),
        ),
    )


@register
class PlaintextCredentials(_SecretFamilyCheck):
    KINDS = ("plaintext",)
    SUBJECT = "plaintext credential(s)"
    meta = CheckMeta(
        check_id="SECRET-005",
        title="Plaintext credentials in configuration",
        description=(
            "A high-entropy value is assigned to a credential-named key, or credentials are "
            "embedded in a URL."
        ),
        category=Category.SECRETS,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=SECRET_TARGETS,
        rationale=(
            "These values have no fixed structure, so detection requires both a "
            "credential-shaped key name and a Shannon entropy above 3.6. Environment "
            "indirection such as ${VAR} is excluded, since that is the recommended fix."
        ),
        security_impact="Credentials readable by anyone with access to the configuration file.",
        remediation="Replace the literal with an environment reference and rotate the credential.",
        references=("https://cwe.mitre.org/data/definitions/256.html",),
        compliance=(
            ("OWASP LLM Top 10 2025", "LLM02: Sensitive Information Disclosure"),
            ("CWE", "CWE-256: Plaintext Storage of a Password"),
        ),
    )


__all__ = ["redact"]
