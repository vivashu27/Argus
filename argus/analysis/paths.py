"""Sensitive path knowledge and Claude permission-rule evaluation.

"Reachable" is defined by spec 5.8 as: the path is *not denied* by the effective
permission ruleset **and** is readable by the current user. Both conditions must
hold for a HIGH-confidence finding; either alone is reported at reduced confidence.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

#: Credential-bearing locations, relative to the user's home directory.
SENSITIVE_HOME_PATHS: tuple[tuple[str, str, str], ...] = (
    (".ssh", "SSH private keys and known hosts", "ssh"),
    (".aws", "AWS credentials and config", "cloud"),
    (".config/gcloud", "Google Cloud credentials", "cloud"),
    (".azure", "Azure credentials", "cloud"),
    (".kube", "Kubernetes cluster credentials", "cloud"),
    (".docker/config.json", "Docker registry credentials", "cloud"),
    (".gnupg", "GnuPG private keyring", "keys"),
    (".netrc", "Plaintext network credentials", "credentials"),
    (".npmrc", "npm registry token", "credentials"),
    (".pypirc", "PyPI upload credentials", "credentials"),
    (".git-credentials", "Plaintext Git credentials", "credentials"),
    (".claude/.credentials.json", "Claude Code OAuth credentials", "credentials"),
    (".config/gh/hosts.yml", "GitHub CLI token", "credentials"),
    (".password-store", "pass password store", "credentials"),
    (".mozilla", "Browser saved credentials", "browser"),
    (".config/google-chrome/Default/Login Data", "Browser saved credentials", "browser"),
)

#: Private key filenames, matched by basename anywhere in scope.
PRIVATE_KEY_NAMES = re.compile(
    r"^(?:id_(?:rsa|dsa|ecdsa|ed25519)|.*\.pem|.*\.key|.*\.p12|.*\.pfx|.*_key)$", re.I
)

#: Files that should never be world-readable or world-writable.
SENSITIVE_CONFIG_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/.credentials.json",
    ".claude.json",
    ".mcp.json",
)

SYSTEM_SENSITIVE = ("/etc/shadow", "/etc/sudoers", "/etc/passwd", "/root")


@dataclass(frozen=True)
class SensitivePath:
    path: Path
    description: str
    kind: str
    exists: bool
    readable: bool


def enumerate_sensitive_paths(home: Path | None = None) -> list[SensitivePath]:
    """List credential locations that exist for the current user."""
    base = home or Path.home()
    out: list[SensitivePath] = []
    for relative, description, kind in SENSITIVE_HOME_PATHS:
        candidate = base / relative
        try:
            exists = candidate.exists()
        except OSError:
            continue
        if not exists:
            continue
        out.append(
            SensitivePath(
                path=candidate,
                description=description,
                kind=kind,
                exists=True,
                readable=os.access(candidate, os.R_OK),
            )
        )
    return out


def find_private_keys(ssh_dir: Path) -> list[Path]:
    """Private key files in an SSH directory. Never reads key contents."""
    if not ssh_dir.is_dir():
        return []
    keys: list[Path] = []
    try:
        entries = list(ssh_dir.iterdir())
    except OSError:
        return []
    for entry in entries:
        if not entry.is_file() or entry.is_symlink():
            continue
        if entry.suffix == ".pub" or entry.name in ("known_hosts", "config", "authorized_keys"):
            continue
        if PRIVATE_KEY_NAMES.match(entry.name):
            keys.append(entry)
    return keys


# ---------------------------------------------------------------------------
# Claude permission rule evaluation
# ---------------------------------------------------------------------------

#: Rules that grant unrestricted use of a tool, e.g. "Bash" or "Bash(*)".
_UNRESTRICTED = re.compile(r"^(?P<tool>[A-Za-z_]+)(?:\(\s*\*?\s*\)|\s*)$")

#: Tools whose unrestricted grant is materially dangerous.
DANGEROUS_TOOLS = {
    "Bash": ("arbitrary command execution", "CRITICAL"),
    "Write": ("arbitrary file write", "HIGH"),
    "Edit": ("arbitrary file modification", "HIGH"),
    "NotebookEdit": ("arbitrary notebook modification", "MEDIUM"),
    "WebFetch": ("arbitrary outbound HTTP requests", "MEDIUM"),
    "WebSearch": ("outbound search queries", "LOW"),
}

NETWORK_TOOLS = {"WebFetch", "WebSearch"}
FILESYSTEM_TOOLS = {"Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit"}


@dataclass
class PermissionRules:
    """The effective permission configuration drawn from a settings file."""

    allow: list[str]
    deny: list[str]
    ask: list[str]
    default_mode: str | None = None

    @classmethod
    def from_settings(cls, settings: dict) -> PermissionRules:
        block = settings.get("permissions") or {}
        if not isinstance(block, dict):
            block = {}
        return cls(
            allow=[str(r) for r in (block.get("allow") or []) if isinstance(r, (str, int))],
            deny=[str(r) for r in (block.get("deny") or []) if isinstance(r, (str, int))],
            ask=[str(r) for r in (block.get("ask") or []) if isinstance(r, (str, int))],
            default_mode=block.get("defaultMode") or settings.get("defaultMode"),
        )

    def unrestricted_grants(self) -> list[tuple[str, str, str]]:
        """Allow rules that grant a whole tool with no argument constraint."""
        out: list[tuple[str, str, str]] = []
        for rule in self.allow:
            match = _UNRESTRICTED.match(rule.strip())
            if not match:
                continue
            tool = match.group("tool")
            if tool in DANGEROUS_TOOLS:
                reason, severity = DANGEROUS_TOOLS[tool]
                out.append((rule, reason, severity))
        return out

    def grants_tool(self, tool: str) -> list[str]:
        return [r for r in self.allow if r.strip() == tool or r.strip().startswith(f"{tool}(")]

    def denies_path(self, path: str) -> bool:
        """True when a deny rule covers the given path.

        Matching is deliberately conservative: an unrecognised rule syntax counts as
        *not* denying, so Argus errs toward reporting exposure rather than assuming
        protection that may not exist.
        """
        needle = str(path).replace("\\", "/")
        home = str(Path.home()).replace("\\", "/")
        for rule in self.deny:
            inner = _rule_argument(rule)
            if inner is None:
                continue
            pattern = inner.replace("\\", "/").replace("$HOME", home).replace("~", home)
            if _glob_covers(pattern, needle):
                return True
        return False

    def has_deny_for(self, keyword: str) -> bool:
        return any(keyword.lower() in r.lower() for r in self.deny)

    @property
    def is_empty(self) -> bool:
        return not (self.allow or self.deny or self.ask)


def _rule_argument(rule: str) -> str | None:
    """Extract ``X`` from ``Tool(X)``; returns the raw rule when there is no paren."""
    match = re.match(r"^\s*[A-Za-z_]+\(\s*(.*?)\s*\)\s*$", rule)
    if match:
        return match.group(1)
    return rule.strip() or None


def _glob_covers(pattern: str, path: str) -> bool:
    """Whether a glob-ish deny pattern covers a path prefix."""
    pattern = pattern.rstrip("/")
    path = path.rstrip("/")
    if not pattern:
        return False
    if pattern.endswith("/**"):
        pattern = pattern[:-3]
    if pattern.endswith("**"):
        pattern = pattern[:-2]
    if pattern.endswith("/*"):
        pattern = pattern[:-2]
    pattern = pattern.rstrip("/")
    if not pattern:
        return False
    regex = re.escape(pattern).replace(r"\*", "[^/]*").replace(r"\?", ".")
    return bool(re.match(f"^{regex}(?:/|$)", path))


#: Arguments that hand an MCP server the whole filesystem.
ROOT_ARGUMENTS = frozenset({"/", "//", "~", "$HOME", "%USERPROFILE%", "C:\\", "C:/", "/home", "/Users"})


def is_root_scope(value: str) -> bool:
    """True when a path argument grants filesystem-wide scope (MCP-003)."""
    if not isinstance(value, str):
        return False
    cleaned = value.strip().rstrip("/\\") or "/"
    if value.strip() in ROOT_ARGUMENTS or cleaned in ("", "/"):
        return True
    expanded = os.path.expandvars(value.strip())
    home = str(Path.home())
    return expanded.rstrip("/\\") in (home.rstrip("/\\"), "/home", "/Users", "")


def touches_sensitive(value: str) -> tuple[bool, str]:
    """Whether a path string points at a known credential location (MCP-004/FS-002)."""
    if not isinstance(value, str):
        return False, ""
    lowered = os.path.expandvars(value).replace("\\", "/").lower()
    for relative, description, _kind in SENSITIVE_HOME_PATHS:
        if f"/{relative.lower()}" in lowered or lowered.endswith(relative.lower()):
            return True, description
    for system_path in SYSTEM_SENSITIVE:
        if lowered.startswith(system_path):
            return True, f"System-sensitive path {system_path}"
    return False, ""


#: Test code is not the implementation. Fixtures write unguarded paths, spawn
#: processes and embed sample credentials as a matter of course, so analysing them
#: as though they ran in production reports the test suite rather than the product.
TEST_MARKERS = ("test", "tests", "__tests__", "spec", "__mocks__", "fixtures", "e2e")


def is_test_file(path: Path | str) -> bool:
    """Whether a path is test code rather than shipped implementation."""
    path = Path(path)
    stem = path.stem.lower()
    if stem.startswith("test_") or stem.endswith(("_test", ".test", ".spec", "_spec")):
        return True
    return any(part.lower() in TEST_MARKERS for part in path.parts)
