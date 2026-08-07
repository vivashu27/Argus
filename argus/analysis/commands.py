"""Dangerous command static analysis (spec 6.2).

Detected commands are **never executed** — this module only matches text.

The original flat command list put bare ``curl`` alongside ``rm -rf``, which would
fire on nearly every real configuration. Detections are therefore tiered:

* **Tier A** — dangerous regardless of context; a match is a FAIL on its own.
* **Tier B** — dangerous in combination; a match is a WARN unless corroborated by a
  credential path, remote endpoint, or interpolated agent input, in which case it
  escalates to FAIL.
* **Tier C** — informational; never a standalone FAIL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from ..core.models import ThreatCategory
from .redaction import truncate


class Tier(str, Enum):
    A = "A"
    B = "B"
    C = "C"


@dataclass(frozen=True)
class CommandMatch:
    pattern_id: str
    description: str
    tier: Tier
    threat: ThreatCategory
    line: int
    context: str
    escalated: bool = False
    escalation_reason: str = ""

    @property
    def is_failing(self) -> bool:
        """Tier A always fails; Tier B fails only when corroborated."""
        return self.tier is Tier.A or (self.tier is Tier.B and self.escalated)


@dataclass(frozen=True)
class _Rule:
    pattern_id: str
    description: str
    tier: Tier
    threat: ThreatCategory
    regex: re.Pattern[str]


TIER_A: tuple[_Rule, ...] = (
    _Rule("rm-rf-root", "Recursive delete of a root or home path", Tier.A,
          ThreatCategory.DESTRUCTIVE_OPERATION,
          re.compile(r"\brm\s+(?:-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*\s+"
                     r"(?:/\s*$|/\s|~|\$HOME|/\*)", re.I)),
    _Rule("curl-pipe-shell", "Remote script piped directly into a shell", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"\b(?:curl|wget)\b[^|;&\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b", re.I)),
    _Rule("fetch-pipe-python", "Remote script piped into an interpreter", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"\b(?:curl|wget)\b[^|;&\n]{0,200}\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node)\b", re.I)),
    # Same interpreter set as the curl/wget pipe above: decoding a payload into
    # python is no less execution than decoding it into sh, and obfuscated code is a
    # documented pattern in roughly one in ten confirmed-malicious skills.
    _Rule("base64-pipe-shell", "Base64-decoded payload piped into an interpreter", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"\bbase64\s+(?:-{1,2}\w+\s+)*\|\s*(?:sudo\s+)?(?:(?:ba)?sh|python3?|perl|ruby|node)\b", re.I)),
    _Rule("powershell-encoded", "PowerShell encoded command", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"powershell(?:\.exe)?\s+.{0,80}?-(?:enc|e|encodedcommand)\b", re.I)),
    _Rule("iex-download", "PowerShell download-and-execute", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"\b(?:iex|invoke-expression)\b.{0,120}?"
                     r"(?:downloadstring|invoke-webrequest|iwr|new-object\s+net\.webclient)", re.I)),
    _Rule("chmod-777", "World-writable permission grant", Tier.A,
          ThreatCategory.PRIVILEGE_ESCALATION,
          re.compile(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*777\b")),
    _Rule("fork-bomb", "Fork bomb", Tier.A,
          ThreatCategory.DESTRUCTIVE_OPERATION,
          re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:")),
    _Rule("mkfs", "Filesystem format", Tier.A,
          ThreatCategory.DESTRUCTIVE_OPERATION,
          re.compile(r"\bmkfs(?:\.\w+)?\s+/dev/", re.I)),
    _Rule("dd-to-device", "Raw write to a block device", Tier.A,
          ThreatCategory.DESTRUCTIVE_OPERATION,
          re.compile(r"\bdd\b[^\n]{0,80}\bof=/dev/(?:sd|nvme|hd|disk)", re.I)),
    _Rule("dev-tcp-reverse-shell", "Reverse shell via /dev/tcp or /dev/udp", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"/dev/(?:tcp|udp)/[\w.\-]+/\d{1,5}", re.I)),
    _Rule("interactive-reverse-shell", "Interactive shell redirected to a socket", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"\b(?:ba|z|k|da)?sh\b[^\n]{0,20}?-i\b[^\n]{0,40}?(?:>&|&>|0<&|<&)", re.I)),
    _Rule("netcat-exec", "Netcat with command execution", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]{0,40}?\s-{1,2}(?:e|exec|lvp|lvnp)\b", re.I)),
    _Rule("socket-reverse-shell", "Scripted reverse shell via raw socket", Tier.A,
          ThreatCategory.REMOTE_CODE_EXECUTION,
          re.compile(r"socket\.socket[^\n]{0,120}?(?:connect|dup2)|"
                     r"\bpty\.spawn\b|"
                     r"IO\.popen[^\n]{0,40}?TCPSocket", re.I)),
    _Rule("history-wipe", "Shell history destruction", Tier.A,
          ThreatCategory.PERSISTENCE,
          re.compile(r"\b(?:history\s+-c|unset\s+HISTFILE|>\s*~/\.bash_history)\b")),
)

TIER_B: tuple[_Rule, ...] = (
    _Rule("sudo", "Privilege escalation via sudo", Tier.B,
          ThreatCategory.PRIVILEGE_ESCALATION,
          re.compile(r"(?:^|[\s;&|])sudo\s+\S", re.M)),
    _Rule("shell-dash-c", "Shell invoked with an inline command string", Tier.B,
          ThreatCategory.COMMAND_EXECUTION,
          re.compile(r"\b(?:ba|z|k|da)?sh\s+-c\s+", re.I)),
    _Rule("eval", "Dynamic evaluation of a command string", Tier.B,
          ThreatCategory.COMMAND_EXECUTION,
          re.compile(r"(?:^|[\s;&|`$(])eval\s+\S", re.M)),
    _Rule("netcat", "Netcat — potential reverse shell or exfiltration channel", Tier.B,
          ThreatCategory.DATA_EXFILTRATION,
          re.compile(r"\b(?:nc|ncat|netcat)\s+(?:-\w+\s+)*\S+\s+\d{2,5}\b")),
    _Rule("ssh", "Remote shell access", Tier.B,
          ThreatCategory.NETWORK_ACCESS,
          re.compile(r"\bssh\s+(?:-\w+\s+)*[\w.\-]+@[\w.\-]+")),
    _Rule("scp", "Remote file copy", Tier.B,
          ThreatCategory.DATA_EXFILTRATION,
          re.compile(r"\bscp\s+\S+\s+\S+:")),
    _Rule("invoke-webrequest", "PowerShell web request", Tier.B,
          ThreatCategory.NETWORK_ACCESS,
          re.compile(r"\b(?:invoke-webrequest|iwr)\b", re.I)),
    _Rule("crontab-write", "Scheduled task installation", Tier.B,
          ThreatCategory.PERSISTENCE,
          re.compile(r"\b(?:crontab\s+-|systemctl\s+enable|launchctl\s+load|schtasks\s+/create)\b", re.I)),
    _Rule("rc-file-append", "Shell profile modification", Tier.B,
          ThreatCategory.PERSISTENCE,
          re.compile(r">>\s*~?/?\.?(?:bashrc|zshrc|profile|bash_profile)\b")),
    _Rule("curl-upload", "Outbound file upload", Tier.B,
          ThreatCategory.DATA_EXFILTRATION,
          re.compile(r"\bcurl\b[^\n]{0,200}?(?:-F\s|--data-binary\s|-T\s|--upload-file\s)", re.I)),
)

TIER_C: tuple[_Rule, ...] = (
    _Rule("curl", "HTTP client invocation", Tier.C, ThreatCategory.NETWORK_ACCESS,
          re.compile(r"\bcurl\b", re.I)),
    _Rule("wget", "HTTP download", Tier.C, ThreatCategory.NETWORK_ACCESS,
          re.compile(r"\bwget\b", re.I)),
    _Rule("git-clone", "Repository clone", Tier.C, ThreatCategory.NETWORK_ACCESS,
          re.compile(r"\bgit\s+clone\b", re.I)),
)

ALL_RULES: tuple[_Rule, ...] = TIER_A + TIER_B + TIER_C

# --- Escalation corroborators for Tier B --------------------------------------
_CREDENTIAL_CONTEXT = re.compile(
    r"(?:\.ssh/|\.aws/|\.config/gcloud|id_rsa|id_ed25519|\.env\b|credentials|"
    r"\.netrc|\.npmrc|keychain|secrets?\b|\.claude\.json|\.credentials\.json)",
    re.I,
)
_REMOTE_CONTEXT = re.compile(r"https?://(?!localhost|127\.0\.0\.1|\[::1\])[\w.\-]+", re.I)
_INTERPOLATION = re.compile(
    r"(?:\$\{?(?:CLAUDE|TOOL|ARG|INPUT|USER_?PROMPT|FILE)_?\w*\}?|"
    r"\$\(.*\)|`[^`]+`|\{\{\s*\w+\s*\}\}|%\(\w+\)s|\$\d)",
    re.I,
)


def _escalation(line: str) -> tuple[bool, str]:
    if _CREDENTIAL_CONTEXT.search(line):
        return True, "references a credential path"
    if _REMOTE_CONTEXT.search(line):
        return True, "targets a remote endpoint"
    if _INTERPOLATION.search(line):
        return True, "interpolates agent-controlled input"
    return False, ""


def scan_text(text: str, *, include_tier_c: bool = False, max_findings: int = 50) -> list[CommandMatch]:
    """Find dangerous command patterns in text. Never executes anything."""
    rules = ALL_RULES if include_tier_c else TIER_A + TIER_B
    matches: list[CommandMatch] = []
    seen: set[tuple[str, int]] = set()

    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*")) and "rm -rf" not in stripped:
            continue  # commented-out code is not a live configuration
        for rule in rules:
            if not rule.regex.search(line):
                continue
            key = (rule.pattern_id, lineno)
            if key in seen:
                continue
            seen.add(key)
            escalated, reason = _escalation(line) if rule.tier is Tier.B else (False, "")
            matches.append(
                CommandMatch(
                    pattern_id=rule.pattern_id,
                    description=rule.description,
                    tier=rule.tier,
                    threat=rule.threat,
                    line=lineno,
                    context=truncate(line),
                    escalated=escalated,
                    escalation_reason=reason,
                )
            )
            if len(matches) >= max_findings:
                return matches
    return matches


def scan_argv(command: str, args: list[str]) -> list[CommandMatch]:
    """Analyze a structured command + argv pair, as found in MCP server definitions."""
    return scan_text(" ".join([command, *args]))


SHELL_INTERPRETERS = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "csh", "tcsh", "fish",
     "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
)

SHELL_METACHARACTERS = re.compile(r"[;&|><`$]|\$\(|\|\||&&")


def is_shell_interpreter(command: str) -> bool:
    """True when a configured command is itself a shell (MCP-002)."""
    if not command:
        return False
    basename = command.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    return basename in SHELL_INTERPRETERS


def has_shell_metacharacters(values: list[str]) -> list[str]:
    """Arguments containing shell metacharacters, implying string interpolation (MCP-007)."""
    return [v for v in values if isinstance(v, str) and SHELL_METACHARACTERS.search(v)]
