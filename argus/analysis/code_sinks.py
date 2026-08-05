"""Dangerous sinks in MCP server source.

:mod:`argus.analysis.commands` answers "is this command string dangerous". This module
answers a different question: "does this code hand attacker-reachable input to a
dangerous API". Every parameter of an MCP tool is attacker-reachable, because the model
chooses those values and the model can be steered by injected text.

The distinction that matters is interpolation. ``os.system("clear")`` is a constant and
uninteresting; ``os.system(f"convert {path}")`` is command injection with the tool's own
parameter as the payload. Sinks are therefore reported only when input flows into them,
which is what keeps this from firing on every server that shells out at all.

This is pattern matching, not dataflow analysis. It finds the shapes that appear in real
advisories; a server that launders input through several helpers will not be caught, and
the checks say so rather than implying the absence of a finding is a clean bill.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .redaction import truncate

#: How much of a call to read when deciding whether input flows into it.
WINDOW = 260


@dataclass(frozen=True)
class SinkMatch:
    sink_id: str
    kind: str  # shell | eval | path | bind
    description: str
    line: int
    excerpt: str
    interpolated: bool


#: Markers that a call argument is built at runtime rather than being a literal.
_INTERPOLATION = re.compile(
    r"""f["']|["'][^"']*\{[^}]*\}|\$\{|\.format\s*\(|%\s*[\(a-zA-Z_]|["']\s*\+\s*\w|\w\s*\+\s*["']"""
)

#: Command execution that goes through a shell. ``subprocess`` is only a shell sink
#: when ``shell=True``, so it is matched separately against its own window.
_SHELL_DIRECT: tuple[tuple[str, str, str], ...] = (
    ("os-system", r"\bos\.system\s*\(", "os.system() runs its argument through a shell"),
    ("os-popen", r"\bos\.popen\s*\(", "os.popen() runs its argument through a shell"),
    ("commands-getoutput", r"\bcommands\.get(status)?output\s*\(", "commands.getoutput() uses a shell"),
    ("node-exec", r"\b(child_process\.)?exec(Sync)?\s*\(", "child_process.exec() runs a shell"),
    ("shelljs", r"\bshelljs?\.exec\s*\(", "shelljs.exec() runs a shell"),
    ("popen-shell", r"\bPopen\s*\(\s*[\"'f]", "Popen() called with a command string"),
)

_SUBPROCESS = re.compile(r"\bsubprocess\.(run|call|check_call|check_output|Popen)\s*\(")
_SHELL_TRUE = re.compile(r"shell\s*[=:]\s*(True|true)")

_EVAL: tuple[tuple[str, str, str], ...] = (
    ("python-eval", r"\beval\s*\(", "eval() executes its argument as code"),
    ("python-exec", r"\bexec\s*\(", "exec() executes its argument as code"),
    ("js-function-ctor", r"\bnew\s+Function\s*\(", "new Function() compiles a string as code"),
    ("vm-run", r"\bvm\.run(InNewContext|InThisContext|InContext)\s*\(", "vm.run*() executes a string"),
)

#: Filesystem entry points that take a caller-supplied path.
_PATH_SINKS: tuple[tuple[str, str, str], ...] = (
    ("open", r"\bopen\s*\(", "open() with a caller-supplied path"),
    ("path-join", r"\bos\.path\.join\s*\(", "os.path.join() with a caller-supplied segment"),
    ("pathlib", r"\bPath\s*\([^)]{0,120}\)\s*/", "Path joined with a caller-supplied segment"),
    ("readfile", r"\b(readFile|readFileSync|writeFile|writeFileSync|createReadStream)\s*\(",
     "fs read/write with a caller-supplied path"),
    ("shutil", r"\bshutil\.(copy|copy2|move|rmtree)\s*\(", "shutil operation on a caller-supplied path"),
)

#: Evidence that a path is confined before use. Any of these in the file is treated as
#: the author having thought about traversal, which downgrades the finding.
_CONTAINMENT = re.compile(
    r"\.resolve\s*\(|\.is_relative_to\s*\(|\.relative_to\s*\(|os\.path\.realpath|"
    r"os\.path\.commonpath|os\.path\.commonprefix|\.startswith\s*\(|path\.normalize|"
    r"\.startsWith\s*\(|sanitiz|is_safe_path|_safe_join|secure_filename"
)

#: Binding to every interface exposes the server beyond localhost. MCP defines no
#: mandatory authentication, so an exposed stdio-style server is usually unauthenticated.
_BIND = re.compile(r"""["'](0\.0\.0\.0|::|\*)["']|--host[= ]+0\.0\.0\.0|host\s*[=:]\s*["']0\.0\.0\.0["']""")

_AUTH = re.compile(
    r"Authorization|Bearer\b|api[_-]?key|access[_-]?token|authenticate|verify_token|"
    r"oauth|jwt|session[_-]?token|X-API-Key",
    re.I,
)

_SHELL_COMPILED = tuple((i, re.compile(p), d) for i, p, d in _SHELL_DIRECT)
_EVAL_COMPILED = tuple((i, re.compile(p), d) for i, p, d in _EVAL)
_PATH_COMPILED = tuple((i, re.compile(p), d) for i, p, d in _PATH_SINKS)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _excerpt(text: str, start: int, end: int) -> str:
    return truncate(text[max(0, start - 20) : end + 80], 160)


def _is_comment(text: str, offset: int) -> bool:
    """Whether the match sits on a commented-out line.

    Advisory text and disabled code both appear in real servers, and reporting a
    commented-out ``os.system`` as command injection would be a false positive.
    """
    line_start = text.rfind("\n", 0, offset) + 1
    prefix = text[line_start:offset].lstrip()
    return prefix.startswith(("#", "//", "*", "/*"))


def shell_sinks(text: str) -> list[SinkMatch]:
    """Shell and code-evaluation sinks, flagged as interpolated where input flows in."""
    out: list[SinkMatch] = []

    for sink_id, expression, description in (*_SHELL_COMPILED, *_EVAL_COMPILED):
        kind = "eval" if any(sink_id == e[0] for e in _EVAL_COMPILED) else "shell"
        for match in expression.finditer(text):
            if _is_comment(text, match.start()):
                continue
            window = text[match.end() : match.end() + WINDOW]
            out.append(
                SinkMatch(
                    sink_id=sink_id,
                    kind=kind,
                    description=description,
                    line=_line_of(text, match.start()),
                    excerpt=_excerpt(text, match.start(), match.end()),
                    interpolated=bool(_INTERPOLATION.search(window.split(")")[0] or window)),
                )
            )

    for match in _SUBPROCESS.finditer(text):
        if _is_comment(text, match.start()):
            continue
        window = text[match.end() : match.end() + WINDOW]
        if not _SHELL_TRUE.search(window):
            # Without shell=True the argument vector is passed directly to execve,
            # which is the safe form and must not be reported.
            continue
        out.append(
            SinkMatch(
                sink_id="subprocess-shell",
                kind="shell",
                description="subprocess called with shell=True",
                line=_line_of(text, match.start()),
                excerpt=_excerpt(text, match.start(), match.end()),
                interpolated=bool(_INTERPOLATION.search(window)),
            )
        )

    return sorted(out, key=lambda m: m.line)


def path_sinks(text: str) -> list[SinkMatch]:
    """Filesystem sinks reached by interpolated input, where nothing confines the path.

    A file containing any containment idiom is treated as having addressed traversal;
    this reports the servers that never do, not every server that opens a file.
    """
    if _CONTAINMENT.search(text):
        return []
    out: list[SinkMatch] = []
    for sink_id, expression, description in _PATH_COMPILED:
        for match in expression.finditer(text):
            if _is_comment(text, match.start()):
                continue
            window = text[match.end() : match.end() + WINDOW]
            if not _INTERPOLATION.search(window.split(")")[0] or window):
                continue
            out.append(
                SinkMatch(
                    sink_id=sink_id,
                    kind="path",
                    description=description,
                    line=_line_of(text, match.start()),
                    excerpt=_excerpt(text, match.start(), match.end()),
                    interpolated=True,
                )
            )
    return sorted(out, key=lambda m: m.line)


def network_binds(text: str) -> list[SinkMatch]:
    """Binds to every interface. Reported with whether the file shows any auth at all."""
    authenticated = bool(_AUTH.search(text))
    out: list[SinkMatch] = []
    for match in _BIND.finditer(text):
        if _is_comment(text, match.start()):
            continue
        out.append(
            SinkMatch(
                sink_id="bind-all-interfaces",
                kind="bind",
                description=(
                    "Server binds to every interface"
                    + ("" if authenticated else " and the file shows no authentication")
                ),
                line=_line_of(text, match.start()),
                excerpt=_excerpt(text, match.start(), match.end()),
                interpolated=not authenticated,
            )
        )
    return sorted(out, key=lambda m: m.line)
