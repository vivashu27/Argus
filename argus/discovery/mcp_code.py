"""Resolve an MCP server's declared command to its source on this machine.

The configuration says *how to launch* a server; the interesting security properties
live in what gets launched. This module closes that gap by mapping ``command`` plus
``args`` onto files already present on disk, so the checks can read a server's tool
definitions and implementation.

Nothing here launches anything. The command string is parsed as data — never passed
to a shell, never resolved through ``PATH`` execution — and every file is read through
:mod:`argus.core.safe_io` with its size cap and symlink rules intact.

Resolution is deliberately conservative. A server that cannot be located is recorded
with the reason why, and the checks report that honestly rather than treating an
unresolvable server as a clean one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..analysis.mcp_tools import ToolDef, extract_tools

# Shared with the plugin checks, which face the same problem: a fake JWT in
# ``test_redact_headers.py`` is a fixture, not a leaked credential.
from ..analysis.paths import TEST_MARKERS  # noqa: F401
from ..analysis.paths import is_test_file as _is_test_file
from ..core.exceptions import ArgusError
from ..core.models import Asset
from ..core.safe_io import iter_files, read_text
from .base import DiscoveryContext

#: Interpreters that take the real entry point as an argument.
INTERPRETERS = frozenset(
    {"node", "nodejs", "bun", "deno", "ts-node", "tsx", "python", "python3", "py", "pypy"}
)

#: Package runners: the first non-flag argument names a package, not a file.
RUNNERS = frozenset({"npx", "uvx", "pnpm", "yarn", "bunx", "pipx"})

#: Containerised servers run from an image, so there is nothing local to read.
CONTAINERS = frozenset({"docker", "podman", "nerdctl", "finch"})

SOURCE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx")

#: Directories a JS package ships compiled output in. ``iter_files`` skips these by
#: name because they are build artefacts in a source tree — but for an installed MCP
#: server they hold the code that actually runs, so they are searched explicitly.
BUILD_DIRS = ("dist", "build", "lib", "out", "src", "bin")

#: Bounds on how much of a server is read. A server package can vendor a great deal;
#: these keep a scan predictable without needing a timeout.
MAX_SOURCE_FILES = 60
MAX_TOTAL_BYTES = 3_000_000
MAX_FILE_BYTES = 600_000

#: An exact version. Anything else — a dist-tag, a caret range, a wildcard — resolves
#: to different code at different times.
_EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+[\w.+-]*")


@dataclass
class SourceFile:
    """One readable source file belonging to a server."""

    path: Path
    text: str

    @property
    def language(self) -> str:
        return "python" if self.path.suffix.lower() == ".py" else "javascript"


@dataclass
class Resolution:
    """What was found for one server, and why nothing was found when that is the case."""

    root: Path | None = None
    entry: Path | None = None
    method: str = ""
    reason: str = ""
    files: list[SourceFile] = field(default_factory=list)
    tools: list[ToolDef] = field(default_factory=list)
    truncated: bool = False
    #: The package spec as written, e.g. ``@scope/pkg@latest``. Empty for a path launch.
    package_spec: str = ""

    @property
    def resolved(self) -> bool:
        return self.root is not None or self.entry is not None


def _basename(command: str) -> str:
    name = Path(command.strip().strip('"').strip("'")).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def _package_root(start: Path, ceiling: int = 4) -> Path:
    """Walk up to the directory that owns this file — the package, not the source dir.

    The walk only continues past a conventional build or source subdirectory. That is
    the difference between ``node_modules/pkg/dist/index.js``, where the package root
    genuinely is two levels up, and ``challenges/easy/challenge2/server.py``, where the
    nearest manifest belongs to a repository that merely contains the server. Without
    that condition a server anywhere inside a monorepo resolves to the whole monorepo,
    and every finding in it is attributed to that one server.
    """
    base = start if start.is_dir() else start.parent
    current = base
    for _ in range(ceiling):
        for marker in ("package.json", "pyproject.toml", "setup.py"):
            if (current / marker).is_file():
                return current
        if current.parent == current or current.name not in BUILD_DIRS:
            break
        current = current.parent
    return base


def _node_module_roots(project_root: Path, home: Path, user_scope: bool) -> list[Path]:
    """Where an npx-launched package may already be installed."""
    roots = [project_root / "node_modules"]
    if not user_scope:
        return roots
    roots.extend(
        [
            home / "node_modules",
            home / ".npm-global" / "lib" / "node_modules",
            Path("/usr/lib/node_modules"),
            Path("/usr/local/lib/node_modules"),
        ]
    )
    # npx caches each package under a content hash, and nvm keeps one tree per version.
    for pattern, base in ((("_npx", "*", "node_modules"), home / ".npm"),
                          (("versions", "node", "*", "lib", "node_modules"), home / ".nvm")):
        if base.is_dir():
            try:
                roots.extend(p for p in base.glob(str(Path(*pattern))) if p.is_dir())
            except OSError:
                continue
    return roots


def _python_site_roots(project_root: Path, home: Path, user_scope: bool) -> list[Path]:
    roots: list[Path] = []
    for venv in (project_root / ".venv", project_root / "venv"):
        roots.extend(sorted(venv.glob("lib/python*/site-packages")))
    if user_scope:
        roots.extend(sorted((home / ".local").glob("lib/python*/site-packages")))
        roots.extend(sorted((home / ".local" / "share" / "uv").glob("tools/*/lib/python*/site-packages")))
    return [r for r in roots if r.is_dir()]


def _version_at(spec: str) -> int:
    """Index of the ``@`` that introduces the version, or -1.

    Searching from index 1 skips the ``@`` that begins a scope, so ``@scope/pkg`` has
    no version while ``@scope/pkg@latest`` does.
    """
    return spec.find("@", 1)


def _strip_version(spec: str) -> str:
    """``@scope/pkg@1.2.3`` -> ``@scope/pkg``. The leading @ of a scope is preserved."""
    at = _version_at(spec)
    return spec[:at] if at > 0 else spec


def _is_unpinned(spec: str) -> bool:
    """Whether this spec can resolve to different code on a later launch.

    Only an exact version is pinned. A dist-tag (``@latest``), a range (``@^1.2.0``)
    and an absent version all mean the package is re-resolved at launch, so the code
    reviewed today is not necessarily the code that runs tomorrow.
    """
    if not spec:
        return False
    at = _version_at(spec)
    if at < 0:
        return True
    return not _EXACT_VERSION.fullmatch(spec[at + 1 :])


def _find_package(name: str, roots: list[Path]) -> Path | None:
    parts = name.split("/")
    for root in roots:
        candidate = root.joinpath(*parts)
        if candidate.is_dir() and not candidate.is_symlink():
            return candidate
    return None


def _looks_like_path(value: str) -> bool:
    return (
        value.endswith(SOURCE_SUFFIXES)
        or "/" in value
        or "\\" in value
        or value.startswith(".")
    )


def _flag_value(args: list[str], flag: str) -> str:
    """Value of ``--flag value`` or ``--flag=value``, or an empty string."""
    for index, arg in enumerate(args):
        if arg == flag and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1]
    return ""


def _resolve_dir(value: str, project_root: Path) -> Path | None:
    raw = Path(value.strip().strip('"').strip("'")).expanduser()
    for candidate in ([raw] if raw.is_absolute() else [project_root / raw, raw]):
        try:
            if candidate.is_dir() and not candidate.is_symlink():
                return candidate
        except OSError:
            continue
    return None


def _resolve_path_arg(value: str, project_root: Path) -> Path | None:
    """A path argument, resolved relative to the project when it is not absolute."""
    raw = Path(value.strip().strip('"').strip("'")).expanduser()
    for candidate in ([raw] if raw.is_absolute() else [project_root / raw, raw]):
        try:
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        except OSError:
            continue
    return None


def resolve(
    command: str, args: list[str], project_root: Path, home: Path, user_scope: bool
) -> Resolution:
    """Locate a server's code from the way it is launched."""
    if not command:
        return Resolution(reason="server has no command (remote transport)")

    base = _basename(command)
    if base in CONTAINERS:
        return Resolution(
            method="container",
            reason=f"launched via {base}; the image is not readable from the host filesystem",
        )

    positional = [a for a in args if not a.startswith("-")]

    # ``uv run`` is common for Python MCP servers and names its project with a flag
    # rather than a positional, so it is resolved before the general cases.
    if base == "uv":
        directory = _flag_value(args, "--directory") or _flag_value(args, "--project")
        if directory:
            root = _resolve_dir(directory, project_root)
            if root:
                return Resolution(root=root, method="uv --directory")
            return Resolution(
                method="uv --directory",
                reason=f"--directory '{directory}' does not exist or is a symlink",
            )
        if positional[:2] == ["tool", "run"]:
            base, positional = "uvx", positional[2:]  # `uv tool run pkg` is uvx
        elif positional[:1] == ["run"]:
            positional = positional[1:]
            for arg in positional:
                entry = _resolve_path_arg(arg, project_root) if _looks_like_path(arg) else None
                if entry:
                    return Resolution(
                        root=_package_root(entry), entry=entry, method="uv run script"
                    )

    # 1. The command is itself a path to the server.
    if _looks_like_path(command):
        entry = _resolve_path_arg(command, project_root)
        if entry:
            return Resolution(root=_package_root(entry), entry=entry, method="command path")

    # 2. An interpreter with the entry point as an argument.
    if base in INTERPRETERS:
        for arg in positional:
            if not _looks_like_path(arg):
                continue
            entry = _resolve_path_arg(arg, project_root)
            if entry:
                return Resolution(root=_package_root(entry), entry=entry, method=f"{base} entry point")
        # ``python -m package``
        if "-m" in args:
            index = args.index("-m")
            if index + 1 < len(args):
                module = args[index + 1].split(".")[0]
                roots = [project_root, project_root / "src", *_python_site_roots(project_root, home, user_scope)]
                found = _find_package(module, roots)
                if found:
                    return Resolution(root=found, method="python -m module", package_spec=module)
                return Resolution(
                    method="python -m module",
                    package_spec=module,
                    reason=f"module '{module}' is not installed anywhere Argus looks",
                )

    # 3. A package runner: the first positional names a package.
    if base in RUNNERS:
        spec = next((a for a in positional if a not in ("dlx", "run")), "")
        if spec:
            name = _strip_version(spec)
            roots = (
                _python_site_roots(project_root, home, user_scope)
                if base in ("uvx", "pipx")
                else _node_module_roots(project_root, home, user_scope)
            )
            found = _find_package(name, roots)
            if found:
                return Resolution(root=found, method=f"{base} package", package_spec=spec)
            return Resolution(
                method=f"{base} package",
                package_spec=spec,
                reason=(
                    f"package '{name}' is not installed locally; {base} fetches it at launch, "
                    "so its code cannot be reviewed before it runs"
                ),
            )

    return Resolution(reason=f"command '{base}' is not a recognised way to launch a local server")


def _entry_points(root: Path) -> list[Path]:
    """Entry files named by package metadata, which a source walk would miss.

    ``main``/``bin`` in ``package.json`` routinely point into ``dist/`` or ``build/``,
    which :func:`iter_files` skips by name — for an installed server that is where the
    code being audited actually lives.
    """
    manifest = root / "package.json"
    if not manifest.is_file():
        return []
    try:
        import json

        data = json.loads(read_text(manifest, MAX_FILE_BYTES))
    except (ArgusError, OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    declared: list[str] = []
    for key in ("main", "module", "types"):
        if isinstance(data.get(key), str):
            declared.append(data[key])
    binary = data.get("bin")
    if isinstance(binary, str):
        declared.append(binary)
    elif isinstance(binary, dict):
        declared.extend(str(v) for v in binary.values() if isinstance(v, str))

    out: list[Path] = []
    for entry in declared:
        candidate = root / entry
        try:
            if candidate.is_file() and not candidate.is_symlink():
                out.append(candidate)
        except OSError:
            continue
    return out


def _collect(resolution: Resolution) -> None:
    """Read the server's source, bounded, and extract whatever tools it declares."""
    candidates: list[Path] = []
    if resolution.entry:
        candidates.append(resolution.entry)

    root = resolution.root
    if root and root.is_dir():
        candidates.extend(_entry_points(root))
        candidates.extend(iter_files(root, suffixes=SOURCE_SUFFIXES, max_depth=3, max_files=200))
        # Compiled output lives in directories iter_files skips by name.
        for name in BUILD_DIRS:
            sub = root / name
            if sub.is_dir() and not sub.is_symlink():
                candidates.extend(iter_files(sub, suffixes=SOURCE_SUFFIXES, max_depth=3, max_files=200))

    seen: set[Path] = set()
    total = 0
    for path in candidates:
        if len(resolution.files) >= MAX_SOURCE_FILES or total >= MAX_TOTAL_BYTES:
            resolution.truncated = True
            break
        try:
            key = path.resolve()
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        if _is_test_file(path):
            continue
        try:
            text = read_text(path, MAX_FILE_BYTES)
        except (ArgusError, OSError, ValueError):
            # Unreadable or oversized: skipped here, surfaced by the caller's counts.
            continue
        total += len(text)
        resolution.files.append(SourceFile(path=path, text=text))

    for source in resolution.files:
        resolution.tools.extend(extract_tools(source.path, source.text))


def enrich(assets: list[Asset], context: DiscoveryContext) -> None:
    """Attach resolved code and tool definitions to each MCP server asset.

    Mutates in place: the server's configuration and its implementation are the same
    asset, so a finding about either names the same server.
    """
    for asset in assets:
        resolution = resolve(
            asset.data.get("command", ""),
            asset.data.get("args", []) or [],
            context.project_root,
            context.home,
            context.user_scope,
        )
        if resolution.resolved:
            _collect(resolution)
            root = resolution.root or (resolution.entry.parent if resolution.entry else None)
            if root is not None:
                # The config named this location, so it becomes part of the audited
                # surface. Recording it keeps scan_roots an honest account of what
                # was read.
                context.record_root(root)

        asset.data["code"] = {
            "root": str(resolution.root) if resolution.root else "",
            "entry": str(resolution.entry) if resolution.entry else "",
            "method": resolution.method,
            "reason": resolution.reason,
            "resolved": resolution.resolved,
            "file_count": len(resolution.files),
            "truncated": resolution.truncated,
            "package_spec": resolution.package_spec,
            "unpinned": _is_unpinned(resolution.package_spec),
        }
        asset.data["tools"] = [t.to_dict() for t in resolution.tools]
        asset.code_files = [(f.path, f.text) for f in resolution.files]
