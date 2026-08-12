"""Containment for a server that is assumed hostile.

Every other module in Argus is safe because it never runs anything. This one runs
the audited server, so its safety rests entirely on the isolation built here. The
design rule that follows is: **no sandbox, no execution**. There is no flag that
runs a server on the host, because the moment such a flag exists it becomes the one
people use when the sandbox is inconvenient.

Bubblewrap is the backend. It needs no daemon and no root, which matters because a
sandbox that requires privilege tends to be run with privilege. The namespace set
below removes the network, the process table, the IPC namespace and every writable
path except a scratch home seeded with canaries.

The isolation is not perfect and the docstrings say where it is not. A kernel
vulnerability defeats a user namespace; a server that only misbehaves against a
real network will look clean here. Naming those gaps is part of the contract —
a containment claim that overstates itself is worse than none, because it is
believed.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

#: Read-only host paths a language runtime needs to start. Nothing under /home,
#: /root, /etc/ssh or the user's real configuration is included.
_RUNTIME_PATHS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt")


def _mount_args(path: str) -> list[str]:
    """Bind one host path, preserving it as a symlink when that is what it is.

    On a merged-``/usr`` distribution ``/lib64`` is a symlink into ``/usr/lib64``.
    Bind-mounting it as a directory silently breaks dynamic linking: the ELF
    interpreter is not where the loader looks, and every exec fails with ENOENT —
    which reads exactly like a broken sandbox rather than a broken mount table.
    """
    source = Path(path)
    if source.is_symlink():
        return ["--symlink", os.readlink(path), path]
    if source.is_dir():
        return ["--ro-bind", path, path]
    if source.exists():
        return ["--ro-bind", path, path]
    return []

#: Minimal /etc. Copying the whole directory would expose host secrets; these are
#: what an interpreter actually reads to resolve users and CA roots.
_ETC_PATHS = (
    "/etc/ssl", "/etc/ca-certificates", "/etc/alternatives",
    "/etc/passwd", "/etc/group", "/etc/localtime", "/etc/nsswitch.conf",
)


class SandboxUnavailable(RuntimeError):
    """No usable sandbox on this host. Probing must not proceed."""


@dataclass(frozen=True)
class Canary:
    """A fake credential planted where a real one would live.

    Detection by canary rather than by syscall tracing is a deliberate trade. It
    cannot see a read that goes nowhere, but the reads that matter are the ones
    whose contents leave — and a unique token proves that end to end, with no
    kernel interface and no false positives. A server has no innocent reason to
    echo a value it found in ``~/.ssh/id_rsa``.
    """

    relative: str
    description: str
    token: str
    body: str


def _make_canaries() -> list[Canary]:
    def token() -> str:
        # Distinctive prefix so a hit is unambiguous, and random so it cannot be
        # guessed by a server that knows Argus plants canaries.
        return f"ARGUS-CANARY-{secrets.token_hex(16)}"

    ssh, aws, env, claude = token(), token(), token(), token()
    return [
        Canary(".ssh/id_rsa", "SSH private key", ssh,
               f"-----BEGIN OPENSSH PRIVATE KEY-----\n{ssh}\n"
               "-----END OPENSSH PRIVATE KEY-----\n"),
        Canary(".aws/credentials", "AWS credentials", aws,
               f"[default]\naws_access_key_id = AKIA{aws[:16]}\n"
               f"aws_secret_access_key = {aws}\n"),
        Canary(".env", "Environment secrets file", env,
               f"OPENAI_API_KEY={env}\nDATABASE_URL=postgres://u:{env}@db/app\n"),
        Canary(".claude/.credentials.json", "Claude Code OAuth credentials", claude,
               f'{{"claudeAiOauth": {{"accessToken": "{claude}"}}}}\n'),
    ]


@dataclass
class Sandbox:
    """A configured bubblewrap jail. Immutable once built, reused for one probe."""

    backend: str
    root: Path
    canaries: list[Canary] = field(default_factory=list)
    #: Host directory exposed read-only, normally the server's package root.
    source: Path | None = None
    network: bool = False

    @property
    def home(self) -> Path:
        return self.root / "home"

    def wrap(self, argv: list[str], *, workdir: str | None = None) -> list[str]:
        """Wrap a command so it runs inside the jail."""
        home = "/home/probe"
        wrapped = [
            "bwrap",
            # Every namespace, then selectively nothing back. --unshare-net is what
            # makes exfiltration fail closed: a server that tries to reach the
            # internet gets ENETUNREACH rather than a socket.
            "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts",
            "--unshare-cgroup-try",
            "--new-session",       # no TIOCSTI injection back into the caller's tty
            "--die-with-parent",   # a wedged server cannot outlive the scan
            "--hostname", "argus-probe",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",  # noqa: S108 — a tmpfs inside the jail, not a host path
            "--tmpfs", "/var",
            "--tmpfs", "/run",
        ]
        if not self.network:
            wrapped.append("--unshare-net")

        for path in (*_RUNTIME_PATHS, *_ETC_PATHS):
            wrapped += _mount_args(path)
        if not self.network:
            # Without a network there is nothing to resolve, and an empty file is a
            # cleaner answer to the server than a missing one.
            wrapped += ["--ro-bind-try", "/dev/null", "/etc/resolv.conf"]

        # The server's own code, read-only. A rug pull that rewrites its source
        # mid-run fails here, which is itself worth knowing.
        if self.source is not None:
            wrapped += ["--ro-bind", str(self.source), str(self.source)]

        wrapped += ["--bind", str(self.home), home]
        wrapped += [
            "--setenv", "HOME", home,
            "--setenv", "USER", "probe",
            "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
            "--setenv", "ARGUS_DYNAMO", "1",
            "--chdir", workdir or home,
            "--",
        ]
        return wrapped + argv

    def seed(self) -> None:
        """Create the scratch home and plant the canaries."""
        self.home.mkdir(parents=True, exist_ok=True)
        for canary in self.canaries:
            target = self.home / canary.relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(canary.body, encoding="utf-8")
            target.chmod(0o600)

    def find_canaries(self, text: str) -> list[Canary]:
        """Canaries whose token appears in text the server produced."""
        return [canary for canary in self.canaries if canary.token in text]


def _bwrap_works() -> bool:
    """Whether bubblewrap can actually create a namespace here.

    Presence on ``PATH`` is not enough: unprivileged user namespaces are disabled
    outright on some hardened kernels and inside some containers. Probing with a
    real jail is the only honest check, and getting a false answer here would mean
    running hostile code unconfined.
    """
    if shutil.which("bwrap") is None:
        return False
    # Mounted exactly the way a real probe is, so a distribution whose layout
    # defeats the mount table is caught here rather than reported as a
    # non-starting server on every MCP server the operator owns.
    argv = ["bwrap", "--unshare-all", "--proc", "/proc", "--dev", "/dev"]
    for path in _RUNTIME_PATHS:
        argv += _mount_args(path)
    argv += ["--", "/usr/bin/true"]
    try:
        result = subprocess.run(argv, capture_output=True, timeout=15)  # noqa: S603
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def detect_sandbox() -> str:
    """Name of a working backend, or raise :class:`SandboxUnavailable`."""
    if _bwrap_works():
        return "bwrap"
    if shutil.which("bwrap") is None:
        raise SandboxUnavailable(
            "bubblewrap is not installed. Install it (apt install bubblewrap, "
            "dnf install bubblewrap) — dynamo will not run a server unconfined."
        )
    raise SandboxUnavailable(
        "bubblewrap is installed but cannot create a namespace here. Unprivileged "
        "user namespaces are often disabled inside containers or by "
        "kernel.unprivileged_userns_clone=0."
    )


def build(root: Path, *, source: Path | None = None, network: bool = False) -> Sandbox:
    """Create and seed a sandbox rooted at a caller-owned scratch directory."""
    backend = detect_sandbox()
    sandbox = Sandbox(
        backend=backend, root=root, canaries=_make_canaries(),
        source=source, network=network,
    )
    sandbox.seed()
    return sandbox


def describe_isolation(sandbox: Sandbox) -> list[str]:
    """Plain statements of what containment does and does not cover.

    Rendered before a probe runs. An operator authorising execution of untrusted
    code is entitled to the limits in the same breath as the guarantees.
    """
    lines = [
        f"backend: {sandbox.backend} (unprivileged user namespace)",
        "filesystem: host is read-only; only a scratch home is writable",
        f"credentials: {len(sandbox.canaries)} canary files planted, real ones not mounted",
        "network: disabled" if not sandbox.network else "network: ENABLED (--allow-network)",
        "process: new PID namespace, killed with the parent",
    ]
    lines.append(
        "limits: a kernel-level namespace escape is not defended against, and a "
        "server that only misbehaves with a real network will look clean"
        if not sandbox.network
        else "limits: with --allow-network the server can reach the internet and "
             "exfiltration will succeed rather than merely be attempted"
    )
    return lines


def scratch_root(base: Path | None = None) -> Path:
    """A private directory for one probe run."""
    root = (base or Path(os.environ.get("TMPDIR", tempfile.gettempdir()))) / f"argus-dynamo-{os.getpid()}"
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    return root
