"""Orchestration for ``argus dynamo``: pick servers, probe them, score the result.

Kept out of :mod:`argus.cli` so the code that executes servers is never imported by
a plain ``argus scan``. The separation is not cosmetic — it means the static path
cannot reach the process-spawning path even by accident.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .core.models import Asset, Target
from .discovery import discover_all
from .dynamic import hook_runner
from .dynamic import probe as probe_mod
from .dynamic import sandbox as sandbox_mod
from .dynamic.hook_runner import HookProbe
from .dynamic.probe import ProbeResult

#: Launchers that need something Argus cannot provide inside the jail: a running
#: container daemon, or a package fetched from the network at start-up.
_UNPROBEABLE = {
    "docker": "runs from a container image, which the sandbox does not nest",
    "podman": "runs from a container image, which the sandbox does not nest",
    "npx": "resolves its package from the network, which the sandbox blocks",
    "uvx": "resolves its package from the network, which the sandbox blocks",
    "pipx": "resolves its package from the network, which the sandbox blocks",
}


@dataclass
class Candidate:
    """One server the probe could attempt, with its launch vector."""

    server_id: str
    argv: list[str]
    source: Path | None
    skip_reason: str = ""


def _resolve_binary(command: str) -> str | None:
    """Absolute path for a launcher, resolved on the host before entering the jail.

    ``PATH`` inside the sandbox is deliberately minimal, so resolution happens out
    here where the answer is knowable. A command that is not on the host ``PATH``
    is not going to appear inside the jail.
    """
    if "/" in command:
        return command if Path(command).exists() else None
    return shutil.which(command)


def candidates(assets: list[Asset]) -> list[Candidate]:
    """Turn discovered MCP servers into probe candidates.

    A server that cannot be probed is returned with the reason rather than dropped.
    Coverage that silently shrinks is the failure mode this whole project keeps
    running into, and a probe is far easier to skip than a file read.
    """
    out: list[Candidate] = []
    for asset in assets:
        if asset.target is not Target.MCP:
            continue
        data = asset.data
        command = str(data.get("command") or "")
        args = [str(a) for a in (data.get("args") or [])]
        server_id = asset.asset_id

        if not command:
            url = data.get("url")
            out.append(
                Candidate(server_id, [], None,
                          skip_reason=f"remote server at {url}, nothing local to run"
                          if url else "no launch command declared")
            )
            continue

        base = Path(command).name.lower()
        if base in _UNPROBEABLE:
            out.append(Candidate(server_id, [], None, skip_reason=_UNPROBEABLE[base]))
            continue

        resolved = _resolve_binary(command)
        if resolved is None:
            out.append(
                Candidate(server_id, [], None,
                          skip_reason=f"launcher {command!r} is not on PATH")
            )
            continue

        # The directory holding the entry point is what gets mounted read-only.
        source: Path | None = None
        for candidate_arg in args:
            path = Path(candidate_arg).expanduser()
            if path.exists():
                source = (path if path.is_dir() else path.parent).resolve()
                break

        out.append(Candidate(server_id, [resolved, *args], source))
    return out


@dataclass
class ProbeRun:
    """Everything one ``argus dynamo`` invocation observed."""

    sandbox: sandbox_mod.Sandbox
    servers: list[ProbeResult] = field(default_factory=list)
    hooks: list[HookProbe] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)

    @property
    def attempted(self) -> int:
        return len(self.servers) + len(self.hooks)

    @property
    def executed(self) -> int:
        return sum(1 for p in self.servers if p.started) + sum(
            1 for h in self.hooks if h.ran
        )


def run_probes(
    project_root: Path,
    *,
    home: Path | None = None,
    user_scope: bool = True,
    only: set[str] | None = None,
    targets: set[Target] | None = None,
    network: bool = False,
    timeout: float = 20.0,
    call_tools: bool = True,
    include_mutating: bool = False,
) -> ProbeRun:
    """Discover components and exercise each one under its own sandbox.

    Every component gets a fresh jail with fresh canaries, so a token recovered from
    one cannot be attributed to another, and a component that fouls its scratch home
    cannot affect the next.
    """
    wanted = targets or {Target.MCP, Target.HOOKS}
    assets, _ = discover_all(project_root, wanted, home=home, user_scope=user_scope)

    root = sandbox_mod.scratch_root()
    # Built up front: the operator needs the isolation summary even when nothing
    # turns out to be probeable, and detect_sandbox() must fail before anything runs.
    run = ProbeRun(sandbox=sandbox_mod.build(root / "_reference", network=network))
    reference: sandbox_mod.Sandbox | None = None

    def matches(identifier: str) -> bool:
        return not only or any(needle in identifier for needle in only)

    if Target.MCP in wanted:
        run.candidates = [c for c in candidates(assets) if matches(c.server_id)]
        for candidate in run.candidates:
            if candidate.skip_reason:
                run.servers.append(
                    ProbeResult(
                        server_id=candidate.server_id,
                        command="",
                        reason=candidate.skip_reason,
                    )
                )
                continue
            jail = sandbox_mod.build(
                probe_mod.scratch_for(root, candidate.server_id),
                source=candidate.source,
                network=network,
            )
            reference = reference or jail
            run.servers.append(
                probe_mod.probe_server(
                    candidate.server_id,
                    candidate.argv,
                    jail,
                    workdir=str(candidate.source) if candidate.source else None,
                    timeout=timeout,
                    call_tools=call_tools,
                    include_mutating=include_mutating,
                )
            )

    if Target.HOOKS in wanted:
        for asset in assets:
            if asset.target is not Target.HOOKS or not matches(asset.asset_id):
                continue
            data = asset.data
            # A hook may invoke a script that lives outside the jail's default mounts.
            script = data.get("script_path")
            source = Path(script).parent.resolve() if script and Path(script).exists() else None
            jail = sandbox_mod.build(
                probe_mod.scratch_for(root, asset.asset_id),
                source=source,
                network=network,
            )
            reference = reference or jail
            declared = data.get("timeout")
            run.hooks.append(
                hook_runner.run_hook(
                    asset.asset_id,
                    str(data.get("event") or ""),
                    str(data.get("matcher") or ""),
                    str(data.get("command") or ""),
                    jail,
                    timeout=float(declared) if isinstance(declared, (int, float)) else timeout,
                )
            )

    if reference is not None:
        run.sandbox = reference
    return run
