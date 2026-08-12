"""Orchestration for ``argus dynamo``: pick servers, probe them, score the result.

Kept out of :mod:`argus.cli` so the code that executes servers is never imported by
a plain ``argus scan``. The separation is not cosmetic — it means the static path
cannot reach the process-spawning path even by accident.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .core.models import Asset, Target
from .discovery import discover_all
from .dynamic import probe as probe_mod
from .dynamic import sandbox as sandbox_mod
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


def run_probes(
    project_root: Path,
    *,
    home: Path | None = None,
    user_scope: bool = True,
    only: set[str] | None = None,
    network: bool = False,
    timeout: float = 20.0,
    call_tools: bool = True,
    include_mutating: bool = False,
) -> tuple[list[ProbeResult], list[Candidate], sandbox_mod.Sandbox]:
    """Discover MCP servers and probe each one under its own sandbox.

    Each server gets a fresh jail with fresh canaries, so a token recovered from one
    server cannot be attributed to another, and a server that fouls its scratch home
    cannot affect the next.
    """
    assets, _ = discover_all(project_root, {Target.MCP}, home=home, user_scope=user_scope)
    found = candidates(assets)
    if only:
        found = [c for c in found if any(needle in c.server_id for needle in only)]

    root = sandbox_mod.scratch_root()
    results: list[ProbeResult] = []
    reference: sandbox_mod.Sandbox | None = None

    for candidate in found:
        if candidate.skip_reason:
            results.append(
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
        results.append(
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

    if reference is None:
        # Nothing was probed, but the operator still needs the isolation summary to
        # know what would have applied.
        reference = sandbox_mod.build(root / "_reference", network=network)
    return results, found, reference
