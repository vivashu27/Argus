"""Run one MCP server under containment and record what it did.

The probe answers questions a reader of the source cannot. It takes a tool listing,
exercises the server, takes another listing, and keeps both. Everything the server
said is retained verbatim so the checks can reason over evidence rather than over a
verdict this module reached on its own — the separation that lets a finding cite
what actually came back down the pipe.

Sequencing is the whole method. A rug pull is invisible in any single snapshot and
obvious across two.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .mcp_client import McpError, StdioMcpClient, ToolInfo
from .sandbox import Canary, Sandbox

#: Tools invoked per probe. A server with hundreds of tools is a scan-time problem,
#: not a reason to skip probing the ones most likely to matter.
MAX_TOOL_CALLS = 12

#: Verbs that suggest a tool changes state. They are called last and only when the
#: caller opts in, because "contained" is not the same as "consequence-free" — a
#: sandboxed tool can still post to a real API if the network is enabled.
_MUTATING = (
    "delete", "remove", "drop", "destroy", "purge", "kill", "write", "create",
    "update", "insert", "send", "post", "publish", "deploy", "execute", "run",
    "install", "payment", "transfer", "email",
)


@dataclass
class ToolSnapshot:
    """A ``tools/list`` result at one point in time."""

    label: str
    at: float
    tools: list[ToolInfo] = field(default_factory=list)

    @property
    def by_name(self) -> dict[str, ToolInfo]:
        return {tool.name: tool for tool in self.tools}


@dataclass
class ToolCall:
    """One invocation and what came back."""

    name: str
    arguments: dict[str, Any]
    output: str = ""
    error: str = ""


@dataclass
class ProbeResult:
    """Everything one probe observed. Checks read this and nothing else."""

    server_id: str
    command: str
    started: bool = False
    reason: str = ""
    snapshots: list[ToolSnapshot] = field(default_factory=list)
    calls: list[ToolCall] = field(default_factory=list)
    canary_hits: list[tuple[Canary, str]] = field(default_factory=list)
    #: Planted agent-configuration files the server rewrote while running. A server
    #: has no more business editing settings.json than a hook does.
    config_changes: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)
    exit_code: int | None = None
    sandbox_backend: str = ""
    network_enabled: bool = False

    @property
    def first(self) -> ToolSnapshot | None:
        return self.snapshots[0] if self.snapshots else None

    @property
    def last(self) -> ToolSnapshot | None:
        return self.snapshots[-1] if self.snapshots else None

    @property
    def usable(self) -> bool:
        """Whether the probe got far enough for a silent check to mean anything.

        A server that never started is not a clean server. Checks consult this so
        an absent finding is never mistaken for a passed one.
        """
        return self.started and len(self.snapshots) >= 2


def _example_value(schema: dict[str, Any], name: str) -> Any:
    """A benign value satisfying one parameter's declared type.

    Deliberately inert. The probe is looking for what a server does when called at
    all, not fuzzing it — a payload here would make any finding a statement about
    Argus's input rather than about the server.
    """
    if not isinstance(schema, dict):
        return "argus-probe"
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    if "default" in schema:
        return schema["default"]
    declared = schema.get("type")
    if isinstance(declared, list):
        declared = next((t for t in declared if t != "null"), "string")
    return {
        "string": "argus-probe",
        "number": 1,
        "integer": 1,
        "boolean": False,
        "array": [],
        "object": {},
        "null": None,
    }.get(str(declared), f"argus-probe-{name}")


def synthesize_arguments(tool: ToolInfo) -> dict[str, Any]:
    """Minimal arguments for a tool: required parameters only."""
    schema = tool.input_schema or {}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    required = schema.get("required")
    names = required if isinstance(required, list) else list(properties)
    return {
        str(name): _example_value(properties.get(name, {}), str(name))
        for name in names
        if isinstance(name, str) and name in properties
    }


def _is_mutating(tool: ToolInfo) -> bool:
    haystack = f"{tool.name} {tool.description}".lower()
    return any(verb in haystack for verb in _MUTATING)


def probe_server(
    server_id: str,
    argv: list[str],
    sandbox: Sandbox,
    *,
    workdir: str | None = None,
    timeout: float = 20.0,
    call_tools: bool = True,
    include_mutating: bool = False,
) -> ProbeResult:
    """Start a server under containment, exercise it, and record the result.

    Never raises for a misbehaving server. A crash, a hang and a refusal to
    handshake are all observations, recorded with the reason, because a probe that
    aborted is a different thing from a server that behaved.
    """
    result = ProbeResult(
        server_id=server_id,
        command=" ".join(argv),
        sandbox_backend=sandbox.backend,
        network_enabled=sandbox.network,
    )
    wrapped = sandbox.wrap(argv, workdir=workdir)
    client = StdioMcpClient(wrapped, timeout=timeout)
    config_before = sandbox.config_digest()

    try:
        client.start()
    except McpError as exc:
        result.reason = str(exc)
        return result

    try:
        try:
            client.initialize()
        except McpError as exc:
            result.reason = f"handshake failed: {exc}"
            return result
        result.started = True

        try:
            result.snapshots.append(
                ToolSnapshot("handshake", time.monotonic(), client.list_tools())
            )
        except McpError as exc:
            result.reason = f"tools/list failed: {exc}"
            return result

        if call_tools and result.snapshots[0].tools:
            candidates = [
                tool for tool in result.snapshots[0].tools
                if include_mutating or not _is_mutating(tool)
            ]
            for tool in candidates[:MAX_TOOL_CALLS]:
                arguments = synthesize_arguments(tool)
                call = ToolCall(name=tool.name, arguments=arguments)
                try:
                    call.output = client.call_tool(tool.name, arguments)
                except McpError as exc:
                    call.error = str(exc)
                result.calls.append(call)
                for canary in sandbox.find_canaries(call.output):
                    result.canary_hits.append((canary, tool.name))
                # Recorded; now strip it so the report cannot carry the secret.
                call.output = sandbox.redact_canaries(call.output)

        # The second listing is the point of the exercise: a description that
        # changed between here and the handshake was changed by the server, after
        # the client had already been shown the honest version.
        try:
            result.snapshots.append(
                ToolSnapshot("post-invocation", time.monotonic(), client.list_tools())
            )
        except McpError as exc:
            result.reason = f"second tools/list failed: {exc}"
    finally:
        client.close()
        result.stderr = client.stderr_tail
        result.exit_code = client.exit_code
        for line in result.stderr:
            for canary in sandbox.find_canaries(line):
                result.canary_hits.append((canary, "stderr"))
        result.stderr = [sandbox.redact_canaries(line) for line in result.stderr]
        result.config_changes = sandbox.config_changes(config_before)

    return result


def scratch_for(root: Path, server_id: str) -> Path:
    """A per-server subdirectory of a probe run's scratch space."""
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in server_id)[:60]
    path = root / (safe or "server")
    path.mkdir(parents=True, exist_ok=True)
    return path
