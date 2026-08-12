"""Dynamic analysis: observe an MCP server by running it, not by reading it.

This package is the one part of Argus that **executes the thing it is auditing**.
Everything else in the codebase holds a read-only guarantee — configuration is
parsed as data, hook scripts are read as text, MCP commands are never passed to a
shell. That guarantee does not hold here, and cannot: the attacks this package
exists to find are ones that only exist at runtime.

A rug pull is the clearest example. A server advertises an honest tool description
at handshake and swaps in a malicious one after the client has approved it. Nothing
in the source distinguishes it from a server that builds its description
dynamically for legitimate reasons. Only calling the server twice and comparing
answers separates them, and that means running it.

Because running untrusted code is the premise, containment is not a feature of this
package — it is the precondition. :mod:`argus.dynamic.sandbox` refuses to launch
anything without a working sandbox, and the CLI refuses to run at all without an
explicit opt-in. There is deliberately no "just run it on the host" escape hatch.
"""

from __future__ import annotations

from .probe import ProbeResult, ToolSnapshot, probe_server
from .sandbox import Sandbox, SandboxUnavailable, detect_sandbox

__all__ = [
    "ProbeResult",
    "Sandbox",
    "SandboxUnavailable",
    "ToolSnapshot",
    "detect_sandbox",
    "probe_server",
]
