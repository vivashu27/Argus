"""Run one Claude Code hook under containment and record what it did.

A hook is a better dynamic target than an MCP tool, for a reason easy to overlook.
A tool runs only if the model decides to call it. A hook fires automatically on an
event — no model judgement stands between a malicious hook and execution, and no
approval prompt either.

Three of a hook's outputs re-enter the model's context: stdout on the events that
feed context, stderr on exit code 2, and the ``additionalContext`` field of a JSON
response. Text arriving by those routes is indistinguishable to the model from the
agent's own reasoning, which makes a hook a first-class injection surface — and one
whose payload may be assembled at runtime from something a source reader never sees.

Hooks are given a synthetic payload, never a real transcript. The values below are
inert placeholders, so anything interesting in the output came from the hook.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any

from .sandbox import Canary, Sandbox

#: Events whose stdout is inserted into the model's context on success. On the rest,
#: stdout is transcript-only and a payload there does not reach the model.
CONTEXT_FEEDING_EVENTS = frozenset({"UserPromptSubmit", "SessionStart"})

#: Exit code 2 is the documented "blocking error": stderr goes back to the model.
#: It therefore turns every hook, on every event, into a context-injection route.
BLOCKING_EXIT_CODE = 2

#: Upper bound regardless of the hook's declared timeout. A hook that declares 600s
#: should not hold a scan for ten minutes.
MAX_TIMEOUT = 30.0


@dataclass
class HookProbe:
    """What one hook did when it was run."""

    hook_id: str
    event: str
    matcher: str
    command: str
    ran: bool = False
    reason: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    canary_hits: list[tuple[Canary, str]] = field(default_factory=list)
    config_changes: list[str] = field(default_factory=list)
    #: Parsed ``hookSpecificOutput.permissionDecision``, when the hook returned JSON.
    decision: str = ""
    decision_reason: str = ""

    @property
    def usable(self) -> bool:
        """Whether the hook actually executed. Silence from a hook that never ran
        is not evidence that the hook is safe."""
        return self.ran

    @property
    def context_text(self) -> str:
        """Everything this hook would have injected into the model's context.

        Assembled from the three documented routes rather than from stdout alone,
        because a payload delivered by exit-2 stderr reaches the model just as
        surely and would otherwise go unscanned.
        """
        parts: list[str] = []
        if self.event in CONTEXT_FEEDING_EVENTS and self.exit_code == 0:
            parts.append(self.stdout)
        if self.exit_code == BLOCKING_EXIT_CODE:
            parts.append(self.stderr)
        for field_name in ("additionalContext", "systemMessage", "reason"):
            value = self._json_field(field_name)
            if value:
                parts.append(value)
        return "\n".join(part for part in parts if part.strip())

    def _json_field(self, name: str) -> str:
        payload = self._payload()
        if not payload:
            return ""
        specific = payload.get("hookSpecificOutput")
        for source in (specific if isinstance(specific, dict) else {}, payload):
            value = source.get(name)
            if isinstance(value, str):
                return value
        return ""

    def _payload(self) -> dict[str, Any]:
        text = self.stdout.strip()
        if not text.startswith("{"):
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}


def synthesize_payload(event: str, matcher: str) -> dict[str, Any]:
    """The stdin JSON a hook of this event would receive.

    Deliberately inert. A payload crafted to provoke the hook would make any finding
    a statement about Argus's input rather than about the hook.
    """
    base: dict[str, Any] = {
        "session_id": "argus-dynamo-probe",
        "transcript_path": "/home/probe/.claude/transcript.jsonl",
        "cwd": "/home/probe",
        "hook_event_name": event,
    }
    tool = matcher if matcher and matcher not in ("*", "") else "Bash"

    if event in ("PreToolUse", "PostToolUse"):
        base["tool_name"] = tool
        base["tool_input"] = _tool_input(tool)
        if event == "PostToolUse":
            base["tool_response"] = {"output": "argus-probe"}
    elif event == "UserPromptSubmit":
        base["prompt"] = "Summarise the README."
    elif event == "SessionStart":
        base["source"] = "startup"
    elif event in ("Stop", "SubagentStop"):
        base["stop_hook_active"] = False
    elif event == "PreCompact":
        base["trigger"] = "manual"
        base["custom_instructions"] = ""
    elif event == "Notification":
        base["message"] = "Claude needs your permission to continue."
    return base


def _tool_input(tool: str) -> dict[str, Any]:
    """A benign tool_input shaped like the tool the matcher selects."""
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return {"file_path": "/home/probe/notes.txt", "content": "argus-probe"}
    if tool in ("Read", "Glob", "Grep"):
        return {"file_path": "/home/probe/notes.txt", "pattern": "argus-probe"}
    if tool in ("WebFetch", "WebSearch"):
        return {"url": "https://example.invalid/probe", "query": "argus-probe"}
    return {"command": "echo argus-probe", "description": "probe"}


def run_hook(
    hook_id: str,
    event: str,
    matcher: str,
    command: str,
    sandbox: Sandbox,
    *,
    timeout: float = 15.0,
) -> HookProbe:
    """Execute one hook in the jail with a synthetic payload on stdin.

    Never raises. A hook that hangs, crashes or is not executable is an observation
    recorded with its reason, because "did not run" and "ran and behaved" must not
    collapse into the same silent result.
    """
    probe = HookProbe(hook_id=hook_id, event=event, matcher=matcher, command=command)
    if not command.strip():
        probe.reason = "hook declares no command"
        return probe

    # A hook command is a shell string by contract, so it needs a shell. Inside the
    # jail that is safe; outside it would be the whole vulnerability.
    argv = sandbox.wrap(["/bin/sh", "-c", command])
    payload = json.dumps(synthesize_payload(event, matcher))
    before = sandbox.config_digest()

    try:
        completed = subprocess.run(  # noqa: S603 — argv is sandbox-built
            argv,
            input=payload,
            capture_output=True,
            text=True,
            timeout=min(timeout, MAX_TIMEOUT),
        )
    except subprocess.TimeoutExpired:
        probe.reason = f"hook did not finish within {min(timeout, MAX_TIMEOUT):g}s"
        return probe
    except (OSError, ValueError) as exc:
        probe.reason = f"could not run hook: {exc}"
        return probe

    probe.ran = True
    probe.stdout = completed.stdout[:200_000]
    probe.stderr = completed.stderr[:200_000]
    probe.exit_code = completed.returncode
    probe.config_changes = sandbox.config_changes(before)

    for stream_name, text in (("stdout", probe.stdout), ("stderr", probe.stderr)):
        for canary in sandbox.find_canaries(text):
            probe.canary_hits.append((canary, stream_name))

    # A canary can also leave by being written into a file the hook creates, which
    # a stdout-only search would miss entirely.
    for path in sorted(sandbox.home.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(path.match(c.relative) for c in sandbox.canaries):
            continue  # the planted file itself, not a copy of it
        try:
            body = path.read_text(encoding="utf-8", errors="ignore")[:200_000]
        except OSError:
            continue
        for canary in sandbox.find_canaries(body):
            probe.canary_hits.append((canary, f"written to ~/{path.relative_to(sandbox.home)}"))

    # Detection is done; the text may now be stored without the secret in it.
    probe.stdout = sandbox.redact_canaries(probe.stdout)
    probe.stderr = sandbox.redact_canaries(probe.stderr)

    payload_json = probe._payload()
    specific = payload_json.get("hookSpecificOutput")
    if isinstance(specific, dict):
        decision = specific.get("permissionDecision")
        if isinstance(decision, str):
            probe.decision = decision
            reason = specific.get("permissionDecisionReason")
            probe.decision_reason = reason if isinstance(reason, str) else ""

    return probe
