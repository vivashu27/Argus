"""A minimal MCP client, enough to interrogate a server over stdio.

The official SDK is not used here for the same reason the rest of Argus avoids
dependencies: this is a security tool, and its dependency tree is part of its threat
model. What is needed is small — newline-delimited JSON-RPC over a pipe, four
methods, and strict timeouts.

Being deliberately hostile-input tolerant matters more than protocol completeness.
The server on the other end of the pipe is the thing under audit; it may return
malformed JSON, never answer, answer a request that was never sent, or emit
gigabytes to stdout. Each of those is handled as data, not as an error condition
that aborts a scan.
"""

from __future__ import annotations

import contextlib
import json
import queue
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any

#: The revision advertised at handshake. Servers negotiate down when they support
#: something older; one that refuses outright is recorded rather than retried.
PROTOCOL_VERSION = "2024-11-05"

#: A response line beyond this is truncated. A server that emits more than this in
#: one message is not answering the question that was asked.
MAX_LINE_BYTES = 2_000_000


class McpError(RuntimeError):
    """The server could not be spoken to. Never fatal — the probe records why."""


@dataclass
class ToolInfo:
    """One entry from ``tools/list``, kept as declared."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Any) -> ToolInfo | None:
        if not isinstance(payload, dict):
            return None
        name = payload.get("name")
        if not isinstance(name, str) or not name:
            return None
        schema = payload.get("inputSchema")
        return cls(
            name=name,
            description=str(payload.get("description") or ""),
            input_schema=schema if isinstance(schema, dict) else {},
        )


def _drain(stream: Any, sink: queue.Queue[str], marker: object) -> None:
    """Read a pipe line by line into a queue until it closes.

    A reader thread rather than a blocking read, because a server that never
    answers must cost a timeout rather than the whole scan.
    """
    try:
        for line in iter(stream.readline, ""):
            sink.put(line[:MAX_LINE_BYTES])
    except (OSError, ValueError):
        pass
    finally:
        sink.put(marker)  # type: ignore[arg-type]


class StdioMcpClient:
    """Speaks MCP to a subprocess over stdin/stdout.

    The caller supplies an already-sandboxed argument vector. This class does not
    decide what is safe to run — that judgement belongs to
    :mod:`argus.dynamic.sandbox`, and keeping it there means there is exactly one
    place where containment can be got wrong.
    """

    def __init__(self, argv: list[str], *, cwd: str | None = None,
                 env: dict[str, str] | None = None, timeout: float = 20.0) -> None:
        self.argv = argv
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self._process: subprocess.Popen[str] | None = None
        self._stdout: queue.Queue[str] = queue.Queue()
        self._closed = object()
        self._next_id = 0
        self.stderr_tail: list[str] = []

    # -- lifecycle ------------------------------------------------------------

    def __enter__(self) -> StdioMcpClient:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def start(self) -> None:
        try:
            self._process = subprocess.Popen(  # noqa: S603 — argv is sandbox-built
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                env=self.env,
                text=True,
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            raise McpError(f"could not start server: {exc}") from exc

        threading.Thread(
            target=_drain, args=(self._process.stdout, self._stdout, self._closed), daemon=True
        ).start()
        stderr_queue: queue.Queue[str] = queue.Queue()
        threading.Thread(
            target=_drain, args=(self._process.stderr, stderr_queue, self._closed), daemon=True
        ).start()
        self._stderr_queue = stderr_queue

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        self._collect_stderr()
        for step in (process.terminate, process.kill):
            if process.poll() is not None:
                break
            step()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                continue
        self._process = None

    def _collect_stderr(self) -> None:
        while True:
            try:
                item = self._stderr_queue.get_nowait()
            except queue.Empty:
                return
            if item is self._closed:
                return
            if len(self.stderr_tail) < 40:
                self.stderr_tail.append(str(item).rstrip("\n"))

    @property
    def exit_code(self) -> int | None:
        return self._process.poll() if self._process else None

    # -- transport ------------------------------------------------------------

    def _send(self, message: dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise McpError("server is not running")
        try:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise McpError(f"server closed its input: {exc}") from exc

    def _read_result(self, request_id: int) -> dict[str, Any]:
        """Wait for the response to one request, skipping anything else.

        Servers interleave notifications and log lines with responses, and a
        malicious one may answer an id it was never asked. Matching on the id and
        discarding the rest is the only safe read.
        """
        deadline = threading.Event()
        timer = threading.Timer(self.timeout, deadline.set)
        timer.start()
        try:
            while not deadline.is_set():
                try:
                    line = self._stdout.get(timeout=0.2)
                except queue.Empty:
                    if self.exit_code is not None and self._stdout.empty():
                        self._collect_stderr()
                        raise McpError(
                            f"server exited with code {self.exit_code} before answering"
                        ) from None
                    continue
                if line is self._closed:
                    self._collect_stderr()
                    raise McpError("server closed its output before answering")
                text = str(line).strip()
                if not text:
                    continue
                try:
                    message = json.loads(text)
                except json.JSONDecodeError:
                    continue  # stray logging on stdout, common and not fatal
                if not isinstance(message, dict) or message.get("id") != request_id:
                    continue
                if "error" in message:
                    error = message["error"]
                    detail = error.get("message") if isinstance(error, dict) else error
                    raise McpError(f"server returned an error: {detail}")
                result = message.get("result")
                return result if isinstance(result, dict) else {}
            raise McpError(f"server did not answer within {self.timeout:g}s")
        finally:
            timer.cancel()

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self._send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        )
        return self._read_result(request_id)

    # -- protocol -------------------------------------------------------------

    def initialize(self) -> dict[str, Any]:
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "argus-dynamo", "version": "1.0"},
            },
        )
        # The notification is required by the spec and takes no reply. A server that
        # rejects it is already misbehaving, but that is the probe's finding to make.
        with contextlib.suppress(McpError):
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def list_tools(self) -> list[ToolInfo]:
        payload = self._request("tools/list")
        raw = payload.get("tools")
        if not isinstance(raw, list):
            return []
        tools = [ToolInfo.from_payload(item) for item in raw]
        return [tool for tool in tools if tool is not None]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Invoke a tool and flatten its content blocks to text.

        Only the text is kept. The probe reasons about what a server *said*, and
        every finding this supports — a leaked canary, an injected instruction —
        lives in the text a model would have been shown.
        """
        payload = self._request("tools/call", {"name": name, "arguments": arguments})
        chunks: list[str] = []
        content = payload.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    chunks.append(block["text"])
                elif isinstance(block, str):
                    chunks.append(block)
        if not chunks:
            # Structured-only results still carry text worth scanning.
            chunks.append(json.dumps(payload, default=str))
        return "\n".join(chunks)
