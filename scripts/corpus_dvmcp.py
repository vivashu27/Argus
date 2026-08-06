"""Score Argus against the Damn Vulnerable MCP Server corpus.

Usage::

    git clone --depth 1 https://github.com/harishsg993010/damn-vulnerable-MCP-server /tmp/dvmcp
    DVMCP=/tmp/dvmcp ARGUS_BIN=.venv/bin/argus python scripts/corpus_dvmcp.py


Expectations come from DVMCP's own README, not from what Argus happens to find.
Two of the ten challenges are runtime data-flow attacks that a static configuration
auditor cannot see by construction; they are marked out-of-scope rather than counted
as misses, and stated as such.

Nothing here executes a challenge server. Argus reads the files; that is all.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CORPUS = Path(os.environ.get("DVMCP", "")) / "challenges"
WORK = Path(tempfile.mkdtemp(prefix="argus-corpus-"))
ARGUS = Path(os.environ.get("ARGUS_BIN", "argus"))

# challenge -> (directory, DVMCP's stated vulnerability, checks that should fire)
# An empty check set means "architecturally out of scope for a static auditor".
EXPECTED: dict[str, tuple[str, str, set[str]]] = {
    "challenge1":  ("easy/challenge1",   "Basic Prompt Injection",     set()),
    "challenge2":  ("easy/challenge2",   "Tool Poisoning",             {"MCP-013"}),
    "challenge3":  ("easy/challenge3",   "Excessive Permission Scope", {"MCP-003", "MCP-004", "MCP-005", "MCP-017"}),
    "challenge4":  ("medium/challenge4", "Rug Pull Attack",            {"MCP-019"}),
    "challenge5":  ("medium/challenge5", "Tool Shadowing",             {"MCP-015"}),
    "challenge6":  ("medium/challenge6", "Indirect Prompt Injection",  set()),
    "challenge7":  ("medium/challenge7", "Token Theft",                {"MCP-006", "MCP-012", "MCP-020"}),
    "challenge8":  ("hard/challenge8",   "Malicious Code Execution",   {"MCP-016"}),
    "challenge9":  ("hard/challenge9",   "Remote Access Control",      {"MCP-016"}),
    "challenge10": ("hard/challenge10",  "Multi-Vector Attack",        {"MCP-013", "MCP-016"}),
}


def build_project() -> Path:
    """One project registering all ten servers, which is how they would really be
    installed — and what tool-shadowing detection needs in order to see a collision."""
    WORK.mkdir(parents=True, exist_ok=True)
    servers = {
        name: {"command": "python3", "args": [str((CORPUS / rel / "server.py").resolve())]}
        for name, (rel, _vuln, _checks) in EXPECTED.items()
    }
    (WORK / ".mcp.json").write_text(json.dumps({"mcpServers": servers}, indent=1))
    return WORK


def scan(project: Path) -> dict[str, set[str]]:
    """Open findings (FAIL or WARN) per server."""
    result = subprocess.run(  # noqa: S603 — invokes Argus itself, not scanned content
        [str(ARGUS), "scan", "--path", str(project), "--no-user-scope", "-f", "json"],
        capture_output=True, text=True, timeout=600,
    )
    payload = json.loads(result.stdout)
    hits: dict[str, set[str]] = {name: set() for name in EXPECTED}
    for finding in payload["findings"]:
        if finding["status"] not in ("FAIL", "WARN"):
            continue
        asset = finding["asset"]
        if asset.startswith("mcp:"):
            name = asset[4:]
            if name in hits:
                hits[name].add(finding["id"])
    return hits


def main() -> int:
    project = build_project()
    hits = scan(project)

    in_scope = detected = 0
    print(f"{'CHALLENGE':<12} {'DVMCP VULNERABILITY':<28} {'VERDICT':<10} DETECTED BY")
    print("-" * 96)
    for name, (_rel, vuln, expected) in EXPECTED.items():
        found = hits[name]
        if not expected:
            verdict = "out-of-scope"
        else:
            in_scope += 1
            if expected & found:
                verdict, _ = "DETECTED", detected
                detected += 1
            else:
                verdict = "MISSED"
        listing = ", ".join(sorted(found)) if found else "-"
        print(f"{name:<12} {vuln:<28} {verdict:<10} {listing[:44]}")

    print("-" * 96)
    print(f"in-scope challenges: {in_scope}   detected: {detected}   "
          f"rate: {detected / in_scope:.0%}")
    return 0 if detected == in_scope else 1


if __name__ == "__main__":
    sys.exit(main())
