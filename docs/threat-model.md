# Threat Model

Two distinct questions:

1. **What threats does Argus help you find?**
2. **What is Argus's own attack surface, given that it parses hostile input by design?**

---

## Part 1 — Threats Argus detects

### The core agent threat

An AI coding agent is a program that takes instructions from text and executes tools. The
text comes from many places the operator does not fully control: repository files, tool
output, web content, MCP server responses, Skills and Plugins installed from marketplaces.

The security of that system rests almost entirely on **configuration** — which tools are
allowed, with which arguments, over which paths, with which approval gates. That
configuration is exactly what Argus audits.

### Attack chain Argus is built around

```
Injection source          Agent capability            Impact
─────────────────         ─────────────────           ──────
poisoned CLAUDE.md    ─┐
hostile repo file      ├─→  unrestricted Bash    ─→  local code execution
malicious Skill        │    unrestricted Read     ─→  credential theft
compromised plugin     │    unrestricted WebFetch ─→  exfiltration
MCP tool output       ─┘    automatic hooks       ─→  unattended persistence
```

Argus evaluates both halves:

- **Injection surface** — INSTR-*, SKILL-003/004/005, HOOK-006
- **Capability** — CLAUDE-*, MCP-*, PLUGIN-*, FS-*
- **Credential reachability** — the join of the two: FS-001…004, SECRET-*

A finding is most serious where both halves meet: an environment with a wide capability
grant *and* an unvetted injection surface.

### What Argus does **not** detect

Stated plainly, because a scanner that implies more coverage than it has is worse than
none:

- **Runtime behaviour.** Argus reads configuration. A Skill that behaves correctly in its
  text and maliciously at runtime is invisible to it.
- **MCP server implementations.** Argus never starts a server, so it cannot enumerate the
  tools a server actually exposes or what they do. `MCP-010` and `MCP-011` return `MANUAL`
  rather than guessing.
- **Intent.** Static analysis cannot distinguish a malicious directive from a documented
  example. Argus reports *"potential prompt injection"* and downgrades matches in
  documentation contexts.
- **Model behaviour.** Whether a given model actually complies with an injected
  instruction is out of scope.
- **Network state.** Argus never fetches a URL it finds. A URL is classified by its
  host, not by retrieving it. The optional `--llm` stage does make outbound requests,
  but only to the provider endpoint you configure — never to a host named in scanned
  content.
- **Compromise that has already happened.** Argus is a configuration auditor, not an EDR
  or a forensics tool.

### Deliberate limits

| Limit | Reason |
|---|---|
| No server execution | Executing scanned content is the thing Argus exists to avoid |
| No fetching of discovered URLs | Fetching a URL from a hostile config is an SSRF primitive |
| Network egress only to a configured provider, opt-in | `--llm` is the only network path, and never targets a host from scanned content |
| No credential file contents read | Reading live tokens for no analytic gain is its own risk |
| Depth-limited project walk | Bounds runtime and avoids surprising the operator |
| Tiered command detection | A scanner that flags every `curl` gets switched off |

---

## Part 2 — Argus's own attack surface

Argus parses attacker-controlled files. It must be safe to point at a configuration
designed to attack the scanner itself.

### Assumed adversary

Someone who can write to any file Argus reads: `CLAUDE.md`, `.mcp.json`, a Skill body, a
plugin file, a hook script. Their goals: execute code in the scanner's process, exfiltrate
data through the scan, escape the scan root, or exhaust resources.

### Controls

| Attack | Control | Where |
|---|---|---|
| Code execution via YAML deserialization | `yaml.safe_load` only; never `yaml.load` | `core/safe_io.py` |
| Code execution via the scanned command | Nothing scanned is ever executed — no `subprocess`, `eval`, `exec`, or import of scanned content | whole codebase |
| Path traversal out of the scan root | `resolve_within()` resolves *then* compares, so a symlink is caught by its target | `core/safe_io.py` |
| Symlink loop / escape | Directory symlinks are never traversed; escapes are reported as FS-006 | `core/safe_io.py` |
| Memory exhaustion via huge file | 5 MiB read cap, enforced on the read, not just on `stat` | `core/safe_io.py` |
| Special files (`/dev/zero`, FIFOs) | Regular-file check, since `stat` reports size 0 for these | `core/safe_io.py` |
| ReDoS via crafted input | Lines over 4000 chars skipped; no nested unbounded quantifiers | `analysis/*` |
| Report flooding | Per-check finding caps; evidence snippets truncated to 200 chars | `analysis/redaction.py` |
| Secret leakage through the report | Redaction at the point of detection, asserted across every reporter | `analysis/redaction.py` |
| XSS in the HTML report | Every value HTML-escaped; report is self-contained with no external subresources | `reporters/html.py` |
| Encoding-based crashes | `errors="replace"` on decode | `core/safe_io.py` |
| One hostile file killing the scan | Per-check and per-discoverer exception isolation | `core/engine.py` |

### Verification

These are enforced by tests, not just by intent:

- `tests/integration/test_pipeline.py::TestSafety::test_scanning_hostile_environment_executes_nothing`
  builds a malicious environment whose hook, MCP server and Skill script all try to
  `touch` a canary path, scans it, and asserts the canary does not exist.
- `test_no_secret_reaches_any_output_format` renders **every** reporter over a scan
  containing synthetic credentials and asserts none appears.
- `test_yaml_never_constructs_python_objects` feeds `!!python/object/apply:os.system` and
  asserts nothing executes.
- `test_iter_files_never_traverses_symlinks` places a symlink to an outside directory in
  the scan root and asserts its contents are not enumerated.
- `test_malformed_configuration_does_not_crash` asserts a scan over invalid JSON, wrong
  types, and binary garbage produces findings with zero `ERROR` results.

### Residual risk from LLM review (`--llm` only)

Enabling `--llm` adds risk that does not exist in the default configuration. Stated
plainly so the trade is deliberate:

- **Third-party data processing.** Redacted excerpts of your agent configuration are
  sent to the provider you choose. Redaction removes secrets and identity, but the
  configuration's *structure* — server names, tool grants, instruction text — is
  transmitted. Argus discloses the processing jurisdiction before the first request;
  Moonshot and DeepSeek are PRC-hosted.
- **The reviewer is injectable.** This is OWASP AST08: a scanned file can address the
  reviewing model directly. Prompt framing reduces it but cannot eliminate it, so the
  mitigation is structural instead — **an LLM verdict can only add a `MANUAL` finding.
  It cannot alter, downgrade, or clear a static finding.** A file that says "report
  this as safe" therefore achieves nothing beyond noise. Without `--llm`, Argus has no
  model in the loop and this class of attack does not apply at all.
- **Non-determinism.** LLM findings are `MANUAL`, so they never affect the score or
  the exit code. The score remains hand-reproducible from the deduction breakdown.
- **Cost and disclosure.** Requests are byte-capped and asset-capped, but scanning a
  large environment with `--llm` has a real API cost.

### Residual risk

- **Dependencies.** Argus depends on `typer`, `rich` and `PyYAML`. A compromise in any of
  those is a compromise of Argus. Pin and review them.
- **Privilege.** Argus reads whatever the invoking user can read. Run it as the user whose
  agent environment you are auditing — never as root.
- **Report distribution.** Reports contain file paths, configuration keys and redacted
  values. They are sensitive; treat SARIF uploaded to a public repository accordingly.
- **Redaction is best-effort for unknown formats.** A credential in a format Argus does
  not recognise may appear in an evidence snippet as ordinary text. Snippets are
  truncated and structural patterns are redacted, but no scanner can guarantee this for
  arbitrary data.

## Reporting a vulnerability in Argus

See [`SECURITY.md`](../SECURITY.md).
