# Argus Agent Security Benchmark (AASB) v1.0

> AASB is an **original Argus benchmark** inspired by CIS-style configuration baselines.
> It is **not** a CIS Benchmark, and Argus is not affiliated with or certified by CIS,
> Anthropic, OpenAI, or any other organization.

A CIS-inspired security configuration baseline for AI-agent environments: 70 checks in
8 sections, each with real detection logic and tests.

## Numbering

There is **one** canonical identifier — the check ID, e.g. `CLAUDE-001`, `MCP-003`. The
CIS-style benchmark number is a derived display label, computed deterministically:

```
AASB number = <category section>.<numeric part of the check ID>
```

| § | Section | Slug | Prefix | Checks |
|:-:|---|---|---|---:|
| 1 | Claude Configuration | `claude` | `CLAUDE-` | 10 |
| 2 | MCP Security | `mcp` | `MCP-` | 19 |
| 3 | Skills | `skills` | `SKILL-` | 10 |
| 4 | Plugins | `plugins` | `PLUGIN-` | 8 |
| 5 | Hooks | `hooks` | `HOOK-` | 6 |
| 6 | Instruction Files | `instructions` | `INSTR-` | 5 |
| 7 | Secrets | `secrets` | `SECRET-` | 5 |
| 8 | Filesystem | `filesystem` | `FS-` | 7 |

So `CLAUDE-001` is AASB **1.1**, `MCP-012` is AASB **2.12**, `FS-007` is AASB **8.7**.
`argus info` accepts either form:

```bash
argus info MCP-003
argus info 2.3
```

## Levels

**Level 1 — Basic security hygiene.**
Detects a concrete misconfiguration with a low false-positive rate, where the remediation
does not materially reduce usability. Suitable as a minimum baseline for any agent
environment.

**Level 2 — Defense in depth.**
Requires tightening that may constrain legitimate workflows, or detects a heuristic or
contextual risk. Intended for environments handling sensitive data or operating with
elevated privilege.

Level 2 is a **superset** baseline: `--level 2` runs Level 1 and Level 2 checks;
`--level 1` runs only Level 1.

```bash
argus scan --level 1     # minimum baseline
argus scan --level 2     # full benchmark (default)
```

## Statuses

| Status | Meaning | Gates exit code | Deducts score |
|---|---|:-:|:-:|
| `PASS` | Control verified as satisfied | no | no |
| `FAIL` | Control verified as violated | **yes** | yes |
| `WARN` | Signal requiring review, not asserted as a failure | no | half |
| `MANUAL` | Not determinable from static evidence | no | no |
| `NOT_APPLICABLE` | Not evaluable in this environment | no | no |
| `ERROR` | The check itself failed | no | no |

`FAIL — ACCEPTED RISK` is a display state for a `FAIL` covered by an active exception. It
stays fully visible but stops gating.

## Confidence vs status

These describe different things and must not be conflated:

- **Confidence** — how certain the *detection* is.
- **Status** — the *control outcome*.

Rules:

- A detection with `LOW` confidence that would otherwise be `FAIL` is reported as `WARN`.
  Argus does not assert a failure it cannot substantiate.
- A control requiring human judgement is `MANUAL` regardless of confidence.

## Design principles

**No placeholder checks.** Every check has real detection logic and at least one positive
and one negative test. The benchmark was not padded to hit a count.

**MANUAL over guessing.** Where the answer needs a runtime handshake — `MCP-010` (tool
surface) and `MCP-011` (destructive capability) — the result is `MANUAL` with an
explanation, never an assumed `PASS`. The same rule governs every check in section 2
that reads server code: a server Argus could not locate reports `MANUAL` naming the
reason, because a server that cannot be read is not a server that is clean.

## MCP server code analysis

`MCP-001` … `MCP-012` audit how a server is *configured*. `MCP-013` … `MCP-019` audit
what that configuration launches, which is where the published MCP attack classes live.

Two properties of the protocol make this a distinct problem. A tool's **description is
model-visible context**, not documentation — text placed there reaches the model with
the standing of the tool list, while the user sees a sentence about what the tool does.
And **every tool parameter is attacker-reachable**, because the model chooses the values
and injected text in any document the model reads can steer that choice.

| Attack class | Check |
|---|---|
| Tool poisoning — hidden instructions in a description | `MCP-013` |
| Invisible payloads (Unicode tag block, zero-width, ANSI) | `MCP-014` |
| Tool shadowing and cross-server instructions | `MCP-015` |
| Remote code execution via shell injection | `MCP-016` |
| Path traversal out of the intended directory | `MCP-017` |
| Unauthenticated exposure on all interfaces | `MCP-018` |
| Rug pull — definitions changing after approval | `MCP-019` |

### How server code is located

Argus **never starts a server**, so it cannot call `tools/list`. The `command` and
`args` are parsed as data — never passed to a shell — and mapped onto code already on
disk: an interpreter's entry-point argument, `python -m` against the project venv and
site-packages, or a package runner's spec against `node_modules`, the npx cache and
global roots. Every file is then read through the same size caps, symlink rules and
depth limits as the rest of discovery, and the resolved root is added to `scan_roots`
so the report discloses what was read.

Two consequences are worth stating plainly:

**Tool extraction is best-effort.** Definitions are recovered from source — Python
`@mcp.tool` decorators and `Tool(...)` constructions, TypeScript `server.tool` calls and
tool-list literals. A server that assembles its tool list at runtime yields fewer tools
than it exposes, so the checks report what was recovered rather than implying the list
is complete.

**An unresolvable server is reported, not passed.** A containerised server, or an
unpinned package that npx fetches at launch, has no local code to read. Those report
`MANUAL` with the reason — and for the npx case that reason *is* the finding, because
code fetched at launch cannot be reviewed before it runs.

**Checks must be disjoint.** Overlapping checks double-count in the score and waste
reviewer time. Notable separations:

| Pair | Distinction |
|---|---|
| `MCP-002` / `MCP-007` | Command *is* a shell vs. arguments contain shell metacharacters |
| `MCP-005` / `MCP-010` | Declared privilege scope vs. number of exposed tools |
| `MCP-007` / `MCP-016` | Shell metacharacters in the *launch arguments* vs. a shell sink inside the *server's code* |
| `MCP-009` / `MCP-019` | Configuration carries no integrity metadata vs. the resolved package can change between launches |
| `MCP-013` / `MCP-014` / `MCP-015` | Visible instructions in a description vs. invisible characters vs. reaching another server's tools |
| `SKILL-001` / `SKILL-008` / `SKILL-010` | Shell grant vs. specific dangerous strings vs. overall grant breadth |
| `SKILL-002` / `SKILL-009` | Reference anywhere in the Skill vs. access inside an executable script |
| `FS-005` / `FS-007` | Read exposure vs. write exposure |
| `PLUGIN-003` / `PLUGIN-008` | What the code does vs. what the manifest requests |

**Redefined hooks checks.** The original draft specified `HOOK-001`/`HOOK-002` as
"PreToolUse/PostToolUse hook executes commands" — which is what a hook *is by definition*.
Those would have fired on 100% of hooks and produced pure noise. They were replaced with
checks that distinguish a risky hook from an ordinary one: unvalidated interpolation of
agent-controlled input (`HOOK-001`) and an overly broad matcher (`HOOK-002`).

## Compliance mappings

Mapped only where technically defensible, against pinned revisions:

- **OWASP Top 10 for LLM Applications 2025** — the 2023 and 2025 lists differ materially,
  so the revision is pinned.
- **MITRE ATLAS**
- **CWE 4.x**

Where a mapping would be a guess, it is omitted. Invented mappings are worse than absent
ones, because they survive into compliance reports unchallenged.

## Full reference

Per-check detail — rationale, impact, remediation, mappings — is in
[`checks.md`](checks.md), generated directly from the registry so it cannot drift from the
implementation.
