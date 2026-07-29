# Argus Agent Security Benchmark (AASB) v1.0

> AASB is an **original Argus benchmark** inspired by CIS-style configuration baselines.
> It is **not** a CIS Benchmark, and Argus is not affiliated with or certified by CIS,
> Anthropic, OpenAI, or any other organization.

A CIS-inspired security configuration baseline for AI-agent environments: 63 checks in
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
| 2 | MCP Security | `mcp` | `MCP-` | 12 |
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
explanation, never an assumed `PASS`.

**Checks must be disjoint.** Overlapping checks double-count in the score and waste
reviewer time. Notable separations:

| Pair | Distinction |
|---|---|
| `MCP-002` / `MCP-007` | Command *is* a shell vs. arguments contain shell metacharacters |
| `MCP-005` / `MCP-010` | Declared privilege scope vs. number of exposed tools |
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
