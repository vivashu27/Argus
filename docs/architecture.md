# Architecture

## Pipeline

```
Discovery → Asset Enumeration → Configuration Collection → Static Analysis
   → Security Checks → Finding Normalization → Risk Classification
   → Security Score → Report Generation
```

Each stage is a separate module boundary, and each is defensive: a hostile or malformed
artifact at any stage degrades that stage's output rather than aborting the scan.

## Module layout

```
argus/
├── cli.py            Typer CLI, exit-code policy, format dispatch
├── config.py         argus.yaml parsing and precedence
├── log.py            logging setup (named `log` to avoid shadowing stdlib `logging`)
│
├── core/
│   ├── models.py     Severity, Status, Confidence, Category, Target, Asset,
│   │                 CheckMeta, Evidence, Finding, ScanResult
│   ├── registry.py   @register decorator, selection logic
│   ├── engine.py     the scan pipeline, exception/accepted-risk application
│   ├── scoring.py    weighted deduction model and Summary
│   ├── severity.py   the two independent gates (display, exit code)
│   ├── safe_io.py    every filesystem read in Argus
│   └── exceptions.py error hierarchy mapped to exit codes
│
├── discovery/        one module per asset domain, all OS-aware
│   ├── platform.py   per-OS path resolution — the only place paths are hardcoded
│   ├── claude_code.py, claude_desktop.py, mcp.py, skills.py,
│   ├── plugins.py, hooks.py, instructions.py, ide.py, filesystem.py
│   └── base.py       DiscoveryContext (unreadable paths, scan roots, errors)
│
├── analysis/         shared detection engines, used by many check families
│   ├── secrets.py    two-stage: structural patterns + entropy-corroborated generics
│   ├── injection.py  prompt-injection heuristics + host classification
│   ├── commands.py   tiered dangerous-command detection
│   ├── paths.py      sensitive-path knowledge, permission-rule evaluation
│   └── redaction.py  redaction at the point of detection
│
├── checks/           one module per AASB section
│   └── base.py       Check ABC, CheckContext, finding constructors
│
├── benchmarks/aasb_v1.py   section metadata, levels, coverage
└── reporters/        terminal, json, yaml, csv, markdown, html, sarif
```

### Naming

Reporter modules are suffixed (`json_reporter.py`, `csv_reporter.py`, `yaml_reporter.py`)
and the logger is `log.py`. Bare `json.py` or `logging.py` inside a package is legal under
absolute imports but is a persistent footgun; the suffix costs nothing.

## Adding a check

Adding a check never requires touching the engine. Subclass `Check`, declare a
`CheckMeta`, and decorate:

```python
from argus.core.models import Category, CheckMeta, Severity, Target
from argus.core.registry import register
from argus.checks.base import Check, CheckContext

@register
class MyCheck(Check):
    meta = CheckMeta(
        check_id="MCP-013",
        title="…",
        description="…",
        category=Category.MCP,
        severity=Severity.HIGH,
        aasb_level=2,
        applies_to=frozenset({Target.MCP}),
        rationale="why this is detectable and what the signal means",
        security_impact="what an attacker gains",
        remediation="what the operator should change",
        compliance=(("CWE", "CWE-123: …"),),
    )

    def run(self, context: CheckContext) -> list[Finding]:
        assets = context.by_target(Target.MCP)
        if not assets:
            return self.no_assets("MCP servers")
        ...
```

The registry derives the AASB number (`MCP-013` → `2.13`) from the category and ID, so
nothing else needs updating.

### Check contract

- **Never raise to signal a problem.** Return an `ERROR` finding, or `MANUAL` when the
  answer is not statically determinable. The engine catches exceptions as a backstop, but
  a check that relies on that loses its evidence.
- **Never do discovery.** Checks receive already-collected assets. The engine owns every
  filesystem read so limits and symlink policy are enforced in one place.
- **Redact before constructing evidence.** Nothing downstream re-redacts.
- **Emit one finding per asset**, so reports can name the specific server, Skill or file
  at fault rather than the category.

## Two independent axes

`Target` and `Category` are orthogonal and both filters may be combined:

- **Target** — *what was discovered*: `claude-code`, `mcp`, `skills`, `hooks`, …
- **Category** — *what kind of check*: `claude`, `mcp`, `secrets`, `filesystem`, …

Every check declares `applies_to: frozenset[Target]`. `--target mcp` runs every check
whose `applies_to` includes `mcp`, including secret checks scoped to MCP assets.

## Two independent gates

- `--severity` filters what appears in the report. `PASS`, `MANUAL`, `NOT_APPLICABLE` and
  `ERROR` are always retained, because hiding an unevaluated control behind a severity
  filter would misrepresent coverage.
- `--fail-on` decides the exit code. Only open `FAIL` findings gate; `WARN` and `MANUAL`
  never do, and accepted risks are excluded.

The score is always computed over the *full* finding set, before any display filter.

## Deduplication

One `(file, line, pattern)` produces at most one finding. Where a specific and a generic
check both match, the specific category wins: `MCP-006`, `SKILL-006`, `PLUGIN-005` and
`INSTR-001` take precedence over the `SECRET-*` family, which covers only assets no other
category owns.

## Error handling

| Condition | Result |
|---|---|
| Malformed JSON/YAML | Asset retained with `malformed: True`; raw text still scanned |
| Unreadable file | Recorded in `metadata.unreadable_paths`, surfaced in every report |
| File over the size cap | Skipped and recorded; never partially parsed |
| Check raises | `ERROR` finding; scan continues; excluded from coverage denominator |
| Discoverer raises | Recorded in `DiscoveryContext.errors`; other discoverers continue |

Coverage is reported honestly: `passed / (total − not_applicable − errors)`.
