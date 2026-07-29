# Contributing to Argus

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

.venv/bin/pytest              # tests
.venv/bin/ruff check argus tests
.venv/bin/mypy argus
```

All three must pass before a change is merged.

## The two rules that matter most

**1. Argus never executes what it scans.**

No `subprocess`, `eval`, `exec`, `os.system`, `pickle`, or `yaml.load` reachable from
scanned content. No network requests. No importing a discovered file as a module. If a
change needs any of these, it is almost certainly the wrong design — open an issue first.

**2. Argus never emits a complete secret.**

Redact at the point of detection, using `argus.analysis.redaction.redact`. Nothing
downstream re-redacts, so a raw value placed into an `Evidence` snippet reaches the report.

Both rules are enforced by `tests/integration/test_pipeline.py::TestSafety`.

## Adding a check

Subclass `Check`, declare a `CheckMeta`, decorate with `@register`, and add it to the
relevant `argus/checks/*.py` module. Nothing in the engine needs to change — see
[`docs/architecture.md`](docs/architecture.md) for a template.

### Requirements for a new check

- **Real detection logic.** No placeholders. If it cannot detect something concrete, it
  does not belong in the benchmark.
- **At least one positive and one negative test.** The negative test matters more: it is
  what stops the check becoming noise.
- **A false-positive test** if the pattern could plausibly match legitimate content.
  Regression cases found in the wild go in `TestFalsePositiveRegression`.
- **`MANUAL`, never a guess.** If the answer needs runtime information Argus will not
  gather, return `MANUAL` with an explanation of what a human should check.
- **Disjoint from existing checks.** If it overlaps one, either narrow it or state the
  precedence explicitly — overlapping checks double-count in the score.
- **Defensible metadata.** `rationale` explains *why the signal means what you claim*.
  `security_impact` states what an attacker gains. `remediation` is actionable.
- **Honest compliance mappings.** Map only where the fit is clear, against the pinned
  revisions in [`docs/benchmark.md`](docs/benchmark.md). Omit rather than guess — an
  invented mapping survives into compliance reports unchallenged.

### Choosing severity and level

Severity describes impact if exploited. Level describes how much the remediation costs the
operator:

- **Level 1** — concrete misconfiguration, low false-positive rate, remediation does not
  materially reduce usability.
- **Level 2** — may constrain legitimate workflows, or the detection is heuristic.

A `CRITICAL` Level 2 check is entirely reasonable: severe impact, but the fix is
disruptive.

### Wording

- Never assert intent. "Potential prompt injection detected", not "malicious Skill".
- Never claim static analysis proves behaviour. Describe what was *observed*.
- Name the specific asset, not the category.

## Detection quality

The fastest way to make a security scanner useless is to make it noisy. Two mechanisms
exist for this and new checks should use them:

- **Tiered command detection** (`analysis/commands.py`) — Tier A fails on its own, Tier B
  fails only with corroborating context, Tier C is informational. A bare `curl` must never
  be a standalone failure.
- **Documentation discounting** (`analysis/injection.py`) — matches inside code fences,
  blockquotes, labelled examples, or documents that read as offensive-security material
  are marked `discounted` and are not `is_actionable`. Security documentation quotes
  injection strings by necessity.

If you find a false positive in a real environment, add it to
`TestFalsePositiveRegression` in `tests/unit/test_secrets.py` or `test_analysis.py` before
fixing it.

## Test fixtures

**Never use a real credential**, even an expired one. Fixture secrets must be structurally
valid so detectors engage, but non-functional. See `tests/conftest.py`.

Note that AWS's documented `AKIAIOSFODNN7EXAMPLE` cannot be used for positive-detection
tests: it contains "EXAMPLE", which the placeholder filter correctly suppresses.

## Regenerating the check reference

`docs/checks.md` is generated and must not be hand-edited:

```bash
python scripts/gen_checks_doc.py > docs/checks.md
```

Regenerate it whenever check metadata changes.

## Code style

- `ruff` with the configured rule set; line length 100.
- Type hints throughout; `mypy` must pass with `disallow_untyped_defs`.
- Comments explain *why*, not *what*. The interesting comments in this codebase document
  non-obvious security reasoning — an unanchored regex matching a substring, a filter that
  exists to avoid punishing correct behaviour. Those are worth writing.
- Match the surrounding code's density and idiom.

## Reporting security issues in Argus itself

See [`SECURITY.md`](SECURITY.md). Please do not open a public issue for a vulnerability in
the scanner.
