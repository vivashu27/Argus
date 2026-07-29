# Scoring

The Argus security score is a **weighted deduction from 100**. Every deduction is printed
in the report so a reader can recompute the score by hand — a score that cannot be audited
is not useful in a security report.

## Formula

```
deduction(finding) = weight[severity] × status_multiplier × confidence_multiplier

score = round(max(0, 100 − Σ deductions))
```

### Severity weights

| Severity | Weight |
|---|---:|
| CRITICAL | 25 |
| HIGH | 10 |
| MEDIUM | 3 |
| LOW | 1 |
| INFO | 0 |

### Status multipliers

| Status | Multiplier | Rationale |
|---|---:|---|
| `FAIL` | 1.0 | A confirmed control failure |
| `WARN` | 0.5 | Needs review, but not asserted as a failure |
| `PASS` | 0.0 | — |
| `MANUAL` | 0.0 | Unevaluated — see below |
| `NOT_APPLICABLE` | 0.0 | Not evaluable in this environment |
| `ERROR` | 0.0 | The check itself failed |

### Confidence multipliers

| Confidence | Multiplier |
|---|---:|
| HIGH | 1.0 |
| MEDIUM | 0.8 |
| LOW | 0.5 |

A `LOW`-confidence detection that would otherwise be `FAIL` is reported as `WARN` instead,
so it is discounted twice — once by status, once by confidence. That is deliberate: a
weak signal should barely move the score.

## Why MANUAL never deducts — and never helps

`MANUAL`, `NOT_APPLICABLE` and `ERROR` contribute **zero** deduction. They also do **not**
count as passes.

This matters. If `MANUAL` deducted, a scanner would be punished for being honest about
what it cannot determine, creating pressure to guess. If `MANUAL` counted as a pass, an
environment could reach 100/100 while nothing was actually verified.

Instead they are excluded from the coverage denominator and reported separately:

```
coverage = passed / (total − not_applicable − errors)
```

A report showing `100/100` with `coverage 12/45` is telling you something important, and
the terminal, HTML and Markdown reporters all surface both numbers together.

## Accepted risk

By default an accepted-risk finding deducts **0**, does not trip the exit code, and stays
fully visible as `FAIL — ACCEPTED RISK`.

To score accepted risks anyway — useful when you want the score to reflect real posture
rather than governance decisions:

```yaml
scoring:
  score_accepted_risk: true
```

## Grades

| Score | Grade |
|---|:-:|
| ≥ 90 | A |
| ≥ 80 | B |
| ≥ 70 | C |
| ≥ 60 | D |
| < 60 | F |

## Customising weights

```yaml
scoring:
  weights:
    CRITICAL: 40
    HIGH: 15
    MEDIUM: 5
    LOW: 1
    INFO: 0
```

Only the keys you specify are overridden; the rest keep their defaults.

## Worked example

A scan produces:

- 1 × CRITICAL FAIL at HIGH confidence → `25 × 1.0 × 1.0` = **25.0**
- 2 × HIGH FAIL at HIGH confidence → `2 × (10 × 1.0 × 1.0)` = **20.0**
- 1 × HIGH WARN at MEDIUM confidence → `10 × 0.5 × 0.8` = **4.0**
- 3 × MEDIUM FAIL at MEDIUM confidence → `3 × (3 × 1.0 × 0.8)` = **7.2**
- 1 × CRITICAL FAIL, accepted risk → **0.0**
- 5 × MANUAL → **0.0**
- 30 × PASS → **0.0**

```
Σ deductions = 25.0 + 20.0 + 4.0 + 7.2 = 56.2
score        = round(100 − 56.2) = 44   → grade F
coverage     = 30/43
```

The report prints this table verbatim, so the arithmetic is checkable.

## Saturation

Weights are absolute, not normalised, so an environment with many high-severity failures
saturates at 0. This is intentional: the difference between "badly misconfigured" and
"very badly misconfigured" is not worth expressing, and normalising would let a large
number of findings dilute each other. Use the severity counts and the finding list — not
the score — to prioritise remediation.

## The score is a summary, never a filter

The score never hides a finding. `--severity` affects what is *displayed*, and is applied
*after* scoring, so the number is always computed over the complete finding set.
