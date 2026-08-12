# Argus

**AI Agent Security Configuration Auditor**

Argus audits the configuration of AI-agent environments — Claude Code, Claude Desktop,
MCP servers, Skills, Plugins, hooks, and `CLAUDE.md` instruction files — against the
**Argus Agent Security Benchmark (AASB)**, a CIS-inspired configuration baseline.

It is conceptually similar to Prowler, ScoutSuite, Lynis, Trivy and OpenSCAP, but for the
agent layer rather than cloud accounts or hosts.

> Argus is **not affiliated with or certified by** CIS, Anthropic, OpenAI, or any other
> organization. AASB is an original Argus benchmark inspired by CIS-style baselines; it is
> not a CIS Benchmark.

---

## Read-only by design

`argus scan` treats every discovered file as untrusted input. It **never**:

- modifies configuration, Skills, Plugins, hooks, or user files
- installs anything
- executes Skills, Plugins, MCP servers, or hooks
- runs commands found in configuration or instruction files
- deserializes scanned content into executable objects (`yaml.safe_load` only)

It is intended to be safe to point at a deliberately malicious configuration. See
[`docs/threat-model.md`](docs/threat-model.md).

> **`argus dynamo` is the one exception, and it is opt-in.** Dynamic analysis works
> by running the MCP servers it audits, under a sandbox, because the attacks it
> finds do not exist until the server is running. It refuses to start without
> `--i-understand-this-executes-code`. See [Dynamic analysis](#dynamic-analysis-argus-dynamo).

---

## Install

Requires **Python 3.10+**. Runs on Linux, macOS and Windows with OS-aware path
discovery.

### Linux / macOS

```bash
git clone https://github.com/vivashu27/Argus.git
cd Argus
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

.venv/bin/argus version
```

To call `argus` without the path prefix, activate the environment first:

```bash
source .venv/bin/activate
argus version
```

### Windows

Use the `py` launcher, and note that the executables live in `Scripts\`, not `bin/`.

**PowerShell**

```powershell
git clone https://github.com/vivashu27/Argus.git
cd Argus
py -m venv .venv
.venv\Scripts\pip install -e ".[dev]"

.venv\Scripts\argus version
```

**Command Prompt (cmd.exe)**

```bat
git clone https://github.com/vivashu27/Argus.git
cd Argus
py -m venv .venv
.venv\Scripts\pip install -e ".[dev]"

.venv\Scripts\argus version
```

To activate the environment instead:

```powershell
.venv\Scripts\Activate.ps1     # PowerShell
.venv\Scripts\activate.bat     # cmd.exe
argus version
```

If PowerShell refuses to run the activation script, allow signed local scripts for
your user only — this does not require an administrator:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

> **The examples below use the Linux/macOS form `.venv/bin/argus`.** On Windows,
> substitute `.venv\Scripts\argus`, or activate the environment and just use `argus`.

#### What differs on Windows

- **Claude Desktop config** is read from `%APPDATA%\Claude\claude_desktop_config.json`;
  Claude Code config from `%USERPROFILE%\.claude\`. Discovery resolves these
  automatically — no configuration needed.
- **`FS-005` and `FS-007` report `NOT_APPLICABLE`.** They evaluate POSIX permission
  bits, which have no meaningful equivalent on NTFS. Argus says so explicitly rather
  than passing them silently, so coverage stays honest. Review NTFS ACLs separately.
- **Terminal output** uses UTF-8 block lettering in Windows Terminal and PowerShell 7.
  On a legacy `cmd.exe` console that cannot encode it, the banner degrades to ASCII
  automatically.

## Quick start

```bash
argus scan                        # audit this environment, terminal report
argus scan --verbose              # include evidence, coverage, score derivation
argus scan --format html -o ./reports
argus list-checks                 # every registered check
argus list-benchmarks             # AASB sections and levels
argus info MCP-003                # full metadata for one check
argus check CLAUDE-006            # run a single check
```

### Targeting

`--target` selects *what was discovered*; `--category` selects *what kind of check*.
They are independent axes and combine with AND.

```bash
argus scan --target mcp --target skills
argus scan --category secrets
argus scan --level 1              # basic hygiene only
argus scan --check MCP-003 --check MCP-004
argus scan --exclude CLAUDE-005   # exclusion always wins over inclusion
argus scan --path ./proj --no-user-scope   # only --path; skip ~/.claude entirely
```

**Where Skills are looked for.** Discovery expects `<path>/<name>/SKILL.md`, so
`--path` should name the directory *containing* skill folders, not a skill folder
itself. Pointing at the skill directly finds nothing — Argus now says so rather than
reporting a clean scan. `<path>/.claude/skills/` and `<path>/skills/` also work.

### Severity vs exit codes

Two independent gates:

```bash
argus scan --severity medium      # report gate: show MEDIUM and above
argus scan --fail-on critical     # exit-code gate: only CRITICAL fails CI
```

| Exit code | Meaning |
|---|---|
| `0` | No FAIL findings at or above `--fail-on` |
| `1` | FAIL findings at or above `--fail-on` |
| `2` | Scanner error |
| `3` | Usage or configuration error |

`WARN` and `MANUAL` never gate the exit code. `--exit-zero` forces `0` whenever the scan
completed.

### Output formats

`terminal` (default), `json`, `yaml`, `csv`, `markdown`, `html`, `sarif`.

`--format` is repeatable. With `--output DIR`, files are written as
`argus-report-<UTC timestamp>.<ext>`. More than one file format without `--output` is a
usage error.

```bash
argus scan --format json --format sarif --format html --output ./reports
```

---

## Custom rules (`.argus`)

Not every policy belongs in a shared benchmark. `.argus` rules let you express a
check without writing Python, in the spirit of a Nuclei template or a YARA rule.

```yaml
id: mcp-unpinned-npx
name: MCP server launched via npx with no version pin
severity: high
target: mcp

match:
  all:
    - field: command
      contains: npx
    - field: args
      not_regex: '@\d+\.\d+\.\d+'

remediation: Pin the package to an exact version.
tags: [mcp, supply-chain]
```

```bash
argus scan --rules ./rules              # a file or a directory, repeatable
argus scan --rules ./rules --rules-only # your rules alone, no built-in checks
argus rule validate ./rules             # schema-check without scanning
argus rule test ./rules                 # run only your rules, with full evidence
```

A rule has `id`, `name`, `severity`, `target` and `match`. The `match` block takes
exactly one combinator (`all`, `any` or `none`) over conditions. Each condition reads
either a `field` (a dotted path into the asset's parsed data) or `text` (the asset's
raw text), and applies exactly one operator: `contains`, `not_contains`, `equals`,
`regex`, `not_regex`, `exists` or `not_exists`. List fields match if any element
matches, so `field: args` works on an argument vector.

Unlike the benchmark checks, rules are yours — but they behave identically once
loaded. Rule findings are deterministic, so they **count toward the score and gate
the exit code** like any built-in check, and they obey the same selection flags:
`--category`, `--target`, `--check CUSTOM-<ID>` and `--exclude CUSTOM-<ID>`.

An optional `category:` field decides where findings are filed. It defaults to the
category matching the `target`, so a `target: skills` rule shows up under
`--category skills` next to the built-in `SKILL-*` checks with no extra work. Set it
explicitly to file elsewhere (`category: secrets`), or use `category: custom` to keep
your rules out of the built-in domains so `--category custom` returns only yours.

Validation is strict and unknown keys are rejected, because `severty: high` would
otherwise leave a rule quietly at its default severity forever. One malformed rule is
reported and skipped; it never stops the others. Full reference in
[`docs/rules.md`](docs/rules.md), runnable examples in
[`examples/rules/`](examples/rules).

### Writing rules with AI

```bash
export OPENAI_API_KEY=...    # or ANTHROPIC_/MOONSHOT_/DEEPSEEK_API_KEY
argus rule new "flag MCP servers that pass a credential path as an argument" \
    --output ./rules/mcp-creds.argus
```

Providers: `openai`, `anthropic`, `moonshot` (Kimi), `deepseek`. No extra
dependencies — all four are reached over the standard library.

**What gets sent is your prompt and the rule schema. Nothing else.** No scanned
configuration, no file contents, no paths, no hostname; you can run it without having
scanned anything. Argus prints the provider and its processing jurisdiction before
sending, and Moonshot and DeepSeek are PRC-hosted.

The model writes a **rule**, not a verdict. Its output is data you read, edit and
commit, and it is validated against the schema before being written, so a bad
generation is a clear error rather than a rule that silently matches nothing. Review
what it produces — `argus rule test` exists for exactly that — and treat it as a
first draft.

## Configuration

`argus.yaml` in the project root, or `--config PATH`. Precedence is
**CLI flag > argus.yaml > built-in default**.

```yaml
scan:
  include: [claude-code, claude-desktop, mcp, skills, plugins, hooks, instructions]
  exclude: [CLAUDE-005]
  level: 2

severity_threshold: high      # exit-code gate; same as --fail-on

scoring:
  weights: { CRITICAL: 25, HIGH: 10, MEDIUM: 3, LOW: 1, INFO: 0 }
  score_accepted_risk: false

report:
  formats: [terminal, html, json, sarif]
  output: ./reports

exceptions:
  - check_id: MCP-003
    asset: mcp:filesystem
    reason: "Required for internal development environment"
    expires: "2027-01-01"
```

### Accepted risk

An exception suppresses **gating**, never **visibility**. An accepted finding:

- displays as `FAIL — ACCEPTED RISK`
- deducts 0 from the score (override with `scoring.score_accepted_risk: true`)
- does not trip the exit code
- is still counted and listed in every report

An **expired** exception is not honoured: the finding reverts to a normal `FAIL` and the
expiry is reported in scan metadata.

---

## Scoring

The score is a weighted deduction from 100, and every deduction appears in the report so
it can be recomputed by hand:

```
deduction = weight[severity] × status_multiplier × confidence_multiplier

weight:      CRITICAL 25  HIGH 10  MEDIUM 3  LOW 1  INFO 0
status:      FAIL 1.0     WARN 0.5   others 0.0
confidence:  HIGH 1.0     MEDIUM 0.8  LOW 0.5

score = round(max(0, 100 − Σ deductions))
```

`MANUAL`, `NOT_APPLICABLE` and `ERROR` never deduct — an unevaluated control is not a
passing control, and is reported separately rather than folded into the score. Grades:
A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

Full derivation in [`docs/scoring.md`](docs/scoring.md).

---

## False positives

A false positive and an accepted risk are different claims, so Argus keeps them
apart. `exceptions:` in `argus.yaml` says *this finding is real and we are living
with it* — it stays fully visible and only stops gating. Triage says *the scanner
was wrong* — it stops counting.

```bash
argus scan -f json -o ./reports                       # produce a report
argus triage add MCP-013 --report ./reports/argus-report-*.json \
      --reason "payload string in our own scanner's docs"
argus triage list                                     # what is suppressed, and why
argus scan                                            # .argus-triage.yaml applies automatically
```

A reason is required; an entry without one is a load error, because an unexplained
hole in a report is worse than the finding it hides.

Two properties make this safe to use:

**Suppressed findings are never hidden.** They are counted in the summary, listed in
the findings, and labelled `FAIL — FALSE POSITIVE` with the reason given. How much of
a clean report rests on suppression is exactly what a reader needs to know.

**Suppression is per finding, not per check.** Entries match a fingerprint of the
finding's own evidence, so suppressing one hit never disables the check. Change the
matched text and the fingerprint changes with it: the finding reappears at full
severity and the stale entry is reported. Line numbers are excluded from the
fingerprint, so moving code does not churn the file.

---

## The benchmark

**AASB v1.0** — 71 static checks in 8 sections, plus 4 dynamic checks in section 10.
Check IDs are canonical; CIS-style numbers are derived (`CLAUDE-001` → AASB `1.1`).

| § | Section | Prefix | Checks | Run by |
|---|---|---|---|---|
| 1 | Claude Configuration | `CLAUDE-` | 10 | `scan` |
| 2 | MCP Security | `MCP-` | 20 | `scan` |
| 3 | Skills | `SKILL-` | 10 | `scan` |
| 4 | Plugins | `PLUGIN-` | 8 | `scan` |
| 5 | Hooks | `HOOK-` | 6 | `scan` |
| 6 | Instruction Files | `INSTR-` | 5 | `scan` |
| 7 | Secrets | `SECRET-` | 5 | `scan` |
| 8 | Filesystem | `FS-` | 7 | `scan` |
| 10 | Dynamic Analysis | `DYN-` | 4 | `dynamo` |

Section 10 is deliberately excluded from `argus scan`, so a static score stays
comparable across releases and is never mixed with observations from a probe.

**Level 1** — basic hygiene: concrete misconfigurations, low false-positive rate,
remediation that does not materially reduce usability.
**Level 2** — defense in depth: tightening that may constrain legitimate workflows, or
heuristic/contextual risk.

Reference: [`docs/checks.md`](docs/checks.md) and [`docs/benchmark.md`](docs/benchmark.md).

### MCP server code analysis

Section 2 audits more than `.mcp.json`. `MCP-013` … `MCP-019` resolve a server's
`command` and `args` to the code already installed on the machine — an interpreter's
entry point, `python -m` against the project venv, or a package spec against
`node_modules` — and audit what actually runs:

| Attack class | Check |
|---|---|
| Tool poisoning — instructions hidden in a tool description | `MCP-013` |
| Invisible payloads (Unicode tag block, zero-width, ANSI) | `MCP-014` |
| Tool shadowing and cross-server instructions | `MCP-015` |
| RCE — tool input reaching a shell or evaluator | `MCP-016` |
| Path traversal out of the intended directory | `MCP-017` |
| Unauthenticated exposure on every interface | `MCP-018` |
| Rug pull — definitions that change after approval | `MCP-019` |
| Hardcoded credentials in the server source | `MCP-020` |

A tool description is model-visible context rather than documentation, and every tool
parameter is attacker-reachable, so both are treated as untrusted. The command string is
parsed as data and **never executed** — Argus still never starts a server, which means
tool extraction is best-effort and a server it cannot locate reports `MANUAL` naming the
reason, never `PASS`. See [`docs/benchmark.md`](docs/benchmark.md#mcp-server-code-analysis).

---

## Dynamic analysis (`argus dynamo`)

Some attacks have no static signature. A rug-pull server's source is identical to a
server that composes its descriptions legitimately — the difference is that one of
them answers `tools/list` differently the second time. `MCP-019` can flag code that
*looks* capable of mutating a description; only running the server settles it.

```bash
argus dynamo --i-understand-this-executes-code
```

| Check | Finds | Why static analysis cannot |
|---|---|---|
| `DYN-001` | Tool description or schema changed after handshake | The source is the same in both states; only the two answers differ |
| `DYN-002` | Tools appeared or vanished mid-session | The inventory is produced at runtime |
| `DYN-003` | A planted credential was read and echoed back | Requires observing a real read |
| `DYN-004` | Injected instructions in tool *output* | The text does not exist until the tool is called |

**Containment.** Each server runs in its own unprivileged
[bubblewrap](https://github.com/containers/bubblewrap) namespace: host filesystem
read-only, your real home not mounted, network disabled, a fresh PID namespace that
dies with the parent. Fake credentials are planted at `~/.ssh/id_rsa`,
`~/.aws/credentials`, `~/.env` and `~/.claude/.credentials.json`; each carries a
random token, so a token coming back in tool output is proof of a read, not an
inference.

**Limits, stated plainly.** A kernel-level namespace escape is not defended against.
`--allow-network` means exfiltration *succeeds* rather than merely being attempted —
it exists for reproducing a finding, not for routine use. Servers launched by
`docker`, `npx` or `uvx` are skipped with a reason, because the sandbox will not nest
a container or fetch a package. And a dynamic check that finds nothing has watched
one execution with synthesised arguments, which is far weaker than a static check
that has read the whole file — so an unprobed server reports `MANUAL`, never `PASS`.

Requires `bubblewrap` (`apt install bubblewrap`). Without a working sandbox, dynamo
refuses to run rather than falling back to the host.

---

## Honest reporting

Argus is built to avoid the two failure modes that make security scanners useless:

- **It will not guess.** A control that cannot be determined from static evidence returns
  `MANUAL`, never an assumed `PASS`. Manual checks are reported separately and never
  improve the score.
- **It will not cry wolf.** Dangerous-command detection is tiered, so a bare `curl` is
  informational while `curl … | sh` fails. Prompt-injection matches inside code fences,
  blockquotes and labelled examples are downgraded, because security documentation
  legitimately quotes those phrases.
- **It will not assert intent.** Static analysis cannot establish motive. Findings say
  *"Potential prompt injection detected"*, never *"malicious"*.
- **It never prints a secret.** Detected credentials are redacted to `AKIA…XXXX` at the
  point of detection, in every output channel including JSON, SARIF and logs.

---

## CI/CD

SARIF output is suitable for GitHub Security:

```yaml
- run: argus scan --format sarif --output ./reports --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./reports
```

Only `FAIL` and `WARN` findings emit SARIF results — passing checks would flood the
Security tab. `MANUAL` findings emit as `note` with `kind: "review"`.

---

## Development

Linux / macOS:

```bash
.venv/bin/pytest              # tests
.venv/bin/ruff check argus    # lint
.venv/bin/mypy argus          # type check
```

Windows:

```powershell
.venv\Scripts\pytest              # tests
.venv\Scripts\ruff check argus    # lint
.venv\Scripts\mypy argus          # type check
```

All three must pass before a change is merged.

Adding a check never requires editing the engine — subclass `Check`, declare a
`CheckMeta`, and decorate with `@register`. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/architecture.md`](docs/architecture.md).

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — pipeline and module layout
- [`docs/benchmark.md`](docs/benchmark.md) — AASB structure, levels, numbering
- [`docs/checks.md`](docs/checks.md) — every check with rationale and remediation
- [`docs/scoring.md`](docs/scoring.md) — scoring algorithm
- [`docs/threat-model.md`](docs/threat-model.md) — what Argus defends against, and its limits
- [`SECURITY.md`](SECURITY.md) — reporting vulnerabilities in Argus itself

## License

MIT — see [`LICENSE`](LICENSE).
