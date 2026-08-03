# Custom `.argus` Rules

A `.argus` file expresses a check without writing Python — the same idea as a Nuclei
template or a YARA rule, applied to agent configuration.

## Why YAML and not a custom grammar

Rule files are input. A hand-written parser in a security tool is somewhere for a
parser bug to become a vulnerability, and `yaml.safe_load` — already the only loader
Argus uses — cannot construct Python objects. The `.argus` extension keeps rules
identifiable without inventing a grammar to maintain and fuzz.

Rules are **data, never code**. Nothing in a rule is executed, evaluated, or
interpolated into a shell. The only dynamic element is regular expressions, which
are compiled and validated at load time, length-capped, and applied to capped input.

## Schema

```yaml
id: mcp-unpinned-npx                 # required, 2-64 chars: a-z 0-9 . _ -
name: MCP server launched via npx with no version pin   # required
severity: high                       # required: critical | high | medium | low | info
target: mcp                          # required, see targets below
category: mcp                        # optional, defaults to the target's category
match:                               # required
  all:
    - field: command
      contains: npx
    - field: args
      not_regex: '@\d+\.\d+\.\d+'

description: >-                      # optional
  npx resolves the newest matching package at launch.
remediation: Pin the package to an exact version.       # optional
references: [https://example.com/advisory]              # optional
tags: [mcp, supply-chain]                               # optional
```

Unknown top-level keys are an error rather than being ignored. A typo such as
`severty: high` would otherwise leave the rule at its default severity forever, which
is exactly the kind of silent miscoverage a scanner should not have.

## Targets and their fields

`target` selects which discovered assets a rule sees. A `field` is a dotted path into
that asset's parsed data.

| Target | Fields |
|---|---|
| `mcp` | `name`, `command`, `args`, `env`, `url`, `transport`, `scope` |
| `skills` | `name`, `scope`, `directory`, `allowed_tools`, `body` |
| `plugins` | `name`, `marketplace`, `trust`, `directory`, `manifest` |
| `hooks` | `event`, `matcher`, `command`, `type`, `scope`, `script_text` |
| `claude-code` | `settings` (dotted, e.g. `settings.permissions.allow`), `scope` |
| `instructions` | `scope`, `name` |
| `filesystem` | `kind`, `mode`, `readable`, `category`, `description` |

Every target also supports `text`, which searches the asset's raw text rather than a
named field. Prefer a specific field where one exists — it is faster and far less
prone to matching something incidental.

## Categories

`target` decides which assets a rule *sees*. `category` decides where its findings are
*filed*, and therefore what `--category` matches. They are separate on purpose: a rule
with `target: skills` might be looking for secrets, not a Skills-hygiene problem.

If you omit `category`, it defaults to the category matching the target, so a
`target: skills` rule appears under `--category skills` alongside the built-in `SKILL-*`
checks. That is usually what you want and needs no extra field.

| Target | Default category |
|---|---|
| `skills` | `skills` |
| `mcp` | `mcp` |
| `hooks` | `hooks` |
| `plugins` | `plugins` |
| `instructions` | `instructions` |
| `filesystem` | `filesystem` |
| `claude-code`, `claude-desktop` | `claude` |
| `ide` | `custom` (no IDE category exists) |

Set it explicitly to override — `category: secrets` on a Skills rule files it with the
other secret findings — or `category: custom` to keep your rules out of the built-in
domains entirely, which is how you get `--category custom` to return just your own.

Rules obey the same selection flags as built-in checks: `--category`, `--target`,
`--check CUSTOM-<ID>` and `--exclude CUSTOM-<ID>`.

## Match blocks

Exactly one combinator per rule:

| Combinator | Fires when |
|---|---|
| `all` | every condition matches |
| `any` | at least one condition matches |
| `none` | no condition matches |

## Operators

Exactly one per condition.

| Operator | Meaning |
|---|---|
| `contains` | substring is present |
| `not_contains` | substring is absent |
| `equals` | exact match |
| `regex` | pattern matches |
| `not_regex` | pattern does not match |
| `exists` | the field is present |
| `not_exists` | the field is absent |

`contains`, `not_contains` and `equals` are case-insensitive by default; set
`ignore_case: false` on the condition for exact case. Regex operators take their
case-sensitivity from the same flag.

**List fields match if any element matches.** A condition on `field: args` tests every
argument, which is what you want when writing a rule about an argument vector. An
absent field satisfies negative operators and fails positive ones.

## How rule findings behave

Rules are deterministic, so their findings are real ones: they carry evidence, count
toward the score, and gate the exit code exactly like a built-in check. That is the
difference between a rule and an advisory signal, and the reason to write one.

Findings appear under check ID `CUSTOM-<RULE-ID>`, filed in whichever category the
rule declares (see above). In place of an AASB number they report their category
slug, because they are not benchmark items and a fabricated number would imply a
standing the rule does not have.

A rule that matches nothing across applicable assets reports `PASS`. A rule whose
target produced no assets reports `NOT_APPLICABLE` with the reason. A rule that
raises reports `ERROR` for that asset and the scan continues.

## Running rules

```bash
argus scan --rules ./rules                  # file or directory, repeatable
argus scan --rules a.argus --rules ./team   # combine sources
argus rule validate ./rules                 # schema check, no scan
argus rule test ./rules                     # run only rules, full evidence
```

Or persist them in `argus.yaml`:

```yaml
rules:
  - ./rules
  - ./team-policy.argus
```

Directories are searched to depth 4 for `*.argus` files. Duplicate rule IDs are
rejected with both file paths named. One malformed rule is reported and skipped —
it never stops the others from loading.

## Generating rules with AI

```bash
export OPENAI_API_KEY=...
argus rule new "flag MCP servers passing a credential path as an argument" \
    --output ./rules/mcp-creds.argus
```

Providers: `openai`, `anthropic`, `moonshot`, `deepseek`.

**Only your prompt and the rule schema are transmitted.** No scanned configuration,
file contents, paths or hostname — you can run this without having scanned anything.
The provider and its processing jurisdiction are printed before sending; Moonshot and
DeepSeek are PRC-hosted.

The model produces a rule, not a verdict. That distinction matters: its output is
data you read and commit rather than a judgement you have to trust, and it is
validated against the schema before being written, so a bad generation is an error
instead of a rule that silently never matches. The likely failure mode is a
plausible-looking rule that matches nothing, which is what `argus rule test` is for.

API keys are read from environment variables only. `llm.api_key` or similar in
`argus.yaml` is a hard error, because that file is one Argus itself scans.

## Worked example

Detect a Skill that can write to agent identity files, where injected instructions
would survive the Skill being removed:

```yaml
id: skill-writes-identity-file
name: Skill references an agent identity file
severity: critical
target: skills

match:
  any:
    - field: body
      regex: '(CLAUDE|AGENTS|MEMORY|SOUL)\.md'
    - field: allowed_tools
      contains: Write

description: >-
  Instructions written into an agent identity file are reloaded every session and
  survive removal of the Skill that wrote them.
remediation: Scope the Skill's write access away from identity files.
tags: [skills, persistence]
```

More in [`examples/rules/`](../examples/rules).
