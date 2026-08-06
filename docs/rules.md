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
| `mcp` | `name`, `command`, `args`, `env`, `url`, `transport`, `scope`, `tools`, `code` |
| `skills` | `name`, `scope`, `directory`, `allowed_tools`, `body` |
| `plugins` | `name`, `marketplace`, `trust`, `directory`, `manifest` |
| `hooks` | `event`, `matcher`, `command`, `type`, `scope`, `script_text` |
| `claude-code` | `settings` (dotted, e.g. `settings.permissions.allow`), `scope` |
| `instructions` | `scope`, `name` |
| `filesystem` | `kind`, `mode`, `readable`, `category`, `description` |

An MCP server also carries what Argus recovered from its implementation: `tools` is a
list of `{name, description, path, line}`, so `field: tools.description` matches every
recovered tool description, and `code` holds the resolution result (`root`, `resolved`,
`package_spec`, `unpinned`).

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

### Fields must exist on the target

`argus rule validate` warns when a rule reads a field its target does not provide,
and a scan reports it too. This is the most common way a rule goes quietly wrong:
the schema is valid, so nothing errors, and the rule simply never fires.

```
warn  my-rule   HIGH   target=hooks category=hooks
      field(s) body do not exist on target 'hooks', so this rule can never match.
      available: command, event, matcher, scope, script_path, script_text, timeout, type
```

Retargeting an existing rule is when this usually happens — a rule written against
`skills` and later pointed at `hooks` keeps validating while silently matching
nothing. Dotted paths are checked on their first segment, so
`settings.permissions.allow` validates against `settings`.

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

### Searching raw text

`text` has two forms, and the short one is usually what you want:

```yaml
- text: ignore previous instructions   # shorthand: raw text contains this

- text: true                           # explicit: any operator, on the raw text
  regex: 'ignore|disregard'
```

They do not combine. `text: "needle"` already names what to look for, so pairing it
with an operator is an error rather than one of the two values being quietly dropped.

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

### Line numbers in evidence

Evidence reports the line the rule matched on, in every format — `SKILL.md:10` in the
terminal and Markdown, `line` in JSON/YAML/CSV, and `region.startLine` in SARIF, so
GitHub Security annotates the right line. The snippet is a window centred on the match
rather than the head of the field, which matters once a rule fires deep in a long file.

**Matches inside a recovered record point at that record's file.** An MCP server's
`tools` are recovered from source, so a `field: tools.description` match reports the
`.py` or `.js` file and the line the text sits on — not the `.mcp.json` that merely
names the server. Records publish a per-field start line as `<field>_line`, so a
directive buried after a long `Args:` block resolves to its own line rather than to
the top of the function.

For everything else, a line is reported only where it is real. For Skills, instruction files and Claude
config, the scanned text is the file byte for byte, so an offset into it is an offset
into the file — including the frontmatter, so a `field: body` match still reports its
true line in `SKILL.md`. For **MCP servers, plugins and hooks** the scanned text is
synthesised: an MCP asset is re-serialised JSON, and a hook is its command joined to
its resolved script. An offset into a reconstruction points at nothing you can open —
your real `.mcp.json` may be minified onto one line — so those findings report no line
rather than a plausible wrong one. The `path` is always present.

Negative operators (`not_contains`, `not_regex`) match by absence, so there is no
match to point at; they report where the field itself begins.

## Running rules

```bash
argus scan --rules ./rules                  # every *.argus in the directory
argus scan --rules ./rules/one.argus        # a single rule file
argus scan --rules a.argus --rules ./team   # repeatable, sources combine
argus scan --rules ./rules --rules-only     # skip the built-in AASB checks
argus rule validate ./rules                 # schema check, no scan
argus rule test ./rules                     # run only rules, full evidence
```

`--rules` takes a file or a directory, so pointing at one template and pointing at a
tree of them are the same flag. Directories are searched to depth 4 for `*.argus`.

`--rules-only` suppresses the built-in checks and reports your rules alone — useful
when you are iterating on a rule and do not want 71 benchmark findings in the way, or
when a policy repo owns its own definition of a pass. Discovery still runs in full,
because rules match against discovered assets. The score is then computed over your
rules only, so an 80/100 from `--rules-only` is not comparable to an ordinary scan.
It is a usage error without `--rules`, since scanning nothing would otherwise print a
clean-looking result.

`argus rule test` is the same thing with evidence always shown, and it takes its rule
paths as arguments rather than as a flag.

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
instead of a rule that silently never matches.

If the first attempt fails validation, the validator's own message is handed back and
one correction is attempted. That covers the constraints no prompt fully conveys — the
regex length cap, the id pattern, which of the two `text` forms to use — at the cost of
a second call only when the first was already going to fail. Two failures report both
errors and write nothing.

**Still read what it writes.** Passing validation means the rule is well-formed, not
that it detects what you asked for. The likely failure mode is a plausible rule that
matches nothing — pointed at the wrong field, or with a regex that never fires. Run
`argus rule test` against something you know is bad and confirm it actually reports.

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
