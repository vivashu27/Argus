# Changelog

All notable changes to Argus are recorded here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.3.0] — 2026-11-06

Gaps found by running NVIDIA SkillSpector's malicious test skills through Argus:
every one scored 100/100. Scores drop for Skills that have these problems.

### Added

- **SKILL-007** recognises HTTP calls made from Python or JavaScript (`requests`,
  `httpx`, `urllib`, `fetch`, `axios`), not only `curl` and `wget`.
- **SKILL-009** fails a bundled script that reads every environment variable and
  also sends data over the network. Copying the environment for a subprocess, or
  reading it with nothing sent anywhere, still passes.
- **Look-alike characters.** A word mixing Latin and Cyrillic letters (`reаd_data`)
  is reported by SKILL-003 and INSTR-004.

### Fixed

- **SKILL-003, 004 and 005 now scan the frontmatter.** Only the body after the YAML
  header was checked, so an injection in `description:`, `parameters:` or any other
  field went unreported, although every field is loaded into the model's context.
- **`review` sends the whole SKILL.md.** Only `name` and `description` were sent, so
  the model never saw the other frontmatter fields. Bundled scripts are now sent as
  their own sections, so a quote from one is cited at its real file and line.
- **`review` retries once on an unusable reply.** Models intermittently return
  malformed or empty JSON, and one bad reply marked every criterion MANUAL.

## [1.2.1] — 2026-11-05

### Fixed — a single downloaded Skill is found

- **`--path` may point at one Skill.** A folder with `SKILL.md` at its top (a skill
  repo you cloned) is now scanned as a Skill. Before, only `<path>/<name>/SKILL.md`
  was found, so a lone Skill gave "no agent assets were found".
- **`--path` may point at a file.** `--path ./skill/SKILL.md` scans the folder the
  file is in, for both `scan` and `review`.
- The "nothing found" message and the README list every place a Skill is looked for.

## [1.2.0] — 2026-11-04

### Fixed — each problem is reported and scored once

Findings were repeated in two ways, and every repeat also deducted from the score
again. Scores rise for any environment that had them.

- **One evidence entry per line.** A line matched by several patterns was listed once
  per pattern inside the same finding. Same-line entries now merge into one that
  keeps every reason. This applies to every check.
- **Overlapping checks are now disjoint.** Where two checks reported the same issue
  on the same line, the more specific check keeps it and the other defers:

  | Issue | Reported by | No longer by |
  |---|---|---|
  | Security-override and concealment directives | SKILL-004 / INSTR-003 | SKILL-003 / INSTR-004 |
  | Remote-instruction directives | SKILL-005 / INSTR-002 | SKILL-003 / INSTR-004 |
  | Reading a known credential path in Skill text | SKILL-002 | SKILL-003 |
  | Credential paths in bundled Skill scripts | SKILL-009 | SKILL-002 |
  | A literal `curl … \| sh` in a Skill | SKILL-008 | SKILL-005 |
  | The download in a hook's `curl … \| sh` | HOOK-003 | HOOK-005 |
  | Plugin hook files the HOOK checks evaluate | HOOK-003 | PLUGIN-002 |
  | Unscoped Bash, file and web tool grants | CLAUDE-002 / 003 / 005 | CLAUDE-007 |

  Each deferring check states this in its rationale (`argus info <ID>`,
  `docs/checks.md`). CLAUDE-007 still reports any dangerous tool no other check owns.

### Changed — action may be needed

- Triage entries for findings whose evidence changed are reported as stale, and the
  finding reappears once to be triaged again.
- Selecting a general check alone (for example `--check SKILL-003`) no longer shows
  matches its specific sibling owns, consistent with the existing precedence of
  MCP-006, SKILL-006, PLUGIN-005 and INSTR-001 over SECRET-*.

## [1.1.0] — 2026-11-04

### Security

- **`argus review` no longer sends private key material.** Only the
  `-----BEGIN … PRIVATE KEY-----` line was redacted; the key body below it was sent.
  Redaction now runs through the `-----END` line, or to the end of the payload if
  the block is truncated.
- **`argus review` no longer sends lines it could not scan.** The secret detector
  skips lines over 4000 characters, so a credential inside minified code passed both
  redaction and the fail-closed re-check. Such lines are now removed before sending.
- **MCP code resolution reads source files only.** A server whose arguments named an
  arbitrary file (for example `~/.kube/config`) had that file read as code and, under
  `argus review`, sent to the provider.
- **A scanned repository can no longer configure its own scan.** `argus.yaml` and
  `.argus-triage.yaml` are read from the current directory, never from `--path`.
  Previously a hostile repository could exclude checks, zero the score weights, or
  suppress its own findings.
- **Test-code detection looks only inside the server or plugin.** A project stored
  under a directory named `tests`, `spec` or similar had all its code skipped and
  reported a false PASS.

### Added

- `argus review --workers N` (`-w`) reviews components in parallel. Default 4,
  range 1–32; `--workers 1` restores sequential review.

### Fixed

- OpenAI requests use `max_completion_tokens`, which newer models require.
- Models that only accept their default temperature (OpenAI o-series, gpt-5) are
  retried once without `temperature`, and it is then omitted for the rest of the run.

### Performance

- Secret scanning is about 2× faster, and a full scan about 40% faster: the generic
  assignment regex no longer backtracks quadratically inside long tokens, and each
  pattern is checked once against the whole file before the per-line pass. Findings
  are unchanged.

### Changed — action may be needed

- If you ran `argus scan --path proj/` and relied on `proj/argus.yaml` or
  `proj/.argus-triage.yaml`, run Argus from `proj/` or pass `--config` / `--triage`.
- An MCP server launched through a script without a source extension now reports
  `MANUAL` instead of having that file analysed.

## [1.0.0]

Initial release: the AASB v1.0 benchmark, custom `.argus` rules, triage, LLM review,
and terminal, JSON, YAML, CSV, Markdown, HTML and SARIF reports.

[1.3.0]: https://github.com/vivashu27/Argus/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/vivashu27/Argus/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/vivashu27/Argus/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/vivashu27/Argus/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/vivashu27/Argus/releases/tag/v1.0.0
