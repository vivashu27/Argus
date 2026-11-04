# Changelog

All notable changes to Argus are recorded here. Versions follow
[Semantic Versioning](https://semver.org/).

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

[1.1.0]: https://github.com/vivashu27/Argus/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/vivashu27/Argus/releases/tag/v1.0.0
