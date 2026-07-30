# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Open a [GitHub security advisory](https://docs.github.com/en/code-security/security-advisories)
on the repository, or contact the maintainers directly.

Please include: affected version, a description of the issue, reproduction steps, and a
minimal proof-of-concept configuration if one applies. Synthetic credentials only — never
send real secrets in a report.

## Scope

Argus parses attacker-controlled input by design, so the following are **in scope** and
treated as vulnerabilities in Argus itself:

- **Code execution** triggered by scanning a crafted configuration, Skill, Plugin, hook,
  or instruction file
- **Path traversal or symlink escape** letting a scan read outside its permitted roots
- **Secret leakage** — any complete credential appearing in terminal output, a report in
  any format, or a log
- **Denial of service** from a crafted input: unbounded memory, catastrophic regex
  backtracking, or a non-terminating scan
- **Cross-site scripting** in the HTML report from scanned content
- **Unsafe deserialization**, including any path that reaches `yaml.load`, `pickle`, or
  `eval`

## Out of scope

- **False positives and false negatives in checks.** These are correctness bugs — please
  file them as normal issues with a sample configuration. They are taken seriously, but
  are not security vulnerabilities in Argus.
- **Findings Argus reports about your environment.** A `CRITICAL` finding is Argus working
  as intended. Fix the configuration it names.
- **Vulnerabilities in scanned software** — Claude Code, MCP servers, plugins. Report those
  to their maintainers.

## Security properties Argus guarantees

Argus is read-only and never executes what it scans. Specifically it does not:

- modify configuration, Skills, Plugins, hooks, or user files
- install software
- execute Skills, Plugins, MCP servers, or hooks
- run commands found in configuration or instruction files
- deserialize scanned content into executable objects

**Network access is the one conditional property.** By default Argus makes no network
requests at all. The optional `--llm` review stage is the sole exception: when
explicitly enabled it sends **redacted excerpts** of scanned configuration to the
provider you select. Secrets are redacted and the home path, username and hostname are
stripped before transmission. It is off unless you ask for it, and API keys are read
only from environment variables — never from `argus.yaml`, which Argus itself scans.

These properties are enforced by tests, notably
`tests/integration/test_pipeline.py::TestSafety`, which scans a deliberately malicious
environment and asserts that a canary file the fixture tries to create does not exist, and
that no synthetic credential reaches any output format.

A regression in any of these properties is a vulnerability. Please report it.

## Handling reports

Reports are acknowledged as soon as practical. Fixes for confirmed issues in the security
properties above are prioritised over feature work. Reporters are credited in the release
notes unless they prefer otherwise.

## Operational guidance

- **Run Argus as the user whose agent environment you are auditing.** Never as root — it
  reads whatever the invoking user can read, and elevating expands that unnecessarily.
- **Treat reports as sensitive.** They contain file paths, configuration keys, and
  redacted values. Review before attaching a SARIF file to a public repository.
- **Pin your dependencies.** Argus depends on `typer`, `rich`, and `PyYAML`; a compromise
  in any of those is a compromise of Argus.
