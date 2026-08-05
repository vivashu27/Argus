# AASB v1.0 — Check Reference

> **Generated file.** Produced from the check registry by
> `python scripts/gen_checks_doc.py > docs/checks.md`. Do not edit by hand.

70 checks across 8 sections.

## Index

| ID | AASB | Level | Severity | Category | Title |
| --- | --- | :-: | --- | --- | --- |
| `CLAUDE-001` | 1.1 | 1 | HIGH | Claude Configuration | Dangerous permission configuration |
| `CLAUDE-002` | 1.2 | 1 | CRITICAL | Claude Configuration | Unrestricted Bash execution permitted |
| `CLAUDE-003` | 1.3 | 1 | HIGH | Claude Configuration | Unrestricted filesystem access permitted |
| `CLAUDE-004` | 1.4 | 2 | HIGH | Claude Configuration | Sensitive directories reachable by agent |
| `CLAUDE-005` | 1.5 | 2 | MEDIUM | Claude Configuration | Network access not sufficiently restricted |
| `CLAUDE-006` | 1.6 | 1 | CRITICAL | Claude Configuration | Permission prompts bypassed or sandbox disabled |
| `CLAUDE-007` | 1.7 | 2 | HIGH | Claude Configuration | Dangerous tools allowed without approval |
| `CLAUDE-008` | 1.8 | 2 | MEDIUM | Claude Configuration | Missing deny rules for sensitive operations |
| `CLAUDE-009` | 1.9 | 1 | HIGH | Claude Configuration | Claude Desktop permission bypass enabled |
| `CLAUDE-010` | 1.10 | 2 | MEDIUM | Claude Configuration | Project trust accepted for sensitive directories |
| `MCP-001` | 2.1 | 1 | HIGH | MCP Security | MCP server configured from an untrusted source |
| `MCP-002` | 2.2 | 1 | HIGH | MCP Security | MCP server command invokes a shell interpreter |
| `MCP-003` | 2.3 | 2 | HIGH | MCP Security | MCP server has unrestricted filesystem access |
| `MCP-004` | 2.4 | 1 | CRITICAL | MCP Security | MCP server granted access to sensitive directories |
| `MCP-005` | 2.5 | 2 | HIGH | MCP Security | MCP server has excessive declared permissions |
| `MCP-006` | 2.6 | 1 | CRITICAL | MCP Security | MCP configuration contains hardcoded secrets |
| `MCP-007` | 2.7 | 2 | HIGH | MCP Security | MCP server launched via shell string interpolation |
| `MCP-008` | 2.8 | 1 | HIGH | MCP Security | MCP server uses an insecure or suspicious remote endpoint |
| `MCP-009` | 2.9 | 2 | MEDIUM | MCP Security | MCP server configuration lacks integrity metadata |
| `MCP-010` | 2.10 | 2 | MEDIUM | MCP Security | MCP server exposes excessive tool capabilities |
| `MCP-011` | 2.11 | 2 | HIGH | MCP Security | MCP tool performs destructive operations without safeguards |
| `MCP-012` | 2.12 | 2 | MEDIUM | MCP Security | MCP server receives credentials via environment |
| `MCP-013` | 2.13 | 1 | CRITICAL | MCP Security | MCP tool description carries instructions aimed at the model |
| `MCP-014` | 2.14 | 1 | HIGH | MCP Security | MCP tool description contains non-rendering characters |
| `MCP-015` | 2.15 | 2 | HIGH | MCP Security | MCP tool name is claimed by more than one server, or targets another server |
| `MCP-016` | 2.16 | 1 | CRITICAL | MCP Security | MCP server passes tool input into a shell or evaluator |
| `MCP-017` | 2.17 | 2 | HIGH | MCP Security | MCP server builds filesystem paths from input without confining them |
| `MCP-018` | 2.18 | 2 | HIGH | MCP Security | MCP server binds to every network interface |
| `MCP-019` | 2.19 | 2 | MEDIUM | MCP Security | MCP tool definitions can change after the user approves them |
| `SKILL-001` | 3.1 | 1 | HIGH | Skills | Skill declares or scripts unrestricted shell execution |
| `SKILL-002` | 3.2 | 1 | HIGH | Skills | Skill accesses sensitive filesystem paths |
| `SKILL-003` | 3.3 | 1 | HIGH | Skills | Potential prompt injection in Skill content |
| `SKILL-004` | 3.4 | 1 | CRITICAL | Skills | Skill attempts to override security instructions |
| `SKILL-005` | 3.5 | 2 | HIGH | Skills | Skill references external untrusted instructions |
| `SKILL-006` | 3.6 | 1 | CRITICAL | Skills | Skill contains embedded secrets |
| `SKILL-007` | 3.7 | 2 | MEDIUM | Skills | Skill performs undeclared network access |
| `SKILL-008` | 3.8 | 1 | HIGH | Skills | Skill contains dangerous commands |
| `SKILL-009` | 3.9 | 1 | CRITICAL | Skills | Skill scripts access credential directories |
| `SKILL-010` | 3.10 | 2 | MEDIUM | Skills | Skill declares excessive tool privileges |
| `PLUGIN-001` | 4.1 | 1 | MEDIUM | Plugins | Plugin installed from an untrusted or unverified source |
| `PLUGIN-002` | 4.2 | 1 | HIGH | Plugins | Plugin registers dangerous hooks |
| `PLUGIN-003` | 4.3 | 2 | MEDIUM | Plugins | Plugin executes shell commands |
| `PLUGIN-004` | 4.4 | 1 | HIGH | Plugins | Plugin accesses sensitive filesystem paths |
| `PLUGIN-005` | 4.5 | 1 | CRITICAL | Plugins | Plugin contains embedded credentials |
| `PLUGIN-006` | 4.6 | 1 | HIGH | Plugins | Plugin references suspicious external URLs |
| `PLUGIN-007` | 4.7 | 2 | HIGH | Plugins | Plugin declares untrusted MCP dependencies |
| `PLUGIN-008` | 4.8 | 2 | MEDIUM | Plugins | Plugin declares excessive privileges |
| `HOOK-001` | 5.1 | 1 | CRITICAL | Hooks | Hook interpolates unvalidated agent-controlled input into a shell command |
| `HOOK-002` | 5.2 | 2 | MEDIUM | Hooks | Hook registered with an overly broad matcher |
| `HOOK-003` | 5.3 | 1 | CRITICAL | Hooks | Hook executes a dangerous command |
| `HOOK-004` | 5.4 | 1 | CRITICAL | Hooks | Hook reads or writes sensitive files |
| `HOOK-005` | 5.5 | 2 | HIGH | Hooks | Hook performs network communication |
| `HOOK-006` | 5.6 | 1 | HIGH | Hooks | Hook contains obfuscated or encoded code |
| `INSTR-001` | 6.1 | 1 | CRITICAL | Instruction Files | Secrets in instruction files |
| `INSTR-002` | 6.2 | 1 | HIGH | Instruction Files | Instructions sourced from an external location |
| `INSTR-003` | 6.3 | 1 | HIGH | Instruction Files | Instructions granting unrestricted command execution |
| `INSTR-004` | 6.4 | 1 | HIGH | Instruction Files | Potential prompt injection in instruction file |
| `INSTR-005` | 6.5 | 2 | MEDIUM | Instruction Files | Instruction file references untrusted URLs |
| `SECRET-001` | 7.1 | 1 | CRITICAL | Secrets | API keys in agent configuration |
| `SECRET-002` | 7.2 | 1 | CRITICAL | Secrets | Cloud provider credentials exposed |
| `SECRET-003` | 7.3 | 1 | CRITICAL | Secrets | Private key material in agent-reachable configuration |
| `SECRET-004` | 7.4 | 1 | HIGH | Secrets | Authentication tokens exposed |
| `SECRET-005` | 7.5 | 2 | HIGH | Secrets | Plaintext credentials in configuration |
| `FS-001` | 8.1 | 1 | HIGH | Filesystem | Sensitive file reachable by agent |
| `FS-002` | 8.2 | 2 | HIGH | Filesystem | Credential directories reachable by agent |
| `FS-003` | 8.3 | 1 | CRITICAL | Filesystem | SSH private keys reachable by agent |
| `FS-004` | 8.4 | 1 | CRITICAL | Filesystem | Cloud credential files reachable by agent |
| `FS-005` | 8.5 | 1 | HIGH | Filesystem | Unsafe permissions on agent configuration file |
| `FS-006` | 8.6 | 2 | MEDIUM | Filesystem | Symlink escapes the workspace |
| `FS-007` | 8.7 | 1 | CRITICAL | Filesystem | World-writable agent configuration |

## Levels

**Level 1 — Basic security hygiene** — Detects a concrete misconfiguration with a low false-positive rate, where the remediation does not materially reduce usability. Suitable as a minimum baseline for any agent environment.

**Level 2 — Defense in depth** — Requires tightening that may constrain legitimate workflows, or detects a heuristic or contextual risk. Intended for environments handling sensitive data or operating with elevated privilege.


---

## 1. Claude Configuration

10 checks — 5 at Level 1, 5 at Level 2.

### CLAUDE-001 — Dangerous permission configuration

**AASB 1.1** · Level 1 · **HIGH** · applies to: claude-code

Claude Code settings define no permission ruleset, or set a default mode that grants tool use without review.

**Detection rationale.** With no allow/deny/ask rules, tool authorisation falls back to interactive prompting only. A permissive defaultMode removes even that, so any prompt injection that reaches the agent inherits the operator's full tool access.

**Security impact.** An attacker who can influence agent context — through a poisoned instruction file, a hostile repository, or injected tool output — can invoke tools without an approval gate.

**Remediation.** Define an explicit permissions block in ~/.claude/settings.json with a deny list for credential paths and destructive commands, and leave defaultMode at its interactive default.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-1188: Initialization of a Resource with an Insecure Default; MITRE ATLAS: AML.T0051: LLM Prompt Injection

**References.** https://docs.anthropic.com/en/docs/claude-code/settings, https://owasp.org/www-project-top-10-for-large-language-model-applications/

### CLAUDE-002 — Unrestricted Bash execution permitted

**AASB 1.2** · Level 1 · **CRITICAL** · applies to: claude-code

An allow rule grants the Bash tool with no command constraint.

**Detection rationale.** 'Bash' or 'Bash(*)' in the allow list pre-authorises every shell command. Argument-scoped rules such as 'Bash(git status:*)' do not carry this risk.

**Security impact.** Unrestricted shell access is full local code execution under the operator's account. It is the highest-value target for prompt injection against an agent.

**Remediation.** Replace the blanket grant with argument-scoped rules, e.g. 'Bash(git status:*)', and add deny rules for destructive commands.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command; MITRE ATLAS: AML.T0051: LLM Prompt Injection

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### CLAUDE-003 — Unrestricted filesystem access permitted

**AASB 1.3** · Level 1 · **HIGH** · applies to: claude-code

File tools are granted without path constraints, or an additional working directory is rooted at / or the home directory.

**Detection rationale.** Write and Edit grants without a path scope let the agent modify any file the user can, including shell profiles and the agent's own configuration.

**Security impact.** Enables persistence (writing to shell rc files), self-modification of agent permissions, and tampering with unrelated projects on the same machine.

**Remediation.** Scope file tool grants to the project directory, e.g. 'Edit(./src/**)', and avoid adding '/' or '~' to additionalDirectories.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-732: Incorrect Permission Assignment for Critical Resource

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### CLAUDE-004 — Sensitive directories reachable by agent

**AASB 1.4** · Level 2 · **HIGH** · applies to: claude-code

Credential directories that exist on this host are not covered by any deny rule in the effective permission ruleset.

**Detection rationale.** Argus only reports credential locations that actually exist and are readable by the current user, so this reflects real exposure rather than a hypothetical.

**Security impact.** A prompt injection that reaches a file-reading tool can retrieve SSH keys, cloud credentials, or agent OAuth tokens and exfiltrate them through any permitted network tool.

**Remediation.** Add deny rules covering credential paths, for example Read(~/.ssh/**), Read(~/.aws/**), Read(**/.env).

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### CLAUDE-005 — Network access not sufficiently restricted

**AASB 1.5** · Level 2 · **MEDIUM** · applies to: claude-code

Network-capable tools are allowed without a domain allowlist.

**Detection rationale.** An unconstrained WebFetch grant provides an outbound channel to any host. Exfiltration requires both read access and an egress path; this check covers the egress half.

**Security impact.** Data read by the agent can be sent to an attacker-controlled endpoint, and remote content can be pulled into context to drive further injection.

**Remediation.** Constrain network tools to specific domains, e.g. 'WebFetch(domain:docs.anthropic.com)', and deny the rest.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### CLAUDE-006 — Permission prompts bypassed or sandbox disabled

**AASB 1.6** · Level 1 · **CRITICAL** · applies to: claude-code

Settings disable the interactive approval gate or opt out of sandboxing.

**Detection rationale.** The approval prompt is the last human control between an injected instruction and a privileged action. Disabling it removes the only interactive defence.

**Security impact.** Every other permission weakness becomes directly exploitable, because no human sees the tool call before it runs.

**Remediation.** Remove skipDangerousModePermissionPrompt / dangerouslySkipPermissions from settings, and keep sandboxing enabled.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-250: Execution with Unnecessary Privileges; MITRE ATLAS: AML.T0054: LLM Jailbreak

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### CLAUDE-007 — Dangerous tools allowed without approval

**AASB 1.7** · Level 2 · **HIGH** · applies to: claude-code

High-impact tools are pre-authorised in the allow list with no corresponding ask rule requiring confirmation.

**Detection rationale.** An allow rule silences the approval prompt for that tool. Where the tool can execute code or write files, that removes the human review step entirely.

**Security impact.** Injected instructions can reach destructive tooling without the operator observing the call.

**Remediation.** Move high-impact tools from 'allow' to 'ask' so each invocation is confirmed, or scope the allow rule to specific safe arguments.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-269: Improper Privilege Management

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### CLAUDE-008 — Missing deny rules for sensitive operations

**AASB 1.8** · Level 2 · **MEDIUM** · applies to: claude-code

The permission ruleset contains no deny entries covering credential paths or destructive commands.

**Detection rationale.** Deny rules are evaluated ahead of allow rules, so they are the only construct that holds regardless of what a future allow rule permits.

**Security impact.** Without explicit denials, broadening an allow rule later silently re-exposes credential paths.

**Remediation.** Add deny rules for credential reads and destructive shell commands, e.g. Read(~/.ssh/**), Read(**/.env), Bash(curl:*), Bash(rm -rf:*).

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-693: Protection Mechanism Failure

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### CLAUDE-009 — Claude Desktop permission bypass enabled

**AASB 1.9** · Level 1 · **HIGH** · applies to: claude-desktop

Claude Desktop preferences opt an account into bypassing permission prompts or enable developer mode.

**Detection rationale.** Claude Desktop stores per-account opt-ins for permission bypass. When set, local tool and MCP invocations proceed without interactive confirmation.

**Security impact.** Every MCP server configured in Claude Desktop can be driven without an approval step, including servers that execute local commands.

**Remediation.** Disable permission bypass in Claude Desktop settings and re-enable prompting for local tool execution.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-250: Execution with Unnecessary Privileges

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### CLAUDE-010 — Project trust accepted for sensitive directories

**AASB 1.10** · Level 2 · **MEDIUM** · applies to: claude-code

Claude Code has recorded trust for directories that sit at a filesystem root, a home directory, or a known credential location.

**Detection rationale.** Trusting a directory enables project-scoped configuration — including .mcp.json and CLAUDE.md — to take effect without further prompting. Trust granted at a home or root directory extends that to everything beneath it.

**Security impact.** Any file dropped into a broadly-trusted directory can silently supply agent configuration or instructions.

**Remediation.** Trust individual project directories rather than home or root, and review recorded trust in ~/.claude.json.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; CWE: CWE-829: Inclusion of Functionality from Untrusted Control Sphere

**References.** https://docs.anthropic.com/en/docs/claude-code/settings


---

## 2. MCP Security

19 checks — 8 at Level 1, 11 at Level 2.

### MCP-001 — MCP server configured from an untrusted source

**AASB 2.1** · Level 1 · **HIGH** · applies to: mcp

The server is launched through a package runner that fetches code at start time, or from a remote endpoint that is not a recognised registry.

**Detection rationale.** A runner such as npx or uvx resolves and executes the newest matching package on every launch. The code reviewed at configuration time is not necessarily the code that runs later.

**Security impact.** A compromised or typosquatted package executes with the user's privileges and inherits every capability the agent grants the server.

**Remediation.** Pin the package to an exact version and integrity hash, or vendor the server locally and launch it from a fixed path.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM03: Supply Chain; CWE: CWE-494: Download of Code Without Integrity Check; MITRE ATLAS: AML.T0010: ML Supply Chain Compromise

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-002 — MCP server command invokes a shell interpreter

**AASB 2.2** · Level 1 · **HIGH** · applies to: mcp

The configured command is itself a shell rather than a program.

**Detection rationale.** When the command is sh, bash, cmd or powershell, the arguments are a script rather than an argv vector, so shell parsing applies to everything after it.

**Security impact.** Any value interpolated into that script — including agent-supplied data — is parsed as shell syntax, producing command injection.

**Remediation.** Invoke the server binary directly and pass parameters as separate argv entries instead of a shell string.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-003 — MCP server has unrestricted filesystem access

**AASB 2.3** · Level 2 · **HIGH** · applies to: mcp

A path argument grants the server the filesystem root or the whole home directory.

**Detection rationale.** Filesystem-style MCP servers take their permitted roots as arguments. A root of '/' or '~' means every file the launching user can read is exposed to the agent through the server's tools.

**Security impact.** The server becomes a general-purpose file read/write primitive reachable by prompt injection, bypassing Claude's own path-scoped permission rules.

**Remediation.** Pass only the specific project directories the server needs.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-732: Incorrect Permission Assignment for Critical Resource

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-004 — MCP server granted access to sensitive directories

**AASB 2.4** · Level 1 · **CRITICAL** · applies to: mcp

A path argument or environment value points at a known credential location.

**Detection rationale.** Unlike MCP-003 this is not about breadth — it is a direct grant over a location whose only contents are credentials.

**Security impact.** Private keys and cloud credentials become readable through an agent tool call, enabling lateral movement well beyond the local machine.

**Remediation.** Remove the credential path from the server's configuration.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-005 — MCP server has excessive declared permissions

**AASB 2.5** · Level 2 · **HIGH** · applies to: mcp

The server declares broad capability scopes, or is configured to run with elevated privileges.

**Detection rationale.** Where a server declares scopes or is wrapped in sudo, the declared privilege level is visible statically and can be compared against least privilege.

**Security impact.** A server running with elevated privilege converts any injection reaching it into privileged code execution.

**Remediation.** Run the server unprivileged and narrow declared scopes to what is used.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-250: Execution with Unnecessary Privileges

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-006 — MCP configuration contains hardcoded secrets

**AASB 2.6** · Level 1 · **CRITICAL** · applies to: mcp

A credential literal appears in the server's configuration block.

**Detection rationale.** MCP configuration files are frequently committed to repositories and synced between machines, so a literal credential there has a wide blast radius. This check takes precedence over the generic SECRET-* family for MCP assets.

**Security impact.** The credential is exposed to anyone with read access to the config file.

**Remediation.** Move the value to an environment variable or secret manager, reference it indirectly, and rotate the exposed credential.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-798: Use of Hard-coded Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-007 — MCP server launched via shell string interpolation

**AASB 2.7** · Level 2 · **HIGH** · applies to: mcp

Server arguments contain shell metacharacters, implying the command line is assembled as a string rather than an argv vector.

**Detection rationale.** Distinct from MCP-002: there the command itself is a shell; here the command is a normal program but its arguments carry pipes, redirects, or command substitution that only a shell would interpret.

**Security impact.** Introduces a command injection point at server launch.

**Remediation.** Pass arguments as discrete argv entries with no shell metacharacters.

**Compliance mapping.** CWE: CWE-77: Improper Neutralization of Special Elements used in a Command; OWASP LLM Top 10 2025: LLM06: Excessive Agency

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-008 — MCP server uses an insecure or suspicious remote endpoint

**AASB 2.8** · Level 1 · **HIGH** · applies to: mcp

A remote server URL uses plaintext HTTP or a disposable-hosting domain.

**Detection rationale.** Traffic to a remote MCP server carries tool arguments and results, which routinely include file contents and credentials.

**Security impact.** Plaintext transport exposes that traffic to interception and modification; tunnelling and paste-style hosts indicate an endpoint that can change owner without notice.

**Remediation.** Use HTTPS endpoints on domains your organisation controls or has vetted.

**Compliance mapping.** CWE: CWE-319: Cleartext Transmission of Sensitive Information; OWASP LLM Top 10 2025: LLM03: Supply Chain

**References.** https://modelcontextprotocol.io/docs/concepts/transports

### MCP-009 — MCP server configuration lacks integrity metadata

**AASB 2.9** · Level 2 · **MEDIUM** · applies to: mcp

No version pin, checksum, or lockfile reference constrains what the server runs.

**Detection rationale.** Without a version pin or hash, the artifact executed today may differ from the one reviewed, and nothing in the configuration would reveal the change.

**Security impact.** Silent substitution of server code between launches goes undetected.

**Remediation.** Pin exact versions, record integrity hashes, and commit a lockfile.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM03: Supply Chain; CWE: CWE-494: Download of Code Without Integrity Check

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-010 — MCP server exposes excessive tool capabilities

**AASB 2.10** · Level 2 · **MEDIUM** · applies to: mcp

The server declares a large or unbounded set of tools.

**Detection rationale.** The tool list a server exposes is only fully known after a handshake, which Argus will not perform. Where a manifest declares tools statically it is evaluated; otherwise the result is MANUAL rather than a guess.

**Security impact.** Every exposed tool is reachable by prompt injection, so unused tools are unnecessary attack surface.

**Remediation.** Expose only the tools in active use and disable the remainder.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-1059: Insufficient Technical Documentation

**References.** https://modelcontextprotocol.io/docs/concepts/tools

### MCP-011 — MCP tool performs destructive operations without safeguards

**AASB 2.11** · Level 2 · **HIGH** · applies to: mcp

Configuration or manifest text indicates destructive capability with no confirmation gate.

**Detection rationale.** Whether a tool is destructive is a property of its implementation, not its configuration. Argus reports MANUAL unless the configuration itself carries dangerous command patterns.

**Security impact.** Irreversible operations can be triggered by injected instructions.

**Remediation.** Require explicit confirmation for destructive tools and run the server against a restricted scope.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-732: Incorrect Permission Assignment for Critical Resource

**References.** https://modelcontextprotocol.io/docs/concepts/tools

### MCP-012 — MCP server receives credentials via environment

**AASB 2.12** · Level 2 · **MEDIUM** · applies to: mcp

The server's env block passes credential-shaped values to the subprocess.

**Detection rationale.** Environment variables are inherited by every child process the server spawns and are readable from process listings on some platforms. Indirect references such as ${VAR} are the recommended pattern and are not flagged.

**Security impact.** A credential passed literally in the environment is exposed to the server's entire process tree and to anything that can read the config file.

**Remediation.** Reference secrets indirectly (${VAR}) and resolve them from a secret manager at launch, scoped to the minimum needed.

**Compliance mapping.** CWE: CWE-214: Invocation of Process Using Visible Sensitive Information; OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### MCP-013 — MCP tool description carries instructions aimed at the model

**AASB 2.13** · Level 1 · **CRITICAL** · applies to: mcp

A tool description contains directives to the assistant rather than a description of the tool — concealment instructions, instruction overrides, or a required read of a credential path.

**Detection rationale.** Tool descriptions are supplied to the model as context, with the standing of the tool list itself. A user approving a server sees a sentence about what the tool does; the model sees whatever else was written there. Detection is tiered: a concealment directive or instruction override is reported on sight, while a description that merely names a credential path needs corroboration.

**Security impact.** The server steers the assistant into reading secrets, routing data to an attacker-controlled parameter, or hiding the action from the user — without exploiting any code, and without the user seeing the instruction.

**Remediation.** Remove the directive text from the description. Treat any server whose descriptions address the assistant as untrusted and disconnect it, then review what the assistant did while it was connected.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; OWASP Agentic AI Threats and Mitigations v1.0: T2: Tool Misuse; MITRE ATLAS: AML.T0051: LLM Prompt Injection; CWE: CWE-77: Improper Neutralization of Special Elements used in a Command

**References.** https://owasp.org/www-project-agentic-skills-top-10/, https://modelcontextprotocol.io/docs/concepts/tools

### MCP-014 — MCP tool description contains non-rendering characters

**AASB 2.14** · Level 1 · **HIGH** · applies to: mcp

A tool description contains zero-width, Unicode tag, bidirectional or ANSI escape characters, which reach the model but not a human reviewer.

**Detection rationale.** The Unicode tag block U+E0000-U+E007F mirrors ASCII, so a complete instruction can be written in characters that no terminal or approval dialog displays. A description that reads as innocuous can therefore carry a payload the reviewer cannot see at all. There is no legitimate reason for a tool description to contain them.

**Security impact.** An instruction invisible to every human review path is delivered to the model verbatim, defeating description review as a control.

**Remediation.** Reject the server. A description containing invisible characters is not a formatting mistake.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; CWE: CWE-176: Improper Handling of Unicode Encoding

**References.** https://modelcontextprotocol.io/docs/concepts/tools

### MCP-015 — MCP tool name is claimed by more than one server, or targets another server

**AASB 2.15** · Level 2 · **HIGH** · applies to: mcp

Two connected servers expose the same tool name, or a description refers to another server's tools and modifies how they should be called.

**Detection rationale.** The model sees one flat tool list assembled from every connected server, and nothing in the protocol binds a name to an origin. A colliding name makes tool selection ambiguous; a description that redefines another server's tool turns one untrusted server into control over a trusted one.

**Security impact.** Calls intended for a trusted server are answered by an untrusted one, or a trusted tool is invoked with attacker-chosen parameters such as an added recipient on an outbound message.

**Remediation.** Give colliding tools distinct names, or connect only one of the servers. Investigate any server whose descriptions mention another server's tools.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; OWASP Agentic AI Threats and Mitigations v1.0: T2: Tool Misuse; CWE: CWE-1021: Improper Restriction of Rendered UI Layers

**References.** https://modelcontextprotocol.io/docs/concepts/tools

### MCP-016 — MCP server passes tool input into a shell or evaluator

**AASB 2.16** · Level 1 · **CRITICAL** · applies to: mcp

Server code builds a shell command or evaluated expression from interpolated input reachable through a tool parameter.

**Detection rationale.** Every tool parameter is attacker-reachable: the model chooses the value, and the model can be steered by injected text in any document it reads. A shell sink with an interpolated argument is therefore remote code execution reachable from content, not just from a malicious user. Constant arguments and the argument-vector form of subprocess are not reported.

**Security impact.** Code execution as the user running the agent, from any content the model can be induced to read.

**Remediation.** Pass an argument vector instead of a command string — subprocess without shell=True, or execFile in place of exec — and validate parameters against an allow-list. Never evaluate a parameter as code.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM05: Improper Output Handling; OWASP Agentic AI Threats and Mitigations v1.0: T2: Tool Misuse; MITRE ATLAS: AML.T0053: LLM Plugin Compromise; CWE: CWE-78: OS Command Injection

**References.** https://cwe.mitre.org/data/definitions/78.html, https://modelcontextprotocol.io/docs/concepts/tools

### MCP-017 — MCP server builds filesystem paths from input without confining them

**AASB 2.17** · Level 2 · **HIGH** · applies to: mcp

Server code opens or writes a path built from interpolated input, and contains no idiom that confines the result to an intended directory.

**Detection rationale.** A filesystem tool that joins a caller-supplied segment onto a base directory escapes that directory with '..' unless the joined result is resolved and checked. Any file containing a containment idiom — resolve, realpath, commonpath, a startswith check — is treated as having addressed this, so the check reports servers that never confine paths rather than every server that opens a file.

**Security impact.** A tool scoped to a project directory reads or writes anywhere the agent's user can, including SSH keys and cloud credentials.

**Remediation.** Resolve the joined path and verify it is still inside the intended root before opening it. Reject the request otherwise.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-22: Improper Limitation of a Pathname to a Restricted Directory

**References.** https://cwe.mitre.org/data/definitions/22.html

### MCP-018 — MCP server binds to every network interface

**AASB 2.18** · Level 2 · **HIGH** · applies to: mcp

Server code binds 0.0.0.0 or ::, exposing it beyond the local machine.

**Detection rationale.** MCP mandates no authentication. A server written for local stdio use that binds every interface is reachable by anyone who can route to the host, with the same tools the agent has. Whether the file shows any authentication at all decides the confidence of this finding.

**Security impact.** Anyone able to reach the port invokes the server's tools directly, with the privileges of the account running it.

**Remediation.** Bind 127.0.0.1 for local use. If remote access is required, put authentication in front of it and restrict the source range.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-306: Missing Authentication for Critical Function, CWE-668: Exposure of Resource to Wrong Sphere

**References.** https://modelcontextprotocol.io/docs/concepts/transports

### MCP-019 — MCP tool definitions can change after the user approves them

**AASB 2.19** · Level 2 · **MEDIUM** · applies to: mcp

The server resolves to a new version at every launch, or its code is writable by the current user, so approved tool definitions can change silently.

**Detection rationale.** A rug pull is a tool that behaves as described until trust is established, then changes. Approval happens once, against the definitions present that day. This reports the conditions that make such a change silent: an unpinned package fetched fresh at each launch, or server code the user's own account can rewrite. Detecting an actual change requires comparing against recorded definitions, which needs a pinned version to compare against in the first place.

**Security impact.** Tool descriptions and behaviour differ from what the user reviewed, with no prompt and no visible difference in configuration.

**Remediation.** Pin the server to an exact version and install it rather than fetching at launch. Re-review tool descriptions whenever that pin is raised.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM03: Supply Chain; OWASP Agentic AI Threats and Mitigations v1.0: T2: Tool Misuse; CWE: CWE-494: Download of Code Without Integrity Check

**References.** https://modelcontextprotocol.io/docs/concepts/tools


---

## 3. Skills

10 checks — 7 at Level 1, 3 at Level 2.

### SKILL-001 — Skill declares or scripts unrestricted shell execution

**AASB 3.1** · Level 1 · **HIGH** · applies to: skills

The Skill grants itself the Bash tool without argument scoping, or bundles a shell script.

**Detection rationale.** A Skill's allowed-tools frontmatter widens the agent's permissions while the Skill is active. An unscoped Bash grant there is equivalent to a global one for the duration.

**Security impact.** Any instruction that activates the Skill — including one injected into a document the agent reads — gains shell access.

**Remediation.** Scope the grant to specific commands, e.g. 'Bash(pytest:*)'.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command

**References.** https://docs.anthropic.com/en/docs/claude-code/skills

### SKILL-002 — Skill accesses sensitive filesystem paths

**AASB 3.2** · Level 1 · **HIGH** · applies to: skills

Skill text or a bundled script references a known credential location.

**Detection rationale.** A Skill referencing ~/.ssh or ~/.aws is directing the agent at credentials.

**Security impact.** Credentials can be read into context and then transmitted anywhere the agent can reach.

**Remediation.** Remove the credential path reference from the Skill.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/skills

### SKILL-003 — Potential prompt injection in Skill content

**AASB 3.3** · Level 1 · **HIGH** · applies to: skills

Skill text contains language that would function as an injected instruction.

**Detection rationale.** Skill bodies are loaded directly into the model's context. Static analysis cannot establish intent, so this reports potential injection only.

**Security impact.** An injected directive can redirect agent behaviour whenever the Skill activates.

**Remediation.** Review the flagged lines and remove any directive that overrides operator instructions.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; MITRE ATLAS: AML.T0051: LLM Prompt Injection; CWE: CWE-1427: Improper Neutralization of Input Used for LLM Prompting

**References.** https://owasp.org/www-project-top-10-for-large-language-model-applications/

### SKILL-004 — Skill attempts to override security instructions

**AASB 3.4** · Level 1 · **CRITICAL** · applies to: skills

Skill text instructs the agent to bypass permissions, approvals, or safety controls.

**Detection rationale.** This is the policy-subversion subset of injection patterns, separated because a Skill telling the agent to skip approvals is categorically different from general injection phrasing.

**Security impact.** Neutralises the operator's configured permission model.

**Remediation.** Remove the directive and review the Skill's provenance.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; MITRE ATLAS: AML.T0054: LLM Jailbreak

**References.** https://owasp.org/www-project-top-10-for-large-language-model-applications/

### SKILL-005 — Skill references external untrusted instructions

**AASB 3.5** · Level 2 · **HIGH** · applies to: skills

The Skill directs the agent to load instructions or content from a remote URL.

**Detection rationale.** Instructions fetched at runtime are not covered by any review of the Skill itself, and the remote content can change after approval.

**Security impact.** Provides a channel for delivering new instructions post-review.

**Remediation.** Vendor required content into the Skill directory and pin it.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; CWE: CWE-829: Inclusion of Functionality from Untrusted Control Sphere

**References.** https://docs.anthropic.com/en/docs/claude-code/skills

### SKILL-006 — Skill contains embedded secrets

**AASB 3.6** · Level 1 · **CRITICAL** · applies to: skills

A credential literal appears in the Skill body or a bundled script.

**Detection rationale.** Skills are shared and version-controlled, so an embedded credential travels with every copy. Takes precedence over SECRET-* for Skill assets.

**Security impact.** The credential is exposed to everyone with access to the Skill.

**Remediation.** Remove the literal, read it from the environment instead, and rotate it.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-798: Use of Hard-coded Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/skills

### SKILL-007 — Skill performs undeclared network access

**AASB 3.7** · Level 2 · **MEDIUM** · applies to: skills

Skill scripts make outbound network calls not reflected in allowed-tools.

**Detection rationale.** Network access inside a bundled script bypasses the tool-permission model entirely, since the script runs as a subprocess rather than as a tool call.

**Security impact.** Creates an egress path invisible to the agent's permission configuration.

**Remediation.** Declare network use explicitly and route it through permission-gated tools.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

**References.** https://docs.anthropic.com/en/docs/claude-code/skills

### SKILL-008 — Skill contains dangerous commands

**AASB 3.8** · Level 1 · **HIGH** · applies to: skills

Skill text or scripts contain commands classified as dangerous.

**Detection rationale.** Tiered detection: Tier A patterns are dangerous in any context and fail outright; Tier B patterns fail only when combined with a credential path, remote endpoint, or interpolated input.

**Security impact.** Skill activation can trigger destructive or remote-code-execution behaviour.

**Remediation.** Remove the command or replace it with a scoped, non-destructive equivalent.

**Compliance mapping.** CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command; OWASP LLM Top 10 2025: LLM06: Excessive Agency

**References.** https://docs.anthropic.com/en/docs/claude-code/skills

### SKILL-009 — Skill scripts access credential directories

**AASB 3.9** · Level 1 · **CRITICAL** · applies to: skills

A bundled script reads from a credential directory at execution time.

**Detection rationale.** SKILL-002 covers references anywhere in the Skill; this narrows to executable scripts, where the access is an action rather than a mention.

**Security impact.** Credentials are read by a subprocess outside the tool permission model.

**Remediation.** Remove credential access from bundled scripts.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; MITRE ATLAS: AML.T0055: Unsecured Credentials; CWE: CWE-522: Insufficiently Protected Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/skills

### SKILL-010 — Skill declares excessive tool privileges

**AASB 3.10** · Level 2 · **MEDIUM** · applies to: skills

The Skill's allowed-tools list is unbounded or unusually broad.

**Detection rationale.** Distinct from SKILL-001, which is specifically about shell access: this measures the overall breadth of the grant.

**Security impact.** Broad grants widen what an injection activating the Skill can reach.

**Remediation.** Declare only the tools the Skill actually uses.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-269: Improper Privilege Management

**References.** https://docs.anthropic.com/en/docs/claude-code/skills


---

## 4. Plugins

8 checks — 5 at Level 1, 3 at Level 2.

### PLUGIN-001 — Plugin installed from an untrusted or unverified source

**AASB 4.1** · Level 1 · **MEDIUM** · applies to: plugins

The plugin's marketplace is not first-party and is not recorded in known_marketplaces.json.

**Detection rationale.** Provenance is a statement about who can change the code, not about whether the code is malicious. An unverified marketplace can push an update at any time with no review gate.

**Security impact.** Plugins contribute hooks, commands, agents, and MCP servers to the agent, so an update from an unvetted source changes agent behaviour directly.

**Remediation.** Install plugins from marketplaces your organisation has reviewed and pinned.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM03: Supply Chain; CWE: CWE-829: Inclusion of Functionality from Untrusted Control Sphere

**References.** https://docs.anthropic.com/en/docs/claude-code/plugins

### PLUGIN-002 — Plugin registers dangerous hooks

**AASB 4.2** · Level 1 · **HIGH** · applies to: plugins

A plugin-shipped hook runs a dangerous command or matches all tool calls.

**Detection rationale.** Plugin hooks execute automatically on agent events, without appearing as tool calls the operator can approve.

**Security impact.** Gives the plugin an automatic, unattended execution path on every matching event.

**Remediation.** Review the hook, narrow its matcher, and remove dangerous commands.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM03: Supply Chain; CWE: CWE-506: Embedded Malicious Code

**References.** https://docs.anthropic.com/en/docs/claude-code/hooks

### PLUGIN-003 — Plugin executes shell commands

**AASB 4.3** · Level 2 · **MEDIUM** · applies to: plugins

Bundled executable files invoke a shell or run commands.

**Detection rationale.** Shell invocation in plugin code is common and often legitimate, so this is reported for review rather than as an outright failure unless the command is itself dangerous (covered by PLUGIN-002).

**Security impact.** Expands the plugin's capability beyond declared tool permissions.

**Remediation.** Prefer language-native APIs to shelling out; validate any interpolated input.

**Compliance mapping.** CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command

**References.** https://docs.anthropic.com/en/docs/claude-code/plugins

### PLUGIN-004 — Plugin accesses sensitive filesystem paths

**AASB 4.4** · Level 1 · **HIGH** · applies to: plugins

Bundled plugin code references a known credential location.

**Detection rationale.** Plugin code runs with the user's privileges and outside tool permission gating.

**Security impact.** Credentials can be read and transmitted without any agent tool call.

**Remediation.** Remove credential path access from the plugin.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/plugins

### PLUGIN-005 — Plugin contains embedded credentials

**AASB 4.5** · Level 1 · **CRITICAL** · applies to: plugins

A credential literal appears in the plugin manifest or bundled files.

**Detection rationale.** Takes precedence over SECRET-* for plugin assets (spec 5, deduplication).

**Security impact.** The credential is distributed to every installation of the plugin.

**Remediation.** Remove the literal, use environment indirection, and rotate the credential.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-798: Use of Hard-coded Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/plugins

### PLUGIN-006 — Plugin references suspicious external URLs

**AASB 4.6** · Level 1 · **HIGH** · applies to: plugins

Plugin files reference disposable hosting, tunnelling, or webhook-collector domains.

**Detection rationale.** Paste sites, request collectors, and tunnelling domains are the standard endpoints for exfiltration and for serving mutable payloads.

**Security impact.** Provides a channel for data exfiltration or delivery of new instructions.

**Remediation.** Remove the reference, or replace it with a vetted domain under your control.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; MITRE ATLAS: AML.T0057: LLM Data Leakage

**References.** https://docs.anthropic.com/en/docs/claude-code/plugins

### PLUGIN-007 — Plugin declares untrusted MCP dependencies

**AASB 4.7** · Level 2 · **HIGH** · applies to: plugins

The plugin ships an .mcp.json defining servers launched from unpinned or remote sources.

**Detection rationale.** A plugin-supplied MCP server is installed transitively — the operator approves the plugin, not each server it brings with it.

**Security impact.** Extends the agent's tool surface with code the operator never directly reviewed.

**Remediation.** Pin plugin-supplied MCP servers and review them as first-class dependencies.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM03: Supply Chain; CWE: CWE-494: Download of Code Without Integrity Check

**References.** https://modelcontextprotocol.io/docs/concepts/architecture

### PLUGIN-008 — Plugin declares excessive privileges

**AASB 4.8** · Level 2 · **MEDIUM** · applies to: plugins

The plugin manifest requests wildcard permissions or a very broad tool set.

**Detection rationale.** Distinct from PLUGIN-003, which observes what the code does: this reads what the manifest asks for.

**Security impact.** Broad declared privileges widen the reachable surface for injected instructions.

**Remediation.** Narrow the manifest's declared permissions to what the plugin uses.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-269: Improper Privilege Management

**References.** https://docs.anthropic.com/en/docs/claude-code/plugins


---

## 5. Hooks

6 checks — 4 at Level 1, 2 at Level 2.

### HOOK-001 — Hook interpolates unvalidated agent-controlled input into a shell command

**AASB 5.1** · Level 1 · **CRITICAL** · applies to: hooks

The hook command embeds agent-supplied values — tool arguments, prompt text, or file paths — directly into a shell string.

**Detection rationale.** Executing a command is what a hook does and is not itself a finding. The risk is interpolation: hook payloads carry model-influenced data, so embedding them in a shell string without quoting creates command injection reachable from anything that can steer the model.

**Security impact.** A crafted filename or prompt fragment can break out of the intended command and execute attacker-chosen code on every matching event.

**Remediation.** Read the hook payload from stdin as JSON in a script, quote every interpolation, and never build a shell string from tool input.

**Compliance mapping.** CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command; OWASP LLM Top 10 2025: LLM05: Improper Output Handling; MITRE ATLAS: AML.T0051: LLM Prompt Injection

**References.** https://docs.anthropic.com/en/docs/claude-code/hooks

### HOOK-002 — Hook registered with an overly broad matcher

**AASB 5.2** · Level 2 · **MEDIUM** · applies to: hooks

A PreToolUse or PostToolUse hook matches every tool call.

**Detection rationale.** A wildcard matcher runs the hook on every tool invocation, multiplying both its blast radius and the amount of agent data it observes.

**Security impact.** A hook that sees every tool call sees every file path, command, and result — an ideal position for surveillance or tampering.

**Remediation.** Restrict the matcher to the specific tools the hook needs to observe.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-732: Incorrect Permission Assignment for Critical Resource

**References.** https://docs.anthropic.com/en/docs/claude-code/hooks

### HOOK-003 — Hook executes a dangerous command

**AASB 5.3** · Level 1 · **CRITICAL** · applies to: hooks

The hook command or its resolved script contains a dangerous command pattern.

**Detection rationale.** Hooks run automatically and are not surfaced for per-invocation approval, so a dangerous command in one executes without review.

**Security impact.** Provides automatic, unattended execution of destructive or remote-code operations.

**Remediation.** Remove the dangerous command or gate it behind an explicit confirmation.

**Compliance mapping.** CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command; OWASP LLM Top 10 2025: LLM06: Excessive Agency

**References.** https://docs.anthropic.com/en/docs/claude-code/hooks

### HOOK-004 — Hook reads or writes sensitive files

**AASB 5.4** · Level 1 · **CRITICAL** · applies to: hooks

The hook references a known credential location.

**Detection rationale.** A hook touching credential paths does so automatically on every matching event.

**Security impact.** Enables silent, repeated credential access with no tool call to review.

**Remediation.** Remove credential path access from the hook.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; MITRE ATLAS: AML.T0055: Unsecured Credentials; CWE: CWE-522: Insufficiently Protected Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/hooks

### HOOK-005 — Hook performs network communication

**AASB 5.5** · Level 2 · **HIGH** · applies to: hooks

The hook makes outbound network calls.

**Detection rationale.** A hook with network access sees agent activity and can transmit it. Calls to loopback are treated as local tooling rather than egress.

**Security impact.** Creates an automatic exfiltration channel for tool inputs and outputs.

**Remediation.** Remove network calls from hooks, or restrict them to vetted internal endpoints.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; MITRE ATLAS: AML.T0057: LLM Data Leakage

**References.** https://docs.anthropic.com/en/docs/claude-code/hooks

### HOOK-006 — Hook contains obfuscated or encoded code

**AASB 5.6** · Level 1 · **HIGH** · applies to: hooks

The hook command or script contains encoded payloads or dynamic evaluation.

**Detection rationale.** Obfuscation in a hook has no legitimate configuration purpose and defeats review — including this scanner's own static analysis.

**Security impact.** Conceals the hook's real behaviour from both operators and auditing tools.

**Remediation.** Replace the encoded payload with readable source and re-review the hook.

**Compliance mapping.** CWE: CWE-506: Embedded Malicious Code; MITRE ATLAS: AML.T0051: LLM Prompt Injection

**References.** https://docs.anthropic.com/en/docs/claude-code/hooks


---

## 6. Instruction Files

5 checks — 4 at Level 1, 1 at Level 2.

### INSTR-001 — Secrets in instruction files

**AASB 6.1** · Level 1 · **CRITICAL** · applies to: instructions

A credential literal appears in CLAUDE.md or another instruction file.

**Detection rationale.** Instruction files are read into context on every turn and are usually committed to version control, so a credential here is both persistently exposed to the model and shared with everyone who clones the repository. Takes precedence over SECRET-* for instruction assets.

**Security impact.** The credential is available to the model on every request and to anyone with repository access, and it may be reproduced in model output.

**Remediation.** Remove the credential, reference it from the environment, and rotate it.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-798: Use of Hard-coded Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://docs.anthropic.com/en/docs/claude-code/memory

### INSTR-002 — Instructions sourced from an external location

**AASB 6.2** · Level 1 · **HIGH** · applies to: instructions

The file directs the agent to fetch instructions or content from a remote URL.

**Detection rationale.** Remote instruction sources are not covered by review of the file itself, and their contents can change silently after approval.

**Security impact.** An attacker controlling the remote resource can deliver new instructions to every session that loads this file.

**Remediation.** Inline the required content into the instruction file and pin it in version control.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; CWE: CWE-829: Inclusion of Functionality from Untrusted Control Sphere

**References.** https://docs.anthropic.com/en/docs/claude-code/memory

### INSTR-003 — Instructions granting unrestricted command execution

**AASB 6.3** · Level 1 · **HIGH** · applies to: instructions

The file tells the agent to run commands freely or without confirmation.

**Detection rationale.** Instruction files influence model behaviour but carry no enforcement. A directive to skip confirmation encourages the model to route around the operator's approval gate.

**Security impact.** Erodes the human review step that the permission system depends on.

**Remediation.** Remove blanket execution directives and rely on the permission configuration.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM06: Excessive Agency; CWE: CWE-250: Execution with Unnecessary Privileges

**References.** https://docs.anthropic.com/en/docs/claude-code/memory

### INSTR-004 — Potential prompt injection in instruction file

**AASB 6.4** · Level 1 · **HIGH** · applies to: instructions

The file contains language that would function as an injected instruction.

**Detection rationale.** Static analysis cannot establish intent, so this reports potential injection. Matches inside code fences, blockquotes, or explicitly labelled examples are downgraded, because security documentation legitimately quotes these phrases.

**Security impact.** An injected directive persists across every session that loads the file, making it far more durable than a single-turn injection.

**Remediation.** Review each flagged line. If it is illustrative, move it into a fenced code block; if it is a live directive, remove it and review file write access.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; MITRE ATLAS: AML.T0051: LLM Prompt Injection; CWE: CWE-1427: Improper Neutralization of Input Used for LLM Prompting

**References.** https://owasp.org/www-project-top-10-for-large-language-model-applications/

### INSTR-005 — Instruction file references untrusted URLs

**AASB 6.5** · Level 2 · **MEDIUM** · applies to: instructions

The file links to disposable hosting, tunnelling, or request-collector domains.

**Detection rationale.** A URL in an instruction file is a candidate destination for agent fetches. Well-known documentation and package hosts are allowlisted to keep the false positive rate usable.

**Security impact.** Fetching such a URL can pull attacker-controlled content into context, or signal to an external collector that the agent ran.

**Remediation.** Replace with a vetted domain, or remove the reference.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM01: Prompt Injection; CWE: CWE-829: Inclusion of Functionality from Untrusted Control Sphere

**References.** https://docs.anthropic.com/en/docs/claude-code/memory


---

## 7. Secrets

5 checks — 4 at Level 1, 1 at Level 2.

### SECRET-001 — API keys in agent configuration

**AASB 7.1** · Level 1 · **CRITICAL** · applies to: claude-code, claude-desktop, filesystem

A provider API key literal appears in an agent configuration file or the environment.

**Detection rationale.** Provider keys have a recognisable structure, so detection is high-confidence and placeholder values are filtered out.

**Security impact.** A leaked API key permits billed use of the provider account and access to any data reachable through it.

**Remediation.** Move the key to a secret manager, reference it indirectly, and rotate it.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-798: Use of Hard-coded Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://cwe.mitre.org/data/definitions/798.html

### SECRET-002 — Cloud provider credentials exposed

**AASB 7.2** · Level 1 · **CRITICAL** · applies to: claude-code, claude-desktop, filesystem

An AWS, GCP, or Azure credential literal appears in an agent-reachable location.

**Detection rationale.** Cloud access key identifiers have fixed prefixes and lengths, giving high-confidence detection.

**Security impact.** Cloud credentials typically grant access to infrastructure and data far beyond the local machine, making this the highest-impact class of local leak.

**Remediation.** Revoke and rotate the credential immediately, then use short-lived role-based credentials instead of long-lived keys.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://cwe.mitre.org/data/definitions/522.html

### SECRET-003 — Private key material in agent-reachable configuration

**AASB 7.3** · Level 1 · **CRITICAL** · applies to: claude-code, claude-desktop, filesystem

A PEM private key block appears inside an agent configuration file.

**Detection rationale.** A PEM header is unambiguous. This check covers key material embedded in configuration; keys in their normal location are covered by FS-003.

**Security impact.** Enables impersonation of the key holder for authentication or signing.

**Remediation.** Remove the key from configuration, store it with 0600 permissions, and rotate it.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials

**References.** https://cwe.mitre.org/data/definitions/522.html

### SECRET-004 — Authentication tokens exposed

**AASB 7.4** · Level 1 · **HIGH** · applies to: claude-code, claude-desktop, filesystem

A session, OAuth, or personal access token literal is present.

**Detection rationale.** Covers environment-variable exposure as well as configuration files, which is why AASB v1.0 defines no separate ENV-* family (spec 5.10).

**Security impact.** Permits authenticated access as the token's owner until it is revoked.

**Remediation.** Revoke the token, reissue with minimal scope, and store it outside configuration.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials

**References.** https://cwe.mitre.org/data/definitions/522.html

### SECRET-005 — Plaintext credentials in configuration

**AASB 7.5** · Level 2 · **HIGH** · applies to: claude-code, claude-desktop, filesystem

A high-entropy value is assigned to a credential-named key, or credentials are embedded in a URL.

**Detection rationale.** These values have no fixed structure, so detection requires both a credential-shaped key name and a Shannon entropy above 3.6. Environment indirection such as ${VAR} is excluded, since that is the recommended fix.

**Security impact.** Credentials readable by anyone with access to the configuration file.

**Remediation.** Replace the literal with an environment reference and rotate the credential.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-256: Plaintext Storage of a Password

**References.** https://cwe.mitre.org/data/definitions/256.html


---

## 8. Filesystem

7 checks — 5 at Level 1, 2 at Level 2.

### FS-001 — Sensitive file reachable by agent

**AASB 8.1** · Level 1 · **HIGH** · applies to: claude-code, filesystem

A credential-bearing location is readable and not covered by any deny rule.

**Detection rationale.** Reachability combines OS permissions with the agent's permission ruleset. Reporting on either alone would produce findings that are not actually exploitable, or miss ones that are.

**Security impact.** Credential material can be read into agent context by a file-reading tool.

**Remediation.** Add deny rules covering these paths in ~/.claude/settings.json.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-552: Files or Directories Accessible to External Parties

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### FS-002 — Credential directories reachable by agent

**AASB 8.2** · Level 2 · **HIGH** · applies to: claude-code, filesystem

Directory-level credential stores are reachable rather than individual files.

**Detection rationale.** A reachable directory exposes future contents too, so it is a durable exposure rather than a point-in-time one.

**Security impact.** Every credential now or later placed in the directory is exposed.

**Remediation.** Deny the directory recursively, e.g. Read(~/.aws/**).

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-552: Files or Directories Accessible to External Parties

**References.** https://docs.anthropic.com/en/docs/claude-code/settings

### FS-003 — SSH private keys reachable by agent

**AASB 8.3** · Level 1 · **CRITICAL** · applies to: claude-code, filesystem

Private key files in ~/.ssh are readable and not denied.

**Detection rationale.** Key files are identified by name and location only — Argus never reads key contents, so no key material passes through the scanner.

**Security impact.** An exfiltrated SSH key grants access to every host trusting it, turning a local agent compromise into lateral movement.

**Remediation.** Add Read(~/.ssh/**) to the deny list and ensure keys are passphrase-protected.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://cwe.mitre.org/data/definitions/522.html

### FS-004 — Cloud credential files reachable by agent

**AASB 8.4** · Level 1 · **CRITICAL** · applies to: claude-code, filesystem

AWS, GCP, Azure or Kubernetes credential stores are readable and not denied.

**Detection rationale.** Detected by location; contents are never read.

**Security impact.** Cloud credentials extend a local compromise into the organisation's infrastructure and data.

**Remediation.** Deny cloud credential paths and prefer short-lived, role-based credentials.

**Compliance mapping.** OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure; CWE: CWE-522: Insufficiently Protected Credentials; MITRE ATLAS: AML.T0055: Unsecured Credentials

**References.** https://cwe.mitre.org/data/definitions/522.html

### FS-005 — Unsafe permissions on agent configuration file

**AASB 8.5** · Level 1 · **HIGH** · applies to: filesystem

An agent configuration file is group- or world-readable.

**Detection rationale.** Files such as .credentials.json hold live tokens and must be owner-only. This check relies on POSIX mode bits and is not applicable on Windows.

**Security impact.** Any local account can read the agent's stored credentials and configuration.

**Remediation.** Restrict permissions to 0600 (files) or 0700 (directories).

**Compliance mapping.** CWE: CWE-732: Incorrect Permission Assignment for Critical Resource; OWASP LLM Top 10 2025: LLM02: Sensitive Information Disclosure

**References.** https://cwe.mitre.org/data/definitions/732.html

### FS-006 — Symlink escapes the workspace

**AASB 8.6** · Level 2 · **MEDIUM** · applies to: filesystem

A symlink inside the project resolves to a location outside it.

**Detection rationale.** Path-scoped permission rules are evaluated against the link path, so a link that resolves elsewhere can defeat a scope the operator believes is enforced.

**Security impact.** An agent restricted to the project directory can read or write outside it by traversing the link.

**Remediation.** Remove the symlink or repoint it inside the workspace.

**Compliance mapping.** CWE: CWE-59: Improper Link Resolution Before File Access, CWE-22: Improper Limitation of a Pathname to a Restricted Directory

**References.** https://cwe.mitre.org/data/definitions/59.html

### FS-007 — World-writable agent configuration

**AASB 8.7** · Level 1 · **CRITICAL** · applies to: filesystem

An agent configuration file or directory is writable by any local user.

**Detection rationale.** Distinct from FS-005, which covers read exposure. Write access to agent configuration is a direct path to controlling the agent. POSIX-only.

**Security impact.** Any local user can add MCP servers, hooks, or permission grants, achieving code execution as the agent's owner.

**Remediation.** Remove world-write permission immediately (chmod o-w).

**Compliance mapping.** CWE: CWE-732: Incorrect Permission Assignment for Critical Resource; OWASP LLM Top 10 2025: LLM03: Supply Chain

**References.** https://cwe.mitre.org/data/definitions/732.html


---

*AASB is an original Argus benchmark inspired by CIS-style baselines. It is not a CIS Benchmark, and Argus is not affiliated with or certified by CIS, Anthropic, OpenAI, or any other organization.*
