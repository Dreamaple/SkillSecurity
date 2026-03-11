# Feature Specification: SkillSecurity Core

**Feature Branch**: `001-skill-security-core`  
**Created**: 2026-03-11  
**Status**: Draft  
**Input**: User description: "SkillSecurity - AI Agent Skill/Tool call security protection layer. A one-click deployable, open-source, universal security solution that provides static scanning, permission declaration, runtime interception, and audit trail for AI Agent skills/tools."

## Clarifications

### Session 2026-03-11

- Q: Fail-open vs fail-close default when the security layer itself fails? → A: Fail-close (default: block). Safety-first posture; advanced users can opt into fail-open.
- Q: Should SkillSecurity protect its own config files from Agent tampering? → A: Hardcoded protection. SkillSecurity's own configuration paths are automatically added to an immutable blocklist — no Agent tool call can modify them.
- Q: How are Skill IDs structured to prevent collisions and impersonation? → A: Namespace format `author/skill-name` (e.g., `openai/web-browser`). Not enforced by a central registry in Core, but format convention prevents accidental collisions.
- Q: When Skill manifest permissions and global policy conflict, which wins? → A: Intersection (most restrictive wins). An operation must be both within the Skill's declared permissions AND allowed by global policy. Either side can restrict, neither side can override the other.
- Q: Should the default policy cover Windows patterns or Unix-only? → A: Dual-platform. Default policy covers both Unix and Windows dangerous patterns simultaneously.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Developer Blocks a Dangerous Command (Priority: P1)

A developer is running an AI Agent locally. The Agent decides to execute `rm -rf /tmp/important-data`. Before the command reaches the operating system, SkillSecurity intercepts it, matches it against the built-in default policy, and blocks execution. The developer sees a clear terminal message explaining what was blocked and why.

**Why this priority**: This is the fundamental value proposition — catching dangerous operations before they cause harm. Without this, SkillSecurity has no reason to exist.

**Independent Test**: Can be fully tested by sending a simulated tool call with a known-dangerous command and verifying the system returns a "block" decision with a human-readable reason.

**Acceptance Scenarios**:

1. **Given** SkillSecurity is initialized with default policy, **When** a tool call with command `rm -rf /` is submitted for checking, **Then** the system returns a "block" decision with severity "critical" and a reason referencing the matched rule.
2. **Given** SkillSecurity is initialized with default policy, **When** a tool call with command `ls /tmp` is submitted for checking, **Then** the system returns an "allow" decision and does not interfere with execution.
3. **Given** SkillSecurity is initialized with default policy, **When** a tool call with command `sudo apt install nginx` is submitted for checking, **Then** the system returns an "ask" decision prompting the user to confirm the elevated privilege operation.

---

### User Story 2 - Developer Configures Custom Security Policy (Priority: P1)

A developer has specific security needs beyond the defaults. They create a YAML configuration file to define custom rules — for example, allowing writes only to a specific project directory, or blocking all network requests to non-whitelisted domains. SkillSecurity loads this configuration and enforces it at runtime.

**Why this priority**: Different users have different risk tolerances and working contexts. Without configurable policies, the system is either too restrictive or too permissive for most users.

**Independent Test**: Can be tested by creating a YAML policy file with a custom rule, initializing SkillSecurity with that policy, and verifying that tool calls are evaluated against the custom rule.

**Acceptance Scenarios**:

1. **Given** a YAML policy file with a rule blocking all file writes outside `/home/user/project/`, **When** a file write to `/etc/hosts` is checked, **Then** the system blocks it citing the custom rule.
2. **Given** a YAML policy file with a syntax error, **When** SkillSecurity attempts to load it, **Then** the system reports a clear error message indicating the location and nature of the syntax problem.
3. **Given** a running SkillSecurity instance, **When** the policy file is modified on disk, **Then** the new policy takes effect within 60 seconds without requiring a restart.

---

### User Story 3 - Developer Gets Actionable Feedback on Decisions (Priority: P1)

When SkillSecurity blocks or flags an operation, the developer sees not just "blocked" but a complete context: which rule triggered, why it was considered dangerous, and what alternatives they might consider. For "ask" decisions, the developer can confirm or reject through the terminal.

**Why this priority**: A security tool that blocks without explanation causes frustration and gets disabled. Clear communication is essential for user trust and adoption.

**Independent Test**: Can be tested by triggering block and ask decisions and verifying the output contains rule ID, reason, severity level, and at least one actionable suggestion.

**Acceptance Scenarios**:

1. **Given** a tool call is blocked, **When** the decision result is rendered in the terminal, **Then** the output includes: the tool type, the blocked parameters, the matched rule ID, a human-readable reason, the severity level, and at least one suggestion.
2. **Given** a tool call triggers an "ask" decision, **When** the user is prompted in the terminal, **Then** the prompt shows the risk level, operation details, and a timeout countdown, and accepts "y" or "n" input.
3. **Given** an "ask" prompt with a 60-second timeout and default behavior set to "block", **When** the user does not respond within 60 seconds, **Then** the system automatically blocks the operation.

---

### User Story 4 - Skill Developer Declares Permissions (Priority: P2)

A third-party Skill developer creates a `skill-manifest.json` file declaring that their weather Skill only needs `network.read` permission with access to `api.openweathermap.org`. When a user registers this Skill with SkillSecurity, any attempt by the Skill to write files or access other network domains is automatically blocked.

**Why this priority**: Permission boundaries turn SkillSecurity from a generic firewall into a true "app permission system" for the LLM OS. This is critical for the ecosystem but depends on the core interception engine being functional first.

**Independent Test**: Can be tested by registering a Skill manifest, then submitting tool calls tagged with that Skill ID — verifying that in-scope operations are allowed and out-of-scope operations are blocked.

**Acceptance Scenarios**:

1. **Given** a Skill manifest declaring only `network.read` permission, **When** a tool call tagged with that Skill ID attempts `file.write`, **Then** the system blocks it with reason "Skill has not declared file.write permission".
2. **Given** a Skill manifest with `network.read` restricted to domain `api.example.com`, **When** the Skill makes a network request to `malicious.com`, **Then** the system blocks it citing the domain constraint.
3. **Given** a tool call tagged with a Skill ID that has no registered manifest, **When** checked by SkillSecurity, **Then** the system falls back to standard policy matching (backward compatible).

---

### User Story 5 - Developer Scans a Skill Before Installation (Priority: P2)

Before installing a third-party Skill, a developer runs SkillSecurity's static scanner on its source code. The scanner finds that the Skill contains code that sends environment variables to an external server — a clear data exfiltration risk. The developer sees a detailed report and decides not to install the Skill.

**Why this priority**: Static scanning is the "antivirus" core capability that differentiates SkillSecurity from a simple runtime firewall. It depends on having the permission system to compare declared vs. actual behavior.

**Independent Test**: Can be tested by pointing the scanner at a directory containing known-dangerous code patterns and verifying that each pattern is detected with correct severity and file/line information.

**Acceptance Scenarios**:

1. **Given** a Skill directory containing `requests.post(url, data={'key': os.environ['API_KEY']})`, **When** the static scanner analyzes it, **Then** the report includes a "critical" finding for data exfiltration with the exact file and line number.
2. **Given** a Skill directory containing only safe code, **When** the static scanner analyzes it, **Then** the report shows risk level "safe" with no issues.
3. **Given** a Skill manifest declaring `network.read` and code that actually uses `network.write`, **When** the scanner runs, **Then** the report includes a permission mismatch finding listing the undeclared permissions.

---

### User Story 6 - Developer Audits Past Operations (Priority: P2)

After noticing unexpected changes in their project files, a developer queries the SkillSecurity audit log to find out what happened. They filter by time range and action type to find that an Agent performed 15 file deletions two hours ago, all blocked by SkillSecurity.

**Why this priority**: Audit trails provide accountability and help diagnose issues after the fact. Essential for trust but requires the core interception pipeline to generate events.

**Independent Test**: Can be tested by performing several interceptions, then querying the log with various filters and verifying correct results are returned in structured format.

**Acceptance Scenarios**:

1. **Given** SkillSecurity has processed 100 tool call checks with various decisions, **When** the log is queried with `--action=block`, **Then** only blocked events are returned, each with a complete audit record.
2. **Given** audit logging is enabled, **When** a tool call containing `password=secret123` is processed, **Then** the log entry automatically redacts the sensitive value to `password=***`.
3. **Given** the log file reaches its configured maximum size, **When** a new event is logged, **Then** the log rotates correctly and old data remains accessible in rotated files.

---

### Edge Cases

- What happens when SkillSecurity itself crashes during a check? The system defaults to fail-close (block all operations) to maintain security posture. Users who prefer availability over safety can explicitly configure `fail_behavior: allow`, but the out-of-box default is block. The host Agent must not crash regardless of which mode is configured.
- How does the system handle an extremely long command string (>100KB)? It should truncate for analysis but still apply basic pattern matching.
- What happens when multiple rules match the same tool call? The first matching rule wins (by order in the policy file).
- How does the system handle a corrupted or missing policy file at startup? It falls back to the built-in default policy and logs a warning.
- What happens when the audit log disk is full? Logging fails gracefully without blocking the interception pipeline.
- How does the system handle concurrent checks from multiple Agents? Each check is independent and stateless (except rate limiting counters).
- What if an Agent tries to modify SkillSecurity's own policy files or configuration? SkillSecurity hardcodes its own configuration paths (policy files, manifests directory, log directory) as immutable protected resources. Any Agent tool call attempting to write, delete, or modify these paths is unconditionally blocked regardless of policy rules.
- What if a Skill manifest declares a permission but global policy blocks it? The intersection rule applies — the operation is blocked. An operation must pass both the Skill permission check AND the global policy check. Neither layer can grant access that the other denies.

## Requirements *(mandatory)*

### Functional Requirements

**Runtime Interception (Phase 1)**

- **FR-001**: System MUST intercept tool call requests before execution and evaluate them against security policies
- **FR-002**: System MUST support intercepting at least these tool types: shell/exec, file.read, file.write, file.delete, network.request, message.send, browser, database
- **FR-003**: System MUST recognize dangerous command patterns for both Unix and Windows platforms, including recursive deletion (`rm -rf`, `del /s /q`, `rd /s`), privilege escalation (`sudo`, `runas`), remote code execution (`curl | bash`, `powershell -exec bypass`), and disk-level operations (`dd`, `mkfs`, `format`)
- **FR-004**: System MUST recognize sensitive path patterns on both Unix and Windows, including system directories (`/etc`, `/System`, `C:\Windows`, `C:\Program Files`), credential files (`~/.ssh`, `.env`, `%APPDATA%`), and configuration files
- **FR-005**: System MUST detect sensitive data in parameters (passwords, tokens, API keys, secrets)

**Policy Configuration (Phase 1)**

- **FR-006**: System MUST load security rules from human-readable configuration files (YAML format)
- **FR-007**: System MUST support rule types: blacklist (block), whitelist (allow), risk escalation (ask), rate limiting, and time-based policies
- **FR-008**: System MUST apply rules in order, with first-match-wins semantics
- **FR-009**: System MUST provide a built-in default policy that works without any user configuration
- **FR-010**: System MUST validate policy file syntax and report clear errors with location information
- **FR-011**: System MUST support hot-reloading policy changes within 60 seconds without restart
- **FR-011a**: System MUST hardcode its own configuration paths (policy files, manifest directory, audit log directory) as immutable protected resources — any Agent tool call targeting these paths is unconditionally blocked, regardless of policy rules

**Decision & Response (Phase 1)**

- **FR-012**: System MUST produce one of three decisions for each check: Allow, Block, or Ask
- **FR-013**: Every decision MUST include: action, human-readable reason, matched rule ID, severity level, and check duration
- **FR-014**: Block decisions MUST include at least one actionable suggestion for the user
- **FR-015**: Ask decisions MUST support configurable timeout with configurable default behavior on timeout (default: block)
- **FR-016**: System MUST provide terminal (CLI) output for all decision types with clear formatting

**Skill Permission Declaration (Phase 2)**

- **FR-017**: System MUST accept a Skill permission manifest (JSON format) with a namespaced Skill ID (`author/skill-name` format), declaring required permissions, optional domain/path constraints, and explicitly denied permissions
- **FR-018**: System MUST enforce permission boundaries using an intersection model — an operation is allowed only if it is both within the Skill's declared permissions AND permitted by global policy. Either layer can restrict an operation; neither can override the other's denial
- **FR-019**: System MUST display Skill permission summaries to users during registration in a human-readable format
- **FR-020**: System MUST remain backward compatible — Skills without manifests fall back to standard policy matching

**Static Scanning (Phase 2)**

- **FR-021**: System MUST scan Skill source code for dangerous patterns (dangerous API calls, data exfiltration, code obfuscation, reverse shells)
- **FR-022**: System MUST support scanning Python and JavaScript/TypeScript code at minimum
- **FR-023**: System MUST compare detected code behavior against declared permissions and report mismatches
- **FR-024**: System MUST produce a structured scan report with risk level, individual findings (file, line, severity, description), and an overall recommendation

**Audit Logging (Phase 2)**

- **FR-025**: System MUST log every tool call check and its decision in a structured format (JSONL)
- **FR-026**: System MUST automatically redact sensitive information in logs (passwords, tokens, keys)
- **FR-027**: System MUST support log rotation by size and retention by age
- **FR-028**: Log writing MUST be asynchronous and MUST NOT block the interception pipeline
- **FR-029**: System MUST provide basic CLI querying of logs with filters (time range, action type, agent ID)

### Key Entities

- **Tool Call**: A request from an AI Agent to execute a tool/Skill, characterized by tool type, operation, parameters, and context (agent ID, session ID, skill ID)
- **Policy**: A set of ordered rules loaded from YAML configuration, defining patterns to match and actions to take
- **Rule**: A single policy entry with an ID, match conditions (patterns, tool types, paths), an action (allow/block/ask), and severity
- **Decision**: The outcome of evaluating a tool call against policies — contains action, reason, matched rule, severity, and suggestions
- **Skill Manifest**: A JSON declaration by a Skill developer with a namespaced ID (`author/skill-name`), specifying required permissions, access constraints, and denied permissions
- **Scan Report**: The output of static analysis on Skill source code — contains risk level, findings list, and permission comparison
- **Audit Log Entry**: A structured record of a single tool call check, including request details, decision, timing, and redacted parameters

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can install and start using SkillSecurity with default protection in under 5 minutes, with zero configuration required
- **SC-002**: 99% of known-dangerous operations (from a standardized test set of 200+ patterns covering both Unix and Windows) are correctly intercepted
- **SC-003**: Less than 1% of normal, safe operations are incorrectly blocked (measured against a test set of 500+ common tool calls)
- **SC-004**: Each security check adds less than 50 milliseconds to tool execution time in 99% of cases
- **SC-005**: Security policy changes take effect within 60 seconds without requiring service restart
- **SC-006**: Static scanning of a 1,000-line Skill completes in under 5 seconds
- **SC-007**: Audit log queries against 100,000 entries return results in under 5 seconds
- **SC-008**: All sensitive data (passwords, tokens, API keys) in audit logs is automatically redacted with zero manual configuration
- **SC-009**: A Skill exceeding its declared permissions is blocked 100% of the time when permission enforcement is enabled
- **SC-010**: The system handles interception engine failure gracefully — defaulting to block (fail-close) unless explicitly configured otherwise, with no crashes or hangs in the host Agent
