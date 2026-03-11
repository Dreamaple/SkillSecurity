# Tasks: SkillSecurity Core

**Input**: Design documents from `/specs/001-skill-security-core/`
**Prerequisites**: plan.md âœ? spec.md âœ? research.md âœ? data-model.md âœ? contracts/ âœ? quickstart.md âœ?

**Tests**: Included â€?plan.md specifies pytest + pytest-cov + hypothesis with â‰?0% coverage gate and a full test directory structure.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story. User stories US1â€“US3 are Phase 1 (P1), US4â€“US6 are Phase 2 (P2).

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization, directory structure, and dependency management

- [x] T001 Create project directory structure with all packages and `__init__.py` files per plan.md (src/skillsecurity/engine/, scanner/, manifest/, audit/, config/, selfprotect/, cli/, models/ and tests/unit/, integration/, testdata/)
- [x] T002 Initialize Python project with dependencies in pyproject.toml (PyYAML, watchdog, click, pytest, pytest-cov, hypothesis, ruff) and configure console_scripts entry point
- [x] T003 [P] Configure ruff linting and formatting rules in pyproject.toml

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core data models, enums, and shared infrastructure that ALL user stories depend on

**âš ï¸ CRITICAL**: No user story work can begin until this phase is complete

- [x] T004 [P] Implement ToolCall and CallContext dataclasses and ToolType enum in src/skillsecurity/models/tool_call.py per data-model.md Â§1.1
- [x] T005 [P] Implement Rule, MatchCondition, RateLimit dataclasses and Action, Severity enums in src/skillsecurity/models/rule.py per data-model.md Â§1.3
- [x] T006 [P] Implement Decision and RuleRef dataclasses with is_allowed, is_blocked, needs_confirmation properties in src/skillsecurity/models/decision.py per data-model.md Â§1.4 and python-api.md
- [x] T007 [P] Implement built-in default policy constants and GlobalConfig defaults (default_action=allow, fail_behavior=block) in src/skillsecurity/config/defaults.py
- [x] T008 [P] Implement self-protection guard with hardcoded immutable path set checking in src/skillsecurity/selfprotect/guard.py per FR-011a and research.md Â§R9
- [x] T009 Create shared test fixtures (sample ToolCalls, temp policy files, temp directories) in tests/conftest.py

**Checkpoint**: Foundation ready â€?user story implementation can now begin

---

## Phase 3: User Story 1 â€?Developer Blocks a Dangerous Command (Priority: P1) ðŸŽ¯ MVP

**Goal**: Intercept tool calls against the built-in default policy, returning Allow/Block/Ask decisions with matched rule info

**Independent Test**: Send simulated ToolCall with known-dangerous command (e.g., `rm -rf /`), verify system returns "block" decision with severity "critical" and a reason referencing the matched rule

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T010 [P] [US1] Write unit tests for rule matching engine (regex match, path match, rate limit, first-match-wins) in tests/unit/test_matcher.py
- [x] T011 [P] [US1] Write unit tests for policy loading and YAML parsing (load default, load custom, rule ordering) in tests/unit/test_policy.py
- [x] T012 [P] [US1] Write unit tests for decision logic (allow/block/ask results, reason/severity/suggestions population) in tests/unit/test_decision.py

### Implementation for User Story 1

- [x] T013 [P] [US1] Create test data files with known-dangerous and safe command patterns in tests/testdata/dangerous_commands.yaml and tests/testdata/safe_commands.yaml
- [x] T014 [US1] Implement rule matching engine with regex pattern matching, path matching, and rate limit tracking in src/skillsecurity/engine/matcher.py
- [x] T015 [US1] Implement policy loading from YAML files, first-match-wins evaluation, and OS-based rule filtering (platform.system()) in src/skillsecurity/engine/policy.py
- [x] T016 [US1] Implement decision logic producing Allow/Block/Ask with human-readable reason, severity, matched rule reference, and suggestions in src/skillsecurity/engine/decision.py
- [x] T017 [US1] Create default policy YAML with Unix and Windows dangerous patterns (recursive delete, privilege escalation, remote code execution, system paths, sensitive data) in policies/default.yaml per policy-schema.md and FR-003/FR-004/FR-005
- [x] T018 [US1] Implement tool call interception entry point orchestrating self-protection check â†?policy matching â†?decision in src/skillsecurity/engine/interceptor.py per data-model.md Â§3 decision flow
- [x] T019 [US1] Implement SkillGuard public API (__init__, check method, protect decorator) and exception classes (SkillSecurityError, PolicyLoadError) in src/skillsecurity/__init__.py per python-api.md
- [x] T020 [US1] Write integration test for full check pipeline: dangerous command â†?block, safe command â†?allow, sudo command â†?ask in tests/integration/test_engine_e2e.py

**Checkpoint**: SkillGuard().check() works with default policy â€?US1 is fully functional and testable independently

---

## Phase 4: User Story 2 â€?Developer Configures Custom Security Policy (Priority: P1)

**Goal**: Load custom YAML policies with validation, clear syntax error reporting, and hot-reload without restart

**Independent Test**: Create YAML policy with custom rule, initialize SkillGuard with that policy, verify tool calls are evaluated against the custom rule. Also test syntax errors produce clear messages with location info.

### Tests for User Story 2

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T021 [P] [US2] Write unit tests for config loader validation (syntax errors with line info, duplicate rule IDs, invalid regex, missing required fields) extending tests/unit/test_policy.py
- [x] T022 [P] [US2] Write integration tests for policy hot-reload (modify file â†?new rules effective within 60s, bad file â†?retain old policy) in tests/integration/test_hot_reload.py

### Implementation for User Story 2

- [x] T023 [US2] Implement YAML config loader with validation and clear error messages (line number, field name, nature of error) in src/skillsecurity/config/loader.py per FR-006/FR-010 and policy-schema.md validation rules
- [x] T024 [US2] Implement file system watcher for policy hot-reload with 1-second debounce using watchdog in src/skillsecurity/config/watcher.py per FR-011 and research.md Â§R4
- [x] T025 [P] [US2] Create strict policy template in policies/strict.yaml and development policy template in policies/development.yaml
- [x] T026 [US2] Integrate config loader, watcher, and policy_file/policy template selection into SkillGuard constructor in src/skillsecurity/__init__.py

**Checkpoint**: Custom policies load with validation, hot-reload works â€?US2 is fully functional and testable independently

---

## Phase 5: User Story 3 â€?Developer Gets Actionable Feedback on Decisions (Priority: P1)

**Goal**: CLI tool with clear formatted output for all decision types, ask confirmation with timeout, and JSON/human-readable output modes

**Independent Test**: Run `skillsecurity check --tool shell --command "rm -rf /"` and verify output includes tool type, blocked parameters, matched rule ID, reason, severity, and at least one suggestion

### Implementation for User Story 3

- [x] T027 [P] [US3] Implement terminal output formatter with colored decision rendering (block/allow/ask), severity indicators, rule info, and suggestions in src/skillsecurity/cli/formatter.py per cli-interface.md output format
- [x] T028 [P] [US3] Implement ask confirmation prompter with configurable timeout (default 60s), countdown display, y/n input, and default-block on timeout in src/skillsecurity/cli/prompter.py per FR-015
- [x] T029 [US3] Implement CLI entry point with `check` command supporting --tool, --command, --path, --url, --json input, human-readable stderr and JSON stdout in src/skillsecurity/cli/main.py per cli-interface.md
- [x] T030 [US3] Implement CLI `init` command (generate config file from template) and `validate` command (syntax check with report) in src/skillsecurity/cli/main.py per cli-interface.md
- [x] T031 [US3] Add global CLI options (--policy, --format, --verbose, --no-color, --no-emoji, --lang, --config) in src/skillsecurity/cli/main.py per cli-interface.md global options table
- [x] T032 [US3] Wire CLI entry point as `skillsecurity` console_scripts in pyproject.toml and export in src/skillsecurity/cli/__init__.py with correct exit codes (0=allow, 1=block, 2=ask, 3=error)

**Checkpoint**: Full CLI working with check/init/validate commands â€?US3 is fully functional and testable independently

---

## Phase 6: User Story 4 â€?Skill Developer Declares Permissions (Priority: P2)

**Goal**: Register Skill manifests declaring permissions, enforce intersection model (Skill permission âˆ?global policy), fallback for unregistered Skills

**Independent Test**: Register a manifest declaring only `network.read`, submit tool call tagged with that Skill ID attempting `file.write`, verify system blocks with "Skill has not declared file.write permission"

### Tests for User Story 4

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T033 [P] [US4] Write unit tests for manifest parser (valid/invalid manifests, missing fields, permission parsing) in tests/unit/test_manifest.py
- [x] T034 [P] [US4] Write unit tests for namespace validation (valid formats, too short, uppercase, missing slash) in tests/unit/test_namespace.py
- [x] T035 [P] [US4] Create sample manifest files (valid weather skill, invalid format, various permission combos) in tests/testdata/sample_manifests/

### Implementation for User Story 4

- [x] T036 [P] [US4] Implement namespace validation (author/skill-name format, length limits, lowercase, regex) in src/skillsecurity/manifest/namespace.py per manifest-schema.md skill ID validation rules
- [x] T037 [P] [US4] Implement permission types enum, constraint matching (domain matching, path glob matching) in src/skillsecurity/manifest/permissions.py per manifest-schema.md permission types table
- [x] T038 [US4] Implement skill-manifest.json parser with schema validation and ManifestValidationError in src/skillsecurity/manifest/parser.py
- [x] T039 [US4] Integrate permission checking into interceptor: self-protection â†?skill permission â†?global policy (intersection model) in src/skillsecurity/engine/interceptor.py per data-model.md Â§3 decision flow
- [x] T040 [US4] Implement register_skill API and permission summary display in src/skillsecurity/__init__.py per python-api.md
- [x] T041 [US4] Implement CLI `register` command and `skills` subcommands (list, show, remove) in src/skillsecurity/cli/main.py per manifest-schema.md registration CLI

**Checkpoint**: Skill manifests enforce permission boundaries via intersection model â€?US4 is fully functional and testable independently

---

## Phase 7: User Story 5 â€?Developer Scans a Skill Before Installation (Priority: P2)

**Goal**: Static scanner detects dangerous patterns in Skill source code, compares detected behavior against declared permissions, produces structured report

**Independent Test**: Point scanner at directory containing `requests.post(url, data={'key': os.environ['API_KEY']})`, verify report includes "critical" finding for data exfiltration with exact file and line number

### Tests for User Story 5

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T042 [P] [US5] Write unit tests for scanner (dangerous pattern detection, risk level calculation, permission mismatch reporting) in tests/unit/test_scanner.py
- [x] T043 [P] [US5] Create sample skill directories: one with dangerous code (data exfiltration, eval, reverse shell), one safe, in tests/testdata/sample_skills/

### Implementation for User Story 5

- [x] T044 [P] [US5] Implement ScanReport, ScanIssue, ScanSummary, PermissionAnalysis, RiskLevel models in src/skillsecurity/models/report.py per data-model.md Â§1.6
- [x] T045 [P] [US5] Implement dangerous pattern definitions for Python and JS/TS (data exfiltration, dynamic code execution, code obfuscation, reverse shells) in src/skillsecurity/scanner/patterns.py per FR-021/FR-022
- [x] T046 [US5] Create scan rules YAML with categorized patterns for Python and JavaScript/TypeScript in policies/scan-rules.yaml
- [x] T047 [US5] Implement static code analysis engine: file traversal, per-file regex matching, Python and JS/TS support in src/skillsecurity/scanner/analyzer.py per FR-021/FR-022
- [x] T048 [US5] Implement scan report generation with risk level calculation (max severity â†?overall risk) and recommendation in src/skillsecurity/scanner/report.py per FR-024
- [x] T049 [US5] Implement scan_skill API with optional manifest for permission comparison (declared vs detected) in src/skillsecurity/__init__.py per python-api.md and FR-023
- [x] T050 [US5] Implement CLI `scan` command with human-readable and JSON output, permission analysis display in src/skillsecurity/cli/main.py per cli-interface.md scan section
- [x] T051 [US5] Write integration test for full scan pipeline (dangerous skill â†?high risk, safe skill â†?safe, permission mismatch detection) in tests/integration/test_scan_pipeline.py

**Checkpoint**: Static scanner analyzes Skill source code and reports risks â€?US5 is fully functional and testable independently

---

## Phase 8: User Story 6 â€?Developer Audits Past Operations (Priority: P2)

**Goal**: Async JSONL audit logging with automatic sensitive data redaction, log rotation, and CLI querying with filters

**Independent Test**: Perform several interceptions, query log with `--action=block`, verify only blocked events returned with complete audit records and redacted sensitive data

### Tests for User Story 6

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T052 [P] [US6] Write unit tests for sensitive data redactor (password, token, API key, Bearer token, partial preservation) in tests/unit/test_redactor.py

### Implementation for User Story 6

- [x] T053 [P] [US6] Implement sensitive data redactor with precompiled regex patterns (password, token, api_key, secret, Bearer, sk-/pk-) in src/skillsecurity/audit/redactor.py per research.md Â§R7
- [x] T054 [P] [US6] Implement async JSONL log writer with Queue + daemon thread and atexit flush in src/skillsecurity/audit/logger.py per FR-025/FR-028 and research.md Â§R6
- [x] T055 [US6] Implement log file rotation by size and retention by age in src/skillsecurity/audit/rotation.py per FR-027
- [x] T056 [US6] Implement log querying and filtering (time range, action type, agent_id, severity) with pagination in src/skillsecurity/audit/query.py per FR-029
- [x] T057 [US6] Integrate audit logging into interceptor pipeline as non-blocking post-decision step in src/skillsecurity/engine/interceptor.py per FR-028
- [x] T058 [US6] Implement query_logs API in src/skillsecurity/__init__.py per python-api.md
- [x] T059 [US6] Implement CLI `log` command with filters and `log stats` subcommand, supporting table/json/jsonl/csv formats in src/skillsecurity/cli/main.py per cli-interface.md log section
- [x] T060 [US6] Write integration test for audit pipeline (log writes, redaction verification, rotation, query accuracy) in tests/integration/test_audit_pipeline.py

**Checkpoint**: Full audit trail with redaction, rotation, and querying â€?US6 is fully functional and testable independently

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Edge cases, hardening, performance, and final validation

- [ ] T061 [P] Write unit test for self-protection guard (block writes to policy/config/log dirs, allow other writes) in tests/unit/test_selfprotect.py
- [ ] T062 [P] Add edge case handling: extremely long commands (>100KB truncation), concurrent stateless checks, corrupted/missing policy fallback to built-in default per spec.md edge cases
- [ ] T063 Performance optimization: ensure <10ms avg / <50ms P99 per check, benchmark with 1000+ rules, verify <50MB memory per FR performance goals
- [ ] T064 [P] Update documentation in docs/README.md and docs/architecture-overview.md to reflect final implementation
- [ ] T065 Run quickstart.md validation: execute all usage examples end-to-end as a smoke test (Python API, CLI commands, custom policy, scan, register, log)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies â€?can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion â€?BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Foundational â€?the core interception engine
- **US2 (Phase 4)**: Depends on US1 (extends policy system with validation + hot-reload)
- **US3 (Phase 5)**: Depends on US1 (renders Decision objects in CLI)
- **US4 (Phase 6)**: Depends on US1 (adds permission layer to interception pipeline)
- **US5 (Phase 7)**: Depends on US4 (compares detected behavior against declared permissions)
- **US6 (Phase 8)**: Depends on US1 (logs interception events from the pipeline)
- **Polish (Phase 9)**: Depends on all desired user stories being complete

### User Story Dependencies

```
Phase 1 (Setup)
    â”?
    â–?
Phase 2 (Foundational) â”€â”€â”€â”€ BLOCKS ALL STORIES
    â”?
    â–?
Phase 3 (US1: Core Interception) â—€â”€â”€ ðŸŽ¯ MVP
    â”?
    â”œâ”€â”€â–?Phase 4 (US2: Custom Policy) â”€â”€â–?extends policy system
    â”?
    â”œâ”€â”€â–?Phase 5 (US3: CLI Feedback) â”€â”€â–?renders decisions
    â”?
    â”œâ”€â”€â–?Phase 6 (US4: Skill Permissions) â”€â”€â–?Phase 7 (US5: Static Scanning)
    â”?
    â””â”€â”€â–?Phase 8 (US6: Audit Logging) â”€â”€â–?logs pipeline events
    
    Phase 9 (Polish) â—€â”€â”€ after all stories
```

- **US2 and US3** can run in parallel after US1
- **US4 and US6** can run in parallel after US1
- **US5** must wait for US4 (needs manifest system for permission comparison)

### Within Each User Story

- Tests (where included) MUST be written and FAIL before implementation
- Models before services
- Services before entry points
- Core implementation before API integration
- Story complete before moving to next priority

### Parallel Opportunities

- **Phase 1**: T003 can run in parallel with T001/T002
- **Phase 2**: T004â€“T008 all in parallel (different files, no dependencies)
- **Phase 3**: T010â€“T013 all in parallel (tests + testdata, different files)
- **Phase 4**: T021â€“T022 in parallel; T025 in parallel with T023/T024
- **Phase 5**: T027â€“T028 in parallel (formatter + prompter, different files)
- **Phase 6**: T033â€“T037 all in parallel (tests + testdata + namespace + permissions)
- **Phase 7**: T042â€“T045 all in parallel (tests + testdata + models + patterns)
- **Phase 8**: T052â€“T054 all in parallel (tests + redactor + logger)
- **Phase 9**: T061, T062, T064 in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all tests + testdata in parallel:
Task: "T010 [P] [US1] Unit tests for matcher in tests/unit/test_matcher.py"
Task: "T011 [P] [US1] Unit tests for policy in tests/unit/test_policy.py"
Task: "T012 [P] [US1] Unit tests for decision in tests/unit/test_decision.py"
Task: "T013 [P] [US1] Test data in tests/testdata/"

# Then sequential implementation (dependency chain):
Task: "T014 [US1] Matcher engine in src/skillsecurity/engine/matcher.py"
Task: "T015 [US1] Policy loading in src/skillsecurity/engine/policy.py"
Task: "T016 [US1] Decision logic in src/skillsecurity/engine/decision.py"
Task: "T017 [US1] Default policy in policies/default.yaml"
Task: "T018 [US1] Interceptor in src/skillsecurity/engine/interceptor.py"
Task: "T019 [US1] SkillGuard API in src/skillsecurity/__init__.py"
Task: "T020 [US1] Integration test in tests/integration/test_engine_e2e.py"
```

## Parallel Example: After US1 Completes

```bash
# US2 and US3 can proceed in parallel (different subsystems):
Developer A: Phase 4 (US2 â€?Custom Policy: config loader + watcher)
Developer B: Phase 5 (US3 â€?CLI Feedback: formatter + prompter + commands)

# US4 and US6 can also proceed in parallel:
Developer A: Phase 6 (US4 â€?Skill Permissions: manifest + intersection model)
Developer B: Phase 8 (US6 â€?Audit Logging: logger + redactor + query)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL â€?blocks all stories)
3. Complete Phase 3: User Story 1 (core interception)
4. **STOP and VALIDATE**: `guard = SkillGuard(); guard.check({"tool": "shell", "command": "rm -rf /"})` â†?block
5. Deploy/demo if ready â€?system already provides core value

### Incremental Delivery

1. Setup + Foundational â†?Foundation ready
2. Add US1 (Core Interception) â†?Test independently â†?**MVP!** (Phase 1 complete)
3. Add US2 (Custom Policy) + US3 (CLI) in parallel â†?Test independently â†?Phase 1 fully done
4. Add US4 (Skill Permissions) â†?Test independently
5. Add US5 (Static Scanning) â†?Test independently
6. Add US6 (Audit Logging) â†?Test independently â†?Phase 2 fully done
7. Polish â†?Final validation â†?Release

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. One developer completes US1 (everyone depends on this)
3. Once US1 is done:
   - Developer A: US2 (Custom Policy) then US4 (Permissions)
   - Developer B: US3 (CLI Feedback) then US5 (Scanning, after US4)
   - Developer C: US6 (Audit Logging)
4. Stories complete and integrate independently

---

## Notes

- [P] tasks = different files, no dependencies on other in-progress tasks
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable
- Verify tests fail before implementing (where tests are included)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Fail-close default: if SkillGuard itself errors, check() returns Block (never crashes host)
