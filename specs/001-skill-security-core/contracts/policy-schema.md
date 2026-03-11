# Policy File Schema (YAML)

**File**: `skillsecurity.yaml` or custom path  
**Format**: YAML 1.1

---

## Schema

```yaml
# Required
version: "1.0"                    # Schema version
name: "string"                    # Policy name

# Optional
description: "string"             # Human-readable description

# Global configuration
global:
  default_action: allow           # allow | block | ask (default: allow)
  log_level: info                 # debug | info | warn | error
  fail_behavior: block            # allow | block (default: block, fail-close)

# Ordered rule list (first-match-wins)
rules:
  - id: "string"                  # REQUIRED - Unique rule ID
    description: "string"         # Optional
    tool_type: "string | [string]" # Optional - tool type(s) to match
    os: "string"                  # Optional - unix | windows | all (default: all)
    match:                        # Optional - at least one sub-field if present
      command_pattern: "regex"    # Regex for command matching
      path_pattern: "regex"       # Regex for file path matching
      url_pattern: "regex"        # Regex for URL matching
      param_pattern: "regex"      # Regex for generic parameter matching
    rate_limit:                   # Optional - mutually exclusive with match
      max_calls: integer          # Max calls in window
      window_seconds: integer     # Time window in seconds
    action: "string"              # REQUIRED - allow | block | ask
    severity: "string"            # Optional - low | medium | high | critical (default: medium)
    message: "string"             # Optional - custom message
    suggestions:                  # Optional
      - "string"

# Time-based policy overrides (optional)
time_policies:
  - id: "string"
    description: "string"
    schedule:
      hours: [integer]            # 0-23
      days: [string]              # mon, tue, wed, thu, fri, sat, sun
    override:
      default_action: "string"    # Overrides global.default_action during schedule

# Skill permission settings (Phase 2)
permissions:
  enforce: boolean                # Enable permission checking (default: true)
  default_policy: "string"       # For unregistered Skills: allow | ask | block (default: ask)
  manifest_dir: "string"         # Directory for manifest files

# Audit settings (Phase 2)
audit:
  enabled: boolean                # default: true
  format: "string"                # jsonl (default)
  output: "string"                # File path (default: ./logs/skillsecurity-audit.jsonl)
  rotation:
    max_size: "string"            # e.g., "100MB"
    max_files: integer            # e.g., 10
    max_age_days: integer         # e.g., 30
  redact:
    enabled: boolean              # default: true
    patterns:                     # Additional redaction regex patterns
      - "regex"

# Scanner settings (Phase 2)
scanner:
  enabled: boolean                # default: true
  auto_scan_on_install: boolean   # default: true
  block_on_critical: boolean      # Auto-reject install on CRITICAL finding (default: true)
  custom_rules: "string"         # Path to custom scan rules YAML
```

## Validation Rules

| Rule | Error |
|------|-------|
| `version` missing | "Missing required field: version" |
| Unknown `action` value | "Invalid action '{value}' at rule '{id}', valid: allow, block, ask" |
| Duplicate rule `id` | "Duplicate rule ID: '{id}'" |
| Invalid regex in `match` | "Invalid regex in rule '{id}' field '{field}': {error}" |
| `rate_limit` with negative values | "rate_limit.max_calls must be positive in rule '{id}'" |
| Empty `rules` list | Warning (not error), falls back to default_action |

## Example: Default Policy (excerpt)

```yaml
version: "1.0"
name: "default"
description: "Default security policy - balanced safety and usability"

global:
  default_action: allow
  fail_behavior: block

rules:
  - id: "block-recursive-delete-unix"
    os: unix
    tool_type: shell
    match:
      command_pattern: "rm\\s+.*(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)"
    action: block
    severity: critical
    message: "Recursive deletion detected"
    suggestions:
      - "Use a precise file path instead"
      - "List files first with: ls <path>"

  - id: "block-recursive-delete-windows"
    os: windows
    tool_type: shell
    match:
      command_pattern: "(del\\s+/s|rd\\s+/s|rmdir\\s+/s)"
    action: block
    severity: critical
    message: "Recursive deletion detected"

  - id: "ask-privilege-escalation"
    tool_type: shell
    match:
      command_pattern: "^(sudo|runas)\\s"
    action: ask
    severity: high
    message: "Privilege escalation operation"

  - id: "block-system-paths"
    tool_type: [file.write, file.delete]
    match:
      path_pattern: "^(/etc|/System|/boot|C:\\\\Windows|C:\\\\Program Files)"
    action: block
    severity: critical
    message: "System directory modification blocked"
```
