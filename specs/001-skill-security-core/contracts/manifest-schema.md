# Skill Manifest Schema (JSON)

**File**: `skill-manifest.json`  
**Format**: JSON

---

## Schema

```json
{
  "$schema": "https://skillsecurity.dev/schemas/skill-manifest-v1.json",

  "skill_id": "author/skill-name",
  "version": "1.0.0",
  "name": "Human Readable Name",
  "author": "author@example.com",
  "description": "What this skill does",

  "permissions": {
    "<permission_type>": {
      "description": "Why this permission is needed",
      "domains": ["allowed.domain.com"],
      "paths": ["/allowed/path/**"]
    }
  },

  "deny_permissions": ["<permission_type>"]
}
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `skill_id` | string | Yes | Namespaced ID: `author/skill-name` |
| `version` | string | Yes | Semver version |
| `name` | string | Yes | Display name |
| `author` | string | No | Author email or name |
| `description` | string | No | Skill description |
| `permissions` | object | Yes | Declared permissions (may be empty `{}`) |
| `deny_permissions` | string[] | No | Explicitly denied permissions |

## Permission Types

| Permission | Description | Constraints |
|------------|-------------|-------------|
| `file.read` | Read files | `paths`: glob patterns |
| `file.write` | Create/modify files | `paths`: glob patterns |
| `file.delete` | Delete files/dirs | `paths`: glob patterns |
| `shell` | Execute commands | (no constraints — full or nothing) |
| `network.read` | HTTP GET, DNS lookup | `domains`: allowed domains |
| `network.write` | HTTP POST/PUT/DELETE | `domains`: allowed domains |
| `message.send` | Email, IM, SMS | (no constraints) |
| `browser` | Browser automation | `domains`: allowed domains |
| `database.read` | DB SELECT queries | (no constraints) |
| `database.write` | DB INSERT/UPDATE/DELETE | (no constraints) |
| `env.read` | Read environment variables | (no constraints) |

## Skill ID Validation

- Format: `author/skill-name`
- `author`: `[a-z0-9][a-z0-9-]{2,49}`
- `skill-name`: `[a-z0-9][a-z0-9-]{2,99}`
- Total max length: 151 characters

## Intersection Model

When SkillSecurity evaluates a tool call tagged with a Skill ID:

```
1. Is permission declared? ──No──▶ BLOCK ("Skill has not declared {perm}")
2. Are constraints met?    ──No──▶ BLOCK ("Domain/path not in scope")
3. Pass to global policy   ──────▶ Normal policy evaluation
4. Final = permission ∩ policy    (both must allow)
```

## Example

```json
{
  "skill_id": "acme/weather-forecast",
  "version": "1.2.0",
  "name": "Weather Forecast",
  "author": "dev@acme.com",
  "description": "Fetches weather data from public APIs",

  "permissions": {
    "network.read": {
      "description": "Fetch weather data from API",
      "domains": ["api.openweathermap.org", "wttr.in"]
    }
  },

  "deny_permissions": [
    "shell",
    "file.write",
    "file.delete",
    "database.write",
    "env.read"
  ]
}
```

## Registration CLI

```bash
# Register from file
skillsecurity register ./weather-skill/skill-manifest.json

# List registered skills
skillsecurity skills list

# Show skill permissions
skillsecurity skills show acme/weather-forecast

# Unregister
skillsecurity skills remove acme/weather-forecast
```
