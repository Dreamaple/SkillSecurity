# Data Model: SkillSecurity Core

**Branch**: `001-skill-security-core` | **Date**: 2026-03-11

---

## 1. Core Entities

### 1.1 ToolCall

表示一次 AI Agent 的工具调用请求。

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool_type` | `ToolType` (enum) | Yes | 工具类型标识 |
| `operation` | `str` | No | 具体操作（如 exec, read, write） |
| `params` | `dict[str, Any]` | Yes | 操作参数（command, path, url 等） |
| `context` | `CallContext` | No | 调用上下文信息 |

**ToolType enum values**:
`shell`, `file.read`, `file.write`, `file.delete`, `network.request`, `message.send`, `browser`, `database`

**CallContext**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | `str` | No | Agent 标识 |
| `session_id` | `str` | No | 会话标识 |
| `skill_id` | `str` | No | Skill 标识（`author/name` 格式） |
| `user_id` | `str` | No | 用户标识 |
| `timestamp` | `datetime` | Auto | 调用时间（自动填充） |

---

### 1.2 Policy

从 YAML 文件加载的安全策略。

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | `str` | Yes | 策略格式版本（如 "1.0"） |
| `name` | `str` | Yes | 策略名称 |
| `description` | `str` | No | 策略描述 |
| `global_config` | `GlobalConfig` | Yes | 全局配置 |
| `rules` | `list[Rule]` | Yes | 有序规则列表 |
| `time_policies` | `list[TimePolicy]` | No | 时间策略 |
| `source_path` | `str` | Auto | 加载来源路径 |
| `loaded_at` | `datetime` | Auto | 加载时间 |

**GlobalConfig**:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_action` | `Action` | `allow` | 未匹配任何规则时的默认行为 |
| `log_level` | `str` | `info` | 日志级别 |
| `fail_behavior` | `Action` | `block` | 安全层故障时的行为（fail-close） |

---

### 1.3 Rule

策略中的单条规则。

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `str` | Yes | 规则唯一 ID |
| `description` | `str` | No | 规则描述 |
| `tool_type` | `str \| list[str]` | No | 匹配的工具类型（空则匹配所有） |
| `os` | `str` | No | 适用 OS：`unix` / `windows` / `all`（默认 `all`） |
| `match` | `MatchCondition` | No | 匹配条件 |
| `rate_limit` | `RateLimit` | No | 速率限制条件 |
| `action` | `Action` (enum) | Yes | 触发的动作 |
| `severity` | `Severity` (enum) | No | 风险等级（默认 `medium`） |
| `message` | `str` | No | 自定义提示消息 |
| `suggestions` | `list[str]` | No | 建议替代方案 |

**MatchCondition**:

| Field | Type | Description |
|-------|------|-------------|
| `command_pattern` | `str` (regex) | 命令正则匹配 |
| `path_pattern` | `str` (regex) | 路径正则匹配 |
| `url_pattern` | `str` (regex) | URL 正则匹配 |
| `param_pattern` | `str` (regex) | 参数通用正则匹配 |

**RateLimit**:

| Field | Type | Description |
|-------|------|-------------|
| `max_calls` | `int` | 窗口内最大调用次数 |
| `window_seconds` | `int` | 时间窗口（秒） |

**Action enum**: `allow`, `block`, `ask`

**Severity enum**: `low`, `medium`, `high`, `critical`

---

### 1.4 Decision

拦截引擎对一次工具调用的决策结果。

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | `Action` | Yes | 决策动作 |
| `reason` | `str` | Yes | 人类可读的原因 |
| `severity` | `Severity` | Yes | 风险等级 |
| `rule_matched` | `RuleRef \| None` | No | 匹配的规则引用 |
| `suggestions` | `list[str]` | No | 建议的替代方案 |
| `check_duration_ms` | `float` | Auto | 检查耗时（毫秒） |
| `timestamp` | `datetime` | Auto | 决策时间 |

**RuleRef**:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | 规则 ID |
| `description` | `str` | 规则描述 |

---

### 1.5 SkillManifest

Skill 开发者的权限声明文件。

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `skill_id` | `str` | Yes | 命名空间 ID（`author/skill-name`） |
| `version` | `str` | Yes | Skill 版本 |
| `name` | `str` | Yes | 显示名称 |
| `author` | `str` | No | 作者信息 |
| `description` | `str` | No | Skill 描述 |
| `permissions` | `dict[str, PermissionSpec]` | Yes | 声明的权限 |
| `deny_permissions` | `list[str]` | No | 明确拒绝的权限 |

**PermissionSpec**:

| Field | Type | Description |
|-------|------|-------------|
| `description` | `str` | 权限用途说明 |
| `domains` | `list[str]` | 允许的域名（network 权限） |
| `paths` | `list[str]` | 允许的路径 glob（file 权限） |

**Skill ID validation rules**:
- 格式：`author/skill-name`
- `author`：3-50 字符，字母数字和连字符
- `skill-name`：3-100 字符，字母数字和连字符
- 全部小写

---

### 1.6 ScanReport

静态扫描的结果报告。

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `skill_id` | `str` | No | 被扫描 Skill 的 ID |
| `scan_time` | `datetime` | Auto | 扫描时间 |
| `risk_level` | `RiskLevel` (enum) | Yes | 综合风险等级 |
| `summary` | `ScanSummary` | Yes | 扫描摘要 |
| `issues` | `list[ScanIssue]` | Yes | 发现的问题列表 |
| `permission_analysis` | `PermissionAnalysis \| None` | No | 权限比对分析 |

**RiskLevel enum**: `safe`, `low`, `medium`, `high`, `critical`

**ScanSummary**:

| Field | Type | Description |
|-------|------|-------------|
| `files_scanned` | `int` | 扫描的文件数 |
| `issues_found` | `int` | 发现问题总数 |
| `critical` | `int` | critical 级别问题数 |
| `high` | `int` | high 级别问题数 |
| `medium` | `int` | medium 级别问题数 |
| `low` | `int` | low 级别问题数 |

**ScanIssue**:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | 扫描规则 ID |
| `severity` | `Severity` | 严重程度 |
| `file` | `str` | 文件路径 |
| `line` | `int` | 行号 |
| `code` | `str` | 匹配的代码片段 |
| `description` | `str` | 问题描述 |
| `recommendation` | `str` | 修复建议 |

**PermissionAnalysis**:

| Field | Type | Description |
|-------|------|-------------|
| `declared` | `list[str]` | 清单中声明的权限 |
| `detected` | `list[str]` | 代码中检测到的权限使用 |
| `undeclared` | `list[str]` | 使用但未声明的权限 |
| `verdict` | `str` | 分析结论 |

---

### 1.7 AuditLogEntry

审计日志中的单条记录。

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `str` | Auto | 唯一日志 ID（时间戳 + 序号） |
| `timestamp` | `datetime` | Auto | 事件时间 |
| `event_type` | `str` | Yes | 事件类型（`tool_call_check`, `scan`, `config_reload`） |
| `agent` | `AgentInfo` | No | Agent 信息 |
| `skill` | `SkillInfo` | No | Skill 信息 |
| `request` | `dict` | Yes | 原始请求（已脱敏） |
| `decision` | `DecisionInfo` | Yes | 决策结果 |
| `user` | `UserInfo` | No | 用户信息 |

---

## 2. Entity Relationships

```
ToolCall ─────────── checked by ──────────▶ Engine
   │                                          │
   │ has context                              │ loads
   ▼                                          ▼
CallContext                                Policy
   │                                          │
   │ references                               │ contains
   ▼                                          ▼
SkillManifest ◀── permission check ──── Rule (ordered)
   │                                          │
   │ scanned by                               │ produces
   ▼                                          ▼
ScanReport                               Decision
                                              │
                                              │ logged as
                                              ▼
                                        AuditLogEntry
```

## 3. Decision Flow (Intersection Model)

```
ToolCall arrives
       │
       ▼
[Self-protection check]──▶ target is protected path? ──Yes──▶ BLOCK (unconditional)
       │ No
       ▼
[Skill permission check]──▶ skill_id present & manifest registered?
       │                         │ Yes
       │ No (skip)               ▼
       │                    operation within declared permissions?
       │                         │ No ──▶ BLOCK (permission violation)
       │                         │ Yes
       │◀────────────────────────┘
       ▼
[Global policy matching]──▶ iterate rules (first-match-wins)
       │
       ▼
  matched? ──No──▶ global.default_action
       │ Yes
       ▼
  rule.action (allow / block / ask)
       │
       ▼
[Rate limit check]──▶ exceeded? ──Yes──▶ BLOCK
       │ No
       ▼
  Final Decision ──▶ log to AuditLogEntry
```
