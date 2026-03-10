# Phase 2：权限声明与审计

> **周期**: 第 5-8 周  
> **前置**: Phase 1 核心拦截引擎已完成  
> **目标**: Skill 有权限边界，操作可追溯  
> **关联**: [主需求文档](../SkillSecurity需求规格说明书.md) / [威胁模型](threat-model.md) T1(恶意 Skill)

---

## 1. Phase 目标

完成后，用户可以做到：

```python
from skillsecurity import SkillGuard

guard = SkillGuard()

# 安装 Skill 前扫描
scan_result = guard.scan_skill("./weather-skill/")
print(scan_result)
# ScanResult(
#   risk_level="safe",
#   permissions_declared=["network.read"],
#   permissions_detected=["network.read"],
#   issues=[]
# )

# 注册 Skill 的权限边界
guard.register_skill("weather-skill", manifest="./weather-skill/skill-manifest.json")

# 运行时自动按权限拦截（weather-skill 尝试写文件会被 Block）
result = guard.check({
    "tool": "file.write",
    "path": "/tmp/data.txt",
    "skill_id": "weather-skill"
})
# result.action == "block"
# result.reason == "Skill 'weather-skill' 未声明 file.write 权限"
```

---

## 2. 功能需求

### F12: Skill 权限声明

#### 2.1 概述

每个 Skill 通过一份清单文件（`skill-manifest.json`）声明自己需要的权限。SkillSecurity 在安装时向用户展示权限范围，在运行时强制执行权限边界。

这类似于 Android 应用的权限系统：安装时告知，运行时强制。

#### 2.2 权限清单格式

```json
{
  "$schema": "https://skillsecurity.dev/schemas/skill-manifest-v1.json",
  "skill_id": "weather-skill",
  "version": "1.0.0",
  "name": "Weather Skill",
  "author": "developer@example.com",
  "description": "获取天气信息",

  "permissions": {
    "network.read": {
      "description": "调用天气 API",
      "domains": ["api.openweathermap.org", "wttr.in"]
    }
  },

  "deny_permissions": [
    "shell",
    "file.write",
    "file.delete",
    "database"
  ]
}
```

#### 2.3 权限类型定义

| 权限标识 | 描述 | 风险级别 |
|---|---|---|
| `file.read` | 读取文件 | LOW |
| `file.write` | 创建/修改文件 | MEDIUM |
| `file.delete` | 删除文件/目录 | HIGH |
| `shell` | 执行命令 | HIGH |
| `network.read` | 发起 HTTP GET 等只读请求 | LOW |
| `network.write` | 发起 HTTP POST/PUT/DELETE 等写入请求 | MEDIUM |
| `message.send` | 发送消息（邮件/IM/SMS） | MEDIUM |
| `browser` | 浏览器控制 | MEDIUM |
| `database.read` | 数据库只读查询 | LOW |
| `database.write` | 数据库增删改 | HIGH |
| `env.read` | 读取环境变量 | MEDIUM |

#### 2.4 权限约束

权限可以附带约束条件，缩小实际范围：

```json
{
  "permissions": {
    "file.read": {
      "paths": ["/data/input/**"],
      "description": "读取输入数据"
    },
    "file.write": {
      "paths": ["/data/output/**"],
      "description": "写入处理结果"
    },
    "network.read": {
      "domains": ["api.example.com"],
      "description": "调用业务 API"
    }
  }
}
```

#### 2.5 安装时权限展示

当用户安装一个 Skill 时，展示其权限需求：

```
📦 安装 Skill: data-processor v1.2.0

请求的权限:
  ✅ file.read      - 读取 /data/input/** 下的文件
  ⚠️  file.write     - 写入 /data/output/** 下的文件
  ✅ network.read   - 访问 api.example.com

明确拒绝:
  🚫 shell          - 不需要命令执行
  🚫 file.delete    - 不需要删除文件

风险评估: LOW
是否安装? [Y/n]
```

#### 2.6 运行时权限强制

| 场景 | 行为 |
|---|---|
| 操作在声明权限内 | Allow（继续正常拦截流程） |
| 操作超出声明权限 | Block，原因 "Skill 未声明此权限" |
| 操作在 `deny_permissions` 中 | Block，原因 "Skill 明确拒绝此权限" |
| Skill 未注册清单 | 退回普通策略匹配（向后兼容） |
| 操作在权限内但触发了策略规则 | 策略规则优先（双重检查） |

#### 2.7 验收标准

- [ ] `skill-manifest.json` 有明确的 JSON Schema 定义
- [ ] 安装时有清晰的权限展示（CLI 输出）
- [ ] 越权操作被 Block 且有明确原因
- [ ] 未注册清单的 Skill 向后兼容（不强制要求清单）
- [ ] 权限约束（paths/domains）生效

---

### F15: Skill 静态扫描

#### 2.8 概述

在 Skill 安装前对其代码进行静态分析，识别潜在的危险行为。这是"杀毒软件"的核心能力——安装前先扫一遍。

#### 2.9 扫描范围

| 扫描项 | 描述 | 风险标记 |
|---|---|---|
| 危险 API 调用 | `os.system`, `subprocess`, `eval`, `exec` | HIGH |
| 数据外泄模式 | HTTP 请求中携带环境变量/文件内容 | CRITICAL |
| 代码混淆 | Base64 编码的 eval、动态 import | HIGH |
| 反向 shell | Socket 连接 + shell 执行 | CRITICAL |
| 环境变量访问 | 读取 `API_KEY`, `TOKEN`, `SECRET` 等 | MEDIUM |
| 文件系统操作 | 非声明范围内的文件读写 | MEDIUM |
| 网络操作 | 非声明域名的网络请求 | MEDIUM |

#### 2.10 扫描引擎设计

```
Skill 代码
    │
    ▼
┌──────────────┐
│  文件遍历     │  递归扫描所有代码文件
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  模式匹配     │  正则表达式匹配危险模式
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  权限比对     │  实际行为 vs 声明权限，检查是否一致
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  生成报告     │  Risk Level + 详细发现列表
└──────────────┘
```

#### 2.11 扫描规则示例

```yaml
# scan-rules.yaml

scan_rules:
  - id: "dangerous-eval"
    description: "检测 eval/exec 动态代码执行"
    languages: ["python", "javascript"]
    patterns:
      python:
        - "eval\\("
        - "exec\\("
        - "__import__\\("
      javascript:
        - "eval\\("
        - "new Function\\("
    severity: high
    recommendation: "避免使用动态代码执行，使用安全的替代方案"

  - id: "env-access"
    description: "检测环境变量访问"
    languages: ["python", "javascript"]
    patterns:
      python:
        - "os\\.environ"
        - "os\\.getenv"
      javascript:
        - "process\\.env"
    severity: medium
    recommendation: "确认是否需要访问环境变量，如需要请在 manifest 中声明 env.read"

  - id: "data-exfil"
    description: "检测潜在数据外泄"
    languages: ["python", "javascript"]
    patterns:
      python:
        - "requests\\.(post|put).*os\\.environ"
        - "urllib.*open.*os\\.environ"
      javascript:
        - "fetch.*process\\.env"
        - "axios\\.(post|put).*process\\.env"
    severity: critical
    recommendation: "代码中存在将环境变量通过网络发送的模式，极高风险"
```

#### 2.12 扫描报告格式

```json
{
  "skill_id": "suspicious-skill",
  "scan_time": "2026-03-11T10:30:00Z",
  "risk_level": "high",
  "summary": {
    "files_scanned": 12,
    "issues_found": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  },
  "issues": [
    {
      "id": "data-exfil",
      "severity": "critical",
      "file": "src/main.py",
      "line": 42,
      "code": "requests.post(url, data={'token': os.environ['API_KEY']})",
      "description": "检测到将环境变量通过 HTTP POST 发送",
      "recommendation": "移除此行为，或确认这是预期功能"
    }
  ],
  "permission_analysis": {
    "declared": ["network.read"],
    "detected": ["network.read", "network.write", "env.read"],
    "undeclared": ["network.write", "env.read"],
    "verdict": "Skill 实际使用了未声明的权限"
  }
}
```

#### 2.13 CLI 扫描输出

```
$ skillsecurity scan ./suspicious-skill/

🔍 扫描 Skill: suspicious-skill
   文件数: 12
   扫描耗时: 230ms

⛔ 风险等级: HIGH

发现问题:
  1. [CRITICAL] src/main.py:42 - 数据外泄风险
     requests.post(url, data={'token': os.environ['API_KEY']})
     → 检测到将环境变量通过 HTTP POST 发送

  2. [HIGH] src/utils.py:15 - 动态代码执行
     eval(user_input)
     → 避免使用 eval，使用安全的替代方案

  3. [MEDIUM] src/config.py:8 - 未声明的环境变量访问
     os.environ.get('SECRET_KEY')
     → 请在 manifest 中声明 env.read 权限

权限分析:
  声明权限: network.read
  实际使用: network.read, network.write, env.read
  ⚠️  未声明权限: network.write, env.read

建议: 不建议安装此 Skill，存在数据外泄风险
```

#### 2.14 验收标准

- [ ] 支持扫描 Python 和 JavaScript/TypeScript 代码
- [ ] 能检测上述所有危险模式类别
- [ ] 扫描 1000 行代码 < 5 秒
- [ ] 权限比对能发现未声明的权限使用
- [ ] 扫描报告有明确的风险等级和建议
- [ ] 误报率 < 10%（需通过测试集验证）

---

### F4: 审计日志

#### 2.15 概述

记录所有工具调用和 SkillSecurity 的决策，支持事后追溯和合规审计。

#### 2.16 日志内容

每条日志记录包含：

```json
{
  "id": "log-20260311-103000-001",
  "timestamp": "2026-03-11T10:30:00.003Z",
  "event_type": "tool_call_check",

  "agent": {
    "agent_id": "agent-001",
    "session_id": "sess-abc123"
  },

  "skill": {
    "skill_id": "file-manager-v1",
    "version": "1.0.0"
  },

  "request": {
    "tool_type": "shell",
    "operation": "exec",
    "params": {
      "command": "rm -rf /tmp/data"
    }
  },

  "decision": {
    "action": "block",
    "reason": "检测到递归删除命令",
    "rule_matched": "block-recursive-delete",
    "severity": "critical",
    "check_duration_ms": 3
  },

  "user": {
    "user_id": "user-001",
    "confirmed": null
  }
}
```

#### 2.17 敏感信息脱敏

日志写入前自动脱敏：

| 原始内容 | 脱敏后 |
|---|---|
| `password=abc123` | `password=***` |
| `token=sk-1234abcd` | `token=sk-****abcd` |
| `Authorization: Bearer eyJ...` | `Authorization: Bearer ***` |
| `api_key=AKIAIOSFODNN7` | `api_key=AKIA****ODNN7` |

脱敏规则可配置，支持自定义正则模式。

#### 2.18 日志存储

| 配置项 | 说明 | 默认值 |
|---|---|---|
| `audit.enabled` | 是否启用审计日志 | true |
| `audit.format` | 日志格式 | jsonl |
| `audit.output` | 输出目标 | `./logs/skillsecurity-audit.jsonl` |
| `audit.rotation.max_size` | 单文件最大大小 | 100MB |
| `audit.rotation.max_files` | 最多保留文件数 | 10 |
| `audit.rotation.max_age_days` | 最长保留天数 | 30 |
| `audit.redact.enabled` | 是否启用脱敏 | true |
| `audit.redact.patterns` | 自定义脱敏正则 | 内置默认 |

#### 2.19 日志查询（基础）

Phase 2 提供基础的 CLI 查询能力：

```bash
# 查看最近 10 条 Block 记录
skillsecurity log --action=block --limit=10

# 查看特定 Agent 的所有操作
skillsecurity log --agent-id=agent-001

# 查看特定时间范围
skillsecurity log --since="2026-03-10" --until="2026-03-11"

# 输出为 JSON 供其他工具处理
skillsecurity log --action=block --format=json | jq '.decision.reason'
```

#### 2.20 验收标准

- [ ] 每条日志可追溯到具体的调用和决策
- [ ] 日志文件可被 `jq`、`grep` 等常见工具解析
- [ ] 脱敏后无法还原原始敏感信息
- [ ] 日志写入异步执行，不阻塞拦截流程
- [ ] 日志轮转正确工作（大小、数量、天数）
- [ ] Agent 崩溃后日志不丢失（写入缓冲合理）

---

## 3. 策略配置扩展

Phase 2 在 Phase 1 的策略配置基础上增加权限相关配置：

```yaml
# skillsecurity.yaml 新增内容

# Skill 权限管理
permissions:
  enforce: true                    # 是否强制权限检查
  default_policy: ask              # 未注册 Skill 的默认权限策略
  manifest_dir: "./skill-manifests" # 清单文件目录

# 静态扫描配置
scanner:
  enabled: true
  auto_scan_on_install: true       # 安装时自动扫描
  block_on_critical: true          # 发现 CRITICAL 问题自动拒绝安装
  custom_rules: "./scan-rules.yaml" # 自定义扫描规则

# 审计日志配置
audit:
  enabled: true
  format: jsonl
  output: "./logs/skillsecurity-audit.jsonl"
  rotation:
    max_size: "100MB"
    max_files: 10
    max_age_days: 30
  redact:
    enabled: true
    patterns:
      - "(password|passwd|pwd)=\\S+"
      - "(token|api_key|secret)=\\S+"
      - "Bearer\\s+\\S+"
```

---

## 4. 测试计划

### 4.1 权限声明测试

| 测试项 | 描述 |
|---|---|
| 清单解析 | 各种合法/非法清单文件的解析 |
| 权限匹配 | 操作与声明权限的匹配逻辑 |
| 越权拦截 | 越权操作被正确 Block |
| 向后兼容 | 无清单 Skill 不受影响 |
| 约束生效 | paths/domains 约束正确限制 |

### 4.2 静态扫描测试

| 测试项 | 描述 |
|---|---|
| 检测准确性 | 已知危险模式是否被检出 |
| 误报测试 | 安全代码是否被误报 |
| 权限比对 | 声明 vs 实际使用的分析准确性 |
| 多语言支持 | Python 和 JS 代码的扫描 |
| 性能测试 | 大型 Skill 的扫描耗时 |

### 4.3 审计日志测试

| 测试项 | 描述 |
|---|---|
| 日志完整性 | 所有操作都被记录 |
| 脱敏正确性 | 敏感信息被正确遮蔽 |
| 日志轮转 | 大小/数量/天数轮转正确 |
| 异步性能 | 日志写入不阻塞主流程 |
| 崩溃恢复 | 进程崩溃后日志不丢失 |

---

## 5. 交付物

| 交付物 | 说明 |
|---|---|
| 权限管理模块 | 清单解析 + 权限匹配 + 越权拦截 |
| 静态扫描引擎 | 代码扫描 + 权限比对 + 报告生成 |
| 审计日志模块 | 异步写入 + 脱敏 + 轮转 |
| 默认扫描规则 | `scan-rules.yaml` |
| JSON Schema | `skill-manifest-v1.json` |
| CLI 命令 | `skillsecurity scan` / `skillsecurity log` |
| 文档 | 权限声明指南 + 扫描规则编写 + 日志查询 |

---

## 6. 里程碑

| 周 | 目标 | 产出 |
|---|---|---|
| 第 5 周 | 权限清单 + 权限匹配 | `skill-manifest.json` 解析和权限检查 |
| 第 6 周 | 静态扫描引擎 | 代码扫描 + 报告生成 |
| 第 7 周 | 审计日志 | 异步写入 + 脱敏 + 轮转 |
| 第 8 周 | 测试 + CLI 命令 + 文档 | Phase 2 可发布 |
