# Phase 4：告警与用户交互

> **周期**: 第 13-16 周  
> **前置**: Phase 1-3 已完成  
> **目标**: 完善通知体系、用户确认流程和日志查询能力  
> **关联**: [主需求文档](../SkillSecurity需求规格说明书.md)

---

## 1. Phase 目标

完成后：
- 危险操作发生时 **多渠道实时告警**
- Ask 决策支持 **多种确认方式**（不仅限于 CLI）
- 审计日志支持 **复杂查询和导出**
- v1.0.0 可正式发布

---

## 2. 功能需求

### F5: 告警通知

#### 2.1 概述

当发生需要关注的安全事件时，向配置的渠道发送告警通知。Phase 1 仅有 CLI 输出，Phase 4 扩展为完整的告警体系。

#### 2.2 告警触发条件

| 事件 | 默认是否告警 | 严重程度 |
|---|---|---|
| 操作被 Block（critical） | 是 | 紧急 |
| 操作被 Block（high） | 是 | 重要 |
| 操作被 Block（medium/low） | 否 | 一般 |
| Ask 确认被用户拒绝 | 否 | 一般 |
| Ask 确认超时 | 是 | 重要 |
| 速率限制触发 | 是 | 重要 |
| Skill 越权操作 | 是 | 紧急 |
| 静态扫描发现 CRITICAL 问题 | 是 | 紧急 |
| 异常模式检测（Enterprise） | 是 | 紧急 |

#### 2.3 通知渠道

| 渠道 | 优先级 | 配置方式 |
|---|---|---|
| **Webhook** | Phase 4 首批 | URL + HTTP Method + Headers |
| **Slack** | Phase 4 首批 | Webhook URL |
| **飞书 / 钉钉** | Phase 4 首批 | Webhook URL |
| **Telegram** | Phase 4 | Bot Token + Chat ID |
| **Email** | Phase 4 | SMTP 配置 |
| **短信** | 可选 / 插件 | 通过 Webhook 对接 |

#### 2.4 通知内容格式

```json
{
  "event_type": "operation_blocked",
  "severity": "critical",
  "timestamp": "2026-03-11T03:15:00Z",
  "summary": "Agent 'data-agent' 的递归删除操作被拦截",
  "details": {
    "agent_id": "data-agent",
    "skill_id": "file-manager",
    "tool_type": "shell",
    "command": "rm -rf /important-data",
    "action": "block",
    "rule": "block-recursive-delete"
  },
  "recommendation": "检查 Agent 是否被 prompt injection 攻击"
}
```

**Slack / 飞书消息示例**：

```
🛑 [SkillSecurity] 操作已拦截

Agent: data-agent
Skill: file-manager  
操作: shell → rm -rf /important-data
规则: block-recursive-delete
时间: 2026-03-11 03:15:00

建议: 检查 Agent 是否被 prompt injection 攻击
```

#### 2.5 通知配置

```yaml
# skillsecurity.yaml 告警配置

alerts:
  enabled: true

  # 通知渠道
  channels:
    - id: "slack-security"
      type: slack
      webhook_url: "https://hooks.slack.com/services/xxx"
      events: [block_critical, block_high, permission_violation]

    - id: "webhook-siem"
      type: webhook
      url: "https://siem.company.com/api/events"
      method: POST
      headers:
        Authorization: "Bearer ${SIEM_TOKEN}"
      events: [all]

    - id: "feishu-ops"
      type: feishu
      webhook_url: "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
      events: [block_critical, rate_limit]

  # 告警策略
  throttle:
    max_alerts_per_minute: 10           # 防止告警风暴
    cooldown_seconds: 300               # 同一规则触发后冷却时间
    aggregate: true                     # 合并短时间内的相同告警

  # 降级
  fallback:
    on_channel_failure: log             # 渠道失败时: log / retry / ignore
    retry_count: 3
    retry_interval_seconds: 30
```

#### 2.6 验收标准

- [ ] 从事件发生到通知发出 < 10 秒
- [ ] Webhook 通知成功率 ≥ 99%（网络正常情况下）
- [ ] 通知失败不阻塞主拦截流程
- [ ] 告警限流正常工作（不产生告警风暴）
- [ ] 支持配置不同事件发到不同渠道
- [ ] 支持自定义通知渠道（插件机制）

---

### F7: 用户确认界面

#### 2.7 概述

当决策为 Ask 时，通过多种方式请求用户确认。Phase 1 仅支持 CLI stdin，Phase 4 扩展更多确认方式。

#### 2.8 确认方式

| 方式 | 适用场景 | 优先级 |
|---|---|---|
| CLI 交互 | 本地开发、终端运行 | Phase 1 已有 |
| Web 弹窗 | 有 Web 界面的场景 | Phase 4 |
| Slack/飞书 回复 | 团队协作场景 | Phase 4 |
| REST API 回调 | 自定义集成 | Phase 4 |

#### 2.9 Web 确认页面

当 Ask 触发时，生成一个临时确认页面：

```
┌─────────────────────────────────────────────┐
│  ⚠️  SkillSecurity - 操作确认               │
│                                             │
│  Agent "data-agent" 请求执行以下操作:         │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │ 工具: shell                         │    │
│  │ 命令: sudo systemctl restart nginx  │    │
│  │ 风险: HIGH                          │    │
│  │ 规则: ask-sudo                      │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  建议: 确认是否确实需要重启 nginx 服务        │
│                                             │
│  [✅ 允许执行]  [❌ 拒绝]  [🔒 始终拒绝]     │
│                                             │
│  ⏱️ 剩余时间: 45 秒                         │
└─────────────────────────────────────────────┘
```

#### 2.10 即时消息确认

**Slack 确认示例**：

```
⚠️ [SkillSecurity] 需要您的确认

Agent: data-agent
操作: sudo systemctl restart nginx
风险: HIGH

[允许] [拒绝] [始终拒绝]

⏱️ 60秒后自动拒绝
```

用户点击按钮后，SkillSecurity 通过 Webhook 回调接收结果。

#### 2.11 确认记忆

```yaml
# 记住用户选择
ask:
  remember:
    enabled: true
    scope: session              # session / agent / global
    max_entries: 100            # 最多记住多少条
    expiry_hours: 24            # 过期时间
```

| 记忆范围 | 说明 |
|---|---|
| `session` | 仅当前会话有效 |
| `agent` | 同一 Agent 的所有会话有效 |
| `global` | 所有 Agent 有效 |

#### 2.12 验收标准

- [ ] Web 确认页面可在 2 秒内加载
- [ ] Slack/飞书按钮点击 → 结果回调 < 3 秒
- [ ] 超时处理正确（默认 Block 或 Allow）
- [ ] "记住选择"功能按配置的范围和过期时间正确工作
- [ ] 用户可查看和撤销已记住的选择

---

### F9: 查询与导出

#### 2.13 概述

提供强大的审计日志查询和导出能力，满足合规审计和问题排查需求。

#### 2.14 查询能力

**CLI 查询**：

```bash
# 按时间范围查询
skillsecurity log query --since="2026-03-01" --until="2026-03-11"

# 按条件过滤
skillsecurity log query \
  --action=block \
  --severity=critical \
  --agent-id=data-agent \
  --tool-type=shell

# 分页
skillsecurity log query --limit=50 --offset=100

# 统计
skillsecurity log stats --group-by=action --since="2026-03-01"
```

**REST API 查询**：

```http
GET /api/v1/logs?action=block&severity=critical&since=2026-03-01&limit=50
Authorization: Bearer <api-key>
```

**响应**：

```json
{
  "total": 156,
  "offset": 0,
  "limit": 50,
  "items": [
    {
      "id": "log-20260311-031500-001",
      "timestamp": "2026-03-11T03:15:00Z",
      "action": "block",
      "severity": "critical",
      "tool_type": "shell",
      "agent_id": "data-agent",
      "summary": "递归删除被拦截"
    }
  ]
}
```

#### 2.15 统计报表

```bash
# 生成日报
skillsecurity log report --type=daily --date=2026-03-10

# 输出示例:
# SkillSecurity 日报 - 2026-03-10
# ─────────────────────────────
# 总检查次数:    1,234
# Allow:         1,180 (95.6%)
# Block:            42 (3.4%)
# Ask:              12 (1.0%)
#
# 风险分布:
#   Critical:        5
#   High:           15
#   Medium:         22
#   Low:            12
#
# Top 触发规则:
#   1. block-recursive-delete    (18 次)
#   2. ask-sudo                  (12 次)
#   3. block-system-paths         (8 次)
#
# Top Agent:
#   1. data-agent        (23 次 Block)
#   2. code-assistant     (8 次 Block)
```

#### 2.16 导出格式

| 格式 | 命令 | 适用场景 |
|---|---|---|
| JSON | `--format=json` | 程序处理 |
| JSONL | `--format=jsonl` | 流式处理 |
| CSV | `--format=csv` | Excel / 数据分析 |
| Table | `--format=table`（默认） | 终端查看 |

```bash
# 导出为 CSV
skillsecurity log query --action=block --format=csv > blocks.csv

# 导出为 JSON
skillsecurity log query --since="2026-03-01" --format=json > march-audit.json
```

#### 2.17 定时导出（可选）

```yaml
# 配置定时导出
audit:
  export:
    enabled: true
    schedule: "0 1 * * *"        # 每天凌晨 1 点
    format: csv
    output_dir: "./exports/"
    retention_days: 90
```

#### 2.18 性能要求

| 指标 | 目标 |
|---|---|
| 查询响应 | < 5 秒（100 万条日志内） |
| 导出速度 | ≥ 10,000 条/秒 |
| 统计计算 | < 10 秒（100 万条日志） |

#### 2.19 验收标准

- [ ] 支持按时间、动作、严重程度、Agent、工具类型过滤
- [ ] 分页查询正确（offset + limit）
- [ ] CSV 导出可被 Excel 正确打开（含中文）
- [ ] 统计报表数据准确
- [ ] 查询性能满足目标

---

## 3. v1.0.0 发布清单

Phase 4 完成后，SkillSecurity 达到 v1.0.0 发布标准：

### 3.1 功能完整性

| 能力 | 状态 | 来源 |
|---|---|---|
| 运行时工具调用拦截 | ✅ | Phase 1 |
| YAML 策略配置 | ✅ | Phase 1 |
| Allow / Block / Ask 决策 | ✅ | Phase 1 |
| CLI 输出 | ✅ | Phase 1 |
| Skill 权限声明 | ✅ | Phase 2 |
| Skill 静态扫描 | ✅ | Phase 2 |
| 审计日志 | ✅ | Phase 2 |
| Python / Node.js SDK | ✅ | Phase 3 |
| REST API | ✅ | Phase 3 |
| 框架集成（LangChain/MCP） | ✅ | Phase 3 |
| 策略模板库 | ✅ | Phase 3 |
| 社区规则共享 | ✅ | Phase 3 |
| 多渠道告警 | ✅ | Phase 4 |
| 多种确认方式 | ✅ | Phase 4 |
| 日志查询与导出 | ✅ | Phase 4 |

### 3.2 质量标准

| 指标 | 目标 |
|---|---|
| 单元测试覆盖率 | ≥ 80% |
| 集成测试 | 所有框架通过 |
| 性能测试 | 延迟和吞吐量达标 |
| 安全测试 | 无已知绕过漏洞 |
| 文档覆盖 | 快速开始 + API 文档 + FAQ + 贡献指南 |

### 3.3 发布产物

| 产物 | 渠道 |
|---|---|
| `skillsecurity` Python 包 | PyPI |
| `skillsecurity` npm 包 | npm |
| `skillsecurity` CLI 二进制 | GitHub Releases |
| `skillsecurity/server` Docker 镜像 | Docker Hub / GHCR |
| 文档站点 | GitHub Pages / 独立域名 |

---

## 4. 测试计划

### 4.1 告警测试

| 测试项 | 描述 |
|---|---|
| Webhook 投递 | 各种 HTTP 方法和 Header 组合 |
| Slack 集成 | 消息格式和投递成功率 |
| 飞书/钉钉 | Webhook 格式兼容性 |
| 限流 | 告警风暴时的限流行为 |
| 降级 | 渠道故障时的 fallback |

### 4.2 确认交互测试

| 测试项 | 描述 |
|---|---|
| Web 确认页面 | 加载速度、按钮响应、超时处理 |
| Slack 按钮 | 点击 → 回调 → 结果传递 |
| 记忆功能 | 范围、过期、撤销 |
| 并发 | 多个 Ask 同时等待确认 |

### 4.3 查询导出测试

| 测试项 | 描述 |
|---|---|
| 过滤准确性 | 各种条件组合的查询结果 |
| 分页 | offset/limit 边界情况 |
| 性能 | 大量日志下的查询响应时间 |
| CSV 编码 | 中文、特殊字符的正确性 |

---

## 5. 里程碑

| 周 | 目标 | 产出 |
|---|---|---|
| 第 13 周 | 告警引擎 + Webhook + Slack | 告警可工作 |
| 第 14 周 | 飞书/钉钉 + Web 确认页面 | 多渠道确认可工作 |
| 第 15 周 | 日志查询 + 导出 + 统计 | 查询和导出可用 |
| 第 16 周 | 集成测试 + 文档 + v1.0.0 发布 | 正式发布 |
