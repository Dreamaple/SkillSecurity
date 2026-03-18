# SkillSecurity 文档索引

> AI Agent Skill/工具调用的安全防护层——Skill 的"杀毒软件"

---

## 文档结构

```
SkillSecurity/
├── SkillSecurity需求规格说明书.md     ← 主文档（总览）
└── docs/
    ├── README.md                     ← 本文件（索引）
    ├── how-it-works.md               ← 设计原理与集成指南
    ├── threat-model.md               ← 威胁模型（八类威胁）
    ├── architecture-overview.md      ← 架构概述
    ├── data-classification-engine.md ← 数据分类与隐私保护层
    ├── phase-1-core-interception.md  ← Phase 1: 核心拦截引擎
    ├── phase-2-permission-and-audit.md ← Phase 2: 权限声明与审计
    ├── phase-3-sdk-and-ecosystem.md  ← Phase 3: 多框架 SDK 与生态
    ├── phase-4-alert-and-interaction.md ← Phase 4: 告警与用户交互
    ├── tier-pro-enterprise.md        ← Pro/Enterprise 扩展层
    ├── openclaw-risk-assessment-zh.md ← OpenClaw 风险预警对照评估与加固方案
    ├── unfinished-features-and-ux-plan-zh.md ← 当前未完成功能清单与交互方案
    └── feishu-approval-integration-todo-zh.md ← 飞书审批接入执行清单
```

---

## 阅读顺序

### 了解项目（先读这些）

| 顺序 | 文档 | 内容 | 阅读时间 |
|---|---|---|---|
| 1 | [设计原理](how-it-works.md) | 工作原理、拦截机制、Agent 集成、自定义配置 | 12 分钟 |
| 2 | [主需求文档](../SkillSecurity需求规格说明书.md) | 产品愿景、目标用户、功能总览、成功指标 | 10 分钟 |
| 3 | [威胁模型](threat-model.md) | 八类威胁分析、防御策略、风险评级 | 10 分钟 |
| 4 | [架构概述](architecture-overview.md) | 系统架构、集成模式、技术选型、部署方案 | 10 分钟 |
| 5 | [数据分类引擎](data-classification-engine.md) | 敏感数据检测、聊天保护、出站检查、域名信誉 | 8 分钟 |
| 6 | [OpenClaw 风险评估](openclaw-risk-assessment-zh.md) | OpenClaw 官方预警对照、可防范围、能力缺口、加固路线 | 8 分钟 |
| 7 | [未完成功能与交互方案](unfinished-features-and-ux-plan-zh.md) | 当前缺口盘点、allow 用户确认方案、两周实施路径 | 8 分钟 |
| 8 | [飞书审批接入代办](feishu-approval-integration-todo-zh.md) | 飞书官方 SDK 接入、回调按钮审批、测试与发布清单 | 6 分钟 |

### 按阶段实施（开发时按需阅读）

| 阶段 | 文档 | 周期 | 核心交付 |
|---|---|---|---|
| Phase 1 | [核心拦截引擎](phase-1-core-interception.md) | 第 1-4 周 | 拦截 + 策略 + 决策 + CLI |
| Phase 2 | [权限声明与审计](phase-2-permission-and-audit.md) | 第 5-8 周 | 权限清单 + 静态扫描 + 审计日志 |
| Phase 3 | [多框架 SDK 与生态](phase-3-sdk-and-ecosystem.md) | 第 9-12 周 | Python/Node SDK + REST API + 模板库 |
| Phase 4 | [告警与用户交互](phase-4-alert-and-interaction.md) | 第 13-16 周 | 多渠道告警 + 确认界面 + 查询导出 → v1.0.0 |
| 扩展 | [Pro/Enterprise](tier-pro-enterprise.md) | v1.0 之后 | Web 界面 + 异常检测 + 沙箱 + SSO |

---

## 项目时间线

```
第 1 周 ─────── Phase 1: 核心拦截引擎 ───────── 第 4 周
                        │
第 5 周 ─────── Phase 2: 权限声明与审计 ──────── 第 8 周
                        │
第 9 周 ─────── Phase 3: SDK 与生态 ────────── 第 12 周
                        │
第 13 周 ────── Phase 4: 告警与交互 ────────── 第 16 周
                        │
                   v1.0.0 发布
                        │
               Pro / Enterprise 持续迭代
```

---

## 产品分层

```
┌─────────────────────────────────────────────┐
│  Enterprise  │ SSO / GDPR / 异常检测 / 沙箱  │
├─────────────────────────────────────────────┤
│  Pro         │ Web 界面 / 性能优化            │
├─────────────────────────────────────────────┤
│  Core        │ 拦截 / 策略 / 权限 / 扫描      │  ← 永久开源
│  (开源)      │ SDK / 告警 / 审计 / 查询       │     Apache 2.0
└─────────────────────────────────────────────┘
```

---

## 贡献指南

（待 Phase 3 社区规则共享功能完成后补充）

---

## 版本历史

| 版本 | 日期 | 变更 |
|---|---|---|
| v0.4.0 | 2026-03-11 | 新增聊天记录保护、设计原理文档、开源准备 |
| v0.3.0 | 2026-03-11 | 新增隐私保护、财务安全、数据分类引擎 |
| v0.2.0 | 2026-03-11 | 重构文档结构，增加威胁模型、架构概述，按阶段拆分需求 |
| v0.1.0 | 2026-03-11 | 初始需求文档 |
