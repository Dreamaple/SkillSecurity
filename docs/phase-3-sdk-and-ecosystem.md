# Phase 3：多框架 SDK 与生态

> **周期**: 第 9-12 周  
> **前置**: Phase 1 + Phase 2 已完成  
> **目标**: 主流 AI 框架可快速集成，社区可贡献规则  
> **关联**: [主需求文档](../SkillSecurity需求规格说明书.md) / [架构概述](architecture-overview.md)

---

## 1. Phase 目标

完成后：
- LangChain / AutoGen 等框架 **3 行代码集成**
- 任意语言通过 **REST API** 即可使用
- 开发者可从 **模板库** 一键选用策略
- 社区可 **贡献和共享** 安全规则

---

## 2. 功能需求

### F6: 多框架适配

#### 2.1 集成方式总览

| 集成方式 | 适用场景 | 安装复杂度 | 性能 |
|---|---|---|---|
| Python SDK | Python 生态 AI 框架 | `pip install` | 嵌入式，最低延迟 |
| Node.js SDK | MCP / Web Agent 生态 | `npm install` | 嵌入式，最低延迟 |
| REST API | 任意语言 / 跨网络 | HTTP 调用 | 网络开销 |
| 框架原生插件 | 特定框架深度集成 | 框架 plugin | 最佳体验 |

#### 2.2 Python SDK

**安装**：

```bash
pip install skillsecurity
```

**基础用法**：

```python
from skillsecurity import SkillGuard

guard = SkillGuard()

# 检查单次调用
result = guard.check({
    "tool": "shell",
    "command": "rm -rf /tmp/data"
})

# 装饰器模式 - 自动拦截
@guard.protect
def execute_command(command: str):
    os.system(command)

# 上下文管理器模式
with guard.session(agent_id="my-agent") as session:
    session.check({"tool": "file.write", "path": "/tmp/out.txt"})
```

**LangChain 集成**：

```python
from skillsecurity.integrations import LangChainGuard

# 3 行代码启用
guard = LangChainGuard()
agent = create_agent(tools=[...])
guarded_agent = guard.wrap(agent)  # 所有工具调用自动拦截
```

**AutoGen 集成**：

```python
from skillsecurity.integrations import AutoGenGuard

guard = AutoGenGuard()
assistant = AssistantAgent("assistant", ...)
guard.protect(assistant)  # 拦截所有 function_call
```

**API 设计原则**：

| 原则 | 说明 |
|---|---|
| 零配置可用 | `SkillGuard()` 无参数即可使用默认策略 |
| 非侵入 | 不要求修改已有代码结构 |
| 可链式 | 支持 `guard.with_policy("strict").check(...)` |
| 异步支持 | 提供 `async check()` |
| 类型安全 | 完整的 type hints 和 TypedDict |

#### 2.3 Node.js SDK

**安装**：

```bash
npm install skillsecurity
```

**基础用法**：

```typescript
import { SkillGuard } from 'skillsecurity';

const guard = new SkillGuard();

// 检查单次调用
const result = await guard.check({
  tool: 'shell',
  command: 'rm -rf /tmp/data'
});

// 中间件模式（适配 MCP Server）
app.use(guard.middleware());
```

**MCP 集成**：

```typescript
import { SkillGuard } from 'skillsecurity';
import { McpServer } from '@modelcontextprotocol/sdk/server';

const guard = new SkillGuard();
const server = new McpServer({ name: 'my-server' });

// 拦截所有 MCP tool 调用
guard.protectMcpServer(server);
```

#### 2.4 REST API

对于其他语言或不想引入 SDK 的场景，提供 HTTP API：

**检查请求**：

```http
POST /api/v1/check
Content-Type: application/json
Authorization: Bearer <api-key>

{
  "tool_type": "shell",
  "operation": "exec",
  "params": {
    "command": "rm -rf /tmp/data"
  },
  "context": {
    "agent_id": "agent-001",
    "skill_id": "file-manager"
  }
}
```

**检查响应**：

```json
{
  "action": "block",
  "reason": "检测到递归删除命令",
  "severity": "critical",
  "rule_matched": "block-recursive-delete",
  "suggestions": ["使用精确路径删除特定文件"],
  "check_duration_ms": 3
}
```

**API 端点**：

| 端点 | 方法 | 描述 |
|---|---|---|
| `/api/v1/check` | POST | 检查工具调用 |
| `/api/v1/scan` | POST | 扫描 Skill 代码 |
| `/api/v1/skills` | GET/POST | 管理已注册 Skill |
| `/api/v1/policies` | GET/PUT | 查看/更新策略 |
| `/api/v1/logs` | GET | 查询审计日志 |
| `/api/v1/health` | GET | 健康检查 |

#### 2.5 验收标准

- [ ] Python SDK: `pip install` 后零配置可用
- [ ] Node.js SDK: `npm install` 后零配置可用
- [ ] LangChain 集成 ≤ 3 行代码
- [ ] MCP Server 集成 ≤ 3 行代码
- [ ] REST API 有完整的 OpenAPI 文档
- [ ] 每个框架有可运行的示例项目
- [ ] SDK 不引入对框架的硬依赖（框架为可选依赖）

---

### F8: 策略模板库

#### 2.6 概述

提供开箱即用的策略模板，覆盖常见使用场景，用户无需从零编写策略。

#### 2.7 内置模板

| 模板 | 文件名 | 适用场景 | 安全级别 |
|---|---|---|---|
| 默认 | `default.yaml` | 通用场景 | 中 |
| 严格 | `strict.yaml` | 生产环境 | 高 |
| 开发 | `development.yaml` | 本地开发 | 低 |
| 企业 | `enterprise.yaml` | 企业合规 | 高 |
| 最小 | `minimal.yaml` | 只拦截最危险的操作 | 极低 |

**模板之间的差异**：

| 行为 | default | strict | development | enterprise |
|---|---|---|---|---|
| `rm -rf` | Block | Block | Ask | Block |
| `sudo` | Ask | Block | Allow | Block |
| 写系统目录 | Block | Block | Ask | Block |
| 读 `.env` | Ask | Block | Allow | Block + Log |
| 网络请求 | Allow | Ask | Allow | Allow + Log |
| 审计日志 | 仅 Block | 全部 | 关闭 | 全部 |
| 默认动作 | Allow | Ask | Allow | Allow + Log |

#### 2.8 模板使用方式

```bash
# 查看可用模板
skillsecurity template list

# 使用指定模板
skillsecurity --policy=strict

# 基于模板创建自定义策略
skillsecurity template init --base=default --output=my-policy.yaml
```

```python
guard = SkillGuard(policy="strict")
# 或
guard = SkillGuard(policy_file="./my-policy.yaml")
```

#### 2.9 验收标准

- [ ] 每个模板有清晰的适用场景说明
- [ ] 模板经过测试，没有语法错误
- [ ] 用户可基于模板自定义（`template init`）
- [ ] 模板差异有对比文档

---

### F16: 社区规则共享

#### 2.10 概述

建立规则共享机制，让社区可以贡献和分享安全规则、扫描模式和策略配置。

#### 2.11 规则包格式

```
my-security-rules/
├── ruleset.yaml          # 规则包元信息
├── rules/
│   ├── crypto-safety.yaml    # 加密操作安全规则
│   └── cloud-api-safety.yaml # 云 API 调用安全规则
├── scan-patterns/
│   └── ml-framework.yaml     # ML 框架特有的扫描模式
└── README.md
```

```yaml
# ruleset.yaml
name: "ml-security-rules"
version: "1.0.0"
author: "community-contributor"
description: "机器学习场景的安全规则集"
tags: ["ml", "pytorch", "tensorflow"]
compatibility: "skillsecurity >= 0.2.0"
```

#### 2.12 规则包安装

```bash
# 从 GitHub 安装
skillsecurity rules install github:user/ml-security-rules

# 从本地安装
skillsecurity rules install ./my-rules/

# 查看已安装规则包
skillsecurity rules list

# 更新规则包
skillsecurity rules update
```

#### 2.13 共享威胁特征库

类似病毒特征库的更新机制：

| 特征类别 | 描述 | 更新频率 |
|---|---|---|
| 已知恶意 Skill | 社区报告的恶意 Skill 特征 | 实时（社区驱动） |
| 危险依赖 | 已知有漏洞的依赖版本 | 每日（对接 CVE 数据库） |
| 攻击模式 | 新发现的攻击手法特征 | 每周（安全团队维护） |

```bash
# 更新威胁特征库
skillsecurity signatures update

# 查看特征库版本
skillsecurity signatures info
```

#### 2.14 验收标准

- [ ] 规则包格式有明确规范
- [ ] 支持从 GitHub 一键安装规则包
- [ ] 已安装规则包可列出、更新、删除
- [ ] 威胁特征库可独立于软件版本更新
- [ ] 有贡献指南文档

---

## 3. 测试计划

### 3.1 SDK 测试

| 测试项 | 描述 |
|---|---|
| Python SDK | 基础 API、装饰器、上下文管理器 |
| Node.js SDK | 基础 API、中间件 |
| LangChain 集成 | 真实 LangChain Agent 的拦截验证 |
| MCP 集成 | 真实 MCP Server 的拦截验证 |
| REST API | OpenAPI 合规性、认证、错误处理 |

### 3.2 兼容性测试

| 测试项 | 描述 |
|---|---|
| Python 版本 | 3.9 / 3.10 / 3.11 / 3.12 |
| Node.js 版本 | 18 / 20 / 22 |
| 框架版本 | LangChain 最新 2 个大版本 |
| 操作系统 | Linux / macOS / Windows |

---

## 4. 交付物

| 交付物 | 说明 |
|---|---|
| Python SDK | PyPI 包 `skillsecurity` |
| Node.js SDK | npm 包 `skillsecurity` |
| REST API Server | Docker 镜像 |
| 策略模板 | 5 个内置模板 |
| 框架插件 | LangChain / AutoGen / MCP 集成 |
| 规则包管理 | CLI 命令 + 规则包格式规范 |
| 文档 | SDK 文档 + 集成指南 + 贡献指南 |

---

## 5. 里程碑

| 周 | 目标 | 产出 |
|---|---|---|
| 第 9 周 | Python SDK + LangChain 集成 | PyPI 包可安装 |
| 第 10 周 | Node.js SDK + MCP 集成 | npm 包可安装 |
| 第 11 周 | REST API + 策略模板库 | Server Docker 镜像 |
| 第 12 周 | 规则共享 + 测试 + 文档 | Phase 3 可发布 |
