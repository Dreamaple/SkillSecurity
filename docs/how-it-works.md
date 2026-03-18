# SkillSecurity 设计原理

> **版本**: 0.4.0  
> **日期**: 2026-03-11  
> **目的**: 帮助开发者理解 SkillSecurity 的工作原理、集成方式与自定义配置

---

## 1. 核心思想：工具调用的"防火墙"

### 1.1 问题背景

当下的 AI Agent（如 LangChain、OpenClaw、AutoGPT、CrewAI 等）本质上是一个 **LLM + 工具调用** 的组合。LLM 负责思考和决策，工具（Skill/Tool）负责执行实际操作——读写文件、执行命令、发送网络请求、操作浏览器等。

```
用户提问 → LLM 思考 → 决定调用工具 → 工具执行 → 返回结果
```

**风险在于**：LLM 决定调用什么工具、传什么参数，这个过程没有任何安全检查。一个恶意或有缺陷的 Skill 可以：

- 执行 `rm -rf /` 删除整个文件系统
- 读取 `.env` 中的 API Key 并 POST 到外部服务器
- 调用 Stripe API 发起一笔支付
- 偷偷读取聊天记录并外发

### 1.2 SkillSecurity 的定位

SkillSecurity 就像传统操作系统中的防火墙，插在 **"LLM 决策"和"工具实际执行"之间**：

```
用户提问 → LLM 思考 → 决定调用工具
                              │
                              ▼
                    ┌──────────────────┐
                    │  SkillSecurity   │ ← 安全检查层
                    │  (防火墙)         │
                    └────────┬─────────┘
                             │
                    Allow? ──┼── Block? ── Ask?
                             │
                             ▼
                    工具实际执行（仅当允许时）
```

**三种决策**：

| 决策 | 含义 | 场景 |
|---|---|---|
| **Allow** | 放行 | 安全操作，如 `ls`、`echo hello` |
| **Block** | 拦截 | 危险操作，如 `rm -rf /`、密钥外发 |
| **Ask** | 需要用户确认 | 风险可控但需人工判断，如 `sudo`、财务操作 |

---

## 2. 拦截机制详解

### 2.1 拦截是如何发生的？

SkillSecurity 不是一个独立运行的守护进程，而是一个 **嵌入式 SDK**。你在代码中调用 `guard.check()` 来检查每一次工具调用——在工具真正执行之前。

```python
from skillsecurity import SkillGuard

guard = SkillGuard()

# 在工具执行前检查
def execute_tool(tool_type, **params):
    decision = guard.check({"tool": tool_type, **params})
    
    if decision.is_blocked:
        print(f"已拦截: {decision.reason}")
        return None
    
    if decision.needs_confirmation:
        if not user_confirms(decision.reason):
            return None
    
    # 安全，执行工具
    return actually_execute(tool_type, **params)
```

### 2.2 检查管线（Pipeline）

每次 `guard.check()` 调用会依次经过以下检查层：

```
Tool Call 请求
       │
       ▼
┌──────────────┐
│ ① 自我保护    │ SkillSecurity 自身的配置/策略文件不允许被修改
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ ② 权限检查    │ 如果 Skill 注册了权限清单，检查是否越权
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ ③ 策略匹配    │ YAML 规则引擎：正则匹配命令/路径/URL/参数
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ ④ 隐私检查    │ 出站请求中是否携带 API Key / PII / 聊天记录？
│              │ 消息是否包含敏感对话数据？
│              │ 目标域名是否可信？是否涉及财务操作？
└──────┬───────┘
       │
       ▼
  最终决策 (Allow / Block / Ask)
       │
       ▼ (异步)
  审计日志记录
```

**关键设计**：整个管线是 **短路求值** 的——一旦某层返回 Block，后续层不再执行，平均耗时 < 10ms。

### 2.3 七层防护体系

| 层 | 检查内容 | 防御目标 |
|---|---|---|
| 自我保护 | SkillSecurity 自身文件 | 防止 Agent 篡改安全配置 |
| 权限边界 | Skill 权限声明 vs 实际操作 | 防止 Skill 越权 |
| 命令拦截 | 危险命令模式（rm -rf、反向 shell 等） | 防止系统破坏 |
| 路径保护 | 系统目录、凭证文件、聊天记录文件 | 防止敏感文件被访问 |
| 数据检查 | API Key、PII、聊天记录、高熵字符串 | 防止敏感数据外发 |
| 财务检查 | 支付 API、购买操作、云资源创建 | 防止未授权消费 |
| 域名检查 | 目标域名信誉 | 防止数据发往可疑域名 |

---

## 3. 如何与 AI Agent 框架集成

### 3.1 通用集成模式

SkillSecurity 是 **框架无关** 的。任何 Agent 框架只要在工具执行前调用 `guard.check()` 即可。核心只需要传入一个描述工具调用的字典：

```python
{
    "tool": "shell",          # 工具类型
    "command": "rm -rf /tmp",  # 工具参数
    "skill_id": "acme/cleanup" # （可选）Skill ID，用于权限检查
}
```

支持的工具类型（`tool` 字段）：

| tool 值 | 含义 | 参数示例 |
|---|---|---|
| `shell` | Shell 命令 | `command: "ls -la"` |
| `file.read` | 读取文件 | `path: "/etc/passwd"` |
| `file.write` | 写入文件 | `path: "/tmp/out.txt"` |
| `file.delete` | 删除文件 | `path: "/tmp/old.log"` |
| `network.request` | 网络请求 | `url: "...", method: "POST", body: {...}` |
| `message.send` | 发送消息 | `channel: "...", content: "..."` |
| `browser` | 浏览器操作 | `action: "click", selector: "..."` |
| `database` | 数据库操作 | `query: "SELECT ..."` |

### 3.2 与 LangChain 集成

```python
from langchain.tools import BaseTool
from skillsecurity import SkillGuard, SkillSecurityError

guard = SkillGuard()

class SecureShellTool(BaseTool):
    name = "shell"
    description = "Execute shell commands"

    def _run(self, command: str) -> str:
        # SkillSecurity 检查
        decision = guard.check({"tool": "shell", "command": command})
        if decision.is_blocked:
            return f"Operation blocked: {decision.reason}"
        if decision.needs_confirmation:
            return f"Needs confirmation: {decision.reason}"
        
        # 实际执行
        import subprocess
        return subprocess.check_output(command, shell=True, text=True)
```

### 3.3 与 OpenClaw / MCP 工具集成

对于 MCP (Model Context Protocol) 类的 Agent 框架，可以在工具调用的包装层统一接入：

```python
from skillsecurity import SkillGuard

guard = SkillGuard()

class SecureMCPToolProxy:
    """包装 MCP 工具调用，加入安全检查。"""

    def __init__(self, mcp_client):
        self.client = mcp_client

    async def call_tool(self, tool_name: str, arguments: dict):
        # 映射 MCP 工具到 SkillSecurity 工具类型
        tool_type = self._map_tool_type(tool_name)
        
        decision = guard.check({
            "tool": tool_type,
            **arguments,
            "skill_id": f"mcp/{tool_name}",
        })

        if decision.is_blocked:
            raise SkillSecurityError(f"Blocked: {decision.reason}")
        
        if decision.needs_confirmation:
            # 可以弹出确认或记录日志
            print(f"[WARN] {decision.reason}")

        return await self.client.call_tool(tool_name, arguments)

    def _map_tool_type(self, tool_name: str) -> str:
        """将 MCP 工具名映射到 SkillSecurity 的工具类型。"""
        mapping = {
            "bash": "shell",
            "read_file": "file.read",
            "write_file": "file.write",
            "http_request": "network.request",
            "browser_navigate": "browser",
        }
        return mapping.get(tool_name, "shell")
```

### 3.4 装饰器模式（最简集成）

如果你只想快速保护一个函数：

```python
from skillsecurity import SkillGuard

guard = SkillGuard()

@guard.protect
def execute(tool_type, **params):
    # 你的工具执行逻辑
    ...

# 安全的调用会正常执行
execute("shell", command="echo hello")

# 危险的调用会抛出 SkillSecurityError
execute("shell", command="rm -rf /")
```

### 3.5 CLI 独立使用

无需写代码，直接用命令行检查：

```bash
# 检查命令是否安全
skillsecurity check --tool shell --command "rm -rf /"

# 扫描一个 Skill 的代码
skillsecurity scan ./my-skill/

# 查看审计日志
skillsecurity log --action block --limit 10

# 查看待审批队列
skillsecurity approval list
skillsecurity approval --api-url http://127.0.0.1:9099 list

# 通过/拒绝审批票据
skillsecurity approval approve appr-1234567890abcdef --scope session --approver alice
skillsecurity approval deny appr-1234567890abcdef --scope once --approver alice
```

---

## 4. 自定义配置

### 4.1 策略文件（核心配置）

所有安全规则都定义在 YAML 策略文件中。初始化一个配置文件：

```bash
skillsecurity init --template default --output skillsecurity.yaml
```

策略文件的核心结构：

```yaml
version: "1.0"
name: "my-project-policy"
description: "My custom security policy"

global:
  default_action: allow    # 默认放行（未匹配任何规则时）
  log_level: info
  fail_behavior: block     # 引擎出错时的降级策略

rules:
  - id: "my-custom-rule"
    tool_type: shell              # 匹配的工具类型
    match:
      command_pattern: "danger.*"  # 正则匹配
    action: block                  # block / allow / ask
    severity: critical             # critical / high / medium / low
    message: "My custom block reason"
    suggestions:
      - "Try a safer alternative"
```

### 4.2 内置策略模板

| 模板 | 默认动作 | 适用场景 |
|---|---|---|
| `default` | allow | 日常使用——拦截已知危险模式，其他放行 |
| `strict` | block | 生产环境——仅白名单操作放行，其他全部拦截或询问 |
| `development` | allow | 本地开发——只拦截最致命的操作（rm -rf、磁盘操作、反向 shell） |
| `openclaw-hardened` | block | OpenClaw/MCP 加固——默认拒绝并增加命令注入/路径穿越/可疑域名拦截 |

```python
# 使用不同策略
guard = SkillGuard(policy="strict")
guard = SkillGuard(policy="development")
guard = SkillGuard(policy_file="./my-policy.yaml")
```

### 4.3 规则匹配能力

| 匹配类型 | YAML 字段 | 示例 |
|---|---|---|
| 命令模式 | `command_pattern` | `"rm\\s+.*-r"` |
| 路径模式 | `path_pattern` | `"^/etc"` |
| URL 模式 | `url_pattern` | `"evil\\.com"` |
| 参数模式 | `param_pattern` | `"(?i)password"` |
| 工具类型过滤 | `tool_type` | `shell` / `file.read` / 列表 |
| 操作系统过滤 | `os` | `unix` / `windows` |
| 速率限制 | `rate_limit` | `max_calls: 10, window_seconds: 60` |

### 4.4 隐私保护配置

通过 Python API 精细控制隐私检查：

```python
guard = SkillGuard(config={
    "rules": [],  # 使用默认规则
    "privacy": {
        "enabled": True,
        "classifier": {
            "secret_detection": True,     # API Key / Token 检测
            "pii_detection": True,        # 个人信息检测
            "entropy_detection": True,    # 高熵字符串检测
            "chat_detection": True,       # 聊天记录检测（新增）
        },
        "domain_intelligence": {
            "trusted_domains": {
                "my_api": ["api.myservice.com", "*.internal.company.com"]
            }
        }
    }
})
```

### 4.5 Skill 权限清单

为第三方 Skill 声明权限边界：

```json
{
  "skill_id": "acme/weather-forecast",
  "version": "1.0.0",
  "name": "Weather Forecast",
  "permissions": {
    "network.read": {
      "description": "Fetch weather data",
      "domains": ["api.openweathermap.org"]
    }
  },
  "deny_permissions": ["shell", "file.write", "file.delete"]
}
```

注册后，该 Skill 的所有工具调用都会被限制在声明的权限范围内：

```python
guard.register_skill("acme/weather-forecast", "skill-manifest.json")

# 正常：在声明域名范围内
guard.check({"tool": "network.request", "url": "https://api.openweathermap.org/...", 
             "skill_id": "acme/weather-forecast"})
# → Allow

# 拦截：未声明 file.write 权限
guard.check({"tool": "file.write", "path": "/tmp/x",
             "skill_id": "acme/weather-forecast"})
# → Block: Skill has not declared 'file.write' permission
```

---

## 5. 聊天记录保护机制

### 5.1 为什么需要保护聊天记录？

聊天记录是 AI Agent 场景下的高度隐私数据。Skill 可能通过以下方式泄露对话数据：

| 路径 | 描述 |
|---|---|
| 文件窃取 | 读取 `chat_history.json`、`conversations.db` 等文件 |
| Payload 夹带 | 调用外部 API 时把完整对话历史附在请求中 |
| 消息转发 | 通过 `message.send` 将对话转发到第三方 |
| 渐进收集 | 每次调用附带少量对话片段，逐步积累 |

### 5.2 三层保护

```
                 ┌─────────────────────────┐
Layer 1: 文件层   │ 保护聊天记录文件和        │
                 │ 聊天应用数据目录           │
                 │ (chat_history.json,       │
                 │  .telegram, .signal...)   │
                 └─────────┬───────────────┘
                           │
                 ┌─────────▼───────────────┐
Layer 2: 数据层   │ 检测出站 payload 中的      │
                 │ 对话数据结构               │
                 │ (role/content, messages   │
                 │  array, timestamped log)  │
                 └─────────┬───────────────┘
                           │
                 ┌─────────▼───────────────┐
Layer 3: 通道层   │ message.send 纳入         │
                 │ 隐私检查范围              │
                 └─────────────────────────┘
```

**批量升级**：当检测到 payload 中包含 ≥ 5 条对话消息时，严重级别从 HIGH 自动升级为 CRITICAL，因为这意味着整段对话正在被外发。

---

## 6. 审计日志

所有检查结果都会被异步记录到 JSONL 格式的审计日志中：

```jsonl
{"timestamp":"2026-03-11T10:00:01Z","event_type":"tool_call_check","decision":{"action":"block","reason":"Recursive deletion detected","severity":"critical"},"request":{"tool_type":"shell","command":"rm -rf /"}}
```

- **自动脱敏**：日志中的密码、Token、API Key 会被自动遮蔽
- **查询接口**：通过 CLI 或 API 按时间、动作、严重级别过滤
- **日志轮转**：自动按大小/时间轮转，防止磁盘占满

```bash
# 查看最近的拦截记录
skillsecurity log --action block --limit 20

# 查看高危操作
skillsecurity log --severity critical --since 2026-03-01
```

---

## 7. 性能与可靠性

### 7.1 性能指标

| 指标 | 目标 | 实际 |
|---|---|---|
| 平均延迟 | < 10ms | 通常 1-5ms |
| P99 延迟 | < 50ms | < 20ms |
| 日志写入 | 异步 | 不阻塞主流程 |

### 7.2 降级策略

当 SkillSecurity 自身出现异常时，通过 `fail_behavior` 配置降级策略：

| 策略 | 行为 | 适用场景 |
|---|---|---|
| `block`（默认） | 引擎出错时拦截所有操作 | 生产环境（安全优先） |
| `allow` | 引擎出错时放行所有操作 | 开发环境（可用性优先） |

### 7.3 热加载

策略文件修改后无需重启应用：

```python
# 指定策略文件路径，自动监听变更
guard = SkillGuard(policy_file="./skillsecurity.yaml")
# 编辑 skillsecurity.yaml → 规则自动生效
```

---

## 8. 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent 运行时                            │
│                                                                  │
│   ┌──────┐    ┌──────┐    ┌──────────────────────────────┐     │
│   │ User │───▶│ LLM  │───▶│    Tool/Skill 调用请求         │     │
│   │Input │    │      │    └────────────┬─────────────────┘     │
│   └──────┘    └──────┘                 │                        │
│                                        ▼                        │
│                     ┌─────────────────────────────────────┐    │
│                     │        SkillSecurity SDK              │    │
│                     │                                       │    │
│                     │  ① Self-Protection (自我保护)          │    │
│                     │  ② Skill Permissions (权限边界)        │    │
│                     │  ③ Policy Engine (策略规则引擎)         │    │
│                     │  ④ Privacy Shield (隐私保护层)          │    │
│                     │     - Secret/PII/Chat Detection       │    │
│                     │     - Outbound Inspection              │    │
│                     │     - Financial Detection              │    │
│                     │     - Domain Intelligence              │    │
│                     │  ⑤ Decision Maker (决策器)              │    │
│                     │                                       │    │
│                     └────────────────┬──────────────────────┘    │
│                                      │                          │
│                           Allow / Block / Ask                   │
│                                      │                          │
│                         ┌────────────▼──────────────┐          │
│                         │  Tool Execution（仅 Allow） │          │
│                         └───────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
         │                                │
         ▼                                ▼
  ┌──────────────┐              ┌──────────────────┐
  │  Audit Log   │              │  CLI / Terminal   │
  │  (JSONL)     │              │  输出             │
  └──────────────┘              └──────────────────┘
```

---

## 9. FAQ

**Q: SkillSecurity 会拖慢 Agent 运行吗？**

A: 不会明显拖慢。平均检查耗时 1-5ms，最坏情况 < 50ms。日志写入是异步的。相比 LLM 推理通常需要数秒，这个开销可以忽略。

**Q: 会不会误拦截正常操作？**

A: 默认策略（`default`）只拦截已知的高危模式，误报率 < 1%。你可以用 `development` 模板进一步降低拦截敏感度，或自定义规则白名单。

**Q: 支持哪些 Agent 框架？**

A: SkillSecurity 是框架无关的 SDK，只要在工具执行前调用 `guard.check()` 即可。已验证兼容 LangChain、AutoGPT、CrewAI、MCP 等。

**Q: 隐私检查会上传我的数据到云端吗？**

A: 不会。所有检查（包括数据分类、域名查询、聊天检测）都在本地完成，SkillSecurity 不会向任何外部服务器发送任何数据。

**Q: 如何添加自定义的敏感数据检测规则？**

A: 通过 `DataClassifier` 的扩展接口添加自定义 Secret/PII/Chat 模式，或在策略文件中添加自定义规则。

**Q: `message.send` 类型的工具调用是怎么被保护的？**

A: `message.send` 和 `browser`、网络写请求（POST/PUT/PATCH/DELETE）一样，都会经过隐私保护层的完整检查——包括 API Key、PII、聊天记录、财务操作和域名信誉检查。
