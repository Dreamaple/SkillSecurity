# Phase 1：核心拦截引擎

> **周期**: 第 1-4 周  
> **目标**: 能跑起来，能拦住危险操作  
> **产出**: MVP，个人开发者可以 `pip install` 后立即使用  
> **关联**: [主需求文档](../SkillSecurity需求规格说明书.md) / [架构概述](architecture-overview.md) / [威胁模型](threat-model.md)

---

## 1. Phase 目标

完成后，用户可以做到：

```python
from skillsecurity import SkillGuard

guard = SkillGuard()  # 默认策略，零配置

# 在工具调用前检查
result = guard.check({
    "tool": "shell",
    "command": "rm -rf /tmp/data"
})

if result.action == "block":
    print(f"已拦截: {result.reason}")
elif result.action == "ask":
    confirm = input(f"⚠️ {result.reason}，是否继续? [y/N] ")
    if confirm.lower() != 'y':
        exit()
# else: allow, 继续执行
```

---

## 2. 功能需求

### F1: 工具调用拦截

#### 2.1 概述

在工具/Skill 实际执行之前，对调用请求进行安全检查。这是 SkillSecurity 最核心的能力。

#### 2.2 支持拦截的工具类型

| 工具类型 | 标识符 | 典型操作 | 默认风险级别 |
|---|---|---|---|
| 命令执行 | `shell`, `exec` | bash 命令、脚本执行 | HIGH |
| 文件读取 | `file.read` | 读取文件内容 | LOW |
| 文件写入 | `file.write` | 创建/修改文件 | MEDIUM |
| 文件删除 | `file.delete` | 删除文件/目录 | HIGH |
| 网络请求 | `network.request` | HTTP/HTTPS 调用 | MEDIUM |
| 消息发送 | `message.send` | 邮件/IM/SMS | MEDIUM |
| 浏览器控制 | `browser` | 打开页面、点击、输入 | MEDIUM |
| 数据库操作 | `database` | SQL 查询、数据修改 | MEDIUM-HIGH |

#### 2.3 拦截请求格式

```json
{
  "tool_type": "shell",
  "operation": "exec",
  "params": {
    "command": "rm -rf /tmp/data",
    "working_dir": "/home/user/project"
  },
  "context": {
    "agent_id": "agent-001",
    "session_id": "sess-abc123",
    "skill_id": "file-manager-v1",
    "user_id": "user-001",
    "timestamp": "2026-03-11T10:30:00Z"
  }
}
```

#### 2.4 危险模式识别

**命令执行类**：

| 模式 | 示例 | 风险 | 默认动作 |
|---|---|---|---|
| 递归删除 | `rm -rf`, `del /s /q` | 数据丢失 | Block |
| 提权操作 | `sudo`, `runas` | 权限提升 | Ask |
| 磁盘写入 | `dd if=`, `mkfs` | 数据破坏 | Block |
| 网络下载执行 | `curl \| bash`, `wget && sh` | 远程代码执行 | Block |
| 环境修改 | `export PATH=`, `setx` | 系统配置篡改 | Ask |
| 进程控制 | `kill -9`, `taskkill /f` | 服务中断 | Ask |

**文件操作类**：

| 模式 | 示例 | 风险 | 默认动作 |
|---|---|---|---|
| 系统目录写入 | 写入 `/etc`, `/System`, `C:\Windows` | 系统损坏 | Block |
| 敏感文件访问 | 读取 `~/.ssh/id_rsa`, `.env` | 凭证泄露 | Ask |
| 配置文件修改 | 修改 `.bashrc`, `.gitconfig` | 环境篡改 | Ask |
| 大范围通配符删除 | `*.{js,py,go}` 在项目根目录 | 代码丢失 | Ask |

**网络请求类**：

| 模式 | 示例 | 风险 | 默认动作 |
|---|---|---|---|
| 敏感数据上传 | POST 包含 token/password 的数据 | 数据外泄 | Block |
| 内网探测 | 请求 `192.168.*`, `10.*`, `localhost` | 内网渗透 | Ask |
| 未知域名 | 请求非白名单域名 | 不可预测 | Ask（严格模式下 Block） |

**数据库操作类**：

| 模式 | 示例 | 风险 | 默认动作 |
|---|---|---|---|
| 无条件删除 | `DELETE FROM table`（无 WHERE） | 数据丢失 | Block |
| 表结构修改 | `DROP TABLE`, `ALTER TABLE` | 结构破坏 | Ask |
| 权限修改 | `GRANT`, `REVOKE` | 权限变更 | Ask |

#### 2.5 性能要求

| 指标 | 目标 |
|---|---|
| 平均拦截延迟 | < 10ms |
| P99 拦截延迟 | < 50ms |
| 内存占用 | < 50MB（策略引擎） |
| 规则数量支持 | ≥ 1000 条规则无性能退化 |

#### 2.6 验收标准

- [ ] 能识别上述所有危险模式类别
- [ ] 拦截延迟满足性能目标
- [ ] 未识别的工具类型默认执行 Allow（不阻塞未知工具）
- [ ] 拦截器异常时不导致 Agent 崩溃（fail-safe）

---

### F2: 策略配置

#### 2.7 概述

通过 YAML 配置文件定义安全规则，支持灵活的策略组合。

#### 2.8 策略文件结构

```yaml
# skillsecurity.yaml - 默认策略配置

version: "1.0"
name: "default"
description: "默认安全策略 - 平衡安全与便利"

# 全局设置
global:
  default_action: allow      # 未匹配任何规则时的默认行为
  log_level: info            # 日志级别: debug/info/warn/error
  fail_behavior: allow       # 安全层自身故障时: allow/block

# 规则列表（按顺序匹配，先匹配先执行）
rules:
  # 黑名单规则 - 绝对禁止
  - id: "block-recursive-delete"
    description: "禁止递归删除"
    tool_type: shell
    match:
      command_pattern: "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r|--recursive)"
    action: block
    severity: critical
    message: "检测到递归删除命令，已拦截"

  - id: "block-system-paths"
    description: "禁止写入系统目录"
    tool_type: ["file.write", "file.delete"]
    match:
      path_pattern: "^(/etc|/System|/boot|C:\\\\Windows)"
    action: block
    severity: critical
    message: "禁止操作系统核心目录"

  # Ask 规则 - 需要用户确认
  - id: "ask-sensitive-files"
    description: "读取敏感文件需确认"
    tool_type: file.read
    match:
      path_pattern: "(\\.env|\\.ssh|credentials|secrets)"
    action: ask
    severity: high
    message: "即将读取可能包含敏感信息的文件"

  - id: "ask-sudo"
    description: "提权操作需确认"
    tool_type: shell
    match:
      command_pattern: "^sudo\\s"
    action: ask
    severity: high
    message: "即将执行提权操作"

  # 速率限制
  - id: "rate-limit-shell"
    description: "限制命令执行频率"
    tool_type: shell
    rate_limit:
      max_calls: 30
      window_seconds: 60
    action: block
    message: "命令执行频率过高，已限制"

  # 白名单规则 - 明确放行
  - id: "allow-tmp-files"
    description: "允许操作临时目录"
    tool_type: ["file.write", "file.delete"]
    match:
      path_pattern: "^/tmp/"
    action: allow

# 时间策略（可选）
time_policies:
  - id: "night-strict"
    description: "深夜提升安全级别"
    schedule:
      hours: [0, 1, 2, 3, 4, 5]
    override:
      default_action: ask
```

#### 2.9 规则匹配逻辑

```
1. 按规则列表顺序逐条匹配
2. 第一条匹配的规则决定结果（First Match Wins）
3. 未匹配任何规则 → 使用 global.default_action
4. 时间策略可覆盖默认行为
```

#### 2.10 配置能力要求

| 能力 | 说明 | 必须/可选 |
|---|---|---|
| YAML 格式 | 人类可读可编辑 | 必须 |
| 语法校验 | 配置错误时清晰报错 | 必须 |
| 热加载 | 修改配置后无需重启（1 分钟内生效） | 必须 |
| 多文件 | 支持 `include` 引入其他策略文件 | 可选 |
| 环境变量 | 支持 `${ENV_VAR}` 引用 | 可选 |

#### 2.11 验收标准

- [ ] 配置语法错误时给出行号和原因
- [ ] 策略变更后 1 分钟内自动生效
- [ ] 空策略文件或无策略文件时使用内置默认策略
- [ ] 策略文件支持注释

---

### F3: 决策与执行

#### 2.12 概述

根据策略匹配结果做出 Allow / Block / Ask 三种决策，并返回结构化的决策结果。

#### 2.13 决策类型

| 决策 | 行为 | 适用场景 |
|---|---|---|
| **Allow** | 放行执行，可选记录日志 | 安全操作 / 白名单匹配 |
| **Block** | 拦截执行，返回拦截原因 | 危险操作 / 黑名单匹配 |
| **Ask** | 暂停执行，请求用户确认 | 高风险但可能合理的操作 |

#### 2.14 决策结果格式

```json
{
  "action": "block",
  "reason": "检测到递归删除命令 rm -rf，已拦截",
  "severity": "critical",
  "rule_matched": {
    "id": "block-recursive-delete",
    "description": "禁止递归删除"
  },
  "suggestions": [
    "如需删除特定文件，请使用精确路径",
    "考虑先列出文件确认: ls /tmp/data"
  ],
  "metadata": {
    "check_duration_ms": 3,
    "timestamp": "2026-03-11T10:30:00.003Z"
  }
}
```

#### 2.15 Ask 模式行为

| 配置项 | 说明 | 默认值 |
|---|---|---|
| `ask_timeout` | 等待用户确认的超时时间 | 60 秒 |
| `ask_default_on_timeout` | 超时后的默认行为 | block |
| `ask_remember` | 是否支持"记住选择" | false（Phase 1 不实现） |

#### 2.16 验收标准

- [ ] Block 时明确告知触发了哪条规则
- [ ] Ask 时告知用户操作的风险等级和具体内容
- [ ] Allow 时可配置是否记录日志
- [ ] 决策结果包含检查耗时
- [ ] 超时处理符合配置

---

### F14: CLI 输出

#### 2.17 概述

Phase 1 的用户交互通过命令行实现，提供清晰的终端输出。

#### 2.18 输出格式

**Block 时**：
```
🛑 [BLOCK] 操作已拦截
   工具: shell
   命令: rm -rf /tmp/data
   原因: 检测到递归删除命令
   规则: block-recursive-delete
   建议: 如需删除特定文件，请使用精确路径
```

**Ask 时**：
```
⚠️  [ASK] 需要确认（风险等级: HIGH）
   工具: shell
   命令: sudo apt install nginx
   原因: 即将执行提权操作
   规则: ask-sudo
   
   是否允许执行? [y/N] (60秒后自动拒绝)
```

**Allow（verbose 模式下）**：
```
✅ [ALLOW] 操作已放行
   工具: file.read
   路径: /home/user/project/README.md
```

#### 2.19 配置项

| 配置项 | 说明 | 默认值 |
|---|---|---|
| `cli.verbose` | 是否显示 Allow 日志 | false |
| `cli.color` | 是否启用彩色输出 | true |
| `cli.emoji` | 是否使用 emoji 图标 | true |
| `cli.language` | 输出语言 | en（支持 zh） |

#### 2.20 验收标准

- [ ] Block 和 Ask 始终输出到 stderr
- [ ] 输出信息包含足够上下文用于排查
- [ ] 无 TTY 时自动禁用颜色和 emoji
- [ ] Ask 的用户输入超时正确处理

---

## 3. 内置默认策略

Phase 1 自带一份默认策略（无需用户创建配置文件即可使用）：

| 规则类别 | 默认行为 |
|---|---|
| `rm -rf` / 递归删除 | Block |
| `sudo` / 提权 | Ask |
| 写入系统目录 | Block |
| 读取 `.env` / `.ssh` | Ask |
| `curl \| bash` 模式 | Block |
| 无 WHERE 的 DELETE/UPDATE | Block |
| 普通文件读取 | Allow |
| 普通 HTTP GET | Allow |

---

## 4. 测试计划

### 4.1 单元测试

| 测试项 | 描述 |
|---|---|
| 规则匹配正确性 | 各类危险模式是否被正确识别 |
| 策略解析 | YAML 解析、校验、错误处理 |
| 决策逻辑 | Allow/Block/Ask 决策是否正确 |
| 速率限制 | 计数器、时间窗口是否准确 |
| 边界情况 | 空命令、超长命令、特殊字符 |

### 4.2 集成测试

| 测试项 | 描述 |
|---|---|
| 端到端拦截 | 从请求到决策到输出完整流程 |
| 策略热加载 | 修改文件后规则是否自动更新 |
| 性能测试 | 延迟和吞吐量是否达标 |
| 故障恢复 | 策略文件损坏/缺失时的行为 |

### 4.3 安全测试

| 测试项 | 描述 |
|---|---|
| 绕过尝试 | 通过编码、转义等试图绕过规则 |
| 规则冲突 | 多条规则匹配同一请求时的优先级 |
| 资源耗尽 | 恶意构造的超大请求 |

---

## 5. 交付物

| 交付物 | 说明 |
|---|---|
| 核心拦截引擎 | Go 二进制 / Python 包 |
| 默认策略文件 | `default.yaml` |
| CLI 交互 | 终端输出 + Ask 确认 |
| 单元测试 | 覆盖率 ≥ 80% |
| 快速开始文档 | 5 分钟上手指南 |
| API 文档 | 拦截请求/决策结果的数据格式 |

---

## 6. 里程碑

| 周 | 目标 | 产出 |
|---|---|---|
| 第 1 周 | 项目骨架 + 策略引擎 | 能加载解析 YAML 策略 |
| 第 2 周 | 拦截器 + 规则匹配 | 能识别危险模式 |
| 第 3 周 | 决策器 + CLI 输出 | 完整的 check → decide → output 流程 |
| 第 4 周 | 测试 + 默认策略 + 文档 | MVP 可发布 |
