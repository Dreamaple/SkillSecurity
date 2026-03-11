# Research: SkillSecurity Core

**Branch**: `001-skill-security-core` | **Date**: 2026-03-11

---

## R1: Implementation Language

**Decision**: Python 3.11+

**Rationale**:
- AI Agent 生态（LangChain、AutoGen、MCP）几乎全部是 Python，用户无需跨语言集成
- `pip install skillsecurity` 是最简单的安装路径，直接满足 SC-001（5 分钟安装）
- Python 的 `re` 模块基于 C 实现，正则匹配性能足以满足 <50ms P99 目标
- 单线程下 1000 次简单正则匹配/秒在 Python 中完全可行（每次匹配 <1ms）
- Phase 3 的 Python SDK 就是核心本身，无需额外包装层
- 开发效率高，4 周 MVP 周期更有把握

**Alternatives considered**:
- **Go**: 性能更优、单二进制分发方便，但 AI 生态集成需要 subprocess/gRPC 桥接，增加 Phase 1 复杂度。适合未来作为独立 Server 模式的引擎。
- **Rust**: 极致性能，但开发效率低，4 周内难以完成 MVP。可作为 PyO3 扩展优化热路径。

**Migration path**: 如果 Python 性能在高负载场景下不足，`engine/matcher.py` 可替换为 Rust 扩展（via PyO3），公共 API 不变。

---

## R2: Regex Engine

**Decision**: Python `re` 标准库（Phase 1），保留 `google-re2` 升级路径

**Rationale**:
- `re` 是 Python 标准库，零额外依赖
- 对于 SkillSecurity 的模式（命令匹配、路径匹配），`re` 足够快
- `re` 的 C 实现在简单模式上性能优秀
- 避免 `google-re2` 的 C++ 编译依赖（影响跨平台安装体验）

**Alternatives considered**:
- **google-re2**: 线性时间保证，防止 ReDoS，但需要 C++ 编译环境
- **regex** (PyPI): 功能更丰富（Unicode 属性等），但对本项目无必要

**Risk**: 恶意构造的正则可能导致 ReDoS。缓解：内置规则已审查；用户自定义规则匹配时设置超时。

---

## R3: Policy Parsing (YAML)

**Decision**: PyYAML（`pyyaml`）with safe_load

**Rationale**:
- 最广泛使用的 Python YAML 库，成熟稳定
- `yaml.safe_load()` 防止 YAML 反序列化攻击
- 轻量，无额外依赖

**Alternatives considered**:
- **ruamel.yaml**: 保留注释和格式，但本项目只需读取不需写回
- **strictyaml**: 更强的类型验证，但社区较小

---

## R4: File Watching (Hot-reload)

**Decision**: `watchdog` library

**Rationale**:
- 跨平台文件系统事件监听（inotify/FSEvents/ReadDirectoryChangesW）
- 成熟稳定，广泛使用
- 支持 Linux / macOS / Windows

**Alternatives considered**:
- **polling**: 定时轮询文件修改时间，简单但不够即时
- **inotify 直接调用**: 仅限 Linux

**Implementation note**: 监听策略文件目录，检测到变更后去抖（debounce 1 秒），然后重新加载。加载失败时保留旧策略，打印警告。

---

## R5: CLI Framework

**Decision**: `click`

**Rationale**:
- Python CLI 框架事实标准
- 声明式命令定义，代码简洁
- 内置帮助文档生成
- 支持子命令（`skillsecurity check`, `skillsecurity scan`, `skillsecurity log`）

**Alternatives considered**:
- **argparse**: 标准库但样板代码多
- **typer**: 基于 type hints 的现代方案，但底层仍依赖 click

---

## R6: Audit Log Async Writing

**Decision**: Python `queue.Queue` + 后台 daemon 线程

**Rationale**:
- 标准库实现，无额外依赖
- `Queue.put()` 非阻塞，满足 FR-028（日志不阻塞拦截流程）
- daemon 线程随主进程退出，结合 `atexit` flush 确保数据不丢失

**Alternatives considered**:
- **asyncio**: 需要整个调用链都是 async，侵入性太强
- **logging module RotatingFileHandler**: 只支持文本日志，不适合结构化 JSONL
- **external queue (Redis/RabbitMQ)**: 对本地工具过重

---

## R7: Sensitive Data Redaction Strategy

**Decision**: 基于正则的流式替换，预编译模式

**Rationale**:
- 预编译正则集合，一次遍历完成所有脱敏
- 内置 10+ 常见敏感模式（password, token, api_key, secret, bearer, authorization）
- 用户可通过配置追加自定义脱敏模式
- 保留部分信息辅助调试（如 `sk-****abcd` 保留前缀和后 4 位）

**Pattern examples**:
```
password\s*[=:]\s*\S+     → password=***
(token|api_key|secret)\s*[=:]\s*\S+  → token=***
Bearer\s+\S+              → Bearer ***
(sk-|pk-)\w{4}\w+(\w{4})  → $1****$2
```

---

## R8: Cross-platform Dangerous Pattern Coverage

**Decision**: 统一规则文件，按 OS 标签分组

**Rationale**:
- 单一 `default.yaml` 同时包含 Unix 和 Windows 模式
- 每条规则可选 `os` 字段（`unix` / `windows` / `all`），默认 `all`
- 运行时根据 `platform.system()` 过滤只加载当前平台 + `all` 的规则
- 这样 Windows 用户不会看到误报的 Unix 命令拦截

**Rule structure example**:
```yaml
- id: "block-recursive-delete-unix"
  os: unix
  tool_type: shell
  match:
    command_pattern: "rm\\s+.*-[a-zA-Z]*r"
  action: block

- id: "block-recursive-delete-windows"
  os: windows
  tool_type: shell
  match:
    command_pattern: "(del\\s+/s|rd\\s+/s|rmdir\\s+/s)"
  action: block
```

---

## R9: Self-protection Implementation

**Decision**: 硬编码受保护路径集合 + 拦截器最高优先级检查

**Rationale**:
- 在拦截流程最前端（策略匹配之前）检查目标路径是否在受保护集合中
- 受保护路径从配置中计算：策略文件路径、清单目录、日志目录、SkillSecurity 自身配置文件
- 此检查不可被策略覆盖（硬编码，非规则）
- 实现简单，无绕过风险

**Protected paths resolution**:
```python
protected = {
    config.policy_file,           # skillsecurity.yaml
    config.policy_dir,            # policies/
    config.manifest_dir,          # skill-manifests/
    config.audit.output_dir,      # logs/
    config.self_config_path,      # 自身配置文件
}
```

---

## Summary of Technology Stack

| Component | Choice | Version/Notes |
|-----------|--------|---------------|
| Language | Python | 3.11+ |
| YAML Parsing | PyYAML | safe_load only |
| Regex | `re` (stdlib) | re2 upgrade path |
| File Watching | watchdog | Cross-platform |
| CLI | click | Subcommand structure |
| Async Logging | queue.Queue + daemon thread | stdlib only |
| Testing | pytest + hypothesis | Coverage ≥80% |
| Packaging | pyproject.toml + hatch | Modern Python packaging |
| Formatting | ruff | Lint + format |
