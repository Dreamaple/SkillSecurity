# Quickstart: SkillSecurity

**目标**: 5 分钟内启用 AI Agent 工具调用安全防护

---

## 1. 安装

```bash
pip install skillsecurity
```

## 2. 立即使用（零配置）

### Python 代码中

```python
from skillsecurity import SkillGuard

guard = SkillGuard()

# 检查一次工具调用
result = guard.check({"tool": "shell", "command": "rm -rf /tmp/data"})

if result.is_blocked:
    print(f"🛑 已拦截: {result.reason}")
elif result.needs_confirmation:
    confirm = input(f"⚠️ {result.reason}，继续? [y/N] ")
    if confirm.lower() != "y":
        print("已取消")
else:
    print("✅ 安全，可以执行")
```

### 命令行

```bash
# 检查单条命令
skillsecurity check --tool shell --command "rm -rf /"
# 🛑 [BLOCK] 检测到递归删除命令

# 检查文件操作
skillsecurity check --tool file.write --path "/etc/passwd"
# 🛑 [BLOCK] 禁止写入系统目录

# 安全操作正常通过
skillsecurity check --tool file.read --path "./README.md"
# ✅ [ALLOW]
```

## 3. 自定义策略

```bash
# 生成配置文件
skillsecurity init
# 创建 ./skillsecurity.yaml
```

编辑 `skillsecurity.yaml` 添加自定义规则：

```yaml
version: "1.0"
name: "my-project"

global:
  default_action: allow
  fail_behavior: block

rules:
  # 只允许写入项目目录
  - id: "allow-project-writes"
    tool_type: [file.write, file.delete]
    match:
      path_pattern: "^/home/me/my-project/"
    action: allow

  # 其他写入全部需要确认
  - id: "ask-other-writes"
    tool_type: [file.write, file.delete]
    action: ask
    severity: medium
    message: "写入非项目目录"
```

使用自定义策略：

```python
guard = SkillGuard(policy_file="./skillsecurity.yaml")
```

## 4. 扫描第三方 Skill（Phase 2）

```bash
# 安装前扫描
skillsecurity scan ./third-party-skill/

# 查看扫描报告
# 🔍 扫描 Skill: ./third-party-skill/
#    文件数: 8
#    风险等级: SAFE ✅
```

## 5. 注册 Skill 权限（Phase 2）

```bash
# 注册 Skill 的权限声明
skillsecurity register ./weather-skill/skill-manifest.json

# 运行时自动执行权限边界
# weather-skill 尝试写文件 → 自动 Block
```

## 6. 查看审计日志（Phase 2）

```bash
# 查看最近被拦截的操作
skillsecurity log --action block --limit 5

# 查看特定时间范围
skillsecurity log --since 2026-03-10 --format json
```

---

## 内置策略模板

| 模板 | 命令 | 适用场景 |
|------|------|----------|
| `default` | `SkillGuard()` | 通用（平衡安全与便利） |
| `strict` | `SkillGuard(policy="strict")` | 生产环境（严格模式） |
| `development` | `SkillGuard(policy="development")` | 开发环境（宽松） |

## 下一步

- 阅读 [策略配置指南](contracts/policy-schema.md) 了解完整规则语法
- 阅读 [Skill 清单指南](contracts/manifest-schema.md) 了解权限声明
- 阅读 [Python API 文档](contracts/python-api.md) 了解完整接口
