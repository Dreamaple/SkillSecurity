# Python API Contract

**Module**: `skillsecurity`  
**Install**: `pip install skillsecurity`

---

## Public Interface: `SkillGuard`

```python
from skillsecurity import SkillGuard, Decision

class SkillGuard:
    def __init__(
        self,
        policy: str | None = None,        # 策略模板名称: "default", "strict", "development"
        policy_file: str | None = None,    # 自定义策略文件路径
        config: dict | None = None,        # 编程式配置（覆盖文件配置）
    ) -> None: ...

    def check(self, tool_call: dict) -> Decision:
        """
        检查一次工具调用是否安全。

        Args:
            tool_call: 工具调用描述，至少包含 "tool" 字段
                {
                    "tool": "shell",           # 必须
                    "command": "rm -rf /tmp",   # 取决于工具类型
                    "path": "/etc/hosts",       # 取决于工具类型
                    "url": "https://...",       # 取决于工具类型
                    "skill_id": "author/name",  # 可选
                    "agent_id": "agent-001",    # 可选
                    "session_id": "sess-abc",   # 可选
                }

        Returns:
            Decision 对象
        """
        ...

    def register_skill(
        self,
        skill_id: str,
        manifest: str | dict,   # 文件路径或 dict
    ) -> None:
        """注册 Skill 权限清单。"""
        ...

    def scan_skill(self, path: str) -> ScanReport:
        """
        静态扫描 Skill 源码目录。

        Args:
            path: Skill 源码目录路径

        Returns:
            ScanReport 对象
        """
        ...

    def query_logs(
        self,
        action: str | None = None,
        severity: str | None = None,
        agent_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """查询审计日志。"""
        ...
```

## Data Classes

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Decision:
    action: str              # "allow" | "block" | "ask"
    reason: str              # 人类可读原因
    severity: str            # "low" | "medium" | "high" | "critical"
    rule_matched: dict | None  # {"id": "...", "description": "..."}
    suggestions: list[str]   # 建议的替代方案
    check_duration_ms: float # 检查耗时

    @property
    def is_allowed(self) -> bool: ...

    @property
    def is_blocked(self) -> bool: ...

    @property
    def needs_confirmation(self) -> bool: ...


@dataclass(frozen=True)
class ScanReport:
    risk_level: str          # "safe" | "low" | "medium" | "high" | "critical"
    summary: dict            # files_scanned, issues_found, critical, high, medium, low
    issues: list[dict]       # 每个 issue: id, severity, file, line, code, description
    permission_analysis: dict | None  # declared, detected, undeclared, verdict
```

## Usage Patterns

### Minimal (零配置)

```python
from skillsecurity import SkillGuard

guard = SkillGuard()
result = guard.check({"tool": "shell", "command": "rm -rf /"})
assert result.is_blocked
```

### Custom Policy

```python
guard = SkillGuard(policy_file="./my-policy.yaml")
```

### With Skill Permission

```python
guard = SkillGuard()
guard.register_skill("acme/weather", manifest="./weather-skill/skill-manifest.json")
result = guard.check({"tool": "file.write", "path": "/tmp/x", "skill_id": "acme/weather"})
assert result.is_blocked  # weather skill 未声明 file.write
```

### Decorator (convenience)

```python
@guard.protect
def execute_tool(tool_type: str, **params):
    ...  # 自动在执行前检查
```

## Error Handling

| Exception | When |
|-----------|------|
| `PolicyLoadError` | 策略文件语法错误或不存在 |
| `ManifestValidationError` | Skill 清单格式无效 |
| `SkillSecurityError` | 其他内部错误（基类） |

当 `fail_behavior=block`（默认）时，内部异常导致 `check()` 返回 Block Decision 而非抛异常。
