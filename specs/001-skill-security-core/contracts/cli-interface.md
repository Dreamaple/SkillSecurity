# CLI Interface Contract

**Binary**: `skillsecurity`  
**Install**: `pip install skillsecurity` (provides CLI entry point)

---

## Commands

### `skillsecurity check`

检查单次工具调用（交互式或管道模式）。

```bash
# 交互式
skillsecurity check --tool shell --command "rm -rf /tmp"

# JSON 输入（管道模式）
echo '{"tool":"shell","command":"rm -rf /tmp"}' | skillsecurity check --json

# 指定策略
skillsecurity check --tool shell --command "sudo apt install nginx" --policy strict
```

**Output (human-readable, stderr)**:
```
🛑 [BLOCK] 操作已拦截
   工具: shell
   命令: rm -rf /tmp
   原因: 检测到递归删除命令
   规则: block-recursive-delete
   严重: critical
   建议: 如需删除特定文件，请使用精确路径
```

**Output (JSON, stdout)**:
```json
{"action":"block","reason":"检测到递归删除命令","severity":"critical","rule_matched":{"id":"block-recursive-delete"},"suggestions":["如需删除特定文件，请使用精确路径"],"check_duration_ms":2.3}
```

**Exit codes**:
- `0`: allow
- `1`: block
- `2`: ask (需要确认)
- `3`: error

---

### `skillsecurity scan`

静态扫描 Skill 目录。

```bash
skillsecurity scan ./my-skill/
skillsecurity scan ./my-skill/ --manifest ./my-skill/skill-manifest.json
skillsecurity scan ./my-skill/ --format json
```

**Output (human-readable)**:
```
🔍 扫描 Skill: ./my-skill/
   文件数: 12
   扫描耗时: 230ms

⛔ 风险等级: HIGH

发现问题:
  1. [CRITICAL] src/main.py:42 - 数据外泄风险
     requests.post(url, data={'token': os.environ['API_KEY']})
  2. [HIGH] src/utils.py:15 - 动态代码执行
     eval(user_input)

权限分析:
  声明: network.read
  实际: network.read, network.write, env.read
  ⚠️  未声明: network.write, env.read

建议: 不建议安装此 Skill
```

**Exit codes**:
- `0`: safe / low risk
- `1`: medium / high / critical risk
- `3`: error

---

### `skillsecurity log`

查询审计日志。

```bash
# 查看最近的 Block 记录
skillsecurity log --action block --limit 10

# 按时间范围
skillsecurity log --since 2026-03-01 --until 2026-03-11

# 按 Agent 过滤
skillsecurity log --agent-id agent-001

# 导出 CSV
skillsecurity log --action block --format csv > blocks.csv

# 统计
skillsecurity log stats --since 2026-03-01
```

**Formats**: `table` (default), `json`, `jsonl`, `csv`

---

### `skillsecurity init`

初始化配置文件。

```bash
# 使用默认策略
skillsecurity init

# 使用指定模板
skillsecurity init --template strict

# 指定输出路径
skillsecurity init --output ./config/skillsecurity.yaml
```

---

### `skillsecurity validate`

验证策略文件语法。

```bash
skillsecurity validate ./skillsecurity.yaml
skillsecurity validate ./my-policy.yaml
```

**Output**:
```
✅ 策略文件有效: ./skillsecurity.yaml
   规则数: 15
   版本: 1.0
```

Or on error:
```
❌ 策略文件有误: ./skillsecurity.yaml
   第 23 行: 未知的 action 值 "deny"，有效值为: allow, block, ask
```

---

## Global Options

| Option | Description | Default |
|--------|-------------|---------|
| `--policy` / `-p` | 策略模板名或文件路径 | `default` |
| `--format` / `-f` | 输出格式: `human`, `json` | `human` |
| `--verbose` / `-v` | 显示详细信息（含 allow） | off |
| `--no-color` | 禁用彩色输出 | auto-detect TTY |
| `--no-emoji` | 禁用 emoji | auto-detect |
| `--lang` | 输出语言: `en`, `zh` | `en` |
| `--config` / `-c` | 配置文件路径 | auto-detect |
