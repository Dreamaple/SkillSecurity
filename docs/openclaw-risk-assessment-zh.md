# OpenClaw 风险预警对照评估与 SkillSecurity 加固方案

> 日期：2026-03-15  
> 评估对象：`Dreamaple/SkillSecurity`（本地仓库）  
> 目标：回答“是否防得住 OpenClaw 近期风险”，并给出可落地的补全资料与改进方案。

---

## 1. 风险来源速览（外部情报）

根据国家网络安全通报中心转引内容（央视网/新浪），OpenClaw 的重点风险集中在 5 类：

1. 架构设计缺陷（认证绕过、权限边界薄弱）
2. 默认配置高风险（公网暴露、弱认证）
3. 高危漏洞密集（命令注入、路径遍历、访问控制）
4. 供应链投毒（插件生态恶意代码）
5. 智能体行为不可控（越权执行、数据外泄、终端接管）

同时，OpenClaw 官方 GitHub Security Advisory（2026-02~03）可见多类高风险案例，包括：

- 路径遍历/Zip Slip：`GHSA-p25h-9q54-ffvw`
- 命令执行策略绕过（safeBins）：`GHSA-3x3x-h76w-hp98`
- WebSocket 作用域越权：`GHSA-rqpp-rjj8-7wv8`
- 非 owner 权限访问 owner-only 面：`GHSA-r7vr-gr74-94p8`
- 工作区插件自动发现导致代码执行：`GHSA-99qw-6mr3-36qr`
- SCP 远程路径命令注入：`GHSA-g2f6-pwvx-r275`

这些漏洞与官方通报中的“访问控制、命令注入、路径遍历、供应链、行为失控”高度一致。

---

## 0. 实施进度（2026-03-15）

- [x] P0-1 新增 `openclaw-hardened` 策略模板（已落地：`policies/openclaw-hardened.yaml`）
- [x] P0-2 补齐默认策略命令注入/路径穿越/可疑 URL/敏感路径下载拦截（已落地：`policies/default.yaml`）
- [x] P0-3 OpenClaw/MCP 集成默认使用 hardened 策略（可被显式 `policy` / `policy_file` 覆盖）
- [x] P1 归一化路径越界检查（已落地：`engine/path_boundary.py`）
- [x] P1 命令语义解析辅助检测（已落地：`engine/command_semantics.py`）
- [x] P1 部署安全审计器（已落地：`security/startup_audit.py`）
- [x] P1 上下文权限约束（已落地：`engine/context_policy.py` + `caller_role/scopes`）
- [x] P2 供应链增强与漏洞情报自动同步（已落地：`supplychain/analyzer.py` + `security/intel_sync.py` + CLI）
- [x] P2 规则效果度量体系（已落地：`metrics/analyzer.py` + CLI）

---

## 2. SkillSecurity 对照结论：能防多少？

### 2.1 总体结论

SkillSecurity 对**工具调用层风险**（危险命令、敏感文件、数据外发、行为链）已有较强防护；  
但对 **OpenClaw 平台自身漏洞**（认证/会话/插件加载/网关配置）属于“旁路能力不足”，无法单独兜底。

换句话说：

- **能防住一部分“被利用后的危险动作”**
- **防不住 OpenClaw 网关/认证/插件加载本身的漏洞触发面**

### 2.2 分项评估（按通报维度）

| 通报风险维度 | SkillSecurity 现状 | 结论 |
|---|---|---|
| 架构设计缺陷 / 认证绕过 | 主要在工具调用阶段拦截；不负责 OpenClaw 网关认证、WebSocket scope 绑定 | **不能单独防住** |
| 默认配置公网暴露 | 无 `bind/auth/port` 基线审计能力 | **不能防住** |
| 命令注入 / 执行绕过 | 有 `pipe to shell`、PowerShell 下载执行、反向 shell、递归删除等规则 | **部分可防** |
| 路径遍历 | 主要是系统目录与凭证路径保护；缺少 `../`、编码穿越、归一化后校验规则 | **部分可防** |
| 供应链投毒 | 有静态扫描与权限清单机制；无签名校验、依赖漏洞联动、插件来源强校验 | **部分可防** |
| 行为失控（越权/外泄） | 有隐私检查、域名信誉、财务识别、行为链检测 | **中高覆盖（部分可防）** |

---

## 3. 代码级核验：当前已具备能力

以下能力在仓库中已存在，可作为“已防住部分场景”的依据：

- 策略规则引擎（命令/路径/URL/参数正则匹配）：`src/skillsecurity/engine/matcher.py`
- 默认策略已覆盖高危命令（`rm -rf`、`curl|bash`、反向 shell、磁盘操作等）：`policies/default.yaml`
- 隐私外发检查（敏感数据 + 域名信誉矩阵）：`src/skillsecurity/privacy/outbound.py`
- 可疑域名与可信域名分类：`src/skillsecurity/privacy/domains.py`
- 财务操作强制 ask：`src/skillsecurity/privacy/financial.py`
- 行为链检测（读敏感文件后外发、侦察后外发等）：`src/skillsecurity/engine/chain.py`
- Skill 权限边界模型：`src/skillsecurity/engine/interceptor.py`
- MCP/OpenClaw 处理器包装：`src/skillsecurity/integrations/mcp.py`

---

## 4. 关键缺口（为什么“还防不全”）

### 4.1 规则层缺口

1. **缺少显式命令注入规则**  
   未见针对 `;`, `&&`, `||`, `` ` ``, `$()` 的通用拦截规则（策略层）。

2. **缺少路径穿越规则**  
   未见 `../`、`..\\`、`%2e%2e` 等路径穿越模式规则；也缺少“路径归一化后越界”判断。

3. **`url_pattern` 引擎支持但内置策略未实配**  
   当前内置 policy 未用 URL 规则做恶意域名硬拦截（主要靠隐私层和域名信誉逻辑）。

### 4.2 架构层缺口

4. **无法治理网关默认暴露与认证配置**  
   当前没有“部署基线审计器”（例如检测 `0.0.0.0` 暴露、弱认证配置）。

5. **缺少调用方身份上下文约束**  
   在 OpenClaw 集成包装里，主要传入 `tool_name`+`arguments`，缺少 `caller_role/scope` 级别的强约束策略。

6. **供应链治理不完整**  
   仅静态代码扫描不足以覆盖插件签名、来源可信性、依赖 CVE、生命周期风险。

7. **默认策略偏“平衡”，非“强隔离”**  
   默认 policy 的 `default_action=allow`，对于未知模式更偏可用性，非安全极限模式。

---

## 5. 需要补全的资料（文档与情报侧）

建议新增一套“可持续更新”的资料体系，而不只是一次性分析：

1. **漏洞对照台账（建议放 `docs/security-intel/openclaw-vuln-matrix.md`）**  
   字段建议：`ID/GHSA/CVE`、`CWE`、`影响版本`、`利用前提`、`是否可被 SkillSecurity 检测`、`缺口`、`修复状态`。

2. **防护映射矩阵（通报项 -> 规则/模块）**  
   形成“官方预警五项”到仓库模块的固定映射，便于每次版本发布做差异审计。

3. **高危 PoC 回归清单**  
   将命令注入、路径遍历、访问控制绕过等 PoC 固化为测试用例（单元 + 集成）。

4. **部署基线清单（OpenClaw + SkillSecurity 联合）**  
   最低要求：loopback 绑定、认证开启、TLS、IP 白名单、最小权限运行、禁用不可信插件。

5. **应急响应 Runbook**  
   包含：发现异常后的封禁策略、日志取证点、规则热更新顺序、业务恢复步骤。

---

## 6. 改进方案（按优先级落地）

## P0（1~3 天，先止血）

1. **新增 `openclaw-hardened` 策略模板**（建议新文件：`policies/openclaw-hardened.yaml`）  
   - 默认 `block`  
   - 强制 `network.request` 写操作 `ask` 或 `block`  
   - 增加命令注入与路径穿越规则  
   - 增加恶意域名 `url_pattern` 规则

2. **补齐命令注入 + 路径穿越规则到默认策略**（`policies/default.yaml`）  
   - 命令注入：`;|&&|\|\||\$\(|\``  
   - 路径穿越：`(\.\./|\.\.\\|%2e%2e)`  
   - 下载落地敏感目录：`curl|wget` + 输出到系统目录

3. **OpenClaw 集成默认启用 strict/hardened 模式**  
   - 降低“默认 allow”带来的未知风险窗口。

## P1（1~2 周，补能力短板）

4. **引入“归一化路径越界检查”**（非纯正则）  
   - 对 `path` 做 resolve/normalize 后判断是否越出允许根目录。

5. **引入“命令语义解析”辅助检测**  
   - 对 shell 命令做 token 级解析，识别参数拼接绕过（safeBins 类问题）。

6. **增加部署安全审计器（startup audit）**  
   - 检测绑定地址、认证状态、危险端口、弱口令/默认 token 风险并告警。

7. **集成上下文权限约束**  
   - 策略输入中增加 `caller_role`、`scope`，实现 owner/admin/operator 级限制。

## P2（2~4 周，体系化）

8. **供应链安全增强**  
   - 插件来源白名单、签名校验、SBOM、依赖漏洞扫描（OSV/GHSA feed）  
   - 插件安装前风险评分与阻断策略

9. **漏洞情报自动同步**  
   - 定时抓取 OpenClaw GHSA/CVE，自动映射到本地规则建议和回归测试任务。

10. **规则效果度量体系**  
   - 指标：拦截率、误报率、绕过率、修复时效、回归覆盖率。

---

## 7. 可直接落地的规则补充示例（草案）

```yaml
- id: "block-command-injection-metachar"
  tool_type: shell
  match:
    command_pattern: "(;|&&|\\|\\||\\$\\(|`)"
  action: block
  severity: critical
  message: "Possible command injection metacharacters detected"

- id: "block-path-traversal"
  tool_type:
    - file.read
    - file.write
    - file.delete
  match:
    path_pattern: "(\\.\\./|\\.\\.\\\\|%2e%2e)"
  action: block
  severity: high
  message: "Path traversal pattern detected"

- id: "block-suspicious-url-direct"
  tool_type: network.request
  match:
    url_pattern: "(?i)(webhook\\.site|requestbin\\.com|.*\\.ngrok\\.io)"
  action: block
  severity: high
  message: "Request to suspicious URL blocked"
```

---

## 8. 最终结论（给决策者）

- SkillSecurity 作为“AI 工具调用防火墙”，**对行为级风险有效**，尤其是危险命令、敏感数据外发、行为链攻击。  
- 但它**不能替代 OpenClaw 平台安全修复**：认证、会话授权、插件加载链路、默认公网暴露等问题必须由平台配置与版本升级先兜底。  
- 最稳妥策略是“**平台修复 + SkillSecurity 行为防火墙**”双层防护。  
- 建议立即执行 P0，加速补齐命令注入/路径穿越/URL 强拦截，并建立漏洞情报台账与回归基线。

---

## 参考来源

- [央视网转引：国家网络安全通报中心发布 OpenClaw 安全风险预警（新浪）](https://news.sina.com.cn/c/2026-03-13/doc-inhqvxrm4044765.shtml)
- [每经快讯（通报摘要）](https://www.nbd.com.cn/articles/2026-03-13/4291686.html)
- [财联社（通报摘要）](https://www.cls.cn/detail/2312439)
- [OpenClaw Security Overview](https://github.com/openclaw/openclaw/security)
- [GHSA-p25h-9q54-ffvw（Zip Slip 路径遍历）](https://github.com/openclaw/openclaw/security/advisories/GHSA-p25h-9q54-ffvw)
- [GHSA-3x3x-h76w-hp98（exec allowlist 绕过）](https://github.com/openclaw/openclaw/security/advisories/GHSA-3x3x-h76w-hp98)
- [GHSA-g2f6-pwvx-r275（SCP 路径命令注入）](https://github.com/openclaw/openclaw/security/advisories/GHSA-g2f6-pwvx-r275)
- [GHSA-rqpp-rjj8-7wv8（WebSocket scope 越权）](https://github.com/openclaw/openclaw/security/advisories/GHSA-rqpp-rjj8-7wv8)
- [GHSA-r7vr-gr74-94p8（owner-only 访问控制缺陷）](https://github.com/openclaw/openclaw/security/advisories/GHSA-r7vr-gr74-94p8)
- [GHSA-99qw-6mr3-36qr（插件自动发现代码执行）](https://github.com/openclaw/openclaw/security/advisories/GHSA-99qw-6mr3-36qr)

