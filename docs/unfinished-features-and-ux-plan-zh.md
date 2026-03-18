# SkillSecurity 未完成功能清单与交互体验方案（基于当前代码）

> 日期：2026-03-15  
> 范围：以当前仓库实现为准，聚焦“用户确认（含你提到的 allow 场景）”与交互体验。

---

## 进度更新（本轮已完成）

- [x] 统一审批票据内核：`ApprovalTicket + ApprovalService`（含 `ticket_id`）
- [x] 各框架 ASK 返回协议统一为 `skillsecurity.approval.v1`
- [x] Dashboard 增加待审批队列（查看、允许、拒绝）
- [x] 记忆决策能力（session/agent/global）与 Dashboard 撤销
- [x] Soft Ask（allow 前轻确认）基础能力已接入 `SkillGuard`
- [x] CLI 审批命令已接入（`approval list/approve/deny/revoke`，支持 `--api-url`）

---

## 0. 现状结论

- 目前核心拦截、规则匹配、隐私检查、行为链检测、P0/P1/P2 增强能力已可用。
- 但“**用户确认链路**”仍是最明显短板：确认逻辑分散、跨框架不一致、缺少统一审批中心与记忆机制。
- 这会直接影响体验：要么用户被频繁打断，要么出现“该确认却无法确认/不易确认”的问题。

---

## 1. 未完成功能点清单（按优先级）

## P0（必须补齐，影响正确性）

1. **统一 Ask 审批中心缺失**
   - **现状证据**：`AskPrompter` 仅在 CLI `check` 分支中生效，框架集成大多直接返回文本/报错。
   - **影响**：非 CLI 场景无法形成完整“待审批 -> 用户操作 -> 回执 -> 继续执行”闭环。
   - **建议补全**：引入 `ApprovalTicket` + `ApprovalService`，所有 `ASK` 统一产出 `ticket_id`。

2. **跨框架 Ask 行为不一致**
   - **现状证据**：`langchain`/`crewai` 返回字符串，`autogen` 返回 `(False, content)`，`mcp` 抛错或文本；`n8n` 仅返回 decision JSON。
   - **影响**：上层应用难以统一处理确认，前端/工作流适配成本高。
   - **建议补全**：定义统一协议：`{status: pending_approval, ticket_id, reason, expire_at}`。

3. **“Allow 的用户确认”缺失（Soft Confirmation）**
   - **现状证据**：`ALLOW` 直接执行；只有 `ASK` 才会交互。
   - **影响**：首次敏感但可接受操作（例如首次外发到新 trusted 域）缺少“轻确认”体验。
   - **建议补全**：新增 `allow_confirmation` 模式（软确认，不等同强制 Ask）。

## P1（强体验项，影响可用性）

4. **确认记忆（remember decision）缺失**
   - **现状证据**：无“允许一次/本会话/本 Agent/24h”缓存模型。
   - **影响**：重复弹窗，用户疲劳，审批质量下降。
   - **建议补全**：引入基于“风险指纹”的短期记忆与可撤销机制。

5. **Dashboard 无“待确认队列”**
   - **现状证据**：Dashboard 当前有日志/扫描/框架开关，无审批中心。
   - **影响**：运维场景无法可视化处理 Ask。
   - **建议补全**：新增 `Pending Approvals` 面板与 `Allow/Deny/Remember` 操作。

6. **确认解释信息不足**
   - **现状证据**：目前主要返回 `reason + suggestions`。
   - **影响**：用户难快速判断风险真实性，容易“全允许”或“全拒绝”。
   - **建议补全**：提供结构化解释卡：触发规则、风险影响、替代方案、历史相似审批结果。

7. **审批身份与权限模型缺失**
   - **现状证据**：无审批人角色验证（owner/security-admin/reviewer）。
   - **影响**：团队场景中审批边界不清晰。
   - **建议补全**：审批 API 加入 `approver_role` 和签名/令牌校验。

## P2（平台化能力）

8. **告警与确认通道联动不足**
   - **现状证据**：暂无多渠道告警与按钮回调确认（Slack/飞书）。
   - **影响**：远程协作审批体验弱。
   - **建议补全**：事件总线 + 通道适配器（告警与审批共享 ticket）。

9. **日志查询导出能力仍偏基础**
   - **现状证据**：`log` 命令过滤维度有限，导出格式与统计报表能力仍有限。
   - **影响**：审计与合规可用性不足。
   - **建议补全**：补 `tool_type/offset/sort/format(csv/jsonl)` 与报表命令。

10. **确认结果闭环指标未接入实时面板**
   - **现状证据**：已新增 `metrics`，但未进入 Dashboard 运营视图。
   - **影响**：难持续优化“打扰率、超时率、误报率”。
   - **建议补全**：Dashboard 增加体验指标卡（见第 3 节）。

---

## 2. 本轮已补的一处关键缺陷

- **LlamaIndex 集成 Ask 漏判已修复**：此前 `ASK` 未拦截会继续执行；现已补齐 `needs_confirmation` 分支并新增测试覆盖。

---

## 3. 用户体验友好的交互方案（建议落地版本）

## 3.1 交互目标

- **高风险不放过**：critical/high 需要强确认或阻断。
- **低风险少打扰**：常见安全操作尽量无感。
- **可解释可撤销**：每次确认“为什么、风险是什么、可否撤销”都清晰。

## 3.2 三层确认模型（重点：allow 用户确认）

1. **Hard Ask（强确认）**
   - 用于高风险（提权、外发敏感数据、财务操作）。
   - 超时默认拒绝。

2. **Soft Ask（Allow 前轻确认）**
   - 用于“可放行但建议确认”的场景（例如首次外发到新域、首次高权限工具调用）。
   - 默认策略可设为“倒计时自动允许 + 用户可一键取消”。
   - 这就是你提到的“allow 用户确认”最佳落地形态。

3. **No Prompt（无感放行）**
   - 低风险且命中记忆策略时直接放行。

## 3.3 统一审批票据（ApprovalTicket）模型

建议新增字段：

- `ticket_id`
- `decision_type` (`hard_ask` / `soft_ask`)
- `risk_fingerprint`（工具类型+关键参数归一化）
- `expires_at`
- `status` (`pending/approved/denied/timeout`)
- `scope` (`once/session/agent/global`)

## 3.4 多端交互流程

**CLI（同步）**
- 展示风险卡 -> 选项：
  - `允许一次`
  - `本会话允许`
  - `拒绝`
  - `查看详情`
- 支持数字快捷键，减少输入负担。

**Dashboard（异步）**
- 新增 `Pending Approvals` 列表：
  - 风险等级、剩余时间、触发规则、参数摘要
  - 操作按钮：`Allow Once` / `Allow Session` / `Deny` / `Always Deny`

**ChatOps（Slack/飞书）**
- 消息卡片带按钮，按钮回调后写回 `ticket_id` 状态。

## 3.5 “记住选择”设计（降低打扰核心）

- 默认仅 `session` 级别记忆，TTL 24h。
- 允许用户升级到 `agent/global`（需更高权限）。
- 每条记忆可在 Dashboard 撤销。

## 3.6 体验指标（持续优化）

建议新增并跟踪：

- `prompt_rate`（每 100 次调用触发确认数）
- `timeout_rate`
- `approve_rate`
- `false_positive_confirm_rate`（被频繁允许的规则）
- `mean_decision_time`（用户确认耗时）

---

## 4. 推荐实施顺序（两周可交付）

**第 1 周**
- ApprovalTicket + ApprovalService
- 统一框架返回协议
- Dashboard 待确认队列（最小版）

**第 2 周**
- Soft Ask（allow 用户确认）
- remember decision + 撤销
- CLI 体验升级（快捷键 + 详情卡）

---

## 5. 验收标准（建议）

- 框架侧 `ASK` 都能返回 `ticket_id`，无分叉行为。
- Soft Ask 开启后，确认打扰率下降且无高风险漏放。
- 用户可在 Dashboard 完成审批与撤销记忆。
- 审批日志可追溯（谁在何时允许了什么，依据是什么）。

