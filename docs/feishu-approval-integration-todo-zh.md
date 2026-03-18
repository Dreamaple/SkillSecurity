# 飞书审批集成执行清单（待办）

> 目标：基于飞书官方 SDK 接入机器人交互卡片，实现 SkillSecurity `ticket_id` 按钮审批闭环。  
> 状态：未开始（后续按指令逐项执行）

---

## 0. 技术路线确认

- [ ] 使用飞书官方 SDK（Python：`lark-oapi`）作为首选实现
- [ ] 明确消息形态：交互卡片按钮（允许一次 / 本会话允许 / 拒绝）
- [ ] 明确回调协议：`ticket_id` + `decision` + `scope` + 时间戳 + 业务签名

---

## 1. 前置准备

- [ ] 创建飞书企业自建应用（机器人能力开启）
- [ ] 开通交互卡片与事件回调能力
- [ ] 配置回调公网 HTTPS 地址（测试环境优先）
- [ ] 准备密钥与配置项（走环境变量）
  - [ ] `APP_ID`
  - [ ] `APP_SECRET`
  - [ ] `VERIFICATION_TOKEN`
  - [ ] `ENCRYPT_KEY`（如启用加密）
- [ ] 建立测试群并邀请机器人

---

## 2. 发送审批卡片（MVP）

- [ ] 新增飞书通知通道模块（建议：`src/skillsecurity/alerts/feishu.py`）
- [ ] 封装发送接口：输入 `ticket_id`、风险级别、触发规则、摘要参数
- [ ] 卡片按钮携带审批参数（allow/deny/scope）
- [ ] 失败降级：发送失败不阻塞主拦截流程，仅审计告警

---

## 3. 回调按钮审批（MVP）

- [ ] 新增飞书回调路由（建议挂在 Dashboard Server）
- [ ] 校验飞书平台签名
- [ ] 校验业务签名与时间戳（防篡改、防重放）
- [ ] 调用现有审批核心：`resolve_approval_ticket(...)`
- [ ] 做幂等：同一 `ticket_id` 重复点击只首次生效
- [ ] 回调后更新卡片状态（已批准/已拒绝/已超时）

---

## 4. 与现有审批体系对齐

- [ ] 与统一协议 `skillsecurity.approval.v1` 对齐
- [ ] 明确 `hard_ask` 与 `soft_ask` 在飞书侧展示差异
- [ ] 审批 scope 映射一致（`once/session/agent/global`）
- [ ] 审计日志补全字段（渠道、审批人、审批耗时、来源消息 ID）

---

## 5. 配置与运维

- [ ] 增加配置节（示例）：
  - [ ] `alerts.channels[].type = feishu`
  - [ ] `approval.channels.feishu.enabled = true`
  - [ ] `approval.channels.feishu.default_scope = session`
- [ ] 增加开关与限流（防消息风暴）
- [ ] 增加失败重试策略（指数退避）
- [ ] 增加健康检查命令（验证 token、群可达、回调可达）

---

## 6. 测试清单

- [ ] 单元测试：签名校验、参数解析、scope 处理、幂等
- [ ] 集成测试：创建票据 -> 发卡片 -> 点按钮 -> ticket 状态变更
- [ ] 回归测试：不影响现有 CLI/Dashboard 审批流程
- [ ] 异常测试：回调重复、过期票据、签名错误、网络超时

---

## 7. 文档与发布

- [ ] 更新 `README.md` / `README_zh.md`（飞书审批配置与示例）
- [ ] 更新 `docs/how-it-works.md`（审批通道架构图）
- [ ] 增加“故障排查”章节（回调失败、签名错误、权限不足）
- [ ] 发布前演练：测试群全链路录屏与审计核对

---

## 8. 验收标准

- [ ] 用户点击飞书按钮后，3 秒内完成 `ticket` 决议写入
- [ ] 回调失败不影响主拦截链路
- [ ] 关键链路全量可审计（谁、何时、对哪个 `ticket_id` 做了什么）
- [ ] 与 CLI / Dashboard 审批结果一致，无状态分叉
