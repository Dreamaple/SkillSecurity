# 数据分类引擎与隐私保护层设计

> **版本**: 0.4.0  
> **日期**: 2026-03-11  
> **关联**: [威胁模型 T5/T6/T7/T8](threat-model.md) / [架构概述](architecture-overview.md)  
> **Phase**: Phase 2 核心交付

---

## 1. 概述

数据分类引擎（Data Classification Engine）是 SkillSecurity 隐私保护层的核心组件，负责在运行时自动识别工具调用中流动的敏感数据。它与出站检查器（Outbound Inspector）、财务操作识别器（Financial Detector）、域名信誉库（Domain Intelligence）共同构成完整的隐私保护层。

### 1.1 设计目标

| 目标 | 指标 |
|---|---|
| 检出率 | ≥ 95% 已知格式的 API Key/Token 被检出 |
| 误报率 | < 5% 正常字符串被误判为敏感数据 |
| 延迟 | 单次分类 < 5ms（平均），不显著增加拦截延迟 |
| 可扩展 | 用户可添加自定义敏感数据模式 |
| 隐私 | 分类过程纯本地，不上传任何数据 |

### 1.2 核心能力

```
              ┌────────────────────────────────────────────────┐
              │           Data Classification Engine            │
              │                                                 │
              │  ┌─────────┐ ┌─────────┐ ┌────────────┐       │
              │  │ Secret  │ │  PII    │ │ Financial  │       │
              │  │Detector │ │Detector │ │ Detector   │       │
              │  └────┬────┘ └────┬────┘ └─────┬──────┘       │
              │       │           │             │              │
              │  ┌────┴───────────┴─────────────┴──────┐       │
              │  │                                      │       │
              │  │  ┌────────────┐  ┌────────────────┐ │       │
              │  │  │  Entropy   │  │ Chat Detector  │ │       │
              │  │  │  Analyzer  │  │ (聊天数据检测)  │ │       │
              │  │  └─────┬──────┘  └───────┬────────┘ │       │
              │  │        │                 │          │       │
              │  └────────┴────────┬────────┘──────────┘       │
              │                    ▼                            │
              │         ┌──────────────────────┐               │
              │         │  Classification      │               │
              │         │  Result              │               │
              │         └──────────────────────┘               │
              └────────────────────────────────────────────────┘
```

---

## 2. 敏感数据分类体系

### 2.1 分类层级

| 级别 | 类型 | 示例 | 检测方式 |
|---|---|---|---|
| **CRITICAL** | API 密钥 / Secret | OpenAI `sk-*`, AWS `AKIA*`, GitHub `ghp_*` | 前缀正则 + 格式校验 |
| **CRITICAL** | 认证凭证 | Bearer Token, Basic Auth, SSH 私钥 | 结构正则 |
| **HIGH** | 高熵疑似密钥 | 16+ 字符的高熵随机字符串 | Shannon 熵分析 |
| **HIGH** | 个人身份信息 (PII) | 邮箱、手机号、身份证号 | 结构正则 |
| **HIGH** | 金融数据 | 信用卡号、银行卡号 | Luhn 校验 + 正则 |
| **HIGH→CRITICAL** | 聊天/对话数据 | role/content 消息数组、对话导出、聊天日志 | 结构正则 + 批量检测（≥5条升级为 CRITICAL） |
| **HIGH** | 聊天文件路径 | chat_history.json、conversations.db、聊天应用数据目录 | 路径正则 |
| **MEDIUM** | 环境变量值 | 从 `os.environ` 读取的值 | 运行时标记追踪 |
| **MEDIUM** | 内部 URL / IP | 内网地址、localhost | CIDR 匹配 |
| **LOW** | 文件路径 | 绝对路径、用户目录路径 | 路径格式正则 |

### 2.2 已知 API Key 格式库

内置对主流服务的 API Key 格式识别：

```yaml
secret_patterns:
  # AI 服务
  - id: openai-api-key
    name: "OpenAI API Key"
    pattern: "sk-[a-zA-Z0-9]{20,}"
    severity: critical
    service: "OpenAI"

  - id: anthropic-api-key
    name: "Anthropic API Key"
    pattern: "sk-ant-[a-zA-Z0-9\\-]{20,}"
    severity: critical
    service: "Anthropic"

  - id: google-ai-key
    name: "Google AI API Key"
    pattern: "AIza[0-9A-Za-z\\-_]{35}"
    severity: critical
    service: "Google AI"

  # 云平台
  - id: aws-access-key
    name: "AWS Access Key"
    pattern: "AKIA[0-9A-Z]{16}"
    severity: critical
    service: "AWS"

  - id: aws-secret-key
    name: "AWS Secret Key"
    pattern: "[0-9a-zA-Z/+]{40}"
    requires_context: "aws_secret|secret_access_key"
    severity: critical
    service: "AWS"

  - id: gcp-service-account
    name: "GCP Service Account Key"
    pattern: '"type"\\s*:\\s*"service_account"'
    multiline: true
    severity: critical
    service: "GCP"

  - id: azure-subscription-key
    name: "Azure Subscription Key"
    pattern: "[0-9a-f]{32}"
    requires_context: "ocp-apim-subscription-key|azure"
    severity: critical
    service: "Azure"

  # 代码托管
  - id: github-pat
    name: "GitHub Personal Access Token"
    pattern: "ghp_[a-zA-Z0-9]{36}"
    severity: critical
    service: "GitHub"

  - id: github-fine-grained
    name: "GitHub Fine-Grained Token"
    pattern: "github_pat_[a-zA-Z0-9_]{22,}"
    severity: critical
    service: "GitHub"

  - id: gitlab-pat
    name: "GitLab Personal Access Token"
    pattern: "glpat-[a-zA-Z0-9\\-]{20,}"
    severity: critical
    service: "GitLab"

  # 支付
  - id: stripe-secret-key
    name: "Stripe Secret Key"
    pattern: "sk_(live|test)_[a-zA-Z0-9]{24,}"
    severity: critical
    service: "Stripe"

  - id: stripe-publishable-key
    name: "Stripe Publishable Key"
    pattern: "pk_(live|test)_[a-zA-Z0-9]{24,}"
    severity: high
    service: "Stripe"

  # 通用
  - id: jwt-token
    name: "JWT Token"
    pattern: "eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}"
    severity: high
    service: "JWT"

  - id: bearer-token
    name: "Bearer Token"
    pattern: "Bearer\\s+[a-zA-Z0-9\\-._~+/]+=*"
    severity: high
    service: "HTTP Auth"

  - id: basic-auth
    name: "Basic Auth Credentials"
    pattern: "Basic\\s+[A-Za-z0-9+/]+=*"
    severity: high
    service: "HTTP Auth"

  - id: private-key-pem
    name: "Private Key (PEM)"
    pattern: "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"
    severity: critical
    service: "Crypto"
```

### 2.3 PII 检测模式

```yaml
pii_patterns:
  - id: email
    name: "Email Address"
    pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
    severity: high
    region: global

  - id: phone-cn
    name: "Chinese Phone Number"
    pattern: "(?:\\+86)?1[3-9]\\d{9}"
    severity: high
    region: cn

  - id: phone-us
    name: "US Phone Number"
    pattern: "(?:\\+1)?[2-9]\\d{2}[\\-.]?\\d{3}[\\-.]?\\d{4}"
    severity: high
    region: us

  - id: id-card-cn
    name: "Chinese ID Card Number"
    pattern: "[1-9]\\d{5}(19|20)\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx]"
    severity: critical
    region: cn

  - id: ssn-us
    name: "US Social Security Number"
    pattern: "\\d{3}-\\d{2}-\\d{4}"
    severity: critical
    region: us

  - id: credit-card
    name: "Credit Card Number"
    pattern: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b"
    severity: critical
    validation: luhn
    region: global

  - id: iban
    name: "International Bank Account Number"
    pattern: "[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}([A-Z0-9]?){0,16}"
    severity: high
    region: global
```

### 2.4 聊天/对话数据检测模式

```yaml
chat_patterns:
  structure:
    - id: chat-messages-role-content
      name: "Chat messages (role/content format)"
      description: "OpenAI/Anthropic 格式的消息数组: {role: user/assistant, content: ...}"
      severity: high → critical (≥5 条)

    - id: chat-messages-array
      name: "Chat messages array"
      description: "包含 'messages' 键的数组结构"
      severity: high → critical (≥5 条)

    - id: chat-sender-text
      name: "Chat history (sender/text format)"
      description: "包含 sender/author + text/message 的对话格式"
      severity: high → critical (≥5 条)

    - id: chat-log-timestamped
      name: "Timestamped chat log"
      description: "时间戳标记的对话日志: [2026-03-11 10:00:00] User: ..."
      severity: medium

    - id: chat-conversation-export
      name: "Conversation export data"
      description: "包含 conversation_id/chat_id + messages/history 的导出结构"
      severity: high → critical (≥5 条)

  file_paths:
    - id: chat-history-file
      name: "Chat history file path"
      description: "聊天记录文件: chat_history.json/db, conversations.db, chat_log.txt 等"
      severity: high

    - id: chat-app-data-dir
      name: "Chat application data directory"
      description: "聊天应用数据目录: .telegram, .signal, .whatsapp, .slack, .discord 等"
      severity: high
```

**批量升级规则**：当检测到 payload 中包含 ≥ 5 条对话消息时，严重级别从 HIGH 升级为 CRITICAL。这是因为少量消息可能是正常 API 调用上下文，但大量消息表明整段对话历史正在被外发。

---

## 3. 信息熵分析器

对于没有已知前缀的密钥（如自定义 token、数据库密码等），使用 Shannon 熵检测高随机性字符串。

### 3.1 原理

Shannon 熵衡量字符串的随机性：
- 英文单词：熵约 2.5-3.5
- Base64 编码数据：熵约 5.0-6.0
- 随机密钥/Token：熵约 4.5-6.0
- 纯随机 hex：熵约 3.5-4.0

### 3.2 检测规则

```python
def shannon_entropy(data: str) -> float:
    """计算字符串的 Shannon 熵"""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * log2(count / length) for count in freq.values())

def is_likely_secret(token: str) -> bool:
    """判断字符串是否可能是密钥"""
    if len(token) < 16:
        return False
    entropy = shannon_entropy(token)
    if entropy > 4.5 and len(token) >= 20:
        return True
    if entropy > 4.0 and len(token) >= 32:
        return True
    return False
```

### 3.3 降低误报的策略

| 策略 | 说明 |
|---|---|
| 最小长度 | 仅检测 ≥ 16 字符的字符串 |
| 上下文排除 | 排除已知的非密钥高熵串（如 UUID、hash 输出） |
| 字典排除 | 排除包含常见英文单词的字符串 |
| 格式排除 | 排除文件路径、URL 中的 path 部分 |
| 用户白名单 | 允许用户标记误报 |

---

## 4. 出站数据检查器（Outbound Inspector）

### 4.1 触发条件

当工具调用类型为 `network.write`（POST/PUT/PATCH/DELETE）时激活检查。

### 4.2 检查流程

```python
class OutboundInspector:
    def inspect(self, tool_call: ToolCall) -> InspectionResult:
        """检查出站请求是否携带敏感数据"""

        # 1. 提取所有可能包含数据的字段
        payload = self._extract_payload(tool_call)

        # 2. 运行数据分类引擎
        matches = self.classifier.classify(payload)

        # 3. 查询域名信誉
        domain = self._extract_domain(tool_call)
        domain_trust = self.domain_intel.query(domain)

        # 4. 综合判定
        if matches.has_critical() and domain_trust != "trusted":
            return InspectionResult(action="block", matches=matches)
        elif matches.has_high() and domain_trust == "unknown":
            return InspectionResult(action="ask", matches=matches)
        elif matches.has_any() and domain_trust == "suspicious":
            return InspectionResult(action="block", matches=matches)
        else:
            return InspectionResult(action="allow")
```

### 4.3 决策矩阵

| 数据敏感度 \ 域名信誉 | trusted（可信） | known（已知） | unknown（未知） | suspicious（可疑） |
|---|---|---|---|---|
| **CRITICAL** (API Key) | Ask | Block | Block | Block |
| **HIGH** (PII/高熵) | Allow | Ask | Ask | Block |
| **MEDIUM** (环境变量) | Allow | Allow | Ask | Block |
| **LOW** (路径等) | Allow | Allow | Allow | Ask |

### 4.4 检查结果格式

```json
{
  "action": "block",
  "reason": "检测到出站请求中携带 OpenAI API Key",
  "severity": "critical",
  "matches": [
    {
      "type": "openai-api-key",
      "field": "body.api_key",
      "value_preview": "sk-****...****abcd",
      "confidence": 0.99
    }
  ],
  "domain": {
    "name": "unknown-analytics.com",
    "trust_level": "unknown",
    "first_seen": true
  },
  "suggestions": [
    "此请求包含 OpenAI API Key，但目标域名非 OpenAI 官方",
    "如果这是预期行为，请在策略中将该域名加入白名单"
  ]
}
```

---

## 5. 域名信誉库（Domain Intelligence）

### 5.1 信誉分级

| 信誉级别 | 说明 | 来源 |
|---|---|---|
| **trusted** | 已知安全的主流服务 | 内置白名单 |
| **known** | 已知但非核心的服务 | 社区维护 |
| **unknown** | 从未见过的域名 | 默认 |
| **suspicious** | 社区报告的可疑域名 | 威胁特征库 |

### 5.2 内置白名单（节选）

```yaml
trusted_domains:
  ai_services:
    - "api.openai.com"
    - "api.anthropic.com"
    - "generativelanguage.googleapis.com"
    - "api.mistral.ai"
    - "api.cohere.ai"

  code_hosting:
    - "api.github.com"
    - "gitlab.com"
    - "bitbucket.org"

  package_registries:
    - "pypi.org"
    - "registry.npmjs.org"
    - "crates.io"

  cloud_providers:
    - "*.amazonaws.com"
    - "*.googleapis.com"
    - "*.azure.com"
    - "*.cloudflare.com"

  search_engines:
    - "api.bing.com"
    - "serpapi.com"
    - "googleapis.com/customsearch"
```

### 5.3 首次外发提醒

当 Skill 首次向一个 `unknown` 域名发送数据时：

```
⚠️  [ASK] 首次外发到未知域名（风险等级: MEDIUM）
   Skill: data-processor
   目标: https://analytics.example.io/collect
   域名: analytics.example.io (首次出现)
   数据: POST body 包含 2.3KB 数据

   此域名不在已知安全域名列表中。是否允许? [y/N]
   (选择 'a' 将此域名加入白名单)
```

---

## 6. 财务操作识别器（Financial Detector）

### 6.1 检测范围

| 类别 | 检测方式 | 示例 |
|---|---|---|
| 支付 API | URL 模式匹配 | Stripe、PayPal、支付宝、微信支付 |
| 浏览器购买 | DOM 操作关键词 | "checkout"、"place order"、"subscribe" |
| 云资源创建 | API 动作识别 | AWS RunInstances、GCP instances.insert |
| 加密货币 | RPC 方法名 | eth_sendTransaction |

### 6.2 检测模式库

```yaml
financial_detection:
  payment_apis:
    - id: stripe
      patterns:
        - url: "api\\.stripe\\.com/v1/(charges|payment_intents|subscriptions|invoices)"
          method: POST
      severity: critical

    - id: paypal
      patterns:
        - url: "api\\.paypal\\.com/(v1|v2)/(payments|orders|billing)"
          method: POST
      severity: critical

    - id: alipay
      patterns:
        - url: "openapi\\.alipay\\.com"
          params: ["alipay\\.trade\\.(pay|create|precreate)"]
      severity: critical

    - id: wechat-pay
      patterns:
        - url: "api\\.mch\\.weixin\\.qq\\.com/(v3/)?(pay|transactions)"
          method: POST
      severity: critical

  cloud_resources:
    - id: aws-ec2
      patterns:
        - url: "ec2\\..*\\.amazonaws\\.com"
          params: ["Action=RunInstances"]
      severity: high

    - id: aws-general
      patterns:
        - url: ".*\\.amazonaws\\.com"
          params: ["Action=(Create|Launch|Purchase|Subscribe)"]
      severity: high

    - id: gcp-compute
      patterns:
        - url: "compute\\.googleapis\\.com/.*/instances"
          method: POST
      severity: high

    - id: azure-vm
      patterns:
        - url: "management\\.azure\\.com/.*/virtualMachines"
          method: PUT
      severity: high

  browser_actions:
    - id: purchase-button
      patterns:
        - selector_text: "(buy|purchase|order|checkout|subscribe|pay now)"
          action: click
      severity: critical

    - id: payment-form
      patterns:
        - input_name: "(card.number|cvv|cvc|expir|billing)"
          action: fill
      severity: critical

  crypto:
    - id: ethereum
      patterns:
        - method: "eth_sendTransaction|eth_signTransaction"
      severity: critical

    - id: bitcoin
      patterns:
        - method: "sendtoaddress|sendmany|sendrawtransaction"
      severity: critical
```

### 6.3 强制确认策略

财务操作的特殊处理：

| 规则 | 说明 |
|---|---|
| 不可跳过 | 即使策略配置为 `allow`，财务操作仍然触发 Ask |
| 明确展示金额 | 如果能解析金额，在确认提示中展示 |
| 二次确认 | CRITICAL 级财务操作需要输入 `CONFIRM` 而非 `y` |
| 审计强制 | 无论审计配置如何，财务操作始终记录 |

```
🔴 [FINANCIAL] 检测到财务操作（需要确认）
   Skill: shopping-assistant
   操作: POST https://api.stripe.com/v1/charges
   金额: $49.99 USD
   描述: "Premium subscription"

   ⚠️  这是一项涉及金钱的操作，无法自动跳过。
   输入 CONFIRM 确认执行，或按 Enter 拒绝:
```

---

## 7. 策略配置扩展

Phase 2 策略文件新增隐私保护相关配置：

```yaml
# skillsecurity.yaml — 隐私保护配置

privacy:
  enabled: true

  # 数据分类引擎
  classifier:
    secret_detection: true
    pii_detection: true
    entropy_detection: true
    min_entropy_threshold: 4.5
    min_token_length: 16
    custom_patterns: "./privacy-patterns.yaml"

  # 出站数据检查
  outbound_inspection:
    enabled: true
    check_body: true
    check_headers: true
    check_query_params: true
    max_body_scan_size: "1MB"

  # 域名信誉
  domain_intelligence:
    enabled: true
    trusted_domains_file: "./trusted-domains.yaml"
    alert_on_first_seen: true
    block_suspicious: true

  # 财务操作
  financial_protection:
    enabled: true
    force_ask: true
    require_explicit_confirm: true
    custom_patterns: "./financial-patterns.yaml"

  # 白名单与例外
  exceptions:
    # 这些域名的出站请求跳过敏感数据检查
    trusted_outbound:
      - "api.openai.com"
      - "api.anthropic.com"

    # 这些字段不做分类检查（降低误报）
    ignored_fields:
      - "user_agent"
      - "request_id"
      - "trace_id"
```

---

## 8. 代码模块结构

```
src/skillsecurity/
├── privacy/                    # 隐私保护层 (Phase 2 新增)
│   ├── __init__.py
│   ├── classifier.py           # 数据分类引擎主入口
│   ├── secrets.py              # 已知密钥格式匹配
│   ├── pii.py                  # PII 检测
│   ├── entropy.py              # Shannon 熵分析
│   ├── chat.py                 # 聊天/对话数据检测
│   ├── outbound.py             # 出站数据检查器
│   ├── financial.py            # 财务操作识别器
│   ├── domains.py              # 域名信誉库
│   └── patterns/               # 内置检测模式
│       ├── secret_patterns.yaml
│       ├── pii_patterns.yaml
│       ├── financial_patterns.yaml
│       └── trusted_domains.yaml
├── behavior/                   # 行为链追踪 (Phase 3 新增)
│   ├── __init__.py
│   ├── tracker.py              # 会话行为追踪器
│   ├── chain_rules.py          # 行为链规则引擎
│   └── risk_scorer.py          # 动态风险评分
├── engine/                     # 现有核心引擎
│   ├── interceptor.py          # 拦截器 (扩展: 调用隐私检查)
│   ├── policy.py
│   ├── matcher.py
│   └── decision.py             # 决策器 (扩展: 整合隐私检查结果)
└── ...
```

---

## 9. API 设计

### 9.1 数据分类 API

```python
from skillsecurity.privacy import DataClassifier

classifier = DataClassifier()

# 分类文本
result = classifier.classify("my api key is sk-abc123def456ghi789")
# ClassificationResult(
#   matches=[
#     SensitiveMatch(
#       type="openai-api-key",
#       value_preview="sk-****...789",
#       confidence=0.99,
#       severity="critical",
#       start=17, end=40
#     )
#   ]
# )

# 分类字典（深度扫描）
result = classifier.classify_dict({
    "url": "https://analytics.example.com/track",
    "headers": {"Authorization": "Bearer eyJ..."},
    "body": {"data": "user token is ghp_abcdefghijklmnopqrstuvwxyz1234567890"}
})
```

### 9.2 出站检查 API

```python
from skillsecurity.privacy import OutboundInspector

inspector = OutboundInspector()

result = inspector.inspect({
    "tool_type": "network.write",
    "params": {
        "url": "https://unknown-service.com/api",
        "method": "POST",
        "body": {"token": "sk-abc123..."}
    }
})
# InspectionResult(
#   action="block",
#   reason="出站请求携带 OpenAI API Key，目标域名不在信任列表",
#   matches=[...],
#   domain_info=DomainInfo(trust="unknown", first_seen=True)
# )
```

### 9.3 集成到现有 guard.check() 流程

```python
# 用户无需更改调用方式——隐私检查自动生效
from skillsecurity import SkillGuard

guard = SkillGuard()  # 默认启用隐私保护

result = guard.check({
    "tool": "network.write",
    "url": "https://example.com/track",
    "method": "POST",
    "body": {"key": "sk-abc123def456"}
})
# result.action == "block"
# result.reason == "出站请求中检测到 OpenAI API Key (sk-****...456)"
# result.privacy_matches == [...]
```

---

## 10. 测试计划

### 10.1 数据分类引擎测试

| 测试项 | 描述 | 测试数据 |
|---|---|---|
| 已知密钥检出 | 所有内置格式均能检出 | 各服务的示例 Key 格式 |
| PII 检出 | 邮箱/手机/身份证等 | 多国格式样本 |
| 熵检测准确性 | 高熵串被检出、低熵串不被误报 | 真实密钥 vs 正常文本 |
| 误报测试 | UUID、文件哈希、常见 ID 不被误报 | 误报样本集 |
| 性能测试 | 1KB/10KB/100KB payload 分类延迟 | 不同大小的 payload |

### 10.2 聊天数据检测测试

| 测试项 | 描述 | 测试数据 |
|---|---|---|
| OpenAI 消息格式检出 | role/content 结构被识别 | `{"messages": [{"role": "user", "content": "..."}]}` |
| 对话导出格式检出 | conversation_id + messages 被识别 | 带 ID 的对话导出 JSON |
| 时间戳日志检出 | `[timestamp] User: ...` 格式被识别 | 时间戳标记的对话日志 |
| 聊天文件路径检出 | chat_history.json 等被识别 | 各种聊天文件路径 |
| 聊天应用目录检出 | .telegram/.signal 等被识别 | 各平台数据目录路径 |
| 批量消息升级 | ≥5 条消息升级为 CRITICAL | 包含多条消息的 payload |
| 普通 JSON 不误报 | 非对话结构不被匹配 | 普通业务 JSON |
| 正常 API 调用不误报 | 单条 system prompt 不触发拦截 | 正常 OpenAI API 调用 |

### 10.3 出站检查测试

| 测试项 | 描述 |
|---|---|
| 含密钥的 POST 被拦截 | body 中携带各类 API Key |
| 含 PII 的 POST 触发 Ask | body 中携带邮箱/手机号 |
| 信任域名放行 | 向 api.openai.com POST Key 应 Allow |
| 未知域名触发 Ask | 首次外发到新域名 |
| 可疑域名拦截 | 向已知可疑域名发送任何数据 |

### 10.4 财务操作测试

| 测试项 | 描述 |
|---|---|
| 支付 API 被识别 | Stripe/PayPal 等 URL 触发 Ask |
| 浏览器购买被识别 | 点击"购买"按钮触发 Ask |
| 云资源创建被识别 | AWS RunInstances 触发 Ask |
| 非财务 API 不触发 | 普通 POST 请求不被误判为财务操作 |
| 强制确认不可跳过 | 即使策略 allow，财务操作仍需确认 |

### 10.5 域名信誉测试

| 测试项 | 描述 |
|---|---|
| 白名单域名放行 | 内置白名单中的域名正常通过 |
| 通配符匹配 | `*.amazonaws.com` 正确匹配子域名 |
| 首次外发提醒 | 新域名触发 Ask 且标记 `first_seen` |
| 自定义白名单 | 用户添加的域名被正确识别 |

---

## 11. 里程碑

| 周 | 目标 | 产出 |
|---|---|---|
| 第 5 周 | 权限清单 + 权限匹配（原 Phase 2 内容） | 权限系统可用 |
| 第 6 周 | 数据分类引擎 + 密钥/PII 检测 | classifier 模块可用 |
| 第 7 周 | 出站检查器 + 域名信誉库 | 隐私检查集成到拦截流程 |
| 第 8 周 | 财务操作识别器 + 审计日志 | 财务保护 + 审计可用 |
| 第 9 周 | 集成测试 + 策略模板 + 文档 | Phase 2 可发布 |

---

## 12. 交付物

| 交付物 | 说明 |
|---|---|
| 数据分类引擎 | `privacy/classifier.py` + 检测模式库 |
| 聊天数据检测器 | `privacy/chat.py` — 对话结构检测 + 聊天文件路径检测 |
| 出站检查器 | `privacy/outbound.py` |
| 域名信誉库 | `privacy/domains.py` + 内置白名单 |
| 财务操作识别器 | `privacy/financial.py` + 检测模式库 |
| 隐私策略模板 | `privacy-default.yaml` / `privacy-strict.yaml` |
| 内置检测模式 | YAML 格式的密钥/PII/财务模式定义 |
| API 文档 | 分类器/检查器的使用文档 |
| 测试集 | 覆盖各类敏感数据的测试样本 |
