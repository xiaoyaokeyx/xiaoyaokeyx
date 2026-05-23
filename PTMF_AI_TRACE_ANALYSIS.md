# PTMF 消息跟踪 AI 分析方案

## 目标

本方案的目标不是让 AI 直接读取或逆向 `.ptmf` 二进制文件，而是建立一条稳定的分析流水线：

```text
PTMF 文件
  -> 原厂工具导出 TXT/CSV
  -> 程序解析成结构化消息
  -> 识别通信流程
  -> 对照正常流程和异常规则
  -> AI 生成问题定位报告
```

最终效果是：把一份 PTMF 消息跟踪文件交给系统，系统可以自动说明这次流程是否正常、失败发生在哪一步、关键证据消息是什么、可能原因是什么、下一步应该检查什么。

## 为什么不要让 AI 直接解 PTMF

`.ptmf` 通常是私有二进制 trace 格式，公开资料少，文件内部可能包含私有编码、压缩块、协议消息块、网元内部字段或版本相关结构。直接让 AI 分析原始二进制有几个问题：

- AI 不知道 PTMF 的私有文件结构。
- 同一个扩展名可能对应不同版本或不同设备导出的格式。
- 二进制内容不可检索，不利于定位某一条消息。
- 即使能看到部分字符串，也无法稳定还原完整流程。
- 后续无法积累样本、标注规则和分析经验。

更可靠的方式是使用 Huawei TraceViewer/PTMF Viewer 等原厂或现有工具把 PTMF 导出成可读文本，再由程序解析文本。AI 负责通信流程分析、异常归因和报告生成，而不是负责底层文件解码。

## 总体架构

```text
+------------------+
| PTMF 原始文件      |
+--------+---------+
         |
         v
+------------------+
| TraceViewer 导出  |
| TXT / CSV / XML   |
+--------+---------+
         |
         v
+------------------+
| 文本解析器         |
| parser            |
+--------+---------+
         |
         v
+------------------+
| 标准化消息 JSON    |
+--------+---------+
         |
         +--------------------+
         |                    |
         v                    v
+------------------+  +------------------+
| 流程识别器         |  | 知识库 / Playbook |
| procedure matcher |  | 正常流程 / 异常规则 |
+--------+---------+  +--------+---------+
         |                    |
         +---------+----------+
                   |
                   v
          +------------------+
          | AI 分析引擎       |
          | RAG + 规则 + LLM |
          +--------+---------+
                   |
                   v
          +------------------+
          | 分析报告          |
          +------------------+
```

## 第一步：PTMF 转成 TXT/CSV

优先使用原厂或已有工具完成转换。

### 推荐导出格式

优先级建议：

1. CSV：最容易被程序解析，列结构稳定。
2. XML：字段层级清楚，但文件可能较大。
3. TXT：最常见，但需要写解析规则。
4. PCAP：如果工具支持导出协议包，可结合 Wireshark 分析。

### 理想导出字段

尽量让导出的文本包含以下字段：

| 字段 | 说明 |
|---|---|
| timestamp | 消息时间戳，最好精确到毫秒 |
| direction | 消息方向，例如 UE -> gNB |
| protocol | 协议，例如 RRC、NAS、NGAP、S1AP、X2AP |
| message | 消息名，例如 RRCSetupRequest |
| source | 源网元 |
| target | 目标网元 |
| ue_id | 用户标识，例如 C-RNTI、AMF UE NGAP ID、SUPI、GUTI |
| cell_id | 小区标识 |
| cause | 失败原因码 |
| raw_detail | 原始消息详情 |

如果导出工具无法自定义字段，也可以先保留完整 TXT，后续通过 parser 抽取。

## 第二步：TXT 解析成标准 JSON

AI 更适合分析结构化数据，而不是直接分析长日志。建议把每条消息解析成统一 JSON。

### 单条消息 JSON

```json
{
  "index": 17,
  "time": "2026-05-23 10:21:33.123",
  "relative_ms": 1532,
  "direction": "UE -> gNB",
  "protocol": "RRC",
  "message": "RRCSetupRequest",
  "source": "UE",
  "target": "gNB",
  "ue_id": {
    "c_rnti": null,
    "amf_ue_ngap_id": null,
    "ran_ue_ngap_id": null,
    "supi": null,
    "guti": null
  },
  "cell": {
    "plmn": "460-00",
    "nr_cell_id": "123456",
    "tac": "1001"
  },
  "fields": {
    "establishmentCause": "mo-Signalling",
    "ue-Identity": "randomValue"
  },
  "cause": null,
  "raw": "原始导出消息内容"
}
```

### 一次 trace 的 JSON

```json
{
  "trace_id": "case-20260523-001",
  "source_file": "sample.ptmf",
  "export_file": "sample.txt",
  "network": "5G",
  "scenario": "registration",
  "start_time": "2026-05-23 10:21:31.591",
  "end_time": "2026-05-23 10:21:35.812",
  "messages": [],
  "metadata": {
    "vendor": "Huawei",
    "tool": "TraceViewer",
    "export_format": "txt",
    "parser_version": "0.1.0"
  }
}
```

### Parser 设计原则

解析器不需要一次做得很完美，但要保证输出稳定。

- 每条消息必须有 `index`。
- 能解析时间戳就填 `time`，不能解析就保留原始行。
- 能识别协议和消息名就填 `protocol/message`。
- 原始文本必须保留在 `raw`，避免解析丢信息。
- 不确定的字段填 `null`，不要猜。
- 解析失败的消息也要保留，标记为 `parse_status: "partial"` 或 `parse_status: "failed"`。

## 第三步：建立正常流程知识库

AI 要能判断异常，必须先知道正常流程是什么。建议把正常流程整理成 Playbook，而不是只靠模型记忆。

### 5G Registration 正常流程示例

```text
1. UE -> gNB: RRCSetupRequest
2. gNB -> UE: RRCSetup
3. UE -> gNB: RRCSetupComplete
4. gNB -> AMF: InitialUEMessage
5. AMF -> UE: Authentication Request
6. UE -> AMF: Authentication Response
7. AMF -> UE: Security Mode Command
8. UE -> AMF: Security Mode Complete
9. AMF -> UE: Registration Accept
10. UE -> AMF: Registration Complete
```

### 5G PDU Session Establishment 正常流程示例

```text
1. UE -> AMF: PDU Session Establishment Request
2. AMF -> SMF: Nsmf_PDUSession_CreateSMContext Request
3. SMF -> UPF: PFCP Session Establishment Request
4. UPF -> SMF: PFCP Session Establishment Response
5. SMF -> AMF: N1N2 Message Transfer
6. AMF -> gNB: PDU Session Resource Setup Request
7. gNB -> UE: RRC Reconfiguration
8. UE -> gNB: RRC Reconfiguration Complete
9. gNB -> AMF: PDU Session Resource Setup Response
10. AMF -> SMF: Nsmf_PDUSession_UpdateSMContext
```

### 4G Attach 正常流程示例

```text
1. UE -> eNB: RRCConnectionRequest
2. eNB -> UE: RRCConnectionSetup
3. UE -> eNB: RRCConnectionSetupComplete + Attach Request
4. eNB -> MME: InitialUEMessage
5. MME -> UE: Authentication Request
6. UE -> MME: Authentication Response
7. MME -> UE: Security Mode Command
8. UE -> MME: Security Mode Complete
9. MME -> SGW/PGW: Create Session Request
10. SGW/PGW -> MME: Create Session Response
11. MME -> UE: Attach Accept
12. UE -> MME: Attach Complete
```

## 第四步：异常规则库

只让 AI 自由判断容易不稳定。建议把常见异常写成规则，再让 AI 结合 trace 解释。

### 通用异常规则

| 异常类型 | 判断方式 | 可能原因 |
|---|---|---|
| 消息缺失 | 正常流程中的关键消息不存在 | 无线侧失败、核心网无响应、trace 不完整 |
| 顺序异常 | 后续消息早于前置消息 | 重传、解析错误、流程交叉 |
| Reject | 出现 Reject/Failure 消息 | 鉴权失败、权限限制、参数错误 |
| Cause 异常 | cause 字段不为空且属于失败原因 | 需根据协议 cause code 解释 |
| 超时 | 请求后长时间没有响应 | 网元无响应、链路问题、负荷问题 |
| 重复重传 | 同一请求重复多次 | 空口质量差、对端未响应、定时器超时 |

### 5G Registration 异常示例

```text
规则：Authentication Reject
触发条件：
- trace 中出现 Authentication Reject

分析方向：
- 检查 SUPI/SUCI 是否正确
- 检查 USIM 鉴权参数
- 检查 AUSF/UDM 是否返回鉴权失败
- 检查 AMF 选择和 PLMN 配置

报告要求：
- 给出 Authentication Request/Response/Reject 的时间顺序
- 引用 Reject 中的 cause
- 判断失败阶段为鉴权阶段
```

```text
规则：Security Mode Failure
触发条件：
- trace 中出现 Security Mode Failure
- 或 Security Mode Command 后没有 Security Mode Complete

分析方向：
- 检查加密/完整性算法协商
- 检查 UE 能力
- 检查 AMF 安全上下文
```

### PDU Session 异常示例

```text
规则：PDU Session Establishment Reject
触发条件：
- trace 中出现 PDU Session Establishment Reject

分析方向：
- 检查 DNN 是否配置
- 检查 S-NSSAI 是否允许
- 检查 SMF/UPF 选择
- 检查用户签约数据
- 检查 cause code
```

## 第五步：AI 分析方式

推荐采用“规则 + RAG + LLM 总结”的方式，而不是一开始就微调模型。

### 为什么先用 RAG

RAG 的优点：

- 可以随时更新正常流程和异常规则。
- 不需要大量训练样本。
- 分析结果更容易追溯。
- 可以要求 AI 引用具体消息作为证据。
- 后续可以逐步加入专家经验。

微调更适合后期已有大量已标注案例时使用，比如几百到几千个“trace + 根因 + 处理建议”的样本。

### 输入给 AI 的内容

AI 不应该直接吃完整原始 TXT，而应该输入筛选后的结构：

```json
{
  "task": "分析 5G 注册失败原因",
  "procedure": "5g_registration",
  "expected_flow": [],
  "detected_flow": [],
  "abnormal_events": [],
  "key_messages": [],
  "raw_evidence": []
}
```

### AI 输出格式

建议固定输出模板：

```markdown
## 结论

本次失败发生在 xxx 阶段，主要证据是 xxx。

## 关键证据

| 时间 | 协议 | 消息 | 方向 | 说明 |
|---|---|---|---|---|

## 正常流程对比

| 正常步骤 | 实际情况 | 判断 |
|---|---|---|

## 可能原因

1. 原因 A
2. 原因 B
3. 原因 C

## 建议检查

1. 检查 xxx 配置
2. 检查 xxx 网元日志
3. 检查 xxx cause code

## 置信度

高 / 中 / 低，并说明原因。
```

## 推荐 Prompt

### 系统 Prompt

```text
你是移动通信消息跟踪分析助手，擅长分析 4G/5G 信令流程。

你必须遵守以下规则：
1. 只根据输入 trace、正常流程知识库和异常规则分析。
2. 不要编造 trace 中不存在的消息。
3. 每个结论都要引用具体消息作为证据。
4. 如果证据不足，明确说明缺少哪些消息或字段。
5. 优先判断失败阶段，再判断可能原因。
6. 输出必须包含：结论、关键证据、正常流程对比、可能原因、建议检查、置信度。
```

### 用户 Prompt 模板

```text
请分析下面的消息跟踪。

场景：{scenario}
网络制式：{network}
正常流程：
{expected_flow}

异常规则：
{rules}

实际消息：
{messages}

请判断：
1. 流程是否正常？
2. 如果失败，失败发生在哪一步？
3. 关键证据消息有哪些？
4. 最可能的原因是什么？
5. 下一步应该检查什么？
```

## 数据分块策略

一份 trace 可能很长，不能直接全部塞给 AI。需要先分块。

### 推荐分块维度

1. 按 UE/session 分块：同一个 UE 的消息放一起。
2. 按流程分块：Registration、PDU Session、Handover、TAU、Attach 等。
3. 按时间窗口分块：例如每 30 秒或每个异常点前后 20 条消息。
4. 按异常事件分块：Reject/Failure/Timeout 前后消息优先。

### 分块后的索引字段

```json
{
  "chunk_id": "case-001-ue-001-registration",
  "trace_id": "case-001",
  "ue_key": "amf_ue_ngap_id:12345",
  "procedure": "5g_registration",
  "start_time": "2026-05-23 10:21:31.591",
  "end_time": "2026-05-23 10:21:35.812",
  "message_count": 38,
  "has_failure": true,
  "failure_message": "Authentication Reject",
  "summary": "UE registration reaches authentication phase and receives Authentication Reject."
}
```

## 最小可行版本

建议先做一个小版本，不要一开始覆盖所有协议。

### MVP 范围

支持：

- 输入：TraceViewer 导出的 TXT。
- 输出：结构化 JSON 和 Markdown 分析报告。
- 场景：先支持 5G Registration。
- 异常：先支持 Reject、Failure、缺消息、超时。
- 分析方式：规则判断 + AI 总结。

暂不支持：

- 直接解析 `.ptmf` 二进制。
- 自动识别所有协议。
- 微调模型。
- 完整图形界面。
- 所有 4G/5G 流程。

### MVP 目录建议

```text
ptmf_ai/
  parser.py
  procedure_detector.py
  rule_engine.py
  ai_analyzer.py
  schemas.py
  playbooks/
    5g_registration.md
    5g_pdu_session.md
  rules/
    common_rules.yaml
    5g_registration_rules.yaml
  samples/
    exports/
    json/
    reports/
```

## 实施阶段

### 阶段 1：收集样本

目标：确认导出的 TXT 长什么样。

需要准备：

- 1 个正常流程 PTMF 导出 TXT。
- 1 个异常流程 PTMF 导出 TXT。
- 如果可能，导出同一文件的 CSV/XML 版本。
- 人工标注每个样本的实际结论，例如“注册成功”“鉴权失败”“PDU 建立被拒绝”。

产出：

- 样本文件。
- 导出格式说明。
- 初版字段映射表。

### 阶段 2：开发 Parser

目标：把 TXT 转成标准 JSON。

重点：

- 识别消息边界。
- 解析时间戳。
- 解析协议名。
- 解析消息名。
- 解析方向。
- 保留 raw 原文。

产出：

- `parser.py`
- JSON schema
- 样本 JSON

### 阶段 3：正常流程和异常规则

目标：让系统知道“什么是正常”。

重点：

- 编写 5G Registration 正常流程。
- 编写常见失败规则。
- 写流程匹配逻辑。
- 生成正常流程对比表。

产出：

- Playbook 文档。
- Rules YAML。
- Procedure detector。

### 阶段 4：AI 分析报告

目标：让 AI 基于结构化结果生成可读报告。

重点：

- 固定 prompt。
- 输入关键消息，不输入整份大日志。
- 要求 AI 引用证据。
- 输出 Markdown。

产出：

- `ai_analyzer.py`
- Markdown 报告。
- 分析结果样例。

### 阶段 5：扩展更多流程

后续可以逐步支持：

- 5G PDU Session Establishment
- 5G Handover
- 4G Attach
- 4G TAU
- VoLTE 注册和呼叫
- EPS Fallback
- NSA EN-DC 添加和释放

## 样例报告

```markdown
# PTMF Trace 分析报告

## 结论

本次 5G 注册失败发生在鉴权阶段。UE 完成 RRC 建链并发送 Registration Request 后，网络侧发起 Authentication Request，UE 返回 Authentication Response，但随后网络侧下发 Authentication Reject，流程终止。

## 关键证据

| 时间 | 协议 | 消息 | 方向 | 说明 |
|---|---|---|---|---|
| 10:21:31.591 | RRC | RRCSetupRequest | UE -> gNB | UE 发起 RRC 建链 |
| 10:21:32.004 | NAS | Registration Request | UE -> AMF | UE 发起注册 |
| 10:21:33.123 | NAS | Authentication Request | AMF -> UE | 网络侧发起鉴权 |
| 10:21:33.456 | NAS | Authentication Response | UE -> AMF | UE 返回鉴权响应 |
| 10:21:33.789 | NAS | Authentication Reject | AMF -> UE | 网络侧拒绝鉴权 |

## 正常流程对比

| 正常步骤 | 实际情况 | 判断 |
|---|---|---|
| RRCSetupRequest | 已出现 | 正常 |
| RRCSetup | 已出现 | 正常 |
| RRCSetupComplete | 已出现 | 正常 |
| InitialUEMessage | 已出现 | 正常 |
| Authentication Request | 已出现 | 正常 |
| Authentication Response | 已出现 | 正常 |
| Security Mode Command | 未出现 | 异常 |
| Registration Accept | 未出现 | 异常 |

## 可能原因

1. UE 鉴权参数与核心网侧不一致。
2. UDM/AUSF 返回鉴权失败。
3. SUPI/SUCI 或用户签约数据异常。
4. AMF 选择的 PLMN 或切片配置与用户签约不匹配。

## 建议检查

1. 检查 Authentication Reject 的 cause 字段。
2. 检查 AMF 到 AUSF/UDM 的鉴权交互日志。
3. 核对 SIM/USIM 中的鉴权参数。
4. 核对用户签约数据、PLMN 和 S-NSSAI。

## 置信度

高。trace 中已经出现 Authentication Reject，并且后续 Security Mode Command 和 Registration Accept 均未出现，失败阶段明确。
```

## 训练与学习策略

这里的“让 AI 学习正常流程”建议分三层做。

### 第一层：知识库学习

把正常流程、异常规则、cause code 解释、专家经验写成 Markdown/YAML，作为 RAG 知识库。

优点：

- 更新快。
- 可控。
- 不需要训练模型。
- 适合早期建设。

### 第二层：案例库学习

每分析一个问题，都保存：

```text
trace 样本
结构化消息
最终结论
专家确认结果
处理建议
```

后续 AI 分析新 trace 时，可以检索相似案例。

### 第三层：模型微调

当积累足够多高质量样本后，再考虑微调。

适合微调的数据格式：

```json
{
  "input": "结构化 trace + 场景 + 关键消息",
  "output": "专家确认后的分析报告"
}
```

建议至少积累几十到几百个高质量案例后再考虑微调。早期不要把主要精力放在微调上，先把解析、规则和案例库做好。

## 关键风险

| 风险 | 影响 | 应对 |
|---|---|---|
| PTMF 无法直接解析 | 无法从二进制得到消息 | 使用 TraceViewer 导出 TXT/CSV |
| 导出 TXT 格式不稳定 | Parser 容易失败 | 保留 raw，按样本迭代 parser |
| trace 消息不完整 | AI 误判 | 报告中明确证据不足 |
| 多 UE 流程混在一起 | 时间线混乱 | 按 UE/session 分组 |
| AI 编造原因 | 结论不可信 | 强制引用消息证据 |
| 专家规则缺失 | 只能泛泛而谈 | 持续积累 playbook 和案例库 |

## 推荐下一步

1. 准备一份 PTMF 导出的 TXT 或 CSV。
2. 从里面截取一个完整流程，包含正常或异常都可以。
3. 定义第一版消息边界和字段映射。
4. 写 parser，把导出文件转成 JSON。
5. 先支持一个流程，例如 5G Registration。
6. 用规则找出异常点，再让 AI 生成报告。

最关键的第一个样本是 PTMF 导出的 TXT/CSV。只要拿到真实导出格式，就可以开始设计 parser 和标准 JSON。
