# OctoBus 能力集成

## 1. 原则

OctoBus 是能力网关，不是 Agent 规划器。每个能力应是参数受限、返回结构化、可审计的业务函数，而不是一个“执行任意命令”的入口。

运行时链路：

```text
Agent Sandbox
  └── CAP_GRPC_TARGET + per-sandbox CAP_TOKEN
       └── agent-compose capability proxy
            └── OctoBus daemon
                 └── approved service instance
```

上游 OctoBus Token 只应保存在 agent-compose daemon 侧，不进入 Sandbox。

## 2. Capset 设计

本仓库在 `capabilities/catalog.yaml` 定义目标能力目录。最小权限原则：

- `traffic-readonly`：PCAP/日志解析和会话查询；
- `alert-readonly`：告警及关联事件查询；
- `asset-readonly`：资产、业务和责任上下文；
- `endpoint-readonly`：进程、登录和终端事件；
- `threat-intel-readonly`：受控 IOC 丰富化；
- `exposure-readonly`、`vulnerability-readonly`：暴露面和漏洞资料；
- `attack-validation-gated`：审批后的低影响验证；
- `compliance-readonly`：法规、标准和控制项；
- `customer-evidence-readonly`：客户制度与审计证据；
- `report-render`、`template-readonly`：确定性统计和文档渲染；
- `security-evidence`：受控写 Evidence，不能修改历史记录。

不要建立一个包含全部方法的 `security-all` capset。

## 3. 服务方法契约

每个方法必须定义：

- 参数 Schema 和最大长度；
- 租户和调用者上下文；
- 所需 capset 与风险级别；
- 超时、最大并发、速率和响应大小；
- 是否产生外部网络请求；
- 是否需要 `authorization_ref` 和 `approval_id`；
- 审计字段和证据输出；
- 明确错误码；
- 版本与弃用策略。

示例：

```yaml
method: traffic.inspect_file
risk: read_only
request:
  artifact_uri: artifact://...
  expected_sha256: ...
response:
  format: pcap
  size_bytes: 1024
  start_time: 2026-09-01T00:00:00Z
  end_time: 2026-09-01T01:00:00Z
  warnings: []
```

## 4. 高风险能力的双重校验

`attack-validation-gated` 服务必须在工具侧再次校验：

- 目标是否在 CIDR/域名/资产清单中；
- DNS 当前解析是否仍在范围内；
- 请求方法、端口和模板是否获批；
- 当前时间是否在授权窗口内；
- 请求计数、错误计数和持续时间是否超限；
- 是否触发目标异常或副作用停止条件。

不能只相信 Agent Prompt 中的“已授权”。

## 5. 实施顺序

1. 建立 `security-evidence` 和 Artifact 读写能力；
2. 建立 `report-render` 与 `compliance-readonly`；
3. 建立 `alert/asset/endpoint/threat-intel` 只读连接；
4. 建立 `traffic-readonly` 离线解析；
5. 最后建立 `attack-validation-gated`，并单独完成安全评审。

## 6. 环境核验边界

`sasctl doctor` 对 OctoBus status interface 只调用官方 `GET /admin/v1/status`，严格要求 HTTP 200 和精确 JSON 字段 `status`、`services`（`status` 必须为 `ok`，`services` 必须是非负整数）。响应体有界读取，禁止把响应内容或主机地址写入用户错误。

当前 `linux/arm64` 已验证部署的 agent-compose、Guest 和 OctoBus RepoDigest 以 [`release-manifest.json`](../../release-manifest.json) 为准。Doctor 只检查 OctoBus status contract；该 status 及其 digest 都不能自证 OctoBus 版本、能力服务或 capability proxy，RepoDigest 也不会从 status 推断，而是 operator-verified deployment input。`services: 0` 不能作为 proxy 或业务能力 smoke 的通过证据。M1 doctor 另外要求固定 `sas101-doctor-probe` project 的 project-scoped Sandbox 列表只有指定 running/retained Docker Sandbox，再以固定 synthetic calculator `Add(20,22)` 验证 Sandbox→capability proxy→OctoBus 数据路径；v2609.1.0 的 JSON tag 会折叠重复 capset，完整 capset 隔离仍需 SAS-103 验收。

## 7. Provider connectivity probe

Provider 检查不通过生成内容验证，也不在 readiness 请求中反复调用模型。doctor 仅在配置了 `LLM_API_ENDPOINT`、`LLM_API_PROTOCOL`（`responses` 或 `chat_completions`）、`LLM_API_KEY`（否则回退 `OPENAI_API_KEY`）和 `LLM_MODEL` 时，使用最终注入的 HTTP client 对按 agent-compose 规则归一化的 provider base `/models` 发起一次带 Bearer 的 GET，并在有界响应中确认 `LLM_MODEL` 及三个 enabled Agent model 引用。root、`/v1`、完整 `/responses` 与 `/chat/completions` endpoint 形式均按固定版本规则处理；带 provider 前缀的模型引用同时按其模型部分匹配。进程环境必须与 daemon 的最终 Provider 配置一致；该检查不读取 daemon 密钥或调用模型生成。

缺少配置、协议不支持、HTTP/schema/model 检查失败均阻断 required provider 检查；取消、超时或无法验证保持 `unknown`。远端 Provider endpoint 必须使用 HTTPS；明文 HTTP 仅允许 loopback 地址用于本机开发。endpoint、凭据和响应内容不会写入错误消息。
