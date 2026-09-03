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
