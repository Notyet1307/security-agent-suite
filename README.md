# Security Agent Suite

一个以 **Go 业务控制面 + agent-compose 隔离运行时 + OctoBus 能力网关** 为核心的公开参考项目，用于快速交付五个可独立调用的网络安全智能体。

> 当前仓库定位是“可运行的工程骨架”，不是已经具备真实客户数据接入和生产验证的成品。默认 `mock` 执行器不会作出真实安全结论；接入 agent-compose、OctoBus 和客户数据源后，才进入真实能力建设阶段。

业务范围来自 [五个智能体产品需求基线](docs/product/requirements.md)，需求到代码和阶段的对应关系见 [追踪矩阵](docs/product/traceability.md)。

## 五个智能体

| Agent ID | 中文名称 | 核心职责 | 默认风险级别 |
| --- | --- | --- | --- |
| `traffic-analysis` | 网络流量包分析智能体 | PCAP、DNS、代理、终端、进程、登录等多源证据关联，重建时间线和攻击链 | 中 |
| `event-triage` | 事件研判智能体 | 告警聚合、假设验证、真伪判断、定级及处置建议 | 中 |
| `attack-path-validation` | 攻击路径验证智能体 | 在授权范围内复核暴露面、漏洞与候选攻击路径 | 高，强制审批 |
| `compliance-query` | 网络安全合规查询智能体 | 法规标准检索、适用性解释、控制差距和证据要求 | 低 |
| `security-report` | 网络安全报告智能体 | 将结构化数据生成日报、周报、月报和专项报告 | 低 |

## 为什么使用 Go

Go 用于承载长期稳定、可审计的控制逻辑，而不是承载模型推理本身：

- HTTP API、CLI、任务状态机、队列、取消和超时；
- 输入契约、幂等、租户边界、授权和审批；
- agent-compose 调用适配；
- 证据、发现、时间线、攻击路径和报告产物协议；
- 文件持久化、审计事件、指标和健康检查。

agent-compose 负责 Agent、Sandbox、Skills、Workspace 和调度生命周期；OctoBus 负责将受控安全能力按 capset 暴露给 Sandbox。三者职责不重叠。

## 架构

```text
调用方 / SOC / Web / 自动化平台
              │
              ▼
┌──────────────────────────────────────────────┐
│ Go Control Plane                            │
│ API · Auth · Idempotency · Policy · Queue   │
│ Run FSM · Approval · Audit · Metrics        │
└──────────────────────┬───────────────────────┘
                       │ Executor Port
              ┌────────┴─────────┐
              │                  │
              ▼                  ▼
       Mock Executor      agent-compose CLI
       本地确定性联调       隔离 Agent Sandbox
                                 │
                                 ▼
                    OctoBus Capability Proxy
                                 │
          ┌──────────┬───────────┼──────────┬──────────┐
          ▼          ▼           ▼          ▼          ▼
        流量工具    SOC/日志    漏洞验证    合规知识库   报告渲染
                                 │
                                 ▼
                 Evidence · Finding · Artifact
```

核心约束：

1. Go 控制面不接受任意 Shell 命令；
2. Agent 只能使用其 `capset_ids` 中明确授权的能力；
3. 主动验证必须同时具备授权范围和人工审批；
4. 关键结论必须引用证据标识；
5. 统计数字由确定性代码计算，不能由模型编造；
6. agent-compose 或 OctoBus 不可用时，核心 API 和测试仍可通过 Mock 运行。

更完整的边界说明见 [产品愿景](docs/product/vision.md)、[总体架构](docs/architecture/overview.md) 和 [安全模型](docs/architecture/security-model.md)。

## 当前已搭建内容

- 五个独立 Agent 定义及 `agent-compose.yml`；
- 五套详细系统提示、15 个核心 Skill、工作流和输出 Schema；
- Go API 服务 `sasd` 与调用 CLI `sasctl`；
- Run 状态机、队列、幂等、审批、取消、超时；
- Mock 与 agent-compose CLI 两种执行器；
- 文件持久化、Artifact、append-only Evidence Store、审计事件和基础指标；
- OpenAPI、JSON Schema、示例请求；
- Docker、Kubernetes 起步清单、PostgreSQL 目标模型；
- 单元测试、HTTP 集成测试、CI、CodeQL、Dependabot；
- 分阶段路线图、验收门槛和可导入 GitHub 的任务清单。
- 当前完成度、验证证据和已知缺口见 [项目状态](PROJECT_STATUS.md)。

## 快速启动

### 1. 本地 Mock 模式

要求 Go 1.23+；CI 和生产镜像使用 Go 1.27.x。

```bash
cp .env.example .env
make verify
make run
```

另一个终端：

```bash
curl -s http://127.0.0.1:8080/healthz
curl -s \
  -H 'X-API-Key: change-me-in-production' \
  -H 'X-Tenant-ID: default' \
  http://127.0.0.1:8080/v1/agents

curl -s -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: change-me-in-production' \
  -H 'X-Tenant-ID: default' \
  --data @agents/event-triage/examples/request.json \
  http://127.0.0.1:8080/v1/agents/event-triage/runs
```

或者使用 CLI：

```bash
make build
./bin/sasctl --base-url http://127.0.0.1:8080 \
  --api-key change-me-in-production --tenant default agents

./bin/sasctl --base-url http://127.0.0.1:8080 \
  --api-key change-me-in-production --tenant default run \
  --agent event-triage \
  --file agents/event-triage/examples/request.json
```

### 2. Docker

```bash
cp .env.example .env
docker compose up --build
```

容器默认仍使用 Mock。agent-compose CLI 适配器更适合先在宿主机部署；后续可改为 Connect/HTTP 客户端或单独的受控执行侧车。

### 3. 接入 agent-compose

先部署 agent-compose daemon，并保证 CLI 可访问：

```bash
agent-compose -f ./agent-compose.yml config --quiet
```

这是人工预检。Doctor 内部改用 `agent-compose --json --file <path> config`，解析单个 normalized JSON object；它不把该命令称为零 I/O，因为 operator-owned compose 声明的外部 scheduler/script source 仍可能被解析。normalized Provider 检查只证明 enabled agent 存在非空声明，不表示真实配置或连通性；Provider 连通性、OctoBus 和 Sandbox→proxy 无法权威验证时仍保持 required `unknown`。当前 suite 采用单镜像 policy：每个 enabled agent 的 canonical `image` 必须与 `AGENT_COMPOSE_GUEST_IMAGE` 完全一致；`build` 不能替代 `image`。SAS-102 的 [`release-manifest.json`](release-manifest.json) 是已验证 `linux/arm64` 部署的版本与镜像元数据真源：Doctor 强制 agent-compose `v2609.1.0` 与 Guest release digest，Doctor 只检查 OctoBus status contract；agent-compose/OctoBus RepoDigest 是 operator 验证后注入的部署输入，不从 status 推断。Mock 仍不需要这些外部依赖；升级与回滚操作见 agent-compose 集成文档。
Release archives preserve cross-platform client binaries, but only the `linux/arm64` archive includes `release-manifest.json` and the verified agent-compose runtime inputs. Other platform archives contain `RUNTIME_SCOPE.txt` marking them client/mock-only; they do not claim agent-compose runtime support.

```bash
agent-compose -f ./agent-compose.yml up
```

再启动本项目：

```bash
export SAS_EXECUTOR=agentcompose-cli
export SAS_AGENT_COMPOSE_BIN=agent-compose
export SAS_AGENT_COMPOSE_FILE=$PWD/agent-compose.yml
export SAS_AGENT_COMPOSE_HOST=http://127.0.0.1:7410
export SAS_OCTOBUS_HOST='<target-environment URL>'
make run
```

`SAS_OCTOBUS_HOST` 没有默认值，必须替换为目标环境地址；未配置时 agent-compose 模式的 `/readyz` fail-closed 返回 503。

Go 网关会执行等价命令：

```bash
agent-compose --json --timeout 0 \
  --host http://127.0.0.1:7410 \
  -f ./agent-compose.yml \
  run <agent-id> \
  --prompt '<structured-task-envelope>' \
  --rm
```
`--timeout 0` 只禁用 CLI HTTP client timeout；正常 Run 的 deadline 由 Go context 根据 agent 的 `default_timeout` 确定，并以 `SAS_RUN_TIMEOUT` 作为兜底和上限，再按每个 Run 的 `max_duration` 缩短。`SAS_AGENT_COMPOSE_TIMEOUT` 仅在 executor 未收到有效的 `request.Timeout` 时作为后备值，不能覆盖上述 deadline；CLI 保持 timeout 为 0，以便 SIGINT cancellation defer 可以运行。


外部进程输出会原样保存为运行产物；业务侧只消费标准化的 Run、Evidence、Finding 和 Artifact 契约。

## 主要 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | 存活检查 |
| `GET` | `/readyz` | 就绪检查 |
| `GET` | `/metrics` | Prometheus 文本指标 |
| `GET` | `/v1/agents` | 查询可调用智能体 |
| `GET` | `/v1/agents/{agent_id}` | 查询单个智能体定义 |
| `POST` | `/v1/agents/{agent_id}/runs` | 创建运行 |
| `GET` | `/v1/runs/{run_id}` | 查询运行和结果 |
| `GET` | `/v1/runs/{run_id}/events` | 查询审计事件 |
| `POST` | `/v1/runs/{run_id}/evidence` | 追加不可变 Evidence；服务端可生成 ID 和采集时间 |
| `GET` | `/v1/runs/{run_id}/evidence` | 查询运行 Evidence |
| `GET` | `/v1/runs/{run_id}/evidence/{evidence_id}` | 查询单条 Evidence |
| `POST` | `/v1/runs/{run_id}/artifacts?name=...` | 流式上传并登记运行产物；可用 `X-Artifact-SHA256` 校验正文 |
| `GET` | `/v1/runs/{run_id}/artifacts` | 查询运行产物元数据 |
| `GET` | `/v1/runs/{run_id}/artifacts/{artifact_id}` | 下载运行产物 |
| `POST` | `/v1/runs/{run_id}/approve` | 审批高风险运行 |
| `POST` | `/v1/runs/{run_id}/cancel` | 取消排队或运行中任务 |

Evidence 追加要求 `type`、`source_uri`、SHA-256、`tool`、`tool_version` 和 `parameters`；服务端可生成 Evidence ID 和 `collected_at`。`artifact_ids`（如提供）记录原始 Artifact 绑定，且必须引用同一 Run 下已登记的 Artifact。Evidence ID 一旦写入不能覆盖，跨租户访问统一隐藏为 `404`。

运行中取消的语义：API 请求取消先返回 `202`（仍在停止）；Go context 是权威，最终 Run 为 `cancelled` 且 `error_code=executor_cancelled`。只有 Go context 尚未到期而 runtime envelope 自身报告 `canceled`/`cancelled` 时才使用 `agent_compose_cancelled`；成功解码的 runtime provenance 仍保留。

完整定义见 [OpenAPI](openapi/openapi.yaml)。

## 攻击路径验证的强制门

主动验证请求必须满足：

- `scope.authorization_ref` 非空；
- 至少指定资产、网络或域名范围；
- `policy.active_validation=true`；
- 创建后进入 `waiting_approval`；
- 由审批接口记录审批人和审批说明后才进入队列；
- 只允许受限网络访问，不接受 unrestricted 模式；
- 到达请求数、时间、影响或证据充分度停止条件后立即停止。

示例见 `agents/attack-path-validation/examples/request.json`。

## 目录

```text
cmd/                 sasd 服务端与 sasctl 客户端
internal/            Go 领域、应用、策略、执行器和基础设施实现
agents/              五个 Agent 的 SYSTEM、Skills、Schema 和示例
contracts/           跨 Agent 通用 JSON Schema
configs/             Agent 目录和策略配置
openapi/              HTTP 接口契约
docs/                 产品、架构、ADR、路线图、研究和运行手册
planning/             阶段任务清单
scripts/              校验、冒烟、打包和 GitHub 发布脚本
agent-compose.yml      五个 Agent 的声明式打包入口
```

## 实施路线

建议按以下顺序推进：

```text
M0 工程基线与公开仓库
  → M1 环境核验与真实 agent-compose 联调
  → M2 统一证据与 OctoBus 能力底座
  → M3 报告智能体
  → M4 合规智能体
  → M5 事件研判智能体
  → M6 流量分析智能体
  → M7 攻击路径验证智能体
  → M8 跨 Agent 闭环与评测
  → M9 生产加固与客户交付
```

每个阶段的变量、依赖、任务、验收条件和人天建议见 [实施路线图](docs/roadmap/implementation-plan.md)。

## 开源与许可证

本仓库使用 Apache-2.0。agent-compose 当前使用 AGPL-3.0；本仓库通过外部 CLI/服务边界集成，不复制或嵌入其源码。其他参考项目也各自拥有许可证，具体见 [参考项目研究](docs/research/reference-projects.md)。商业组合、镜像再分发或源码复制前仍需单独完成开源治理审查。

## 免责声明

本项目仅用于获得明确授权的防御、安全运营、合规与验证场景。不得用于扫描、利用、干扰或访问未授权系统。Mock 输出仅用于工程联调，不代表真实安全判断。

### 显式准备与提交输入

单项 event-triage 可用 `execution_mode: manual` 创建不执行的 `preparing` Run，再上传原始合成 JSON 并显式提交。使用方法、恢复和回滚边界见 [manual input runbook](docs/runbooks/manual-input.md)；这不证明真实模型已消费输入。
