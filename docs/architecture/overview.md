# 总体架构

## 1. 第一性原理

这个项目只保留三类事实：

### 变量

- **任务**：谁发起、要调用哪个智能体、输入是什么、输出格式是什么。
- **权限**：租户、授权范围、网络策略、工具集合、审批记录。
- **状态**：任务从创建到终态的可观测过程。
- **能力**：PCAP 解析、日志查询、情报查询、漏洞验证、法规检索、报告渲染。
- **证据**：原始输入、工具版本、参数、输出、时间、哈希和结论引用。
- **运行时**：模型、Skills、Sandbox、超时、资源和取消。

### 关系

- 一个调用请求只创建一个 `Run`，同一租户内 `request_id` 幂等。
- 一个 `Run` 只绑定一个 `AgentDefinition`，但可以产生多个 Evidence、Finding 和 Artifact。
- Agent 不能直接访问任意系统，只能通过 agent-compose 授权的 OctoBus capset 使用能力。
- Finding 必须引用 Evidence；攻击路径的节点和边必须引用 Finding 或 Evidence。
- 报告只消费结构化事实和经过确定性计算的指标，不反向修改事实。

### 约束

- 不接收调用方提供的任意 Shell。
- 不把客户输入或工具输出当成系统指令。
- 主动验证必须具备书面授权、明确范围和人工审批。
- 默认拒绝 unrestricted 网络访问。
- 所有租户数据必须逻辑隔离；生产环境还必须物理或存储级隔离。
- 高风险结论必须可复核、可追溯、可撤回。
- Mock 执行器只证明工程链路，不代表智能体真实有效。

## 2. 组件边界

```text
┌─────────────────────────────────────────────────────────────────────┐
│ 调用方：SOC / 安全运营平台 / Web UI / 自动化流程 / 命令行          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ HTTPS + API Key/OIDC + Tenant
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Security Agent Suite（Go 控制面）                                   │
│                                                                     │
│ API ─ Auth ─ Tenant ─ Idempotency ─ Policy ─ Queue ─ Run FSM       │
│                                  │                                  │
│                                  ├── Store / Audit / Metrics        │
│                                  └── Executor Port                  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ structured task envelope
                     ┌─────────┴──────────┐
                     │                    │
                     ▼                    ▼
              Mock Executor       agent-compose Adapter
              确定性联调           CLI（当前）/ Connect（目标）
                                          │
                                          ▼
                              isolated Agent Sandbox
                              SYSTEM + Skills + Schema
                                          │
                                          ▼
                                  capability proxy
                                          │
                                          ▼
                                      OctoBus
              ┌───────────────┬───────────┼─────────────┬──────────┐
              ▼               ▼           ▼             ▼          ▼
          流量分析服务      SOC连接器    漏洞验证服务   合规知识库  报告渲染
              │               │           │             │          │
              └───────────────┴───────────┴─────────────┴──────────┘
                                          │
                                          ▼
                       Evidence / Finding / Timeline / Artifact
```

### Go 控制面负责

- 对外稳定 API 和 CLI；
- 输入校验、幂等、租户边界和速率限制；
- 状态机、队列、并发、取消、超时和恢复；
- 授权范围、人工审批和高风险策略；
- 运行记录、Artifact 索引、审计日志和指标；
- 将业务请求转换为稳定的任务信封；
- 隔离上游 agent-compose 协议变化。

### agent-compose 负责

- Agent 的声明式定义；
- Provider、模型、系统提示和 Skills 注入；
- Docker、微虚机等隔离运行时；
- Workspace、Volume 和运行生命周期；
- OctoBus capset 绑定和能力代理；
- 运行日志与 Sandbox 管理。

### OctoBus 负责

- 把企业内部 API、命令、分析器和知识服务包装为受控能力；
- 以 capset 为最小授权组合；
- 统一参数、响应、超时、审计和版本；
- 避免 Agent 直接持有下游系统凭据。

## 3. 五个 Agent Pack

每个 Pack 必须是独立、最小、可版本化的交付单元：

```text
agents/<agent-id>/
├── SYSTEM.md                  # 角色、边界、禁止事项
├── output.schema.json         # 机器可校验的最终输出
├── examples/request.json      # 最小调用样例
└── skills/
    └── <skill>/SKILL.md       # 稳定 SOP，而非动态事实
```

五个 Pack 共享控制面和领域协议，但不共享系统提示、工具白名单和高风险权限。

## 4. Run 生命周期

```text
POST /runs
    │
    ▼
preflight policy
    │
    ├── 普通任务 ───────────────▶ queued
    │                                │
    └── 主动验证 ─▶ waiting_approval │
                       │ approve     │
                       └─────────────▶│
                                        ▼
                                    validating
                                        │
                                        ▼
                                      running
                                        │
                          ┌─────────────┼─────────────┐
                          ▼             ▼             ▼
                      succeeded       partial        failed

任意非终态 ── cancel ──▶ cancelled
服务重启时：running/validating 标记 failed；queued 重新入队。
```

状态机由 Go 实现，模型无权修改状态。

## 5. 数据流

1. 调用方上传或引用输入，Go 只接收受控 URI 和元数据。
2. Go 进行确定性前置校验，建立 Run 和审计事件。
3. Go 构造任务信封，标明数据是不可信内容、允许模式和输出 Schema。
4. agent-compose 在隔离 Sandbox 内启动对应 Agent。
5. Agent 通过 capset 调用确定性工具，工具产物写入 Artifact/Evidence 存储。
6. Agent 生成符合 Schema 的结构化结果。
7. Go 保存原始执行输出，校验并暴露运行状态和产物。
8. 报告 Agent 可以消费其他 Run 的结构化结果，但不得覆盖历史证据。

## 6. 当前实现与目标实现

| 能力 | 当前骨架 | 生产目标 |
| --- | --- | --- |
| API | Go `net/http`，API Key | OIDC/mTLS、细粒度 RBAC |
| 队列 | 进程内有界队列 | PostgreSQL/消息队列，可重试、租约和 HA |
| 状态 | JSON 文件 + JSONL 审计 | PostgreSQL 事务、不可变审计表 |
| Artifact | 本地文件 | S3/MinIO + KMS + 生命周期策略 |
| Executor | Mock、agent-compose CLI | agent-compose Connect/HTTP 客户端 |
| Schema | 请求与结果契约 | 全部 Agent 输出的运行时强校验 |
| OctoBus | capset 声明 | 真实服务包、审批钩子和证据写入服务 |
| 观测 | 基础 Prometheus 文本指标 | OTEL trace、日志聚合、SLO 和告警 |
| 部署 | 单实例 | 单写多读或完整 HA，灾备和升级策略 |

## 7. 部署拓扑

### 开发模式

```text
sasd(mock) + 本地文件存储
```

用途：API、状态机、审批、前端和调用方联调。

### 集成模式

```text
sasd(agentcompose-cli) → agent-compose daemon → Docker Sandbox → OctoBus
```

用途：验证五个 Agent Pack、Skills、capset 和真实工具。

### 生产模式

```text
Ingress/API Gateway
        │
        ▼
Go Control Plane ─ PostgreSQL ─ Object Storage
        │
        ▼
agent-compose control plane
        │
        ▼
Sandbox network zone ─ capproxy ─ OctoBus ─ Security systems
```

生产环境必须把控制面、Sandbox 区、能力网关和目标网络划分为不同信任区。

## 8. 不做什么

- 不在 Go 服务里实现另一个通用 Agent 编排器；
- 不允许模型生成后直接执行任意命令；
- 不把参考项目整仓复制进来；
- 不让所有 Agent 共用一个超级 capset；
- 不在报告 Agent 内重新判定攻击事实；
- 不在第一阶段同时建设五个智能体的全部真实工具。
