# 领域数据模型

## 1. 核心对象

### AgentDefinition

稳定的能力目录，包含 Agent ID、允许模式、输入类型、输出类型、默认超时、风险等级、审批条件和 capset。它是控制面策略依据，不由 Agent 自己声明。

### Run

一次不可复用的运行实例。核心字段：

- `id`：服务生成的唯一标识；
- `request_id`：调用方提供，同一租户内幂等；
- `tenant_id`：隔离边界；
- `agent_id`、`mode`；
- `input_refs`、`scope`、`policy`、`output`；
- `status`、`version`、时间戳；
- `approval`、`events`、`result`。

### Evidence

可复核观察事实。最小信息：来源、采集时间、原始对象哈希、工具名称和版本、参数模板、输出位置、摘要和完整性信息。

### Finding

对一个或多个 Evidence 的综合判断。必须区分：

- observed：工具直接观察；
- inferred：根据多个事实推断；
- reported：由外部系统或人员提供但未独立验证。

### TimelineEvent

统一时间基准后的事件，保存源时区、时钟偏差、主体、客体、动作、证据和置信度。

### AttackPath

有向图：节点为入口、资产、服务、漏洞、身份、权限、网络区和数据；边为可达、认证、信任、依赖、可利用或权限变化。每条边必须标记 `verified`、`candidate` 或 `blocked`。

### Artifact

文件产物索引，不直接把大文件塞进 Run JSON。包含名称、媒体类型、大小、SHA-256、存储 URI 和敏感级别。

## 2. 关键不变量

1. `request_id` 在同一租户内唯一；不同 Agent 不能复用同一键。
2. Run 状态只能按状态机允许的边迁移。
3. 终态不可回退。
4. 审批记录只能追加，不能由 Agent 生成。
5. High/Critical Finding 至少引用一个 Evidence。
6. Artifact 路径必须限制在该 Run 的存储目录下。
7. 租户 A 查询租户 B 的 Run 必须返回 not found，避免存在性泄漏。
8. 所有时间在存储时使用 UTC。
9. 原始证据不可被后续报告或重跑覆盖。
10. 模型输出不能直接成为 Evidence；只能成为 Finding、解释或建议，除非明确标记为模型生成材料。

## 3. 标识关系

```text
Tenant
  └── Run
      ├── Approval (0..1 baseline; target 0..n append-only)
      ├── Event (1..n)
      ├── Evidence (0..n)
      ├── Finding (0..n) ── references ──▶ Evidence
      ├── TimelineEvent (0..n) ──────────▶ Evidence
      ├── AttackPath (0..n) ─────────────▶ Finding / Evidence
      └── Artifact (0..n)
```

## 4. 版本策略

- HTTP API 使用 `/v1` 路径；
- JSON Schema 使用独立 `$id`；
- 新增可选字段属于兼容变更；
- 删除字段、改变语义、枚举收缩必须进入 v2；
- Agent Pack、Skill、工具服务和模板均应使用独立语义版本；
- Run 需记录执行时的模型、Agent Pack、Skill、工具和模板版本，当前骨架尚未全部持久化，列为 M1/M2 任务。
