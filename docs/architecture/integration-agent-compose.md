# agent-compose 集成

## 1. 当前边界

本仓库不复制 agent-compose 源码。`internal/executor/agentcompose` 通过固定 CLI 参数调用其 daemon：

```text
agent-compose --json --timeout <duration>
  [--host <daemon>]
  -f <agent-compose.yml>
  run <agent-id>
  --prompt <structured-envelope>
  [--rm]
```

命令参数由 Go 生成，调用方无法注入额外参数或 Shell。

## 2. 准备

```bash
cp .env.example .env
agent-compose -f ./agent-compose.yml config --quiet
agent-compose -f ./agent-compose.yml up
```

切换执行器：

```bash
SAS_EXECUTOR=agentcompose-cli \
SAS_AGENT_COMPOSE_HOST=http://127.0.0.1:7410 \
./bin/sasd
```

若 daemon 使用认证，应在宿主环境按 agent-compose 官方方式配置客户端凭据，不要写入 Agent Prompt。

## 3. Agent 配置

`agent-compose.yml` 声明五个 Agent，分别配置：

- Provider 和模型；
- Sandbox 镜像及 Driver；
- SYSTEM；
- 三个基线 Skill；
- 最小 capset；
- evidence/artifact Volume。

系统提示在 YAML 中保留了简版，完整说明在每个 Pack 的 `SYSTEM.md`。生产前应决定一个唯一真源，推荐由构建脚本将 `SYSTEM.md` 生成进 compose，避免重复漂移。

## 4. 结果契约

CLI 适配器的结果契约为：

- 完整 CLI JSON envelope 保存为受控 Artifact，仅供审计和排障；
- 顶层 `output` 仅视为 transcript，普通副本会脱敏后保存；
- 只有 `result_json.finalText` 进入业务结果：原文成为 `RunResult.RawOutput`，其普通 `final-output` 副本同样脱敏；
- 应用层 `validation.Gate` 执行受支持的五类契约与 evidence 校验，并拒绝格式错误或不可信的输出。

## 5. 从 CLI 到 Connect/HTTP

CLI 适配器适合起步，但生产目标应是官方稳定 API：

1. 对 daemon 使用长连接或流式接口；
2. 保存 daemon run ID 和 sandbox ID；
3. 将取消请求传播到真实运行；
4. 区分创建失败、Sandbox 失败、Provider 失败、工具失败和输出校验失败；
5. 消除 stdout 格式变化带来的解析风险；
6. 支持事件流直接进入审计和前端。

在接口稳定前，保留 `Executor` Port，避免上层业务依赖 agent-compose 内部模型。

## 6. Doctor 与 readiness

Doctor 固定支持 agent-compose `v2609.1.0`：`agent-compose --json version` 必须返回完整且匹配的 build JSON；daemon 使用 `agent-compose --json --host <daemon> status`，严格校验 `/api/version` envelope。Doctor 的 compose 检查运行 `agent-compose --json --file <path> config`，只解析一个 normalized JSON object 并验证声明形状、Provider 声明和 Driver 适用性；不会以 `config --quiet` 的零退出作 complete fallback。每个 normalized agent 必须显式包含布尔值 `enabled`。当前 suite 的单镜像 readiness policy 要求每个 enabled agent 的 canonical `image` 非空，并与 trim 后的 `AGENT_COMPOSE_GUEST_IMAGE` 完全相等；`build` 不能替代 `image`。因此后续一次 Docker inspect 检查的正是运行声明使用的镜像。SAS-101 只拒绝无 tag、`:latest` 和畸形 digest；普通版本 tag 仍是可变引用，不能当作 SAS-102 的 immutable digest 验收。

Provider 检查通过只表示 enabled agent 存在非空 provider declaration，不表示 Provider 已真实配置或可连通；连通性由独立 required probe 判定，无法权威验证时保持 `unknown`。normalized 输出按 64 KiB 上限 fail-closed；当前五 Agent 配置实测 8,964 bytes（约 8.8 KiB）。

人工预检仍可使用 `agent-compose -f <path> config --quiet`。但 `config` 可能解析 operator-owned compose 声明的外部 scheduler/script source，不能宣称零 I/O；Doctor 测试通过注入命令执行器保持离线。

`/readyz` 不直接运行命令，而是读取后台缓存的 runtime-only doctor 结果。Mock 完成服务启动即 ready；`agentcompose-cli` 的任一 required 检查不是 `passed` 时返回结构化 503。固定版没有 capability CLI；在 Connect 编码及目标环境协议未确认前，OctoBus、Provider 和 Sandbox→proxy 保持 `unknown`，不得用 TCP 连通或离线 fixture 替代。

## 7. 版本与升级

- SAS-102 必须将 agent-compose Guest 镜像固定为 `sha256` digest，并写入 release manifest；普通版本 tag 不满足不可变性验收；
- 升级前运行五个 Agent 的固定评测集；
- 对 compose schema、CLI JSON 和 capset 注入做兼容测试；
- Sandbox 已启动后不会自动获得新配置，升级时按运行时语义重建；
- Git/HTTP Skill 必须固定 SHA 和校验值；当前仓库使用本地 Skill。

## 8. 故障处理

| 故障 | Go Run 结果 | 操作 |
| --- | --- | --- |
| daemon 不可达 | failed / executor_error | 恢复 daemon 后由调用方新建 Run；M1 增加受控重试 |
| 队列满 | failed / queue_unavailable | 扩容或限流；不静默丢任务 |
| Provider 超时 | failed / executor_timeout | 检查模型、上下文、工具阻塞 |
| 输出非 JSON | partial/failed（目标） | 保存原始输出，进入回归修复 |
| Sandbox 被取消 | cancelled/failed | 审计取消人和原因 |
| OctoBus 暂不可用 | 工具错误 | Agent 必须返回证据缺口，不能猜测 |
