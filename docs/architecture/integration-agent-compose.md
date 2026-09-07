# agent-compose 集成

## 1. 当前边界

本仓库不复制 agent-compose 源码。`internal/executor/agentcompose` 通过固定 CLI 参数调用其 daemon：

```text
agent-compose --json --timeout 0
  [--host <daemon>]
  -f <agent-compose.yml>
  run <agent-id>
  --prompt <structured-envelope>
  [--rm]
```

命令参数由 Go 生成，调用方无法注入额外参数或 Shell。
`--timeout 0` 只禁用 CLI HTTP client timeout；正常 Run 的 deadline 由 Go context 根据 agent 的 `default_timeout` 确定，并以 `SAS_RUN_TIMEOUT` 作为兜底和上限，再按每个 Run 的 `max_duration` 缩短。`SAS_AGENT_COMPOSE_TIMEOUT` 仅在 executor 未收到有效的 `request.Timeout` 时作为后备值，不能覆盖上述 deadline；CLI 保持 timeout 为 0，以便 SIGINT cancellation defer 可以运行。


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
- 业务 `RunResult.RawOutput` 仅在 runtime 使用配置中 pinned 的 provider（允许 `codex`、`claude`、`gemini`、`opencode`、`pi`、`dsh`；当前环境为 `pi`）且 `result_json.finalTextSource=provider_message` 时取 `finalText`；`transcript_fallback` 只作为 provenance 标记和诊断 Artifact 保留，不进入业务结果。由于 pinned Pi fallback 是可能混入 stderr 和不可信文本的拼接 transcript，应用层故意 fail closed；这可能使 live gate 低于 99%，不构成验收；
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

Doctor 固定支持 agent-compose `v2609.1.0`：`agent-compose --json version` 必须返回完整且匹配的 build JSON；daemon 使用 `agent-compose --json --host <daemon> status`，严格校验 `/api/version` envelope。Doctor 的 compose 检查运行 `agent-compose --json --file <path> config`，只解析一个 normalized JSON object 并验证声明形状、Provider 声明和 Driver 适用性；不会以 `config --quiet` 的零退出作 complete fallback。每个 normalized agent 必须显式包含布尔值 `enabled`。所有 enabled Agent 的 canonical `image` 必须与 trim 后的 `AGENT_COMPOSE_GUEST_IMAGE` 完全一致，且在 `agentcompose-cli` 模式必须是与 release contract 相符的 `repository@sha256`；`build` 不能替代 `image`。Doctor 强制 agent-compose 版本和 Guest release digest；agent-compose 与 OctoBus RepoDigest 不从 version/status 响应推断，而是 operator-verified deployment inputs。

Provider 检查通过只表示 enabled agent 存在非空 provider declaration，不表示 Provider 已真实配置或可连通；连通性由独立 required probe 判定，无法权威验证时保持 `unknown`。normalized 输出按 64 KiB 上限 fail-closed；当前五 Agent 配置实测 8,964 bytes（约 8.8 KiB）。

人工预检仍可使用 `agent-compose -f <path> config --quiet`。但 `config` 可能解析 operator-owned compose 声明的外部 scheduler/script source，不能宣称零 I/O；Doctor 测试通过注入命令执行器保持离线。

`/readyz` 不直接运行命令，而是读取后台缓存的 runtime-only doctor 结果，并每 5 分钟刷新。Mock 完成服务启动即 ready；`agentcompose-cli` 的任一 required 检查不是 `passed` 时返回结构化 503。Doctor 对固定的 M1 probe project 使用 `--project-name sas101-doctor-probe sandbox ls` 做 project-scoped Sandbox 列表绑定，再用 inspect/exec 验证隔离 synthetic calculator 调用；不能用 TCP 连通或离线 fixture 替代。v2609.1.0 的 inspect JSON 会折叠重复 capset tag，完整 capset 隔离仍需 SAS-103 的独立验收。

## 7. SAS-102 运行时契约、升级与回滚

[`release-manifest.json`](../../release-manifest.json) 是已验证 `linux/arm64` 部署的版本与镜像元数据真源：它记录 agent-compose `v2609.1.0` 以及 agent-compose、Guest、OctoBus 的 RepoDigest。Doctor 强制 agent-compose 版本和 Guest release digest，并检查 OctoBus status contract；agent-compose/OctoBus RepoDigest 是 operator 验证后注入的部署输入，不从 status 推断。Mock 保持可在没有 agent-compose 和 OctoBus 时运行。

上游 agent-compose `v2609.1.0` 未发布 `$schema` 或 compose schema ID。SAS-102 固定原始 `agent-compose.yml` 的 SHA-256；`parser_version: "v2609.1.0"` 只标识运行该版本 parser 时应使用的固定版本，不表示 CI 已运行 parser。该 pinned parser 在实际运行时是 compose contract 的权威 validator；`make verify` 仍只做离线 manifest/hash/shape 检查，可能跳过 live agent-compose。

在受控 Docker 部署中，operator 可对 manifest 中每个完整 RepoDigest 做本地核验（不使用 `.Id`）：
```sh
for ref in \
  'docker.io/chaitin/agent-compose@sha256:79eceaf444f0a59555d0871ce77e11dd4348fe49071b6026cd34faafcc429bfd' \
  'docker.io/chaitin/agent-compose-guest@sha256:f1ebca0021d1de4ebd02d4da4117d7651e09b5a6db35be20092f03cc26a586b9' \
  'docker.io/chaitin/octobus@sha256:9961c9d80d7ba14001da7b96967980c85bec44ab846f87cc2a4e7ff55d9c280b'; do
  docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep -Fqx "$ref" || exit 1
done
```
核验失败时不要重标记或替换镜像；恢复上一份已审阅的 manifest、compose 和完整 RepoDigest 输入，按受控部署流程停止并重建受影响的 container/Sandbox，再重新运行上述核验和 Doctor。运行中 container 的 `.Id` 不是 RepoDigest 证明。升级同样先核验新输入、再重建受影响的 Sandbox；该契约不替代真实 Agent、capset 隔离或完整生产部署验收。

## 8. SAS-103 证据与取消契约

SAS-103 收集固定为五个 Agent 各 20 个正常运行（100 个，必须 100/100），外加每个 Agent 一个取消和一个超时 lifecycle 检查（10 个）。正常运行须通过仓库构建路径 `bin/sasctl` 的 `sasctl validate-output`；证据报告绑定 validator binary、原始输出、验证契约和投影文件的 SHA-256。投影只保留 allowlist 字段及 request/body、tenant、原始输出的 hash。
正常输出校验使用带租户/API 认证的请求下载精确 `agent-compose-final-output.json` 字节，核对 Artifact 元数据的 SHA-256 和 size，与 API `raw_output` 做严格 JSON 语义等价比较，再验证 Agent Schema；证据只保留哈希和元数据，不保留 Artifact 正文。
业务 `RunResult.RawOutput` 仅接受配置中 pinned 的 runtime provider（允许 `codex`、`claude`、`gemini`、`opencode`、`pi`、`dsh`；当前环境为 `pi`）且 `result_json.finalTextSource=provider_message`；`transcript_fallback` 只作为 provenance 标记和诊断 Artifact 保留，不进入业务结果。Pinned Pi fallback 是可能混入 stderr 和不可信文本的拼接 transcript，故应用层 fail closed；这可能使 live gate 低于 99%，不构成验收。


外部控制不是 harness 自造的案例：必须由独立执行的真实非生产控制提供，并经既有治理流程认可的外部签名/独立可审阅 attestation 约束，且恰好为四类乘以五个 Agent，即 20 个。当前仓库没有可信签名机制；`--controls` 明确返回 `controls_unverified`，导入控制不能满足 `verify_report` 或任何验收计数。Hash、reviewer、时间戳和投影交换只能证明字节完整性，不能证明来源、真实性或 runtime truth；本 harness 不会自创认证。

超时 lifecycle 必须先观察至少一个非终态轮询，再核对配置的精确 `max_duration`；证据不能证明墙钟到期。`downstream_acknowledged` 仅在取消或超时的最终 Agent Compose runtime envelope 已成功解码时为真；其中 `daemon_run_id` 与 `sandbox_id` 都必须是 64 个小写十六进制字符，runtime `status` 必须是 `canceled` 或 `cancelled`。缺失、无法解码或字段不符时必须 fail closed，SAS-103 验收被阻断。

中止收集会在任何 create POST 可能已发出后标记 `cleanup_required`，包括中断、响应不明确或 run ID 校验前的无效响应；operator 必须先停止/排空 acceptance control plane 并按 agent-compose 受控流程清理 retained synthetic Sandbox。

`POST /v1/runs/{runID}/cancel` 对运行中的 Run 在停止期间返回 `202`，并在取消立即得到 terminal Run 时返回 `200`；Go context 是权威，运行中 API 取消最终为 `cancelled`，其 `error_code` 为 `executor_cancelled`。只有 Go context 尚未到期而 Agent Compose runtime envelope 自身报告 `canceled`/`cancelled` 时才使用 `agent_compose_cancelled`；成功解码的 runtime provenance 仍保留。取消和超时都必须轮询 `GET /v1/runs/{runID}` 直到 terminal 状态；`202` 或发出 SIGINT 本身不是完成证明。

中止或失败的收集应先停止 SAS acceptance control plane，再由获授权的 operator 按 agent-compose 受控流程清理 retained synthetic Sandbox，并恢复已审阅的先前二进制与配置。证据保留或删除须由明确的 retention 决定；审阅前绝不自动删除证据。

## 9. 故障处理

| 故障 | Go Run 结果 | 操作 |
| --- | --- | --- |
| agent-compose Connect 不可用（exit code 3） | failed / agent_compose_unavailable | 修复依赖后由调用方新建 Run；没有权威无副作用或幂等信号时不得自动重试 |
| 执行器启动或协议错误 | failed / executor_error | 保留结构化错误；确认版本、配置和 daemon 状态后由调用方新建 Run |
| 队列满 | failed / queue_unavailable | 扩容或限流；不静默丢任务 |
| Provider 超时 | failed / executor_timeout | 检查模型、上下文、工具阻塞 |
| 输出非 JSON 或契约无效 | failed / agent_output_malformed 或 agent_output_contract_invalid | 保留受控原始输出/Artifact，修复后重新创建 Run |
| API/Go context 取消 | cancelled / executor_cancelled | 轮询到 terminal；审计取消人和原因 |
| Agent Compose runtime 取消 | cancelled / agent_compose_cancelled | 仅在 runtime envelope 成功解码且 Go context 未到期时使用；保留 provenance |
| OctoBus 暂不可用 | 工具错误 | Agent 必须返回证据缺口，不能猜测 |

本表只定义错误分类和操作，不启用盲重试；任何重试实现必须先有权威的“未产生外部副作用”或幂等证明。
