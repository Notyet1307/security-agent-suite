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

当前 CLI 适配器把：

- CLI JSON 摘要；
- stdout；
- stderr；
- 解析后的最终文本

保存为 Artifact，并尝试抽取 Agent 的 JSON 输出。M1 必须补充严格的输出 Schema 验证；不通过 Schema 的运行只能是 `partial` 或 `failed`，不能标记为成功。

## 5. 从 CLI 到 Connect/HTTP

CLI 适配器适合起步，但生产目标应是官方稳定 API：

1. 对 daemon 使用长连接或流式接口；
2. 保存 daemon run ID 和 sandbox ID；
3. 将取消请求传播到真实运行；
4. 区分创建失败、Sandbox 失败、Provider 失败、工具失败和输出校验失败；
5. 消除 stdout 格式变化带来的解析风险；
6. 支持事件流直接进入审计和前端。

在接口稳定前，保留 `Executor` Port，避免上层业务依赖 agent-compose 内部模型。

## 6. 版本与升级

- agent-compose 镜像必须固定 tag 或 digest；
- 升级前运行五个 Agent 的固定评测集；
- 对 compose schema、CLI JSON 和 capset 注入做兼容测试；
- Sandbox 已启动后不会自动获得新配置，升级时按运行时语义重建；
- Git/HTTP Skill 必须固定 SHA 和校验值；当前仓库使用本地 Skill。

## 7. 故障处理

| 故障 | Go Run 结果 | 操作 |
| --- | --- | --- |
| daemon 不可达 | failed / executor_error | 恢复 daemon 后由调用方新建 Run；M1 增加受控重试 |
| 队列满 | failed / queue_unavailable | 扩容或限流；不静默丢任务 |
| Provider 超时 | failed / executor_timeout | 检查模型、上下文、工具阻塞 |
| 输出非 JSON | partial/failed（目标） | 保存原始输出，进入回归修复 |
| Sandbox 被取消 | cancelled/failed | 审计取消人和原因 |
| OctoBus 暂不可用 | 工具错误 | Agent 必须返回证据缺口，不能猜测 |
