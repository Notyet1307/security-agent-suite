# 本地开发运行手册

## Mock 模式

```bash
cp .env.example .env
make verify
make run
```

验证：

```bash
make smoke
./bin/sasctl --api-key change-me-in-production --tenant default agents
```

数据写入 `./var/state` 和 `./var/artifacts`。删除这些目录会清除本地运行历史。

## agent-compose 模式

1. 启动并配置 agent-compose daemon；
2. 配置 OctoBus 与 capability proxy；
3. 运行 `agent-compose -f agent-compose.yml config --quiet`；
4. 运行 `agent-compose -f agent-compose.yml up`；
5. 在 `.env` 中把 `SAS_EXECUTOR` 改为 `agentcompose-cli`；
6. 运行 API 并提交每个 Agent 的示例请求。

不要把 Provider Token、OctoBus Token 或客户密钥写入仓库、Prompt 或示例文件。
