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
5. 在 `.env` 中把 `SAS_EXECUTOR` 改为 `agentcompose-cli`，并填写目标环境提供的 `SAS_AGENT_COMPOSE_HOST` 与 `SAS_OCTOBUS_HOST`；
6. 在一个终端先运行 `make build`，再运行 `make run`；
7. API 就绪后，在另一个终端加载同一 `.env` 后运行：

   ```sh
   set -a; . ./.env; set +a
   ./bin/sasctl doctor
   ```

   检查 JSON 报告与退出码；
8. 提交每个 Agent 的示例请求。

`mock` 下 integration checks 为 optional/skipped。`agentcompose-cli` 下 daemon、OctoBus、协议、Provider、镜像或网络任一项未验证都会为 required `failed`/`unknown`；`doctor` 仍输出 JSON 并以非零退出。

协议确定后需在代码中接入权威探针；当前未接入的 required 检查按 `unknown` 失败，不能宣称可通过。

不要把 Provider Token、OctoBus Token 或客户密钥写入仓库、Prompt 或示例文件。
