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
7. `sasd` 启动且 `/healthz` 可用后，在另一个终端加载同一 `.env` 并运行：

   ```sh
   set -a; . ./.env; set +a
   ./bin/sasctl doctor
   ```

   检查 JSON 报告与退出码；
8. 提交每个 Agent 的示例请求。

第 3 步是人工预检；Doctor 内部使用 `agent-compose --json --file <path> config` 并解析单个 normalized JSON object，而不是 `config --quiet` fallback。该命令可能解析 operator-owned compose 声明的外部 scheduler/script source，因此不应宣称零 I/O；Doctor 测试通过注入命令执行器保持离线。normalized Provider 检查只验证声明存在，不能替代真实连通性检查。当前 suite 要求所有 enabled agent 的 canonical `image` 与单一 `AGENT_COMPOSE_GUEST_IMAGE` 完全一致，`build` 不能替代；SAS-101 拒绝无 tag 和 `:latest`，但普通版本 tag 仍可变，SAS-102 才要求 digest 和 release manifest。


`mock` 下 integration checks 为 optional/skipped，服务完成启动后 `/readyz` 返回 200。`agentcompose-cli` 下 readiness 在后台缓存 runtime-only doctor 结果；HTTP 请求不会执行外部命令。daemon、OctoBus、协议、Provider、镜像或网络任一 required 检查为 `failed`/`unknown` 时，`/readyz` 返回结构化 503，`doctor` 输出 JSON 并以非零退出。

当前 Mac mini 的 Docker/OrbStack 可用，但 agent-compose 没有持久安装；临时从精确 commit 构建的固定 `v2609.1.0` 已验证 bare daemon `/api/version` 和 Doctor protocol。OctoBus、Provider、Sandbox→proxy、真实 Sandbox 与 capability 仍未认证，因此该环境只能验证 fail-closed 和固定协议，不能作为 SAS-101 全绿验收。

不要把 Provider Token、OctoBus Token 或客户密钥写入仓库、Prompt 或示例文件。
