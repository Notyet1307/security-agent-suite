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
3. `.env` 只保存非秘密配置，例如 executor、compose 路径、目标 host 和专用 probe Sandbox ID。将 Provider credential 连同最终 `LLM_API_ENDPOINT`、`LLM_API_PROTOCOL`、`LLM_API_KEY`、`LLM_MODEL` 和三个 `SAS_*_MODEL` 放入 operator-owned、仓库外的 `0600` env 文件；daemon、`sasd` 与 `sasctl doctor` 必须加载同一份最终值；
4. 每个进程都按“仓库内非秘密配置在前、operator 文件在后”的顺序加载，再执行 compose 预检和部署：

   ```sh
   set -a
   . ./.env
   . /path/to/operator/provider.env
   set +a
   agent-compose -f agent-compose.yml config --quiet
   agent-compose -f agent-compose.yml up
   ```

5. 先运行 `make build`。构建完成后，在运行服务的终端按相同顺序加载配置，并直接启动二进制；agent-compose daemon 的启动方式也必须加载同一个 operator 文件：

   ```sh
   make build
   set -a
   . ./.env
   . /path/to/operator/provider.env
   set +a
   ./bin/sasd
   ```

6. `sasd` 启动且 `/healthz` 可用后，在另一个终端加载相同配置并运行：

   ```sh
   set -a
   . ./.env
   . /path/to/operator/provider.env
   set +a
   ./bin/sasctl doctor
   ```

   检查 JSON 报告与退出码；
7. 提交每个 Agent 的示例请求。

第 4 步是人工预检；Doctor 内部使用 `agent-compose --json --file <path> config` 并解析单个 normalized JSON object，而不是 `config --quiet` fallback。该命令可能解析 operator-owned compose 声明的外部 scheduler/script source，因此不应宣称零 I/O；Doctor 测试通过注入命令执行器保持离线。normalized Provider 检查只验证声明存在，不能替代真实连通性检查。当前 suite 要求所有 enabled agent 的 canonical `image` 非空，并与单一 `AGENT_COMPOSE_GUEST_IMAGE` 完全一致；由于 v2609.1.0 的 normalized 输出会保留该字段的 `${AGENT_COMPOSE_GUEST_IMAGE}` 引用，Doctor 仅在源 compose 插值已解析且引用名称准确时接受它，`build` 不能替代 `image`。SAS-101 拒绝无 tag 和 `:latest`，但普通版本 tag 仍可变，SAS-102 才要求 digest 和 release manifest。


`mock` 下 integration checks 为 optional/skipped，服务完成启动后 `/readyz` 返回 200。`agentcompose-cli` 下 readiness 在后台缓存 runtime-only doctor 结果，并每 5 分钟刷新；HTTP 请求不会执行外部命令。daemon、OctoBus、协议、Provider、镜像或网络任一 required 检查为 `failed`/`unknown` 时，`/readyz` 返回结构化 503，`doctor` 输出 JSON 并以非零退出。
Sandbox→proxy 检查要求 operator 在固定的 `sas101-doctor-probe` project 中预先创建一个长期运行、隔离的 Docker Sandbox，并将其绑定到 agent `probe`；它必须使用固定 guest image，运行时状态必须是 `retained`，并只授予用户批准的 pinned M1-only synthetic calculator fixture（基于 OctoBus v0.2.0 example/SDK，service `sas101-calculator`、instance `calculator-test`、label `sas101`）。Doctor 以固定 `--project-name sas101-doctor-probe sandbox ls` 做 project-scoped 列表绑定，要求列表只有该 Sandbox，再核对 Sandbox ID、running 状态、Docker driver、精确 guest image 与 retained 状态，随后 inspect 同一完整 ID 并执行固定的 `CalculatorService/Add(20, 22)` 合成调用，严格验证固定 fixture 身份及返回 `42`。v2609.1.0 的 inspect JSON 将重复 capset tag 压成单值，因此该检查要求 operator 先保证只有 `dev`；完整 capset 隔离仍属于 SAS-103 验收，不能由此 doctor 结果宣称。此 Sandbox 和 capability 只用于 M1 目标环境验收与 readiness，不是生产 capability，也不应承载 Provider 路由、客户数据或生产凭据。结果只保存在当前 readiness 状态中，不创建或持久化可复用 receipt。

Provider connectivity 使用 daemon、`sasd` 与 `sasctl doctor` 共同加载的最终 `LLM_API_*` 和 suite model 配置。Doctor 只做一次有界 `/models` GET，不生成模型内容；endpoint 会按 agent-compose 的 root、`/v1` 或完整 `/responses`/`/chat/completions` 形式归一化，并核对 `LLM_MODEL` 及三个启用 Agent model 引用。
不要把 Provider Token、OctoBus Token 或客户密钥写入仓库、Prompt 或示例文件。
