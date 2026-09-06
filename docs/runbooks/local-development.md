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

第 4 步是人工预检；Doctor 内部使用 `agent-compose --json --file <path> config` 并解析单个 normalized JSON object，而不是 `config --quiet` fallback。该命令可能解析 operator-owned compose 声明的外部 scheduler/script source，因此不应宣称零 I/O；Doctor 测试通过注入命令执行器保持离线。SAS-102 的 [`release-manifest.json`](../../release-manifest.json) 是已验证 `linux/arm64` 部署的版本与镜像元数据真源：Doctor 强制 agent-compose 版本和 Guest release digest，并检查 OctoBus status contract；agent-compose/OctoBus RepoDigest 是 operator 验证后注入的部署输入，不从 status 推断。上游 v2609.1.0 没有 `$schema` 或 compose schema ID；manifest 固定原始 compose SHA-256，`parser_version` 标识 pinned parser 版本，只有实际运行该 parser 时才进行 compose contract 权威验证。升级或回滚按 [agent-compose 集成说明](../architecture/integration-agent-compose.md#7-sas-102-运行时契约升级与回滚) 同步 manifest、默认值和二进制集合，并重建受影响的 Sandbox。


`mock` 下 integration checks 为 optional/skipped，服务完成启动后 `/readyz` 返回 200。`agentcompose-cli` 下 readiness 在后台缓存 runtime-only doctor 结果，并每 5 分钟刷新；HTTP 请求不会执行外部命令。daemon、OctoBus、协议、Provider、镜像或网络任一 required 检查为 `failed`/`unknown` 时，`/readyz` 返回结构化 503，`doctor` 输出 JSON 并以非零退出。
Sandbox→proxy 检查要求 operator 在固定的 `sas101-doctor-probe` project 中预先创建一个长期运行、隔离的 Docker Sandbox，并将其绑定到 agent `probe`；它必须使用固定 guest image，运行时状态必须是 `retained`，并只授予用户批准的 pinned M1-only synthetic calculator fixture（service `sas101-calculator`、instance `calculator-test`、label `sas101`）。Doctor 以固定 `--project-name sas101-doctor-probe sandbox ls` 做 project-scoped 列表绑定，要求列表只有该 Sandbox，再核对 Sandbox ID、running 状态、Docker driver、精确 guest image 与 retained 状态，随后 inspect 同一完整 ID 并执行固定的 `CalculatorService/Add(20, 22)` 合成调用，严格验证固定 fixture 身份及返回 `42`。v2609.1.0 的 inspect JSON 将重复 capset tag 压成单值，因此该检查要求 operator 先保证只有 `dev`；完整 capset 隔离仍属于 SAS-103 验收，不能由此 doctor 结果宣称。此 Sandbox 和 capability 只用于 M1 目标环境验收与 readiness，不是生产 capability，也不应承载 Provider 路由、客户数据或长期任务。

Provider connectivity 使用 daemon、`sasd` 与 `sasctl doctor` 共同加载的最终 `LLM_API_*` 和 suite model 配置。Doctor 只做一次有界 `/models` GET，不生成模型内容；endpoint 会按 agent-compose 的 root、`/v1` 或完整 `/responses`/`/chat/completions` 形式归一化，并核对 `LLM_MODEL` 及三个启用 Agent model 引用。
不要把 Provider Token、OctoBus Token 或客户密钥写入仓库、Prompt 或示例文件。
