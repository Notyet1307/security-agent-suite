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

## SAS-103 真实 Sandbox 验收

这不是 `make verify` 或 Mock smoke。只能使用 [`evals/sas103-fixtures.json`](../../evals/sas103-fixtures.json) 中的合成 fixture；不得输入客户数据，或把 Provider/OctoBus token、API key 或客户内容写入仓库、命令行或证据目录。`.env` 不得保存真实 `SAS_API_KEY`；它只能从 operator-owned、仓库外且权限为 `0600` 的环境文件加载。

```sh
set -a
. ./.env
. /path/to/operator/sas103.env
set +a

make build
install -d -m 700 "$PWD/var/sas103-evidence"
SAS103_OUT="$PWD/var/sas103-evidence/$(date -u +%Y%m%dT%H%M%SZ)"
SAS103_CONTROLS=/path/to/human-reviewed/sas103-controls.json

python3 scripts/sas103_acceptance.py collect \
  --base-url "$SAS_BASE_URL" \
  --tenant-id sas103-synthetic \
  --runs-per-agent 20 \
  --timeout-max-duration 1s \
  --sasctl-bin "$PWD/bin/sasctl" \
  --controls "$SAS103_CONTROLS" \
  --output-dir "$SAS103_OUT"
```
当前实现没有可信 controls attestation，以上命令若提供 `--controls` 会返回非零 `controls_unverified`，并只写入标记为 `failure: "controls_unverified"` 的 raw index；这不是验收成功。

`$SAS103_OUT` 必须尚不存在；收集器会创建并检查它是 `0700`，其证据文件是 `0600`。若 `$SAS_BASE_URL` 是非 loopback 地址，只能在已授权的 HTTPS 非生产环境追加 `--allow-remote`。收集后运行：

```sh
python3 scripts/sas103_acceptance.py verify \
  --report "$SAS103_OUT/sas103-report.json" \
  --sasctl-bin "$PWD/bin/sasctl" \
  --controls "$SAS103_CONTROLS"
git diff --check
```

收集器固定执行五个 Agent 各 20 个正常运行（共 100，必须 100/100），并对每个 Agent 执行一个取消和一个超时 lifecycle 检查（共 10）。超时检查必须先观察至少一个非终态轮询，再核对配置的精确 `max_duration`；证据只能证明观察到的 API/runtime envelope，不能证明墙钟到期。每个正常输出都由仓库构建路径 `bin/sasctl` 的 `validate-output` 验证；报告绑定 validator binary、原始输出、验证契约和投影文件的 SHA-256。SHA-256 只校验字节完整性，不证明二进制或控制证据来源。
正常输出校验使用带租户/API 认证的请求下载精确 `agent-compose-final-output.json` 字节，核对 Artifact 元数据的 SHA-256 和 size，与 API `raw_output` 做严格 JSON 语义等价比较，再验证 Agent Schema；证据只保留哈希和元数据，不保留 Artifact 正文。

业务 `RawOutput` 仅接受配置中 pinned 的 runtime provider（允许值为 `codex`、`claude`、`gemini`、`opencode`、`pi`、`dsh`；当前环境使用 `pi`）且 `finalTextSource=provider_message`；`transcript_fallback` 只保留为 provenance 标记和诊断 Artifact。由于 pinned Pi fallback 是可能混入 stderr/不可信文本的拼接 transcript，应用层故意 fail closed；这可能使 live gate 低于 99%，不构成验收。


当前没有仓库内可信签名或独立证明机制。`--controls` 因此明确返回 `controls_unverified`，任何导入的控制都不能进入报告计数或通过 `verify`；不得用 hash、reviewer、时间戳或投影交换自证。要完成 live SAS-103，operator 必须先提供现有治理流程认可的外部签名/独立可审阅 attestation，并为 `bin/sasctl` 提供受治理的构建来源；本 harness 不会自创签名方案。
写入的 API 证据是 allowlist 投影：请求体、tenant/request 标识和原始输出只保留 hash，不保存完整 body；目录名 `raw-api-responses` 不表示可以保存未脱敏原文。

### `$SAS103_CONTROLS` 格式

控制文件顶层只能是：

```json
{
  "schema": "sas103-controls.v1",
  "controls": [
    {
      "agent_id": "<agent-id>",
      "kind": "<control-kind>",
      "state": "executed",
      "relative_path": "raw-api-responses/<six-digit>-<label>.json",
      "sha256": "<64-lowercase-hex SHA-256 of source bytes>"
    }
  ]
}
```

验收用的 `controls` 必须恰好有 20 个唯一 agent×kind 条目，覆盖五个 Agent 与四个控制种类各一次；但当前 harness 没有可信 attestation mechanism，因此 `--controls` 会以非零退出并写入 `failure: "controls_unverified"` 的 raw index，绝不输出 acceptance。`verify_report` 在没有外部可信 attestation 时始终抛出 `controls_unverified`，不会返回 counts；unsigned/fabricated `executed` 条目不能通过。

控制文件所在目录的 `raw-api-responses` 必须是 `0700`、非 symlink 的目录；每个引用文件必须是 `0600`、非 symlink 的常规文件，且 `relative_path` 必须匹配 `^raw-api-responses/[0-9]{6}-[a-z0-9_-]+\.json$`。`sha256` 是完整未改动源文件字节的 SHA-256，不是投影后的 hash，也不是来源/真实性证明。

每个源文件只能包含下列原始交换形状（`<...>` 是类型占位符，不是实际 body 或结果）：

```text
{
  "request":  {"method": <string>, "path": <string>, "body_json": <JSON-text-string-or-null>},
  "response": {"status": <integer>, "body_json": <JSON-text-string>}
}
```

参数细节可通过 `python3 scripts/sas103_acceptance.py collect --help` 查看；CLI 的成功消息仅表示 raw index 已写入或（未来配置可信 attestation 后）报告结构检查完成，不表示 SAS-103 live acceptance。

取消语义、`downstream_acknowledged` 与受控清理见 [agent-compose 的 SAS-103 证据与取消契约](../architecture/integration-agent-compose.md#8-sas-103-证据与取消契约)。

第 4 步是人工预检；Doctor 内部使用 `agent-compose --json --file <path> config` 并解析单个 normalized JSON object，而不是 `config --quiet` fallback。该命令可能解析 operator-owned compose 声明的外部 scheduler/script source，因此不应宣称零 I/O；Doctor 测试通过注入命令执行器保持离线。SAS-102 的 [`release-manifest.json`](../../release-manifest.json) 是已验证 `linux/arm64` 部署的版本与镜像元数据真源：Doctor 强制 agent-compose 版本和 Guest release digest，并检查 OctoBus status contract；agent-compose/OctoBus RepoDigest 是 operator 验证后注入的部署输入，不从 status 推断。上游 v2609.1.0 没有 `$schema` 或 compose schema ID；manifest 固定原始 compose SHA-256，`parser_version` 标识 pinned parser 版本，只有实际运行该 parser 时才进行 compose contract 权威验证。升级或回滚按 [agent-compose 集成说明](../architecture/integration-agent-compose.md#7-sas-102-运行时契约升级与回滚) 同步 manifest、默认值和二进制集合，并重建受影响的 Sandbox。


`mock` 下 integration checks 为 optional/skipped，服务完成启动后 `/readyz` 返回 200。`agentcompose-cli` 下 readiness 在后台缓存 runtime-only doctor 结果，并每 5 分钟刷新；HTTP 请求不会执行外部命令。daemon、OctoBus、协议、Provider、镜像或网络任一 required 检查为 `failed`/`unknown` 时，`/readyz` 返回结构化 503，`doctor` 输出 JSON 并以非零退出。
Sandbox→proxy 检查要求 operator 在固定的 `sas101-doctor-probe` project 中预先创建一个长期运行、隔离的 Docker Sandbox，并将其绑定到 agent `probe`；它必须使用固定 guest image，运行时状态必须是 `retained`，并只授予用户批准的 pinned M1-only synthetic calculator fixture（service `sas101-calculator`、instance `calculator-test`、label `sas101`）。Doctor 以固定 `--project-name sas101-doctor-probe sandbox ls` 做 project-scoped 列表绑定，要求列表只有该 Sandbox，再核对 Sandbox ID、running 状态、Docker driver、精确 guest image 与 retained 状态，随后 inspect 同一完整 ID 并执行固定的 `CalculatorService/Add(20, 22)` 合成调用，严格验证固定 fixture 身份及返回 `42`。v2609.1.0 的 inspect JSON 将重复 capset tag 压成单值，因此该检查要求 operator 先保证只有 `dev`；完整 capset 隔离仍属于 SAS-103 验收，不能由此 doctor 结果宣称。此 Sandbox 和 capability 只用于 M1 目标环境验收与 readiness，不是生产 capability，也不应承载 Provider 路由、客户数据或长期任务。

Provider connectivity 使用 daemon、`sasd` 与 `sasctl doctor` 共同加载的最终 `LLM_API_*` 和 suite model 配置。Doctor 只做一次有界 `/models` GET，不生成模型内容；endpoint 会按 agent-compose 的 root、`/v1` 或完整 `/responses`/`/chat/completions` 形式归一化，并核对 `LLM_MODEL` 及三个启用 Agent model 引用。
不要把 Provider Token、OctoBus Token 或客户密钥写入仓库、Prompt 或示例文件。
