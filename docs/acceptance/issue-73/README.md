# #73 独立输入闭环验收（offline）

结论：两位未参与 #72 实现的独立 AI 复核人分别接受所分配的 API/绑定与恢复/并发范围；主会话复核实际输出和摘要后，接受固定版本的离线输入闭环。报告不代真人签字，不是模型实际消费、真实研判或 #61 五 Agent 正式验收。

## 固定版本与授权

- 实现提交：`342c9b6d8d6c20f872bd9c71d3b6a1d83300613a`，由 [PR #75](https://github.com/Notyet1307/security-agent-suite/pull/75) 合并；任务 [#72](https://github.com/Notyet1307/security-agent-suite/issues/72) 已关闭。
- 唯一行为规格：[#70 v3](https://github.com/Notyet1307/security-agent-suite/issues/70)，updated_at `2026-09-10T09:08:22Z`。本报告记录验收，不复制或更改规格。
- [#73](https://github.com/Notyet1307/security-agent-suite/issues/73) 授权来自用户 2026-09-10“合并 然后进行下一步”；范围为独立离线验收，不包含真实 Provider/daemon/Sandbox/OctoBus 或外部目标。
- API 为 `/v1`，OpenAPI 3.1.0 / info.version 0.1.0；输入 schema 为 `sas.synthetic-alert/v1`；fixture 为 `sas.input-fixtures/v1`。v3 明确保留 fixture manifest 的 spec_version 2 及原始字节。
- [版本与摘要](versions.json) 固定规格正文 SHA-256、API/schema/manifest 和全部 10 个原始样本的字节摘要及大小。实现源自干净独立工作树，未使用原目录的未提交改动。

## 实际观察

以下值从独立探针的原始 JSON 日志提取并由主会话对照 fixture manifest 复算；完整 Artifact/Evidence/Run ID、冻结字段及摘要在 [API 原始结果](api-raw.txt)。每个样本使用独立真实临时 file/artifact/evidence store 和明确标记的计数测试 executor，HTTP 通过公共 handler，不启动监听端口。

| fixture | 原始 bytes | 首次 submit HTTP | 上传后调用数 | 提交及重发后调用数 | 输入 Evidence 数 | 最终状态 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| normal | 205 | 202 | 0 | 1 | 1 | failed |
| empty-observations | 104 | 202 | 0 | 1 | 1 | failed |
| prompt-injection | 261 | 202 | 0 | 1 | 1 | failed |
| damaged | 202 | 400 | 0 | 0 | 0 | preparing |
| duplicate-key | 222 | 400 | 0 | 0 | 0 | preparing |
| trailing-data | 208 | 400 | 0 | 0 | 0 | preparing |
| invalid-utf8 | 202 | 400 | 0 | 0 | 0 | preparing |
| nonstandard-number | 204 | 400 | 0 | 0 | 0 | preparing |
| unknown-version | 205 | 400 | 0 | 0 | 0 | preparing |
| non-synthetic | 206 | 400 | 0 | 0 | 0 | preparing |

有效样本的 `failed` 是计数 executor 显式返回 failed 测试结果后的终态（测试设置 ErrorCode=test_only），用来验证终态重发200；不是研判失败证据，也没有把结果伪装成成功。全部下载字节与上传原文相等；有效样本的 Artifact URI/摘要/大小、Evidence ID/来源/工具语义和 Run 冻结 inputs/submission 绑定通过断言。无效样本为400/invalid_request且不发布输入 Evidence。

恢复复核实际覆盖24种中断组合（file/memory × 六 journal/Evidence/Run 边界 × 同实例重试/重启）、满队列补通知、并发提交/取消、损坏绑定拒绝恢复、running/validating 不重试、Evidence 伪造与预占、目录同步失败和 CLI 旧行为。独立追加探针记录：取消后重发再启动执行数0，另一 Run 占用保留 Evidence ID 返回409，异租户返回404，最终执行数0。

## 独立身份与原始结论

- `/root/accept73_api`：[原始独立报告](api-review.md)，[命令结果](api-raw.txt)，[探针源码](api-probe_test.go.txt)。结论 ACCEPT API/input-binding/protocol。
- `/root/accept73_recovery`：[原始独立报告](recovery-review.md)，[命令结果](recovery-raw.txt)，[探针源码](recovery-probe_test.go.txt)。结论接受恢复/并发/持久化/CLI/回滚说明。
- 两人均未实现 #72；只读产品源码，临时 overlay 不改产品。主会话整理附件和交叉核对，不冒用独立复核身份。
- API 探针首次误读 fixture 嵌套 manifest 字段，导致探针自身在产品调用前失败；修正探针后通过。[首次失败原文](api-probe-first-attempt.txt) 保留，此失败不隐去，也不计为产品缺陷。两份原始报告保留当时 `/tmp` 路径；本目录附件是对应文件的原样归档。

## 验证与复跑

固定实现工作树执行 `make verify SAS_VERIFY_AGENT_COMPOSE=0` 和 `make race`，均 exit0：[verify 原文](verify-raw.txt)、[race 原文](race-raw.txt)。PyYAML 未安装，verify 的可选 YAML 解析跳过；合并主分支 CI 安装 PyYAML 并通过 verify、Mock smoke 和 race：[CI](https://github.com/Notyet1307/security-agent-suite/actions/runs/34460654089)、[原始 CI 状态](main-ci.json)。[CodeQL](https://github.com/Notyet1307/security-agent-suite/actions/runs/34460654125) 也通过，[状态快照](main-codeql.json)。本地未启动 daemon 或真实 runtime，测试中的 fake subprocess 不是真实 agent-compose。

在固定实现版本或只增加本验收附件的分支根目录运行下列命令；它只将归档探针临时映射进现有测试包，复用已提交的计数 executor/临时存储 helper。原始复核命令另保留在各报告与日志中。

```sh
python3 - <<'PYCODE'
import json, pathlib, subprocess, tempfile
root = pathlib.Path.cwd()
evidence = root / 'docs/acceptance/issue-73'
subprocess.run(['git', 'diff', '--exit-code', '342c9b6d8d6c20f872bd9c71d3b6a1d83300613a', '--', 'cmd', 'internal', 'contracts', 'evals', 'openapi'], check=True)
with tempfile.TemporaryDirectory() as tmp:
    replacements = {}
    for name in ('api', 'recovery'):
        source = pathlib.Path(tmp) / (name + '_test.go')
        source.write_bytes((evidence / (name + '-probe_test.go.txt')).read_bytes())
        replacements[str(root / 'internal/httpapi' / ('accept73_' + name + '_test.go'))] = str(source)
    overlay = pathlib.Path(tmp) / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': replacements}))
    subprocess.run(['go', 'test', '-overlay', str(overlay), './internal/httpapi', '-run', 'TestAcceptance73RawBinding|TestIndependent73CancellationAndCrossRunReservedEvidence|TestManual|TestSlowManualUploadDoesNotBlockAutomaticCancellation|TestHTTPRunLifecycleAndTenantIsolation|TestHTTPEvidenceAppendAndTenantIsolation', '-count=1', '-v'], check=True)
PYCODE
```

低层 store/artifact 同步失败及 CLI 的精确复跑命令见 [恢复原始记录](recovery-raw.txt)。`SHA256SUMS` 固定本目录证据，验证命令为在此目录执行 `shasum -a 256 -c SHA256SUMS`。

## 边界与后续

通过的是单服务进程输入准备、验证、证据绑定和至多一次测试调度。没有实际断电、实际回滚演练、跨进程 exactly-once/HA 或真实模型消费证据；memory 的重启是保留内存适配器后重建服务实例。注入样本作为字节保存不证明 LLM 抗注入能力。回滚只核对文档的旧二进制隔离/一致备份约束。

输入阶段证据通过后，路线 #69 可提出“实际消费冻结输入并返回受允许 Evidence ID 约束的研判输出”的下一阶段规格与任务。不得凭本报告关闭 #31/#20/#61，也不自动开始真实运行或 Accord 集成。本报告的归档交付由对应 PR 审核并合并后关闭 #73。
