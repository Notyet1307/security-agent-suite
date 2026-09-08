# Project Status

**Version:** `v0.1.0-alpha.1`  
**Status date:** 2026-09-07
**Positioning:** runnable engineering baseline; not a production security-analysis product.

## Completed

- Go API service (`sasd`) and CLI (`sasctl`).
- Five independent agent entries and agent-compose declarations.
- Fifteen versioned Skills, five output schemas, and example requests.
- Run state machine, queue, idempotency, tenant isolation, approval, cancellation, timeout, restart recovery, audit events, artifacts, and metrics.
- Deterministic policy gate for active validation; client-supplied approval IDs are rejected.
- Mock executor for offline development and an agent-compose CLI adapter for real sandboxes.
- Common Evidence, Finding, Timeline, AttackPath, RunResult, and Approval contracts.
- OpenAPI, Docker, Kubernetes starter manifests, PostgreSQL target schema, CI, CodeQL, Dependabot, evaluation fixtures, roadmap, and issue backlog.
- SAS-102 release contract in `release-manifest.json`: the checked-in `linux/arm64` source of truth and verified-deployment metadata pins agent-compose `v2609.1.0` at `docker.io/chaitin/agent-compose@sha256:79eceaf444f0a59555d0871ce77e11dd4348fe49071b6026cd34faafcc429bfd`, Guest at `docker.io/chaitin/agent-compose-guest@sha256:f1ebca0021d1de4ebd02d4da4117d7651e09b5a6db35be20092f03cc26a586b9`, and OctoBus at `docker.io/chaitin/octobus@sha256:9961c9d80d7ba14001da7b96967980c85bec44ab846f87cc2a4e7ff55d9c280b`. The raw `agent-compose.yml` SHA-256 is paired with parser version `v2609.1.0`, the authoritative compose validator when run; no upstream compose schema ID exists and this does not claim CI ran the parser. Doctor enforces agent-compose version and Guest release digest and checks the OctoBus status contract; the agent-compose/OctoBus RepoDigests remain operator-verified deployment inputs. Manifest normal/drift tests are checked in.
- SAS-201 local-file Artifact baseline: authenticated tenant-scoped streaming upload, atomic metadata registration, SHA-256/size/media-type validation, listing, and ranged download; Artifact bytes stay outside Run JSON.
- SAS-202 append-only Evidence Store: source/tool/version/parameters/time/SHA-256 fields, same-Run Artifact validation, tenant-scoped append/list/get, immutable local persistence, and no update/delete path.

## Verification evidence

The following repository-level checks are recorded across GitHub CI and sanitized local verification. They are offline or Mock evidence, not live Agent acceptance:

```text
make verify
make race
make smoke
git diff --check
```

PR #60's sanitized local smoke evidence used `scripts/smoke.sh`; the CI workflow's `make smoke` is Mock-only. Neither is live Agent evidence.

PyYAML is not installed, so `make verify` skipped YAML syntax parsing; its semantic checks still validated five agents, 15 skills, JSON contracts, and local links. The fixed `agent-compose v2609.1.0` binary normalized the current five-Agent compose shape to 8,964 bytes; its normalized output preserves the `${AGENT_COMPOSE_GUEST_IMAGE}` image reference, which Doctor now reconciles only against the already-validated source interpolation and configured digest.

The Mock smoke test proves two critical paths:

1. A normal event-triage run reaches `succeeded` in Mock mode.
2. An active attack-path-validation run stops at `waiting_approval` and executes only after server-side approval.

On the Mac mini target, the real controlled environment checks observed:

- agent-compose `v2609.1.0`, daemon `/api/version` and protocol status passed on `127.0.0.1:7410`; Docker image identity was `docker.io/chaitin/agent-compose@sha256:79eceaf444f0a59555d0871ce77e11dd4348fe49071b6026cd34faafcc429bfd`;
- OctoBus `GET /admin/v1/status` returned `{"status":"ok","services":1}` on `127.0.0.1:19000`;
- the running OctoBus container image identity was `docker.io/chaitin/octobus@sha256:9961c9d80d7ba14001da7b96967980c85bec44ab846f87cc2a4e7ff55d9c280b`; the endpoint status check did not infer a release version from that digest.
- the configured Guest image was present by immutable digest `sha256:f1ebca0021d1de4ebd02d4da4117d7651e09b5a6db35be20092f03cc26a586b9`;
- the dedicated retained probe Sandbox passed project-scoped binding, full-ID inspection, and the fixed synthetic `CalculatorService/Add(20,22)` proxy call returning `42`;
- the operator-owned, repository-external `0600` injection used the OMP machine provider `baizhi-responses` (called `baizhiyun` by the user), endpoint `https://ai-api-gateway.app.baizhi.cloud/api/openai`, protocol `responses`, and model `gpt-5.6-sol`; the daemon, `sasd`, and Doctor loaded the same final Provider settings;
- real `sasctl doctor` passed all 18 required checks, including Provider `/models` connectivity, and exited 0; the real `sasd` smoke returned `/healthz=200` and `/readyz=200`.

The target evidence above used only the dedicated non-production synthetic probe and no customer data or model generation. It does not claim real Agent execution, other runtime platforms, an OctoBus release version, or a production deployment.

## Deliberately not claimed

- No real customer data source is connected.
- No real security finding is produced by Mock mode.
- SAS-101 is complete, but it does not claim real execution capability for the five Agents or complete capset isolation; the running target containers are not a release deployment.
- File storage is single-node development storage, not HA storage.
- The local Artifact and Evidence APIs use bounded single-node files; they do not claim chunked or presigned object storage, HA, encryption-at-rest, lifecycle management, tamper-proof audit, or production retention/deletion controls.
- Kubernetes manifests are a production migration starting point, not a completed production deployment.
- GitHub currently reports the default `main` branch as unprotected; CI workflow presence is not branch-protection evidence.

## SAS-103 status and hard gate

The SAS-103 repository harness, offline contracts, cancellation/timeout contracts, schema gate, artifact binding, provenance handling, tests, and documentation were delivered by PR #60. Issue #9 is closed for that repository-reachable scope. Live SAS-103 remains **not complete**: live acceptance evidence is absent. The harness can produce a structural raw index for the required 100 normal runs and 10 lifecycle checks, but `--controls` is currently blocked with `failure: "controls_unverified"`; `verify_report` raises `controls_unverified` rather than returning counts until an external trusted attestation mechanism exists.

The remaining gates are 100/100 normal runs, 10 lifecycle checks, a fresh operator-authorized credential for a non-production provider, and independently executed, human-reviewed real non-production evidence for exactly 20 external controls (four control kinds across five Agents) covered by an existing governed signed/independent attestation and build provenance. Missing authoritative actual model/runtime-version provenance for each run and a missing authoritative no-side-effect/idempotency signal for transient retries are additional blockers; configured values are inputs and must not be called proof. The deliberate pinned-provider/`finalTextSource=provider_message` fail-closed gate may keep the live pass rate below 99% and is not acceptance evidence. Hashes, reviewer metadata, timestamps, and projected exchanges are not authentication. Until all are available, do not represent SAS-103 as complete or use customer data.

M1 issue status: SAS-104 has repository-level supported-subset output validation; SAS-105 lacks authoritative actual model, Skill, and tool versions; SAS-106 lacks real downstream Sandbox cancellation evidence; SAS-107 has partial error classification but no safe retry. None of these is closed by Issue #9.

## SAS-108 preflight

**Decision:** `BLOCKED`; 本轮批准只覆盖前置核验，未执行任何 live Provider、agent-compose、OctoBus、网络或 Sandbox 动作。

| Gate | Status | Evidence/source |
| --- | --- | --- |
| 授权引用与批准的非生产范围 | `BLOCKED` | 未提供可验证的 live authorization reference；preflight 批准不等于 live 执行授权 |
| fresh operator credential | `UNVERIFIED` | 未读取 `.env` 或 credential；需要 operator 只确认存在性，不提交凭据值 |
| live SAS listener | `UNVERIFIED` | 本轮未探测 endpoint；没有获授权的 listener 证据 |
| validator/build provenance | `BLOCKED` | `release-manifest.json` 只固定部署元数据；无受治理 build attestation，当前 `bin/sasctl` 不存在 |
| 20-control attestation | `BLOCKED` | `scripts/sas103_acceptance.py` 的 `import_controls`/`verify_controls` 明确返回 `controls_unverified` |
| actual model/Skill/tool/runtime provenance | `BLOCKED` | `docs/architecture/data-model.md` 与 runtime adapter 没有权威实际版本来源；配置值不算证据 |
| no-side-effect/idempotency retry signal | `BLOCKED` | 当前没有权威信号或安全重试实现；不得自动重试 |
| independent acceptance owner | `PENDING` | 尚未指定不参与实现的独立验收人 |
| repository inputs | `PASS (offline only)` | pinned manifest 与五个 synthetic fixtures 已通过结构核验；不构成 live evidence |

任一 `BLOCKED`、`UNVERIFIED` 或 `PENDING` 都禁止进入 SAS-108 live collect；本记录不是 acceptance evidence。

See [`docs/roadmap/implementation-plan.md`](docs/roadmap/implementation-plan.md) and [`planning/backlog.tsv`](planning/backlog.tsv).
