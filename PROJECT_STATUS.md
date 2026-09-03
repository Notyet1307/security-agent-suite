# Project Status

**Version:** `v0.1.0-alpha.1`  
**Status date:** 2026-09-03  
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

## Verification evidence

The following checks pass in the build environment:

```text
./scripts/verify.sh
./scripts/smoke.sh
go test -race ./... -timeout 180s
bash -n scripts/*.sh
YAML parse: 18 files
```

The smoke test proves two critical paths:

1. A normal event-triage run reaches `succeeded` in Mock mode.
2. An active attack-path-validation run stops at `waiting_approval` and executes only after server-side approval.

## Deliberately not claimed

- No real customer data source is connected.
- No real security finding is produced by Mock mode.
- The current environment did not contain an agent-compose daemon, OctoBus deployment, Docker daemon, model provider credentials, or reviewed security tools, so real sandbox/capability integration is not certified yet.
- File storage is single-node development storage, not HA storage.
- Kubernetes manifests are a production migration starting point, not a completed production deployment.
- The repository has not been pushed to GitHub from this environment because the connected GitHub integration is read-only for repository creation and file writes.

## Next hard gate

Proceed with **M1: environment doctor and real agent-compose integration**. Do not start implementing the five domain agents against production data until all five minimal sandbox runs, structured output validation, cancellation, timeout, provenance, and capset isolation pass in the target environment.

See [`docs/roadmap/implementation-plan.md`](docs/roadmap/implementation-plan.md) and [`planning/backlog.tsv`](planning/backlog.tsv).
