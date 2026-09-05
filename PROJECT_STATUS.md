# Project Status

**Version:** `v0.1.0-alpha.1`  
**Status date:** 2026-09-05
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

The following checks pass in the current worktree:

```text
make verify
make race
make smoke
git diff --check
```

PyYAML is not installed, so `make verify` skipped YAML syntax parsing; its semantic checks still validated five agents, 15 skills, JSON contracts, and local links. The fixed `agent-compose v2609.1.0` binary normalized the current five-Agent compose shape to 8,964 bytes, and the current Doctor parser returned `compose_file=passed`; this validates the pinned CLI contract, not runtime capability.

The smoke test proves two critical paths:

1. A normal event-triage run reaches `succeeded` in Mock mode.
2. An active attack-path-validation run stops at `waiting_approval` and executes only after server-side approval.

## Deliberately not claimed

- No real customer data source is connected.
- No real security finding is produced by Mock mode.
- Docker/OrbStack is available on the Mac mini. `agent-compose v2609.1.0` was temporarily source-built from exact commit `fee546bf137c56bb7473d3632b17ed14bdd3b54a`; its bare daemon `/api/version` and Doctor protocol checks passed, but agent-compose is not persistently deployed. OctoBus, Provider, Sandbox, and capability paths remain uncertified, so SAS-101 and target-environment readiness are not claimed green.
- File storage is single-node development storage, not HA storage.
- Kubernetes manifests are a production migration starting point, not a completed production deployment.

## Next hard gate

Proceed with **M1: environment doctor and real agent-compose integration**. Do not start implementing the five domain agents against production data until all five minimal sandbox runs, structured output validation, cancellation, timeout, provenance, and capset isolation pass in the target environment.

See [`docs/roadmap/implementation-plan.md`](docs/roadmap/implementation-plan.md) and [`planning/backlog.tsv`](planning/backlog.tsv).
