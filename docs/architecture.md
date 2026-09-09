# Architecture

Callers → Go HTTP/CLI control plane → executor port → Mock or agent-compose CLI → Sandbox → OctoBus capabilities. Evidence, findings, timelines, attack paths, and artifacts return through versioned contracts.

Go owns stable authorization, state, tenancy, queueing, persistence, audit, and validation. agent-compose owns sandbox lifecycle. OctoBus owns capability exposure. This separation preserves offline development and prevents transport/runtime concerns entering the domain model.

Detailed rationale: [`architecture/overview.md`](architecture/overview.md), [`architecture/security-model.md`](architecture/security-model.md), [`architecture/data-model.md`](architecture/data-model.md).
