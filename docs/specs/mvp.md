# MVP Specification

## Behavior
- Expose the five agents through the catalog and run API.
- Validate inputs, tenant boundaries, authorization, and output contracts.
- Queue runs and support approval, cancellation, timeout, recovery, audit, artifacts, and immutable evidence.
- Run offline with Mock; use agent-compose only through the executor adapter.

## Security behavior
Active validation requires an authorization reference, explicit scope, stop conditions, and server-side approval. Missing required runtime evidence remains `unknown` or `failed`; it is never a successful result.

## Execution failure boundary
Execution errors are classified into structured error codes and retained with the original output and audit trail. The MVP is fail-closed: it never automatically retries. A future retry design requires a trusted runtime contract proving no side effect or idempotency; configuration, error text, and model judgment are not proof.

## Acceptance
`make verify`, `make race`, and Mock smoke pass; malformed contracts and unauthorized high-risk requests fail with structured errors. Live runtime acceptance is separate and not part of the alpha claim.
