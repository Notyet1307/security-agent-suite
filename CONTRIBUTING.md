# Contributing

## Development flow

1. Use the GitHub Issue as the task source: record scope, non-goals, dependencies, acceptance, and evidence tier before coding.
2. Assign one writer for each task and its shared files. Reviewers and readers may work in parallel; do not make concurrent edits to the same core state or file without an explicit handoff.
3. Create a focused branch.
4. Add or update tests with the change.
5. Run `make verify`; run `make race` when changing concurrency or persistence.
6. Open a pull request using the repository template; link the source Issue and sanitized evidence.
7. Keep changes within one architectural boundary unless the PR explicitly records a cross-boundary migration.

## Evidence and acceptance

Label each result:

- `offline`: unit, contract, or static checks with no external runtime;
- `controlled-environment`: synthetic non-production dependency checks, not live Agent acceptance;
- `live`: authorized non-production execution with real provider and runtime evidence.

CI or Mock output cannot satisfy a `live` criterion. The implementer records commands, commit, target class, sanitized output or hashes, and remaining gates. An independent reviewer who did not produce the implementation records acceptance separately.

## Authorized execution

Live Provider, agent-compose, OctoBus, network, or target actions require an explicit authorization reference, approved non-production scope, fresh operator-owned credentials kept outside the repository, command line, and logs, plus a stop, cleanup, and retention plan. Without those inputs, stay offline. Active validation still requires both an authorization reference and server-side approval.

## Commit style

Use imperative, scoped messages where practical, for example:

- `feat(api): add run approval endpoint`
- `fix(policy): reject empty authorization scope`
- `docs(roadmap): split traffic analysis milestones`

## Security-sensitive changes

Changes to attack validation, authorization, secret handling, executor invocation, artifact paths, or tenant isolation require a threat-model note in the PR.
