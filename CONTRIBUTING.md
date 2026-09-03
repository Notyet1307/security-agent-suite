# Contributing

## Development flow

1. Create a focused branch.
2. Add or update tests with the change.
3. Run `make verify`; run `make race` when changing concurrency or persistence.
4. Open a pull request using the repository template.
5. Keep changes within one architectural boundary unless the PR explicitly records a cross-boundary migration.

## Commit style

Use imperative, scoped messages where practical, for example:

- `feat(api): add run approval endpoint`
- `fix(policy): reject empty authorization scope`
- `docs(roadmap): split traffic analysis milestones`

## Security-sensitive changes

Changes to attack validation, authorization, secret handling, executor invocation, artifact paths, or tenant isolation require a threat-model note in the PR.
