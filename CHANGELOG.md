# Changelog

## Unreleased

### Added

- Go-based API gateway and CLI.
- Five independently callable agent definitions.
- Mock and agent-compose CLI executors.
- Run state machine, approval gate, file persistence, artifacts, audit events, metrics, OpenAPI contract, tests, and implementation roadmap.
- SAS-103 synthetic real-Sandbox acceptance harness and evidence verifier.
- Run-scoped streaming Artifact upload and metadata registration with SHA-256 validation and tenant-authorized download.
- Append-only Evidence Store with source/tool/version/parameters/time/SHA-256 metadata, optional same-Run Artifact binding, tenant isolation, and immutable file persistence.

### Changed

- agent-compose process cancellation and timeout now permit daemon `StopRun` acknowledgement; a cancellation request for a running Run returns HTTP `202` until it becomes terminal.
