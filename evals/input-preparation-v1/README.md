# Input preparation fixture pack v1

These are offline, repository-authored synthetic bytes for [task #71](https://github.com/Notyet1307/security-agent-suite/issues/71). The sole behavior specification is [#70 v2](https://github.com/Notyet1307/security-agent-suite/issues/70); this directory is its machine-checkable fixture attachment, not another specification.

- [manifest.json](manifest.json) pins the source declaration, specification version, schema hash, raw byte SHA-256/size, and expected validation outcome for each payload.
- [synthetic-alert-v1.schema.json](../../contracts/synthetic-alert-v1.schema.json) fixes the narrow single-alert model. It does not complete the full data model or evaluation framework in #31/#20.
- `.payload` files deliberately include invalid JSON and UTF-8. Read them as bytes; do not reformat, transcode, or regenerate their manifest hashes to conceal drift.

Run from the repository root:

```sh
python3 scripts/verify_input_fixtures.py
make verify
```

The checker uses only Python's standard library and the limited schema keywords present in this attachment. It checks fixture integrity and deterministic parsing/schema outcomes; it is not the production input validator or a general JSON Schema implementation. New schema keywords require an explicit checker change. JSON/schema failure categories are fixture diagnostics; the planned API exposes the existing `invalid_request` code.

For #72, create a fresh manual Run per fixture with its `input_manifest`, upload the exact `.payload` bytes as `application/json` with the pinned digest header, then explicitly submit its Artifact ID. Invalid JSON can upload successfully because upload validates bytes/metadata, while submit validates JSON/schema. The expected submit status describes the future API contract, not an HTTP test already performed here.

Normal, empty-observation, and prompt-injection samples are structurally acceptable. They establish no malicious/benign verdict. Injection text must remain untrusted data; this static checker does not prove runtime resistance. Remaining API, concurrency, recovery, executor-consumption, and independent acceptance work belongs to #72/#73. No service, Provider, Sandbox, or OctoBus is called by this checker.
