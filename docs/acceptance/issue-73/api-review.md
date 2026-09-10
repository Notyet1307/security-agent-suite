# #73 independent API acceptance

Reviewer: `/root/accept73_api` (independent AI subagent, not #72 implementation author; not a human signature).
Fixed implementation SHA: `342c9b6d8d6c20f872bd9c71d3b6a1d83300613a`.
Sole behavior spec: GitHub #70 v3, updatedAt `2026-09-10T09:08:22Z`, snapshot `/tmp/sas73-spec.json`.

Conclusion: ACCEPT the offline API/input-binding/protocol scope reviewed here. No production defect found in this scope. Recovery/concurrency-wide acceptance is delegated to the other independent reviewer; this does not replace that review. No live provider/daemon/Sandbox/OctoBus or external target was invoked, and this does not prove actual model input consumption or prompt-injection resistance in an LLM.

I independently read the public HTTP parsing, strict Unicode/schema validation, normalization/fingerprint and submission binding paths, and reviewed existing manual API/legacy regression assertions before running them. Existing fixture test asserted only an aggregate of 3 executor calls and did not assert every fixture's full raw-byte/Artifact/Evidence/Run chain. I therefore added a temporary, reproducible overlay probe (no repository edits). It creates a fresh real temporary file/artifact/evidence store and clearly labelled counting executor per fixture, checks downloaded original bytes, all relevant frozen binding fields, per-fixture execution counts, and valid terminal replay.

Observed: all 10 fixtures have 0 executor calls after creation/upload. normal, empty-observations and prompt-injection each produce submit202, terminal replay200, 1 executor call and 1 input Evidence; the other 7 produce 400/invalid_request, remain preparing, and have 0 calls and 0 Evidence. Original bytes and SHA/size match each manifest entry and downloaded Artifact. Full actual IDs, SHA, size, Evidence, frozen InputRef and Submission are JSON logs in the raw result. Existing independently inspected tests cover strict keys/UTF8/duplicates/surrogates/limits, cross-tenant/Run404, field/array drift409, explicit defaults, the Chinese+HTML fixed creation fingerprint, 12-way creation, 16-way submit and different Artifact409, and old automatic lifecycle/artifact/Evidence compatibility.

First attempt failure was in my new probe: I read `sha256` and `size_bytes` at the fixture's top level instead of under `input_manifest`, causing empty digest/zero size and `fixture manifest mismatch` before exercising the product. I corrected the probe's manifest struct/accessors only. Failed output is retained at `/tmp/sas73-api-probe-first-attempt.txt`; it is not a product failure. Final test run exit0, package result 7.789s.

Reproduce from the fixed worktree:

```sh
cd /Users/yet/Developer/security-agent-suite-acceptance-73
go test -overlay /tmp/sas73-api-overlay.json ./internal/httpapi -run 'TestAcceptance73RawBinding|TestManual|TestHTTPRunLifecycleAndTenantIsolation|TestHTTPEvidenceAppendAndTenantIsolation' -count=1 -v > /tmp/sas73-api-raw.txt 2>&1
```

Overlay maps the absent `internal/httpapi/accept73_probe_test.go` in that worktree to `/tmp/sas73-api-probe_test.go`. It reuses committed helper setup while adding independent public API assertions. Root worktree remained clean.

SHA256 evidence:

- probe: f4aadbedc432f7d79ece59ff2b996dcebf86f25628d4077e8064e34d63db9ce0
- overlay: 14fbe827d137f49740be48cde939220459df7af50f626c8933abc8e5c36a72d9
- final raw: 5bef1d029e07b88f1749613f5ddbddf26b9a2f7c29b564402372cc3c8465eb3e
- first attempt raw: 765608d952d5342c9c5d3d3a15ec6f6953bdb17ef8499f35d40e2a16c32e5b8e
- synthetic-alert-v1 schema: 754438471f89afeefd28f831f112f59179bdb15c59818d19cc2c0b644ac6c22d
- run-request schema: 2e06658e88a3395c7840a8c4a72f436c92ba69e047b2a00d202c3eee37f7a2ee
- OpenAPI: b7dc8b3bec5efaa8bed281068eb2257aebcd5a05c4f0538a2c594b1143891849
- fixture manifest: 5d8693a6208cb69d77b2aadcdc481c4be1b658eb632b90ad5cb5068a96125ee1

The fixture pack remains sas.input-fixtures/v1 with spec_version2 as explicitly retained by v3; schema is sas.synthetic-alert/v1. No malicious/benign label inferred from acceptance.
