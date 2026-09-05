#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FIXTURE="internal/executor/agentcompose/testdata/fixtures/agent-compose-v2609.1.0-pi-runtime-envelope.json"
[[ -f "$FIXTURE" ]] || { echo "contract fixture missing: $FIXTURE" >&2; exit 1; }

# Provenance: agent-compose v2609.1.0, composeRunOutput in
# https://github.com/chaitin/agent-compose/blob/v2609.1.0/cmd/agent-compose/cli_run_output.go
# and AgentResult in
# https://github.com/chaitin/agent-compose/blob/v2609.1.0/runtime/javascript/src/types.ts.
# Keep this check offline.
GO_BIN="${GO:-go}"
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  "$GO_BIN" test ./internal/executor/agentcompose -run '^TestParseRuntimeEnvelope$' -count=1

printf '%s\n' 'contract smoke passed: TestParseRuntimeEnvelope'
