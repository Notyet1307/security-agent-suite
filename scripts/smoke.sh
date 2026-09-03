#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v curl >/dev/null 2>&1 || { echo 'curl is required' >&2; exit 1; }
TMP="$(mktemp -d)"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
)"
BASE="http://127.0.0.1:${PORT}"
API_KEY='smoke-secret'
TENANT='smoke-tenant'
PID=''

cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

CGO_ENABLED=0 go build -o "$TMP/sasd" ./cmd/sasd
SAS_ADDR="127.0.0.1:${PORT}" \
SAS_API_KEY="$API_KEY" \
SAS_EXECUTOR=mock \
SAS_STATE_DIR="$TMP/state" \
SAS_ARTIFACT_DIR="$TMP/artifacts" \
SAS_AGENT_CATALOG="$ROOT/configs/agents.json" \
"$TMP/sasd" >"$TMP/server.log" 2>&1 &
PID=$!

for _ in $(seq 1 100); do
  if curl -fsS "$BASE/healthz" >/dev/null; then break; fi
  sleep 0.05
done
curl -fsS "$BASE/healthz" >/dev/null || { cat "$TMP/server.log"; exit 1; }

headers=(-H "X-API-Key: $API_KEY" -H "X-Tenant-ID: $TENANT")
curl -fsS "${headers[@]}" "$BASE/v1/agents" > "$TMP/agents.json"
python3 - "$TMP/agents.json" <<'PY'
import json, sys
obj=json.load(open(sys.argv[1]))
assert len(obj['agents']) == 5, obj
PY

REQUEST="$TMP/request.json"
python3 - "$REQUEST" <<'PY'
import json, sys, time
request = {
  'request_id': f'smoke-event-{time.time_ns()}',
  'mode': 'triage',
  'inputs': [{'type': 'json', 'uri': 'artifact://smoke/alert.json'}],
  'scope': {'tenant_id': 'smoke-tenant', 'assets': ['asset-smoke-01']},
  'policy': {'network_access': 'deny', 'active_validation': False},
  'output': {'language': 'zh-CN', 'formats': ['json']}
}
json.dump(request, open(sys.argv[1], 'w'))
PY
curl -fsS -X POST "${headers[@]}" -H 'Content-Type: application/json' \
  --data @"$REQUEST" "$BASE/v1/agents/event-triage/runs" > "$TMP/run.json"
RUN_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$TMP/run.json")"

terminal=''
for _ in $(seq 1 100); do
  curl -fsS "${headers[@]}" "$BASE/v1/runs/$RUN_ID" > "$TMP/current.json"
  terminal="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$TMP/current.json")"
  case "$terminal" in succeeded|partial|failed|cancelled) break;; esac
  sleep 0.05
done
[[ "$terminal" == 'succeeded' ]] || { cat "$TMP/current.json"; cat "$TMP/server.log"; exit 1; }

ATTACK="$TMP/attack.json"
python3 - "$ATTACK" <<'PY'
import json, sys, time
request = {
  'request_id': f'smoke-attack-{time.time_ns()}',
  'mode': 'active_validate',
  'inputs': [{'type': 'json', 'uri': 'artifact://smoke/finding.json'}],
  'scope': {
    'tenant_id': 'smoke-tenant',
    'authorization_ref': 'AUTH-SMOKE-001',
    'assets': ['192.0.2.10'],
    'networks': ['192.0.2.0/24']
  },
  'policy': {
    'network_access': 'restricted',
    'active_validation': True,
    'max_requests': 10,
    'max_duration': '2m'
  },
  'output': {'language': 'zh-CN', 'formats': ['json']}
}
json.dump(request, open(sys.argv[1], 'w'))
PY
curl -fsS -X POST "${headers[@]}" -H 'Content-Type: application/json' \
  --data @"$ATTACK" "$BASE/v1/agents/attack-path-validation/runs" > "$TMP/attack-run.json"
ATTACK_ID="$(python3 -c 'import json,sys; o=json.load(open(sys.argv[1])); assert o["status"]=="waiting_approval"; print(o["id"])' "$TMP/attack-run.json")"

curl -fsS -X POST "${headers[@]}" -H 'Content-Type: application/json' \
  --data '{"approval_id":"APR-SMOKE-001","actor":"smoke-approver","reason":"authorized smoke test"}' \
  "$BASE/v1/runs/$ATTACK_ID/approve" > "$TMP/approved.json"

status=''
for _ in $(seq 1 100); do
  curl -fsS "${headers[@]}" "$BASE/v1/runs/$ATTACK_ID" > "$TMP/attack-current.json"
  status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$TMP/attack-current.json")"
  case "$status" in succeeded|partial|failed|cancelled) break;; esac
  sleep 0.05
done
[[ "$status" == 'succeeded' ]] || { cat "$TMP/attack-current.json"; cat "$TMP/server.log"; exit 1; }

echo "smoke passed: event=$RUN_ID attack=$ATTACK_ID"
