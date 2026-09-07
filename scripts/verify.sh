#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo '[1/6] Go formatting'
UNFORMATTED="$(gofmt -l ./cmd ./internal)"
if [[ -n "$UNFORMATTED" ]]; then
  echo "These files are not gofmt-formatted:" >&2
  echo "$UNFORMATTED" >&2
  exit 1
fi

echo '[2/6] Static analysis'
go vet ./...

echo '[3/6] Tests and coverage'
go test -coverprofile=coverage.txt ./...

echo '[4/6] Builds'
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/sasd ./cmd/sasd
CGO_ENABLED=0 go build -trimpath -o bin/sasctl ./cmd/sasctl

echo '[5/6] Contract and repository checks'
python3 scripts/verify_release_test.py
python3 scripts/sas103_acceptance_test.py
python3 scripts/verify_release.py .
python3 - <<'PY'
from pathlib import Path
import json
import re
import sys

root = Path('.')
for path in root.rglob('*.json'):
    try:
        json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise SystemExit(f'invalid JSON {path}: {exc}')

catalog = json.loads((root / 'configs/agents.json').read_text(encoding='utf-8'))
agents = catalog['agents'] if isinstance(catalog, dict) else catalog
ids = [item['id'] for item in agents]
expected = {
    'traffic-analysis', 'event-triage', 'attack-path-validation',
    'compliance-query', 'security-report'
}
if set(ids) != expected or len(ids) != 5:
    raise SystemExit(f'agent catalog must contain exactly {sorted(expected)}, got {ids}')

for agent_id in ids:
    base = root / 'agents' / agent_id
    required = [base / 'SYSTEM.md', base / 'output.schema.json', base / 'examples/request.json']
    for path in required:
        if not path.is_file() or not path.read_text(encoding='utf-8').strip():
            raise SystemExit(f'missing or empty required file: {path}')
    schema = json.loads((base / 'output.schema.json').read_text(encoding='utf-8'))
    if schema.get('$schema') != 'https://json-schema.org/draft/2020-12/schema':
        raise SystemExit(f'{base}/output.schema.json must use JSON Schema 2020-12')
    skills = sorted(base.glob('skills/*/SKILL.md'))
    if len(skills) != 3:
        raise SystemExit(f'{agent_id} must contain exactly 3 baseline skills, got {len(skills)}')
    for skill in skills:
        text = skill.read_text(encoding='utf-8')
        if not text.startswith('---\n') or '\nname:' not in text or '\ndescription:' not in text:
            raise SystemExit(f'invalid skill front matter: {skill}')

compose = (root / 'agent-compose.yml').read_text(encoding='utf-8')
for agent_id in expected:
    if not re.search(rf'^  {re.escape(agent_id)}:', compose, flags=re.M):
        raise SystemExit(f'agent-compose.yml does not define {agent_id}')

openapi = (root / 'openapi/openapi.yaml').read_text(encoding='utf-8')
for fragment in ('/v1/agents/{agentID}/runs:', '/v1/runs/{runID}/approve:', '/v1/runs/{runID}/cancel:'):
    if fragment not in openapi:
        raise SystemExit(f'OpenAPI is missing {fragment}')

try:
    import yaml
except ModuleNotFoundError:
    print('PyYAML not installed; YAML syntax parsing skipped (semantic checks still ran).')
else:
    for path in sorted(list(root.rglob('*.yml')) + list(root.rglob('*.yaml'))):
        yaml.safe_load(path.read_text(encoding='utf-8'))

# Check local Markdown links. Ignore anchors, mailto and external URLs.
link_pattern = re.compile(r'\[[^\]]*\]\(([^)]+)\)')
for doc in root.rglob('*.md'):
    text = doc.read_text(encoding='utf-8')
    for target in link_pattern.findall(text):
        target = target.split('#', 1)[0].strip()
        if not target or target.startswith(('http://', 'https://', 'mailto:', 'artifact://')):
            continue
        candidate = (doc.parent / target).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            raise SystemExit(f'local Markdown link escapes repository: {doc} -> {target}')
        if not candidate.exists():
            raise SystemExit(f'broken local Markdown link: {doc} -> {target}')

print(f'validated 5 agents, {sum(1 for _ in root.glob("agents/*/skills/*/SKILL.md"))} skills, JSON contracts and local links')
PY

echo '[6/6] Optional agent-compose validation'
if [[ "${SAS_VERIFY_AGENT_COMPOSE:-0}" == "1" ]]; then
  command -v agent-compose >/dev/null 2>&1 || { echo 'agent-compose is required for SAS_VERIFY_AGENT_COMPOSE=1' >&2; exit 1; }
  agent-compose -f ./agent-compose.yml config --quiet
else
  echo 'skipped; set SAS_VERIFY_AGENT_COMPOSE=1 to enable'
fi

echo 'verification passed'
