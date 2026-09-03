#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v gh >/dev/null 2>&1 || { echo 'GitHub CLI (gh) is required.' >&2; exit 1; }
gh auth status >/dev/null
REPO="${GITHUB_REPOSITORY:-Notyet1307/security-agent-suite}"

python3 - "$REPO" <<'PY'
from pathlib import Path
import csv, subprocess, sys
repo=sys.argv[1]
rows=list(csv.DictReader(Path('planning/backlog.tsv').open(encoding='utf-8'), delimiter='\t'))
existing=subprocess.run(['gh','issue','list','--repo',repo,'--state','all','--limit','500','--json','title'],text=True,capture_output=True,check=True)
import json
titles={x['title'] for x in json.loads(existing.stdout)}
for row in rows:
    title=f"[{row['ID']}] {row['TITLE']}"
    if title in titles:
        print('skip', title)
        continue
    labels=[x.strip() for x in row['LABELS'].split(',') if x.strip()]
    for label in labels:
        subprocess.run(['gh','label','create',label,'--repo',repo,'--force'],check=True,stdout=subprocess.DEVNULL)
    body=(f"## 阶段\n\n{row['PHASE']}\n\n"
          f"## 依赖\n\n{row['DEPENDS_ON'] or '无'}\n\n"
          f"## 验收条件\n\n- {row['ACCEPTANCE']}\n\n"
          "## 完成定义\n\n- [ ] 代码与契约已提交\n- [ ] 正常和失败路径测试通过\n"
          "- [ ] 安全边界已 Review\n- [ ] 文档和回滚说明已更新\n")
    cmd=['gh','issue','create','--repo',repo,'--title',title,'--body',body]
    for label in labels:
        cmd += ['--label',label]
    subprocess.run(cmd,check=True)
PY
