#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${SKIP_VERIFY:-0}" != "1" ]]; then
  ./scripts/verify.sh
fi

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
NAME="security-agent-suite-${VERSION}"
mkdir -p dist
rm -f "dist/${NAME}.tar.gz" "dist/${NAME}.zip" "dist/${NAME}.sha256"

tar --exclude='./.git' --exclude='./dist' --exclude='./bin' --exclude='./var' \
  --exclude='./coverage.txt' --exclude='./.env' --exclude='*/__pycache__' \
  --transform "s#^\.#${NAME}#" -czf "dist/${NAME}.tar.gz" .
python3 - "$ROOT" "$NAME" <<'PY'
from pathlib import Path
import sys, zipfile

root = Path(sys.argv[1])
name = sys.argv[2]
excluded_parts = {'.git', 'dist', 'bin', 'var', '__pycache__'}
excluded_files = {'coverage.txt', '.env'}
with zipfile.ZipFile(root / 'dist' / f'{name}.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    for p in sorted(root.rglob('*')):
        rel = p.relative_to(root)
        if p.is_dir() or p.name in excluded_files or any(part in excluded_parts for part in rel.parts):
            continue
        z.write(p, Path(name) / rel)
PY
sha256sum "dist/${NAME}.tar.gz" "dist/${NAME}.zip" > "dist/${NAME}.sha256"
echo "created dist/${NAME}.tar.gz and dist/${NAME}.zip"
