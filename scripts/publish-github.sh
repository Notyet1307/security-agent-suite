#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OWNER="${GITHUB_OWNER:-Notyet1307}"
REPO="${GITHUB_REPO:-security-agent-suite}"
VISIBILITY="${GITHUB_VISIBILITY:-public}"
command -v gh >/dev/null 2>&1 || { echo 'GitHub CLI (gh) is required.' >&2; exit 1; }
gh auth status >/dev/null

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || git init -b main
if ! git config user.name >/dev/null; then git config user.name "$OWNER"; fi
if ! git config user.email >/dev/null; then git config user.email "notyet.1307@gmail.com"; fi
git add .
if ! git diff --cached --quiet; then
  git commit -m 'feat: bootstrap security agent suite'
fi

if ! gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  gh repo create "$OWNER/$REPO" --"$VISIBILITY" \
    --description 'Go control plane and agent-compose delivery scaffold for five evidence-driven cybersecurity agents' \
    --source . --remote origin --push
else
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$OWNER/$REPO.git"
  git push -u origin main
fi

gh repo edit "$OWNER/$REPO" --enable-issues --enable-wiki=false \
  --add-topic golang --add-topic ai-agents --add-topic cybersecurity \
  --add-topic agent-compose --add-topic octobus

echo "published: https://github.com/$OWNER/$REPO"
