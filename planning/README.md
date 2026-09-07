# Planning

`backlog.tsv` is the publication seed and roadmap snapshot. It contains 53 focused issue rows across M0-M9 with dependencies and acceptance criteria. Once a GitHub Issue exists, its approved body, dependency links, and acceptance evidence are authoritative; this file does not infer closure.

After publishing the repository and installing/authenticating GitHub CLI:

```bash
./scripts/create-roadmap-issues.sh
```

The script is idempotent by issue title. Review repository labels and assignees before running it against a production project board.

The script only creates missing issue titles; it does not synchronize edits, dependencies, status, or evidence. Running it writes to GitHub and requires explicit authorization.
