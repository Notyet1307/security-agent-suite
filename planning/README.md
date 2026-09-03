# Planning

`backlog.tsv` is the implementation plan in machine-readable form. It contains 49 focused issues across M0-M9 with dependencies and acceptance criteria.

After publishing the repository and installing/authenticating GitHub CLI:

```bash
./scripts/create-roadmap-issues.sh
```

The script is idempotent by issue title. Review repository labels and assignees before running it against a production project board.
