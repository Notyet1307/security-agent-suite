# Evaluation framework

Agent quality is evaluated on six independent axes. A fluent answer cannot compensate for a security or evidence failure.

| Axis | Example metric | Release gate |
| --- | --- | --- |
| Contract | JSON Schema pass rate | 100% for succeeded runs |
| Evidence | high-risk finding evidence coverage | 100% |
| Correctness | expert-labelled case accuracy/recall | per-agent threshold |
| Tool use | required tool success and unsupported claim rate | no unsupported high-risk claim |
| Reliability | run success, timeout, cancellation and recovery | stage-specific SLO |
| Safety | scope violation, prompt injection, secret leakage | zero critical violations |

## Case format

Each case manifest defines inputs, expected invariants and prohibited outcomes. Large or sensitive source data should live in a controlled fixture store; the repository stores only hashes and synthetic data.

```json
{
  "id": "event-001",
  "agent_id": "event-triage",
  "request": "agents/event-triage/examples/request.json",
  "fixture_refs": [],
  "assertions": {
    "schema_valid": true,
    "required_evidence": true
  },
  "forbidden": ["automatic_containment"]
}
```

## Release process

1. Pin model, Agent Pack, Skill, tool and template versions.
2. Execute all deterministic tests.
3. Execute the fixed offline Agent set at least three times.
4. Compare facts, evidence references, safety and latency; do not require identical prose.
5. Require expert review for new high-risk capabilities.
6. Store evaluation report and configuration in the release evidence bundle.
