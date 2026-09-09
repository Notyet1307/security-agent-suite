# Context

## Product
Security Agent Suite is a Go control plane that exposes five independently callable cybersecurity agents.

## Terms
- **Control plane**: API, CLI, policy, run state, persistence, audit, and metrics.
- **Agent**: one catalogued capability with a versioned prompt, skills, and output contract.
- **Evidence**: immutable, identified input or tool output supporting a result.
- **Active validation**: high-risk verification requiring authorization scope and explicit approval.
- **Mock**: deterministic offline executor; its output is not a real security conclusion.

## Boundaries
Inputs and tool outputs are untrusted. High-risk findings require evidence identifiers. Runtime dependencies remain optional for Mock development; unavailable required integrations are reported fail-closed.
