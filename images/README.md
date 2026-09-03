# Agent images

Do not build five unrelated images. Use three image families:

| Image | Agents | Purpose |
| --- | --- | --- |
| `security-agent-base` | event, compliance, report | minimal guest runtime and CA/timezone support |
| `security-agent-traffic` | traffic | offline packet-analysis clients and controlled wrappers |
| `security-agent-attack` | attack-path | separately reviewed low-impact validation clients |

The current repository intentionally does not install third-party scanners in these Dockerfiles. Exact package versions, redistribution rights and the base guest image must be frozen during M1/M6/M7. Build tools as OctoBus services where possible, so the Agent image only contains clients and cannot execute unrestricted local tooling.
