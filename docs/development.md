# Development

## Requirements
Go 1.23+; Docker is optional for Mock mode.

## Verify

```bash
make verify
make race
make smoke
```

## Run Mock

```bash
cp .env.example .env
make run
```

## Build

```bash
make build
```

## Runtime integration
Set `SAS_EXECUTOR=agentcompose-cli`, configure agent-compose and OctoBus hosts, then run `sasctl doctor` before starting the service. Do not treat configuration as live acceptance evidence.
