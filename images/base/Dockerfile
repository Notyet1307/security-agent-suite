# syntax=docker/dockerfile:1.7
ARG AGENT_COMPOSE_GUEST_IMAGE=chaitin/agent-compose-guest:v2609.1.0
FROM ${AGENT_COMPOSE_GUEST_IMAGE}

# Baseline image only. Add packages through a reviewed, digest-pinned build in M1.
LABEL org.opencontainers.image.title="security-agent-base" \
      org.opencontainers.image.description="Baseline guest image for Security Agent Suite"
