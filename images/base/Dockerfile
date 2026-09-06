# syntax=docker/dockerfile:1.7
ARG AGENT_COMPOSE_GUEST_IMAGE=docker.io/chaitin/agent-compose-guest@sha256:f1ebca0021d1de4ebd02d4da4117d7651e09b5a6db35be20092f03cc26a586b9
FROM ${AGENT_COMPOSE_GUEST_IMAGE}

# Baseline image only. Add packages through a reviewed, digest-pinned build.
LABEL org.opencontainers.image.title="security-agent-base" \
      org.opencontainers.image.description="Baseline guest image for Security Agent Suite"
