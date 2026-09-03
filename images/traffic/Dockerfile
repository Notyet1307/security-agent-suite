# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=security-agent-base:local
FROM ${BASE_IMAGE}

# Traffic tools should normally run behind OctoBus services. Any local parser
# added here must be pinned, licensed, sandboxed and covered by fixtures.
LABEL org.opencontainers.image.title="security-agent-traffic"
