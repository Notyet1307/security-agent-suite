# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=security-agent-base:local
FROM ${BASE_IMAGE}

# Do not add generic exploit frameworks or shells by default. Only reviewed
# clients for approved validation templates belong in this image.
LABEL org.opencontainers.image.title="security-agent-attack"
