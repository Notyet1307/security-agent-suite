SHELL := /usr/bin/env bash

-include .env
export

BINARY_DIR := bin
GO ?= go

.PHONY: help fmt test race vet build run smoke verify clean package

help:
	@printf '%s\n' \
	  'make fmt      - format Go sources' \
	  'make test     - run unit and integration tests' \
	  'make race     - run tests with the race detector' \
	  'make vet      - run go vet' \
	  'make build    - build sasd and sasctl' \
	  'make run      - run the API (executor is read from .env)' \
	  'make smoke    - run an HTTP smoke test' \
	  'make verify   - fmt check, vet, tests, build and contract checks' \
	  'make package  - create dist archives'

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o $(BINARY_DIR)/sasd ./cmd/sasd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o $(BINARY_DIR)/sasctl ./cmd/sasctl

run:
	$(GO) run ./cmd/sasd

smoke:
	./scripts/smoke.sh

verify:
	./scripts/verify.sh

clean:
	rm -rf $(BINARY_DIR) dist coverage.txt var

package: verify
	./scripts/package.sh
