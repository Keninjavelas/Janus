# Makefile

# -------------------------------------------------
# Build & Development tasks for Janus
# -------------------------------------------------

BIN_DIR := bin
BIN := $(BIN_DIR)/pqc-engine
MAINPKG := ./cmd/pq-engine

.PHONY: all build run test test-core test-cache test-wire-live test-liboqs test-envoy test-integration test-benchmark benchmark lint docker clean

all: build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) $(MAINPKG)

run: build
	$(BIN)

test:
	$(MAKE) test-core

# Host-safe default test surface.
# This excludes packages that currently require:
# - liboqs system libraries
# - Envoy-specific compatibility work
# - integration-only infrastructure or build tags
# - separate cache-test execution on this Windows host
test-core:
	go test -v -cover -race ./api/proto/v1 ./api/proto/v1/api/proto/v1 ./cmd/pq-engine ./cmd/tls-verifier ./cmd/janus-wire-verifier ./internal/algorithms ./internal/api ./internal/audit ./internal/config ./internal/discovery ./internal/engine ./internal/fallback ./internal/metrics ./internal/migration ./internal/orchestrator ./internal/risk ./internal/server ./internal/tracing ./internal/verification

# Run cache regression tests separately.
# CI on Linux should be treated as the source of truth for this target.
test-cache:
	go test -v -cover ./internal/cache

# Run Linux-only live wire-capture tests explicitly.
test-wire-live:
	go test -tags=livecapture -v ./internal/verification -run TestLiveWireVerification

# Run liboqs-backed packages explicitly.
test-liboqs:
	go test -tags=liboqs -v ./internal/crypto

# Run Envoy-specific packages explicitly.
test-envoy:
	go test -tags=envoy -v ./internal/envoy

# Run integration tests explicitly.
test-integration:
	go test -tags=integration -v ./pqc-zta-engine/test/integration

test-benchmark:
	go test -run=^$$ -bench=. ./pqc-zta-engine/test/benchmark

benchmark:
	go test -run=^$$ -bench=. ./internal/benchmarks ./pqc-zta-engine/test/benchmark

lint:
	golangci-lint run ./...

docker:
	docker build -t $${IMAGE:-pqc-zta-engine:latest} .

clean:
	rm -rf $(BIN_DIR)
