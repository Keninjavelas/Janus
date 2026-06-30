# Makefile

# -------------------------------------------------
# Build & Development tasks for PQC‑ZTA Engine
# -------------------------------------------------

# Binary output directory
BIN_DIR := bin
BIN := $(BIN_DIR)/pqc-engine

# Go source entry point (assumes cmd/main.go exists)
MAINPkg := ./cmd

.PHONY: all build run test lint docker clean

all: build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) $(MAINPkg)

run: build
	$(BIN)

# Run unit & integration tests
# -cover generates coverage data
# -race enables the race detector
# Adjust packages as needed.

test:
	go test -v -cover -race ./... 

# Lint using golangci-lint (install with `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)
lint:
	golangci-lint run ./... 

# Build the multi‑stage Docker image (requires Docker daemon)
# Image name is configurable via the IMAGE env var.
# Example: make docker IMAGE=myrepo/pqc-zta-engine:latest

docker:
	docker build -t $${IMAGE:-pqc-zta-engine:latest} .

clean:
	rm -rf $(BIN_DIR)
