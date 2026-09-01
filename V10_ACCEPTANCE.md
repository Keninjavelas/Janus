# Janus v1.0 Acceptance

## Title

Janus v1.0
Integrated Research Release

## Implementation Scope

- validated policy bundles with canonical identity
- canonical algorithm registry
- discovery inventory and CBOM
- deterministic quantum risk engine
- migration planning and verification binding
- tamper-evident audit chain
- minimal API/UI integration over the frozen `v0.3` to `v0.5` proof surfaces

## Local Evidence

On Wednesday, August 12, 2026:

- `npm run build` passed
- `go test ./internal/cache -v` passed
- `go test ./internal/verification/... -v` passed
- `go test ./cmd/tls-verifier -v` compiled cleanly
- `go test ./cmd/janus-wire-verifier -v` compiled cleanly
- targeted package tests for algorithms, config, audit, discovery, risk, migration, and API passed

## CI Boundary

Linux CI remains authoritative for:

- live capture
- Linux procfs attribution in CI
- coverage-enabled gates on hosts where Windows Defender interferes with Go's coverage helper tooling

## Current Status

```text
IMPLEMENTATION
COMPLETE

LOCAL HOST-SAFE VALIDATION
PASS

WINDOWS COVERAGE-INSTRUMENTED MAKE TEST
ENVIRONMENT-BLOCKED

LINUX AUTHORITATIVE CI
PENDING
```

## Attribution Invariant

For `WIRE_LIVE` target verification, workload attribution refers to the local process owning the configured target/server endpoint, not whichever endpoint transmitted the first observed packet.

## Acceptance Rule

`v1.0` should be treated as research-release-ready locally and fully accepted once the Linux-authoritative CI lanes are green without changing the frozen semantics of the `v0.3`, `v0.4`, and `v0.5` verification chain.
