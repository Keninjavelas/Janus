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

## Local & Linux Container Evidence

- `npm run build` passed (React SPA assets compiled to `web/dist/`)
- `go test ./internal/cache -v` passed
- `go test ./internal/verification/... -v` passed
- `go test ./cmd/tls-verifier -v` compiled cleanly
- `go test ./cmd/janus-wire-verifier -v` compiled cleanly
- Targeted package tests for algorithms, config, audit, discovery, risk, migration, and API passed (100%)
- Linux Livecapture Compile Gate (`go test -tags=livecapture ./internal/verification -run '^$'`): `PASS`
- Linux Livecapture Run 1 (`go test -count=1 -tags=livecapture ./internal/verification -run TestLiveWireVerification -v`): `PASS` (6/6 gates)
- Linux Livecapture Run 2 (`go test -count=1 -tags=livecapture ./internal/verification -run TestLiveWireVerification -v`): `PASS` (6/6 gates, uncached)

## Current Status

```text
IMPLEMENTATION
COMPLETE

LOCAL HOST-SAFE VALIDATION
PASS

LINUX LIVECAPTURE CONTAINER ACCEPTANCE
PASS (2/2 CONSECUTIVE PASSES)

RELEASE STATUS
ACCEPTED
```

## Attribution Invariant

For `WIRE_LIVE` target verification, workload attribution refers to the local process owning the configured target/server endpoint, not whichever endpoint transmitted the first observed packet. Exact connected socket attribution is preferred (`CONNECTED_SOCKET`), falling back transparently to the target endpoint's listening socket (`LISTEN_SOCKET`) when ephemeral connections terminate quickly.

## Acceptance Rule

`v1.0` is accepted as research-release-ready with full cryptographic live-wire attestation and dual-basis process attribution verified across all milestones.
