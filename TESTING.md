# Testing Guide

Janus now separates test surfaces by dependency profile. The default target should validate the host-safe core of the project without requiring liboqs, Envoy-specific APIs, or integration infrastructure.

GitHub Actions on Linux is the intended authoritative execution environment for the default core test surface and the cache regression test once the workflow has been pushed and run. Local Windows behavior can still be useful for development, but CI should become the source of truth for pass/fail.

The negotiated-group verifier and `ConnectionState.CurveID` observation path require Go `1.25+`.
The live wire-capture slice additionally requires Linux, `libpcap`, and capture privileges, and is release-authoritative only in Ubuntu CI.

## Targets

- `make test`
  Runs the host-safe default surface.
- `make test-core`
  Same as `make test`; pure-Go core packages only.
- `make test-cache`
  Runs the cache regression tests separately.
- `make test-wire-live`
  Runs the Linux-only live wire-capture proof surface with the `livecapture` build tag.
- `make test-liboqs`
  Runs packages that require `liboqs` and the `liboqs` build tag.
- `make test-envoy`
  Runs Envoy-specific packages with the `envoy` build tag.
- `make test-integration`
  Runs the integration suite with the `integration` build tag.
- `make test-benchmark`
  Runs benchmark targets explicitly.

## Classification

### Category A: should work on a normal development machine

- `api/proto/v1`
- `cmd/pq-engine`
- `internal/api`
- `internal/config`
- `internal/engine`
- `internal/fallback`
- `internal/metrics`
- `internal/orchestrator`
- `internal/server`
- `internal/tracing`

### Separate explicit target

- `pqc-zta-engine/test/benchmark`
  Run through `make test-benchmark`.

### Category B: requires extra system dependencies or build tags

- `internal/crypto`
  Requires `liboqs` and the `liboqs` build tag.
- `internal/envoy`
  Requires the `envoy` build tag and ongoing API compatibility work.

### Category C: requires integration infrastructure or explicit opt-in

- `pqc-zta-engine/test/integration`
  Runs only with the `integration` build tag.
- `internal/verification` live wire tests
  Run only with the `livecapture` build tag on Linux with `libpcap` and capture privileges.

## Current note on cache tests

A cache regression test has been added, but execution remains unverified on this Windows host because Windows Defender blocked the generated test binary during `go test`.

That should be reported precisely rather than treated as a pass. Linux CI should become the source of truth for `make test-cache` after the first successful remote run.

## Current note on live wire tests

The `v0.4` live wire-attestation slice is implemented, but its authoritative release evidence is the Ubuntu `libpcap` lane in [`.github/workflows/ci.yml`](C:\Users\aryan\OneDrive\Desktop\Janus\.github\workflows\ci.yml).

Local Windows runs can still validate the offline parser and offline PCAP reconstruction, but they are not the source of truth for:

- `livecapture` build tags
- passive interface capture
- Linux loopback semantics
- privileged packet observation
- the three-process live verifier harness

As of August 11, 2026, `v0.4` should be treated as implementation-complete but release-pending until that Ubuntu lane executes successfully.
