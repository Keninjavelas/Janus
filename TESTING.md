# Testing

Janus uses a split test strategy so host-safe logic, Linux-specific proof surfaces, and optional research dependencies do not blur together.

## Host-Safe Commands

- `make test`
- `go test ./internal/cache -v`
- `go test ./internal/verification/... -v`
- `go test ./cmd/tls-verifier -v`
- `go test ./cmd/janus-wire-verifier -v`
- `npm run build`

These commands validate:

- algorithm registry behavior
- policy validation and canonical bundle compilation
- audit-chain verification
- discovery inventory and direct TLS scanning
- deterministic risk assessment
- migration verification logic
- direct TLS verification
- passive wire parsing and offline PCAP reconstruction
- workload attribution unit surfaces
- frontend build integrity

## Linux-Authoritative Commands

- `make test-wire-live`
- Linux CI workflow lanes under [`.github/workflows/ci.yml`](C:/Users/aryan/OneDrive/Desktop/Janus/.github/workflows/ci.yml)

These remain authoritative for:

- live packet capture
- Linux procfs behavior in CI
- integrated workload attribution + passive wire observation under Linux-only conditions

## Benchmarks

- `make benchmark`

The benchmark suite covers the v1.0 research surface where practical:

- policy decision latency
- wire parser throughput
- offline PCAP inspection throughput
- discovery inventory observation overhead
- risk evaluation latency
- migration verification latency

Benchmark results should always be reported with environment details and should never be fabricated.

## Windows Notes

On Wednesday, August 12, 2026, the Windows host used for local validation showed two environment-specific issues:

- Windows Defender blocked Go's `covdata.exe`, which caused `make test` to fail when coverage instrumentation was enabled
- some successful `go test` runs emitted a temporary-file cleanup warning (`unlinkat ... test.exe`) after the package had already passed

Those are host-environment issues, not demonstrated logic failures in Janus. Linux CI remains the source of truth for coverage-enabled and privileged lanes.
