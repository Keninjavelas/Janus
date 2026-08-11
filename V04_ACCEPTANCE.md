# v0.4 Acceptance Criteria

This document defines the narrow acceptance criteria for Janus `v0.4`.

The goal is not broader platform engineering. The goal is one deployment-boundary cryptographic attestation experiment:

```text
REAL TLS CONNECTION
        ->
PASSIVE PACKET OBSERVATION
        ->
TCP RECONSTRUCTION
        ->
TLS 1.3 SERVERHELLO PARSING
        ->
WIRE_LIVE EVIDENCE
```

## Definition of done

Given a policy requiring:

```text
X25519MLKEM768
```

Janus must demonstrate all of the following:

1. A real TLS 1.3 connection is established between separate client and server processes.
2. A third verifier process passively observes packets from a Linux network interface.
3. The verifier does not initiate TLS, terminate TLS, query either endpoint for `CurveID`, or receive the negotiated group over IPC.
4. The verifier reuses the same packet, reassembly, and TLS parsing pipeline used for offline PCAP inspection.
5. The verifier extracts the TLS 1.3 `ServerHello` `key_share` group from wire evidence.
6. A hybrid connection selecting `X25519MLKEM768` is reported as `COMPLIANT`.
7. A classical-only connection selecting `X25519` is reported as `NON_COMPLIANT`.
8. Missing, incomplete, or ambiguous capture evidence is reported as `UNVERIFIED`.
9. Ambiguous TCP evidence, including conflicting overlap, fails closed rather than being guessed.
10. The emitted evidence records `WIRE_LIVE` provenance plus capture interface and flow metadata.

## Release gate

`v0.4` is complete when the Linux live-capture proof surface executes successfully in CI.

Required release evidence:

1. `go test -tags=livecapture ./internal/verification -run TestLiveWireVerification -v`
2. `go test -tags=livecapture ./cmd/janus-wire-verifier -v`

Until those pass remotely on Ubuntu with `libpcap`, `v0.4` remains implementation-complete but release-pending.

## Minimal architecture

Keep the first live slice intentionally small:

```text
Client process
  -> real TLS 1.3 traffic
  -> Server process

Passive verifier process
  -> Linux interface capture
  -> packet / flow layer
  -> TCP reconstruction
  -> TLS ServerHello parser
  -> WIRE_LIVE evidence
```

The verifier must answer:

```text
What key-exchange group crossed the network boundary?
```

It must derive that answer exclusively from observed packet evidence.

## Scope constraints

For `v0.4`, Janus does not need to simultaneously add:

- eBPF-based attribution
- Kubernetes rollout
- workload identity correlation
- richer TLS parsing beyond the current negotiated group proof
- UI expansion
- service mesh integration
- packet loss metrics

## Non-goals

The following do not satisfy `v0.4` by themselves:

- another offline parser feature
- another dashboard view
- another observability panel
- another AI assistant feature
- a compile-only live-capture path without executed proof

The following are explicitly out of scope for `v0.4` and belong to later milestones:

- `EVIDENCE_CONFLICT`
- PID or container attribution
- pod or workload identity mapping
- eBPF probes
- CBOM and discovery work
- signed policy provenance chains

If the milestone does not prove negotiated cryptographic posture from passive live packet observation, it is not complete.
