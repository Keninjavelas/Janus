# v0.3 Acceptance Criteria

This document defines the narrow acceptance criteria for Janus `v0.3`.

The goal is not broader platform polish. The goal is one closed-loop cryptographic control-plane experiment:

```text
DECIDE -> ENFORCE -> VERIFY
```

## Definition of done

Given a policy requiring:

```text
X25519MLKEM768
```

Janus must demonstrate all of the following:

1. The policy evaluates successfully.
2. The requirement reaches the component responsible for establishing TLS.
3. A real TLS or mTLS connection is established.
4. The negotiated key exchange is observed independently of Janus's policy decision.
5. The observed algorithm equals the required algorithm.
6. Janus reports `COMPLIANT`.
7. A deliberately classical-only connection is attempted.
8. The observed algorithm differs from the required algorithm.
9. Janus reports `NON-COMPLIANT` or prevents the connection.
10. Automated integration evidence covers both the compliant and downgrade cases.

## Release gate

`v0.3` is complete when Linux CI has executed the agreed proof surface successfully.

Required release evidence:

1. `make test`
2. `make test-cache`
3. `go test ./internal/verification -v`
4. `go test ./cmd/tls-verifier -v`
5. `npm run build` in `web/`

Until those pass remotely, `v0.3` remains implementation-complete but release-pending.

## Minimal architecture

Keep the first vertical slice intentionally small:

```text
Client
  -> PQ-capable TLS endpoint or proxy
  -> Test service

Context
  -> Janus policy engine
  -> required posture
  -> TLS configuration layer

TLS connection
  -> independent verifier
  -> observed negotiated posture
```

The verifier must answer:

```text
What actually happened on the connection?
```

It must not simply restate what Janus selected.

## Scope constraints

For `v0.3`, Janus does not need to simultaneously add:

- SPIFFE or workload identity
- OIDC
- TPM attestation
- signed CBOMs
- policy provenance chains
- multiple service meshes
- multiple PQC stacks

Trusted test inputs are acceptable for this milestone if the trust boundary is documented clearly.

## Recommended first slice

Start with exactly one hybrid posture:

```text
X25519MLKEM768
```

Then make one end-to-end path impeccable:

- one policy
- one enforcement mechanism
- one verifier
- one downgrade scenario
- one integration test path

Generalize only after that slice works.

## Non-goals

The following do not satisfy `v0.3` by themselves:

- another advisory header
- another dashboard view
- another simulator path
- another metrics panel
- another AI assistant feature

The following are explicitly out of scope for `v0.3` and belong to later milestones:

- wire-level packet capture
- eBPF-based attestation
- deployment-boundary verifier rollout
- service-mesh-wide enforcement
- workload identity expansion
- CBOM and discovery work

If the milestone does not cause and prove a real negotiated cryptographic posture, it is not complete.
