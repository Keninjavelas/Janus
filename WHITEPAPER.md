# Janus Whitepaper

## Thesis

Janus explores whether a crypto-agility control plane can do more than recommend algorithms. The central research question is whether one system can discover cryptographic posture, attribute it to workloads, assess migration urgency, derive required posture, verify actual negotiated behavior independently, and preserve trustworthy evidence across that loop.

## Result

As of Wednesday, August 12, 2026, Janus demonstrates an integrated research architecture with these layers:

1. Discovery and CBOM inventory
2. Workload attribution
3. Deterministic quantum-risk assessment
4. Policy derivation and validated bundle lifecycle
5. Enforcement-oriented verification paths
6. Passive wire verification
7. Audit integrity and migration planning

## What Janus Proves

- A required post-quantum TLS posture can be derived from policy.
- A real TLS 1.3 connection can be verified as compliant, non-compliant, or unverifiable.
- Passive wire evidence can identify negotiated `X25519` vs `X25519MLKEM768`.
- Linux source-side attribution can bind a specific observed flow to a specific local workload.
- Discovery inventory can turn cryptographic observations into a machine-readable CBOM.
- Risk can be prioritized deterministically and explained rather than guessed by opaque AI scoring.
- Migration success can be tied to observed evidence rather than configuration intent alone.
- An append-only audit hash chain can make record tampering detectable.

## What Janus Does Not Claim

- production-ready zero-trust enforcement across arbitrary infrastructure
- universal workload identity across all orchestration systems
- complete autonomous network discovery across an enterprise
- hardened PKI-backed signing infrastructure
- authoritative policy activation by AI

## Design Principles

- never guess security state
- separate protocol metadata from runtime capability
- separate cryptographic compliance from workload attribution
- fail closed on ambiguity
- treat AI as advisory only
- preserve provenance across discovery, decision, verification, and migration
