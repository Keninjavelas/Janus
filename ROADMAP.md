# Janus Roadmap

This roadmap freezes Janus around depth-first milestones. The goal is to avoid more disconnected features and instead strengthen the central thesis of the project.

## Milestones

| Version | Purpose |
|---------|---------|
| `v0.2` | Existing research prototype |
| `v0.3` | PQC enforcement plus negotiated-crypto verification |
| `v0.4` | Deployment-boundary cryptographic attestation |
| `v0.5` | Typed algorithm registry plus validated policy DSL |
| `v0.6` | Workload identity plus authenticated control and data planes |
| `v0.7` | Crypto discovery plus CBOM |
| `v0.8` | HNDL and data-lifetime risk engine |
| `v0.9` | Downgrade detection, signed audit chain, and migration modes |
| `v1.0` | Benchmarked, reproducible, documented research release |

## Current milestone state

As of August 11, 2026, `v0.4` is implementation-complete but release-pending.

The remaining gate is the Ubuntu live-capture CI lane that exercises the passive verifier against the three required outcomes:

1. `X25519MLKEM768` observed on the wire -> `COMPLIANT`
2. `X25519` observed on the wire while policy still requires `X25519MLKEM768` -> `NON_COMPLIANT`
3. Missing or unusable capture evidence -> `UNVERIFIED`

See [V04_ACCEPTANCE.md](C:\Users\aryan\OneDrive\Desktop\Janus\V04_ACCEPTANCE.md) for the frozen definition of done and release gate.

## Previous milestone: v0.3

The next turning point is simple:

> Janus must take one policy decision, enforce it on one genuine connection, and independently prove the cryptography that was actually negotiated.

That milestone should deliver:

1. A required posture decision such as `X25519MLKEM768`.
2. A real connection that either satisfies or violates that posture.
3. A verification path that classifies the connection as compliant or non-compliant.
4. A downgrade result that explicitly explains why a classical-only fallback failed policy.

See [V03_ACCEPTANCE.md](C:\Users\aryan\OneDrive\Desktop\Janus\V03_ACCEPTANCE.md) for the `v0.3` acceptance criteria and minimal slice architecture.

## Implementation order

1. Finish `v0.4` by treating the Ubuntu live-capture lane as the release authority.
2. Freeze `v0.4` once that lane passes.
3. Add the typed algorithm registry in `v0.5`.
4. Add policy compilation and validation.
5. Add identity and authenticated planes.
6. Add discovery and migration planning.

## Non-goals for the next sprint

- More dashboard polish
- More AI assistant surface area
- More observability-only features
- More infrastructure breadth without stronger cryptographic depth

## v0.4 theme

`v0.4` strengthens evidence rather than broadening features:

- move observation outside the direct TLS participant
- preserve one packet / reassembly / parser interpretation engine
- raise `observation_level` to `WIRE_OFFLINE` and `WIRE_LIVE`
- fail closed on missing or ambiguous packet evidence
- do not mix this milestone with eBPF, attribution, CBOM, identity expansion, or UI growth
