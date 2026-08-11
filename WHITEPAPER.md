# Janus - Research Platform Brief

**Version:** 1.1  
**Date:** 2026-08-07

## Executive summary

Janus is a cloud-native research platform for adaptive post-quantum cryptographic policy. It evaluates contextual inputs and returns a recommended cryptographic posture, exposes those decisions over service APIs, and provides a dashboard for simulation, review, and observability.

The central idea is crypto agility, not a claim that the repository already delivers full wire-level zero-trust enforcement. The current codebase demonstrates policy selection, control-plane plumbing, and PQC experimentation. The next milestone is to connect those decisions to protocol enforcement and independently verify the negotiated result.

## What Janus is today

- A policy decision engine with hot-reloadable YAML rules
- A gRPC and REST service for evaluation and management
- A demo UI for simulation, metrics, and policy editing
- An Envoy integration path that can propagate recommendations downstream
- A liboqs-backed experimentation layer for `ML-KEM-*` operations

## What Janus is not yet

- A complete policy administrator and policy enforcement point
- Proof that `X-PQC-Recommended` changed the negotiated handshake
- A production-hardened PQC enforcement stack
- A signed and tamper-evident policy distribution system
- A cryptographic inventory or CBOM platform

## Current architecture

```text
Client
  -> Envoy/ext_authz
  -> Janus gRPC decision engine
  -> decision payload
  -> downstream advisory handling
```

This is useful for experimentation, but it is not enough to claim verified post-quantum enforcement.

## Target architecture

```text
Identity, posture, sensitivity, lifetime, risk, capability
  -> Janus policy engine
  -> signed policy decision
  -> policy administrator
  -> TLS or mTLS enforcement layer
  -> negotiated cryptographic posture
  -> independent verification
  -> downgrade detection, audit, migration tracking
```

## Security boundaries

### Advisory versus enforcement

The current Wasm path injects advisory metadata. That metadata can help downstream systems reason about policy intent, but it does not itself prove cryptographic negotiation.

### AI assistance

The AI feature is intentionally limited to drafting YAML. Human review in the policy editor is required before a policy is applied.

### Standards naming

This repository now uses standardized names such as `ML-KEM-768`, `ML-DSA-65`, and `X25519MLKEM768` in public-facing docs and examples. Where the current `liboqs-go` binding still expects legacy identifiers internally, Janus translates them in code.

## Recommended engineering priorities

1. Close `v0.3` with authoritative Linux CI evidence for the enforcement and verification slice.
2. Move from direct subprocess TLS observation to deployment-boundary attestation in `v0.4`.
3. Sign and version policies, then simulate and review before rollout.
4. Replace simplified attributes with stronger identity and posture sources.
5. Add cryptographic discovery, CBOM generation, and migration planning.
6. Strengthen cache invalidation and failure semantics.

## Evaluation plan

Strong future evaluation should answer:

- What overhead does adaptive cryptographic policy introduce?
- Can Janus detect and block downgrade from hybrid to classical modes?
- How quickly can policy changes respond to algorithm deprecation?
- How accurately can Janus identify high-priority migration targets?
- Which compatibility and latency tradeoffs appear under different postures?

## Operational status

Janus should currently be presented as a production-oriented research platform and reference implementation, not as a finished production system.

## Related documents

- [README.md](C:\Users\aryan\OneDrive\Desktop\Janus\README.md)
- [THREAT_MODEL.md](C:\Users\aryan\OneDrive\Desktop\Janus\THREAT_MODEL.md)
