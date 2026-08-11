# Threat Model

## Purpose

This document captures the current security boundaries for Janus as a post-quantum crypto-agility research platform. It is intentionally explicit about what the repository does today, what it assumes, and where the highest-risk gaps remain.

## Assets

- Policy definitions in `configs/policy.yaml`
- Decision responses returned over gRPC and HTTP
- Audit and application logs
- Management APIs for policy retrieval and update
- Web UI state and user-authored policy drafts
- Algorithm selection logic and fallback behavior
- Experimental PQC operations performed through `liboqs-go`

## Trust boundaries

1. Client to Janus API
2. Web UI to REST management endpoints
3. Envoy and ext_authz integration to Janus gRPC
4. Policy file on disk to in-memory loaded policy
5. AI-assisted draft generation to human-reviewed policy editing
6. Janus decision output to any downstream system that attempts enforcement

## Threat actors

- Malicious client sending crafted evaluation requests
- Compromised workload trying to obtain weaker cryptographic posture
- Malicious or mistaken policy author
- Network attacker attempting downgrade or replay
- Supply-chain attacker targeting dependencies or build artifacts
- Compromised AI provider or malformed model output
- Operator error during policy updates or rollout

## Security assumptions

- The host or cluster running Janus is trusted enough to load policy and serve decisions.
- Downstream systems treat Janus output as advisory unless they implement explicit enforcement.
- Humans review AI-generated drafts before a policy is applied.
- Request attributes such as `region`, `risk`, and `device_type` are demo inputs unless backed by stronger identity or posture sources.

## Current limitations

### No independent cryptographic verification

The repository does not yet independently verify the algorithm negotiated on the wire. A returned recommendation is not proof of TLS or mTLS enforcement.

### Simplified attribute provenance

Several request inputs are accepted directly from callers. That is useful for demos, but it is weaker than workload identity, attestation, infrastructure metadata, or trusted risk-engine input.

### Management-plane hardening is incomplete

Policy update endpoints are present, but signed policy bundles, rollout simulation, approval workflows, and tamper-evident audit trails are not yet implemented.

### Cache invalidation is weak

Decision caching is time-based. It is not yet tied to revocation, policy versioning, or trusted-attribute version changes.

### AI output must not be authoritative

The AI path is allowed to draft candidate YAML only. It must not become a direct authority for weakening cryptographic posture or bypassing deterministic safeguards.

## Failure modes to treat as high priority

- Classical-only downgrade when hybrid PQC is required
- Acceptance of unknown or malformed algorithm identifiers
- Stale cached decisions surviving important policy or posture changes
- Unauthenticated or weakly authenticated policy management
- Silent failure in Envoy integration causing false confidence
- Build or dependency compromise in the Go, Node, Wasm, or C toolchain

## Desired invariants

- Unknown algorithm identifiers must fail closed.
- Stronger policy requirements must never select weaker cryptography.
- AI-generated policy must require human review before application.
- Policy changes should be attributable, reviewable, and rollback-safe.
- Hybrid-required workloads must never silently return classical-only posture.

## Out of scope for the current repository

- Full enterprise identity federation design
- Complete service mesh policy administration
- Verified eBPF or packet-capture-based downgrade attestation
- Full supply-chain attestation and reproducible build pipeline

## Near-term hardening work

1. Add signed policy bundles and versioned rollout metadata.
2. Add semantic validation and invariant checking for policy changes.
3. Replace demo attributes with stronger identity and posture sources.
4. Add revocation-driven cache invalidation.
5. Add independent protocol-verification telemetry.
6. Expand adversarial testing, fuzzing, and downgrade simulation.

## Related plans

- [TESTING.md](C:\Users\aryan\OneDrive\Desktop\Janus\TESTING.md)
- [ROADMAP.md](C:\Users\aryan\OneDrive\Desktop\Janus\ROADMAP.md)
- [security-tests/README.md](C:\Users\aryan\OneDrive\Desktop\Janus\security-tests\README.md)
