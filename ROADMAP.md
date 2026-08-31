# Janus Roadmap

This roadmap is now primarily historical. The depth-first milestone sequence is:

- `v0.3`: decision, direct verification, fail-closed enforcement
- `v0.4`: passive wire attestation
- `v0.5`: workload attribution
- `v0.6`: algorithm registry and policy bundle integrity
- `v0.7`: discovery and CBOM
- `v0.8`: deterministic quantum risk assessment
- `v0.9`: migration planning and audit integrity
- `v1.0`: integrated research release

## Historical Progression

```text
v0.3
What posture is required,
and should traffic be allowed?

v0.4
What cryptography actually
crossed the wire?

v0.5
Which local workload owned
that exact observed connection?

v1.0
What exists, who owns it,
how risky is it, what should change,
and can the result be verified?
```

## Current State

As of Wednesday, August 12, 2026:

- implementation is integrated through the `v1.0` research-release surface
- host-safe validation passed locally
- frontend build passed locally
- Linux live-capture and procfs-specific CI remain authoritative before calling the release fully accepted

## Near-Term Non-Goals

- production-readiness claims
- automatic infrastructure mutation
- Kubernetes-native identity expansion inside this release
- broader AI features or autonomous policy activation
- broad UI redesign work
