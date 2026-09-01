# v0.5 Acceptance Criteria

This document defines the narrow acceptance criteria for Janus `v0.5`.

The goal is not broader platform expansion. The goal is one workload-attribution experiment:

```text
LIVE WIRE EVIDENCE
        +
FLOW OWNERSHIP ATTRIBUTION
        ->
WORKLOAD-BOUND CRYPTOGRAPHIC EVIDENCE
```

## Definition of done

Given a policy requiring:

```text
X25519MLKEM768
```

Janus must demonstrate all of the following:

1. A Linux process establishes a real TLS 1.3 connection.
2. The existing `v0.4` verifier independently observes the negotiated key-exchange group from live wire evidence.
3. A separate attribution mechanism associates the exact observed TCP flow with its owning process.
4. Janus records PID plus executable name in the resulting evidence.
5. Janus records cgroup or equivalent workload-boundary metadata when available.
6. Two simultaneous attributed processes cannot be confused with one another.
7. Process termination or reuse cannot cause stale ownership to be treated as current attribution.
8. Missing, unavailable, or ambiguous ownership becomes `UNATTRIBUTED`, never guessed.
9. Linux CI proves the complete attribution path end to end.

## Release gate

`v0.5` is complete when Linux CI has executed the agreed workload-attribution proof surface successfully.

Required release evidence:

1. One live `COMPLIANT` wire observation with correct workload attribution.
2. One live `NON_COMPLIANT` wire observation with correct workload attribution.
3. One unavailable or ambiguous ownership case that yields `UNATTRIBUTED`.

Until those pass remotely on Linux, `v0.5` remains implementation-complete but release-pending.

## Minimal architecture

Keep the first slice intentionally small:

```text
Linux process
  -> opens TCP/TLS connection

Passive wire verifier
  -> observes packets
  -> reconstructs TCP stream
  -> derives negotiated key exchange

Attribution observer
  -> derives process / workload ownership for the same flow

Janus evidence
  -> merges wire posture and workload attribution
```

The attribution path must answer:

```text
Which workload owned the connection that Janus observed on the wire?
```

It must not guess ownership from timing or heuristics when the answer is ambiguous.

## Scope constraints

For `v0.5`, Janus does not need to simultaneously add:

- SPIFFE or workload identity rollout
- Kubernetes admission control
- CBOM or discovery expansion
- dashboard or UI redesign
- policy-language expansion
- AI feature growth

## Non-goals

The following do not satisfy `v0.5` by themselves:

- another parser feature
- another offline packet test
- another dashboard panel
- another AI assistant workflow
- a best-effort ownership guess

The following are explicitly out of scope for `v0.5` and belong to later milestones:

- service-mesh-wide deployment
- SPIFFE integration
- signed policy provenance chains
- CBOM and environment-wide discovery
- richer identity trust weighting

If the milestone does not bind live wire evidence to the owning workload of the observed connection, it is not complete.
