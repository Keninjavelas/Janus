# Janus

Janus is an experimental post-quantum crypto-agility control plane. It discovers cryptographic exposure, attributes observed connections to workloads, assesses quantum migration risk, derives required posture, verifies negotiated TLS behavior independently, fails closed on non-compliant or unverifiable cryptographic state, and produces evidence-backed migration plans.

Janus is a research platform. It is not production-ready.

As of Wednesday, August 12, 2026, the repository is strongest as a reproducible research stack across five frozen milestones:

- `v0.3`: posture decision, direct TLS verification, fail-closed application gating
- `v0.4`: passive wire-level TLS attestation with TCP reconstruction
- `v0.5`: Linux workload attribution bound to the same live wire evidence
- `v0.6-v0.9`: discovery/CBOM, deterministic quantum risk, policy bundle integrity, audit chain, and migration planning
- `v1.0`: integrated research-release surface with backend/API/UI plumbing and benchmark entry points

## Proven

- Policy-driven posture decisions over gRPC and HTTP
- Direct TLS 1.3 verification with `COMPLIANT`, `NON_COMPLIANT`, and `UNVERIFIED`
- Fail-closed traffic gating for non-compliant or unverifiable crypto state
- Passive TLS 1.3 `ServerHello` parsing from raw bytes and offline PCAPs
- Live wire evidence classification for `X25519` and `X25519MLKEM768`
- Linux procfs attribution from TCP 4-tuple to workload with PID, executable, socket inode, and process start time
- Independent crypto and attribution verdicts on the same evidence record
- Canonical algorithm registry with runtime-support boundaries separated from protocol metadata
- Validated, versioned policy bundles with canonical hash and draft-to-activate lifecycle
- Tamper-evident append-only audit log with hash-chain verification
- Cryptographic discovery inventory and JSON CBOM generation
- Deterministic quantum/HNDL-style risk assessment with explainable reasons
- Migration planning that requires verification evidence before a migration can be marked verified
- Minimal dashboard support for exposure, assets, workload detail, policy bundle metadata, and migration state

## Experimental

- Discovery currently combines direct TLS scanning and verification-evidence ingestion rather than a broad autonomous crawler
- Linux live capture and procfs attribution remain the authoritative environment-specific proof surfaces
- Policy signatures are lightweight research metadata rather than a hardened PKI-backed signing system
- Migration planning is a control-plane plan and verification loop, not automatic production mutation
- AI Policy Copilot remains draft-only and intentionally non-authoritative

## Future Work

- Kubernetes and container-native workload identity beyond local procfs attribution
- Richer endpoint-to-wire conflict detection and multi-observer reconciliation
- Broader non-TLS cryptographic discovery
- More extensive benchmark datasets and Linux CI benchmark capture
- Additional signed release artifacts and supply-chain automation beyond the current practical controls

## Runtime Boundaries

- Go runtime baseline: `1.25+`
- Active TLS runtime key-exchange scope: `X25519`, `X25519MLKEM768`
- The registry may describe algorithms such as `ML-KEM-1024` and `ML-DSA-87` without claiming Go TLS can negotiate them directly

## Quickstart

```powershell
cd C:\Users\aryan\OneDrive\Desktop\Janus
$env:OPENAI_API_KEY="sk-..."  # optional, only for draft policy generation
.\run_all.ps1
```

Backend services:

- HTTP API: `http://localhost:8080`
- gRPC API: `localhost:50051`
- React UI: `http://localhost:5173`

## Core Commands

- `make test`: host-safe backend surface
- `make test-cache`: cache regression tests
- `make test-wire-live`: Linux-only live capture verification
- `make benchmark`: benchmark entry point for the v1.0 research surface
- `npm run build`: frontend production build in [web](C:/Users/aryan/OneDrive/Desktop/Janus/web)

## API Surface

Janus exposes:

- `/api/evaluate`: posture recommendation
- `/api/policy`, `/api/policy/validate`, `/api/policy/bundle`: draft, validate, activate, inspect policy bundles
- `/api/discovery/scan`, `/api/discovery/evidence`, `/api/discovery/assets`, `/api/discovery/cbom`: discovery and inventory
- `/api/risk/evaluate`: deterministic quantum exposure assessment
- `/api/migration/plan`, `/api/migration/plans`, `/api/migration/verify`: migration planning and evidence-backed verification
- `/api/audit/records`, `/api/audit/verify`: tamper-evident audit inspection

## Security Invariants

- Missing cryptographic evidence -> `UNVERIFIED`
- Weaker or different observed posture than required -> `NON_COMPLIANT`
- Ambiguous packet evidence -> `UNVERIFIED`
- Unknown workload owner -> `UNATTRIBUTED`
- Multiple plausible workload owners -> `AMBIGUOUS`
- LLM output -> draft policy only, never automatically authoritative

## Verification Notes

Local Windows verification on Wednesday, August 12, 2026:

- `npm run build` passed
- `go test ./internal/cache -v` passed
- `go test ./internal/verification/... -v` passed
- `go test ./cmd/tls-verifier -v` compiled cleanly
- `go test ./cmd/janus-wire-verifier -v` compiled cleanly
- `make test` was partially blocked by Windows Defender quarantining Go's `covdata.exe` coverage helper on this host

Linux CI remains authoritative for:

- live capture
- procfs attribution in CI
- coverage-enabled gates that are unreliable on this Windows machine

## Supporting Docs

- [WHITEPAPER.md](C:/Users/aryan/OneDrive/Desktop/Janus/WHITEPAPER.md)
- [THREAT_MODEL.md](C:/Users/aryan/OneDrive/Desktop/Janus/THREAT_MODEL.md)
- [TESTING.md](C:/Users/aryan/OneDrive/Desktop/Janus/TESTING.md)
- [ROADMAP.md](C:/Users/aryan/OneDrive/Desktop/Janus/ROADMAP.md)
- [V03_ACCEPTANCE.md](C:/Users/aryan/OneDrive/Desktop/Janus/V03_ACCEPTANCE.md)
- [V04_ACCEPTANCE.md](C:/Users/aryan/OneDrive/Desktop/Janus/V04_ACCEPTANCE.md)
- [V05_ACCEPTANCE.md](C:/Users/aryan/OneDrive/Desktop/Janus/V05_ACCEPTANCE.md)
- [V10_ACCEPTANCE.md](C:/Users/aryan/OneDrive/Desktop/Janus/V10_ACCEPTANCE.md)
