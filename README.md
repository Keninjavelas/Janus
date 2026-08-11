# Janus - Adaptive Post-Quantum Crypto-Agility Control Plane

Janus is a production-oriented research platform for evaluating post-quantum cryptographic posture in cloud-native systems. As of Tuesday, August 11, 2026, the repository is strongest as a policy decision engine plus a layered cryptographic verification experiment: it maps request context to recommended PQC settings, exposes those decisions over gRPC and HTTP, and now includes both direct TLS verification and passive wire-level attestation paths for experimentation.

Janus is not yet a full zero-trust enforcement system. In the current implementation, the strongest proof surface is a research-grade verifier stack rather than full deployment rollout, identity correlation, or service-mesh-wide enforcement.

## Current scope

- Policy-driven PQC selection with hot-reloadable YAML rules
- gRPC and REST interfaces for evaluation, metrics, and policy editing
- React dashboard with simulator, metrics, and policy review workflows
- Envoy ext_authz and Wasm integration for advisory propagation experiments
- liboqs-backed KEM experiments for standardized `ML-KEM-*` selections

## Roadmap pillars

1. Adaptive crypto policy engine
2. Cryptographic enforcement plane
3. Independent downgrade verification
4. Crypto-agility discovery, inventory, and migration planning

## Architecture status

Current:

```text
Context -> Janus policy engine -> decision payload -> advisory integration
```

Target:

```text
Context -> Janus policy engine -> signed crypto policy decision
        -> enforcement configuration -> negotiated protocol posture
        -> independent verification -> downgrade detection and audit
```

## Important boundaries

- `X-PQC-Recommended` is advisory metadata. It is not proof of TLS or mTLS enforcement.
- The AI feature drafts policy. It does not automatically deploy policy.
- `liboqs` integration in this repo is for experimentation and interoperability work, not a claim of hardened production cryptography.
- The sample policies in `configs/policy.yaml` are demo logic, not a normative security baseline.

## Quickstart

To run the backend on `:8080` and `:50051`, plus the React frontend on `:5173`:

```powershell
cd C:\Users\aryan\OneDrive\Desktop\Janus
$env:OPENAI_API_KEY="sk-..."  # optional, for the policy assistant
.\run_all.ps1
```

The UI will be available at `http://localhost:5173`.

Janus `v0.3` verification support requires Go `1.25+`. The negotiated key-exchange evidence path depends on the `crypto/tls` APIs available in Go 1.25.
Janus `v0.4` live wire verification additionally depends on Linux, `libpcap`, and the `livecapture` build tag.

## Web UI

The frontend in `web/` provides:

- Dashboard metrics and threat summaries
- Request simulator for demo policy evaluation
- Policy editor for review and manual application
- AI policy assistant that drafts YAML and sends it to the editor for human review

## Backend commands

| Command | Description |
|---------|-------------|
| `make test` | Run the host-safe default test surface |
| `make test-cache` | Run cache regression tests separately |
| `make test-wire-live` | Run the Linux-only live wire-capture proof surface |
| `make test-liboqs` | Run liboqs-backed packages with the `liboqs` build tag |
| `make test-envoy` | Run Envoy-specific packages with the `envoy` build tag |
| `make test-integration` | Run integration tests with the `integration` build tag |
| `make lint` | Run `golangci-lint` |
| `make docker` | Build the multi-stage Docker image |
| `make run` | Run the compiled binary locally |
| `./scripts/build_wasm.sh` | Compile the Envoy Wasm filter |

## Interfaces

Janus currently exposes:

- gRPC on `:50051` for backend-to-backend evaluation
- REST on `:8080` for the web UI, metrics, and policy management

Example evaluation:

```bash
curl -X POST http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"scenario":"MICROSEGMENTATION","region":"EU","risk":4,"device_type":"iot"}'
```

## Policy example

Edit [configs/policy.yaml](C:\Users\aryan\OneDrive\Desktop\Janus\configs\policy.yaml) directly or use the web editor.

```yaml
default:
  kem: "ML-KEM-768"
  hybrid_peer: "X25519MLKEM768"
  security_level: 3

rules:
  - name: "High Risk EU IoT Demo"
    match:
      region: "EU"
      risk_min: 4
      device_type: "iot"
    config:
      kem: "ML-KEM-1024"
      sig: "ML-DSA-87"
      security_level: 5
```

## Security priorities

The most important next steps are:

1. Move from recommendation to real protocol-level enforcement.
2. Add independent verification of negotiated cryptography and downgrade detection.
3. Sign, version, simulate, and audit policy changes.
4. Introduce stronger identity and posture sources for request attributes.
5. Expand from demo rules to discovery, CBOM, and migration planning.

## Threat model

See [THREAT_MODEL.md](C:\Users\aryan\OneDrive\Desktop\Janus\THREAT_MODEL.md) for assets, trust boundaries, threat actors, assumptions, and failure modes.

## Testing

See [TESTING.md](C:\Users\aryan\OneDrive\Desktop\Janus\TESTING.md) for the split between host-safe tests, live-capture tests, liboqs-gated tests, Envoy-gated tests, integration tests, and the current Windows and CI notes.

Linux CI is configured in [`.github/workflows/ci.yml`](C:\Users\aryan\OneDrive\Desktop\Janus\.github\workflows\ci.yml) as the authoritative pass/fail path for the core test surface, cache regression test, and the `v0.4` Ubuntu live-capture lane.

## Roadmap

See [ROADMAP.md](C:\Users\aryan\OneDrive\Desktop\Janus\ROADMAP.md) for the depth-first milestone plan and current freeze point.

The concrete `v0.3` definition of done lives in [V03_ACCEPTANCE.md](C:\Users\aryan\OneDrive\Desktop\Janus\V03_ACCEPTANCE.md).
The concrete `v0.4` definition of done lives in [V04_ACCEPTANCE.md](C:\Users\aryan\OneDrive\Desktop\Janus\V04_ACCEPTANCE.md).

As of Tuesday, August 11, 2026, `v0.4` should be treated as implementation-complete but release-pending until the Ubuntu live-capture CI lane executes successfully.

## Known gaps

- No endpoint-to-wire evidence conflict model yet
- No signed policy bundles or tamper-evident audit chain yet
- No eBPF, PID, container, or workload attribution yet
- Request attributes are still simplified demo inputs
- Cache invalidation is time-based, not revocation-driven
- The Envoy integration surface needs more build and interoperability work

## Repository notes

- Standardized algorithm identifiers in docs and sample policy use `ML-KEM`, `ML-DSA`, and `X25519MLKEM768`.
- `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024` are standardized for TLS 1.3 hybrid key agreement in RFC 10024.
- The code still maps those names to the legacy identifiers required by the current `liboqs-go` binding where necessary.

Built with Go, gRPC, React, Tailwind, OpenTelemetry, Prometheus, Envoy, TinyGo, and liboqs experiments.
