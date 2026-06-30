# Janus – Post-Quantum Zero-Trust Engine

A **production-ready, observable Go microservice** that maps Zero-Trust Architecture (ZTA) context to concrete post-quantum cryptography (PQC) algorithm choices. Janus now includes a **fully integrated React Web UI** and an **AI-powered Policy Co-Pilot**.

It ships with **eight flagship features**:

1. **Kubernetes Hardening** – Horizontal Pod Autoscaler and TLS-enabled Ingress.
2. **Istio/Envoy ext_authz** – External authz filter for Envoy.
3. **Grafana Dashboard** – Real-time metrics for decisions, latency, cache, and crypto execution.
4. **Extended Policies** – Region, time-of-day, and device-type conditions.
5. **LRU Decision Cache** – Sub-millisecond decision latency.
6. **Envoy Wasm Filter** – TinyGo Wasm plugin that injects `X-PQC-Recommended` headers.
7. **liboqs Crypto Execution** – Real PQC key-encapsulation (KEM) operations via liboqs.
8. **React Web UI & AI Co-Pilot** – Modern dashboard with a Request Simulator, YAML Editor, and OpenAI-powered policy generation.

---

## 🚀 Quickstart: Full Stack (Windows/Powershell)

To run the complete Janus stack (Go Backend on `:8080` & `:50051`, and React Frontend on `:5173`):

```powershell
# 1️⃣ Clone the repo
cd C:\Users\aryan\OneDrive\Desktop\Janus

# 2️⃣ Set OpenAI API Key for AI Co-Pilot (Optional but recommended)
$env:OPENAI_API_KEY="sk-..."

# 3️⃣ Run the full stack script
.\run_all.ps1
```
The UI will be available at `http://localhost:5173`.

---

## 💻 Web UI Features

The Janus frontend (`web/`) is built with React, Tailwind CSS, and Zustand. It provides a visual interface for interacting with the backend engine:

- **Dashboard**: Real-time metrics and a dynamic Threat Gauge tracking the ratio of classical vs. PQC algorithms.
- **Request Simulator**: Test cryptographic decisions across regions, risk levels, and advanced options (IoT, Server, Root CA).
- **Policy Editor**: Monaco-based YAML editor with hot-reloading capabilities.
- **AI Co-Pilot**: Integrated chat interface that connects to `gpt-4o-mini` to automatically generate valid Janus policies from natural language prompts.

---

## ⚙️ Backend Development (Linux/Mac)

| Command | Description |
|---------|-------------|
| `make test` | Run unit, integration, and chaos tests |
| `make lint` | Run `golangci-lint` |
| `make docker` | Build the multi-stage Docker image |
| `make run` | Run the compiled binary locally |
| `./scripts/build_wasm.sh` | Compile the Envoy Wasm filter |

---

## 🌐 HTTP REST API & gRPC

Janus exposes two interfaces:
- **gRPC (`:50051`)**: For high-performance backend-to-backend communication (e.g., Envoy).
- **REST API (`:8080`)**: Used by the React frontend for evaluation, metrics, and policy management.

### Example REST Evaluation
```bash
curl -X POST http://localhost:8080/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"scenario":"MICROSEGMENTATION","region":"EU","risk":4}'
```

---

## ☁️ Deployment

```bash
# Deploy all Kubernetes manifests (deployment, service, HPA, Ingress, ServiceMonitor)
kubectl apply -k deployments/kubernetes/

# Deploy Envoy with Wasm filter
kubectl apply -f deployments/envoy/envoy-wasm.yaml
```

### Prometheus & Grafana

- Metrics are exposed on `:9090/metrics`.
- Import `deployments/grafana/dashboard.json` into Grafana to view throughput, latency, algorithm distribution, and cache rates.

---

## 🔒 Extending Policies

Edit `configs/policy.yaml` (or use the Web UI Editor) – the service hot-reloads changes instantly. 
```yaml
default:
  kem: "ML-KEM-768"
  hybrid_peer: "X25519Kyber768"
  security_level: 3
rules:
  - name: "High Risk EU"
    match:
      region: "EU"
      risk_min: 4
      device_type: "iot"
    config:
      kem: "ML-KEM-1024"
      sig: "ML-DSA-87"
      security_level: 5
```

---

## 🛡️ Production Hardening (Missing Gaps)

| Gap | Why It Matters | How to Fix |
|-----|----------------|-----------|
| **Authentication** | Janus accepts requests without credentials | Add mTLS or OIDC to gRPC endpoints |
| **Audit Logging** | Decisions are logged but not tamper-proof | Write to a WAL (write-ahead log) or blockchain |
| **Disaster Recovery** | If Janus crashes, how do you restore? | Add a persistent volume for cache state |
| **SLA Monitoring** | If p99 exceeds 2 ms, what happens? | Add alerts to Prometheus (Alertmanager) |
| **Integration Testing** | Not all scenarios are tested | Add more integration tests (e.g., Envoy + Wasm) |

---

*Built with Go 1.22+, React, Tailwind, gRPC, OpenTelemetry, Prometheus, Viper, fsnotify, Zerolog, liboqs, Envoy, and TinyGo.*
