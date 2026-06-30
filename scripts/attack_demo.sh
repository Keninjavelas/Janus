#!/usr/bin/env bash
# attack_demo.sh - Reproducible script for the 2‑minute "Attack & Defend" demo
# This script sets up a local Janus + Envoy + Wasm demo, captures traffic, and shows the algorithm upgrade.
# It is meant to be run on a workstation with Docker, kubectl, and tcpdump installed.

set -euo pipefail

# -------------------------------------------------------------------
# 1. Prerequisites check
# -------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required"; exit 1; }
command -v tcpdump >/dev/null 2>&1 || { echo "tcpdump is required"; exit 1; }

# -------------------------------------------------------------------
# 2. Build Janus binary and Wasm filter (if not already built)
# -------------------------------------------------------------------
if [[ ! -f bin/janus ]]; then
  echo "Building Janus binary..."
  make build
fi
if [[ ! -f deployments/envoy/filter.wasm ]]; then
  echo "Building Wasm filter..."
  ./scripts/build_wasm.sh
fi

# -------------------------------------------------------------------
# 3. Start a local Kind cluster (lightweight Kubernetes)
# -------------------------------------------------------------------
if ! kind get clusters | grep -q "janus-demo"; then
  echo "Creating Kind cluster 'janus-demo'..."
  kind create cluster --name janus-demo --config=<(cat <<EOF
kind: ClusterConfig
apiVersion: kind.x-k8s.io/v1
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080
    hostPort: 30080
    protocol: TCP
    # Envoy listener
  - containerPort: 30081
    hostPort: 30081
    protocol: TCP
    # Grafana (optional)
  - containerPort: 30082
    hostPort: 30082
    protocol: TCP
EOF
)
fi

# Set context to the Kind cluster
kubectl cluster-info --context kind-janus-demo

# -------------------------------------------------------------------
# 4. Deploy Janus core components (deployment, service, HPA, Ingress, ServiceMonitor)
# -------------------------------------------------------------------
echo "Applying Janus Kubernetes manifests..."
kubectl apply -k deployments/kubernetes/ --context kind-janus-demo

# -------------------------------------------------------------------
# 5. Deploy Envoy with Wasm filter
# -------------------------------------------------------------------
echo "Deploying Envoy with Wasm filter..."
kubectl apply -f deployments/envoy/envoy-wasm.yaml --context kind-janus-demo
kubectl apply -f deployments/kubernetes/envoy-wasm-deployment.yaml --context kind-janus-demo

# Wait for pods to be ready
echo "Waiting for all pods to become Ready..."
kubectl wait --for=condition=Ready pod -l app=janus --timeout=120s --context kind-janus-demo
kubectl wait --for=condition=Ready pod -l app=envoy-wasm --timeout=120s --context kind-janus-demo

# -------------------------------------------------------------------
# 6. Capture traffic with tcpdump (background)
# -------------------------------------------------------------------
CAPTURE_FILE="/tmp/janus_demo.pcap"
echo "Starting tcpdump capture to $CAPTURE_FILE (background)..."
# Capture traffic on the Kind node's network interface (docker0)
sudo tcpdump -i docker0 -w $CAPTURE_FILE port 30080 or port 30081 &
TCPDUMP_PID=$!

# -------------------------------------------------------------------
# 7. Simulate an attacker capturing traffic (pre‑upgrade)
# -------------------------------------------------------------------
echo "=== Phase 1: Attacker captures classic TLS traffic ==="
# Send a request that Janus will initially answer with a classic algorithm (simulate by setting low risk)
grpcurl -plaintext -d '{"scenario":"MICROSEGMENTATION","risk":1,"latency_budget_ms":10}' localhost:30080 janusengine.v1.JanusEngine/Evaluate

# Sleep to ensure capture
sleep 2

# -------------------------------------------------------------------
# 8. Trigger policy change (region = EU) so Janus upgrades to a PQC algorithm
# -------------------------------------------------------------------
echo "=== Phase 2: Janus upgrades to ML‑KEM‑768 based on region ==="
# Update policy.yaml locally (region EU) – in a real demo you would edit the ConfigMap.
# For simplicity we patch the ConfigMap directly:
kubectl patch configmap janus-config --type merge -p '{"data":{"policy.yaml":"region: \"EU\"\nrisk: 3\nalgorithm: \"ML-KEM-768\""}}' --context kind-janus-demo

# Give Janus a moment to reload
sleep 5

# Send a request that now matches the EU region and higher risk
grpcurl -plaintext -d '{"scenario":"MICROSEGMENTATION","risk":3,"latency_budget_ms":2}' localhost:30080 janusengine.v1.JanusEngine/Evaluate

# Sleep to capture
sleep 2

# -------------------------------------------------------------------
# 9. Stop tcpdump and analyze the capture
# -------------------------------------------------------------------
echo "Stopping tcpdump..."
kill $TCPDUMP_PID
wait $TCPDUMP_PID 2>/dev/null || true

# Show a brief summary (packet counts)
echo "=== Capture summary ==="
sudo tcpdump -nn -r $CAPTURE_FILE | wc -l

# Optional: convert to a GIF/MP4 for the demo video (requires ffmpeg)
# ffmpeg -i $CAPTURE_FILE -c:v libx264 demo.mp4

# -------------------------------------------------------------------
# 10. Clean up (optional)
# -------------------------------------------------------------------
# Uncomment to delete the Kind cluster after the demo
# kind delete cluster --name janus-demo

echo "Demo script completed. Use the captured $CAPTURE_FILE to illustrate the attacker’s view before and after the upgrade."
