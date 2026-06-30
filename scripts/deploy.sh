#!/usr/bin/env bash
# deploy.sh - Zero‑Touch deployment for Janus on GCP (can be adapted for AWS/Azure)
# Usage: ./deploy.sh --cloud=gcp --project=my-gcp-project --region=us-central1

set -euo pipefail

# Default values
CLOUD="gcp"
PROJECT=""
REGION="us-central1"
ZONE=""
CLUSTER_NAME="janus-cluster"

print_help() {
  cat <<EOF
Usage: $0 [options]
Options:
  --cloud=[gcp|aws|azure]   Target cloud provider (default: gcp)
  --project=PROJECT_ID       GCP project ID (required for GCP)
  --region=REGION            Cloud region (default: us-central1)
  --zone=ZONE                Zone for GKE (optional)
  --cluster=NAME             GKE cluster name (default: janus-cluster)
  -h, --help                 Show this help message
EOF
}

# Parse arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --cloud=*) CLOUD="${1#*=}" ;;
    --project=*) PROJECT="${1#*=}" ;;
    --region=*) REGION="${1#*=}" ;;
    --zone=*) ZONE="${1#*=}" ;;
    --cluster=*) CLUSTER_NAME="${1#*=}" ;;
    -h|--help) print_help; exit 0 ;;
    *) echo "Unknown option: $1"; print_help; exit 1 ;;
  esac
  shift
done

if [[ "$CLOUD" == "gcp" ]]; then
  if [[ -z "$PROJECT" ]]; then
    echo "Error: --project is required for GCP"
    exit 1
  fi
  echo "🟢 Deploying Janus to GCP project $PROJECT in region $REGION"

  # 1️⃣ Enable required APIs
  gcloud services enable container.googleapis.com monitoring.googleapis.com logging.googleapis.com

  # 2️⃣ Create GKE cluster (if not exists)
  if ! gcloud container clusters describe "$CLUSTER_NAME" --region "$REGION" --project "$PROJECT" >/dev/null 2>&1; then
    echo "Creating GKE cluster $CLUSTER_NAME..."
    gcloud container clusters create "$CLUSTER_NAME" \
      --region "$REGION" \
      --project "$PROJECT" \
      --num-nodes 3 \
      --machine-type e2-standard-4 \
      --enable-autoscaling --min-nodes 2 --max-nodes 10
  else
    echo "Cluster $CLUSTER_NAME already exists"
  fi

  # 3️⃣ Get credentials
  gcloud container clusters get-credentials "$CLUSTER_NAME" --region "$REGION" --project "$PROJECT"

  # 4️⃣ Deploy Prometheus & Grafana (using kube‑prometheus‑stack)
  echo "Deploying Prometheus & Grafana..."
  kubectl apply -f https://github.com/prometheus-operator/kube-prometheus/releases/download/v0.13.0/kube-prometheus-stack.yaml

  # 5️⃣ Deploy Janus manifests (deployment, service, HPA, Ingress, ServiceMonitor)
  echo "Deploying Janus core components..."
  kubectl apply -k deployments/kubernetes/

  # 6️⃣ Deploy Envoy with Wasm filter
  echo "Deploying Envoy + Wasm..."
  kubectl apply -f deployments/envoy/envoy-wasm.yaml
  kubectl apply -f deployments/kubernetes/envoy-wasm-deployment.yaml

  echo "✅ Deployment complete. Access the service via the Ingress hostname you configured."
  echo "Grafana: http://<your‑ingress‑host>/grafana (default credentials admin/admin)"
else
  echo "Cloud provider $CLOUD not yet supported in this script. Feel free to extend it!"
  exit 1
fi
