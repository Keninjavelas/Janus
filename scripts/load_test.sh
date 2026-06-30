#!/usr/bin/env bash
set -e
# Load test wrapper using hey (HTTP load generator)
# Adjust ENDPOINT as needed; default assumes the gRPC server also serves HTTP health/metrics on port 50051
ENDPOINT="http://localhost:50051"
REQ_COUNT=10000
CONCURRENCY=100
echo "Running load test against $ENDPOINT with $REQ_COUNT requests at $CONCURRENCY concurrency..."
hey -n $REQ_COUNT -c $CONCURRENCY $ENDPOINT
