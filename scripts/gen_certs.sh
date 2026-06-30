#!/bin/bash
# scripts/gen_certs.sh
# Generates mTLS test certificates (CA, server, client) for Janus.

set -e

OUT_DIR="testdata"
mkdir -p "$OUT_DIR"

# CA
openssl genrsa -out "$OUT_DIR/ca.key" 2048
openssl req -new -x509 -days 3650 -key "$OUT_DIR/ca.key" \
    -subj "/CN=Janus CA" -out "$OUT_DIR/ca.crt"

# Server
openssl genrsa -out "$OUT_DIR/server.key" 2048
openssl req -new -key "$OUT_DIR/server.key" -subj "/CN=janus-server" \
    -out "$OUT_DIR/server.csr"
openssl x509 -req -in "$OUT_DIR/server.csr" -CA "$OUT_DIR/ca.crt" \
    -CAkey "$OUT_DIR/ca.key" -CAcreateserial -days 365 -out "$OUT_DIR/server.crt"

# Client
openssl genrsa -out "$OUT_DIR/client.key" 2048
openssl req -new -key "$OUT_DIR/client.key" -subj "/CN=janus-client" \
    -out "$OUT_DIR/client.csr"
openssl x509 -req -in "$OUT_DIR/client.csr" -CA "$OUT_DIR/ca.crt" \
    -CAkey "$OUT_DIR/ca.key" -CAcreateserial -days 365 -out "$OUT_DIR/client.crt"

# Clean up CSR files
rm "$OUT_DIR"/*.csr

echo "✅ Certificates generated in $OUT_DIR"
