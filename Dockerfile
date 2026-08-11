# Dockerfile

# ---------- Build stage ----------
FROM golang:1.25-alpine AS builder
WORKDIR /app

# Cache go.mod and go.sum for faster builds
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . ./

# Build the binary (static linking for minimal image)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /pqc-engine ./cmd/pq-engine

# ---------- Runtime stage ----------
FROM alpine:3.20
RUN adduser -D -u 1000 appuser
USER appuser
COPY --from=builder /pqc-engine /usr/local/bin/pqc-engine

# Expose gRPC and Prometheus ports
EXPOSE 50051 9090

ENTRYPOINT ["/usr/local/bin/pqc-engine"]
