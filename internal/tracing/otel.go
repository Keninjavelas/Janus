// internal/tracing/otel.go
package tracing

import (
    "context"
    "os"

    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/sdk/resource"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    "go.opentelemetry.io/otel/trace"
    "go.opentelemetry.io/otel/semconv/v1.17.0"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

// InitTracer creates an OTLP exporter (e.g., Jaeger, Honeycomb) and registers a tracer provider.
// The collector endpoint is read from the OTEL_EXPORTER_OTLP_ENDPOINT environment variable;
// if not set, it defaults to "localhost:4317" (the OTLP gRPC receiver port).
func InitTracer() func(context.Context) error {
    // Resolve endpoint
    endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint == "" {
        endpoint = "localhost:4317"
    }

    // Build gRPC client options – insecure is fine for local dev; production can set TLS via env vars.
    clientOpts := []otlptracegrpc.Option{
        otlptracegrpc.WithEndpoint(endpoint),
        otlptracegrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
    }

    exporter, err := otlptracegrpc.New(context.Background(), clientOpts...)
    if err != nil {
        // In a production binary we would log the error and fall back to a no‑op exporter.
        // For simplicity we panic – the service cannot start without tracing if this is configured.
        panic(err)
    }

    // Create a resource describing this service.
    res, err := resource.New(context.Background(),
        resource.WithAttributes(
            semconv.ServiceNameKey.String("pqc-zta-engine"),
        ),
    )
    if err != nil {
        panic(err)
    }

    tp := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(exporter),
        sdktrace.WithResource(res),
    )
    otel.SetTracerProvider(tp)
    return tp.Shutdown
}

// GetTracer returns a named tracer that can be used throughout the codebase.
func GetTracer() trace.Tracer {
    return otel.Tracer("pqc.engine")
}
