// internal/server/grpc.go
package server

import (
    "context"
    "net"
    "time"

    "github.com/rs/zerolog"
    "os"
    "github.com/yourorg/janus/internal/orchestrator"
    pb "github.com/yourorg/janus/api/proto/v1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/health"
    healthpb "google.golang.org/grpc/health/grpc_health_v1"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
)

var (
    logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
    tracer = otel.Tracer("pqc.engine.server")
)

type EngineServer struct {
    pb.UnimplementedPqcEngineServer
}

func (s *EngineServer) Evaluate(ctx context.Context, req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
    // Start tracing span
    ctx, span := tracer.Start(ctx, "pqc.engine.evaluate", trace.WithAttributes(
        attribute.String("scenario", req.Scenario),
        attribute.Int("risk", int(req.Risk)),
    ))
    defer span.End()

    // Enforce hard timeout via context (already done by caller in EvaluateContext)
    cfg, err := orchestrator.EvaluateContext(ctx, req)
    if err != nil {
        logger.Error().Err(err).Msg("evaluation failed")
        span.RecordError(err)
        return nil, err
    }
    // Record metric (placeholder – actual metric increment handled elsewhere)
    span.SetAttributes(attribute.String("kem", cfg.Kem), attribute.String("sig", cfg.Sig))
    return cfg, nil
}

// StartGRPC launches the gRPC server on the given address.
func StartGRPC(address string) error {
    lis, err := net.Listen("tcp", address)
    if err != nil {
        return err
    }
    opts := []grpc.ServerOption{
        grpc.UnaryInterceptor(unaryInterceptor()),
    }
    grpcServer := grpc.NewServer(opts...)
    pb.RegisterPqcEngineServer(grpcServer, &EngineServer{})

    // Register health service
    healthSrv := health.NewServer()
    healthpb.RegisterHealthServer(grpcServer, healthSrv)
    healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

    logger.Info().Msgf("gRPC server listening on %s", address)
    return grpcServer.Serve(lis)
}

// unaryInterceptor adds simple logging for each request.
func unaryInterceptor() grpc.UnaryServerInterceptor {
    return func(
        ctx context.Context,
        req interface{},
        info *grpc.UnaryServerInfo,
        handler grpc.UnaryHandler,
    ) (interface{}, error) {
        start := time.Now()
        resp, err := handler(ctx, req)
        duration := time.Since(start)
        logger.Info().
            Str("method", info.FullMethod).
            Dur("duration", duration).
            Err(err).
            Msg("handled unary RPC")
        return resp, err
    }
}
