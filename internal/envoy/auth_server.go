// internal/envoy/auth_server.go
package envoy

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/orchestrator"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	tracer = otel.Tracer("pqc.engine.envoy")
)

// AuthServer implements Envoy's external authorization gRPC service.
type AuthServer struct {
	auth.UnimplementedAuthorizationServer
}

// Check receives an Envoy CheckRequest, translates it into our internal ContextRequest,
// runs the policy engine, and returns an AuthorizationResponse.
func (s *AuthServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	ctx, span := tracer.Start(ctx, "envoy.auth.check", trace.WithAttributes(
		attribute.String("source.ip", req.Attributes.SourceAddress),
	))
	defer span.End()

	// Basic mapping – in a real deployment we would parse headers, query params, etc.
	// For demo purposes we construct a minimal ContextRequest.
	engineReq := &pb.ContextRequest{
		Scenario:        "default",
		Risk:            2,
		LatencyBudgetMs: 100.0,
		RamKb:           256000,
		// Peer algorithms could be extracted from a header like "x-peer-algs"
		PeerAlgorithms:   []string{"ML-KEM-768"},
		KeyRotationHours: 24,
		CertValidityDays: 365,
		ExecuteCrypto:    false,
	}

	cfg, err := orchestrator.EvaluateContext(ctx, engineReq)
	if err != nil {
		logger.Error().Err(err).Msg("policy evaluation failed")
		span.RecordError(err)
		// Deny by default on error.
		return &auth.CheckResponse{Status: &auth.CheckResponse_DeniedResponse{DeniedResponse: &auth.DeniedHttpResponse{}}}, nil
	}

	// If evaluation succeeds, allow the request.
	// Here we could embed selected algorithm in response headers for downstream services.
	resp := &auth.CheckResponse{Status: &auth.CheckResponse_OkResponse{OkResponse: &auth.OkHttpResponse{}}}
	// Example: add algorithm info as a header.
	if cfg != nil && cfg.Kem != "" {
		header := &auth.HeaderValueOption{Header: &auth.HeaderValue{Key: "x-selected-kem", Value: cfg.Kem}}
		resp.OkResponse.Headers = append(resp.OkResponse.Headers, header)
	}
	logger.Info().Str("kem", cfg.Kem).Msg("authorization allowed")
	return resp, nil
}

// StartAuthServer launches the Envoy ext_authz gRPC server.
var authGRPCServer *grpc.Server

// authInterceptor adds basic logging for incoming auth requests.
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	logger.Debug().
		Str("method", info.FullMethod).
		Dur("duration", time.Since(start)).
		Err(err).
		Msg("auth request handled")
	return resp, err
}

// StartAuthServer launches the Envoy ext_authz gRPC server on the given address.
func StartAuthServer(address string) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	authGRPCServer = grpc.NewServer(grpc.UnaryInterceptor(authInterceptor))
	auth.RegisterAuthorizationServer(authGRPCServer, &AuthServer{})
	// Health service
	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(authGRPCServer, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	logger.Info().Msgf("Envoy auth gRPC server listening on %s", address)
	return authGRPCServer.Serve(lis)
}

// ShutdownAuthServer gracefully stops the auth server.
func ShutdownAuthServer(timeout time.Duration) {
	if authGRPCServer != nil {
		go func() {
			time.Sleep(timeout)
			authGRPCServer.GracefulStop()
		}()
	}
}

// Duplicate server start block removed - kept earlier implementation

// Helper to gracefully shutdown – omitted for brevity.
func stopServer(s *grpc.Server, timeout time.Duration) {
	go func() {
		time.Sleep(timeout)
		s.GracefulStop()
	}()
}
