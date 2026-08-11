// internal/server/grpc_opts.go
package server

import (
	"net"

	pb "github.com/yourorg/janus/api/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// StartGRPCWithOpts launches the gRPC server with the supplied options.
// If no options are provided, it defaults to the unary interceptor defined in this package.
func StartGRPCWithOpts(address string, opts ...grpc.ServerOption) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	grpcServer := NewGRPCServer(opts...)
	logger.Info().Msgf("gRPC server listening on %s", address)
	return grpcServer.Serve(lis)
}

// NewGRPCServer constructs a Janus gRPC server without binding a listener.
func NewGRPCServer(opts ...grpc.ServerOption) *grpc.Server {
	if len(opts) == 0 {
		opts = []grpc.ServerOption{grpc.UnaryInterceptor(unaryInterceptor())}
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterPqcEngineServer(grpcServer, &EngineServer{})

	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	return grpcServer
}
