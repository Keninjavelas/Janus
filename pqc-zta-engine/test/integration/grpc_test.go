//go:build integration

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startTestServer(t *testing.T) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	srv := server.NewGRPCServer()
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Fatalf("server error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	return srv, lis
}

func TestGRPCEvaluate(t *testing.T) {
	srv, lis := startTestServer(t)
	defer srv.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	client := pb.NewPqcEngineClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := &pb.ContextRequest{Scenario: "MICROSEGMENTATION", Risk: 3, LatencyBudgetMs: 2.0}
	resp, err := client.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if resp.Kem != "ML-KEM-768" {
		t.Fatalf("expected KEM ML-KEM-768, got %s", resp.Kem)
	}
}
