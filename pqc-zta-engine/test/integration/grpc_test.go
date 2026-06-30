package integration

import (
    "context"
    "net"
    "testing"
    "time"

    "google.golang.org/grpc"
    "github.com/yourorg/janus/internal/server"
    pb "github.com/yourorg/janus/api/proto/v1"
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
    // give server a moment to start
    time.Sleep(100 * time.Millisecond)
    return srv, lis
}

func TestGRPCEvaluate(t *testing.T) {
    srv, lis := startTestServer(t)
    defer srv.Stop()

    conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
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
    if resp.Kem != "ML-KEM-512" {
        t.Fatalf("expected KEM ML-KEM-512, got %s", resp.Kem)
    }
}
