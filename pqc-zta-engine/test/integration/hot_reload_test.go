package integration

import (
    "context"
    "io/ioutil"
    "net"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "google.golang.org/grpc"
    "github.com/yourorg/janus/internal/server"
    pb "github.com/yourorg/janus/api/proto/v1"
)

func TestHotReload(t *testing.T) {
    // Start gRPC server on a random port
    lis, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatalf("listen error: %v", err)
    }
    srv := server.NewGRPCServer()
    go func() {
        if err := srv.Serve(lis); err != nil {
            t.Fatalf("server error: %v", err)
        }
    }()
    defer srv.Stop()
    time.Sleep(100 * time.Millisecond)

    // Create client
    conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
    if err != nil {
        t.Fatalf("dial error: %v", err)
    }
    defer conn.Close()
    client := pb.NewPqcEngineClient(conn)
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    // Initial request – expect ML-KEM-512 per default policy
    req := &pb.ContextRequest{Scenario: "MICROSEGMENTATION", Risk: 3, LatencyBudgetMs: 2.0}
    resp, err := client.Evaluate(ctx, req)
    if err != nil {
        t.Fatalf("initial eval error: %v", err)
    }
    if resp.Kem != "ML-KEM-512" {
        t.Fatalf("expected ML-KEM-512, got %s", resp.Kem)
    }

    // Modify policy.yaml: replace ML-KEM-512 with ML-KEM-768
    policyPath := filepath.Join("configs", "policy.yaml")
    orig, err := ioutil.ReadFile(policyPath)
    if err != nil {
        t.Fatalf("read policy: %v", err)
    }
    modified := strings.ReplaceAll(string(orig), "ML-KEM-512", "ML-KEM-768")
    if err := ioutil.WriteFile(policyPath, []byte(modified), 0644); err != nil {
        t.Fatalf("write policy: %v", err)
    }
    // Give watcher time to detect change
    time.Sleep(200 * time.Millisecond)

    // Second request – should now return ML-KEM-768
    resp2, err := client.Evaluate(ctx, req)
    if err != nil {
        t.Fatalf("second eval error: %v", err)
    }
    if resp2.Kem != "ML-KEM-768" {
        t.Fatalf("expected ML-KEM-768 after reload, got %s", resp2.Kem)
    }

    // Write malformed YAML – engine should keep previous good policy
    bad := []byte("default:\n  kem: ML-KEM-768\n  hybrid_peer: X25519Kyber768\n  security_level: 3\nrules:\n  - name: BadRule\n    match:\n      scenario: MICROSEGMENTATION\n    config:\n      kem: ML-KEM-768\n      sig: null\n      security_level: 1\n# missing closing brace")
    if err := ioutil.WriteFile(policyPath, bad, 0644); err != nil {
        t.Fatalf("write bad policy: %v", err)
    }
    time.Sleep(200 * time.Millisecond)

    // Third request – should still return ML-KEM-768 (last good config)
    resp3, err := client.Evaluate(ctx, req)
    if err != nil {
        t.Fatalf("eval after bad policy: %v", err)
    }
    if resp3.Kem != "ML-KEM-768" {
        t.Fatalf("expected ML-KEM-768 after bad policy, got %s", resp3.Kem)
    }

    // Restore original policy
    _ = ioutil.WriteFile(policyPath, orig, 0644)
}
