//go:build integration

package integration

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestHotReload(t *testing.T) {
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
		t.Fatalf("initial eval error: %v", err)
	}
	if resp.Kem != "ML-KEM-768" {
		t.Fatalf("expected ML-KEM-768, got %s", resp.Kem)
	}

	policyPath := filepath.Join("configs", "policy.yaml")
	orig, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	modified := strings.ReplaceAll(string(orig), "ML-KEM-768", "ML-KEM-1024")
	if err := os.WriteFile(policyPath, []byte(modified), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	defer os.WriteFile(policyPath, orig, 0644)

	time.Sleep(200 * time.Millisecond)

	resp2, err := client.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("second eval error: %v", err)
	}
	if resp2.Kem != "ML-KEM-1024" {
		t.Fatalf("expected ML-KEM-1024 after reload, got %s", resp2.Kem)
	}

	bad := []byte("default:\n  kem: ML-KEM-768\n  hybrid_peer: X25519MLKEM768\n  security_level: 3\nrules:\n  - name: BadRule\n    match:\n      scenario: MICROSEGMENTATION\n    config:\n      kem: ML-KEM-768\n      sig: null\n      security_level: 1\n  : bad")
	if err := os.WriteFile(policyPath, bad, 0644); err != nil {
		t.Fatalf("write bad policy: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	resp3, err := client.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("eval after bad policy: %v", err)
	}
	if resp3.Kem != "ML-KEM-1024" {
		t.Fatalf("expected ML-KEM-1024 after bad policy, got %s", resp3.Kem)
	}
}
