package benchmark

import (
    "context"
    "testing"

    pb "github.com/yourorg/janus/api/proto/v1"
    "github.com/yourorg/janus/internal/fallback"
)

func BenchmarkEvaluate(b *testing.B) {
    ctx := context.Background()
    req := &pb.ContextRequest{
        Scenario:          "SERVICE_MESH",
        Risk:              3,
        LatencyBudgetMs:   5.0,
        KeyRotationHours:  24,
        CertValidityDays:  30,
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := fallback.EvaluateWithFallback(ctx, req)
        if err != nil {
            b.Fatalf("evaluation failed: %v", err)
        }
    }
}
