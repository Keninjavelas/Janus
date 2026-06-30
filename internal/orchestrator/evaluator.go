// internal/orchestrator/evaluator.go
package orchestrator

import (
    "context"
    "time"

    "github.com/rs/zerolog"
    "github.com/yourorg/janus/internal/fallback"
    pb "github.com/yourorg/janus/api/proto/v1"
    "os"
)

var logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

// EvaluateContext is the public entry point used by the gRPC server.
// It enforces a hard timeout of 4ms and delegates to the fallback chain.
func EvaluateContext(ctx context.Context, req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
    ctx, cancel := context.WithTimeout(ctx, 4*time.Millisecond)
    defer cancel()
    cfg, err := fallback.EvaluateWithFallback(ctx, req)
    if err != nil {
        logger.Error().Err(err).Msg("fallback evaluation failed")
        return nil, err
    }
    return cfg, nil
}
