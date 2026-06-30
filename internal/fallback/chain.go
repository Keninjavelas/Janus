// internal/fallback/chain.go
package fallback

import (
    "context"
    "errors"

    "github.com/yourorg/janus/internal/config"
    "github.com/yourorg/janus/internal/engine"
    pb "github.com/yourorg/janus/api/proto/v1"
)

var (
    ErrFallback = errors.New("fallback evaluation failed")
)

// EvaluateWithFallback attempts core evaluation, then peer-aware fallback, then safe default.
func EvaluateWithFallback(ctx context.Context, req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
    // 1. Core engine evaluation
    cfg, err := coreEval(ctx, req)
    if err == nil && cfg != nil {
        return cfg, nil
    }
    // 2. Peer-aware fallback
    cfg, err = peerFallback(req)
    if err == nil && cfg != nil {
        return cfg, nil
    }
    // 3. Safe default
    return defaultConfig(), nil
}

func coreEval(ctx context.Context, req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
    // Build internal context struct
    // Build internal context struct using helper
    c := engine.NewContextFromProto(req)

    // Get current policy snapshot
    policy := config.GetPolicy()
    // Iterate rules in order
    for _, rule := range policy.Rules {
        if engine.Matches(rule.Match, c) {
            cfg := rule.Config
            // Apply lifecycle overrides if needed
            cfg = applyLifecycleOverrides(cfg, c)
            return &pb.AlgorithmConfig{
                Kem:           cfg.Kem,
                Sig:           safeString(cfg.Sig),
                HybridPeer:    cfg.HybridPeer,
                SecurityLevel: int32(cfg.SecurityLevel),
            }, nil
        }
    }
    // No rule matched – fallback to default
    d := policy.Default
    return &pb.AlgorithmConfig{
        Kem:           d.Kem,
        Sig:           safeString(d.Sig),
        HybridPeer:    d.HybridPeer,
        SecurityLevel: int32(d.SecurityLevel),
    }, nil
}

func safeString(s *string) string {
    if s == nil {
        return ""
    }
    return *s
}

func applyLifecycleOverrides(cfg config.Config, ctx engine.Context) config.Config {
    // Full lifecycle overrides based on the research paper.
    // 1. Key rotation: if rotation < 48h, enforce a strong signature.
    if ctx.KeyRotationHours < 48 && cfg.Sig == nil {
        sig := "ML-DSA-87"
        cfg.Sig = &sig
    }
    // 2. Cert validity: if cert validity > 365 days, allow larger KEM for higher security.
    if ctx.CertValidityDays > 365 && cfg.Kem == "ML-KEM-512" {
        cfg.Kem = "ML-KEM-768"
    }
    // 3. Latency budget: if latency budget is very tight (< 1.0 ms), downgrade to the smallest KEM.
    if ctx.LatencyBudgetMs < 1.0 {
        cfg.Kem = "ML-KEM-512"
        // Prefer a lightweight signature if not already set.
        if cfg.Sig == nil {
            sig := "ML-DSA-44"
            cfg.Sig = &sig
        }
    }
    // 4. RAM constraints: if RAM is limited, choose a KEM with smaller key size.
    if ctx.RAMKB < 1024 && cfg.Kem == "ML-KEM-1024" {
        cfg.Kem = "ML-KEM-768"
    }
    return cfg
}

func peerFallback(req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
    // Richer peer capability negotiation.
    // The request may contain TLS extension identifiers that map to supported algorithms.
    // For this example we assume PeerAlgorithms is a list of algorithm identifiers advertised by the peer.
    // We maintain a ranking of algorithms by security and performance.
    ranking := map[string]int{
        "ML-KEM-1024": 3,
        "ML-KEM-768":  2,
        "ML-KEM-512":  1,
    }
    // Choose the strongest algorithm that both sides support.
    var best string
    bestScore := 0
    for _, peerAlg := range req.PeerAlgorithms {
        if score, ok := ranking[peerAlg]; ok {
            if score > bestScore {
                best = peerAlg
                bestScore = score
            }
        }
    }
    if best != "" {
        return &pb.AlgorithmConfig{Kem: best, HybridPeer: best, SecurityLevel: int32(bestScore + 1)}, nil
    }
    // If no known algorithm matches, fall back to a safe default.
    return nil, errors.New("no peer match")
}

func defaultConfig() *pb.AlgorithmConfig {
    return &pb.AlgorithmConfig{Kem: "ML-KEM-768", HybridPeer: "X25519Kyber768", SecurityLevel: 3}
}
