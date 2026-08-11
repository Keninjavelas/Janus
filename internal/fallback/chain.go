package fallback

import (
	"context"
	"errors"

	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/config"
	"github.com/yourorg/janus/internal/engine"
)

var (
	ErrFallback = errors.New("fallback evaluation failed")
)

// EvaluateWithFallback attempts core evaluation, then peer-aware fallback, then
// a safe default.
func EvaluateWithFallback(ctx context.Context, req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
	cfg, err := coreEval(ctx, req)
	if err == nil && cfg != nil {
		return cfg, nil
	}

	cfg, err = peerFallback(req)
	if err == nil && cfg != nil {
		return cfg, nil
	}

	return defaultConfig(), nil
}

func coreEval(ctx context.Context, req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
	c := engine.NewContextFromProto(req)
	policy := config.GetPolicy()

	for _, rule := range policy.Rules {
		if engine.Matches(rule.Match, c) {
			cfg := applyLifecycleOverrides(rule.Config, c)
			return &pb.AlgorithmConfig{
				Kem:           cfg.Kem,
				Sig:           safeString(cfg.Sig),
				HybridPeer:    cfg.HybridPeer,
				SecurityLevel: int32(cfg.SecurityLevel),
			}, nil
		}
	}

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
	if ctx.KeyRotationHours < 48 && cfg.Sig == nil {
		sig := "ML-DSA-87"
		cfg.Sig = &sig
	}

	if ctx.CertValidityDays > 365 && cfg.Kem == "ML-KEM-512" {
		cfg.Kem = "ML-KEM-768"
	}

	if ctx.LatencyBudgetMs < 1.0 {
		cfg.Kem = "ML-KEM-512"
		if cfg.Sig == nil {
			sig := "ML-DSA-44"
			cfg.Sig = &sig
		}
	}

	if ctx.RAMKB < 1024 && cfg.Kem == "ML-KEM-1024" {
		cfg.Kem = "ML-KEM-768"
	}

	return cfg
}

func peerFallback(req *pb.ContextRequest) (*pb.AlgorithmConfig, error) {
	ranking := map[string]int{
		"ML-KEM-1024": 3,
		"ML-KEM-768":  2,
		"ML-KEM-512":  1,
	}

	var best string
	bestScore := 0
	for _, peerAlg := range req.PeerAlgorithms {
		if score, ok := ranking[peerAlg]; ok && score > bestScore {
			best = peerAlg
			bestScore = score
		}
	}

	if best != "" {
		return &pb.AlgorithmConfig{
			Kem:           best,
			HybridPeer:    hybridPeerForKEM(best),
			SecurityLevel: int32(bestScore + 1),
		}, nil
	}

	return nil, errors.New("no peer match")
}

func defaultConfig() *pb.AlgorithmConfig {
	return &pb.AlgorithmConfig{
		Kem:           "ML-KEM-768",
		HybridPeer:    hybridPeerForKEM("ML-KEM-768"),
		SecurityLevel: 3,
	}
}

func hybridPeerForKEM(kem string) string {
	if kem == "ML-KEM-768" || kem == "Kyber768" {
		return "X25519MLKEM768"
	}
	return ""
}
