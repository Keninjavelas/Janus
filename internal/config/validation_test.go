package config

import (
	"strings"
	"testing"
	"time"
)

func TestCompilePolicyProducesStableMetadata(t *testing.T) {
	sig := "ML-DSA-87"
	policy := Policy{
		Metadata: PolicyMetadata{
			ID:      "janus-test",
			Version: "v1",
			State:   PolicyStateActive,
		},
		Default: Config{
			Kem:           "ML-KEM-768",
			Sig:           &sig,
			HybridPeer:    "X25519MLKEM768",
			SecurityLevel: 3,
		},
	}

	compiled, err := CompilePolicy(policy, time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	if compiled.PolicyID != "janus-test" || compiled.Version != "v1" {
		t.Fatalf("unexpected compiled identity: %#v", compiled)
	}
	if compiled.CanonicalHash == "" {
		t.Fatal("expected canonical hash")
	}
	if !compiled.Active || compiled.Signature == nil {
		t.Fatalf("expected active policy signature, got %#v", compiled)
	}
}

func TestValidatePolicyRejectsUnknownAlgorithms(t *testing.T) {
	policy := Policy{
		Default: Config{
			Kem:           "UNKNOWN-KEM",
			HybridPeer:    "X25519MLKEM768",
			SecurityLevel: 3,
		},
	}

	err := ValidatePolicy(policy)
	if err == nil || !strings.Contains(err.Error(), "unknown algorithm") {
		t.Fatalf("expected unknown algorithm error, got %v", err)
	}
}
