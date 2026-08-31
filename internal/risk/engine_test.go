package risk

import (
	"testing"

	"github.com/yourorg/janus/internal/discovery"
)

func TestEvaluateMonotonicityForSensitivityAndLifetime(t *testing.T) {
	base := Evaluate(Input{
		Asset: discovery.CryptoAsset{
			KeyExchange: "X25519",
			QuantumSafe: false,
		},
		DataSensitivity:      "confidential",
		ConfidentialityYears: 5,
	})

	elevated := Evaluate(Input{
		Asset: discovery.CryptoAsset{
			KeyExchange: "X25519",
			QuantumSafe: false,
		},
		DataSensitivity:      "restricted",
		ConfidentialityYears: 30,
		ExternalExposure:     true,
	})

	if elevated.Score < base.Score {
		t.Fatalf("expected elevated risk inputs not to lower score: base=%#v elevated=%#v", base, elevated)
	}
	if elevated.Priority > base.Priority {
		t.Fatalf("expected elevated risk inputs not to lower priority: base=%#v elevated=%#v", base, elevated)
	}
}
