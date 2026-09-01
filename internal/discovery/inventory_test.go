package discovery

import (
	"testing"
	"time"

	"github.com/yourorg/janus/internal/verification"
)

func TestObserveEvidenceDeduplicatesAndPreservesFirstSeen(t *testing.T) {
	inventory := NewInventory()
	first := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	second := first.Add(10 * time.Minute)

	evidence := verification.VerificationEvidence{
		Observed:         "X25519",
		Status:           verification.NonCompliant,
		ObservationLevel: "WIRE_LIVE",
		TLSVersion:       "TLS 1.3",
		Flow: &verification.FlowMetadata{
			Src: "127.0.0.1:8443",
			Dst: "127.0.0.1:50123",
		},
		Timestamp: first,
	}
	asset, err := inventory.ObserveEvidence(evidence)
	if err != nil {
		t.Fatalf("observe first evidence: %v", err)
	}
	if asset.KeyExchangeClass != "CLASSICAL" {
		t.Fatalf("expected classical key exchange class, got %s", asset.KeyExchangeClass)
	}

	evidence.Timestamp = second
	evidence.Observed = "X25519MLKEM768"
	if _, err := inventory.ObserveEvidence(evidence); err != nil {
		t.Fatalf("observe second evidence: %v", err)
	}

	assets := inventory.List(0)
	if len(assets) != 1 {
		t.Fatalf("expected one deduplicated asset, got %d", len(assets))
	}
	if !assets[0].FirstSeen.Equal(first) || !assets[0].LastSeen.Equal(second) {
		t.Fatalf("unexpected timestamps: %#v", assets[0])
	}
}
