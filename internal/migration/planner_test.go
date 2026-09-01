package migration

import (
	"testing"
	"time"

	"github.com/yourorg/janus/internal/discovery"
	"github.com/yourorg/janus/internal/risk"
	"github.com/yourorg/janus/internal/verification"
)

func TestVerifyPlanRequiresMatchingWireEvidence(t *testing.T) {
	plan := BuildPlan(discovery.CryptoAsset{
		ID:          "127.0.0.1:8443/TLS",
		Host:        "127.0.0.1",
		KeyExchange: "X25519",
		QuantumSafe: false,
	}, risk.Assessment{Risk: risk.Critical, Priority: risk.P0}, nil, ModeEnforce)

	mismatch := VerifyPlan(plan, verification.VerificationEvidence{
		Required:     "X25519MLKEM768",
		Observed:     "X25519",
		Status:       verification.NonCompliant,
		ConnectionID: "conn-1",
		Timestamp:    time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC),
	})
	if mismatch.VerificationState != VerificationFailed {
		t.Fatalf("expected mismatch verification failure, got %#v", mismatch)
	}

	match := VerifyPlan(plan, verification.VerificationEvidence{
		Required:     "X25519MLKEM768",
		Observed:     "X25519MLKEM768",
		Status:       verification.Compliant,
		ConnectionID: "conn-2",
		Timestamp:    time.Date(2026, 8, 12, 0, 1, 0, 0, time.UTC),
	})
	if match.VerificationState != VerificationSuccessful || match.Status != StatusVerified {
		t.Fatalf("expected successful verification, got %#v", match)
	}
}
