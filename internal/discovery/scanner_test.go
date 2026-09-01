package discovery

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/yourorg/janus/internal/verification"
)

type discoveryVerifier struct{}

func (discoveryVerifier) Verify(ctx context.Context, req verification.VerificationRequest) (verification.VerificationOutcome, error) {
	evidence, err := ScanTarget(ctx, ScanRequest{
		TargetAddress: req.TargetAddress,
		ServerName:    req.ServerName,
		ClientCurves:  req.ClientCurves,
	})
	if err != nil {
		return verification.VerificationOutcome{}, err
	}
	return verification.VerificationOutcome{Evidence: evidence}, nil
}

func TestScanTargetObservesTLSPosture(t *testing.T) {
	result, err := verification.RunTLSVerification(context.Background(), verification.TLSHarnessConfig{
		Required:     verification.RequiredPosture{},
		ServerCurves: []tls.CurveID{tls.X25519MLKEM768},
		ClientCurves: []tls.CurveID{tls.X25519MLKEM768},
		Verifier:     discoveryVerifier{},
	})
	if err != nil {
		t.Fatalf("run discovery scan harness: %v", err)
	}
	if result.Evidence.Observed != "X25519MLKEM768" {
		t.Fatalf("expected observed hybrid posture, got %#v", result.Evidence)
	}
	if result.Evidence.ObservationLevel != "DISCOVERY_DIRECT" {
		t.Fatalf("expected direct discovery observation level, got %#v", result.Evidence)
	}
}
