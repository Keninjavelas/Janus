package verification

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"crypto/tls"
	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/config"
	"github.com/yourorg/janus/internal/fallback"
)

var initPolicyOnce sync.Once
var initPolicyErr error

func TestTLSVerificationCompliant(t *testing.T) {
	required := mustRequiredPosture(t)

	result, err := RunTLSVerification(context.Background(), TLSHarnessConfig{
		Required:           required,
		ServerCurves:       []tls.CurveID{tls.X25519MLKEM768},
		ClientCurves:       []tls.CurveID{tls.X25519MLKEM768},
		Verifier:           helperProcessVerifier(t),
		ApplicationPayload: []byte("janus-application-data"),
	})
	if err != nil {
		t.Fatalf("run tls verification: %v", err)
	}

	if result.Evidence.Status != Compliant {
		t.Fatalf("expected status %s, got %s (%s)", Compliant, result.Evidence.Status, result.Evidence.Details)
	}
	if result.Evidence.Required != "X25519MLKEM768" {
		t.Fatalf("expected required X25519MLKEM768, got %s", result.Evidence.Required)
	}
	if result.Evidence.Observed != "X25519MLKEM768" {
		t.Fatalf("expected observed X25519MLKEM768, got %s", result.Evidence.Observed)
	}
	if result.Evidence.Source != "tls-verifier" {
		t.Fatalf("expected source tls-verifier, got %s", result.Evidence.Source)
	}
	if result.Evidence.ConnectionID == "" {
		t.Fatal("expected connection id to be populated")
	}
	if result.Evidence.DecisionID == "" {
		t.Fatal("expected decision id to be populated")
	}
	if result.Evidence.PolicyVersion == "" {
		t.Fatal("expected policy version to be populated")
	}
	if result.Evidence.ApplicationAccess != AccessAllowed {
		t.Fatalf("expected application access %s, got %s", AccessAllowed, result.Evidence.ApplicationAccess)
	}
	if result.Evidence.ObservationLevel != "SUBPROCESS_DIRECT_TLS_OBSERVATION" {
		t.Fatalf("expected direct subprocess observation level, got %s", result.Evidence.ObservationLevel)
	}
	if !result.TrafficAllowed {
		t.Fatal("expected compliant traffic to be allowed")
	}
	if result.ApplicationACK != "janus-ok" {
		t.Fatalf("expected application ack janus-ok, got %s", result.ApplicationACK)
	}
}

func TestTLSVerificationDowngradeBlocksTraffic(t *testing.T) {
	required := mustRequiredPosture(t)

	result, err := RunTLSVerification(context.Background(), TLSHarnessConfig{
		Required:           required,
		ServerCurves:       []tls.CurveID{tls.X25519},
		ClientCurves:       []tls.CurveID{tls.X25519},
		Verifier:           helperProcessVerifier(t),
		ApplicationPayload: []byte("janus-application-data"),
	})
	if err != nil {
		t.Fatalf("run tls verification: %v", err)
	}

	if result.Evidence.Status != NonCompliant {
		t.Fatalf("expected status %s, got %s (%s)", NonCompliant, result.Evidence.Status, result.Evidence.Details)
	}
	if result.Evidence.Required != "X25519MLKEM768" {
		t.Fatalf("expected required X25519MLKEM768, got %s", result.Evidence.Required)
	}
	if result.Evidence.Observed != "X25519" {
		t.Fatalf("expected observed X25519, got %s", result.Evidence.Observed)
	}
	if result.Evidence.ApplicationAccess != AccessDenied {
		t.Fatalf("expected application access %s, got %s", AccessDenied, result.Evidence.ApplicationAccess)
	}
	if result.TrafficAllowed {
		t.Fatal("expected non-compliant traffic to be blocked")
	}
	if result.ApplicationACK != "" {
		t.Fatalf("expected no application ack, got %s", result.ApplicationACK)
	}
}

func TestTLSVerificationUnverifiedBlocksTraffic(t *testing.T) {
	required := mustRequiredPosture(t)

	result, err := RunTLSVerification(context.Background(), TLSHarnessConfig{
		Required:           required,
		ServerCurves:       []tls.CurveID{tls.X25519MLKEM768},
		ClientCurves:       []tls.CurveID{tls.X25519MLKEM768},
		Verifier:           ExecutableVerifier{Path: "does-not-exist-verifier"},
		ApplicationPayload: []byte("janus-application-data"),
	})
	if err != nil {
		t.Fatalf("run tls verification: %v", err)
	}

	if result.Evidence.Status != Unverified {
		t.Fatalf("expected status %s, got %s", Unverified, result.Evidence.Status)
	}
	if result.Evidence.ApplicationAccess != AccessDenied {
		t.Fatalf("expected application access %s, got %s", AccessDenied, result.Evidence.ApplicationAccess)
	}
	if result.TrafficAllowed {
		t.Fatal("expected unverified traffic to be blocked")
	}
	if result.ApplicationACK != "" {
		t.Fatalf("expected no application ack, got %s", result.ApplicationACK)
	}
}

func TestBuildEvidenceUnverifiedWhenObservedMissing(t *testing.T) {
	evidence := BuildEvidence(
		RequiredPosture{KeyExchange: "X25519MLKEM768", PolicyVersion: "test-policy"},
		"decision-1",
		"",
		"tls-verifier",
		"conn-1",
		nil,
		"",
		time.Now(),
	)

	if evidence.Status != Unverified {
		t.Fatalf("expected status %s, got %s", Unverified, evidence.Status)
	}
	if evidence.Details == "" {
		t.Fatal("expected detail to explain why evidence is unverified")
	}
	if evidence.ApplicationAccess != AccessDenied {
		t.Fatalf("expected application access %s, got %s", AccessDenied, evidence.ApplicationAccess)
	}
}

func TestVerifierCLIHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_JANUS_VERIFIER_HELPER") != "1" {
		return
	}
	if err := RunVerifierCLI(os.Stdin, os.Stdout); err != nil {
		t.Fatalf("run verifier cli: %v", err)
	}
	os.Exit(0)
}

func TestCurveNamesRoundTrip(t *testing.T) {
	input := []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	names := CurveNames(input)
	ids, err := CurveIDs(names)
	if err != nil {
		t.Fatalf("curve ids: %v", err)
	}
	if len(ids) != len(input) {
		t.Fatalf("expected %d ids, got %d", len(input), len(ids))
	}
	for i := range ids {
		if ids[i] != input[i] {
			t.Fatalf("expected curve %v at index %d, got %v", input[i], i, ids[i])
		}
	}
}

func TestVerificationRequestRoundTrip(t *testing.T) {
	req := VerificationRequest{
		DecisionID:   "decision-1",
		ConnectionID: "conn-1",
		Required: RequiredPosture{
			KeyExchange:   "X25519MLKEM768",
			PolicyVersion: "policy-artifact-hash",
		},
		TargetAddress:        "127.0.0.1:443",
		ServerName:           "janus.local",
		ClientCurves:         []string{"X25519MLKEM768"},
		ObservationInterface: "lo",
		CaptureTimeoutMs:     1500,
		ApplicationPayload:   "janus-application-data",
	}

	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var decoded VerificationRequest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	if decoded.DecisionID != req.DecisionID || decoded.ConnectionID != req.ConnectionID {
		t.Fatal("verification request lost identity fields during round-trip")
	}
	if decoded.ObservationInterface != req.ObservationInterface || decoded.CaptureTimeoutMs != req.CaptureTimeoutMs {
		t.Fatal("verification request lost live capture fields during round-trip")
	}
}

func mustRequiredPosture(t *testing.T) RequiredPosture {
	t.Helper()
	initPolicyOnce.Do(func() {
		policyPath := filepath.Join("..", "..", "configs", "policy.yaml")
		initPolicyErr = config.InitLoader(policyPath)
	})
	if initPolicyErr != nil {
		t.Fatalf("init policy loader: %v", initPolicyErr)
	}

	req := &pb.ContextRequest{
		Scenario:        "MICROSEGMENTATION",
		Risk:            3,
		LatencyBudgetMs: 2.0,
	}
	cfg, err := fallback.EvaluateWithFallback(context.Background(), req)
	if err != nil {
		t.Fatalf("evaluate with fallback: %v", err)
	}

	required := RequiredPostureFromAlgorithmConfig(cfg, config.GetPolicyVersion())
	if required.KeyExchange != "X25519MLKEM768" {
		t.Fatalf("expected required key exchange X25519MLKEM768, got %s", required.KeyExchange)
	}
	return required
}

func helperProcessVerifier(t *testing.T) Verifier {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	return ExecutableVerifier{
		Path: exe,
		Args: []string{"-test.run=TestVerifierCLIHelperProcess"},
		Env:  []string{"GO_WANT_JANUS_VERIFIER_HELPER=1"},
	}
}
