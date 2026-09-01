package verification

import (
	"testing"
	"time"

	"github.com/yourorg/janus/internal/verification/attribution"
)

func TestUnverifiedEvidenceNeverAllowsApplicationTraffic(t *testing.T) {
	evidence := BuildEvidence(
		RequiredPosture{KeyExchange: "X25519MLKEM768", PolicyVersion: "policy-v1"},
		"decision-1",
		"",
		"tls-verifier",
		"conn-1",
		nil,
		"",
		time.Now(),
	)
	if evidence.Status != Unverified {
		t.Fatalf("expected unverified status, got %s", evidence.Status)
	}
	if evidence.ApplicationAccess != AccessDenied {
		t.Fatalf("expected denied application access, got %s", evidence.ApplicationAccess)
	}
}

func TestNonCompliantEvidenceNeverAllowsApplicationTraffic(t *testing.T) {
	evidence := BuildEvidence(
		RequiredPosture{KeyExchange: "X25519MLKEM768", PolicyVersion: "policy-v1"},
		"decision-2",
		"X25519",
		"tls-verifier",
		"conn-2",
		nil,
		"",
		time.Now(),
	)
	if evidence.Status != NonCompliant {
		t.Fatalf("expected non-compliant status, got %s", evidence.Status)
	}
	if evidence.ApplicationAccess != AccessDenied {
		t.Fatalf("expected denied application access, got %s", evidence.ApplicationAccess)
	}
}

func TestAmbiguousOwnershipNeverBecomesAttributed(t *testing.T) {
	evidence := VerificationEvidence{}
	ApplyAttributionResult(&evidence, attribution.Result{
		Status: attribution.Ambiguous,
		Detail: "multiple plausible owners",
	})
	if evidence.AttributionStatus != Ambiguous {
		t.Fatalf("expected ambiguous attribution status, got %s", evidence.AttributionStatus)
	}
	if evidence.Workload != nil {
		t.Fatalf("expected no workload metadata on ambiguous attribution, got %#v", evidence.Workload)
	}
}
