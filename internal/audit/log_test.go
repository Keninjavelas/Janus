package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log := NewLog(path)

	if _, err := log.Append(Event{
		Type:      "policy_activated",
		Timestamp: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC),
		Payload:   map[string]any{"policy_id": "janus-policy"},
	}); err != nil {
		t.Fatalf("append first: %v", err)
	}
	if _, err := log.Append(Event{
		Type:      "connection_observed",
		Timestamp: time.Date(2026, 8, 12, 0, 1, 0, 0, time.UTC),
		Payload:   map[string]any{"observed": "X25519"},
	}); err != nil {
		t.Fatalf("append second: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"index":0,"type":"policy_activated","timestamp":"2026-08-12T00:00:00Z","payload":{"policy_id":"janus-policy"},"hash":"tampered"}`+"\n"), 0o644); err != nil {
		t.Fatalf("tamper audit log: %v", err)
	}

	result, err := log.Verify()
	if err != nil {
		t.Fatalf("verify tampered log: %v", err)
	}
	if result.Valid {
		t.Fatalf("expected tampered log to fail verification: %#v", result)
	}
}
