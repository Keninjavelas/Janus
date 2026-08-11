package cache

import (
	"testing"

	pb "github.com/yourorg/janus/api/proto/v1"
)

func TestKeyChangesWhenContextChanges(t *testing.T) {
	base := &pb.ContextRequest{
		Scenario:         "MICROSEGMENTATION",
		Region:           "EU",
		Risk:             4,
		DeviceType:       "iot",
		KeyRotationHours: 24,
		CertValidityDays: 365,
		LatencyBudgetMs:  1.5,
	}

	same := &pb.ContextRequest{
		Scenario:         base.Scenario,
		Region:           base.Region,
		Risk:             base.Risk,
		DeviceType:       base.DeviceType,
		KeyRotationHours: base.KeyRotationHours,
		CertValidityDays: base.CertValidityDays,
		LatencyBudgetMs:  base.LatencyBudgetMs,
	}

	changed := &pb.ContextRequest{
		Scenario:         base.Scenario,
		Region:           base.Region,
		Risk:             base.Risk,
		DeviceType:       base.DeviceType,
		KeyRotationHours: base.KeyRotationHours,
		CertValidityDays: base.CertValidityDays,
		LatencyBudgetMs:  0.5,
	}

	if Key(base) != Key(same) {
		t.Fatal("expected identical requests to produce the same cache key")
	}

	if Key(base) == Key(changed) {
		t.Fatal("expected a different latency budget to change the cache key")
	}
}
