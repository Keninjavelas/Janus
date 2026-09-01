package risk

import (
	"strings"

	"github.com/yourorg/janus/internal/discovery"
)

type Classification string
type Priority string

const (
	Low      Classification = "LOW"
	Medium   Classification = "MEDIUM"
	High     Classification = "HIGH"
	Critical Classification = "CRITICAL"

	P0 Priority = "P0"
	P1 Priority = "P1"
	P2 Priority = "P2"
	P3 Priority = "P3"
)

type Input struct {
	Asset                 discovery.CryptoAsset `json:"asset"`
	DataSensitivity       string                `json:"data_sensitivity,omitempty"`
	ConfidentialityYears  int                   `json:"confidentiality_years,omitempty"`
	AssetCriticality      string                `json:"asset_criticality,omitempty"`
	ExternalExposure      bool                  `json:"external_exposure,omitempty"`
	WorkloadType          string                `json:"workload_type,omitempty"`
	RetentionYears        int                   `json:"retention_years,omitempty"`
	MigrationReady        bool                  `json:"migration_ready"`
	CompatibilityBlockers []string              `json:"compatibility_blockers,omitempty"`
}

type Assessment struct {
	Risk     Classification `json:"risk"`
	Priority Priority       `json:"priority"`
	Reasons  []string       `json:"reasons"`
	Score    int            `json:"score"`
}

func Evaluate(input Input) Assessment {
	score := 0
	reasons := make([]string, 0, 8)

	if input.Asset.KeyExchange == "UNKNOWN" || input.Asset.KeyExchange == "" {
		score += 5
		reasons = append(reasons, "unknown cryptographic posture")
	} else if !input.Asset.QuantumSafe {
		score += 5
		reasons = append(reasons, "classical public-key cryptography")
	}

	lifetime := max(input.ConfidentialityYears, input.RetentionYears)
	switch {
	case lifetime >= 25:
		score += 4
		reasons = append(reasons, "long confidentiality requirement")
	case lifetime >= 10:
		score += 2
		reasons = append(reasons, "multi-year confidentiality requirement")
	}

	switch strings.ToLower(strings.TrimSpace(input.DataSensitivity)) {
	case "restricted", "high", "secret":
		score += 4
		reasons = append(reasons, "restricted data classification")
	case "confidential", "medium":
		score += 2
		reasons = append(reasons, "confidential data classification")
	}

	switch strings.ToLower(strings.TrimSpace(input.AssetCriticality)) {
	case "mission-critical", "critical":
		score += 3
		reasons = append(reasons, "critical workload")
	case "important", "high":
		score += 2
		reasons = append(reasons, "important workload")
	}

	if input.ExternalExposure {
		score += 3
		reasons = append(reasons, "externally exposed workload")
	}

	if len(input.CompatibilityBlockers) > 0 || !input.MigrationReady {
		score += 1
		reasons = append(reasons, "migration blockers present")
	}

	risk := Medium
	priority := P2
	switch {
	case score >= 12:
		risk = Critical
		priority = P0
	case score >= 8:
		risk = High
		priority = P1
	case score >= 4:
		risk = Medium
		priority = P2
	default:
		risk = Low
		priority = P3
	}

	return Assessment{
		Risk:     risk,
		Priority: priority,
		Reasons:  reasons,
		Score:    score,
	}
}

func max(values ...int) int {
	best := 0
	for _, value := range values {
		if value > best {
			best = value
		}
	}
	return best
}
