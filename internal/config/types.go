// internal/config/types.go
package config

import "time"

type Policy struct {
	Metadata PolicyMetadata `yaml:"metadata,omitempty"`
	Default  Config         `yaml:"default"`
	Rules    []Rule         `yaml:"rules"`
}

type Config struct {
	Kem           string  `yaml:"kem"`
	Sig           *string `yaml:"sig"`
	HybridPeer    string  `yaml:"hybrid_peer"`
	SecurityLevel int     `yaml:"security_level"`
}

type Rule struct {
	Name   string    `yaml:"name"`
	Match  MatchCond `yaml:"match"`
	Config Config    `yaml:"config"`
}

type MatchCond struct {
	Scenario               string   `yaml:"scenario,omitempty"`
	RiskMin                *int     `yaml:"risk_min,omitempty"`
	RiskMax                *int     `yaml:"risk_max,omitempty"`
	MaxLatencyBudgetMs     *float64 `yaml:"max_latency_budget_ms,omitempty"`
	MinRamKb               *int64   `yaml:"min_ram_kb,omitempty"`
	RotationHoursMin       *int     `yaml:"rotation_hours_min,omitempty"`
	RotationHoursMax       *int     `yaml:"rotation_hours_max,omitempty"`
	CertValidityDaysMin    *int     `yaml:"cert_validity_days_min,omitempty"`
	CertValidityDaysMax    *int     `yaml:"cert_validity_days_max,omitempty"`
	PeerAlgorithmsContains []string `yaml:"peer_algorithms_contains,omitempty"`
	Region                 string   `yaml:"region,omitempty"`
	TimeFrom               string   `yaml:"time_from,omitempty"`
	TimeTo                 string   `yaml:"time_to,omitempty"`
	DeviceType             string   `yaml:"device_type,omitempty"`
}

// Helper to represent optional durations for lifecycle overrides
type LifecycleOverrides struct {
	RotationHours    *int
	CertValidityDays *int
}

// The loaded policy and a timestamp of last successful load
type LoadedPolicy struct {
	Policy        Policy               `json:"policy"`
	LoadedAt      time.Time            `json:"loaded_at"`
	Version       string               `json:"version"`
	PolicyID      string               `json:"policy_id"`
	CreatedAt     time.Time            `json:"created_at"`
	Active        bool                 `json:"active"`
	State         PolicyLifecycleState `json:"state"`
	CanonicalHash string               `json:"canonical_hash"`
	Signature     *PolicySignature     `json:"signature,omitempty"`
}
