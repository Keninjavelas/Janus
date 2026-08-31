package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/janus/internal/algorithms"
	"gopkg.in/yaml.v3"
)

type PolicyLifecycleState string

const (
	PolicyStateDraft  PolicyLifecycleState = "draft"
	PolicyStateActive PolicyLifecycleState = "active"
)

type PolicySignature struct {
	Algorithm string    `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`
	Signer    string    `yaml:"signer,omitempty" json:"signer,omitempty"`
	Value     string    `yaml:"value,omitempty" json:"value,omitempty"`
	SignedAt  time.Time `yaml:"signed_at,omitempty" json:"signed_at,omitempty"`
}

type PolicyMetadata struct {
	ID        string               `yaml:"id,omitempty" json:"id,omitempty"`
	Version   string               `yaml:"version,omitempty" json:"version,omitempty"`
	CreatedAt time.Time            `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	Active    bool                 `yaml:"active,omitempty" json:"active,omitempty"`
	State     PolicyLifecycleState `yaml:"state,omitempty" json:"state,omitempty"`
	Signature *PolicySignature     `yaml:"signature,omitempty" json:"signature,omitempty"`
}

type CompiledPolicy struct {
	Policy        Policy               `json:"policy"`
	PolicyID      string               `json:"policy_id"`
	Version       string               `json:"version"`
	CreatedAt     time.Time            `json:"created_at"`
	Active        bool                 `json:"active"`
	State         PolicyLifecycleState `json:"state"`
	CanonicalHash string               `json:"canonical_hash"`
	Signature     *PolicySignature     `json:"signature,omitempty"`
}

func ParsePolicyYAML(data []byte) (Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func ValidatePolicy(policy Policy) error {
	registry := algorithms.DefaultRegistry()

	if err := validateConfig(policy.Default, registry, "default"); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(policy.Rules))
	for i, rule := range policy.Rules {
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("rule %d has no name", i)
		}
		if _, exists := seen[rule.Name]; exists {
			return fmt.Errorf("duplicate rule name %q", rule.Name)
		}
		seen[rule.Name] = struct{}{}
		if err := validateMatch(rule.Match, rule.Name); err != nil {
			return err
		}
		if err := validateConfig(rule.Config, registry, fmt.Sprintf("rule %q", rule.Name)); err != nil {
			return err
		}
	}
	return nil
}

func CompilePolicy(policy Policy, now time.Time) (*LoadedPolicy, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}

	canonical, err := CanonicalizePolicy(policy)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(canonical)
	canonicalHash := hex.EncodeToString(hash[:])

	metadata := policy.Metadata
	policyID := metadata.ID
	if policyID == "" {
		policyID = "janus-policy"
	}

	state := metadata.State
	if state == "" {
		state = PolicyStateActive
	}

	createdAt := metadata.CreatedAt
	if createdAt.IsZero() {
		createdAt = now.UTC()
	}

	version := metadata.Version
	if version == "" {
		version = canonicalHash
	}

	active := metadata.Active
	if state == PolicyStateActive {
		active = true
	}

	signature := metadata.Signature
	if active && signature == nil {
		signature = &PolicySignature{
			Algorithm: "sha256",
			Signer:    "manual-review",
			Value:     canonicalHash,
			SignedAt:  now.UTC(),
		}
	}

	return &LoadedPolicy{
		Policy:        policy,
		LoadedAt:      now.UTC(),
		Version:       version,
		PolicyID:      policyID,
		CreatedAt:     createdAt,
		Active:        active,
		State:         state,
		CanonicalHash: canonicalHash,
		Signature:     signature,
	}, nil
}

func CanonicalizePolicy(policy Policy) ([]byte, error) {
	type canonicalPolicy struct {
		Default Config `json:"default"`
		Rules   []Rule `json:"rules"`
	}
	return json.Marshal(canonicalPolicy{
		Default: policy.Default,
		Rules:   policy.Rules,
	})
}

func validateMatch(match MatchCond, ruleName string) error {
	if match.RiskMin != nil && match.RiskMax != nil && *match.RiskMin > *match.RiskMax {
		return fmt.Errorf("%s has invalid risk range", ruleName)
	}
	if match.RotationHoursMin != nil && match.RotationHoursMax != nil && *match.RotationHoursMin > *match.RotationHoursMax {
		return fmt.Errorf("%s has invalid rotation-hour range", ruleName)
	}
	if match.CertValidityDaysMin != nil && match.CertValidityDaysMax != nil && *match.CertValidityDaysMin > *match.CertValidityDaysMax {
		return fmt.Errorf("%s has invalid cert-validity range", ruleName)
	}
	return nil
}

func validateConfig(cfg Config, registry algorithms.Registry, scope string) error {
	if cfg.SecurityLevel < 1 || cfg.SecurityLevel > 5 {
		return fmt.Errorf("%s has invalid security_level %d", scope, cfg.SecurityLevel)
	}

	kem, err := registry.MustResolve(cfg.Kem)
	if err != nil {
		return fmt.Errorf("%s kem: %w", scope, err)
	}
	if kem.AlgorithmType != algorithms.TypeKEM {
		return fmt.Errorf("%s kem %q is not a KEM", scope, cfg.Kem)
	}

	if cfg.HybridPeer != "" {
		peer, err := registry.MustResolve(cfg.HybridPeer)
		if err != nil {
			return fmt.Errorf("%s hybrid_peer: %w", scope, err)
		}
		if peer.AlgorithmType != algorithms.TypeKeyExchange {
			return fmt.Errorf("%s hybrid_peer %q is not a key exchange", scope, cfg.HybridPeer)
		}
	}

	if cfg.Sig != nil && strings.TrimSpace(*cfg.Sig) != "" {
		sig, err := registry.MustResolve(*cfg.Sig)
		if err != nil {
			return fmt.Errorf("%s sig: %w", scope, err)
		}
		if sig.AlgorithmType != algorithms.TypeSignature {
			return fmt.Errorf("%s sig %q is not a signature algorithm", scope, *cfg.Sig)
		}
	}

	return nil
}
