package algorithms

import (
	"fmt"
	"strings"
)

type Type string
type Lifecycle string
type KeyExchangeClass string

const (
	TypeKeyExchange Type = "KEY_EXCHANGE"
	TypeKEM         Type = "KEM"
	TypeSignature   Type = "SIGNATURE"

	LifecycleApproved     Lifecycle = "APPROVED"
	LifecycleTransitional Lifecycle = "TRANSITIONAL"
	LifecycleExperimental Lifecycle = "EXPERIMENTAL"
	LifecycleDeprecated   Lifecycle = "DEPRECATED"
	LifecycleDisallowed   Lifecycle = "DISALLOWED"

	KeyExchangeClassClassical KeyExchangeClass = "CLASSICAL"
	KeyExchangeClassHybridPQ  KeyExchangeClass = "HYBRID_PQ"
	KeyExchangeClassUnknown   KeyExchangeClass = "UNKNOWN"
)

type Metadata struct {
	CanonicalName    string           `json:"canonical_name"`
	Aliases          []string         `json:"aliases,omitempty"`
	AlgorithmType    Type             `json:"algorithm_type"`
	Standard         string           `json:"standard,omitempty"`
	QuantumSafe      bool             `json:"quantum_safe"`
	Hybrid           bool             `json:"hybrid"`
	SecurityCategory int              `json:"security_category,omitempty"`
	Lifecycle        Lifecycle        `json:"lifecycle"`
	RuntimeSupported bool             `json:"runtime_supported"`
	KeyExchangeClass KeyExchangeClass `json:"key_exchange_class,omitempty"`
}

type Registry struct {
	byNormalized map[string]Metadata
	byCanonical  map[string]Metadata
}

func DefaultRegistry() Registry {
	entries := []Metadata{
		{
			CanonicalName:    "X25519",
			AlgorithmType:    TypeKeyExchange,
			Standard:         "RFC 8446",
			QuantumSafe:      false,
			Hybrid:           false,
			Lifecycle:        LifecycleApproved,
			RuntimeSupported: true,
			KeyExchangeClass: KeyExchangeClassClassical,
		},
		{
			CanonicalName:    "X25519MLKEM768",
			Aliases:          []string{"X25519Kyber768Draft00", "X25519_KYBER768"},
			AlgorithmType:    TypeKeyExchange,
			Standard:         "RFC 10024",
			QuantumSafe:      true,
			Hybrid:           true,
			SecurityCategory: 3,
			Lifecycle:        LifecycleTransitional,
			RuntimeSupported: true,
			KeyExchangeClass: KeyExchangeClassHybridPQ,
		},
		{
			CanonicalName:    "ML-KEM-512",
			Aliases:          []string{"MLKEM512", "Kyber512"},
			AlgorithmType:    TypeKEM,
			Standard:         "Pre-FIPS research profile",
			QuantumSafe:      true,
			SecurityCategory: 1,
			Lifecycle:        LifecycleExperimental,
			RuntimeSupported: false,
		},
		{
			CanonicalName:    "ML-KEM-768",
			Aliases:          []string{"MLKEM768", "Kyber768"},
			AlgorithmType:    TypeKEM,
			Standard:         "FIPS 203",
			QuantumSafe:      true,
			SecurityCategory: 3,
			Lifecycle:        LifecycleApproved,
			RuntimeSupported: false,
		},
		{
			CanonicalName:    "ML-KEM-1024",
			Aliases:          []string{"MLKEM1024", "Kyber1024"},
			AlgorithmType:    TypeKEM,
			Standard:         "FIPS 203",
			QuantumSafe:      true,
			SecurityCategory: 5,
			Lifecycle:        LifecycleApproved,
			RuntimeSupported: false,
		},
		{
			CanonicalName:    "ML-DSA-44",
			Aliases:          []string{"MLDSA44", "Dilithium2"},
			AlgorithmType:    TypeSignature,
			Standard:         "FIPS 204",
			QuantumSafe:      true,
			SecurityCategory: 2,
			Lifecycle:        LifecycleTransitional,
			RuntimeSupported: false,
		},
		{
			CanonicalName:    "ML-DSA-65",
			Aliases:          []string{"MLDSA65", "Dilithium3"},
			AlgorithmType:    TypeSignature,
			Standard:         "FIPS 204",
			QuantumSafe:      true,
			SecurityCategory: 3,
			Lifecycle:        LifecycleApproved,
			RuntimeSupported: false,
		},
		{
			CanonicalName:    "ML-DSA-87",
			Aliases:          []string{"MLDSA87", "Dilithium5"},
			AlgorithmType:    TypeSignature,
			Standard:         "FIPS 204",
			QuantumSafe:      true,
			SecurityCategory: 5,
			Lifecycle:        LifecycleApproved,
			RuntimeSupported: false,
		},
		{
			CanonicalName:    "SLH-DSA-128s",
			Aliases:          []string{"SLHDSA128S"},
			AlgorithmType:    TypeSignature,
			Standard:         "FIPS 205",
			QuantumSafe:      true,
			SecurityCategory: 1,
			Lifecycle:        LifecycleExperimental,
			RuntimeSupported: false,
		},
	}

	byNormalized := make(map[string]Metadata, len(entries)*2)
	byCanonical := make(map[string]Metadata, len(entries))
	for _, entry := range entries {
		byCanonical[entry.CanonicalName] = entry
		byNormalized[normalize(entry.CanonicalName)] = entry
		for _, alias := range entry.Aliases {
			byNormalized[normalize(alias)] = entry
		}
	}
	return Registry{
		byNormalized: byNormalized,
		byCanonical:  byCanonical,
	}
}

func (r Registry) Resolve(name string) (Metadata, bool) {
	entry, ok := r.byNormalized[normalize(name)]
	return entry, ok
}

func (r Registry) MustResolve(name string) (Metadata, error) {
	entry, ok := r.Resolve(name)
	if !ok {
		return Metadata{}, fmt.Errorf("unknown algorithm %q", name)
	}
	return entry, nil
}

func (r Registry) All() []Metadata {
	entries := make([]Metadata, 0, len(r.byCanonical))
	for _, entry := range r.byCanonical {
		entries = append(entries, entry)
	}
	return entries
}

func normalize(name string) string {
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	return strings.ToUpper(replacer.Replace(strings.TrimSpace(name)))
}
