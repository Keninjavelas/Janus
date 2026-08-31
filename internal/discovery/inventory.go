package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/janus/internal/algorithms"
	"github.com/yourorg/janus/internal/verification"
)

type WorkloadIdentity struct {
	PID                   int    `json:"pid,omitempty" yaml:"pid,omitempty"`
	Executable            string `json:"executable,omitempty" yaml:"executable,omitempty"`
	ProcessStartTimeTicks uint64 `json:"process_start_time_ticks,omitempty" yaml:"process_start_time_ticks,omitempty"`
	SocketInode           string `json:"socket_inode,omitempty" yaml:"socket_inode,omitempty"`
}

type CryptoAsset struct {
	ID                string                      `json:"id" yaml:"id"`
	Host              string                      `json:"host" yaml:"host"`
	Port              int                         `json:"port" yaml:"port"`
	Protocol          string                      `json:"protocol" yaml:"protocol"`
	TLSAvailable      bool                        `json:"tls_available" yaml:"tls_available"`
	TLSVersion        string                      `json:"tls_version,omitempty" yaml:"tls_version,omitempty"`
	KeyExchange       string                      `json:"key_exchange,omitempty" yaml:"key_exchange,omitempty"`
	KeyExchangeClass  algorithms.KeyExchangeClass `json:"key_exchange_class" yaml:"key_exchange_class"`
	QuantumSafe       bool                        `json:"quantum_safe" yaml:"quantum_safe"`
	Signature         string                      `json:"signature,omitempty" yaml:"signature,omitempty"`
	RequiredPosture   string                      `json:"required_posture,omitempty" yaml:"required_posture,omitempty"`
	CryptoStatus      string                      `json:"crypto_status,omitempty" yaml:"crypto_status,omitempty"`
	AttributionStatus string                      `json:"attribution_status,omitempty" yaml:"attribution_status,omitempty"`
	Workload          *WorkloadIdentity           `json:"workload,omitempty" yaml:"workload,omitempty"`
	EvidenceSource    string                      `json:"evidence_source" yaml:"evidence_source"`
	FirstSeen         time.Time                   `json:"first_seen" yaml:"first_seen"`
	LastSeen          time.Time                   `json:"last_seen" yaml:"last_seen"`
	Stale             bool                        `json:"stale,omitempty" yaml:"stale,omitempty"`
}

type CBOM struct {
	GeneratedAt time.Time     `json:"generated_at" yaml:"generated_at"`
	Assets      []CryptoAsset `json:"assets" yaml:"assets"`
}

type Inventory struct {
	mu     sync.RWMutex
	now    func() time.Time
	assets map[string]CryptoAsset
}

func NewInventory() *Inventory {
	return &Inventory{
		now:    time.Now,
		assets: make(map[string]CryptoAsset),
	}
}

func (i *Inventory) ObserveEvidence(evidence verification.VerificationEvidence) (CryptoAsset, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	host, port := assetEndpoint(evidence)
	if host == "" {
		return CryptoAsset{}, fmt.Errorf("verification evidence did not identify an asset endpoint")
	}

	id := fmt.Sprintf("%s:%d/TLS", host, port)
	now := evidence.Timestamp
	if now.IsZero() {
		now = i.now().UTC()
	}

	class := algorithms.KeyExchangeClassUnknown
	quantumSafe := false
	if entry, ok := algorithms.DefaultRegistry().Resolve(evidence.Observed); ok {
		class = entry.KeyExchangeClass
		quantumSafe = entry.QuantumSafe
	}

	asset, exists := i.assets[id]
	if !exists {
		asset = CryptoAsset{
			ID:           id,
			Host:         host,
			Port:         port,
			Protocol:     "TLS",
			TLSAvailable: true,
			FirstSeen:    now.UTC(),
		}
	}

	asset.TLSAvailable = evidence.TLSVersion != "" || evidence.Observed != ""
	asset.TLSVersion = evidence.TLSVersion
	asset.KeyExchange = valueOrUnknown(evidence.Observed)
	asset.KeyExchangeClass = class
	asset.QuantumSafe = quantumSafe
	asset.Signature = evidence.CertificateSignature
	asset.RequiredPosture = evidence.Required
	asset.CryptoStatus = string(evidence.Status)
	asset.AttributionStatus = string(evidence.AttributionStatus)
	asset.EvidenceSource = evidence.ObservationLevel
	asset.LastSeen = now.UTC()
	if evidence.Workload != nil {
		asset.Workload = &WorkloadIdentity{
			PID:                   evidence.Workload.PID,
			Executable:            evidence.Workload.Executable,
			ProcessStartTimeTicks: evidence.Workload.ProcessStartTimeTicks,
			SocketInode:           evidence.Workload.SocketInode,
		}
	}

	i.assets[id] = asset
	return asset, nil
}

func (i *Inventory) List(staleAfter time.Duration) []CryptoAsset {
	i.mu.RLock()
	defer i.mu.RUnlock()

	out := make([]CryptoAsset, 0, len(i.assets))
	now := i.now().UTC()
	for _, asset := range i.assets {
		clone := asset
		if staleAfter > 0 && !asset.LastSeen.IsZero() && now.Sub(asset.LastSeen) > staleAfter {
			clone.Stale = true
		}
		out = append(out, clone)
	}
	sort.Slice(out, func(a, b int) bool {
		return out[a].ID < out[b].ID
	})
	return out
}

func (i *Inventory) CBOMJSON(staleAfter time.Duration) ([]byte, error) {
	return json.MarshalIndent(CBOM{
		GeneratedAt: i.now().UTC(),
		Assets:      i.List(staleAfter),
	}, "", "  ")
}

func assetEndpoint(evidence verification.VerificationEvidence) (string, int) {
	if evidence.Flow == nil {
		return "", 0
	}

	target := evidence.Flow.Dst
	if evidence.ObservationLevel == "WIRE_LIVE" {
		target = evidence.Flow.Src
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0
	}
	return host, port
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "UNKNOWN"
	}
	return value
}
