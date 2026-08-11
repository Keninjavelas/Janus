package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru"
	pb "github.com/yourorg/janus/api/proto/v1"
)

type CachedDecision struct {
	Config    *pb.AlgorithmConfig
	Timestamp time.Time
}

var (
	cache *lru.Cache
	mu    sync.RWMutex
)

func InitCache(size int) error {
	var err error
	cache, err = lru.New(size)
	return err
}

// Key generates a stable hash from the request fields that affect the decision.
// Two requests whose security-relevant context differs must never incorrectly
// share a cached decision. This is still a simplified key, but it avoids
// integer-to-rune conversion bugs and covers the current request surface.
func Key(req *pb.ContextRequest) string {
	data := fmt.Sprintf(
		"scenario=%s|risk=%d|region=%s|device_type=%s|rotation=%d|cert_days=%d|latency=%.3f",
		req.Scenario,
		req.Risk,
		req.Region,
		req.DeviceType,
		req.KeyRotationHours,
		req.CertValidityDays,
		req.LatencyBudgetMs,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func Get(req *pb.ContextRequest) (*pb.AlgorithmConfig, bool) {
	mu.RLock()
	defer mu.RUnlock()
	if cache == nil {
		return nil, false
	}

	key := Key(req)
	if val, ok := cache.Get(key); ok {
		entry := val.(CachedDecision)
		if time.Since(entry.Timestamp) < 5*time.Second {
			return entry.Config, true
		}
		cache.Remove(key)
	}

	return nil, false
}

func Set(req *pb.ContextRequest, cfg *pb.AlgorithmConfig) {
	mu.Lock()
	defer mu.Unlock()
	if cache == nil {
		return
	}

	cache.Add(Key(req), CachedDecision{
		Config:    cfg,
		Timestamp: time.Now(),
	})
}

func Clear() {
	mu.Lock()
	defer mu.Unlock()
	if cache != nil {
		cache.Purge()
	}
}
