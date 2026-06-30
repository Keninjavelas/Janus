// internal/cache/decision_cache.go
package cache

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"

    "github.com/hashicorp/golang-lru"
    pb "github.com/yourorg/janus/api/proto/v1"
)

// CachedDecision holds the algorithm config and a timestamp so we can expire it.
type CachedDecision struct {
    Config    *pb.AlgorithmConfig
    Timestamp time.Time
}

var (
    cache *lru.Cache
    mu    sync.RWMutex
)

// InitCache creates the LRU cache with the given size (e.g., 1024 entries).
func InitCache(size int) error {
    var err error
    cache, err = lru.New(size)
    return err
}

// Key generates a unique hash from the request fields that affect the decision.
// We include scenario, risk, region, device_type, and key_rotation_hours.
func Key(req *pb.ContextRequest) string {
    data := req.Scenario +
        string(req.Risk) +
        req.Region +
        req.DeviceType +
        string(req.KeyRotationHours) +
        string(req.CertValidityDays)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// Get retrieves a cached decision if it exists and is still fresh (TTL = 5 seconds).
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
        // Expired – remove it
        cache.Remove(key)
    }
    return nil, false
}

// Set stores a decision in the cache.
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

// Clear purges the entire cache (useful for testing).
func Clear() {
    mu.Lock()
    defer mu.Unlock()
    if cache != nil {
        cache.Purge()
    }
}
