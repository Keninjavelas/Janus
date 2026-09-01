package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/yourorg/janus/internal/audit"
	"github.com/yourorg/janus/internal/discovery"
	"github.com/yourorg/janus/internal/migration"
)

type migrationStore struct {
	mu    sync.RWMutex
	plans map[string]migration.Plan
}

func newMigrationStore() *migrationStore {
	return &migrationStore{plans: make(map[string]migration.Plan)}
}

func (s *migrationStore) Put(plan migration.Plan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plans[plan.AssetID] = plan
}

func (s *migrationStore) Get(assetID string) (migration.Plan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plan, ok := s.plans[assetID]
	return plan, ok
}

func (s *migrationStore) List() []migration.Plan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plans := make([]migration.Plan, 0, len(s.plans))
	for _, plan := range s.plans {
		plans = append(plans, plan)
	}
	return plans
}

var (
	inventory     = discovery.NewInventory()
	auditLog      = audit.NewLog("data/audit.log")
	migrations    = newMigrationStore()
	staleAssetAge = 24 * time.Hour
)

func recordAuditEvent(eventType string, payload map[string]any) {
	if _, err := auditLog.Append(audit.Event{
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	}); err != nil {
		logger.Warn().Err(err).Str("event_type", eventType).Msg("failed to append audit event")
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
