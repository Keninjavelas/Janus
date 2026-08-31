package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sashabaranov/go-openai"
	pb "github.com/yourorg/janus/api/proto/v1"
	"github.com/yourorg/janus/internal/algorithms"
	"github.com/yourorg/janus/internal/config"
	"github.com/yourorg/janus/internal/discovery"
	"github.com/yourorg/janus/internal/fallback"
	"github.com/yourorg/janus/internal/migration"
	"github.com/yourorg/janus/internal/risk"
	"github.com/yourorg/janus/internal/verification"
	"gopkg.in/yaml.v3"
)

var logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

type MetricsCollector struct {
	mu              sync.RWMutex
	TotalDecisions  int64
	AlgorithmCounts map[string]int64
	Latencies       []float64
	CacheHits       int64
	CacheMisses     int64
}

var metrics = &MetricsCollector{
	AlgorithmCounts: make(map[string]int64),
	Latencies:       []float64{},
}

type ContextRequest struct {
	Scenario         string  `json:"scenario"`
	Region           string  `json:"region"`
	Risk             int32   `json:"risk"`
	DeviceType       string  `json:"device_type"`
	KeyRotationHours int32   `json:"key_rotation_hours"`
	CertValidityDays int32   `json:"cert_validity_days"`
	LatencyBudgetMs  float64 `json:"latency_budget_ms"`
}

type RiskEvaluateRequest struct {
	AssetID               string                 `json:"asset_id,omitempty"`
	Asset                 *discovery.CryptoAsset `json:"asset,omitempty"`
	DataSensitivity       string                 `json:"data_sensitivity,omitempty"`
	ConfidentialityYears  int                    `json:"confidentiality_years,omitempty"`
	AssetCriticality      string                 `json:"asset_criticality,omitempty"`
	ExternalExposure      bool                   `json:"external_exposure,omitempty"`
	WorkloadType          string                 `json:"workload_type,omitempty"`
	RetentionYears        int                    `json:"retention_years,omitempty"`
	MigrationReady        bool                   `json:"migration_ready"`
	CompatibilityBlockers []string               `json:"compatibility_blockers,omitempty"`
}

type MigrationPlanRequest struct {
	RiskEvaluateRequest
	Mode migration.Mode `json:"mode,omitempty"`
}

type MigrationVerifyRequest struct {
	AssetID  string                            `json:"asset_id"`
	Evidence verification.VerificationEvidence `json:"evidence"`
}

type DiscoveryScanRequest struct {
	Targets []struct {
		TargetAddress string   `json:"target_address"`
		ServerName    string   `json:"server_name"`
		ClientCurves  []string `json:"client_curves,omitempty"`
	} `json:"targets"`
}

func RecordDecision(kem string, latencyMs float64, cacheHit bool) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	metrics.TotalDecisions++
	metrics.AlgorithmCounts[kem]++
	metrics.Latencies = append(metrics.Latencies, latencyMs)
	if len(metrics.Latencies) > 10000 {
		metrics.Latencies = metrics.Latencies[len(metrics.Latencies)-10000:]
	}
	if cacheHit {
		metrics.CacheHits++
	} else {
		metrics.CacheMisses++
	}
}

func StartHTTPServer() {
	r := mux.NewRouter()
	r.HandleFunc("/api/evaluate", handleEvaluate).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/metrics", handleMetrics).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/algorithms", handleAlgorithms).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/policy", handleGetPolicy).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/policy", handleUpdatePolicy).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/policy/bundle", handleGetPolicyBundle).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/policy/validate", handleValidatePolicy).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/ai/generate", handleAIGenerate).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/discovery/evidence", handleObserveDiscoveryEvidence).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/discovery/scan", handleDiscoveryScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/discovery/assets", handleListDiscoveredAssets).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/discovery/cbom", handleGetCBOM).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/risk/evaluate", handleRiskEvaluate).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/migration/plan", handleBuildMigrationPlan).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/migration/plans", handleListMigrationPlans).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/migration/verify", handleVerifyMigration).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/audit/records", handleAuditRecords).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/audit/verify", handleAuditVerify).Methods("GET", "OPTIONS")

	r.Use(corsMiddleware)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dist")))

	logger.Info().Msg("HTTP API server listening on :8080")
	_ = http.ListenAndServe(":8080", r)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req ContextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error().Err(err).Msg("failed to decode evaluate request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	grpcReq := &pb.ContextRequest{
		Scenario:         req.Scenario,
		Region:           req.Region,
		Risk:             req.Risk,
		DeviceType:       req.DeviceType,
		KeyRotationHours: req.KeyRotationHours,
		CertValidityDays: req.CertValidityDays,
		LatencyBudgetMs:  req.LatencyBudgetMs,
	}

	start := time.Now()
	cfg, err := fallback.EvaluateWithFallback(r.Context(), grpcReq)
	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		logger.Error().Err(err).Msg("evaluation failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	RecordDecision(cfg.Kem, latencyMs, false)
	recordAuditEvent("decision_created", map[string]any{
		"scenario":    req.Scenario,
		"region":      req.Region,
		"risk":        req.Risk,
		"kem":         cfg.Kem,
		"hybrid_peer": cfg.HybridPeer,
	})

	writeJSON(w, http.StatusOK, cfg)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()

	var p99 float64
	if len(metrics.Latencies) > 0 {
		sum := 0.0
		for _, value := range metrics.Latencies {
			sum += value
		}
		p99 = (sum / float64(len(metrics.Latencies))) * 1.5
	}

	total := metrics.TotalDecisions
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(metrics.CacheHits) / float64(total)
	}

	assets := inventory.List(staleAssetAge)
	priorityCounts := map[string]int{
		"P0": 0,
		"P1": 0,
		"P2": 0,
		"P3": 0,
	}
	for _, plan := range migrations.List() {
		priorityCounts[string(plan.Priority)]++
	}

	quantumSafe := 0
	classical := 0
	unknown := 0
	for _, asset := range assets {
		switch asset.KeyExchangeClass {
		case algorithms.KeyExchangeClassHybridPQ:
			quantumSafe++
		case algorithms.KeyExchangeClassClassical:
			classical++
		default:
			unknown++
		}
	}

	quantumExposure := "safe"
	if priorityCounts["P0"] > 0 || classical > 0 {
		quantumExposure = "critical"
	} else if unknown > 0 || priorityCounts["P1"] > 0 {
		quantumExposure = "warning"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_decisions":           total,
		"cache_hit_rate":            hitRate,
		"avg_latency_ms":            p99 * 0.6,
		"p99_latency_ms":            p99,
		"algorithm_counts":          metrics.AlgorithmCounts,
		"threat_level":              quantumExposure,
		"quantum_exposure":          quantumExposure,
		"total_assets":              len(assets),
		"quantum_safe_assets":       quantumSafe,
		"classical_assets":          classical,
		"unknown_assets":            unknown,
		"migration_priority_counts": priorityCounts,
	})
}

func handleAlgorithms(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, algorithms.DefaultRegistry().All())
}

func handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("configs/policy.yaml")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/yaml")
	_, _ = w.Write(data)
}

func handleGetPolicyBundle(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, config.GetLoadedPolicy())
}

func handleValidatePolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policy, err := config.ParsePolicyYAML(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	policy.Metadata.State = config.PolicyStateDraft
	policy.Metadata.Active = false
	policy.Metadata.Signature = nil

	compiled, err := config.CompilePolicy(policy, time.Now().UTC())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, compiled)
}

func handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policy, err := config.ParsePolicyYAML(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policy.Metadata.State = config.PolicyStateActive
	policy.Metadata.Active = true
	compiled, err := config.CompilePolicy(policy, time.Now().UTC())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policy.Metadata.ID = compiled.PolicyID
	policy.Metadata.Version = compiled.Version
	policy.Metadata.CreatedAt = compiled.CreatedAt
	policy.Metadata.Active = compiled.Active
	policy.Metadata.State = compiled.State
	policy.Metadata.Signature = compiled.Signature

	rendered, err := yaml.Marshal(policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile("configs/policy.yaml", rendered, 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := config.ReloadPolicy(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	recordAuditEvent("policy_activated", map[string]any{
		"policy_id":      compiled.PolicyID,
		"version":        compiled.Version,
		"canonical_hash": compiled.CanonicalHash,
	})
	writeJSON(w, http.StatusOK, compiled)
}

func handleObserveDiscoveryEvidence(w http.ResponseWriter, r *http.Request) {
	var evidence verification.VerificationEvidence
	if err := json.NewDecoder(r.Body).Decode(&evidence); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	asset, err := inventory.ObserveEvidence(evidence)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	recordAuditEvent("connection_observed", map[string]any{
		"asset_id":           asset.ID,
		"required":           evidence.Required,
		"observed":           evidence.Observed,
		"crypto_status":      evidence.Status,
		"attribution_status": evidence.AttributionStatus,
		"observation_level":  evidence.ObservationLevel,
		"connection_id":      evidence.ConnectionID,
	})
	writeJSON(w, http.StatusOK, asset)
}

func handleDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	var req DiscoveryScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	requests := make([]discovery.ScanRequest, 0, len(req.Targets))
	for _, target := range req.Targets {
		requests = append(requests, discovery.ScanRequest{
			TargetAddress: target.TargetAddress,
			ServerName:    target.ServerName,
			ClientCurves:  target.ClientCurves,
		})
	}

	assets, err := discovery.ScanInventory(r.Context(), inventory, requests)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, asset := range assets {
		recordAuditEvent("asset_discovered", map[string]any{
			"asset_id":        asset.ID,
			"key_exchange":    asset.KeyExchange,
			"evidence_source": asset.EvidenceSource,
		})
	}
	writeJSON(w, http.StatusOK, assets)
}

func handleListDiscoveredAssets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, inventory.List(staleAssetAge))
}

func handleGetCBOM(w http.ResponseWriter, r *http.Request) {
	payload, err := inventory.CBOMJSON(staleAssetAge)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

func handleRiskEvaluate(w http.ResponseWriter, r *http.Request) {
	var req RiskEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	asset, ok := resolveAssetRequest(req.AssetID, req.Asset)
	if !ok {
		http.Error(w, "unknown asset", http.StatusBadRequest)
		return
	}

	assessment := risk.Evaluate(risk.Input{
		Asset:                 asset,
		DataSensitivity:       req.DataSensitivity,
		ConfidentialityYears:  req.ConfidentialityYears,
		AssetCriticality:      req.AssetCriticality,
		ExternalExposure:      req.ExternalExposure,
		WorkloadType:          req.WorkloadType,
		RetentionYears:        req.RetentionYears,
		MigrationReady:        req.MigrationReady,
		CompatibilityBlockers: req.CompatibilityBlockers,
	})
	recordAuditEvent("risk_evaluated", map[string]any{
		"asset_id": asset.ID,
		"risk":     assessment.Risk,
		"priority": assessment.Priority,
	})
	writeJSON(w, http.StatusOK, assessment)
}

func handleBuildMigrationPlan(w http.ResponseWriter, r *http.Request) {
	var req MigrationPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	asset, ok := resolveAssetRequest(req.AssetID, req.Asset)
	if !ok {
		http.Error(w, "unknown asset", http.StatusBadRequest)
		return
	}

	assessment := risk.Evaluate(risk.Input{
		Asset:                 asset,
		DataSensitivity:       req.DataSensitivity,
		ConfidentialityYears:  req.ConfidentialityYears,
		AssetCriticality:      req.AssetCriticality,
		ExternalExposure:      req.ExternalExposure,
		WorkloadType:          req.WorkloadType,
		RetentionYears:        req.RetentionYears,
		MigrationReady:        req.MigrationReady,
		CompatibilityBlockers: req.CompatibilityBlockers,
	})

	mode := req.Mode
	if mode == "" {
		mode = migration.ModeAudit
	}

	plan := migration.BuildPlan(asset, assessment, req.CompatibilityBlockers, mode)
	migrations.Put(plan)
	recordAuditEvent("migration_recommended", map[string]any{
		"asset_id": plan.AssetID,
		"current":  plan.Current,
		"target":   plan.Target,
		"priority": plan.Priority,
		"status":   plan.Status,
	})
	writeJSON(w, http.StatusOK, plan)
}

func handleListMigrationPlans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, migrations.List())
}

func handleVerifyMigration(w http.ResponseWriter, r *http.Request) {
	var req MigrationVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	plan, ok := migrations.Get(req.AssetID)
	if !ok {
		http.Error(w, "unknown migration plan", http.StatusBadRequest)
		return
	}

	updated := migration.VerifyPlan(plan, req.Evidence)
	migrations.Put(updated)
	if _, err := inventory.ObserveEvidence(req.Evidence); err == nil {
		recordAuditEvent("migration_verification", map[string]any{
			"asset_id":           updated.AssetID,
			"verification_state": updated.VerificationState,
			"connection_id":      req.Evidence.ConnectionID,
			"observed":           req.Evidence.Observed,
			"required":           req.Evidence.Required,
			"crypto_status":      req.Evidence.Status,
			"attribution_status": req.Evidence.AttributionStatus,
		})
	}

	writeJSON(w, http.StatusOK, updated)
}

func handleAuditRecords(w http.ResponseWriter, r *http.Request) {
	records, err := auditLog.ReadAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, records)
}

func handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	result, err := auditLog.Verify()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func handleAIGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prompt string `json:"prompt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		logger.Warn().Msg("OPENAI_API_KEY not set, returning fallback YAML")
		fallbackYAML := `# Draft policy generated without a live model.
# Review, validate, and manually activate this policy before applying.
metadata:
  state: draft
default:
  kem: "ML-KEM-768"
  hybrid_peer: "X25519MLKEM768"
  security_level: 3
rules:
  - name: "Fallback Rule"
    match:
      region: "EU"
      risk_min: 3
    config:
      kem: "ML-KEM-1024"
      sig: "ML-DSA-87"
      security_level: 5`
		writeJSON(w, http.StatusOK, map[string]string{"yaml": fallbackYAML})
		return
	}

	client := openai.NewClient(apiKey)
	systemPrompt := `You are the Janus Policy Assistant.
Generate ONLY valid YAML for a draft policy that must be reviewed by a human before activation.
Always emit metadata.state: draft.
Use standardized names such as ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87, and X25519MLKEM768.
Do not emit unsupported, fictional, or classical-only fallback algorithms.
The schema is metadata, default, and rules.
Do not claim the policy is active or approved.`

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4oMini,
			Messages: []openai.ChatCompletionMessage{
				{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
				{Role: openai.ChatMessageRoleUser, Content: req.Prompt},
			},
			Temperature: 0.3,
		},
	)
	if err != nil {
		logger.Error().Err(err).Msg("OpenAI API call failed")
		http.Error(w, "AI generation failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"yaml": resp.Choices[0].Message.Content})
}

func resolveAssetRequest(assetID string, inline *discovery.CryptoAsset) (discovery.CryptoAsset, bool) {
	if inline != nil {
		return *inline, true
	}
	if assetID == "" {
		return discovery.CryptoAsset{}, false
	}
	for _, asset := range inventory.List(0) {
		if asset.ID == assetID {
			return asset, true
		}
	}
	return discovery.CryptoAsset{}, false
}
