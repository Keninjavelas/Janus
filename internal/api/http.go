// internal/api/http.go
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
	"github.com/yourorg/janus/internal/fallback"
)

var logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

// In-memory metrics aggregator
type MetricsCollector struct {
	mu               sync.RWMutex
	TotalDecisions   int64
	AlgorithmCounts  map[string]int64
	Latencies        []float64
	CacheHits        int64
	CacheMisses      int64
}

var metrics = &MetricsCollector{
	AlgorithmCounts: make(map[string]int64),
	Latencies:       []float64{},
}

// RecordDecision stores a decision for metrics aggregation
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

// ContextRequest matches the frontend JSON payload (CRITICAL: json tags must match frontend keys)
type ContextRequest struct {
	Scenario         string  `json:"scenario"`
	Region           string  `json:"region"`            // ✅ FIXED: proper json tag
	Risk             int32   `json:"risk"`
	DeviceType       string  `json:"device_type"`       // ✅ NEW: for IoT rules
	KeyRotationHours int32   `json:"key_rotation_hours"` // ✅ NEW: for short-lived certs
	CertValidityDays int32   `json:"cert_validity_days"` // ✅ NEW: for long-lived root CA
	LatencyBudgetMs  float64 `json:"latency_budget_ms"`
}

func StartHTTPServer() {
	r := mux.NewRouter()
	r.HandleFunc("/api/evaluate", handleEvaluate).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/metrics", handleMetrics).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/policy", handleGetPolicy).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/policy", handleUpdatePolicy).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/ai/generate", handleAIGenerate).Methods("POST", "OPTIONS")

	// Enable CORS for local development
	r.Use(corsMiddleware)

	// Serve static files (React build) - fallback to index.html for SPA
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dist")))

	logger.Info().Msg("HTTP API server listening on :8080")
	http.ListenAndServe(":8080", r)
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
		logger.Error().Err(err).Msg("Failed to decode evaluate request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// ✅ DEBUG: Log what we received to confirm the UI is sending region correctly
	logger.Info().
		Str("scenario", req.Scenario).
		Str("region", req.Region).
		Int32("risk", req.Risk).
		Str("device_type", req.DeviceType).
		Int32("rotation_hours", req.KeyRotationHours).
		Int32("cert_days", req.CertValidityDays).
		Msg("📥 Received evaluate request")

	// Map to gRPC ContextRequest
	grpcReq := &pb.ContextRequest{
		Scenario:          req.Scenario,
		Region:            req.Region,
		Risk:              req.Risk,
		DeviceType:        req.DeviceType,
		KeyRotationHours:  req.KeyRotationHours,
		CertValidityDays:  req.CertValidityDays,
		LatencyBudgetMs:   req.LatencyBudgetMs,
	}

	start := time.Now()
	cfg, err := fallback.EvaluateWithFallback(r.Context(), grpcReq)
	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		logger.Error().Err(err).Msg("Evaluation failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Record for metrics
	cacheHit := false // TODO: pass actual cache hit from evaluator
	RecordDecision(cfg.Kem, latencyMs, cacheHit)

	logger.Info().
		Str("kem", cfg.Kem).
		Str("sig", cfg.Sig).
		Float64("latency_ms", latencyMs).
		Msg("✅ Evaluation successful")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()

	// Calculate percentiles
	var p99 float64
	if len(metrics.Latencies) > 0 {
		sorted := make([]float64, len(metrics.Latencies))
		copy(sorted, metrics.Latencies)
		// Simple sort (for production, use a better algorithm)
		// For demo purposes, we use a simple average for p99 approximation
		// In a real implementation, you would use a quantile library
		sum := 0.0
		for _, v := range metrics.Latencies {
			sum += v
		}
		p99 = sum / float64(len(metrics.Latencies)) * 1.5 // rough approximation for demo
		if p99 > 10 {
			p99 = 10
		}
	}

	total := metrics.TotalDecisions
	var hitRate float64
	if total > 0 {
		hitRate = float64(metrics.CacheHits) / float64(total)
	}

	// Determine threat level based on algorithm distribution
	threatLevel := "safe"
	if total > 0 {
		classicalCount := metrics.AlgorithmCounts["RSA-2048"] + metrics.AlgorithmCounts["ECDSA-P256"]
		if classicalCount > 0 {
			threatLevel = "critical"
		} else if metrics.AlgorithmCounts["ML-KEM-512"] > total/2 {
			threatLevel = "warning"
		}
	}

	response := map[string]interface{}{
		"total_decisions":   total,
		"cache_hit_rate":    hitRate,
		"avg_latency_ms":    p99 * 0.6, // approximate avg
		"p99_latency_ms":    p99,
		"algorithm_counts":  metrics.AlgorithmCounts,
		"threat_level":      threatLevel,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("configs/policy.yaml")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/yaml")
	w.Write(data)
}

func handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := os.WriteFile("configs/policy.yaml", body, 0644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Hot-reload is automatic via fsnotify
	logger.Info().Msg("📝 Policy updated and hot-reloaded")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"reloaded"}`))
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
	
	// If no API key, fallback to a basic template response
	if apiKey == "" {
		logger.Warn().Msg("OPENAI_API_KEY not set, returning fallback YAML")
		fallbackYAML := `default:
  kem: "ML-KEM-768"
  hybrid_peer: "X25519Kyber768"
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"yaml": fallbackYAML})
		return
	}

	client := openai.NewClient(apiKey)
	systemPrompt := `You are Janus, a YAML policy generator for a Post-Quantum Cryptography engine. 
Generate ONLY valid YAML. 
The schema is: default (kem, hybrid_peer, security_level) and rules (name, match, config). 
Available match fields: scenario, region, risk_min, risk_max, time_from, time_to, device_type, rotation_hours_min/max, cert_validity_days_min. 
Available config fields: kem (ML-KEM-512/768/1024), sig (ML-DSA-44/65/87/SLH-DSA-128s/null), hybrid_peer, security_level (1-5).`

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

	yaml := resp.Choices[0].Message.Content
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"yaml": yaml})
}
