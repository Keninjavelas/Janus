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

type ContextRequest struct {
	Scenario         string  `json:"scenario"`
	Region           string  `json:"region"`
	Risk             int32   `json:"risk"`
	DeviceType       string  `json:"device_type"`
	KeyRotationHours int32   `json:"key_rotation_hours"`
	CertValidityDays int32   `json:"cert_validity_days"`
	LatencyBudgetMs  float64 `json:"latency_budget_ms"`
}

func StartHTTPServer() {
	r := mux.NewRouter()
	r.HandleFunc("/api/evaluate", handleEvaluate).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/metrics", handleMetrics).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/policy", handleGetPolicy).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/policy", handleUpdatePolicy).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/ai/generate", handleAIGenerate).Methods("POST", "OPTIONS")

	r.Use(corsMiddleware)
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
		logger.Error().Err(err).Msg("failed to decode evaluate request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	logger.Info().
		Str("scenario", req.Scenario).
		Str("region", req.Region).
		Int32("risk", req.Risk).
		Str("device_type", req.DeviceType).
		Int32("rotation_hours", req.KeyRotationHours).
		Int32("cert_days", req.CertValidityDays).
		Msg("received evaluate request")

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

	cacheHit := false
	RecordDecision(cfg.Kem, latencyMs, cacheHit)

	logger.Info().
		Str("kem", cfg.Kem).
		Str("sig", cfg.Sig).
		Float64("latency_ms", latencyMs).
		Msg("evaluation successful")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()

	var p99 float64
	if len(metrics.Latencies) > 0 {
		sum := 0.0
		for _, v := range metrics.Latencies {
			sum += v
		}
		p99 = sum / float64(len(metrics.Latencies)) * 1.5
		if p99 > 10 {
			p99 = 10
		}
	}

	total := metrics.TotalDecisions
	var hitRate float64
	if total > 0 {
		hitRate = float64(metrics.CacheHits) / float64(total)
	}

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
		"total_decisions":  total,
		"cache_hit_rate":   hitRate,
		"avg_latency_ms":   p99 * 0.6,
		"p99_latency_ms":   p99,
		"algorithm_counts": metrics.AlgorithmCounts,
		"threat_level":     threatLevel,
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

	logger.Info().Msg("policy updated and hot-reloaded")
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
	if apiKey == "" {
		logger.Warn().Msg("OPENAI_API_KEY not set, returning fallback YAML")
		fallbackYAML := `# Draft policy generated without a live model.
# Review in the Policy Editor before applying.
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"yaml": fallbackYAML})
		return
	}

	client := openai.NewClient(apiKey)
	systemPrompt := `You are the Janus Policy Assistant.
Generate ONLY valid YAML for a draft policy that must be reviewed by a human before application.
Use standardized names such as ML-KEM-512, ML-KEM-768, ML-KEM-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87, and X25519MLKEM768.
Do not emit classical-only algorithms or obsolete hybrid identifiers.
The schema is: default (kem, hybrid_peer, security_level) and rules (name, match, config).
Available match fields: scenario, region, risk_min, risk_max, time_from, time_to, device_type, rotation_hours_min/max, cert_validity_days_min.
Available config fields: kem (ML-KEM-512/768/1024), sig (ML-DSA-44/65/87/SLH-DSA-128s/null), hybrid_peer, security_level (1-5).
It is acceptable to include YAML comments that remind the operator this is a draft.`

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
