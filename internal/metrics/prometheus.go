// internal/metrics/prometheus.go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
    "sync"
)

var (
    decisionsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "pqc_decisions_total",
            Help: "Total number of algorithm decisions made, labeled by scenario and kem.",
        },
        []string{"scenario", "kem"},
    )
    latencyHistogram = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "pqc_decision_latency_ms",
            Help:    "Latency of decision evaluation in milliseconds.",
            Buckets: prometheus.ExponentialBuckets(0.5, 2, 10), // 0.5ms to ~256ms
        },
        []string{"scenario"},
    )
    // Cache metrics
    CacheHits = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "pqc_cache_hits_total",
        Help: "Total number of cache hits",
    })
    CacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "pqc_cache_misses_total",
        Help: "Total number of cache misses",
    })
    // Crypto execution metrics
    CryptoExecutionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "pqc_crypto_executions_total",
        Help: "Total number of crypto executions performed",
    })
    CryptoExecutionErrors = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "pqc_crypto_errors_total",
        Help: "Total number of crypto execution failures",
    })
    CryptoExecutionDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "pqc_crypto_execution_duration_ms",
        Help:    "Duration of crypto executions in milliseconds",
        Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 20, 50},
    })
    once sync.Once
)

// Init registers metrics and starts a /metrics HTTP endpoint.
func Init(addr string) {
    once.Do(func() {
        prometheus.MustRegister(decisionsTotal, latencyHistogram)
        go func() {
            http.Handle("/metrics", promhttp.Handler())
            // ignore error – server runs in background
            _ = http.ListenAndServe(addr, nil)
        }()
    })
}

// RecordDecision increments the counter and observes latency.
func RecordDecision(scenario, kem string, latencyMs float64) {
    decisionsTotal.WithLabelValues(scenario, kem).Inc()
    latencyHistogram.WithLabelValues(scenario).Observe(latencyMs)
}
