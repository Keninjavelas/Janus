// cmd/pq-engine/main.go
package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/yourorg/janus/internal/api"
	"github.com/yourorg/janus/internal/cache"
	"github.com/yourorg/janus/internal/config"
	"github.com/yourorg/janus/internal/server"
)

var logger = zerolog.New(os.Stdout).With().Timestamp().Logger()

func main() {
	// 1. Load policy (hot‑reload)
	if err := config.InitLoader("configs/policy.yaml"); err != nil {
		logger.Fatal().Err(err).Msg("failed to load policy")
	}

	// 2. Cache initialization
	if err := cache.InitCache(1024); err != nil {
		logger.Fatal().Err(err).Msg("failed to init cache")
	}
	logger.Info().Msg("LRU cache initialized")

	// 3. HTTP API server for React frontend
	go func() {
		api.StartHTTPServer()
	}()

	// 4. Main gRPC server (insecure for now)
	grpcAddr := ":50051"
	go func() {
		if err := server.StartGRPC(grpcAddr); err != nil {
			logger.Error().Err(err).Msg("main gRPC server stopped")
		}
	}()
	logger.Info().Str("address", grpcAddr).Msg("Main gRPC server listening")

	// 5. Wait for termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("Shutting down servers...")
	time.Sleep(2 * time.Second)
	logger.Info().Msg("Shutdown complete")
}
