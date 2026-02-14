package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"crabstack.local/projects/crab-discord/internal/config"
	"crabstack.local/projects/crab-discord/internal/listener"
)

func main() {
	logger := log.New(os.Stdout, "crab-discord ", log.Ldate|log.Ltime|log.Lmicroseconds|log.LUTC)

	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("invalid config: %v", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	l := listener.NewListener(cfg, logger, httpClient)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := l.Start(ctx); err != nil {
		logger.Fatalf("failed to start listener: %v", err)
	}

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	done := make(chan error, 1)
	go func() {
		done <- l.Stop()
	}()

	select {
	case err := <-done:
		if err != nil {
			logger.Printf("listener shutdown error: %v", err)
		}
	case <-shutdownCtx.Done():
		logger.Printf("listener shutdown timed out")
	}
}
