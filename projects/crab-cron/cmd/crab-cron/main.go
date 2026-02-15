package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"crabstack.local/projects/crab-cron/internal/config"
	"crabstack.local/projects/crab-cron/internal/emitter"
	"crabstack.local/projects/crab-cron/internal/scheduler"
	"crabstack.local/projects/crab-cron/internal/tools"
	"crabstack.local/projects/crab-sdk/toolhost"
)

func main() {
	logger := log.New(os.Stdout, "crab-cron ", log.Ldate|log.Ltime|log.Lmicroseconds|log.LUTC)

	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("invalid config: %v", err)
	}

	store := scheduler.NewMemoryJobStore()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	eventEmitter := emitter.NewHTTPEventEmitter(cfg.GatewayHTTPURL, httpClient)
	sched := scheduler.NewScheduler(store, eventEmitter, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := sched.Start(ctx); err != nil {
		logger.Fatalf("failed to start scheduler: %v", err)
	}
	defer sched.Stop()

	host := toolhost.NewToolHost("crab-cron", logger)
	host.Register(tools.NewCronListHandler(store))
	host.Register(tools.NewCronCreateHandler(store, sched.Reload))
	host.Register(tools.NewCronRemoveHandler(store, sched.Reload))

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           host.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		logger.Printf("tool host listening on %s", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-serverErrCh:
		logger.Printf("tool host server failed: %v", err)
		cancel()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Printf("tool host shutdown error: %v", err)
	}
}
