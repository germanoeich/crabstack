package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"crabstack.local/projects/crab-gateway/internal/config"
	"crabstack.local/projects/crab-gateway/internal/dispatch"
	"crabstack.local/projects/crab-gateway/internal/gateway"
	"crabstack.local/projects/crab-gateway/internal/httpapi"
	"crabstack.local/projects/crab-gateway/internal/model"
	"crabstack.local/projects/crab-gateway/internal/pairing"
	"crabstack.local/projects/crab-gateway/internal/session"
	"crabstack.local/projects/crab-gateway/internal/subscribers"
	logging "crabstack.local/projects/crab-gateway/internal/subscribers/logging"
	"crabstack.local/projects/crab-gateway/internal/subscribers/webhook"
)

func main() {
	logger := log.New(os.Stdout, "gateway ", log.Ldate|log.Ltime|log.Lmicroseconds|log.LUTC)
	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("invalid config: %v", err)
	}

	subs := []subscribers.Subscriber{logging.New(logger)}
	for idx, webhookURL := range webhookSubscriberURLsFromEnv() {
		name := webhookSubscriberName(idx, webhookURL)
		subs = append(subs, webhook.New(name, webhookURL, logger))
	}
	dispatcher := dispatch.New(logger, subs)
	store, err := session.NewGormStore(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		logger.Fatalf("failed to initialize session store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Printf("store close error: %v", err)
		}
	}()

	modelRegistry := model.NewRegistry()
	if apiKey := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); apiKey != "" {
		modelRegistry.Register("anthropic", model.NewAnthropicProvider(apiKey))
	}
	if apiKey := strings.TrimSpace(os.Getenv("OPENAI_API_KEY")); apiKey != "" {
		modelRegistry.Register("openai", model.NewOpenAIProvider(apiKey))
	}

	identity, err := pairing.LoadOrCreateIdentity(cfg.KeyDir, cfg.GatewayID)
	if err != nil {
		logger.Fatalf("failed to initialize gateway identity: %v", err)
	}
	certificateAuthority, err := pairing.LoadOrCreateCertificateAuthority(cfg.KeyDir, cfg.GatewayID)
	if err != nil {
		logger.Fatalf("failed to initialize pairing certificate authority: %v", err)
	}

	peerStore, err := pairing.NewGormPeerStore(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		logger.Fatalf("failed to initialize pairing store: %v", err)
	}
	defer func() {
		if err := peerStore.Close(); err != nil {
			logger.Printf("pairing store close error: %v", err)
		}
	}()

	pairingTLSConfig, err := pairing.LoadTLSClientConfig(
		cfg.PairMTLSCAFile,
		cfg.PairMTLSClientCertFile,
		cfg.PairMTLSClientPrivateKeyFile,
	)
	if err != nil {
		logger.Fatalf("failed to initialize pairing mTLS config: %v", err)
	}

	pairingService := pairing.NewManager(
		logger,
		identity,
		peerStore,
		cfg.PairTimeout,
		pairing.WithCertificateIssuer(certificateAuthority),
		pairing.WithTLSClientConfig(pairingTLSConfig),
		pairing.WithRequireMTLSRemote(cfg.PairRequireMTLSRemote),
		pairing.WithAllowInsecureLoopback(cfg.PairAllowInsecureLoopback),
	)

	service := gateway.NewService(logger, dispatcher, store, modelRegistry)
	publicSrv := httpapi.NewServer(logger, cfg.HTTPAddr, service, nil, false)
	adminSrv := httpapi.NewServer(logger, "unix://"+cfg.AdminSocketPath, service, pairingService, true)

	if err := os.MkdirAll(filepath.Dir(cfg.AdminSocketPath), 0o700); err != nil {
		logger.Fatalf("failed to create admin socket dir: %v", err)
	}
	if err := os.Remove(cfg.AdminSocketPath); err != nil && !os.IsNotExist(err) {
		logger.Fatalf("failed to remove stale admin socket: %v", err)
	}
	adminListener, err := net.Listen("unix", cfg.AdminSocketPath)
	if err != nil {
		logger.Fatalf("failed to listen on admin socket: %v", err)
	}
	defer func() {
		_ = adminListener.Close()
		if err := os.Remove(cfg.AdminSocketPath); err != nil && !os.IsNotExist(err) {
			logger.Printf("admin socket cleanup error: %v", err)
		}
	}()
	if err := os.Chmod(cfg.AdminSocketPath, 0o600); err != nil {
		logger.Printf("admin socket chmod warning: %v", err)
	}

	go func() {
		logger.Printf("listening on %s", cfg.HTTPAddr)
		if err := publicSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server crashed: %v", err)
		}
	}()
	go func() {
		logger.Printf("admin socket listening on %s", cfg.AdminSocketPath)
		if err := adminSrv.Serve(adminListener); !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("admin server crashed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := publicSrv.Shutdown(ctx); err != nil {
		logger.Printf("public server shutdown error: %v", err)
	}
	if err := adminSrv.Shutdown(ctx); err != nil {
		logger.Printf("admin server shutdown error: %v", err)
	}
}

func webhookSubscriberURLsFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv("CRAB_GATEWAY_WEBHOOK_URLS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	urls := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			urls = append(urls, value)
		}
	}
	return urls
}

func webhookSubscriberName(index int, webhookURL string) string {
	parsed, err := url.Parse(webhookURL)
	if err == nil {
		host := strings.TrimSpace(parsed.Host)
		if host != "" {
			return host
		}
	}
	return fmt.Sprintf("webhook-%d", index+1)
}
