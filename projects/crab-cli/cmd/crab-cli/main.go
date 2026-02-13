package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-cli/internal/client"
	"crabstack.local/projects/crab-cli/internal/pairing"
	"crabstack.local/projects/crab-cli/internal/tui"
)

func main() {
	if len(os.Args) > 1 && strings.EqualFold(strings.TrimSpace(os.Args[1]), "pair") {
		if err := runPairCommand(os.Args[2:]); err != nil {
			log.Fatalf("crab pair failed: %v", err)
		}
		return
	}

	cfg, err := configFromFlags(os.Args[1:])
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := tui.Run(ctx, cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		log.Fatalf("crab failed: %v", err)
	}
}

func configFromFlags(args []string) (client.Config, error) {
	fs := flag.NewFlagSet("crab", flag.ContinueOnError)
	gatewayWS := fs.String("gateway-ws", envOrDefault("CRAB_CLI_GATEWAY_WS_URL", "ws://127.0.0.1:8080/v1/pair"), "gateway pairing websocket url")
	gatewayPub := fs.String("gateway-public-key", strings.TrimSpace(os.Getenv("CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519")), "trusted gateway ed25519 public key (base64)")
	tenantID := fs.String("tenant-id", envOrDefault("CRAB_CLI_TENANT_ID", "local"), "tenant id")
	agentID := fs.String("agent-id", envOrDefault("CRAB_CLI_AGENT_ID", "assistant"), "agent id")
	sessionID := fs.String("session-id", envOrDefault("CRAB_CLI_SESSION_ID", fmt.Sprintf("cli-%d", time.Now().UTC().Unix())), "session id")
	componentID := fs.String("component-id", envOrDefault("CRAB_CLI_COMPONENT_ID", hostnameOrDefault("crab-cli")), "component id")
	componentType := fs.String("component-type", envOrDefault("CRAB_CLI_COMPONENT_TYPE", string(types.ComponentTypeOperator)), "component type")
	platform := fs.String("platform", envOrDefault("CRAB_CLI_PLATFORM", "cli"), "source platform for outbound events")
	channelID := fs.String("channel-id", envOrDefault("CRAB_CLI_CHANNEL_ID", "terminal"), "source channel_id for outbound events")
	actorID := fs.String("actor-id", envOrDefault("CRAB_CLI_ACTOR_ID", "operator"), "source actor_id for outbound events")
	if err := fs.Parse(args); err != nil {
		return client.Config{}, err
	}

	cfg := client.Config{
		GatewayWSURL:               strings.TrimSpace(*gatewayWS),
		GatewayPublicKeyEd25519B64: strings.TrimSpace(*gatewayPub),
		TenantID:                   strings.TrimSpace(*tenantID),
		AgentID:                    strings.TrimSpace(*agentID),
		SessionID:                  strings.TrimSpace(*sessionID),
		ComponentID:                strings.TrimSpace(*componentID),
		ComponentType:              types.ComponentType(strings.TrimSpace(*componentType)),
		Platform:                   strings.TrimSpace(*platform),
		ChannelID:                  strings.TrimSpace(*channelID),
		ActorID:                    strings.TrimSpace(*actorID),
	}
	return cfg, cfg.Validate()
}

func runPairCommand(args []string) error {
	fs := flag.NewFlagSet("crab pair", flag.ContinueOnError)
	adminSocket := fs.String("admin-socket", envOrDefault("CRAB_GATEWAY_ADMIN_SOCKET_PATH", ".crabstack/run/gateway-admin.sock"), "gateway admin unix socket path")
	gatewayPub := fs.String("gateway-public-key", strings.TrimSpace(os.Getenv("CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519")), "trusted gateway ed25519 public key (base64)")
	componentType := fs.String("component-type", envOrDefault("CRAB_CLI_PAIR_COMPONENT_TYPE", string(types.ComponentTypeToolHost)), "pair component type (tool_host|listener|subscriber|provider)")
	componentID := fs.String("component-id", envOrDefault("CRAB_CLI_COMPONENT_ID", hostnameOrDefault("crab-cli")), "component id")
	listenAddr := fs.String("listen-addr", envOrDefault("CRAB_CLI_PAIR_LISTEN_ADDR", "127.0.0.1:0"), "local listen address for temporary pair endpoint")
	listenPath := fs.String("listen-path", envOrDefault("CRAB_CLI_PAIR_LISTEN_PATH", "/v1/pair"), "local listen path for temporary pair endpoint")
	timeout := fs.Duration("timeout", 20*time.Second, "pairing timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := pairing.Pair(ctx, pairing.Config{
		GatewayAdminSocketPath:        strings.TrimSpace(*adminSocket),
		GatewayPublicKeyEd25519Base64: strings.TrimSpace(*gatewayPub),
		ComponentType:                 types.ComponentType(strings.TrimSpace(*componentType)),
		ComponentID:                   strings.TrimSpace(*componentID),
		ListenAddr:                    strings.TrimSpace(*listenAddr),
		ListenPath:                    strings.TrimSpace(*listenPath),
		Timeout:                       *timeout,
	})
	if err != nil {
		return err
	}

	fmt.Printf(
		"pairing complete\npairing_id=%s\ncomponent_type=%s\ncomponent_id=%s\nendpoint=%s\nmtls_cert_fingerprint=%s\n",
		result.PairingID,
		result.ComponentType,
		result.ComponentID,
		result.Endpoint,
		result.MTLSCertFingerprint,
	)
	return nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func hostnameOrDefault(fallback string) string {
	hostname, err := os.Hostname()
	if err != nil {
		return fallback
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return fallback
	}
	return hostname
}
