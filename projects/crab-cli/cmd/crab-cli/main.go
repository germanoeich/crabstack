package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-cli/internal/client"
	"crabstack.local/projects/crab-cli/internal/pairing"
	"crabstack.local/projects/crab-cli/internal/tui"
)

func main() {
	if len(os.Args) > 1 {
		switch strings.ToLower(strings.TrimSpace(os.Args[1])) {
		case "pair":
			if err := runPairCommand(os.Args[2:]); err != nil {
				log.Fatalf("crab pair failed: %v", err)
			}
			return
		}
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
	if len(args) == 0 {
		return fmt.Errorf("usage: crab pair <test|tool|subscriber> ...")
	}

	subcommand := strings.ToLower(strings.TrimSpace(args[0]))
	switch subcommand {
	case "test":
		return runPairTestCommand(args[1:])
	case "tool":
		return runPairTargetCommand("tool", types.ComponentTypeToolHost, args[1:])
	case "subscriber":
		return runPairTargetCommand("subscriber", types.ComponentTypeSubscriber, args[1:])
	default:
		return fmt.Errorf("unsupported pair subcommand %q (supported: test, tool, subscriber)", subcommand)
	}
}

func runPairTargetCommand(subcommand string, componentType types.ComponentType, args []string) error {
	fs := flag.NewFlagSet("crab pair "+subcommand, flag.ContinueOnError)
	adminSocket := fs.String("admin-socket", envOrDefault("CRAB_GATEWAY_ADMIN_SOCKET_PATH", ".crabstack/run/gateway-admin.sock"), "gateway admin unix socket path")
	timeout := fs.Duration("timeout", 20*time.Second, "pairing timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	positionals := fs.Args()
	if len(positionals) != 2 {
		return fmt.Errorf("usage: crab pair %s [--admin-socket <path>] [--timeout <duration>] <endpoint> <name>", subcommand)
	}

	endpoint := strings.TrimSpace(positionals[0])
	componentID := strings.TrimSpace(positionals[1])
	if endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	if componentID == "" {
		return fmt.Errorf("name is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := pairing.TriggerGatewayPair(ctx, pairing.GatewayPairConfig{
		GatewayAdminSocketPath: strings.TrimSpace(*adminSocket),
		ComponentType:          componentType,
		ComponentID:            componentID,
		Endpoint:               endpoint,
		Timeout:                *timeout,
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

func runPairTestCommand(args []string) error {
	fs := flag.NewFlagSet("crab pair test", flag.ContinueOnError)
	adminSocket := fs.String("admin-socket", envOrDefault("CRAB_GATEWAY_ADMIN_SOCKET_PATH", ".crabstack/run/gateway-admin.sock"), "gateway admin unix socket path")
	gatewayPub := fs.String("gateway-public-key", strings.TrimSpace(os.Getenv("CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519")), "trusted gateway ed25519 public key (base64)")
	componentID := fs.String("component-id", envOrDefault("CRAB_CLI_COMPONENT_ID", hostnameOrDefault("crab-cli-test")), "component id")
	listenAddr := fs.String("listen-addr", envOrDefault("CRAB_CLI_PAIR_LISTEN_ADDR", "127.0.0.1:0"), "local listen address for temporary pair endpoint")
	listenPath := fs.String("listen-path", envOrDefault("CRAB_CLI_PAIR_LISTEN_PATH", "/v1/pair"), "local listen path for temporary pair endpoint")
	timeout := fs.Duration("timeout", 20*time.Second, "pairing timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolvedGatewayPub, err := resolveGatewayPublicKey(*gatewayPub)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := pairing.Pair(ctx, pairing.Config{
		GatewayAdminSocketPath:        strings.TrimSpace(*adminSocket),
		GatewayPublicKeyEd25519Base64: resolvedGatewayPub,
		ComponentType:                 types.ComponentTypeToolHost,
		ComponentID:                   strings.TrimSpace(*componentID),
		ListenAddr:                    strings.TrimSpace(*listenAddr),
		ListenPath:                    strings.TrimSpace(*listenPath),
		Timeout:                       *timeout,
	})
	if err != nil {
		return err
	}

	fmt.Printf(
		"pairing test complete\npairing_id=%s\ncomponent_type=%s\ncomponent_id=%s\nendpoint=%s\nmtls_cert_fingerprint=%s\n",
		result.PairingID,
		result.ComponentType,
		result.ComponentID,
		result.Endpoint,
		result.MTLSCertFingerprint,
	)
	return nil
}

func resolveGatewayPublicKey(flagValue string) (string, error) {
	key := strings.TrimSpace(flagValue)
	if key != "" {
		return key, nil
	}

	keyDir := envOrDefault("CRAB_GATEWAY_KEY_DIR", ".crabstack/keys")
	identityPath := filepath.Join(keyDir, "gateway_identity.json")
	data, err := os.ReadFile(identityPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("gateway public key is required (set -gateway-public-key or CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519); identity file not found at %s", identityPath)
		}
		return "", fmt.Errorf("read gateway identity file: %w", err)
	}

	var identityRecord struct {
		PrivateKeyEd25519 string `json:"private_key_ed25519"`
	}
	if err := json.Unmarshal(data, &identityRecord); err != nil {
		return "", fmt.Errorf("decode gateway identity file: %w", err)
	}

	privateKeyB64 := strings.TrimSpace(identityRecord.PrivateKeyEd25519)
	if privateKeyB64 == "" {
		return "", fmt.Errorf("gateway identity file is missing private_key_ed25519")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode gateway private key: %w", err)
	}
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid gateway private key size %d", len(privateKeyBytes))
	}

	publicKey := ed25519.PrivateKey(privateKeyBytes).Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(publicKey), nil
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
