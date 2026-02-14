package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"crabstack.local/lib/types"
	authflow "crabstack.local/projects/crab-cli/internal/auth"
	"crabstack.local/projects/crab-cli/internal/client"
	"crabstack.local/projects/crab-cli/internal/pairing"
	"crabstack.local/projects/crab-cli/internal/tui"
)

var (
	codexLogin                      = authflow.Login
	codexSaveCredentials            = authflow.SaveCredentials
	codexDefaultConfig              = authflow.DefaultConfig
	codexDefaultCredentialsPath     = authflow.DefaultCredentialsPath
	claudeLogin                     = authflow.LoginClaude
	claudeSaveCredentials           = authflow.SaveClaudeCredentials
	claudeDefaultConfig             = authflow.DefaultClaudeConfig
	claudeDefaultCredentialsPath    = authflow.DefaultClaudeCredentialsPath
	anthropicLogin                  = authflow.LoginAnthropic
	anthropicSaveCredentials        = authflow.SaveAnthropicCredentials
	anthropicDefaultConfig          = authflow.DefaultAnthropicConfig
	anthropicDefaultCredentialsPath = authflow.DefaultAnthropicCredentialsPath
)

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func runCLI(args []string) error {
	resolution := resolveCommand(crabCommandCatalog, args)
	if err := dispatchResolvedCommand(resolution); err != nil {
		if len(resolution.path) > 0 {
			switch resolution.path[0] {
			case "pair", "auth", "event":
				return fmt.Errorf("crab %s failed: %w", resolution.path[0], err)
			}
		}
		return err
	}
	return nil
}

func runDefaultCLI(args []string) error {
	cfg, err := configFromFlags(args)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := tui.Run(ctx, cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("crab failed: %w", err)
	}
	return nil
}

func configFromFlags(args []string) (client.Config, error) {
	fs := flag.NewFlagSet("crab", flag.ContinueOnError)
	gatewayWS := fs.String("gateway-ws", envOrDefault("CRAB_CLI_GATEWAY_WS_URL", "ws://127.0.0.1:8080/v1/pair"), "gateway pairing websocket url")
	gatewayPub := fs.String("gateway-public-key", strings.TrimSpace(os.Getenv("CRAB_CLI_GATEWAY_PUBLIC_KEY_ED25519")), "trusted gateway ed25519 public key (base64)")
	tenantID := fs.String("tenant-id", "local", "tenant id")
	agentID := fs.String("agent-id", envOrDefault("CRAB_CLI_AGENT_ID", "assistant"), "agent id")
	sessionID := fs.String("session-id", fmt.Sprintf("cli-%d", time.Now().UTC().Unix()), "session id")
	componentID := fs.String("component-id", hostnameOrDefault("crab-cli"), "component id")
	componentType := fs.String("component-type", envOrDefault("CRAB_CLI_COMPONENT_TYPE", string(types.ComponentTypeOperator)), "component type")
	platform := fs.String("platform", "cli", "source platform for outbound events")
	channelID := fs.String("channel-id", "terminal", "source channel_id for outbound events")
	actorID := fs.String("actor-id", "operator", "source actor_id for outbound events")
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
	return dispatchNamedSubcommand(crabCommandCatalog, "pair", args)
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
	componentID := fs.String("component-id", hostnameOrDefault("crab-cli-test"), "component id")
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

func runAuthCommand(args []string) error {
	return dispatchNamedSubcommand(crabCommandCatalog, "auth", args)
}

func runAuthCodexCommand(args []string) error {
	defaultCfg := codexDefaultConfig()
	fs := flag.NewFlagSet("crab auth codex", flag.ContinueOnError)
	authFile := fs.String("auth-file", codexDefaultCredentialsPath(), "output path for codex oauth credentials json")
	timeout := fs.Duration("timeout", 60*time.Second, "oauth callback wait timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		return fmt.Errorf("usage: crab auth codex [--auth-file <path>] [--timeout <duration>]")
	}

	cfg := defaultCfg
	cfg.Timeout = *timeout

	creds, err := codexLogin(context.Background(), cfg, os.Stdin, os.Stdout)
	if err != nil {
		return fmt.Errorf("codex oauth login failed: %w", err)
	}
	outputPath, err := codexSaveCredentials(strings.TrimSpace(*authFile), creds)
	if err != nil {
		return fmt.Errorf("persist codex oauth credentials: %w", err)
	}

	fmt.Printf(
		"codex auth complete\naccount_id=%s\nexpires_at=%s\npath=%s\n",
		creds.AccountID,
		creds.ExpiresAt.UTC().Format(time.RFC3339),
		outputPath,
	)
	return nil
}

func runAuthAnthropicCommand(args []string) error {
	defaultCfg := anthropicDefaultConfig()
	fs := flag.NewFlagSet("crab auth anthropic", flag.ContinueOnError)
	authFile := fs.String("auth-file", anthropicDefaultCredentialsPath(), "output path for anthropic oauth credentials json")
	timeout := fs.Duration("timeout", defaultCfg.Timeout, "oauth callback wait timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		return fmt.Errorf("usage: crab auth anthropic [--auth-file <path>] [--timeout <duration>]")
	}

	cfg := defaultCfg
	cfg.Timeout = *timeout

	creds, err := anthropicLogin(context.Background(), cfg, os.Stdin, os.Stdout)
	if err != nil {
		return fmt.Errorf("anthropic oauth login failed: %w", err)
	}
	outputPath, err := anthropicSaveCredentials(strings.TrimSpace(*authFile), creds)
	if err != nil {
		return fmt.Errorf("persist anthropic oauth credentials: %w", err)
	}

	fmt.Printf(
		"anthropic auth complete\naccount_id=%s\nexpires_at=%s\npath=%s\n",
		creds.AccountID,
		creds.ExpiresAt.UTC().Format(time.RFC3339),
		outputPath,
	)
	return nil
}

func runAuthClaudeCommand(args []string) error {
	defaultCfg := claudeDefaultConfig()
	fs := flag.NewFlagSet("crab auth claude", flag.ContinueOnError)
	authFile := fs.String("auth-file", claudeDefaultCredentialsPath(), "output path for claude oauth credentials json")
	mode := fs.String("mode", string(defaultCfg.Mode), "auth mode label: max or console")
	timeout := fs.Duration("timeout", defaultCfg.Timeout, "setup-token input timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		return fmt.Errorf("usage: crab auth claude [--auth-file <path>] [--mode <max|console>] [--timeout <duration>]")
	}

	cfg := defaultCfg
	cfg.Mode = authflow.ClaudeMode(strings.ToLower(strings.TrimSpace(*mode)))
	cfg.Timeout = *timeout

	creds, err := claudeLogin(context.Background(), cfg, os.Stdin, os.Stdout)
	if err != nil {
		return fmt.Errorf("claude login failed: %w", err)
	}
	outputPath, err := claudeSaveCredentials(strings.TrimSpace(*authFile), creds)
	if err != nil {
		return fmt.Errorf("persist claude credentials: %w", err)
	}

	fmt.Printf(
		"claude auth complete\naccount_id=%s\nexpires_at=%s\npath=%s\n",
		creds.AccountID,
		creds.ExpiresAt.UTC().Format(time.RFC3339),
		outputPath,
	)
	return nil
}

func runEventCommand(args []string) error {
	return dispatchNamedSubcommand(crabCommandCatalog, "event", args)
}

func runEventSendCommand(args []string) error {
	fs := flag.NewFlagSet("crab event send", flag.ContinueOnError)
	gatewayHTTP := fs.String("gateway-http", envOrDefault("CRAB_CLI_GATEWAY_HTTP_URL", "http://127.0.0.1:8080"), "gateway HTTP base URL")
	tenantID := fs.String("tenant-id", "local", "tenant id")
	agentID := fs.String("agent-id", "assistant", "agent id")
	componentID := fs.String("component-id", hostnameOrDefault("crab-cli"), "component id")
	channelID := fs.String("channel-id", "cli", "channel id")
	actorID := fs.String("actor-id", "operator", "actor id")
	timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	text := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if text == "" {
		return fmt.Errorf("usage: crab event send [flags] <text>")
	}

	eventsURL, err := normalizeGatewayEventsURL(strings.TrimSpace(*gatewayHTTP))
	if err != nil {
		return err
	}

	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: text})
	if err != nil {
		return fmt.Errorf("marshal channel message payload: %w", err)
	}

	sessionID := "cli-" + newHexID()
	event := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    newHexID(),
		TraceID:    newHexID(),
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   strings.TrimSpace(*tenantID),
		Source: types.EventSource{
			ComponentType: types.ComponentTypeOperator,
			ComponentID:   strings.TrimSpace(*componentID),
			Platform:      "cli",
			ChannelID:     strings.TrimSpace(*channelID),
			ActorID:       strings.TrimSpace(*actorID),
			Transport:     types.TransportTypeHTTP,
		},
		Routing: types.EventRouting{
			AgentID:   strings.TrimSpace(*agentID),
			SessionID: sessionID,
		},
		Payload: payload,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resultEventID, err := sendEvent(ctx, eventsURL, event)
	if err != nil {
		return err
	}

	fmt.Printf(
		"event sent\nsession_id=%s\nevent_id=%s\n",
		sessionID,
		resultEventID,
	)
	return nil
}

func normalizeGatewayEventsURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("gateway-http is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid gateway-http url: %w", err)
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("gateway-http must include scheme and host")
	}
	if strings.TrimSpace(parsed.Path) == "" || parsed.Path == "/" {
		parsed.Path = "/v1/events"
	}
	return parsed.String(), nil
}

func sendEvent(ctx context.Context, eventsURL string, event types.EventEnvelope) (string, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal event envelope: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, eventsURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build events request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send event request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read events response: %w", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("gateway rejected event: %s", msg)
	}

	var result struct {
		Accepted bool   `json:"accepted"`
		EventID  string `json:"event_id"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode events response: %w", err)
	}
	if !result.Accepted {
		return "", fmt.Errorf("gateway did not accept event")
	}
	if strings.TrimSpace(result.EventID) == "" {
		return "", fmt.Errorf("gateway response missing event_id")
	}
	return result.EventID, nil
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

func newHexID() string {
	buf := make([]byte, 16)
	if _, err := cryptorand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
