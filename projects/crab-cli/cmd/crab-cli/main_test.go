package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crabstack.local/lib/types"
	authflow "crabstack.local/projects/crab-cli/internal/auth"
)

type observedPairRequest struct {
	ComponentType string `json:"component_type"`
	ComponentID   string `json:"component_id"`
	Endpoint      string `json:"endpoint"`
}

func TestRunPairCommandTool(t *testing.T) {
	adminSocket := startAdminPairServer(t, func(req observedPairRequest) (int, map[string]any) {
		if req.ComponentType != "tool_host" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected component_type %q", req.ComponentType)}
		}
		if req.ComponentID != "memory-east" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected component_id %q", req.ComponentID)}
		}
		if req.Endpoint != "wss://10.0.0.1:5225/v1/pair" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected endpoint %q", req.Endpoint)}
		}
		return http.StatusOK, map[string]any{
			"pairing_id": "pair_tool_1",
			"endpoint":   req.Endpoint,
			"peer": map[string]any{
				"component_type":        "tool_host",
				"component_id":          "memory-east",
				"mtls_cert_fingerprint": "sha256:abc",
				"status":                "active",
				"paired_at":             time.Now().UTC().Format(time.RFC3339Nano),
				"last_seen_at":          time.Now().UTC().Format(time.RFC3339Nano),
				"endpoint":              req.Endpoint,
			},
		}
	})

	err := runPairCommand([]string{
		"tool",
		"-admin-socket", adminSocket,
		"-timeout", "2s",
		"wss://10.0.0.1:5225/v1/pair",
		"memory-east",
	})
	if err != nil {
		t.Fatalf("runPairCommand(tool) failed: %v", err)
	}
}

func TestRunPairCommandSubscriber(t *testing.T) {
	adminSocket := startAdminPairServer(t, func(req observedPairRequest) (int, map[string]any) {
		if req.ComponentType != "subscriber" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected component_type %q", req.ComponentType)}
		}
		if req.ComponentID != "discord-outbound" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected component_id %q", req.ComponentID)}
		}
		return http.StatusOK, map[string]any{
			"pairing_id": "pair_subscriber_1",
			"endpoint":   req.Endpoint,
			"peer": map[string]any{
				"component_type":        "subscriber",
				"component_id":          "discord-outbound",
				"mtls_cert_fingerprint": "sha256:def",
				"status":                "active",
				"paired_at":             time.Now().UTC().Format(time.RFC3339Nano),
				"last_seen_at":          time.Now().UTC().Format(time.RFC3339Nano),
				"endpoint":              req.Endpoint,
			},
		}
	})

	err := runPairCommand([]string{
		"subscriber",
		"-admin-socket", adminSocket,
		"wss://10.0.0.2:7443/v1/pair",
		"discord-outbound",
	})
	if err != nil {
		t.Fatalf("runPairCommand(subscriber) failed: %v", err)
	}
}

func TestRunPairCommandCLI(t *testing.T) {
	adminSocket := startAdminPairServer(t, func(req observedPairRequest) (int, map[string]any) {
		if req.ComponentType != "operator" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected component_type %q", req.ComponentType)}
		}
		if req.ComponentID != "laptop-admin" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected component_id %q", req.ComponentID)}
		}
		if req.Endpoint != "wss://10.0.0.3:7443/v1/pair" {
			return http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("unexpected endpoint %q", req.Endpoint)}
		}
		return http.StatusOK, map[string]any{
			"pairing_id": "pair_cli_1",
			"endpoint":   req.Endpoint,
			"peer": map[string]any{
				"component_type":        "operator",
				"component_id":          "laptop-admin",
				"mtls_cert_fingerprint": "sha256:cli",
				"status":                "active",
				"paired_at":             time.Now().UTC().Format(time.RFC3339Nano),
				"last_seen_at":          time.Now().UTC().Format(time.RFC3339Nano),
				"endpoint":              req.Endpoint,
			},
		}
	})

	err := runPairCommand([]string{
		"cli",
		"-admin-socket", adminSocket,
		"wss://10.0.0.3:7443/v1/pair",
		"laptop-admin",
	})
	if err != nil {
		t.Fatalf("runPairCommand(cli) failed: %v", err)
	}
}

func TestRunPairCommandValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing subcommand",
			args: []string{},
			want: "usage: crab pair <test|tool|subscriber|cli>",
		},
		{
			name: "unsupported subcommand",
			args: []string{"provider"},
			want: "unsupported pair subcommand",
		},
		{
			name: "missing tool name",
			args: []string{"tool", "wss://10.0.0.1:5225/v1/pair"},
			want: "usage: crab pair tool",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runPairCommand(tc.args)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRunEventCommandSend(t *testing.T) {
	received := make(chan types.EventEnvelope, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/v1/events" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var event types.EventEnvelope
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
			return
		}
		received <- event
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted": true,
			"event_id": event.EventID,
		})
	}))
	defer server.Close()

	err := runEventCommand([]string{
		"send",
		"-gateway-http", server.URL,
		"-tenant-id", "tenant_cli",
		"-agent-id", "agent_cli",
		"-component-id", "cli_sender",
		"-channel-id", "cli",
		"-actor-id", "gin",
		"hello from cli",
	})
	if err != nil {
		t.Fatalf("runEventCommand(send) failed: %v", err)
	}

	select {
	case event := <-received:
		if event.EventType != types.EventTypeChannelMessageReceived {
			t.Fatalf("unexpected event_type %s", event.EventType)
		}
		if event.Source.ComponentType != types.ComponentTypeOperator {
			t.Fatalf("unexpected source.component_type %s", event.Source.ComponentType)
		}
		if event.Source.Platform != "cli" {
			t.Fatalf("unexpected source.platform %q", event.Source.Platform)
		}
		if event.Source.ChannelID != "cli" {
			t.Fatalf("unexpected source.channel_id %q", event.Source.ChannelID)
		}
		if !strings.HasPrefix(event.Routing.SessionID, "cli-") {
			t.Fatalf("expected auto session id with cli- prefix, got %q", event.Routing.SessionID)
		}
		var payload types.ChannelMessageReceivedPayload
		if err := event.DecodePayload(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.Text != "hello from cli" {
			t.Fatalf("unexpected payload text %q", payload.Text)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event payload")
	}
}

func TestRunEventCommandSendUsesGatewayHTTPEnv(t *testing.T) {
	received := make(chan types.EventEnvelope, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/v1/events" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var event types.EventEnvelope
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
			return
		}
		received <- event
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted": true,
			"event_id": event.EventID,
		})
	}))
	defer server.Close()

	t.Setenv("CRAB_CLI_GATEWAY_HTTP_URL", server.URL)
	err := runEventCommand([]string{
		"send",
		"env-backed send",
	})
	if err != nil {
		t.Fatalf("runEventCommand(send) failed: %v", err)
	}

	select {
	case event := <-received:
		var payload types.ChannelMessageReceivedPayload
		if err := event.DecodePayload(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.Text != "env-backed send" {
			t.Fatalf("unexpected payload text %q", payload.Text)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event payload")
	}
}

func TestRunEventCommandValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing subcommand",
			args: []string{},
			want: "usage: crab event <send>",
		},
		{
			name: "unsupported subcommand",
			args: []string{"list"},
			want: "unsupported event subcommand",
		},
		{
			name: "missing text",
			args: []string{"send"},
			want: "usage: crab event send",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runEventCommand(tc.args)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRunAuthCommandValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing subcommand",
			args: []string{},
			want: "usage: crab auth <codex|claude|anthropic>",
		},
		{
			name: "unsupported subcommand",
			args: []string{"api-key"},
			want: "unsupported auth subcommand",
		},
		{
			name: "unexpected positional arg",
			args: []string{"codex", "extra"},
			want: "usage: crab auth codex",
		},
		{
			name: "unexpected positional arg anthropic",
			args: []string{"anthropic", "extra"},
			want: "usage: crab auth anthropic",
		},
		{
			name: "unexpected positional arg claude",
			args: []string{"claude", "extra"},
			want: "usage: crab auth claude",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runAuthCommand(tc.args)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRunAuthCommandCodex(t *testing.T) {
	originalLogin := codexLogin
	originalSave := codexSaveCredentials
	originalDefaults := codexDefaultConfig
	originalDefaultPath := codexDefaultCredentialsPath
	t.Cleanup(func() {
		codexLogin = originalLogin
		codexSaveCredentials = originalSave
		codexDefaultConfig = originalDefaults
		codexDefaultCredentialsPath = originalDefaultPath
	})

	fixedNow := time.Date(2026, 2, 14, 1, 2, 3, 0, time.UTC)
	codexDefaultConfig = func() authflow.Config {
		cfg := authflow.DefaultConfig()
		cfg.Now = func() time.Time { return fixedNow }
		return cfg
	}
	codexDefaultCredentialsPath = func() string {
		return filepath.Join(t.TempDir(), "default-codex.json")
	}

	var observedLoginConfig authflow.Config
	codexLogin = func(_ context.Context, cfg authflow.Config, _ io.Reader, _ io.Writer) (authflow.Credentials, error) {
		observedLoginConfig = cfg
		return authflow.Credentials{
			Provider:     "codex",
			ClientID:     "client_test",
			AccountID:    "acct_test",
			AccessToken:  "access",
			RefreshToken: "refresh",
			ExpiresAt:    fixedNow.Add(1 * time.Hour),
			ObtainedAt:   fixedNow,
		}, nil
	}

	outputPath := filepath.Join(t.TempDir(), "auth", "codex.json")
	var savedPath string
	codexSaveCredentials = func(path string, creds authflow.Credentials) (string, error) {
		if creds.AccountID != "acct_test" {
			return "", fmt.Errorf("unexpected account id %q", creds.AccountID)
		}
		savedPath = path
		return path, nil
	}

	err := runAuthCommand([]string{
		"codex",
		"-auth-file", outputPath,
		"-timeout", "90s",
	})
	if err != nil {
		t.Fatalf("runAuthCommand(codex) failed: %v", err)
	}

	if observedLoginConfig.Originator != authflow.DefaultConfig().Originator {
		t.Fatalf("unexpected originator %q", observedLoginConfig.Originator)
	}
	if observedLoginConfig.Timeout != 90*time.Second {
		t.Fatalf("unexpected timeout %s", observedLoginConfig.Timeout)
	}
	if savedPath != outputPath {
		t.Fatalf("unexpected saved path %q", savedPath)
	}
}

func TestRunAuthCommandAnthropic(t *testing.T) {
	originalLogin := anthropicLogin
	originalSave := anthropicSaveCredentials
	originalDefaults := anthropicDefaultConfig
	originalDefaultPath := anthropicDefaultCredentialsPath
	t.Cleanup(func() {
		anthropicLogin = originalLogin
		anthropicSaveCredentials = originalSave
		anthropicDefaultConfig = originalDefaults
		anthropicDefaultCredentialsPath = originalDefaultPath
	})

	fixedNow := time.Date(2026, 2, 14, 1, 2, 3, 0, time.UTC)
	anthropicDefaultConfig = func() authflow.AnthropicConfig {
		cfg := authflow.DefaultAnthropicConfig()
		cfg.Now = func() time.Time { return fixedNow }
		return cfg
	}
	anthropicDefaultCredentialsPath = func() string {
		return filepath.Join(t.TempDir(), "default-anthropic.json")
	}

	var observedLoginConfig authflow.AnthropicConfig
	anthropicLogin = func(_ context.Context, cfg authflow.AnthropicConfig, _ io.Reader, _ io.Writer) (authflow.Credentials, error) {
		observedLoginConfig = cfg
		return authflow.Credentials{
			Provider:     "anthropic",
			ClientID:     "client_test",
			AccountID:    "acct_test",
			AccountEmail: "user@example.com",
			AccessToken:  "access",
			RefreshToken: "refresh",
			ExpiresAt:    fixedNow.Add(1 * time.Hour),
			ObtainedAt:   fixedNow,
		}, nil
	}

	outputPath := filepath.Join(t.TempDir(), "auth", "anthropic.json")
	var savedPath string
	anthropicSaveCredentials = func(path string, creds authflow.Credentials) (string, error) {
		if creds.Provider != "anthropic" {
			return "", fmt.Errorf("unexpected provider %q", creds.Provider)
		}
		if creds.AccountID != "acct_test" {
			return "", fmt.Errorf("unexpected account id %q", creds.AccountID)
		}
		savedPath = path
		return path, nil
	}

	err := runAuthCommand([]string{
		"anthropic",
		"-auth-file", outputPath,
		"-timeout", "90s",
	})
	if err != nil {
		t.Fatalf("runAuthCommand(anthropic) failed: %v", err)
	}

	if observedLoginConfig.Scope != authflow.DefaultAnthropicConfig().Scope {
		t.Fatalf("unexpected scope %q", observedLoginConfig.Scope)
	}
	if observedLoginConfig.CallbackAddr != authflow.DefaultAnthropicConfig().CallbackAddr {
		t.Fatalf("unexpected callback addr %q", observedLoginConfig.CallbackAddr)
	}
	if observedLoginConfig.Timeout != 90*time.Second {
		t.Fatalf("unexpected timeout %s", observedLoginConfig.Timeout)
	}
	if savedPath != outputPath {
		t.Fatalf("unexpected saved path %q", savedPath)
	}
}

func TestRunAuthCommandClaude(t *testing.T) {
	originalLogin := claudeLogin
	originalSave := claudeSaveCredentials
	originalDefaults := claudeDefaultConfig
	originalDefaultPath := claudeDefaultCredentialsPath
	t.Cleanup(func() {
		claudeLogin = originalLogin
		claudeSaveCredentials = originalSave
		claudeDefaultConfig = originalDefaults
		claudeDefaultCredentialsPath = originalDefaultPath
	})

	fixedNow := time.Date(2026, 2, 14, 1, 2, 3, 0, time.UTC)
	claudeDefaultConfig = func() authflow.ClaudeConfig {
		cfg := authflow.DefaultClaudeConfig()
		cfg.Now = func() time.Time { return fixedNow }
		return cfg
	}
	claudeDefaultCredentialsPath = func() string {
		return filepath.Join(t.TempDir(), "default-claude.json")
	}

	var observedLoginConfig authflow.ClaudeConfig
	claudeLogin = func(_ context.Context, cfg authflow.ClaudeConfig, _ io.Reader, _ io.Writer) (authflow.Credentials, error) {
		observedLoginConfig = cfg
		return authflow.Credentials{
			Provider:     "claude",
			ClientID:     "client_test",
			AccountID:    "acct_test",
			AccessToken:  "access",
			RefreshToken: "refresh",
			ExpiresAt:    fixedNow.Add(1 * time.Hour),
			ObtainedAt:   fixedNow,
		}, nil
	}

	outputPath := filepath.Join(t.TempDir(), "auth", "claude.json")
	var savedPath string
	claudeSaveCredentials = func(path string, creds authflow.Credentials) (string, error) {
		if creds.Provider != "claude" {
			return "", fmt.Errorf("unexpected provider %q", creds.Provider)
		}
		if creds.AccountID != "acct_test" {
			return "", fmt.Errorf("unexpected account id %q", creds.AccountID)
		}
		savedPath = path
		return path, nil
	}

	err := runAuthCommand([]string{
		"claude",
		"-auth-file", outputPath,
		"-mode", "console",
		"-timeout", "90s",
	})
	if err != nil {
		t.Fatalf("runAuthCommand(claude) failed: %v", err)
	}

	if observedLoginConfig.Mode != authflow.ClaudeModeConsole {
		t.Fatalf("unexpected mode %q", observedLoginConfig.Mode)
	}
	if observedLoginConfig.Scope != authflow.DefaultClaudeConfig().Scope {
		t.Fatalf("unexpected scope %q", observedLoginConfig.Scope)
	}
	if observedLoginConfig.CallbackAddr != authflow.DefaultClaudeConfig().CallbackAddr {
		t.Fatalf("unexpected callback addr %q", observedLoginConfig.CallbackAddr)
	}
	if observedLoginConfig.Timeout != 90*time.Second {
		t.Fatalf("unexpected timeout %s", observedLoginConfig.Timeout)
	}
	if savedPath != outputPath {
		t.Fatalf("unexpected saved path %q", savedPath)
	}
}

func TestResolveGatewayPublicKeyFromIdentityFile(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	keyDir := t.TempDir()
	t.Setenv("CRAB_GATEWAY_KEY_DIR", keyDir)
	identityPath := filepath.Join(keyDir, "gateway_identity.json")
	identityDoc := map[string]string{
		"gateway_id":          "gw_test",
		"private_key_ed25519": base64.StdEncoding.EncodeToString(priv),
	}
	encoded, err := json.Marshal(identityDoc)
	if err != nil {
		t.Fatalf("marshal identity file: %v", err)
	}
	if err := os.WriteFile(identityPath, encoded, 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}

	got, err := resolveGatewayPublicKey("")
	if err != nil {
		t.Fatalf("resolveGatewayPublicKey failed: %v", err)
	}
	want := base64.StdEncoding.EncodeToString(pub)
	if got != want {
		t.Fatalf("unexpected public key: got=%s want=%s", got, want)
	}
}

func TestResolveGatewayPublicKeyMissingIdentityFile(t *testing.T) {
	t.Setenv("CRAB_GATEWAY_KEY_DIR", t.TempDir())
	_, err := resolveGatewayPublicKey("")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "gateway public key is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func startAdminPairServer(t *testing.T, handle func(observedPairRequest) (int, map[string]any)) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "gateway-admin.sock")
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("cleanup socket path: %v", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix socket listen not permitted in this environment: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/pairings" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			var req observedPairRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
				return
			}
			status, body := handle(req)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		}),
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	go func() {
		_ = server.Serve(listener)
	}()

	return socketPath
}
