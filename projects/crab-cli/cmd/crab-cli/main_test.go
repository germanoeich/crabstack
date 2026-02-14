package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crabstack.local/lib/types"
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
