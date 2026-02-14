package pairing

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crabstack.local/lib/types"
)

func TestTriggerGatewayPair(t *testing.T) {
	adminSocket := filepath.Join(t.TempDir(), "gateway-admin.sock")
	if err := os.Remove(adminSocket); err != nil && !os.IsNotExist(err) {
		t.Fatalf("cleanup socket path: %v", err)
	}
	listener, err := net.Listen("unix", adminSocket)
	if err != nil {
		t.Skipf("unix socket listen not permitted in this environment: %v", err)
	}
	defer listener.Close()

	serverErrCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pairings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req gatewayPairRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
			return
		}
		if req.ComponentType != string(types.ComponentTypeToolHost) {
			serverErrCh <- fmt.Errorf("unexpected component_type %q", req.ComponentType)
		}
		if req.ComponentID != "tool-host-1" {
			serverErrCh <- fmt.Errorf("unexpected component_id %q", req.ComponentID)
		}
		if req.Endpoint != "ws://127.0.0.1:5225/v1/pair" {
			serverErrCh <- fmt.Errorf("unexpected endpoint %q", req.Endpoint)
		}

		_ = json.NewEncoder(w).Encode(gatewayPairResponse{
			PairingID: "pair_123",
			Endpoint:  req.Endpoint,
			Peer: struct {
				ComponentID         string `json:"component_id"`
				ComponentType       string `json:"component_type"`
				MTLSCertFingerprint string `json:"mtls_cert_fingerprint"`
			}{
				ComponentID:         "tool-host-1",
				ComponentType:       string(types.ComponentTypeToolHost),
				MTLSCertFingerprint: "sha256:test",
			},
		})
	})

	server := &http.Server{Handler: mux}
	defer func() { _ = server.Shutdown(context.Background()) }()
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := TriggerGatewayPair(ctx, GatewayPairConfig{
		GatewayAdminSocketPath: adminSocket,
		ComponentType:          types.ComponentTypeToolHost,
		ComponentID:            "tool-host-1",
		Endpoint:               "ws://127.0.0.1:5225/v1/pair",
		Timeout:                2 * time.Second,
	})
	if err != nil {
		t.Fatalf("trigger pair: %v", err)
	}
	if result.PairingID != "pair_123" {
		t.Fatalf("unexpected pairing id %q", result.PairingID)
	}
	if result.ComponentID != "tool-host-1" {
		t.Fatalf("unexpected component id %q", result.ComponentID)
	}
	if result.ComponentType != types.ComponentTypeToolHost {
		t.Fatalf("unexpected component type %q", result.ComponentType)
	}
	if result.MTLSCertFingerprint != "sha256:test" {
		t.Fatalf("unexpected fingerprint %q", result.MTLSCertFingerprint)
	}

	select {
	case err := <-serverErrCh:
		t.Fatalf("mock gateway error: %v", err)
	default:
	}
}

func TestTriggerGatewayPairValidate(t *testing.T) {
	ctx := context.Background()
	_, err := TriggerGatewayPair(ctx, GatewayPairConfig{
		GatewayAdminSocketPath: "",
		ComponentType:          types.ComponentTypeToolHost,
		ComponentID:            "tool-host-1",
		Endpoint:               "ws://127.0.0.1:5225/v1/pair",
		Timeout:                time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "gateway admin socket path") {
		t.Fatalf("expected admin socket validation error, got %v", err)
	}

	_, err = TriggerGatewayPair(ctx, GatewayPairConfig{
		GatewayAdminSocketPath: "/tmp/gateway.sock",
		ComponentType:          types.ComponentTypeToolHost,
		ComponentID:            "",
		Endpoint:               "",
		Timeout:                time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "component_id is required") {
		t.Fatalf("expected component_id validation error, got %v", err)
	}

	_, err = TriggerGatewayPair(ctx, GatewayPairConfig{
		GatewayAdminSocketPath: "/tmp/gateway.sock",
		ComponentType:          types.ComponentTypeToolHost,
		ComponentID:            "tool-host-1",
		Endpoint:               "",
		Timeout:                time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Fatalf("expected endpoint validation error, got %v", err)
	}
}

func TestTriggerGatewayPairGatewayError(t *testing.T) {
	adminSocket := filepath.Join(t.TempDir(), "gateway-admin.sock")
	if err := os.Remove(adminSocket); err != nil && !os.IsNotExist(err) {
		t.Fatalf("cleanup socket path: %v", err)
	}
	listener, err := net.Listen("unix", adminSocket)
	if err != nil {
		t.Skipf("unix socket listen not permitted in this environment: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pairings", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream exploded", http.StatusBadGateway)
	})

	server := &http.Server{Handler: mux}
	defer func() { _ = server.Shutdown(context.Background()) }()
	go func() {
		_ = server.Serve(listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = TriggerGatewayPair(ctx, GatewayPairConfig{
		GatewayAdminSocketPath: adminSocket,
		ComponentType:          types.ComponentTypeToolHost,
		ComponentID:            "tool-host-1",
		Endpoint:               "ws://127.0.0.1:5225/v1/pair",
		Timeout:                2 * time.Second,
	})
	if err == nil {
		t.Fatalf("expected gateway error")
	}
	if !strings.Contains(err.Error(), "gateway pairing failed") {
		t.Fatalf("expected gateway pairing failed error, got %v", err)
	}
}
