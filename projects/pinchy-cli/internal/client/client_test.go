package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"pinchy.local/lib/types"
	"pinchy.local/projects/pinchy-cli/internal/protocol"
)

func TestClientConnectSendReceive(t *testing.T) {
	gatewayPub, gatewayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway ed25519 keypair: %v", err)
	}
	gatewayPubB64 := base64.StdEncoding.EncodeToString(gatewayPub)

	gatewayX25519Priv, gatewayX25519PubB64, err := protocol.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate gateway x25519 keypair: %v", err)
	}

	serverErrCh := make(chan error, 1)
	upgrader := websocket.Upgrader{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pair", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErrCh <- fmt.Errorf("upgrade websocket: %w", err)
			return
		}
		defer conn.Close()

		pairInit := protocol.PairInitWire{
			Type:      types.PairingMessageTypeInit,
			Version:   types.VersionV1,
			PairingID: "pair_1",
			Gateway: protocol.PairGatewayInfoWire{
				GatewayID:        "gw_test",
				PublicKeyEd25519: gatewayPubB64,
				PublicKeyX25519:  gatewayX25519PubB64,
				Nonce:            "nonce",
				IssuedAt:         time.Now().UTC(),
			},
		}
		pairInit, err = protocol.SignPairInit(pairInit, gatewayPriv)
		if err != nil {
			serverErrCh <- fmt.Errorf("sign pair.init: %w", err)
			return
		}

		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErrCh <- err
			return
		}
		if err := conn.WriteJSON(pairInit); err != nil {
			serverErrCh <- fmt.Errorf("write pair.init: %w", err)
			return
		}

		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErrCh <- err
			return
		}
		var identity types.PairIdentity
		if err := conn.ReadJSON(&identity); err != nil {
			serverErrCh <- fmt.Errorf("read pair.identity: %w", err)
			return
		}
		if err := protocol.VerifyPairIdentity(identity); err != nil {
			serverErrCh <- err
			return
		}

		challenge, err := protocol.EncryptPairChallenge(gatewayX25519Priv, identity.Remote.PublicKeyX25519, "pair_1", "challenge_1", []byte("proof"), []byte("aad"))
		if err != nil {
			serverErrCh <- fmt.Errorf("encrypt challenge: %w", err)
			return
		}
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErrCh <- err
			return
		}
		if err := conn.WriteJSON(challenge); err != nil {
			serverErrCh <- fmt.Errorf("write pair.challenge: %w", err)
			return
		}

		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErrCh <- err
			return
		}
		var challengeResp types.PairChallengeResponse
		if err := conn.ReadJSON(&challengeResp); err != nil {
			serverErrCh <- fmt.Errorf("read pair.challenge_response: %w", err)
			return
		}
		if err := protocol.VerifyPairChallengeResponse(challengeResp, identity.Remote.PublicKeyEd25519); err != nil {
			serverErrCh <- err
			return
		}
		responsePlaintext, err := base64.StdEncoding.DecodeString(challengeResp.ChallengePlaintext)
		if err != nil {
			serverErrCh <- fmt.Errorf("decode challenge response plaintext: %w", err)
			return
		}
		if string(responsePlaintext) != "proof" {
			serverErrCh <- fmt.Errorf("unexpected challenge response plaintext %q", string(responsePlaintext))
			return
		}

		complete := types.PairComplete{
			Type:      types.PairingMessageTypeComplete,
			Version:   types.VersionV1,
			PairingID: "pair_1",
			Status:    types.PairingStatusOK,
		}
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErrCh <- err
			return
		}
		if err := conn.WriteJSON(complete); err != nil {
			serverErrCh <- fmt.Errorf("write pair.complete: %w", err)
			return
		}

		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErrCh <- err
			return
		}
		var inbound types.EventEnvelope
		if err := conn.ReadJSON(&inbound); err != nil {
			serverErrCh <- fmt.Errorf("read inbound event: %w", err)
			return
		}
		if inbound.EventType != types.EventTypeChannelMessageReceived {
			serverErrCh <- fmt.Errorf("unexpected inbound event_type %s", inbound.EventType)
			return
		}

		outboundPayload, err := json.Marshal(types.AgentResponseCreatedPayload{ResponseID: "resp_1"})
		if err != nil {
			serverErrCh <- err
			return
		}
		outbound := types.EventEnvelope{
			Version:    types.VersionV1,
			EventID:    "evt_out",
			TraceID:    inbound.TraceID,
			OccurredAt: time.Now().UTC(),
			EventType:  types.EventTypeAgentResponseCreated,
			TenantID:   inbound.TenantID,
			Source: types.EventSource{
				ComponentType: types.ComponentTypeGateway,
				ComponentID:   "gateway-core",
			},
			Routing: inbound.Routing,
			Payload: outboundPayload,
		}

		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErrCh <- err
			return
		}
		if err := conn.WriteJSON(outbound); err != nil {
			serverErrCh <- fmt.Errorf("write outbound event: %w", err)
			return
		}
	})

	server, err := newTCP4Server(mux)
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/pair"
	cfg := Config{
		GatewayWSURL:               wsURL,
		GatewayPublicKeyEd25519B64: gatewayPubB64,
		TenantID:                   "tenant_1",
		AgentID:                    "agent_1",
		SessionID:                  "session_1",
		ComponentID:                "cli_1",
		ComponentType:              types.ComponentTypeOperator,
		Platform:                   "cli",
		ChannelID:                  "terminal",
		ActorID:                    "operator",
	}

	cli, err := New(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cli.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if err := cli.SendTextMessage(ctx, "hello"); err != nil {
		t.Fatalf("send text message: %v", err)
	}

	select {
	case event := <-cli.Events():
		if event.EventType != types.EventTypeAgentResponseCreated {
			t.Fatalf("unexpected event_type %s", event.EventType)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for gateway event")
	}

	select {
	case err := <-serverErrCh:
		t.Fatalf("server assertion failed: %v", err)
	default:
	}
}

func TestClientConnectRejectsMismatchedGatewayKey(t *testing.T) {
	gatewayPub, gatewayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway ed25519 keypair: %v", err)
	}
	gatewayPubB64 := base64.StdEncoding.EncodeToString(gatewayPub)

	gatewayX25519Priv, gatewayX25519PubB64, err := protocol.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate gateway x25519 keypair: %v", err)
	}

	upgrader := websocket.Upgrader{}
	server, err := newTCP4Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		pairInit := protocol.PairInitWire{
			Type:      types.PairingMessageTypeInit,
			Version:   types.VersionV1,
			PairingID: "pair_1",
			Gateway: protocol.PairGatewayInfoWire{
				GatewayID:        "gw_test",
				PublicKeyEd25519: gatewayPubB64,
				PublicKeyX25519:  gatewayX25519PubB64,
				Nonce:            "nonce",
				IssuedAt:         time.Now().UTC(),
			},
		}
		pairInit, _ = protocol.SignPairInit(pairInit, gatewayPriv)
		_ = conn.WriteJSON(pairInit)

		_, _, _ = conn.ReadMessage()
		_ = gatewayX25519Priv
	}))
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	defer server.Close()

	cfg := Config{
		GatewayWSURL:               "ws" + strings.TrimPrefix(server.URL, "http"),
		GatewayPublicKeyEd25519B64: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		TenantID:                   "tenant_1",
		AgentID:                    "agent_1",
		SessionID:                  "session_1",
		ComponentID:                "cli_1",
		ComponentType:              types.ComponentTypeOperator,
		Platform:                   "cli",
		ChannelID:                  "terminal",
		ActorID:                    "operator",
	}

	cli, err := New(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cli.Connect(ctx); err == nil {
		t.Fatalf("expected connect to fail with mismatched configured gateway key")
	}
}

func newTCP4Server(handler http.Handler) (*localServer, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()
	return &localServer{
		URL:      "http://" + listener.Addr().String(),
		listener: listener,
		server:   server,
	}, nil
}

type localServer struct {
	URL      string
	listener net.Listener
	server   *http.Server
}

func (s *localServer) Close() {
	if s == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.server.Shutdown(shutdownCtx)
	_ = s.listener.Close()
}
