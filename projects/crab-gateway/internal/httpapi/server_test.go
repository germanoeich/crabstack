package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"crabstack.local/projects/crab-gateway/internal/dispatch"
	"crabstack.local/projects/crab-gateway/internal/gateway"
	"crabstack.local/projects/crab-gateway/internal/model"
	"crabstack.local/projects/crab-gateway/internal/pairing"
	"crabstack.local/projects/crab-gateway/internal/session"
	"crabstack.local/projects/crab-sdk/types"
)

type fakePairingService struct {
	result pairing.PairResult
	err    error
	seen   pairing.PairRequest
}

type staticModelProvider struct{}

func (staticModelProvider) Complete(_ context.Context, _ model.CompletionRequest) (model.CompletionResponse, error) {
	return model.CompletionResponse{
		Content: "ok",
		Model:   "claude-sonnet-4-20250514",
	}, nil
}

func newModelRegistryForTests() *model.Registry {
	registry := model.NewRegistry()
	registry.Register("anthropic", staticModelProvider{})
	return registry
}

func (f *fakePairingService) Pair(_ context.Context, req pairing.PairRequest) (pairing.PairResult, error) {
	f.seen = req
	if f.err != nil {
		return pairing.PairResult{}, f.err
	}
	return f.result, nil
}

func TestHealthz(t *testing.T) {
	h := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestEventsAcceptsValidEnvelope(t *testing.T) {
	h := newTestHandler(t, nil)
	event := validEnvelope(t)
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestEventsRejectsInvalidEnvelope(t *testing.T) {
	h := newTestHandler(t, nil)
	event := validEnvelope(t)
	event.TenantID = ""
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestValidateEventEnvelope(t *testing.T) {
	event := validEnvelope(t)
	if err := validateEventEnvelope(event); err != nil {
		t.Fatalf("expected valid envelope, got %v", err)
	}

	event.EventType = types.EventType("unknown")
	if err := validateEventEnvelope(event); err == nil {
		t.Fatalf("expected unsupported event_type error")
	}
}

func TestPairingsRouteDisabledOnPublicServer(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	d := dispatch.New(logger, nil)
	store := session.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	svc := gateway.NewService(logger, d, store, newModelRegistryForTests())
	srv := NewServer(logger, ":0", svc, &fakePairingService{}, false)

	body := []byte(`{"component_type":"tool","component_id":"memory-east","endpoint":"ws://10.0.0.1:5225"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/pairings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when pairing routes are disabled, got %d", rr.Code)
	}
}

func TestPairingsRoute(t *testing.T) {
	fake := &fakePairingService{
		result: pairing.PairResult{
			PairingID: "pair_1",
			Endpoint:  "ws://10.0.0.1:5225",
			Peer: types.PairedPeerRecord{
				ComponentType: types.ComponentTypeToolHost,
				ComponentID:   "memory-east",
				Endpoint:      "ws://10.0.0.1:5225",
				Status:        types.PairedPeerStatusActive,
			},
		},
	}
	h := newTestHandler(t, fake)

	body := []byte(`{"component_type":"tool","component_id":"memory-east","endpoint":"ws://10.0.0.1:5225"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/pairings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if fake.seen.ComponentType != types.ComponentTypeToolHost {
		t.Fatalf("expected normalized component type tool_host, got %s", fake.seen.ComponentType)
	}
	if fake.seen.ComponentID != "memory-east" {
		t.Fatalf("expected component id memory-east, got %s", fake.seen.ComponentID)
	}
}

func TestPairingsRouteErrorMapping(t *testing.T) {
	fake := &fakePairingService{err: errors.New("boom")}
	h := newTestHandler(t, fake)

	body := []byte(`{"component_type":"tool","component_id":"memory-east","endpoint":"ws://10.0.0.1:5225"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/pairings", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}

	fake.err = pairing.ErrUnsupportedComponent
	req = httptest.NewRequest(http.MethodPost, "/v1/pairings", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/pairings", bytes.NewReader([]byte(`{"component_type":"tool","endpoint":"ws://10.0.0.1:5225"}`)))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing component_id, got %d", rr.Code)
	}
}

func TestPairingsWS(t *testing.T) {
	fake := &fakePairingService{
		result: pairing.PairResult{PairingID: "pair_ws", Endpoint: "ws://10.0.0.2:9000", Peer: types.PairedPeerRecord{ComponentType: types.ComponentTypeListener, ComponentID: "listener-a", Endpoint: "ws://10.0.0.2:9000", Status: types.PairedPeerStatusActive}},
	}
	h := newTestHandler(t, fake)
	ts := httptest.NewServer(h)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	u.Scheme = "ws"
	u.Path = "/v1/pairings/ws"

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(map[string]any{
		"action":         "pair.start",
		"component_type": "listener",
		"component_id":   "listener-a",
		"endpoint":       "ws://10.0.0.2:9000",
	}); err != nil {
		t.Fatalf("write ws request: %v", err)
	}

	var result wsPairResult
	if err := conn.ReadJSON(&result); err != nil {
		t.Fatalf("read ws response: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected ws pairing success, got error=%s", result.Error)
	}
	if result.Result == nil || result.Result.PairingID != "pair_ws" {
		t.Fatalf("unexpected ws pairing result: %+v", result.Result)
	}
	if fake.seen.ComponentID != "listener-a" {
		t.Fatalf("expected component_id listener-a, got %s", fake.seen.ComponentID)
	}
}

func TestPairingsWSRejectsCrossOrigin(t *testing.T) {
	fake := &fakePairingService{
		result: pairing.PairResult{PairingID: "pair_ws", Endpoint: "ws://10.0.0.2:9000", Peer: types.PairedPeerRecord{ComponentType: types.ComponentTypeListener, ComponentID: "listener-a", Endpoint: "ws://10.0.0.2:9000", Status: types.PairedPeerStatusActive}},
	}
	h := newTestHandler(t, fake)
	ts := httptest.NewServer(h)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	u.Scheme = "ws"
	u.Path = "/v1/pairings/ws"

	headers := http.Header{}
	headers.Set("Origin", "http://evil.example")
	conn, resp, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("expected cross-origin websocket upgrade failure")
	}
	if resp == nil {
		t.Fatalf("expected http response for failed websocket upgrade")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin upgrade, got %d", resp.StatusCode)
	}
}

func TestPairingsWSAcceptsMatchingOrigin(t *testing.T) {
	fake := &fakePairingService{
		result: pairing.PairResult{PairingID: "pair_ws", Endpoint: "ws://10.0.0.2:9000", Peer: types.PairedPeerRecord{ComponentType: types.ComponentTypeListener, ComponentID: "listener-a", Endpoint: "ws://10.0.0.2:9000", Status: types.PairedPeerStatusActive}},
	}
	h := newTestHandler(t, fake)
	ts := httptest.NewServer(h)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	u.Scheme = "ws"
	u.Path = "/v1/pairings/ws"

	headers := http.Header{}
	headers.Set("Origin", ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		t.Fatalf("dial websocket with same-origin header: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(map[string]any{
		"action":         "pair.start",
		"component_type": "listener",
		"component_id":   "listener-a",
		"endpoint":       "ws://10.0.0.2:9000",
	}); err != nil {
		t.Fatalf("write ws request: %v", err)
	}

	var result wsPairResult
	if err := conn.ReadJSON(&result); err != nil {
		t.Fatalf("read ws response: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected ws pairing success with matching origin, got error=%s", result.Error)
	}
}

func TestPairingsWSRejectsOversizedRequest(t *testing.T) {
	fake := &fakePairingService{
		result: pairing.PairResult{PairingID: "pair_ws"},
	}
	h := newTestHandler(t, fake)
	ts := httptest.NewServer(h)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	u.Scheme = "ws"
	u.Path = "/v1/pairings/ws"

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	oversizedEndpoint := "ws://127.0.0.1/" + strings.Repeat("a", int(maxPairingsWSRequestBytes)+1024)
	if err := conn.WriteJSON(map[string]any{
		"action":         "pair.start",
		"component_type": "tool",
		"component_id":   "tool-a",
		"endpoint":       oversizedEndpoint,
	}); err != nil {
		t.Fatalf("write oversized ws request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var result wsPairResult
	err = conn.ReadJSON(&result)
	if err == nil && result.OK {
		t.Fatalf("expected oversized request to fail")
	}
	if fake.seen.Endpoint != "" {
		t.Fatalf("expected pairing service not to be called for oversized request")
	}
}

func newTestHandler(t *testing.T, pairingSvc pairing.Service) http.Handler {
	t.Helper()
	logger := log.New(os.Stdout, "", 0)
	d := dispatch.New(logger, nil)
	store := session.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	svc := gateway.NewService(logger, d, store, newModelRegistryForTests())
	srv := NewServer(logger, ":0", svc, pairingSvc, true)
	return srv.Handler
}

func validEnvelope(t *testing.T) types.EventEnvelope {
	t.Helper()
	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: "ping"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_123",
		TraceID:    "trace_123",
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   "tenant_123",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   "listener_123",
		},
		Routing: types.EventRouting{
			AgentID:   "agent_123",
			SessionID: "session_123",
		},
		Payload: payload,
	}
}
