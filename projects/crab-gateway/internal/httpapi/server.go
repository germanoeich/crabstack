package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-gateway/internal/gateway"
	"crabstack.local/projects/crab-gateway/internal/pairing"
	"crabstack.local/projects/crab-gateway/internal/session"
)

type server struct {
	logger  *log.Logger
	gateway *gateway.Service
	pairing pairing.Service
}

const maxPairingsWSRequestBytes int64 = 1 << 20

func NewServer(logger *log.Logger, addr string, gatewayService *gateway.Service, pairingService pairing.Service, enablePairingRoutes bool) *http.Server {
	h := &server{
		logger:  logger,
		gateway: gatewayService,
		pairing: pairingService,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.handleHealth)
	mux.HandleFunc("/v1/events", h.handleEvents)
	if enablePairingRoutes {
		mux.HandleFunc("/v1/pairings", h.handlePairings)
		mux.HandleFunc("/v1/pairings/ws", h.handlePairingsWS)
	}

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	var event types.EventEnvelope
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&event); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}
	if dec.More() {
		http.Error(w, "invalid json: trailing content", http.StatusBadRequest)
		return
	}

	if err := validateEventEnvelope(event); err != nil {
		http.Error(w, fmt.Sprintf("invalid event: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.gateway.AcceptEvent(r.Context(), event); err != nil {
		if errors.Is(err, session.ErrSessionQueueFull) {
			http.Error(w, "session queue full", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "failed to accept event", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted": true,
		"event_id": event.EventID,
	})
}

func (s *server) handlePairings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pairing == nil {
		http.Error(w, "pairing not configured", http.StatusNotImplemented)
		return
	}

	defer r.Body.Close()
	var req pairRequestBody
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
		return
	}
	if dec.More() {
		http.Error(w, "invalid json: trailing content", http.StatusBadRequest)
		return
	}

	pairReq, err := toPairRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := s.pairing.Pair(r.Context(), pairReq)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, pairing.ErrInvalidRequest) || errors.Is(err, pairing.ErrUnsupportedComponent) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *server) handlePairingsWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pairing == nil {
		http.Error(w, "pairing not configured", http.StatusNotImplemented)
		return
	}

	upgrader := websocket.Upgrader{CheckOrigin: isWebSocketOriginAllowed}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Printf("pairings ws upgrade failed: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(maxPairingsWSRequestBytes)

	var req wsPairMessage
	if err := conn.ReadJSON(&req); err != nil {
		_ = conn.WriteJSON(wsPairResult{Action: "pair.result", OK: false, Error: fmt.Sprintf("invalid request: %v", err)})
		return
	}
	if req.Action != "pair.start" {
		_ = conn.WriteJSON(wsPairResult{Action: "pair.result", OK: false, Error: "unsupported action"})
		return
	}

	pairReq, err := toPairRequest(pairRequestBody{
		ComponentType: req.ComponentType,
		ComponentID:   req.ComponentID,
		Endpoint:      req.Endpoint,
	})
	if err != nil {
		_ = conn.WriteJSON(wsPairResult{Action: "pair.result", OK: false, Error: err.Error()})
		return
	}

	result, err := s.pairing.Pair(r.Context(), pairReq)
	if err != nil {
		_ = conn.WriteJSON(wsPairResult{Action: "pair.result", OK: false, Error: err.Error()})
		return
	}
	_ = conn.WriteJSON(wsPairResult{Action: "pair.result", OK: true, Result: &result})
}

func validateEventEnvelope(event types.EventEnvelope) error {
	if event.Version != types.VersionV1 {
		return fmt.Errorf("unsupported version %q", event.Version)
	}
	if strings.TrimSpace(event.EventID) == "" {
		return errors.New("event_id is required")
	}
	if strings.TrimSpace(event.TraceID) == "" {
		return errors.New("trace_id is required")
	}
	if event.OccurredAt.IsZero() {
		return errors.New("occurred_at is required")
	}
	if strings.TrimSpace(string(event.EventType)) == "" {
		return errors.New("event_type is required")
	}
	if !validEventType(event.EventType) {
		return fmt.Errorf("unsupported event_type %q", event.EventType)
	}
	if strings.TrimSpace(event.TenantID) == "" {
		return errors.New("tenant_id is required")
	}
	if strings.TrimSpace(string(event.Source.ComponentType)) == "" {
		return errors.New("source.component_type is required")
	}
	if strings.TrimSpace(event.Source.ComponentID) == "" {
		return errors.New("source.component_id is required")
	}
	if strings.TrimSpace(event.Routing.AgentID) == "" {
		return errors.New("routing.agent_id is required")
	}
	if strings.TrimSpace(event.Routing.SessionID) == "" {
		return errors.New("routing.session_id is required")
	}
	if len(event.Payload) == 0 {
		return errors.New("payload is required")
	}
	if !json.Valid(event.Payload) {
		return errors.New("payload must be valid json")
	}
	return nil
}

func validEventType(t types.EventType) bool {
	switch t {
	case types.EventTypeChannelMessageReceived,
		types.EventTypeChannelMessageEdited,
		types.EventTypeChannelMessageDeleted,
		types.EventTypeCronTriggered,
		types.EventTypeHeartbeatTick,
		types.EventTypeAgentTurnStarted,
		types.EventTypeAgentTurnCompleted,
		types.EventTypeAgentTurnFailed,
		types.EventTypeAgentResponseCreated,
		types.EventTypeToolCallRequested,
		types.EventTypeToolCallCompleted,
		types.EventTypeToolCallFailed,
		types.EventTypePairingStarted,
		types.EventTypePairingCompleted,
		types.EventTypePairingFailed,
		types.EventTypeConfigApplied,
		types.EventTypeConfigReverted:
		return true
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func isWebSocketOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsedOrigin, err := url.Parse(origin)
	if err != nil || strings.TrimSpace(parsedOrigin.Host) == "" {
		return false
	}
	return strings.EqualFold(parsedOrigin.Host, r.Host)
}

type pairRequestBody struct {
	ComponentType string `json:"component_type"`
	ComponentID   string `json:"component_id"`
	Endpoint      string `json:"endpoint"`
}

type wsPairMessage struct {
	Action        string `json:"action"`
	ComponentType string `json:"component_type"`
	ComponentID   string `json:"component_id"`
	Endpoint      string `json:"endpoint"`
}

type wsPairResult struct {
	Action string              `json:"action"`
	OK     bool                `json:"ok"`
	Error  string              `json:"error,omitempty"`
	Result *pairing.PairResult `json:"result,omitempty"`
}

func toPairRequest(req pairRequestBody) (pairing.PairRequest, error) {
	componentType, err := pairing.ParseComponentType(req.ComponentType)
	if err != nil {
		return pairing.PairRequest{}, err
	}
	componentID := strings.TrimSpace(req.ComponentID)
	if componentID == "" {
		return pairing.PairRequest{}, errors.New("component_id is required")
	}
	return pairing.PairRequest{
		ComponentType: componentType,
		ComponentID:   componentID,
		Endpoint:      strings.TrimSpace(req.Endpoint),
	}, nil
}
