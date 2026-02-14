package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

func TestHandleSuccessfulPost(t *testing.T) {
	var (
		gotMethod      string
		gotPath        string
		gotContentType string
		gotBody        []byte
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	event := newTestEvent(types.EventTypeAgentTurnCompleted)
	wantBody, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	subscriber := New("webhook-test", server.URL+"/events", testLogger())
	if err := subscriber.Handle(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("unexpected method: %s", gotMethod)
	}
	if gotPath != "/events" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("unexpected content-type: %s", gotContentType)
	}
	if !bytes.Equal(gotBody, wantBody) {
		t.Fatalf("unexpected body: got=%s want=%s", gotBody, wantBody)
	}
}

func TestHandleNon2xxReturnsErrorWithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream failed"))
	}))
	defer server.Close()

	subscriber := New("webhook-test", server.URL, testLogger())
	err := subscriber.Handle(context.Background(), newTestEvent(types.EventTypeAgentTurnCompleted))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status code in error, got %v", err)
	}
	if !strings.Contains(err.Error(), "upstream failed") {
		t.Fatalf("expected response body in error, got %v", err)
	}
}

func TestHandleEventFilterSkipsNonMatching(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	subscriber := New(
		"webhook-test",
		server.URL,
		testLogger(),
		WithEventFilter(func(eventType types.EventType) bool {
			return eventType == types.EventTypeAgentTurnCompleted
		}),
	)

	err := subscriber.Handle(context.Background(), newTestEvent(types.EventTypeAgentTurnFailed))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("expected no webhook call, got %d", calls)
	}
}

func TestHandleEventFilterAllowsMatching(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	subscriber := New(
		"webhook-test",
		server.URL,
		testLogger(),
		WithEventFilter(func(eventType types.EventType) bool {
			return eventType == types.EventTypeAgentTurnCompleted
		}),
	)

	err := subscriber.Handle(context.Background(), newTestEvent(types.EventTypeAgentTurnCompleted))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected one webhook call, got %d", calls)
	}
}

func TestHandleNilFilterForwardsAllEvents(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	subscriber := New("webhook-test", server.URL, testLogger())
	err := subscriber.Handle(context.Background(), newTestEvent(types.EventTypeAgentTurnFailed))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected one webhook call, got %d", calls)
	}
}

func TestHandlePostTimeoutReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 50 * time.Millisecond}
	subscriber := New("webhook-test", server.URL, testLogger(), WithHTTPClient(client))
	err := subscriber.Handle(context.Background(), newTestEvent(types.EventTypeAgentTurnCompleted))
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("expected timeout/deadline error, got %v", err)
	}
}

func TestHandleUsesCustomHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	customClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	subscriber := New("webhook-test", server.URL+"/redirect", testLogger(), WithHTTPClient(customClient))
	err := subscriber.Handle(context.Background(), newTestEvent(types.EventTypeAgentTurnCompleted))
	if err == nil {
		t.Fatalf("expected error from non-2xx redirect response")
	}
	if !strings.Contains(err.Error(), "307") {
		t.Fatalf("expected 307 status in error, got %v", err)
	}
}

func testLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func newTestEvent(eventType types.EventType) types.EventEnvelope {
	return types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_1",
		TraceID:    "trace_1",
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
		EventType:  eventType,
		TenantID:   "tenant_1",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeGateway,
			ComponentID:   "gateway",
		},
		Routing: types.EventRouting{
			AgentID:   "agent_1",
			SessionID: "session_1",
		},
		Payload: json.RawMessage(`{"message":"hello"}`),
	}
}
