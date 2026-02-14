package consumer

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"crabstack.local/projects/crab-discord/internal/chanmap"
	"crabstack.local/projects/crab-discord/internal/config"
	"crabstack.local/projects/crab-sdk/types"
)

func TestHandleEventsAgentResponseSendMessageAction(t *testing.T) {
	registry := chanmap.NewChannelRegistry()
	registry.Register("session-1", "channel-1")

	sender := &mockDiscordSender{}
	consumer := NewConsumer(config.Config{}, sender, log.New(io.Discard, "", 0))
	consumer.SetChannelRegistry(registry)

	server := httptest.NewServer(consumer.routes())
	defer server.Close()

	envelope := responseEnvelope(t, types.AgentResponseCreatedPayload{
		ResponseID: "resp-1",
		Actions: []types.AgentResponseAction{
			{
				Kind: types.AgentResponseActionKindSendMessage,
				Args: map[string]any{"text": "hello from action"},
			},
		},
	})
	envelope.Routing.SessionID = "session-1"

	resp := postEnvelope(t, server.Client(), server.URL+"/v1/events", envelope)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected one discord send call, got %d", len(calls))
	}
	if calls[0].channelID != "channel-1" {
		t.Fatalf("expected channel-1, got %q", calls[0].channelID)
	}
	if calls[0].content != "hello from action" {
		t.Fatalf("expected action text, got %q", calls[0].content)
	}
}

func TestHandleEventsAgentResponseTextContent(t *testing.T) {
	registry := chanmap.NewChannelRegistry()
	registry.Register("session-1", "channel-2")

	sender := &mockDiscordSender{}
	consumer := NewConsumer(config.Config{}, sender, log.New(io.Discard, "", 0))
	consumer.SetChannelRegistry(registry)

	server := httptest.NewServer(consumer.routes())
	defer server.Close()

	envelope := responseEnvelope(t, types.AgentResponseCreatedPayload{
		ResponseID: "resp-2",
		Content: []types.AgentResponseContent{
			{
				Type: types.AgentResponseContentTypeText,
				Text: "hello from content",
			},
		},
	})
	envelope.Routing.SessionID = "session-1"

	resp := postEnvelope(t, server.Client(), server.URL+"/v1/events", envelope)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	calls := sender.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected one discord send call, got %d", len(calls))
	}
	if calls[0].channelID != "channel-2" {
		t.Fatalf("expected channel-2, got %q", calls[0].channelID)
	}
	if calls[0].content != "hello from content" {
		t.Fatalf("expected content text, got %q", calls[0].content)
	}
}

func TestHandleEventsNonMatchingEventTypeReturns200(t *testing.T) {
	sender := &mockDiscordSender{}
	consumer := NewConsumer(config.Config{}, sender, log.New(io.Discard, "", 0))

	server := httptest.NewServer(consumer.routes())
	defer server.Close()

	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: "ignored"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	envelope := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt-ignored",
		TraceID:    "trace-ignored",
		OccurredAt: time.Date(2026, time.February, 14, 12, 0, 0, 0, time.UTC),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   "tenant-a",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   "discord-listener",
		},
		Routing: types.EventRouting{
			AgentID:   "assistant",
			SessionID: "session-1",
		},
		Payload: payload,
	}

	resp := postEnvelope(t, server.Client(), server.URL+"/v1/events", envelope)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if len(sender.Calls()) != 0 {
		t.Fatalf("expected no discord send calls")
	}
}

func TestHandleEventsInvalidJSONReturns400(t *testing.T) {
	sender := &mockDiscordSender{}
	consumer := NewConsumer(config.Config{}, sender, log.New(io.Discard, "", 0))

	server := httptest.NewServer(consumer.routes())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/v1/events", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatalf("post invalid json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestHandleEventsMissingChannelMappingReturns200(t *testing.T) {
	var logBuf bytes.Buffer
	sender := &mockDiscordSender{}
	consumer := NewConsumer(config.Config{}, sender, log.New(&logBuf, "", 0))
	consumer.SetChannelRegistry(chanmap.NewChannelRegistry())

	server := httptest.NewServer(consumer.routes())
	defer server.Close()

	envelope := responseEnvelope(t, types.AgentResponseCreatedPayload{
		ResponseID: "resp-3",
		Actions: []types.AgentResponseAction{
			{
				Kind: types.AgentResponseActionKindSendMessage,
				Args: map[string]any{"text": "hello"},
			},
		},
	})
	envelope.EventID = "evt-missing-channel"
	envelope.Routing.SessionID = "missing"
	envelope.Source.ChannelID = ""

	resp := postEnvelope(t, server.Client(), server.URL+"/v1/events", envelope)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if len(sender.Calls()) != 0 {
		t.Fatalf("expected no discord send calls")
	}
	if !strings.Contains(logBuf.String(), "missing discord channel mapping") {
		t.Fatalf("expected missing mapping warning log, got %q", logBuf.String())
	}
}

func responseEnvelope(t *testing.T, payload types.AgentResponseCreatedPayload) types.EventEnvelope {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal response payload: %v", err)
	}

	return types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt-1",
		TraceID:    "trace-1",
		OccurredAt: time.Date(2026, time.February, 14, 12, 0, 0, 0, time.UTC),
		EventType:  types.EventTypeAgentResponseCreated,
		TenantID:   "tenant-a",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeGateway,
			ComponentID:   "gateway-core",
		},
		Routing: types.EventRouting{
			AgentID:   "assistant",
			SessionID: "session-1",
		},
		Payload: data,
	}
}

func postEnvelope(t *testing.T, client *http.Client, url string, envelope types.EventEnvelope) *http.Response {
	t.Helper()

	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post envelope: %v", err)
	}
	return resp
}

type sendCall struct {
	channelID string
	content   string
}

type mockDiscordSender struct {
	mu    sync.Mutex
	calls []sendCall
}

func (m *mockDiscordSender) SendMessage(channelID string, content string) error {
	m.mu.Lock()
	m.calls = append(m.calls, sendCall{channelID: channelID, content: content})
	m.mu.Unlock()
	return nil
}

func (m *mockDiscordSender) Calls() []sendCall {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]sendCall, len(m.calls))
	copy(out, m.calls)
	return out
}
