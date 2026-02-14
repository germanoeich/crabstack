package gateway

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"testing"
	"time"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-gateway/internal/dispatch"
	"crabstack.local/projects/crab-gateway/internal/session"
	"crabstack.local/projects/crab-gateway/internal/subscribers"
)

type collectorSubscriber struct {
	events chan types.EventEnvelope
}

func (c *collectorSubscriber) Name() string {
	return "collector"
}

func (c *collectorSubscriber) Handle(_ context.Context, event types.EventEnvelope) error {
	c.events <- event
	return nil
}

func TestServiceProcessEvent_ChannelMessage(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	collector := &collectorSubscriber{events: make(chan types.EventEnvelope, 8)}
	d := dispatch.New(logger, []subscribers.Subscriber{collector})
	store := session.NewMemoryStore()
	defer func() { _ = store.Close() }()
	svc := NewService(logger, d, store)

	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: "hello"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	inbound := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_in",
		TraceID:    "trace_1",
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   "tenant_1",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   "listener_1",
		},
		Routing: types.EventRouting{
			AgentID:   "agent_1",
			SessionID: "session_1",
		},
		Payload: payload,
	}

	svc.processEvent(context.Background(), inbound)

	seen := map[types.EventType]types.EventEnvelope{}
	deadline := time.After(2 * time.Second)
	for len(seen) < 3 {
		select {
		case event := <-collector.events:
			seen[event.EventType] = event
		case <-deadline:
			t.Fatalf("timed out waiting for events; got=%d", len(seen))
		}
	}

	if _, ok := seen[types.EventTypeAgentTurnStarted]; !ok {
		t.Fatalf("expected %s", types.EventTypeAgentTurnStarted)
	}
	if _, ok := seen[types.EventTypeAgentTurnCompleted]; !ok {
		t.Fatalf("expected %s", types.EventTypeAgentTurnCompleted)
	}
	respEvent, ok := seen[types.EventTypeAgentResponseCreated]
	if !ok {
		t.Fatalf("expected %s", types.EventTypeAgentResponseCreated)
	}

	var resp types.AgentResponseCreatedPayload
	if err := respEvent.DecodePayload(&resp); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text != "hello" {
		t.Fatalf("unexpected response content: %+v", resp.Content)
	}

	turns, err := store.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns: %v", err)
	}
	if len(turns) != 1 {
		t.Fatalf("expected one turn, got %d", len(turns))
	}
	if turns[0].Status != session.TurnStatusCompleted {
		t.Fatalf("expected completed turn status, got %s", turns[0].Status)
	}
}

func TestServiceProcessEvent_InvalidPayloadEmitsFailed(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	collector := &collectorSubscriber{events: make(chan types.EventEnvelope, 8)}
	d := dispatch.New(logger, []subscribers.Subscriber{collector})
	store := session.NewMemoryStore()
	defer func() { _ = store.Close() }()
	svc := NewService(logger, d, store)

	inbound := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_in_bad",
		TraceID:    "trace_2",
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   "tenant_1",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   "listener_1",
		},
		Routing: types.EventRouting{
			AgentID:   "agent_1",
			SessionID: "session_1",
		},
		Payload: []byte("[]"),
	}

	svc.processEvent(context.Background(), inbound)

	seen := map[types.EventType]bool{}
	deadline := time.After(2 * time.Second)
	for len(seen) < 2 {
		select {
		case event := <-collector.events:
			seen[event.EventType] = true
		case <-deadline:
			t.Fatalf("timed out waiting for events")
		}
	}

	if !seen[types.EventTypeAgentTurnStarted] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnStarted)
	}
	if !seen[types.EventTypeAgentTurnFailed] {
		t.Fatalf("expected %s", types.EventTypeAgentTurnFailed)
	}
	if seen[types.EventTypeAgentTurnCompleted] {
		t.Fatalf("did not expect %s", types.EventTypeAgentTurnCompleted)
	}

	turns, err := store.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns: %v", err)
	}
	if len(turns) != 1 {
		t.Fatalf("expected one turn, got %d", len(turns))
	}
	if turns[0].Status != session.TurnStatusFailed {
		t.Fatalf("expected failed turn status, got %s", turns[0].Status)
	}
}

func TestServiceProcessEvent_CLIMessageTracksCLIChannel(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	collector := &collectorSubscriber{events: make(chan types.EventEnvelope, 8)}
	d := dispatch.New(logger, []subscribers.Subscriber{collector})
	store := session.NewMemoryStore()
	defer func() { _ = store.Close() }()
	svc := NewService(logger, d, store)

	payload, err := json.Marshal(types.ChannelMessageReceivedPayload{Text: "hello cli"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	inbound := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "evt_cli_1",
		TraceID:    "trace_cli_1",
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   "tenant_cli",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeOperator,
			ComponentID:   "crab-cli-1",
			Platform:      "cli",
			ChannelID:     "cli",
			ActorID:       "operator",
			Transport:     types.TransportTypeHTTP,
		},
		Routing: types.EventRouting{
			AgentID:   "agent_cli",
			SessionID: "session_cli_1",
		},
		Payload: payload,
	}

	svc.processEvent(context.Background(), inbound)

	seenResponse := false
	deadline := time.After(2 * time.Second)
	for !seenResponse {
		select {
		case event := <-collector.events:
			if event.EventType == types.EventTypeAgentResponseCreated {
				seenResponse = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for response event")
		}
	}

	sessionRec, err := store.GetSession(context.Background(), "tenant_cli", "session_cli_1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sessionRec.LastActivePlatform != "cli" {
		t.Fatalf("expected last active platform cli, got %q", sessionRec.LastActivePlatform)
	}
	if sessionRec.LastActiveChannelID != "cli" {
		t.Fatalf("expected last active channel cli, got %q", sessionRec.LastActiveChannelID)
	}
}
