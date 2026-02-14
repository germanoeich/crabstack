package session

import (
	"context"
	"testing"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

func TestMemoryStoreSessionAndTurns(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	event := testEvent("evt_1", "trace_1", "tenant_1", "session_1", "agent_1", "discord", "chan_1", "user_1", "hello")
	sessionRec, err := store.EnsureSession(context.Background(), event)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	if sessionRec.LastActiveChannelID != "chan_1" {
		t.Fatalf("expected last active channel chan_1, got %q", sessionRec.LastActiveChannelID)
	}

	event2 := testEvent("evt_2", "trace_2", "tenant_1", "session_1", "agent_1", "discord", "chan_2", "user_1", "world")
	sessionRec, err = store.EnsureSession(context.Background(), event2)
	if err != nil {
		t.Fatalf("ensure session update: %v", err)
	}
	if sessionRec.LastActiveChannelID != "chan_2" {
		t.Fatalf("expected last active channel chan_2, got %q", sessionRec.LastActiveChannelID)
	}

	turn1, err := store.StartTurn(context.Background(), event)
	if err != nil {
		t.Fatalf("start turn1: %v", err)
	}
	if turn1.Sequence != 1 {
		t.Fatalf("expected turn1 sequence=1, got %d", turn1.Sequence)
	}

	turn2, err := store.StartTurn(context.Background(), event2)
	if err != nil {
		t.Fatalf("start turn2: %v", err)
	}
	if turn2.Sequence != 2 {
		t.Fatalf("expected turn2 sequence=2, got %d", turn2.Sequence)
	}

	resp := types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    "resp_1",
		TraceID:    "trace_1",
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeAgentResponseCreated,
		TenantID:   "tenant_1",
		Source: types.EventSource{
			ComponentType: types.ComponentTypeGateway,
			ComponentID:   "gateway-core",
		},
		Routing: event.Routing,
		Payload: []byte(`{"response_id":"r1"}`),
	}

	if err := store.CompleteTurn(context.Background(), turn1.TurnID, &resp); err != nil {
		t.Fatalf("complete turn1: %v", err)
	}
	if err := store.FailTurn(context.Background(), turn2.TurnID, "boom"); err != nil {
		t.Fatalf("fail turn2: %v", err)
	}

	turns, err := store.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns: %v", err)
	}
	if len(turns) != 2 {
		t.Fatalf("expected 2 turns, got %d", len(turns))
	}
	if turns[0].Status != TurnStatusCompleted {
		t.Fatalf("expected turn1 completed, got %s", turns[0].Status)
	}
	if turns[1].Status != TurnStatusFailed {
		t.Fatalf("expected turn2 failed, got %s", turns[1].Status)
	}
}
