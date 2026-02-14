package session

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

func TestGormStoreSQLiteSessionAndTurns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	store, err := NewGormStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("new gorm store: %v", err)
	}
	defer func() { _ = store.Close() }()

	event := testEvent("evt_1", "trace_1", "tenant_1", "session_1", "agent_1", "discord", "chan_1", "user_1", "hello")
	sessionRec, err := store.EnsureSession(context.Background(), event)
	if err != nil {
		t.Fatalf("ensure session: %v", err)
	}
	if sessionRec.SessionID != "session_1" {
		t.Fatalf("unexpected session id: %s", sessionRec.SessionID)
	}

	loaded, err := store.GetSession(context.Background(), "tenant_1", "session_1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if loaded.LastActiveChannelID != "chan_1" {
		t.Fatalf("expected last active channel chan_1, got %q", loaded.LastActiveChannelID)
	}

	turn1, err := store.StartTurn(context.Background(), event)
	if err != nil {
		t.Fatalf("start turn1: %v", err)
	}
	event2 := testEvent("evt_2", "trace_2", "tenant_1", "session_1", "agent_1", "discord", "chan_1", "user_1", "world")
	turn2, err := store.StartTurn(context.Background(), event2)
	if err != nil {
		t.Fatalf("start turn2: %v", err)
	}
	if turn1.Sequence != 1 || turn2.Sequence != 2 {
		t.Fatalf("unexpected turn sequence values: %d, %d", turn1.Sequence, turn2.Sequence)
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
	if err := store.FailTurn(context.Background(), turn2.TurnID, "failed"); err != nil {
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

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := NewGormStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen gorm store: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	loadedSession, err := reopened.GetSession(context.Background(), "tenant_1", "session_1")
	if err != nil {
		t.Fatalf("get session after reopen: %v", err)
	}
	if loadedSession.AgentID != "agent_1" {
		t.Fatalf("unexpected session agent id after reopen: %s", loadedSession.AgentID)
	}

	reopenedTurns, err := reopened.GetTurns(context.Background(), "tenant_1", "session_1", 10)
	if err != nil {
		t.Fatalf("get turns after reopen: %v", err)
	}
	if len(reopenedTurns) != 2 {
		t.Fatalf("expected 2 turns after reopen, got %d", len(reopenedTurns))
	}
}

func testEvent(eventID, traceID, tenantID, sessionID, agentID, platform, channelID, actorID, text string) types.EventEnvelope {
	return types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    eventID,
		TraceID:    traceID,
		OccurredAt: time.Now().UTC(),
		EventType:  types.EventTypeChannelMessageReceived,
		TenantID:   tenantID,
		Source: types.EventSource{
			ComponentType: types.ComponentTypeListener,
			ComponentID:   "listener_1",
			Platform:      platform,
			ChannelID:     channelID,
			ActorID:       actorID,
		},
		Routing: types.EventRouting{
			AgentID:   agentID,
			SessionID: sessionID,
		},
		Payload: []byte(`{"text":"` + text + `"}`),
	}
}
