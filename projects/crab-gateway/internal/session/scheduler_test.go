package session

import (
	"context"
	"log"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

func TestSchedulerOrderingPerSession(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)

	got := make([]string, 0, 3)
	var mu sync.Mutex
	done := make(chan struct{}, 3)
	handler := func(_ context.Context, event types.EventEnvelope) {
		mu.Lock()
		got = append(got, event.EventID)
		mu.Unlock()
		done <- struct{}{}
	}

	s := NewScheduler(logger, 16, handler)
	events := []types.EventEnvelope{
		makeEvent("t1", "s1", "e1"),
		makeEvent("t1", "s1", "e2"),
		makeEvent("t1", "s1", "e3"),
	}

	for _, event := range events {
		if err := s.Enqueue(context.Background(), event); err != nil {
			t.Fatalf("enqueue failed: %v", err)
		}
	}

	for range events {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for scheduled events")
		}
	}

	want := []string{"e1", "e2", "e3"}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected order: want=%v got=%v", want, got)
	}
}

func TestSchedulerQueueFull(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	block := make(chan struct{})
	started := make(chan struct{}, 1)

	handler := func(_ context.Context, _ types.EventEnvelope) {
		started <- struct{}{}
		<-block
	}

	s := NewScheduler(logger, 1, handler)
	e1 := makeEvent("t1", "s1", "e1")
	e2 := makeEvent("t1", "s1", "e2")
	e3 := makeEvent("t1", "s1", "e3")

	if err := s.Enqueue(context.Background(), e1); err != nil {
		t.Fatalf("enqueue e1 failed: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for worker start")
	}
	if err := s.Enqueue(context.Background(), e2); err != nil {
		t.Fatalf("enqueue e2 failed: %v", err)
	}
	if err := s.Enqueue(context.Background(), e3); err != ErrSessionQueueFull {
		t.Fatalf("expected ErrSessionQueueFull, got %v", err)
	}

	close(block)
}

func makeEvent(tenantID, sessionID, eventID string) types.EventEnvelope {
	return types.EventEnvelope{
		TenantID: tenantID,
		EventID:  eventID,
		Routing: types.EventRouting{
			SessionID: sessionID,
			AgentID:   "agent",
		},
	}
}
