package dispatch

import (
	"context"
	"errors"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"crabstack.local/projects/crab-gateway/internal/subscribers"
	"crabstack.local/projects/crab-sdk/types"
)

type fakeSubscriber struct {
	name      string
	failUntil int

	mu    sync.Mutex
	calls int
	ch    chan types.EventEnvelope
}

func (f *fakeSubscriber) Name() string {
	return f.name
}

func (f *fakeSubscriber) Handle(_ context.Context, event types.EventEnvelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failUntil {
		return errors.New("forced failure")
	}
	if f.ch != nil {
		f.ch <- event
	}
	return nil
}

func (f *fakeSubscriber) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestDispatcherRetriesThenSucceeds(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	sub := &fakeSubscriber{name: "sub", failUntil: 2, ch: make(chan types.EventEnvelope, 1)}
	d := New(logger, []subscribers.Subscriber{sub})
	event := types.EventEnvelope{EventID: "evt_1"}

	d.Dispatch(context.Background(), event)

	select {
	case got := <-sub.ch:
		if got.EventID != event.EventID {
			t.Fatalf("unexpected event id: %s", got.EventID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for dispatch")
	}

	if calls := sub.Calls(); calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestDispatcherStopsAfterRetries(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	sub := &fakeSubscriber{name: "sub", failUntil: 10, ch: make(chan types.EventEnvelope, 1)}
	d := New(logger, []subscribers.Subscriber{sub})
	event := types.EventEnvelope{EventID: "evt_2"}

	d.Dispatch(context.Background(), event)
	time.Sleep(800 * time.Millisecond)

	if calls := sub.Calls(); calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
	select {
	case <-sub.ch:
		t.Fatalf("did not expect successful dispatch")
	default:
	}
}
