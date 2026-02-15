package scheduler

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

func TestSchedulerFiresAtCorrectTime(t *testing.T) {
	store := NewMemoryJobStore()
	job, err := store.Create(context.Background(), Job{
		Name:      "every-minute",
		Schedule:  "* * * * *",
		EventType: types.EventTypeCronTriggered,
		TenantID:  "tenant-1",
		AgentID:   "agent-1",
		SessionID: "session-1",
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}

	emitter := newRecordingEmitter()
	s := NewScheduler(store, emitter, log.New(io.Discard, "", 0))

	manualTicker := &manualTicker{ch: make(chan time.Time, 8)}
	s.tickerFactory = func(time.Duration) schedulerTicker { return manualTicker }

	var nowMu sync.Mutex
	now := time.Date(2026, time.February, 14, 12, 0, 5, 0, time.UTC)
	s.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	setNow := func(v time.Time) {
		nowMu.Lock()
		now = v
		nowMu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	manualTicker.ch <- time.Now()
	emitter.waitForCount(t, 1, 2*time.Second)

	setNow(time.Date(2026, time.February, 14, 12, 0, 30, 0, time.UTC))
	manualTicker.ch <- time.Now()
	time.Sleep(50 * time.Millisecond)
	if got := emitter.Count(); got != 1 {
		t.Fatalf("expected one fire in same minute, got %d", got)
	}

	setNow(time.Date(2026, time.February, 14, 12, 1, 0, 0, time.UTC))
	manualTicker.ch <- time.Now()
	emitter.waitForCount(t, 2, 2*time.Second)

	events := emitter.Events()
	if events[0].EventType != types.EventTypeCronTriggered {
		t.Fatalf("event type got=%q want=%q", events[0].EventType, types.EventTypeCronTriggered)
	}
	var payload types.CronTriggeredPayload
	if err := events[0].DecodePayload(&payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.JobID != job.ID {
		t.Fatalf("job id got=%q want=%q", payload.JobID, job.ID)
	}
}

func TestSchedulerSkipsDisabledJobs(t *testing.T) {
	store := NewMemoryJobStore()
	_, err := store.Create(context.Background(), Job{
		Name:      "disabled",
		Schedule:  "* * * * *",
		EventType: types.EventTypeCronTriggered,
		TenantID:  "tenant-1",
		AgentID:   "agent-1",
		SessionID: "session-1",
		Enabled:   false,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}

	emitter := newRecordingEmitter()
	s := NewScheduler(store, emitter, log.New(io.Discard, "", 0))

	manualTicker := &manualTicker{ch: make(chan time.Time, 2)}
	s.tickerFactory = func(time.Duration) schedulerTicker { return manualTicker }
	s.now = func() time.Time {
		return time.Date(2026, time.February, 14, 12, 0, 0, 0, time.UTC)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	manualTicker.ch <- time.Now()
	time.Sleep(100 * time.Millisecond)

	if got := emitter.Count(); got != 0 {
		t.Fatalf("expected disabled job not to fire, got %d events", got)
	}
}

func TestSchedulerBuildsCronTriggeredPayload(t *testing.T) {
	store := NewMemoryJobStore()
	job, err := store.Create(context.Background(), Job{
		Name:      "heartbeat",
		Schedule:  "* * * * *",
		EventType: types.EventTypeHeartbeatTick,
		TenantID:  "tenant-1",
		AgentID:   "agent-1",
		SessionID: "session-1",
		Input: map[string]any{
			"source": "cron",
		},
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}

	emitter := newRecordingEmitter()
	s := NewScheduler(store, emitter, log.New(io.Discard, "", 0))

	manualTicker := &manualTicker{ch: make(chan time.Time, 2)}
	s.tickerFactory = func(time.Duration) schedulerTicker { return manualTicker }
	current := time.Date(2026, time.February, 14, 9, 10, 42, 0, time.UTC)
	s.now = func() time.Time { return current }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	manualTicker.ch <- time.Now()
	emitter.waitForCount(t, 1, 2*time.Second)

	event := emitter.Events()[0]
	if event.EventType != types.EventTypeHeartbeatTick {
		t.Fatalf("event type got=%q want=%q", event.EventType, types.EventTypeHeartbeatTick)
	}
	if event.Source.ComponentType != types.ComponentTypeCron {
		t.Fatalf("source component type got=%q want=%q", event.Source.ComponentType, types.ComponentTypeCron)
	}
	if event.Source.ComponentID != cronComponentID {
		t.Fatalf("source component id got=%q want=%q", event.Source.ComponentID, cronComponentID)
	}
	if event.Routing.AgentID != job.AgentID {
		t.Fatalf("routing agent id got=%q want=%q", event.Routing.AgentID, job.AgentID)
	}
	if event.Routing.SessionID != job.SessionID {
		t.Fatalf("routing session id got=%q want=%q", event.Routing.SessionID, job.SessionID)
	}

	var payload types.CronTriggeredPayload
	if err := event.DecodePayload(&payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.JobID != job.ID {
		t.Fatalf("job id got=%q want=%q", payload.JobID, job.ID)
	}
	if payload.JobName != job.Name {
		t.Fatalf("job name got=%q want=%q", payload.JobName, job.Name)
	}
	if !payload.ScheduledFor.Equal(current.Truncate(time.Minute)) {
		t.Fatalf("scheduled_for got=%s want=%s", payload.ScheduledFor.Format(time.RFC3339), current.Truncate(time.Minute).Format(time.RFC3339))
	}
	if !payload.TriggeredAt.Equal(current) {
		t.Fatalf("triggered_at got=%s want=%s", payload.TriggeredAt.Format(time.RFC3339), current.Format(time.RFC3339))
	}
	if payload.Reason != types.CronTriggerReasonHeartbeat {
		t.Fatalf("reason got=%q want=%q", payload.Reason, types.CronTriggerReasonHeartbeat)
	}
}

type manualTicker struct {
	ch chan time.Time
}

func (t *manualTicker) Chan() <-chan time.Time {
	return t.ch
}

func (t *manualTicker) Stop() {}

type recordingEmitter struct {
	mu     sync.Mutex
	events []types.EventEnvelope
	notify chan struct{}
}

func newRecordingEmitter() *recordingEmitter {
	return &recordingEmitter{notify: make(chan struct{}, 32)}
}

func (e *recordingEmitter) EmitEvent(_ context.Context, event types.EventEnvelope) error {
	e.mu.Lock()
	e.events = append(e.events, event)
	e.mu.Unlock()

	select {
	case e.notify <- struct{}{}:
	default:
	}
	return nil
}

func (e *recordingEmitter) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

func (e *recordingEmitter) Events() []types.EventEnvelope {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]types.EventEnvelope, len(e.events))
	copy(out, e.events)
	return out
}

func (e *recordingEmitter) waitForCount(t *testing.T, want int, timeout time.Duration) {
	t.Helper()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		if e.Count() >= want {
			return
		}
		select {
		case <-e.notify:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %d events, got %d", want, e.Count())
		}
	}
}
