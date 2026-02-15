package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

const cronComponentID = "crab-cron"

var ErrSchedulerAlreadyStarted = errors.New("scheduler already started")

type EventEmitter interface {
	EmitEvent(ctx context.Context, event types.EventEnvelope) error
}

type Scheduler struct {
	store   JobStore
	emitter EventEmitter
	logger  *log.Logger

	mu             sync.Mutex
	jobs           map[string]scheduledJob
	lastFireMinute map[string]time.Time
	running        bool
	stopCh         chan struct{}
	doneCh         chan struct{}

	now           func() time.Time
	tickerFactory func(interval time.Duration) schedulerTicker
}

type scheduledJob struct {
	job  Job
	expr CronExpr
}

func NewScheduler(store JobStore, emitter EventEmitter, logger *log.Logger) *Scheduler {
	if store == nil {
		panic("scheduler: store is required")
	}
	if emitter == nil {
		panic("scheduler: emitter is required")
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Scheduler{
		store:          store,
		emitter:        emitter,
		logger:         logger,
		jobs:           make(map[string]scheduledJob),
		lastFireMinute: make(map[string]time.Time),
		now: func() time.Time {
			return time.Now().UTC()
		},
		tickerFactory: func(interval time.Duration) schedulerTicker {
			return newRealTicker(interval)
		},
	}
}

func (s *Scheduler) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := s.Reload(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrSchedulerAlreadyStarted
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	ticker := s.tickerFactory(time.Second)
	s.running = true
	s.stopCh = stopCh
	s.doneCh = doneCh
	s.mu.Unlock()

	go s.run(ctx, ticker, stopCh, doneCh)
	return nil
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	stopCh := s.stopCh
	doneCh := s.doneCh
	s.running = false
	s.stopCh = nil
	s.doneCh = nil
	s.mu.Unlock()

	close(stopCh)
	<-doneCh
}

func (s *Scheduler) Reload(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	jobs, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("list jobs: %w", err)
	}

	compiled := make(map[string]scheduledJob, len(jobs))
	for _, job := range jobs {
		job.ID = strings.TrimSpace(job.ID)
		if job.ID == "" {
			s.logger.Printf("skipping job with empty id")
			continue
		}
		expr, err := ParseCronExpr(job.Schedule)
		if err != nil {
			s.logger.Printf("skipping job %q invalid schedule %q: %v", job.ID, job.Schedule, err)
			continue
		}
		if job.EventType == "" {
			job.EventType = types.EventTypeCronTriggered
		}
		compiled[job.ID] = scheduledJob{job: cloneJob(job), expr: expr}
	}

	s.mu.Lock()
	s.jobs = compiled
	for jobID := range s.lastFireMinute {
		if _, ok := compiled[jobID]; !ok {
			delete(s.lastFireMinute, jobID)
		}
	}
	s.mu.Unlock()

	return nil
}

func (s *Scheduler) run(ctx context.Context, ticker schedulerTicker, stopCh <-chan struct{}, doneCh chan<- struct{}) {
	defer close(doneCh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.Chan():
			s.evaluate(ctx)
		}
	}
}

func (s *Scheduler) evaluate(ctx context.Context) {
	now := s.now().UTC()
	scheduledFor := now.Truncate(time.Minute)

	s.mu.Lock()
	candidates := make([]scheduledJob, 0, len(s.jobs))
	for jobID, job := range s.jobs {
		if !job.job.Enabled {
			continue
		}
		if !job.expr.Matches(now) {
			continue
		}
		if last, ok := s.lastFireMinute[jobID]; ok && last.Equal(scheduledFor) {
			continue
		}
		s.lastFireMinute[jobID] = scheduledFor
		candidates = append(candidates, job)
	}
	s.mu.Unlock()

	for _, candidate := range candidates {
		event, err := buildCronEvent(candidate.job, scheduledFor, now)
		if err != nil {
			s.logger.Printf("failed to build event for job %q: %v", candidate.job.ID, err)
			continue
		}
		if err := s.emitter.EmitEvent(ctx, event); err != nil {
			s.logger.Printf("failed to emit event for job %q: %v", candidate.job.ID, err)
		}
	}
}

func buildCronEvent(job Job, scheduledFor time.Time, triggeredAt time.Time) (types.EventEnvelope, error) {
	eventType := job.EventType
	if eventType == "" {
		eventType = types.EventTypeCronTriggered
	}

	payload := types.CronTriggeredPayload{
		JobID:        job.ID,
		JobName:      job.Name,
		ScheduledFor: scheduledFor,
		TriggeredAt:  triggeredAt,
		Input:        cloneMap(job.Input),
		Reason:       cronTriggerReasonForEvent(eventType),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return types.EventEnvelope{}, fmt.Errorf("marshal cron payload: %w", err)
	}

	return types.EventEnvelope{
		Version:    types.VersionV1,
		EventID:    newID(),
		TraceID:    newID(),
		OccurredAt: triggeredAt,
		EventType:  eventType,
		TenantID:   job.TenantID,
		Source: types.EventSource{
			ComponentType: types.ComponentTypeCron,
			ComponentID:   cronComponentID,
			Transport:     types.TransportTypeHTTP,
		},
		Routing: types.EventRouting{
			AgentID:   job.AgentID,
			SessionID: job.SessionID,
		},
		Payload: payloadJSON,
	}, nil
}

func cronTriggerReasonForEvent(eventType types.EventType) types.CronTriggerReason {
	if eventType == types.EventTypeHeartbeatTick {
		return types.CronTriggerReasonHeartbeat
	}
	return types.CronTriggerReasonScheduledJob
}

type schedulerTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type realTicker struct {
	ticker *time.Ticker
}

func newRealTicker(interval time.Duration) *realTicker {
	return &realTicker{ticker: time.NewTicker(interval)}
}

func (t *realTicker) Chan() <-chan time.Time {
	return t.ticker.C
}

func (t *realTicker) Stop() {
	t.ticker.Stop()
}
