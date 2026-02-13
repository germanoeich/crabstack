package session

import (
	"context"
	"errors"
	"log"
	"sync"

	"crabstack.local/lib/types"
)

var ErrSessionQueueFull = errors.New("session queue full")

type EventHandler func(context.Context, types.EventEnvelope)

type Scheduler struct {
	logger    *log.Logger
	handler   EventHandler
	queueSize int

	mu      sync.Mutex
	workers map[string]*worker
}

type worker struct {
	ch chan types.EventEnvelope
}

func NewScheduler(logger *log.Logger, queueSize int, handler EventHandler) *Scheduler {
	if queueSize <= 0 {
		queueSize = 256
	}
	return &Scheduler{
		logger:    logger,
		handler:   handler,
		queueSize: queueSize,
		workers:   make(map[string]*worker),
	}
}

func (s *Scheduler) Enqueue(ctx context.Context, event types.EventEnvelope) error {
	key := event.TenantID + ":" + event.Routing.SessionID
	w := s.workerFor(key)

	select {
	case w.ch <- event:
		return nil
	default:
		s.logger.Printf("session queue full key=%s", key)
		return ErrSessionQueueFull
	}
}

func (s *Scheduler) workerFor(key string) *worker {
	s.mu.Lock()
	defer s.mu.Unlock()

	if w, ok := s.workers[key]; ok {
		return w
	}

	w := &worker{ch: make(chan types.EventEnvelope, s.queueSize)}
	s.workers[key] = w

	go func() {
		for event := range w.ch {
			s.handler(context.Background(), event)
		}
	}()

	return w
}
