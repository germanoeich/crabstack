package dispatch

import (
	"context"
	"log"
	"time"

	"crabstack.local/projects/crab-gateway/internal/subscribers"
	"crabstack.local/projects/crab-sdk/types"
)

type Dispatcher struct {
	logger       *log.Logger
	subscribers  []subscribers.Subscriber
	retryCount   int
	retryBackoff time.Duration
}

func New(logger *log.Logger, subs []subscribers.Subscriber) *Dispatcher {
	return &Dispatcher{
		logger:       logger,
		subscribers:  subs,
		retryCount:   3,
		retryBackoff: 150 * time.Millisecond,
	}
}

func (d *Dispatcher) Dispatch(ctx context.Context, event types.EventEnvelope) {
	for _, sub := range d.subscribers {
		s := sub
		go d.dispatchOne(ctx, s, event)
	}
}

func (d *Dispatcher) dispatchOne(ctx context.Context, sub subscribers.Subscriber, event types.EventEnvelope) {
	for attempt := 1; attempt <= d.retryCount; attempt++ {
		err := sub.Handle(ctx, event)
		if err == nil {
			return
		}

		d.logger.Printf("subscriber=%s event_id=%s attempt=%d err=%v", sub.Name(), event.EventID, attempt, err)
		if attempt == d.retryCount {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(d.retryBackoff):
		}
	}
}
