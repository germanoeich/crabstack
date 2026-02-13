package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"pinchy.local/lib/types"
)

type Subscriber struct {
	logger *log.Logger
}

func New(logger *log.Logger) *Subscriber {
	return &Subscriber{logger: logger}
}

func (s *Subscriber) Name() string {
	return "logging"
}

func (s *Subscriber) Handle(_ context.Context, event types.EventEnvelope) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	s.logger.Printf("subscriber=logging event=%s", encoded)
	return nil
}
