package logging

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"crabstack.local/lib/types"
)

func TestSubscriberHandle(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := New(logger)

	event := types.EventEnvelope{EventID: "evt_1"}
	if err := s.Handle(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Name() != "logging" {
		t.Fatalf("unexpected name: %s", s.Name())
	}
	if !strings.Contains(buf.String(), "evt_1") {
		t.Fatalf("expected log output to contain event id, got %q", buf.String())
	}
}
